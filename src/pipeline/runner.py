from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from legacy.r2.cache import FileCache, compute_file_md5
from src.analysis.features import FEATURE_KEYS
from src.analysis.includes import make_preamble
from src.analysis.scorer import GhidraFunctionScorer
from src.analysis.triage import triage_binary
from src.config import AppConfig
from src.domains import get_domain_pack
from src.ghidra.headless import GhidraError, run_ghidra_decompile
from src.logging_setup import setup_logging
from src.pipeline.metrics import RunMetrics

logger = logging.getLogger("revllm.pipeline")
GHIDRA_CACHE_KEY = "ghidra_full_v6"
# Bump when restorer/polisher prompts or fidelity contract change.
LLM_PROMPT_VER = "p3"


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _call_tokens(
    callees: List[str],
    name_by_addr: Dict[str, str],
    thunk_target: Dict[str, str],
) -> List[Tuple[str, List[str]]]:
    from src.analysis.fidelity import build_call_tokens
    return build_call_tokens(callees, name_by_addr=name_by_addr, thunk_target=thunk_target)


def _llm_cache_key(
    profile: str,
    addr: str,
    kind: str = "restore",
    model: str = "",
) -> str:
    safe_profile = (profile or "generic").replace("/", "_")
    safe_model = (model or "unknown").replace(":", "_").replace("/", "_")
    return f"llm/{LLM_PROMPT_VER}/{safe_profile}/{safe_model}/{kind}/{addr}"


def run(config: AppConfig) -> int:
    run_dir = setup_logging(config.output_dir, config.log_level)
    logger.info("Pipeline (Ghidra-only) started")

    try:
        pack = get_domain_pack(config.domain_pack)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2
    logger.info("domain_pack=%s", pack.name)

    metrics = RunMetrics(
        domain_pack=pack.name,
        scoring_mode=config.scoring_mode,
    )

    binary_path = Path(config.binary_path)
    if not binary_path.exists():
        logger.error("Binary file not found: %s", binary_path)
        return 2

    binary_md5 = compute_file_md5(binary_path)
    logger.info("Binary md5: %s", binary_md5)

    t0 = time.perf_counter()
    triage = triage_binary(binary_path)
    metrics.mark_stage("triage", t0)
    metrics.triage_profile = triage.profile
    logger.info("Triage: %s profile=%s", triage.summary, triage.profile)

    _save_json(
        run_dir / "binary_info.json",
        {
            "path": str(binary_path),
            "size": binary_path.stat().st_size,
            "md5": binary_md5,
            "domain_pack": pack.name,
            "triage": triage.to_dict(),
        },
    )
    _save_json(run_dir / "triage.json", triage.to_dict())

    cache: Optional[FileCache] = None
    if config.use_cache:
        cache = FileCache(Path(config.output_dir) / "cache" / binary_md5)
        logger.info("Cache directory: %s", cache.root)

    try:
        # 1. Единый дамп из Ghidra
        t0 = time.perf_counter()
        ghidra = cache.get(GHIDRA_CACHE_KEY) if cache is not None else None
        from_cache = ghidra is not None
        if ghidra is None:
            ghidra = run_ghidra_decompile(
                ghidra_path=Path(config.ghidra_path),
                binary_path=binary_path,
                project_dir=Path(config.output_dir) / "ghidra" / binary_md5,
                script_dirs=[Path("scripts"), Path("src") / "ghidra"],
                out_json=run_dir / "ghidra_raw.json",
                timeout_sec=config.ghidra_timeout,
            )
            if cache is not None and ghidra:
                cache.put(GHIDRA_CACHE_KEY, ghidra)
        metrics.mark_stage("ghidra_cache" if from_cache else "ghidra", t0)

        functions = ghidra.get("functions", []) or []
        imports = ghidra.get("imports", []) or []
        strings = ghidra.get("strings", []) or []
        thunks = ghidra.get("thunks", []) or []
        if not functions:
            raise GhidraError("Ghidra dump has 0 functions")
        metrics.functions_total = len(functions)

        # Обогатить triage фактами из Ghidra
        triage = triage_binary(binary_path, ghidra=ghidra)
        metrics.triage_profile = triage.profile
        _save_json(run_dir / "triage.json", triage.to_dict())
        _save_json(
            run_dir / "binary_info.json",
            {
                "path": str(binary_path),
                "size": binary_path.stat().st_size,
                "md5": binary_md5,
                "domain_pack": pack.name,
                "triage": triage.to_dict(),
            },
        )

        _save_json(run_dir / "ghidra_raw.json", ghidra)
        _save_json(run_dir / "functions.json", functions)
        _save_json(run_dir / "imports.json", sorted(set(imports)))
        _save_json(run_dir / "strings.json", strings)

        logger.info(
            "ghidra: %d functions, %d imports, %d strings",
            len(functions), len(imports), len(strings),
        )

        # 2. Кандидаты
        candidates = [
            f for f in functions
            if config.min_function_size <= int(f.get("size", 0)) <= 50_000
        ]
        metrics.candidates = len(candidates)
        logger.info("candidates: %d", len(candidates))

        # 3. Скоринг
        t0 = time.perf_counter()
        ml_bundle = None
        effective_mode = "heuristic"
        if config.scoring_mode == "ml" and config.ml_weights_path:
            meta_p = Path(config.ml_weights_path)
            if meta_p.exists():
                try:
                    import joblib
                    meta = json.loads(meta_p.read_text(encoding="utf-8"))
                    ml_bundle = joblib.load(meta_p.with_name(meta["model_file"]))
                    logger.info(
                        "ML model loaded: %s (%d features)",
                        ml_bundle.get("model_type"),
                        len(ml_bundle.get("feature_keys", [])),
                    )
                    effective_mode = "ml"
                except Exception as exc:
                    logger.warning("Cannot load ML model (%s); fallback heuristic", exc)
            else:
                logger.warning("ml meta not found: %s; fallback heuristic", meta_p)

        if ml_bundle is not None:
            extra = set(ml_bundle.get("feature_keys", [])) - set(FEATURE_KEYS)
            if extra:
                logger.warning("ML model feature mismatch %s; fallback heuristic", sorted(extra))
                ml_bundle = None
                effective_mode = "heuristic"

        metrics.scoring_mode = effective_mode
        scorer = GhidraFunctionScorer(
            strings, functions,
            seed_score=config.hot_seed_score,
            ml_bundle=ml_bundle,
            thunks=thunks,
        )
        scored = scorer.score_all(candidates)
        metrics.mark_stage("score", t0)

        filtered_view = [
            {k: v for k, v in s.items() if k != "ghidra_code"}
            for s in scored
        ]
        _save_json(run_dir / "filtered.json", filtered_view)
        _save_json(
            run_dir / "features.json",
            [
                {
                    "address": s["address"],
                    "name": s["name"],
                    "score": s["score"],
                    "features": {k: s.get(k, 0) for k in FEATURE_KEYS},
                }
                for s in scored
            ],
        )

        print()
        print("=== ETAP 2 RESULT (GHIDRA-ONLY) ===")
        print(f"OK: функций всего: {len(functions)}")
        print(f"OK: импортов: {len(imports)}")
        print(f"OK: строк: {len(strings)}")
        print(f"OK: кандидатов: {len(candidates)}")
        print(f"OK: domain_pack: {pack.name}")
        print(f"OK: triage: {triage.summary} -> {triage.profile}")
        print()
        print("=== TOP-15 USER CODE CANDIDATES ===")
        for i, s in enumerate(scored[:15], 1):
            reasons = ", ".join(s["reasons"][:3])
            print(f"{i:2}. score={s['score']:8.3f}  {s['name']}  size={s['size']}  :: {reasons}")

        # 4. Этап 3: LLM-восстановление
        if config.use_llm:
            from src.agents.assembler import assemble
            from src.agents.restorer import CodeRestorerLLM
            from src.analysis.fidelity import check_function
            from src.llm.client import OllamaClient

            client = OllamaClient(
                base_url=config.ollama_url,
                model=config.model_name,
                timeout_sec=config.llm_timeout,
                num_ctx=config.llm_num_ctx,
            )
            restorer = CodeRestorerLLM(
                client,
                dump_dir=run_dir / "prompts",
                profile=triage.profile,
            )

            top = [s for s in scored if s["score"] > 0][: config.llm_top]
            metrics.llm_top = len(top)
            restored: List[Dict[str, Any]] = []

            guess_by_addr_init = {f["address"]: (f.get("name") or "") for f in functions}
            for t in thunks:
                if t.get("address"):
                    guess_by_addr_init[t["address"]] = t.get("name") or ""
            thunk_target_init = {
                t["address"]: t["target"] for t in thunks if t.get("target")
            }

            print()
            print("=== STAGE 3: LLM RESTORATION ===")
            t0 = time.perf_counter()
            for i, s in enumerate(top, 1):
                addr = s["address"]
                gh_code = s.get("ghidra_code", "") or ""
                print(
                    f"[{i}/{len(top)}] {s['name']} @ {addr} "
                    f"(ghidra {len(gh_code)} chars) ...",
                    flush=True,
                )

                cache_key = _llm_cache_key(
                    triage.profile, addr, "restore", model=config.model_name
                )
                data = cache.get(cache_key) if cache is not None else None
                from_llm_cache = data is not None
                if from_llm_cache:
                    metrics.llm_cache_hit += 1
                if data is None:
                    metrics.llm_attempted += 1
                    try:
                        max_retries = 2
                        for retry in range(max_retries):
                            try:
                                data = restorer.restore_with_refinement(
                                    s, gh_code, max_attempts=3,
                                    guess_by_addr=guess_by_addr_init,
                                    thunk_target=thunk_target_init,
                                )
                                break
                            except Exception as exc:
                                if "timed out" in str(exc).lower() and retry < max_retries - 1:
                                    logger.warning(
                                        "LLM timeout for %s, retry %d/%d",
                                        addr, retry + 1, max_retries,
                                    )
                                    data = None
                                else:
                                    logger.error("LLM failed for %s: %s", addr, exc)
                                    data = None
                                    break
                    except Exception as exc:
                        logger.error("LLM failed for %s: %s", addr, exc)
                        data = None
                    if cache is not None and data:
                        cache.put(cache_key, data)

                if not data:
                    if not from_llm_cache:
                        metrics.llm_fail += 1
                    print("    -> нет ответа (попытка fallback)")
                    try:
                        metrics.llm_attempted += 1
                        raw_response = restorer.client.generate(
                            f"Переведи этот Ghidra-код в C++:\n\n{gh_code}",
                            system="Ответь ТОЛЬКО C++ кодом, без JSON и пояснений.",
                        )
                        data = {
                            "classification": "user_code",
                            "guessed_name": None,
                            "purpose": "fallback restoration",
                            "evidence": [],
                            "cpp_code": raw_response,
                            "includes": [],
                            "confidence": 50,
                        }
                        metrics.llm_fallback += 1
                        logger.warning("Using fallback for %s", addr)
                    except Exception as exc:
                        metrics.llm_fail += 1
                        logger.error("Fallback failed for %s: %s", addr, exc)
                        print("    -> нет ответа (fallback тоже не сработал)")
                        continue
                else:
                    if not from_llm_cache:
                        metrics.llm_ok += 1

                cls = data.get("classification", "unknown")
                guess = data.get("guessed_name") or "-"
                conf = data.get("confidence", 0)
                print(f"    -> {cls} | {guess} | confidence {conf}")

                data["address"] = addr
                data["ghidra_name"] = s["name"]
                data["score"] = s["score"]
                data["literals"] = s.get("literals", [])
                data["ext_calls"] = s.get("ext_calls", [])
                data["callees"] = s.get("callees", [])
                restored.append(data)

            metrics.mark_stage("llm_restore", t0)
            _save_json(run_dir / "restored.json", restored)

            user_parts = [
                r for r in restored
                if r.get("classification") == "user_code"
                and (r.get("cpp_code") or "").strip()
            ]

            if user_parts:
                lines = ["// Восстановленный код (Ghidra-only + LLM)", ""]
                includes = set()
                for r in user_parts:
                    for inc in r.get("includes", []) or []:
                        includes.add(inc)
                for inc in sorted(includes):
                    lines.append(f"#include {inc}")
                if includes:
                    lines.append("")
                for r in user_parts:
                    lines.append("// " + "=" * 60)
                    guess = r.get("guessed_name") or r["ghidra_name"]
                    lines.append(
                        f"// guessed: {guess} @ {r['address']} "
                        f"(confidence {r.get('confidence')})"
                    )
                    lines.append("// " + "=" * 60)
                    lines.append((r.get("cpp_code") or "").strip())
                    lines.append("")
                (run_dir / "restored.cpp").write_text(
                    "\n".join(lines), encoding="utf-8"
                )
                print(f"OK: restored.cpp: {len(user_parts)} user-функций")

                t0 = time.perf_counter()
                preamble = make_preamble(
                    f"// restored_v2.cpp: symbol linking + struct dedup + noise removal"
                    f" [domain={pack.name} profile={triage.profile}]",
                    restored,
                    functions,
                    pack=pack,
                )
                v2_text, n2 = assemble(
                    restored, functions, thunks, pack=pack, preamble_lines=preamble
                )
                (run_dir / "restored_v2.cpp").write_text(v2_text, encoding="utf-8")
                metrics.mark_stage("assemble", t0)
                print(f"OK: restored_v2.cpp: {n2} user-функций")

                if config.polish:
                    from src.agents.polisher import CodePolisher

                    polisher = CodePolisher(client, pack=pack)
                    # Полная карта имён: Ghidra + угаданные LLM (единый fidelity)
                    name_by_addr = dict(guess_by_addr_init)
                    for r in restored:
                        g = (r.get("guessed_name") or "").strip()
                        if g and r.get("address"):
                            name_by_addr[r["address"]] = g
                    thunk_target = {
                        t["address"]: t["target"] for t in thunks if t.get("target")
                    }

                    v3_lines = make_preamble(
                        f"// restored_v3.cpp: polished C++17"
                        f" [domain={pack.name} profile={triage.profile}]",
                        restored,
                        functions,
                        pack=pack,
                    )

                    t0 = time.perf_counter()
                    for r in user_parts:
                        addr = r["address"]
                        call_tokens = _call_tokens(
                            r.get("callees") or [], name_by_addr, thunk_target
                        )
                        v2_code = r.get("cpp_code", "")
                        # ghidra_code нужен для const-check; берём из scored top
                        entry = dict(r)
                        src = next((x for x in top if x["address"] == addr), None)
                        if src and src.get("ghidra_code"):
                            entry["ghidra_code"] = src["ghidra_code"]
                        fid_v2 = check_function(entry, v2_code, call_tokens)

                        if fid_v2["fidelity"] >= 0.95:
                            logger.info(
                                "Skipping polish for %s: fidelity already %.3f",
                                addr, fid_v2["fidelity"],
                            )
                            metrics.polish_skipped += 1
                            code = v2_code
                            fid_v3 = fid_v2
                        else:
                            polish_key = _llm_cache_key(
                                triage.profile, addr, "polish", model=config.model_name
                            )
                            data = (
                                cache.get(polish_key)
                                if cache is not None else None
                            )
                            if data is not None:
                                metrics.llm_cache_hit += 1
                            if data is None:
                                metrics.polish_attempted += 1
                                try:
                                    data = polisher.polish(r.get("cpp_code") or "")
                                    if data:
                                        metrics.polish_ok += 1
                                    else:
                                        metrics.polish_fail += 1
                                except Exception as exc:
                                    logger.error("polish failed for %s: %s", addr, exc)
                                    data = None
                                    metrics.polish_fail += 1
                                if cache is not None and data:
                                    cache.put(polish_key, data)
                            code = (data or {}).get("cpp_code") or r.get("cpp_code") or ""
                            fid_v3 = check_function(entry, code, call_tokens)

                            if fid_v3["fidelity"] < fid_v2["fidelity"]:
                                logger.warning(
                                    "Polish degraded fidelity for %s: %.3f -> %.3f",
                                    addr, fid_v2["fidelity"], fid_v3["fidelity"],
                                )
                                code = v2_code
                                metrics.polish_rolled_back += 1
                                fid_v3 = fid_v2

                        guess = r.get("guessed_name") or r["ghidra_name"]
                        v3_lines += [
                            "// " + "=" * 60,
                            f"// polished: {guess} @ {addr} [fid={fid_v3['fidelity']:.3f}]",
                            "// " + "=" * 60,
                            code.strip(),
                            "",
                        ]

                    metrics.mark_stage("polish", t0)
                    (run_dir / "restored_v3.cpp").write_text(
                        "\n".join(v3_lines), encoding="utf-8"
                    )
                    print(f"OK: restored_v3.cpp: {len(user_parts)} функций")

                    # Fidelity + best-of v2/v3
                    t0 = time.perf_counter()
                    v2_text = (run_dir / "restored_v2.cpp").read_text(encoding="utf-8")
                    v3_text = (run_dir / "restored_v3.cpp").read_text(encoding="utf-8")

                    pat = r"// [^\n]*?@ (0x[0-9a-fA-F]+)[^\n]*\n// =+\n"
                    v2_by_addr = dict(zip(*[iter(re.split(pat, v2_text)[1:])] * 2))
                    v3_by_addr = dict(zip(*[iter(re.split(pat, v3_text)[1:])] * 2))

                    final_lines = [
                        f"// restored_final.cpp: best-of v2/v3 by fidelity [domain={pack.name}]",
                        "",
                    ]
                    report = []

                    for s in top:
                        addr = s["address"]
                        v2 = v2_by_addr.get(addr, "")
                        v3c = v3_by_addr.get(addr, "")
                        toks = _call_tokens(
                            s.get("callees") or [], name_by_addr, thunk_target
                        )
                        rep = check_function(s, v3c, toks)
                        chosen_v3 = bool(v3c) and not rep["drift"]
                        chosen = v3c if chosen_v3 else v2
                        report.append({**rep, "chosen": "v3" if chosen_v3 else "v2"})

                        final_lines.append("// " + "=" * 60)
                        final_lines.append(
                            f"// {name_by_addr.get(addr) or s['name']} @ {addr} "
                            f"[{'v3' if chosen_v3 else 'v2'}] fid={rep['fidelity']}"
                        )
                        final_lines.append("// " + "=" * 60)
                        final_lines.append(chosen.strip())
                        final_lines.append("")

                    metrics.record_fidelity(report)
                    metrics.mark_stage("fidelity", t0)
                    _save_json(run_dir / "fidelity.json", report)
                    (run_dir / "restored_final.cpp").write_text(
                        "\n".join(final_lines), encoding="utf-8"
                    )

                    print()
                    print("=== FIDELITY (v3 vs Ghidra facts) ===")
                    for r in report:
                        flag = "OK  " if r["chosen"] == "v3" else "V2  "
                        extra = ""
                        if r["drift"]:
                            extra = (
                                f" | lit={r['missing_literals'][:2]} "
                                f"ext={r['missing_ext'][:2]} "
                                f"cal={r['missing_calls'][:2]}"
                            )
                        elif r["missing_consts"]:
                            extra = f" | consts={r['missing_consts'][:3]}"
                        print(f"{flag} {r['address']} fid={r['fidelity']:.2f}{extra}")
                    print("OK: restored_final.cpp")

    except Exception:
        logger.exception("Pipeline failed")
        _save_json(run_dir / "metrics.json", metrics.to_dict())
        return 1

    _save_json(run_dir / "metrics.json", metrics.to_dict())
    for line in metrics.summary_lines():
        print(line)
    print(f"OK: артефакты: {run_dir}")
    return 0
