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
from src.analysis.scorer import GhidraFunctionScorer, select_llm_targets
from src.analysis.triage import triage_binary
from src.config import AppConfig
from src.domains.pack import NONE_PACK
from src.ghidra.headless import GhidraError, run_ghidra_decompile
from src.logging_setup import setup_logging
from src.pipeline.metrics import RunMetrics

logger = logging.getLogger("revllm.pipeline")
GHIDRA_CACHE_KEY = "ghidra_full_v6"
# Bump when restorer/polisher prompts or fidelity contract change.
LLM_PROMPT_VER = "p4"


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


def _corpus_cases() -> List[Any]:
    try:
        from src.analysis.corpus import load_corpus
        return load_corpus()
    except Exception as exc:
        logger.warning("corpus not loaded: %s", exc)
        return []


def _per_function_compile(
    data: Dict[str, Any],
    *,
    restorer: Any,
    functions: List[Dict[str, Any]],
    run_dir: Path,
    config: AppConfig,
    metrics: RunMetrics,
    cache: Optional[Any],
    profile: str,
    addr: str,
    corpus_cases: Optional[List[Any]] = None,
) -> None:
    """Syntax-check one restored function; optional LLM fix (Phase 2).

    Compile-fix writes compile_fn/*_fix.cpp and cache kind=compile_fn_fix.
    It must not overwrite data['cpp_code'] or the restore cache key.
    """
    if data.get("classification") != "user_code":
        return
    body = (data.get("cpp_code") or "").strip()
    if not body:
        return
    from src.analysis.compile_verify import compile_snippet
    from src.analysis.ghidra_cpp import extract_named_function, sanitize_ghidra_cpp
    from src.analysis.includes import make_preamble

    fname = (data.get("guessed_name") or data.get("ghidra_name") or "").strip()
    if fname:
        body = extract_named_function(body, fname)
    body = sanitize_ghidra_cpp(body)
    data["cpp_code"] = body

    preamble = make_preamble(
        f"// per-function compile {addr}",
        [data],
        functions,
    )
    crep = compile_snippet(
        body,
        preamble_lines=preamble,
        work_dir=run_dir / "compile_fn",
        name=addr,
        compiler=config.cxx_compiler,
        timeout_sec=config.compile_timeout,
    )
    data["compile_ok"] = bool(crep.ok)
    data["compile_n_errors"] = crep.n_errors
    if not crep.attempted:
        return
    if crep.ok:
        metrics.compile_fn_ok += 1
        print("    -> compile ok", flush=True)
        return
    metrics.compile_fn_fail += 1
    print(f"    -> compile FAIL errors={crep.n_errors}", flush=True)
    if not (config.compile_fix and crep.errors):
        return
    from src.agents.compiler import match_errors, write_proposal

    decision = match_errors(crep.errors, corpus_cases or [])
    if decision.known_ids:
        print(
            f"    -> known dialect {', '.join(decision.known_ids[:4])}",
            flush=True,
        )
    if not decision.need_llm:
        metrics.compile_known_skip += 1
        print("    -> Compiler agent: skip LLM (all errors in corpus)", flush=True)
        return
    try:
        write_proposal(
            run_dir / "corpus_proposals",
            profile=profile,
            errors=crep.errors,
            snippet=body,
            addr=addr,
        )
        metrics.compiler_proposals += 1
    except Exception as exc:
        logger.warning("corpus proposal failed for %s: %s", addr, exc)
    try:
        metrics.llm_attempted += 1
        fixed = restorer.fix_compile(
            body, crep.errors, compiler=crep.compiler
        )
        if not fixed:
            metrics.llm_fail += 1
            return
        from src.agents.assembler import strip_int_dat_redecls
        fixed = strip_int_dat_redecls(fixed)
        crep2 = compile_snippet(
            fixed,
            preamble_lines=preamble,
            work_dir=run_dir / "compile_fn",
            name=addr + "_fix",
            compiler=config.cxx_compiler or crep.compiler,
            timeout_sec=config.compile_timeout,
        )
        data["compile_fix_ok"] = bool(crep2.ok)
        data["compile_fix_n_errors"] = crep2.n_errors
        if crep2.ok or (crep2.attempted and crep2.n_errors < crep.n_errors):
            metrics.compile_fn_fixed += 1
            metrics.llm_ok += 1
            print(
                f"    -> compile-fix errors {crep.n_errors} -> {crep2.n_errors}"
                f" ok={crep2.ok} (not applied to restore)",
                flush=True,
            )
            if cache is not None:
                cache.put(
                    _llm_cache_key(
                        profile, addr, "compile_fn_fix", model=config.model_name
                    ),
                    {"cpp_code": fixed, "compile_ok": bool(crep2.ok)},
                )
        else:
            metrics.llm_fail += 1
    except Exception as exc:
        metrics.llm_fail += 1
        logger.warning("per-function compile-fix failed for %s: %s", addr, exc)


def run(config: AppConfig) -> int:
    run_dir = setup_logging(config.output_dir, config.log_level)
    logger.info("Pipeline (Ghidra-only) started")

    pack = NONE_PACK
    logger.info("no sample-specific hints; includes from calls/DLLs only")

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
        print(f"OK: triage: {triage.summary} -> {triage.profile}")
        print()
        print("=== TOP-15 USER CODE CANDIDATES ===")
        for i, s in enumerate(scored[:15], 1):
            reasons = ", ".join(s["reasons"][:3])
            print(f"{i:2}. score={s['score']:8.3f}  {s['name']}  size={s['size']}  :: {reasons}")

        # 4. Этап 3: LLM-восстановление
        if config.use_llm:
            from src.agents.assembler import assemble, user_emit_order
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

            top, n_filtered = select_llm_targets(scored, config.llm_top)
            metrics.runtime_filtered = n_filtered
            metrics.llm_top = len(top)
            if n_filtered:
                logger.info(
                    "Runtime noise filtered from LLM top: %d (kept %d)",
                    n_filtered, len(top),
                )
            print()
            print("=== LLM TARGETS (CRT/STL filtered) ===")
            for i, s in enumerate(top, 1):
                print(f"{i:2}. score={s['score']:8.3f}  {s['name']}  @ {s['address']}")
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
            corpus_cases = _corpus_cases()
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
                                    best_of=config.llm_best_of,
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
                from src.analysis.platform import is_runtime_noise, looks_like_user_restore_name
                if (
                    cls in ("stl", "crt")
                    and looks_like_user_restore_name(s.get("name") or "")
                    and (data.get("cpp_code") or "").strip()
                ):
                    data["classification"] = "user_code"
                    cls = "user_code"
                    print("    -> reclass user_code (user-like name)")

                data["address"] = addr
                data["ghidra_name"] = s["name"]
                data["score"] = s["score"]
                data["literals"] = s.get("literals", [])
                data["ext_calls"] = s.get("ext_calls", [])
                data["callees"] = s.get("callees", [])
                if config.compile_verify and config.compile_per_function:
                    _per_function_compile(
                        data,
                        restorer=restorer,
                        functions=functions,
                        run_dir=run_dir,
                        config=config,
                        metrics=metrics,
                        cache=cache,
                        profile=triage.profile,
                        addr=addr,
                        corpus_cases=corpus_cases,
                    )
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
                    f" [profile={triage.profile}]",
                    restored,
                    functions,
                )
                v2_text, n2 = assemble(
                    restored, functions, thunks, preamble_lines=preamble
                )
                (run_dir / "restored_v2.cpp").write_text(v2_text, encoding="utf-8")
                metrics.mark_stage("assemble", t0)
                print(f"OK: restored_v2.cpp: {n2} user-функций")

                if config.polish:
                    from src.agents.polisher import CodePolisher

                    polisher = CodePolisher(client)
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
                        f" [profile={triage.profile}]",
                        restored,
                        functions,
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

                    from src.agents.assembler import assemble

                    report = []
                    emit = []
                    ordered = user_emit_order(user_parts)
                    by_addr_top = {s["address"]: s for s in top}
                    for r in ordered:
                        addr = r["address"]
                        s = by_addr_top.get(addr) or r
                        v2 = v2_by_addr.get(addr, "")
                        v3c = v3_by_addr.get(addr, "")
                        toks = _call_tokens(
                            s.get("callees") or [], name_by_addr, thunk_target
                        )
                        rep_v2 = check_function(s, v2, toks)
                        rep_v3 = check_function(s, v3c, toks) if v3c else None
                        use_v3 = bool(
                            rep_v3
                            and v3c.strip()
                            and rep_v3["fidelity"] >= rep_v2["fidelity"]
                            and not (
                                rep_v3["drift"] and not rep_v2["drift"]
                            )
                        )
                        if use_v3:
                            chosen, rep, tag = v3c, rep_v3, "v3"
                        else:
                            chosen, rep, tag = v2, rep_v2, "v2"
                        name = (
                            name_by_addr.get(addr)
                            or s.get("name")
                            or r.get("ghidra_name")
                        )
                        report.append({**rep, "chosen": tag})
                        item = dict(r)
                        item["cpp_code"] = chosen
                        item["guessed_name"] = name
                        emit.append(item)

                    preamble = make_preamble(
                        f"// restored_final.cpp: best-of v2/v3 by fidelity [profile={triage.profile}]",
                        emit,
                        functions,
                    )
                    final_text, _n = assemble(
                        emit, functions, thunks, preamble_lines=preamble
                    )

                    metrics.record_fidelity(report)
                    metrics.mark_stage("fidelity", t0)
                    _save_json(run_dir / "fidelity.json", report)
                    (run_dir / "restored_final.cpp").write_text(
                        final_text, encoding="utf-8"
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

                source_cpp = None
                for name in ("restored_final.cpp", "restored_v2.cpp", "restored.cpp"):
                    cand = run_dir / name
                    if cand.exists():
                        source_cpp = cand
                        break
                name_by_addr = dict(guess_by_addr_init)
                for r in restored:
                    g = (r.get("guessed_name") or "").strip()
                    if g and r.get("address"):
                        name_by_addr[r["address"]] = g
                thunk_target = {
                    t["address"]: t["target"] for t in thunks if t.get("target")
                }
                ghidra_by_addr = {s["address"]: s for s in top}
                tu_text = (
                    source_cpp.read_text(encoding="utf-8") if source_cpp else ""
                )
                from src.agents.critic import review_compile_fix, review_run

                assembled_ok = None
                if config.compile_verify and source_cpp is not None:
                    from src.analysis.compile_verify import compile_cpp
                    from src.agents.compiler import match_errors, write_proposal

                    t0 = time.perf_counter()
                    crep = compile_cpp(
                        source_cpp,
                        compiler=config.cxx_compiler,
                        timeout_sec=config.compile_timeout,
                    )
                    assembled_ok = bool(crep.ok) if crep.attempted else None
                    payload = crep.to_dict()
                    if (
                        not crep.ok
                        and crep.attempted
                        and config.compile_fix
                        and crep.errors
                    ):
                        decision = match_errors(crep.errors, corpus_cases)
                        payload["compiler_agent"] = {
                            "known_ids": decision.known_ids,
                            "n_unknown": len(decision.unknown),
                            "need_llm": decision.need_llm,
                        }
                        if decision.known_ids:
                            print(
                                "  known dialect: "
                                + ", ".join(decision.known_ids[:6]),
                                flush=True,
                            )
                        if not decision.need_llm:
                            metrics.compile_known_skip += 1
                            print(
                                "  Compiler agent: skip LLM (all errors in corpus)",
                                flush=True,
                            )
                        else:
                            try:
                                write_proposal(
                                    run_dir / "corpus_proposals",
                                    profile=triage.profile,
                                    errors=crep.errors,
                                    snippet=source_cpp.read_text(encoding="utf-8")[:4000],
                                    addr="tu",
                                )
                                metrics.compiler_proposals += 1
                            except Exception as exc:
                                logger.warning("TU corpus proposal failed: %s", exc)
                            try:
                                metrics.llm_attempted += 1
                                fixed = restorer.fix_compile(
                                    source_cpp.read_text(encoding="utf-8"),
                                    crep.errors,
                                    compiler=crep.compiler,
                                )
                                if fixed:
                                    from src.agents.assembler import strip_int_dat_redecls
                                    fixed = strip_int_dat_redecls(fixed)
                                    ident_ok, ident_reasons = review_compile_fix(
                                        fixed,
                                        user_parts,
                                        ghidra_by_addr=ghidra_by_addr,
                                    )
                                    if not ident_ok:
                                        print(
                                            "  critic REJECT compile-fix: "
                                            + "; ".join(ident_reasons),
                                            flush=True,
                                        )
                                        metrics.llm_fail += 1
                                        payload["compile_fix_rejected"] = ident_reasons
                                    else:
                                        fix_path = run_dir / "restored_compilefix.cpp"
                                        fix_path.write_text(fixed, encoding="utf-8")
                                        crep2 = compile_cpp(
                                            fix_path,
                                            compiler=config.cxx_compiler or crep.compiler,
                                            timeout_sec=config.compile_timeout,
                                        )
                                        payload["compile_fix"] = crep2.to_dict()
                                        if crep2.ok or (
                                            crep2.attempted
                                            and crep2.n_errors < crep.n_errors
                                        ):
                                            metrics.compile_fixed = True
                                            metrics.llm_ok += 1
                                        else:
                                            metrics.llm_fail += 1
                                else:
                                    metrics.llm_fail += 1
                            except Exception as exc:
                                metrics.llm_fail += 1
                                logger.warning("compile-fix LLM failed: %s", exc)
                    metrics.mark_stage("compile", t0)
                    metrics.compile_attempted = crep.attempted
                    metrics.compile_ok = bool(assembled_ok)
                    metrics.compile_n_errors = crep.n_errors
                    metrics.compile_skipped = crep.skipped_reason
                    payload["assembled_ok"] = assembled_ok
                    _save_json(run_dir / "compile.json", payload)
                    print()
                    print("=== COMPILE VERIFY ===")
                    if crep.skipped_reason and not crep.attempted:
                        print(f"SKIP: {crep.skipped_reason}")
                    else:
                        flag = "OK" if assembled_ok else "FAIL"
                        print(
                            f"{flag}: {crep.compiler} errors={crep.n_errors} "
                            f"assembled={assembled_ok} "
                            f"fixed={metrics.compile_fixed}"
                        )
                        for err in crep.errors[:8]:
                            print(
                                f"  {err.get('file')}:{err.get('line')}: "
                                f"{err.get('message')}"
                            )

                t_crit = time.perf_counter()
                verdict = review_run(
                    user_parts,
                    ghidra_by_addr=ghidra_by_addr,
                    name_by_addr=name_by_addr,
                    thunk_target=thunk_target,
                    tu_text=tu_text,
                    compile_ok=assembled_ok,
                    functions=functions,
                    thunks=thunks,
                )
                metrics.critic_accept = bool(verdict.accept)
                metrics.critic_reject = sum(
                    1 for f in verdict.functions if not f.accept
                )
                metrics.mark_stage("critic", t_crit)
                _save_json(run_dir / "critic.json", verdict.to_dict())
                if not config.polish:
                    _save_json(
                        run_dir / "fidelity.json",
                        [f.to_dict() for f in verdict.functions],
                    )
                    metrics.record_fidelity(
                        [
                            {"fidelity": f.fidelity, "address": f.address}
                            for f in verdict.functions
                        ]
                    )
                print()
                print("=== CRITIC ===")
                flag = "ACCEPT" if verdict.accept else "REJECT"
                print(
                    f"{flag}: identity={verdict.identity_ok} "
                    f"fidelity={verdict.fidelity_ok} "
                    f"compile={verdict.compile_ok} "
                    f"reject_fn={metrics.critic_reject}"
                )
                for reason in verdict.reasons[:8]:
                    print(f"  {reason}")

    except Exception:
        logger.exception("Pipeline failed")
        _save_json(run_dir / "metrics.json", metrics.to_dict())
        return 1

    _save_json(run_dir / "metrics.json", metrics.to_dict())
    for line in metrics.summary_lines():
        print(line)
    print(f"OK: артефакты: {run_dir}")
    return 0
