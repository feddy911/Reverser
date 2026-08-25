from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config import AppConfig
from src.logging_setup import setup_logging
from legacy.r2.cache import FileCache, compute_file_md5
from src.ghidra.headless import run_ghidra_decompile
from src.analysis.scorer import GhidraFunctionScorer


logger = logging.getLogger("revllm.pipeline")

GHIDRA_CACHE_KEY = "ghidra_full_v4"

FEATURE_KEYS = (
    "size", "n_local_callees", "n_ext_calls", "n_gmp", "n_stdio",
    "n_fileio", "n_iostream", "n_literals", "n_crt", "crt_ratio",
    "thunk_ratio", "is_fun_name", "is_thunk_name", "is_named", "n_callers",
    "is_crt_name", "is_stl_name", "is_lib_name",
    "hot_callers", "hot_callees",
)


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def run(config: AppConfig) -> int:
    run_dir = setup_logging(config.output_dir, config.log_level)

    logger.info("Pipeline (Ghidra-only) started")
    binary_path = Path(config.binary_path)

    if not binary_path.exists():
        logger.error("Binary file not found: %s", binary_path)
        return 2

    binary_md5 = compute_file_md5(binary_path)
    logger.info("Binary md5: %s", binary_md5)

    _save_json(
        run_dir / "binary_info.json",
        {
            "path": str(binary_path),
            "size": binary_path.stat().st_size,
            "md5": binary_md5,
        },
    )

    cache: Optional[FileCache] = None
    if config.use_cache:
        cache = FileCache(Path(config.output_dir) / "cache" / binary_md5)
        logger.info("Cache directory: %s", cache.root)

    try:
        # 1. Единый дамп из Ghidra
        ghidra = cache.get(GHIDRA_CACHE_KEY) if cache is not None else None
        if ghidra is None:
            try:
                ghidra = run_ghidra_decompile(
                    ghidra_path=Path(config.ghidra_path),
                    binary_path=binary_path,
                    project_dir=Path(config.output_dir) / "ghidra",
                    script_dirs=[Path("scripts"), Path("src") / "ghidra"],
                    out_json=run_dir / "ghidra_raw.json",
                    timeout_sec=config.ghidra_timeout,
                )
            except Exception as exc:
                logger.error("Ghidra failed: %s", exc)
                ghidra = {}
            if cache is not None and ghidra:
                cache.put(GHIDRA_CACHE_KEY, ghidra)

        functions = ghidra.get("functions", []) or []
        imports = ghidra.get("imports", []) or []
        strings = ghidra.get("strings", []) or []
        thunks = ghidra.get("thunks", []) or []

        _save_json(run_dir / "ghidra_raw.json", ghidra)  # снапшот даже из кэша
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
        logger.info("candidates: %d", len(candidates))

        # 3. Скоринг
        ml_weights = None
        if config.scoring_mode == "ml" and config.ml_weights_path:
            p = Path(config.ml_weights_path)
            if p.exists():
                try:
                    ml_weights = json.loads(p.read_text(encoding="utf-8"))
                    logger.info("ML weights loaded: %d features",
                                len(ml_weights.get("feature_keys", [])))
                except Exception as exc:
                    logger.warning("Cannot load ml weights (%s); fallback heuristic", exc)
            else:
                logger.warning("ml_weights_path not found: %s; fallback heuristic", p)
        if ml_weights is not None:
            extra = set(ml_weights.get("feature_keys", [])) - set(FEATURE_KEYS)
            if extra:
                logger.warning("ML weights feature mismatch %s; fallback heuristic", sorted(extra))
                ml_weights = None
        scorer = GhidraFunctionScorer(
            strings, functions,
            seed_score=getattr(config, "hot_seed_score", 60),
            ml_weights=ml_weights,
            thunks=thunks,
        )
        scored = scorer.score_all(candidates)

        filtered_view = [{k: v for k, v in s.items() if k != "ghidra_code"} for s in scored]
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
        print()
        print("=== TOP-15 USER CODE CANDIDATES ===")
        for i, s in enumerate(scored[:15], 1):
            reasons = ", ".join(s["reasons"][:3])
            print(f"{i:2}. score={s['score']:8.3f}  {s['name']}  size={s['size']}  :: {reasons}")

        # 4. Этап 3: LLM-восстановление
        if config.use_llm:
            from src.llm.client import OllamaClient
            from src.agents.restorer import CodeRestorerLLM

            client = OllamaClient(
                base_url=config.ollama_url,
                model=config.model_name,
                timeout_sec=config.llm_timeout,
                num_ctx=config.llm_num_ctx,
            )
            restorer = CodeRestorerLLM(client, dump_dir=run_dir / "prompts")

            top = [s for s in scored if s["score"] > 0][: config.llm_top]
            restored: List[Dict[str, Any]] = []

            print()
            print("=== STAGE 3: LLM RESTORATION ===")
            for i, s in enumerate(top, 1):
                addr = s["address"]
                gh_code = s.get("ghidra_code", "") or ""
                print(
                    f"[{i}/{len(top)}] {s['name']} @ {addr} "
                    f"(ghidra {len(gh_code)} chars) ...",
                    flush=True,
                )

                data = cache.get(f"llm/{addr}") if cache is not None else None
                if data is None:
                    try:
                        data = restorer.restore(s, gh_code)
                    except Exception as exc:
                        logger.error("LLM failed for %s: %s", addr, exc)
                        data = None
                    if cache is not None and data:
                        cache.put(f"llm/{addr}", data)

                if not data:
                    print("    -> нет ответа")
                    continue

                cls = data.get("classification", "unknown")
                guess = data.get("guessed_name") or "-"
                conf = data.get("confidence", 0)
                print(f"    -> {cls} | {guess} | confidence {conf}")

                data["address"] = addr
                data["ghidra_name"] = s["name"]
                data["score"] = s["score"]
                restored.append(data)

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

                from src.agents.assembler import assemble
                v2_text, n2 = assemble(restored, functions, thunks)
                (run_dir / "restored_v2.cpp").write_text(v2_text, encoding="utf-8")
                print(f"OK: restored_v2.cpp: {n2} user-функций")

                if getattr(config, "polish", False):
                    from src.agents.polisher import CodePolisher
                    polisher = CodePolisher(client)
                    v3: List[str] = [
                        "// restored_v3.cpp: polished C++17",
                        "#include <cstdio>", "#include <cstring>", "#include <iostream>",
                        "#include <string>", "#include <vector>", "#include <chrono>",
                        "#include <fstream>", "#include <gmp.h>", "",
                    ]
                    for r in user_parts:
                        addr = r["address"]
                        data = cache.get(f"llm/polish_{addr}") if cache is not None else None
                        if data is None:
                            try:
                                data = polisher.polish(r.get("cpp_code") or "")
                            except Exception as exc:
                                logger.error("polish failed for %s: %s", addr, exc)
                                data = None
                            if cache is not None and data:
                                cache.put(f"llm/polish_{addr}", data)
                        code = (data or {}).get("cpp_code") or r.get("cpp_code") or ""
                        guess = r.get("guessed_name") or r["ghidra_name"]
                        v3 += ["// " + "=" * 60,
                               f"// polished: {guess} @ {addr}",
                               "// " + "=" * 60,
                               code.strip(), ""]
                    (run_dir / "restored_v3.cpp").write_text("\n".join(v3), encoding="utf-8")
                    print(f"OK: restored_v3.cpp: {len(user_parts)} функций")

        print(f"OK: артефакты: {run_dir}")
        return 0

    except Exception:
        logger.exception("Pipeline failed")
        return 1