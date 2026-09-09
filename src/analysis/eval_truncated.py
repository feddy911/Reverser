"""Scan restore-cache JSON for truncated cpp_code; optional Ollama continue.

  py -m src.analysis.eval_truncated --cache output/cache/<md5>
  py -m src.analysis.eval_truncated --cache output/cache/<md5> --continue-llm

Does not rewrite identifiers (no basic_st to basic_string). Does not write
back into the restore cache. Live runner already continues on cache-hit.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]


def iter_restore_json(cache_root: Path) -> List[Path]:
    if not cache_root.exists():
        return []
    return sorted(cache_root.glob("llm/**/restore/*.json"))


def scan_truncated(cache_root: Path) -> List[Dict[str, Any]]:
    from src.agents.restorer import ident_cut_head, looks_truncated_cpp, repair_restore_debris

    hits: List[Dict[str, Any]] = []
    for path in iter_restore_json(cache_root):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        code = str(data.get("cpp_code") or "")
        repaired = repair_restore_debris(code)
        if not looks_truncated_cpp(repaired) and not looks_truncated_cpp(code):
            continue
        tail = (ident_cut_head(repaired) or ident_cut_head(code) or repaired).rstrip()
        hits.append(
            {
                "path": str(path),
                "address": data.get("address") or path.stem,
                "guessed_name": data.get("guessed_name") or "",
                "truncated_raw": looks_truncated_cpp(code),
                "truncated_repaired": looks_truncated_cpp(repaired),
                "tail": tail[-120:],
            }
        )
    return hits


def continue_hits(
    hits: List[Dict[str, Any]],
    *,
    client: Any,
    system: str = "",
) -> List[Dict[str, Any]]:
    from src.agents.restorer import (
        continue_truncated_cpp,
        looks_truncated_cpp,
        repair_restore_debris,
    )

    out: List[Dict[str, Any]] = []
    for hit in hits:
        path = Path(hit["path"])
        data = json.loads(path.read_text(encoding="utf-8"))
        code = repair_restore_debris(str(data.get("cpp_code") or ""))
        got = continue_truncated_cpp(client, code, system)
        out.append(
            {
                **hit,
                "continued": True,
                "still_truncated": looks_truncated_cpp(got),
                "has_basic_string": "basic_string" in got,
                "kept_basic_st_prefix": "std::basic_st" in got or "basic_st" in got,
                "n_chars_before": len(code),
                "n_chars_after": len(got),
                "preview": got[-240:],
            }
        )
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Find truncated restore cache bodies")
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--continue-llm", action="store_true")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--config", type=Path, default=None)
    args = p.parse_args(argv)
    hits = scan_truncated(args.cache)
    rec: Dict[str, Any] = {
        "cache": str(args.cache),
        "n_restore_json": len(iter_restore_json(args.cache)),
        "n_truncated": len(hits),
        "hits": hits if not args.continue_llm else None,
        "note": "No ident rewrite. Cache is not updated.",
    }
    if args.continue_llm:
        from src.config import load_config
        from src.llm.client import OllamaClient
        from src.analysis.prompts import system_prompt_for

        cfg = load_config(args.config or (ROOT / "config.yaml"))
        client = OllamaClient(
            cfg.ollama_url,
            cfg.model_name,
            timeout_sec=cfg.llm_timeout,
            num_ctx=cfg.llm_num_ctx,
        )
        rec["continued"] = continue_hits(
            hits, client=client, system=system_prompt_for("generic")
        )
        rec["hits"] = None
    out = args.out or (ROOT / "output" / "truncated_report.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        f"restore_json={rec['n_restore_json']} truncated={rec['n_truncated']}"
    )
    show = rec.get("continued") or hits
    for h in show[:20]:
        print(f"  {h.get('address')} {h.get('guessed_name')} tail={h.get('tail')!r}")
        if h.get("continued"):
            print(
                f"    still_trunc={h.get('still_truncated')} "
                f"basic_string={h.get('has_basic_string')} "
                f"{h.get('n_chars_before')}->{h.get('n_chars_after')}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
