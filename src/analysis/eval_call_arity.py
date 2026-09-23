"""Gym-only leftover call arity vs CallSiteFacts / IAT proto. Not live.

  py -m src.analysis.eval_call_arity --dry-run
  py -m src.analysis.eval_call_arity --run output/logs/run_<ts>

Does not call runner, does not bump p4/v6, does not emit corpus YAML,
does not invent the missing immediate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "call_arity_report.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_dry() -> Dict[str, Any]:
    from src.analysis.ghidra_cpp import leftover_call_arity
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    helper = (
        "void helper(longlong *xs);\n"
        "void wrap(void) { longlong *xs; helper(xs); }\n"
    )
    sites = {
        "sites": [
            {
                "off": 12,
                "arg_regs": ["rcx", "rdx"],
                "imm_slots": [["rdx", 2]],
                "iat_name": "",
            }
        ]
    }
    iat = {
        "protos": [
            {"name": "__gmpz_cmp_ui", "arity": 2, "variadic": False}
        ]
    }
    gmp = "void wrap(void) { __gmpz_cmp_ui(param_1); }\n"
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "helper_hits": leftover_call_arity(helper, sites, None),
        "empty_bag": leftover_call_arity(helper, None, None),
        "gmp_hits": leftover_call_arity(gmp, None, iat),
        "sleep_gmp": leftover_call_arity(gmp, None, {"protos": []}),
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and leftover_call_arity(helper, sites, None) == ["helper"]
            and leftover_call_arity(helper, None, None) == []
            and leftover_call_arity(gmp, None, iat) == ["__gmpz_cmp_ui"]
            and leftover_call_arity(gmp, None, {"protos": []}) == []
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "Do not invent the missing immediate. Empty bag is not a class."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.call_sites import call_sites_from_bytes
    from src.analysis.ghidra_cpp import leftover_call_arity
    from src.analysis.iat_proto import iat_facts_from_exe
    from src.analysis.pe_image import pe_iat_name_by_va, read_va
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    run_dir = Path(run_dir)
    binary_info = _load_json(run_dir / "binary_info.json") or {}
    functions = _load_json(run_dir / "functions.json") or []
    restored = _load_json(run_dir / "restored.json") or []
    restored_by = {
        str(r.get("address") or ""): r
        for r in restored
        if isinstance(r, dict)
    }
    binary = str(binary_info.get("path") or "")
    bin_path = Path(binary)
    if binary and not bin_path.is_file():
        bin_path = ROOT / binary
    iat_facts = iat_facts_from_exe(bin_path) if bin_path.is_file() else iat_facts_from_exe("")
    iat_map = pe_iat_name_by_va(bin_path.read_bytes()) if bin_path.is_file() else {}
    want = {
        addr
        for addr, r in restored_by.items()
        if r.get("classification") in (None, "user_code")
        and (r.get("cpp_code") or "").strip()
    }
    n_fn = 0
    n_hit = 0
    tokens: List[str] = []
    seen = set()
    for fn in functions:
        addr = str(fn.get("address") or "")
        if want and addr not in want:
            continue
        try:
            va = int(addr, 16)
            sz = int(fn.get("size") or 0)
        except (TypeError, ValueError):
            continue
        dump = str(fn.get("ghidra_code") or "")
        blob = read_va(bin_path, va, sz) if bin_path.is_file() else b""
        sites = call_sites_from_bytes(
            blob, addr=addr, func_va=va, iat_by_va=iat_map
        )
        hits = leftover_call_arity(dump, sites, iat_facts)
        n_fn += 1
        if hits:
            n_hit += 1
            for t in hits:
                if t not in seen:
                    seen.add(t)
                    tokens.append(t)
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "n": n_fn,
        "n_hit": n_hit,
        "n_iat_proto": len(iat_facts.protos),
        "tokens": tokens,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "invented_immediate": False,
        "ok": LLM_PROMPT_VER == "p4" and GHIDRA_CACHE_KEY == "ghidra_full_v6",
        "note": (
            "Gym apply-only. Not a recipe catalog. Not live restore. "
            "Do not invent immediates. Empty bag is not a class."
        ),
    }
    dest = run_dir / "call_arity.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only leftover call arity (not live, not invent immediate)"
    )
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--run", type=Path, default=None, help="output/logs/run_* directory")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = p.parse_args(argv)
    if args.dry_run or not args.run:
        rec = run_dry()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        rec["out"] = str(args.out)
    else:
        rec = run_on_dir(args.run)
    print(json.dumps(rec, indent=2))
    return 0 if rec.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
