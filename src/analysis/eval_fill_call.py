"""Gym check for unique-immediate fill of truncated calls.

Live fill is emit_sanitized_restore scanning func_bytes. This module does
not call the runner, does not bump p4/v6, does not emit corpus YAML,
does not invent the missing immediate, does not bind T* vs U*.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "fill_call_report.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_dry() -> Dict[str, Any]:
    from src.analysis.ghidra_cpp import fill_truncated_call_imms, leftover_call_arity
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
    gmp = (
        "undefined8 __gmpz_cmp_ui(undefined8 param_1);\n"
        "void wrap(void) { __gmpz_cmp_ui(param_1); __gmpz_set(zs); }\n"
    )
    gmp_sites = {
        "sites": [
            {
                "iat_name": "__gmpz_cmp_ui",
                "arg_regs": ["rcx", "rdx"],
                "imm_slots": [["rdx", 1]],
            },
            {
                "iat_name": "__gmpz_set",
                "arg_regs": ["rcx", "rdx"],
                "imm_slots": [],
            },
        ]
    }
    iat = {
        "protos": [
            {
                "name": "__gmpz_cmp_ui",
                "arity": 2,
                "slots": [["rcx", "mpz_srcptr"], ["rdx", "unsigned long"]],
            },
            {
                "name": "__gmpz_set",
                "arity": 2,
                "slots": [["rcx", "mpz_ptr"], ["rdx", "mpz_srcptr"]],
            },
        ]
    }
    filled = fill_truncated_call_imms(helper, sites, None)
    gmp_filled = fill_truncated_call_imms(gmp, gmp_sites, iat)
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "helper_filled": "helper(xs, 2)" in filled,
        "empty_bag": fill_truncated_call_imms(helper, None, None) == helper,
        "gmp_cmp_filled": "__gmpz_cmp_ui(param_1, 1)" in gmp_filled,
        "gmp_set_untouched": "__gmpz_set(zs);" in gmp_filled
        and "__gmpz_set(zs," not in gmp_filled,
        "no_mpz_cast": "mpz_srcptr" not in gmp_filled and "mpz_ptr" not in gmp_filled,
        "formal_unsigned_long": "unsigned long" in gmp_filled,
        "leftover_after": leftover_call_arity(gmp_filled, gmp_sites, iat),
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and "helper(xs, 2)" in filled
            and fill_truncated_call_imms(helper, None, None) == helper
            and "__gmpz_cmp_ui(param_1, 1)" in gmp_filled
            and "__gmpz_set(zs);" in gmp_filled
            and "mpz_srcptr" not in gmp_filled
            and leftover_call_arity(gmp_filled, gmp_sites, iat) == ["__gmpz_set"]
        ),
        "note": (
            "Gym check. Live fill is emit_sanitized_restore from func_bytes, "
            "not the restore prompt. Do not bump LLM_PROMPT_VER. "
            "Do not invent the missing immediate. Do not bind T* vs U*."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.call_sites import call_sites_from_bytes
    from src.analysis.ghidra_cpp import fill_truncated_call_imms, leftover_call_arity
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
    n_filled = 0
    filled_tokens: List[str] = []
    leftover_after: List[str] = []
    seen_f = set()
    seen_l = set()
    invented_immediate = False
    mpz_cast = False
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
        n_fn += 1
        filled = fill_truncated_call_imms(dump, sites, iat_facts)
        if filled == dump:
            continue
        n_filled += 1
        before = leftover_call_arity(dump, sites, iat_facts)
        after = leftover_call_arity(filled, sites, iat_facts)
        for tok in before:
            if tok not in after and tok not in seen_f:
                seen_f.add(tok)
                filled_tokens.append(tok)
        for tok in after:
            if tok not in seen_l:
                seen_l.add(tok)
                leftover_after.append(tok)
        if "mpz_srcptr" in filled and "mpz_srcptr" not in dump:
            mpz_cast = True
        if "mpz_ptr" in filled and "mpz_ptr" not in dump:
            mpz_cast = True
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "n": n_fn,
        "n_filled": n_filled,
        "filled_tokens": filled_tokens,
        "leftover_after": leftover_after,
        "invented_immediate": invented_immediate,
        "mpz_cast": mpz_cast,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and not invented_immediate
            and not mpz_cast
        ),
        "note": (
            "Gym apply-only. Not a recipe catalog. Not live restore. "
            "Do not invent immediates. Empty bag is not a class. "
            "Do not bind T* vs U*."
        ),
    }
    dest = run_dir / "fill_call.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only unique-imm fill of truncated calls (not live)"
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
