"""Gym-only second decoder (objdump) vs pe_image call sites. Not live.

  py -m src.analysis.eval_second_decode --dry-run
  py -m src.analysis.eval_second_decode --run output/logs/run_<ts>

DisCo: agree/disagree on CALL offs, kind, callee, arg_regs, imm/lea.
Does not call runner, does not bump p4/v6, does not emit corpus YAML,
does not decompile C (no r2 pdc / RetDec / Hex-Rays).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "second_decode_report.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_dry() -> Dict[str, Any]:
    from src.analysis.eval_call_sites import WRAP_IMM, WRAP_LEA, WRAP_VA
    from src.analysis.second_decode import objdump_available, scan_and_objdump
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    imm = scan_and_objdump(
        WRAP_IMM,
        addr=f"0x{WRAP_VA:x}",
        func_va=WRAP_VA,
        dump_code="void wrap(void) { helper(xs); }\n",
    )
    lea = scan_and_objdump(
        WRAP_LEA,
        addr=f"0x{WRAP_VA:x}",
        func_va=WRAP_VA,
        dump_code="__gmpz_cmp_ui(param_1);\n",
    )
    have = objdump_available()
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "objdump_available": have,
        "imm_agree": bool(imm.get("compare") and imm["compare"].get("agree")),
        "lea_agree": bool(lea.get("compare") and lea["compare"].get("agree")),
        "c_leaked": bool(imm.get("c_leaked_into_facts") or lea.get("c_leaked_into_facts")),
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and not imm.get("c_leaked_into_facts")
            and (
                not have
                or (
                    imm.get("compare")
                    and imm["compare"].get("agree")
                    and lea.get("compare")
                    and lea["compare"].get("agree")
                )
            )
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "Objdump text is a decoder, not a second C. No r2 pdc."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.pe_image import read_va
    from src.analysis.second_decode import objdump_available, scan_and_objdump
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    run_dir = Path(run_dir)
    functions = _load_json(run_dir / "functions.json") or []
    binary_info = _load_json(run_dir / "binary_info.json") or {}
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
    want = {
        addr
        for addr, r in restored_by.items()
        if r.get("classification") in (None, "user_code")
        and (r.get("cpp_code") or "").strip()
    }
    n_fn = 0
    n_obj = 0
    n_agree = 0
    n_sites = 0
    disagree: List[str] = []
    for fn in functions:
        addr = str(fn.get("address") or "")
        if want and addr not in want:
            continue
        try:
            va = int(addr, 16)
            sz = int(fn.get("size") or 0)
        except (TypeError, ValueError):
            continue
        blob = read_va(bin_path, va, sz) if bin_path.is_file() else b""
        rec = scan_and_objdump(blob, addr=addr, func_va=va)
        n_fn += 1
        n_sites += len((rec.get("scan") or {}).get("sites") or [])
        if rec.get("objdump"):
            n_obj += 1
            if rec.get("compare") and rec["compare"].get("agree"):
                n_agree += 1
            else:
                disagree.append(addr)
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "n": n_fn,
        "n_objdump": n_obj,
        "n_agree": n_agree,
        "n_sites": n_sites,
        "disagree": disagree,
        "objdump_available": objdump_available(),
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "ok": LLM_PROMPT_VER == "p4" and GHIDRA_CACHE_KEY == "ghidra_full_v6",
        "note": (
            "Gym apply-only. DisCo pe_image vs objdump. Not a second C. "
            "Not live restore. runner.py does not consume this."
        ),
    }
    dest = run_dir / "second_decode.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only objdump vs pe_image call sites (not live, not C)"
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
