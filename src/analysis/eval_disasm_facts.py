"""Gym-only disasm facts vs Ghidra leftover classes. Not live.

  py -m src.analysis.eval_disasm_facts --dry-run
  py -m src.analysis.eval_disasm_facts --run output/logs/run_<ts>

Reads functions.json + binary_info + restored.json from a run directory.
Writes disasm_facts.json next to the run. Does not call runner, does not
bump p4/v6, does not emit corpus YAML.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "disasm_facts_report.json"
WRAP_BYTES = bytes.fromhex("4883ec40488d4de0488945e0c3")


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_dry() -> Dict[str, Any]:
    from src.analysis.disasm_facts import scan_and_capstone
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    wrap = {
        "address": "0x140001000",
        "size": len(WRAP_BYTES),
        "callees": ["0x140002000"],
        "ghidra_code": "void wrap(void) {\n  longlong ****xs[8];\n  (void)xs;\n}\n",
    }
    rec = scan_and_capstone(
        wrap,
        func_bytes=WRAP_BYTES,
        dump_code=str(wrap["ghidra_code"]),
    )
    rec["dry_run"] = True
    rec["live_prompt_ver"] = LLM_PROMPT_VER
    rec["ghidra_cache_key"] = GHIDRA_CACHE_KEY
    rec["ok"] = (
        LLM_PROMPT_VER == "p4"
        and GHIDRA_CACHE_KEY == "ghidra_full_v6"
        and rec["scan"]["stack_alloc"] == 0x40
        and rec["scan"]["lea_arg_slots"] == [-0x20]
        and rec["scan"]["qword_store_slots"] == [-0x20]
        and "extra_star_vs_outparam" in rec["vs_c"]
        and not rec["c_leaked_into_facts"]
        and (
            rec.get("capstone") is None
            or (
                rec["compare"]["agree"]
                and rec["capstone"]["source"] == "capstone"
            )
        )
    )
    rec["note"] = (
        "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this."
    )
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.disasm_facts import scan_and_capstone
    from src.analysis.pe_image import read_va
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
    rows: List[Dict[str, Any]] = []
    n_agree = 0
    n_cap = 0
    n_dump = 0
    n_rest = 0
    for fn in functions:
        addr = str(fn.get("address") or "")
        if want and addr not in want:
            continue
        try:
            va = int(addr, 16)
            sz = int(fn.get("size") or 0)
        except (TypeError, ValueError):
            continue
        blob = read_va(bin_path, va, sz) if binary else b""
        rest_c = str((restored_by.get(addr) or {}).get("cpp_code") or "")
        rec = scan_and_capstone(
            fn,
            func_bytes=blob,
            dump_code=str(fn.get("ghidra_code") or ""),
            restored_code=rest_c,
        )
        rec["address"] = addr
        rows.append(rec)
        if rec.get("capstone"):
            n_cap += 1
            if rec.get("compare") and rec["compare"].get("agree"):
                n_agree += 1
        if rec.get("vs_c_dump"):
            n_dump += 1
        if rec.get("vs_c_restored"):
            n_rest += 1
    out = {
        "run_dir": str(run_dir.resolve()),
        "n": len(rows),
        "n_capstone": n_cap,
        "n_agree": n_agree,
        "n_vs_c_dump": n_dump,
        "n_vs_c_restored": n_rest,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "ok": LLM_PROMPT_VER == "p4" and GHIDRA_CACHE_KEY == "ghidra_full_v6",
        "note": "Gym apply-only. Not a recipe catalog. Not live restore.",
        "items": rows,
    }
    dest = run_dir / "disasm_facts.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only capstone/pe_image facts vs leftover C (not live)"
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
    skip = ("items", "scan", "capstone")
    print(json.dumps({k: rec[k] for k in rec if k not in skip}, indent=2))
    return 0 if rec.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
