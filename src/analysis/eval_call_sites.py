"""Gym-only MS x64 call-site facts. Not live.

  py -m src.analysis.eval_call_sites --dry-run
  py -m src.analysis.eval_call_sites --run output/logs/run_<ts>

Writes call_sites.json next to the run. Does not call runner, does not
bump p4/v6, does not emit corpus YAML, does not invent mpz_ptr.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "call_sites_report.json"
WRAP_VA = 0x140001000
WRAP_CALLEE = 0x140002000


def _rel_call(prefix: bytes, func_va: int, callee: int) -> bytes:
    call_end = func_va + len(prefix) + 5
    rel = callee - call_end
    return prefix + b"\xe8" + struct.pack("<i", rel) + b"\xc3"


# sub rsp, 0x28; mov ecx, 1; mov edx, 2; call wrap_callee; ret
WRAP_IMM = _rel_call(
    bytes.fromhex("4883ec28b901000000ba02000000"),
    WRAP_VA,
    WRAP_CALLEE,
)
# lea rcx, [rbp-0x20]; xor edx, edx; call wrap_callee; ret
WRAP_LEA = _rel_call(
    bytes.fromhex("488d4de031d2"),
    WRAP_VA,
    WRAP_CALLEE,
)


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _wrap_ok(rec: Dict[str, Any], *, expect_imm: bool) -> bool:
    scan = rec.get("scan") or {}
    sites = scan.get("sites") or []
    if len(sites) != 1:
        return False
    site = sites[0]
    if site.get("callee_va") != f"0x{WRAP_CALLEE:x}":
        return False
    if site.get("iat_name"):
        return False
    regs = site.get("arg_regs") or []
    if "rcx" not in regs or "rdx" not in regs:
        return False
    if expect_imm:
        imm = {a: b for a, b in (site.get("imm_slots") or [])}
        if imm.get("rcx") != 1 or imm.get("rdx") != 2:
            return False
    else:
        lea = {a: b for a, b in (site.get("lea_slots") or [])}
        imm = {a: b for a, b in (site.get("imm_slots") or [])}
        if lea.get("rcx") != -0x20 or imm.get("rdx") != 0:
            return False
    if rec.get("c_leaked_into_facts"):
        return False
    cap = rec.get("capstone")
    if cap is None:
        return True
    return bool(rec.get("compare") and rec["compare"].get("agree"))


def run_dry() -> Dict[str, Any]:
    from src.analysis.call_sites import scan_and_capstone
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    imm = scan_and_capstone(
        WRAP_IMM,
        addr=f"0x{WRAP_VA:x}",
        func_va=WRAP_VA,
        dump_code="void wrap(void) { helper(xs); }\n",
    )
    lea = scan_and_capstone(
        WRAP_LEA,
        addr=f"0x{WRAP_VA:x}",
        func_va=WRAP_VA,
        dump_code="__gmpz_cmp_ui(param_1);\n",
    )
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "imm": imm,
        "lea": lea,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and _wrap_ok(imm, expect_imm=True)
            and _wrap_ok(lea, expect_imm=False)
            and not imm["scan"]["sites"][0]["iat_name"]
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "IAT names empty until Q1. Do not invent mpz_ptr."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.call_sites import scan_and_capstone
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
    n_sites = 0
    n_agree = 0
    n_cap = 0
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
        rec = scan_and_capstone(blob, addr=addr, func_va=va)
        rec["address"] = addr
        rows.append(rec)
        n_sites += len((rec.get("scan") or {}).get("sites") or [])
        if rec.get("capstone"):
            n_cap += 1
            if rec.get("compare") and rec["compare"].get("agree"):
                n_agree += 1
    out = {
        "run_dir": str(run_dir.resolve()),
        "n": len(rows),
        "n_sites": n_sites,
        "n_capstone": n_cap,
        "n_agree": n_agree,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "ok": LLM_PROMPT_VER == "p4" and GHIDRA_CACHE_KEY == "ghidra_full_v6",
        "note": "Gym apply-only. Not a recipe catalog. Not live restore. Not IAT proto.",
        "items": rows,
    }
    dest = run_dir / "call_sites.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only MS x64 call-site facts (not live, not second C)"
    )
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--run", type=Path, default=None, help="output/logs/run_* directory")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = p.parse_args(argv)
    if args.dry_run or not args.run:
        rec = run_dry()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        slim = {k: rec[k] for k in rec if k not in ("imm", "lea")}
        slim["imm_ok"] = _wrap_ok(rec["imm"], expect_imm=True)
        slim["lea_ok"] = _wrap_ok(rec["lea"], expect_imm=False)
        args.out.write_text(
            json.dumps({**slim, "imm": rec["imm"], "lea": rec["lea"]}, indent=2),
            encoding="utf-8",
        )
        rec["out"] = str(args.out)
        print(json.dumps({**slim, "out": rec["out"]}, indent=2))
        return 0 if rec.get("ok") else 1
    rec = run_on_dir(args.run)
    skip = ("items",)
    print(json.dumps({k: rec[k] for k in rec if k not in skip}, indent=2))
    return 0 if rec.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
