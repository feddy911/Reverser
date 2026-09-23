"""Gym-only skip-forever → Q0–Q2 feedback. Not live.

  py -m src.analysis.eval_feedback --dry-run
  py -m src.analysis.eval_feedback --run output/logs/run_<ts>

Does not call runner, does not bump p4/v6, does not emit corpus YAML,
does not LLM-fix skip-forever, does not invent mpz_ptr.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "feedback_report.json"
_RE_FN_HDR = re.compile(
    r"^// (FUN_[0-9A-Fa-f]+) @ (0x[0-9A-Fa-f]+)\s*$"
)


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_dry() -> Dict[str, Any]:
    from src.analysis.feedback_facts import plan_one
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    cmp_msg = (
        "too few arguments to function "
        "'int __gmpz_cmp_ui(mpz_srcptr, long unsigned int)'"
    )
    sites = {
        "sites": [{
            "iat_name": "__gmpz_cmp_ui",
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [["rdx", 1]],
        }]
    }
    iat = {"protos": [{"name": "__gmpz_cmp_ui", "arity": 2}]}
    hit = plan_one(
        "ghidra truncated mpz call",
        cmp_msg,
        "void wrap(void) { __gmpz_cmp_ui(param_1); }\n",
        call_sites=sites,
        iat_facts=iat,
    )
    miss = plan_one(
        "ghidra truncated mpz call",
        cmp_msg,
        "void wrap(void) { __gmpz_cmp_ui(param_1); }\n",
    )
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "hit_action": hit["action"],
        "miss_action": miss["action"],
        "need_llm": bool(hit.get("need_llm") or miss.get("need_llm")),
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and hit["action"] == "leftover"
            and miss["action"] == "skip_forever"
            and not hit.get("need_llm")
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "Do not invent mpz_ptr. Do not LLM-fix skip-forever."
        ),
    }
    return rec


def _tu_fn_ranges(text: str) -> List[Tuple[int, int, int]]:
    """(va, start_line, end_line) from assemble headers. Lines are 1-based."""
    lines = (text or "").splitlines()
    marks: List[Tuple[int, int]] = []
    for i, line in enumerate(lines, 1):
        m = _RE_FN_HDR.match(line)
        if not m:
            continue
        try:
            va = int(m.group(2), 16)
        except ValueError:
            continue
        marks.append((va, i))
    out: List[Tuple[int, int, int]] = []
    for i, (va, start) in enumerate(marks):
        end = marks[i + 1][1] - 1 if i + 1 < len(marks) else len(lines)
        out.append((va, start, end))
    return out


def _va_for_line(ranges: Sequence[Tuple[int, int, int]], line: int) -> int:
    for va, start, end in ranges:
        if start <= line <= end:
            return va
    return 0


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.call_sites import call_sites_from_bytes
    from src.analysis.dat_facts import candidate_vas_for_fn, dat_facts_from_exe
    from src.analysis.feedback_facts import plan_one
    from src.analysis.iat_proto import iat_facts_from_exe
    from src.analysis.pe_image import pe_iat_name_by_va, read_va
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    run_dir = Path(run_dir)
    binary_info = _load_json(run_dir / "binary_info.json") or {}
    functions = _load_json(run_dir / "functions.json") or []
    restored = _load_json(run_dir / "restored.json") or []
    compile_rep = _load_json(run_dir / "compile.json") or {}
    tu_path = run_dir / "restored_final.cpp"
    tu_text = tu_path.read_text(encoding="utf-8", errors="replace") if tu_path.exists() else ""
    ranges = _tu_fn_ranges(tu_text)
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
    errors = compile_rep.get("errors") or []
    from src.agents.compiler import skip_forever_reason

    want = {
        addr
        for addr, r in restored_by.items()
        if r.get("classification") in (None, "user_code")
        and (r.get("cpp_code") or "").strip()
    }
    by_va: Dict[int, Dict[str, Any]] = {}
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
        restored_cpp = str((restored_by.get(addr) or {}).get("cpp_code") or "")
        blob = read_va(bin_path, va, sz) if bin_path.is_file() else b""
        sites = call_sites_from_bytes(
            blob, addr=addr, func_va=va, iat_by_va=iat_map
        )
        code = dump or restored_cpp
        vas = candidate_vas_for_fn(
            dump_code=code, func_bytes=blob, func_va=va
        )
        dats = dat_facts_from_exe(bin_path, vas) if bin_path.is_file() else None
        by_va[va] = {"code": code, "call_sites": sites, "dat_facts": dats}
    n_in = 0
    n_leftover = 0
    n_skip = 0
    n_filled = 0
    kinds: List[str] = []
    seen_k = set()
    rows: List[Dict[str, Any]] = []
    for err in errors:
        msg = str(err.get("message") or "").strip()
        if not msg:
            continue
        reason = skip_forever_reason(msg)
        if not reason:
            continue
        n_in += 1
        try:
            line = int(err.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        va = _va_for_line(ranges, line)
        unit = by_va.get(va) or {}
        one = plan_one(
            reason,
            msg,
            str(unit.get("code") or ""),
            call_sites=unit.get("call_sites"),
            iat_facts=iat_facts,
            dat_facts=unit.get("dat_facts"),
        )
        rec = {
            "reason": reason,
            "action": one["action"],
            "kind": str(one.get("kind") or ""),
            "filled": bool(one.get("filled")),
            "callee": str(one.get("callee") or ""),
            "need_llm": bool(one.get("need_llm")),
        }
        rows.append(rec)
        if one["action"] == "leftover":
            n_leftover += 1
            if one.get("filled"):
                n_filled += 1
            k = str(one.get("kind") or "")
            if k and k not in seen_k:
                seen_k.add(k)
                kinds.append(k)
        else:
            n_skip += 1
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "n_skip_in": n_in,
        "n_leftover": n_leftover,
        "n_skip": n_skip,
        "n_filled": n_filled,
        "kinds": kinds,
        "rows": rows,
        "need_llm": False,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and n_filled == 1
            and n_leftover >= 1
            and not any(r.get("need_llm") for r in rows)
        ),
        "note": (
            "Gym apply-only. Planner, not chat. Do not LLM-fix skip-forever. "
            "Do not invent mpz_ptr. Empty bag is not a hit."
        ),
    }
    dest = run_dir / "feedback.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only skip-forever feedback vs Q0-Q2 (not live, not LLM)"
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
