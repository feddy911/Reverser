"""Gym-only gated Q7 restore facts. Not live.

  py -m src.analysis.eval_restore_facts --dry-run
  py -m src.analysis.eval_restore_facts --run output/logs/run_<ts>

Does not call runner, does not bump p4/v6, does not emit corpus YAML,
does not invent mpz_ptr, does not put unique-imm leftover into the prompt.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "restore_facts_report.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_dry() -> Dict[str, Any]:
    from src.agents.critic import p8_restore_contract
    from src.agents.restorer import build_restore_prompt
    from src.analysis.restore_facts import FACTS_SECTION_TITLE, format_restore_facts
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    entry = {
        "address": "0x140001000",
        "name": "wrap",
        "ghidra_name": "FUN_wrap",
        "size": 16,
    }
    set_src = "void wrap(void) { __gmpz_set(zs); }\n"
    cmp_src = "void wrap(void) { __gmpz_cmp_ui(param_1); }\n"
    sites_set = {
        "sites": [{
            "iat_name": "__gmpz_set",
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [],
        }]
    }
    sites_cmp = {
        "sites": [{
            "iat_name": "__gmpz_cmp_ui",
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [["rdx", 1]],
        }]
    }
    iat = {
        "protos": [
            {"name": "__gmpz_set", "arity": 2,
             "slots": [["rcx", "mpz_ptr"], ["rdx", "mpz_srcptr"]]},
            {"name": "__gmpz_cmp_ui", "arity": 2,
             "slots": [["rcx", "mpz_srcptr"], ["rdx", "unsigned long"]]},
        ]
    }
    live = build_restore_prompt(entry, set_src)
    gated = build_restore_prompt(
        entry, set_src, call_sites=sites_set, iat_facts=iat
    )
    folded = format_restore_facts(cmp_src, sites_cmp, iat)
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "live_has_facts": FACTS_SECTION_TITLE in live,
        "gated_has_facts": FACTS_SECTION_TITLE in gated,
        "unique_imm_omitted": folded == "",
        "p8_gated": p8_restore_contract(gated),
        "need_llm": False,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and FACTS_SECTION_TITLE not in live
            and FACTS_SECTION_TITLE in gated
            and "mpz_ptr" not in gated
            and folded == ""
            and p8_restore_contract(gated)
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "Do not invent mpz_ptr. Unique imm stays sanitizer Q4."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.agents.critic import p8_restore_contract
    from src.agents.restorer import build_restore_prompt
    from src.analysis.call_sites import call_sites_from_bytes
    from src.analysis.iat_proto import iat_facts_from_exe
    from src.analysis.pe_image import pe_iat_name_by_va, read_va
    from src.analysis.restore_facts import (
        FACTS_SECTION_TITLE,
        format_restore_facts,
        leftover_unfilled,
    )
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
    n_with = 0
    callees: List[str] = []
    seen = set()
    mpz_hit = False
    p8_ok = True
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
        if not dump.strip():
            continue
        n_fn += 1
        blob = read_va(bin_path, va, sz) if bin_path.is_file() else b""
        sites = call_sites_from_bytes(
            blob, addr=addr, func_va=va, iat_by_va=iat_map
        )
        block = format_restore_facts(dump, sites, iat_facts)
        live = build_restore_prompt(fn, dump)
        gated = build_restore_prompt(
            fn, dump, call_sites=sites, iat_facts=iat_facts
        )
        if FACTS_SECTION_TITLE in live:
            p8_ok = False
        if "mpz_ptr" in (block or "") or "mpz_srcptr" in (block or ""):
            mpz_hit = True
        if not p8_restore_contract(gated):
            p8_ok = False
        if block:
            n_with += 1
            for name in leftover_unfilled(dump, sites, iat_facts):
                if name not in seen:
                    seen.add(name)
                    callees.append(name)
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "n_fn": n_fn,
        "n_with_facts": n_with,
        "callees": callees,
        "mpz_ptr_in_facts": mpz_hit,
        "p8_ok": p8_ok,
        "need_llm": False,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and n_with >= 1
            and "__gmpz_set" in callees
            and "__gmpz_cmp_ui" not in callees
            and not mpz_hit
            and p8_ok
        ),
        "note": (
            "Gym apply-only. Unique imm (cmp_ui) omitted. set leftover is facts. "
            "Live restore omits this. Do not bump p4. Do not invent mpz_ptr."
        ),
    }
    dest = run_dir / "restore_facts.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only gated Q7 restore facts (not live, not LLM)"
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
