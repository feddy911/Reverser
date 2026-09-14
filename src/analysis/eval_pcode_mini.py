"""Optional p5 mini restore vs live p4 on the same fixture. Not live.

  py -m src.analysis.eval_pcode_mini --dry-run
  py -m src.analysis.eval_pcode_mini --ab
  py -m src.analysis.eval_pcode_mini --ab --config config.yaml

A/B: p4 = Ghidra C only (live path); p5 = same C plus high p-code.
``p5_wins`` only if p5 is ok and p4 is not. 14.09 mini A/B was a tie
(both C++ with printf, no IR leak). Live stays p4.
Does not bump ``LLM_PROMPT_VER``. ``CodeRestorerLLM.restore`` live path still
omits pcode. Do not copy this into ``runner.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE = ROOT / "tests" / "fixtures" / "mini_ghidra.json"
DEFAULT_OUT = ROOT / "output" / "pcode_mini_report.json"

# P-code dialect leaked as C++. A C++ ``return`` is not a leak.
PCODE_LEAK_MARKERS = (
    "(unique,",
    "(register,",
    "(const,",
    "COPY (",
    "STORE ",
    "LOAD ",
)


def load_fixture(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data.get("functions"):
        raise ValueError(f"Bad fixture: {path}")
    return data


def judge_cpp(code: str, *, ghidra_code: str = "", pcode: str = "") -> Dict[str, Any]:
    """Did the model emit C++, not p-code syntax? Names/literals from C dump."""
    body = code or ""
    leaks = [m for m in PCODE_LEAK_MARKERS if m in body]
    printf_in_c = "printf" in (ghidra_code or "")
    return {
        "n_chars": len(body),
        "pcode_leak": leaks,
        "has_printf": "printf" in body,
        "printf_required": printf_in_c,
        "ok": bool(body.strip()) and not leaks and (not printf_in_c or "printf" in body),
        "pcode_ops_shown": bool((pcode or "").strip()),
    }


def compare_ab(p4: Dict[str, Any], p5: Dict[str, Any]) -> Dict[str, Any]:
    """Strict win: p5 ok without IR leak, and p4 failed. Tie keeps live p4."""
    j4 = (p4 or {}).get("judge") or {}
    j5 = (p5 or {}).get("judge") or {}
    p4_ok = bool(j4.get("ok"))
    p5_ok = bool(j5.get("ok"))
    p5_leaks = list(j5.get("pcode_leak") or [])
    p4_leaks = list(j4.get("pcode_leak") or [])
    p5_clean = p5_ok and not p5_leaks
    wins = p5_clean and not p4_ok
    if wins:
        reason = "p5 ok without IR leak; p4 failed"
    elif p5_leaks:
        reason = "p5 leaked IR; live stays p4"
    elif p4_ok and p5_ok:
        reason = "tie: both emit C++ without IR leak; do not bump p4"
    elif p4_ok and not p5_ok:
        reason = "p5 worse than p4; live stays p4"
    elif not p4_ok and not p5_ok:
        reason = "both failed; live stays p4"
    else:
        reason = "live stays p4"
    return {
        "p4_ok": p4_ok,
        "p5_ok": p5_ok,
        "p4_leaks": p4_leaks,
        "p5_leaks": p5_leaks,
        "p5_wins": wins,
        "live_stays_p4": True,
        "reason": reason,
    }


def restore_fixture(
    entry: Dict[str, Any],
    *,
    client: Any,
    profile: str = "generic",
    use_pcode: bool = True,
) -> Dict[str, Any]:
    from src.agents.restorer import CodeRestorerLLM, PCODE_SECTION_TITLE, build_restore_prompt
    from src.analysis.pcode import entry_pcode

    ghidra_code = str(entry.get("ghidra_code") or "")
    pcode = entry_pcode(entry) if use_pcode else ""
    prompt = build_restore_prompt(
        entry, ghidra_code, profile=profile, pcode=pcode
    )
    restorer = CodeRestorerLLM(client, profile=profile)
    parsed = restorer.restore(entry, ghidra_code, pcode=pcode) or {}
    code = str(parsed.get("cpp_code") or "")
    judge = judge_cpp(code, ghidra_code=ghidra_code, pcode=pcode)
    return {
        "address": entry.get("address"),
        "name": entry.get("name"),
        "use_pcode": use_pcode,
        "prompt_has_pcode": PCODE_SECTION_TITLE in prompt,
        "classification": parsed.get("classification"),
        "cpp_code": code,
        "judge": judge,
    }


def run_mini(
    *,
    fixture: Path = DEFAULT_FIXTURE,
    out: Path = DEFAULT_OUT,
    dry_run: bool = False,
    ab: bool = True,
    config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    from src.agents.restorer import PCODE_SECTION_TITLE, build_restore_prompt
    from src.analysis.pcode import entry_pcode
    from src.pipeline.runner import LLM_PROMPT_VER

    dump = load_fixture(fixture)
    entry = dump["functions"][0]
    ghidra_code = str(entry.get("ghidra_code") or "")
    pcode = entry_pcode(entry)
    prompt_p4 = build_restore_prompt(entry, ghidra_code, pcode="")
    prompt_p5 = build_restore_prompt(entry, ghidra_code, pcode=pcode)
    rec: Dict[str, Any] = {
        "fixture": str(fixture),
        "live_prompt_ver": LLM_PROMPT_VER,
        "prompt_has_pcode": PCODE_SECTION_TITLE in prompt_p5,
        "p4_prompt_has_pcode": PCODE_SECTION_TITLE in prompt_p4,
        "p5_prompt_has_pcode": PCODE_SECTION_TITLE in prompt_p5,
        "dry_run": dry_run,
        "ab": ab,
        "note": "Not live. Do not bump LLM_PROMPT_VER. runner.py does not pass pcode.",
    }
    if dry_run:
        rec["ok"] = (
            bool(pcode.strip())
            and rec["p5_prompt_has_pcode"]
            and not rec["p4_prompt_has_pcode"]
            and LLM_PROMPT_VER == "p4"
        )
        rec["compare"] = {
            "p5_wins": False,
            "live_stays_p4": True,
            "reason": "dry-run: prompts only; live stays p4",
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
        return rec

    from src.config import load_config
    from src.llm.client import OllamaClient

    cfg = load_config(config_path or (ROOT / "config.yaml"))
    client = OllamaClient(
        cfg.ollama_url,
        cfg.model_name,
        timeout_sec=cfg.llm_timeout,
        num_ctx=cfg.llm_num_ctx,
    )
    if ab:
        rec["restore_p4"] = restore_fixture(entry, client=client, use_pcode=False)
        rec["restore_p5"] = restore_fixture(entry, client=client, use_pcode=True)
        rec["compare"] = compare_ab(rec["restore_p4"], rec["restore_p5"])
        rec["restore"] = rec["restore_p5"]
        rec["ok"] = LLM_PROMPT_VER == "p4" and rec["compare"]["live_stays_p4"]
        rec["cpp_preview"] = (rec["restore_p5"].get("cpp_code") or "")[:800]
        rec["cpp_preview_p4"] = (rec["restore_p4"].get("cpp_code") or "")[:800]
    else:
        rec["restore"] = restore_fixture(entry, client=client, use_pcode=True)
        rec["ok"] = bool(rec["restore"]["judge"]["ok"]) and rec["live_prompt_ver"] == "p4"
        rec["cpp_preview"] = (rec["restore"].get("cpp_code") or "")[:800]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    return rec


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="p5 mini restore A/B vs live p4 (not live)")
    p.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--ab",
        action="store_true",
        default=True,
        help="restore p4 (no IR) and p5 (p-code) on the same fixture (default)",
    )
    p.add_argument(
        "--p5-only",
        action="store_true",
        help="restore with p-code only (legacy mini path)",
    )
    p.add_argument("--config", type=Path, default=None)
    args = p.parse_args(argv)
    rec = run_mini(
        fixture=args.fixture,
        out=args.out,
        dry_run=args.dry_run,
        ab=not args.p5_only,
        config_path=args.config,
    )
    skip = ("restore", "restore_p4", "restore_p5", "cpp_preview", "cpp_preview_p4")
    print(json.dumps({k: rec[k] for k in rec if k not in skip}, indent=2))
    if rec.get("compare"):
        print("compare:", json.dumps(rec["compare"], indent=2))
    if rec.get("restore_p4"):
        print("p4 judge:", json.dumps(rec["restore_p4"]["judge"], indent=2))
        print("--- cpp_code p4 ---")
        print(rec["restore_p4"].get("cpp_code") or "")
    if rec.get("restore_p5"):
        print("p5 judge:", json.dumps(rec["restore_p5"]["judge"], indent=2))
        print("--- cpp_code p5 ---")
        print(rec["restore_p5"].get("cpp_code") or "")
    elif rec.get("restore"):
        j = rec["restore"]["judge"]
        print("judge:", json.dumps(j, indent=2))
        print("--- cpp_code ---")
        print(rec["restore"].get("cpp_code") or "")
    return 0 if rec.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
