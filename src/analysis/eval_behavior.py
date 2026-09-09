"""I5: golden run of original CLI samples. Not a compile-gate and not recipes.

  py -m src.analysis.eval_behavior
  py -m src.analysis.eval_behavior --restored path/to/restored_final.cpp

Compares stable stdout of PointCloud / FibTimer / XorCipher originals.
Timing lines (elapsed_us) are masked. Do not add ghidra_cpp recipes from this.
A restored TU is optional: compile+run only when --restored is given.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "behavior_report.json"

_ELAPSED = re.compile(r"elapsed_us=\d+")


def mask_stdout(text: str) -> str:
    return _ELAPSED.sub("elapsed_us=<n>", text or "")


CASES: List[Dict[str, Any]] = [
    {
        "id": "pointcloud_default",
        "exe": "samples/PointCloud.exe",
        "argv": [],
        "expect_contains": [
            "=== PointCloud ===",
            "Nearest index:",
            "Path length:",
        ],
        "expect_exit": 0,
    },
    {
        "id": "fibtimer_n3",
        "exe": "samples/FibTimer.exe",
        "argv": ["3"],
        "expect_contains": [
            "=== FibTimer ===",
            "n=3",
            "Series: 0 1 1 2",
            "fib(n)=2",
        ],
        "expect_exit": 0,
    },
    {
        "id": "xorcipher_hi",
        "exe": "samples/XorCipher.exe",
        "argv": ["Hi", "0x01"],
        "expect_contains": [
            "=== XorCipher ===",
            "plain: Hi",
            "OK: round-trip matched",
        ],
        "expect_exit": 0,
    },
]


def run_exe(
    exe: Path,
    argv: Sequence[str],
    *,
    timeout_sec: float = 15.0,
    cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    if not exe.exists():
        return {
            "ok": False,
            "skipped": True,
            "reason": f"missing {exe}",
            "stdout": "",
            "exit": None,
        }
    try:
        proc = subprocess.run(
            [str(exe), *argv],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(cwd or ROOT),
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "skipped": False,
            "reason": "timeout",
            "stdout": "",
            "exit": None,
        }
    out = mask_stdout(proc.stdout or "")
    return {
        "ok": proc.returncode == 0,
        "skipped": False,
        "reason": "",
        "stdout": out,
        "stderr": (proc.stderr or "")[-500:],
        "exit": proc.returncode,
    }


def check_case(case: Dict[str, Any], run: Dict[str, Any]) -> Dict[str, Any]:
    if run.get("skipped"):
        return {**run, "id": case["id"], "missing": list(case["expect_contains"])}
    body = run.get("stdout") or ""
    missing = [s for s in case["expect_contains"] if s not in body]
    want_exit = case.get("expect_exit")
    exit_ok = want_exit is None or run.get("exit") == want_exit
    return {
        "id": case["id"],
        "ok": (not missing) and bool(exit_ok) and not run.get("skipped"),
        "skipped": False,
        "missing": missing,
        "exit": run.get("exit"),
        "exit_ok": exit_ok,
        "stdout": body,
    }


def eval_originals(root: Path = ROOT) -> Dict[str, Any]:
    rows = []
    for case in CASES:
        exe = root / case["exe"]
        run = run_exe(exe, list(case.get("argv") or []), cwd=root)
        rows.append(check_case(case, run))
    n_ok = sum(1 for r in rows if r.get("ok"))
    n_skip = sum(1 for r in rows if r.get("skipped"))
    return {
        "n_cases": len(rows),
        "n_ok": n_ok,
        "n_skip": n_skip,
        "ok": n_ok == len(rows) - n_skip and n_ok > 0 and n_skip == 0,
        "cases": rows,
        "note": "Original binaries only. Restored TU is --restored. Not a recipe source.",
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="I5 golden CLI runs (original samples)")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--restored", type=Path, default=None, help="unused in this slice")
    args = p.parse_args(argv)
    rec = eval_originals(ROOT)
    if args.restored:
        rec["restored"] = str(args.restored)
        rec["restored_note"] = (
            "Restored TU compare is not in this slice; originals only."
        )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: rec[k] for k in rec if k != "cases"}, indent=2))
    for row in rec["cases"]:
        flag = "OK" if row.get("ok") else ("SKIP" if row.get("skipped") else "FAIL")
        print(f"  {flag} {row['id']} missing={row.get('missing')}")
    return 0 if rec.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
