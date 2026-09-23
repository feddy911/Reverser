"""I5: golden run of original CLI samples, plus self-golden for console PE.

  py -m src.analysis.eval_behavior
  py -m src.analysis.eval_behavior --restored path/to/restored_final.cpp
  py -m src.analysis.eval_behavior --restored path/to/restored_final.cpp --case pointcloud_default

Named CASES: PointCloud / FibTimer / XorCipher. Unknown console PE: observe
THIS exe (empty argv, stdin closed). Empty stdout is not a pass. Timing
lines (elapsed_us) are masked. Do not add ghidra_cpp recipes from this.
``--restored`` compiles+links that TU and compares masked stdout to the
original exe for ``--case`` (default: pointcloud_default).
Stdlib/fs candidates live in eval/i5_probe_index.yaml; they are not CASES.
Path-like stdout is masked by mask_paths (probe_cohort --golden, mask: paths).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "behavior_report.json"

_ELAPSED = re.compile(r"elapsed_us=\d+")
_QUOTED_WINABS = re.compile(r'(?i)"[a-z]:(?:\\|/).*?"')
_UNQUOTED_WINABS = re.compile(r'(?i)(?<![.\w/])[a-z]:(?:\\+|/)[^\s\"\'<>|]+')
_ABS_UNIX = re.compile(r"/(?:home|tmp|usr|Users|cygdrive)/[^\s\"']+")


def mask_stdout(text: str) -> str:
    return _ELAPSED.sub("elapsed_us=<n>", text or "")


def _path_needles(raw: Path) -> List[str]:
    s = str(raw)
    win = s.replace("/", "\\")
    posix = s.replace("\\", "/")
    doubled = win.replace("\\", "\\\\")
    out: List[str] = []
    for needle in (doubled, win, posix, s):
        if needle and needle not in out:
            out.append(needle)
    return out


def mask_paths(text: str, *, root: Path = ROOT) -> str:
    """Replace host paths so filesystem golden stdout is comparable.

    libstdc++ quotes paths and doubles backslashes. Do not treat
    ``/bin\\cat`` as a UNC path. Not a sanitizer recipe.
    """
    body = text or ""
    for raw in (root, Path.cwd()):
        for needle in _path_needles(raw):
            body = body.replace(needle, "<path>")
    body = _QUOTED_WINABS.sub('"<path>"', body)
    body = _UNQUOTED_WINABS.sub("<path>", body)
    body = _ABS_UNIX.sub("<path>", body)
    return body


SELF_CLI = "self_cli"
SELF_CLI_TIMEOUT_SEC = 8.0


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


_WIN_AV = 0xC0000005


def _crash_reason(exit_code: Any) -> Optional[str]:
    """Windows AV and Unix SIGSEGV. Not a sanitizer class."""
    if exit_code is None:
        return None
    try:
        n = int(exit_code)
    except (TypeError, ValueError):
        return None
    if n == -11 or n == 139:
        return "process crashed (SIGSEGV)"
    u = n + (1 << 32) if n < 0 else n
    if (u & 0xFFFFFFFF) == _WIN_AV:
        return "process crashed (STATUS_ACCESS_VIOLATION)"
    return None


def case_for_binary(path: Path | str) -> Optional[Dict[str, Any]]:
    """Match a sample exe stem to CASES. Unknown binaries have no I5 golden."""
    stem = Path(path).stem.lower()
    if not stem:
        return None
    for case in CASES:
        if Path(case["exe"]).stem.lower() == stem:
            return case
    return None


def restored_kind(rec: Dict[str, Any]) -> str:
    if rec.get("skipped"):
        return "skipped"
    if rec.get("ok"):
        return "match"
    link = rec.get("link") or {}
    if link.get("skipped"):
        return "skipped"
    if not link.get("ok"):
        return "link_fail"
    if _crash_reason(rec.get("exit")):
        return "crash"
    if rec.get("stdout_match") is False:
        return "stdout_mismatch"
    return "fail"


def i5_summary(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": rec.get("id"),
        "ok": bool(rec.get("ok")),
        "skipped": bool(rec.get("skipped")),
        "kind": rec.get("kind") or restored_kind(rec),
        "reason": rec.get("reason") or "",
        "exit": rec.get("exit"),
        "stdout_match": bool(rec.get("stdout_match")),
        "contains_ok": bool(rec.get("contains_ok")),
        "exit_ok": bool(rec.get("exit_ok")),
        "link_ok": bool((rec.get("link") or {}).get("ok")),
        "not_compile_gate": True,
        "not_recipe_source": True,
        "source": rec.get("source") or rec.get("id") or "",
        "need_pin": False,
    }


def case_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    for case in CASES:
        if case["id"] == case_id:
            return case
    return None


def cli_case_for_binary(path: Path | str) -> Optional[Dict[str, Any]]:
    """Named I5 golden, or a console PE self-golden. GUI/unknown is not a case."""
    named = case_for_binary(path)
    if named is not None:
        return dict(named)
    p = Path(path)
    if not p.is_file():
        return None
    try:
        blob = p.read_bytes()
    except OSError:
        return None
    from src.analysis.pe_image import pe_is_console

    if not pe_is_console(blob):
        return None
    return {
        "id": SELF_CLI,
        "exe": str(p),
        "argv": [],
        "expect_contains": [],
        "expect_exit": None,
        "source": SELF_CLI,
        "not_recipe_source": True,
    }


def run_exe(
    exe: Path,
    argv: Sequence[str],
    *,
    timeout_sec: float = 15.0,
    cwd: Optional[Path] = None,
    stdin_devnull: bool = False,
) -> Dict[str, Any]:
    if not exe.exists():
        return {
            "ok": False,
            "skipped": True,
            "reason": f"missing {exe}",
            "stdout": "",
            "exit": None,
        }
    kwargs: Dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout_sec,
        "cwd": str(cwd or ROOT),
        "encoding": "utf-8",
        "errors": "replace",
    }
    if stdin_devnull:
        kwargs["stdin"] = subprocess.DEVNULL
    if sys.platform == "win32" and stdin_devnull:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            [str(exe), *argv],
            **kwargs,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "skipped": False,
            "reason": "timeout",
            "stdout": "",
            "exit": None,
        }
    except OSError as exc:
        return {
            "ok": False,
            "skipped": True,
            "reason": str(exc),
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


def observe_cli(
    path: Path | str,
    *,
    timeout_sec: float = SELF_CLI_TIMEOUT_SEC,
) -> Dict[str, Any]:
    """Black-box golden from THIS exe. Empty I/O is not a pass token.

    Named CASES keep their argv. Unknown console PE uses empty argv and
    closed stdin. Timeout, crash, and empty stdout are skip, not a recipe.
    """
    rec: Dict[str, Any] = {
        "id": "",
        "skipped": True,
        "ok": False,
        "kind": "no_cli",
        "reason": "",
        "stdout": "",
        "stdout_n": 0,
        "exit": None,
        "case": None,
        "not_compile_gate": True,
        "not_recipe_source": True,
        "need_pin": False,
        "source": "",
    }
    case = cli_case_for_binary(path)
    if case is None:
        rec["reason"] = "no named I5 case and not a console PE"
        return rec
    rec["id"] = str(case.get("id") or "")
    rec["source"] = str(case.get("source") or case.get("id") or "")
    self_cli = rec["id"] == SELF_CLI
    exe = Path(case["exe"])
    if not exe.is_file():
        exe = ROOT / str(case["exe"])
    run = run_exe(
        exe,
        list(case.get("argv") or []),
        timeout_sec=float(timeout_sec if self_cli else 15.0),
        cwd=ROOT,
        stdin_devnull=self_cli,
    )
    rec["exit"] = run.get("exit")
    rec["stdout"] = run.get("stdout") or ""
    rec["stdout_n"] = len(rec["stdout"])
    if run.get("skipped"):
        rec["kind"] = "skipped"
        rec["reason"] = str(run.get("reason") or "skipped")
        return rec
    if run.get("reason") == "timeout":
        rec["kind"] = "no_cli_contract"
        rec["reason"] = "timeout"
        return rec
    crash = _crash_reason(run.get("exit"))
    if crash:
        rec["kind"] = "no_cli_contract"
        rec["reason"] = crash
        return rec
    if self_cli and not rec["stdout"].strip():
        rec["kind"] = "no_cli_contract"
        rec["reason"] = "empty stdout is not a CLI contract"
        return rec
    rec["skipped"] = False
    rec["ok"] = True
    rec["kind"] = "observed"
    rec["reason"] = ""
    bag = dict(case)
    if self_cli:
        bag["expect_exit"] = run.get("exit")
    rec["case"] = bag
    return rec


def check_case(case: Dict[str, Any], run: Dict[str, Any]) -> Dict[str, Any]:
    if run.get("skipped"):
        return {**run, "id": case["id"], "missing": list(case.get("expect_contains") or [])}
    body = run.get("stdout") or ""
    missing = [s for s in (case.get("expect_contains") or []) if s not in body]
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


def compile_link(
    source: Path,
    out_exe: Path,
    *,
    timeout_sec: int = 60,
) -> Dict[str, Any]:
    """Link a restored TU to a runnable binary. Syntax-only compile_cpp is not this."""
    from src.analysis.compile_verify import find_cxx_compiler

    rec: Dict[str, Any] = {
        "ok": False,
        "skipped": False,
        "reason": "",
        "compiler": "",
        "command": [],
        "stderr": "",
        "exe": str(out_exe),
    }
    if not source.exists():
        rec["skipped"] = True
        rec["reason"] = f"missing {source}"
        return rec
    cxx = find_cxx_compiler()
    if not cxx:
        rec["skipped"] = True
        rec["reason"] = "no C++ compiler on PATH (g++/clang++)"
        return rec
    if Path(cxx).stem.lower() == "cl":
        rec["skipped"] = True
        rec["reason"] = "I5 restored link uses g++/clang, not cl"
        return rec
    out_exe.parent.mkdir(parents=True, exist_ok=True)
    cmd = [cxx, "-std=c++17", "-O0", "-o", str(out_exe), str(source)]
    rec["compiler"] = cxx
    rec["command"] = cmd
    kwargs: Dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout_sec,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        rec["reason"] = f"link timeout ({timeout_sec}s)"
        return rec
    rec["stderr"] = ((proc.stderr or "") + "\n" + (proc.stdout or ""))[-2000:]
    rec["ok"] = proc.returncode == 0 and out_exe.exists()
    if not rec["ok"]:
        rec["reason"] = f"link failed rc={proc.returncode}"
    return rec


def eval_restored(
    source: Path,
    case: Dict[str, Any],
    golden_stdout: str,
    *,
    root: Path = ROOT,
) -> Dict[str, Any]:
    """Compile+run restored TU; compare masked stdout to the original exe."""
    rec: Dict[str, Any] = {
        "id": case["id"],
        "source": str(source),
        "ok": False,
        "skipped": False,
        "reason": "",
        "stdout_match": False,
        "contains_ok": False,
        "exit_ok": False,
        "missing": list(case.get("expect_contains") or []),
        "stdout": "",
        "exit": None,
        "link": {},
        "not_recipe_source": True,
        "need_pin": False,
    }
    with tempfile.TemporaryDirectory(prefix="i5_restored_") as td:
        exe = Path(td) / ("restored.exe" if sys.platform == "win32" else "restored")
        link = compile_link(source, exe)
        rec["link"] = {
            "ok": link.get("ok"),
            "skipped": link.get("skipped"),
            "reason": link.get("reason"),
            "compiler": link.get("compiler"),
        }
        if link.get("skipped"):
            rec["skipped"] = True
            rec["reason"] = link.get("reason") or "link skipped"
            rec["kind"] = restored_kind(rec)
            return rec
        if not link.get("ok"):
            rec["reason"] = link.get("reason") or "link failed"
            rec["kind"] = restored_kind(rec)
            rec["stderr"] = (link.get("stderr") or "")[-800:]
            return rec
        env = os.environ.copy()
        self_cli = str(case.get("id") or "") == SELF_CLI
        run = run_exe(
            exe,
            list(case.get("argv") or []),
            cwd=root,
            stdin_devnull=self_cli,
            timeout_sec=SELF_CLI_TIMEOUT_SEC if self_cli else 15.0,
        )
        rec["stdout"] = run.get("stdout") or ""
        rec["exit"] = run.get("exit")
        rec["reason"] = run.get("reason") or ""
        crash = _crash_reason(rec["exit"])
        if crash:
            rec["reason"] = crash
        elif not rec["reason"] and rec["exit"] not in (0, None):
            rec["reason"] = f"exit={rec['exit']}"
        checked = check_case(case, run)
        rec["missing"] = checked.get("missing") or []
        rec["contains_ok"] = bool(checked.get("ok"))
        rec["exit_ok"] = bool(checked.get("exit_ok"))
        rec["stdout_match"] = mask_stdout(rec["stdout"]) == mask_stdout(golden_stdout)
        rec["ok"] = bool(rec["stdout_match"] and rec["exit_ok"] and not run.get("skipped"))
        rec["kind"] = restored_kind(rec)
        if run.get("skipped"):
            rec["skipped"] = True
        return rec


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
    p.add_argument(
        "--restored",
        type=Path,
        default=None,
        help="restored_final.cpp to compile, run, and compare to --case golden",
    )
    p.add_argument(
        "--case",
        default="pointcloud_default",
        help="CASES id for --restored (default: pointcloud_default)",
    )
    args = p.parse_args(argv)
    rec = eval_originals(ROOT)
    rc = 0 if rec.get("ok") else 1
    if args.restored:
        case = case_by_id(args.case)
        if not case:
            rec["restored"] = {"ok": False, "reason": f"unknown case {args.case}"}
            rc = 1
        else:
            golden_row = next((r for r in rec["cases"] if r.get("id") == case["id"]), {})
            restored = eval_restored(
                args.restored,
                case,
                golden_row.get("stdout") or "",
                root=ROOT,
            )
            rec["restored"] = restored
            rec["restored_note"] = (
                "Masked stdout vs original exe. Not a critic compile-gate. "
                "Not a sanitizer recipe source."
            )
            if restored.get("skipped"):
                rc = 1
            elif not restored.get("ok"):
                rc = 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: rec[k] for k in rec if k not in ("cases",)}, indent=2))
    for row in rec["cases"]:
        flag = "OK" if row.get("ok") else ("SKIP" if row.get("skipped") else "FAIL")
        print(f"  {flag} {row['id']} missing={row.get('missing')}")
    if rec.get("restored"):
        rst = rec["restored"]
        flag = "OK" if rst.get("ok") else ("SKIP" if rst.get("skipped") else "FAIL")
        print(
            f"  {flag} restored/{rst.get('id')} "
            f"match={rst.get('stdout_match')} contains={rst.get('contains_ok')} "
            f"reason={rst.get('reason')!r}"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
