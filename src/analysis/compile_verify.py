from __future__ import annotations

"""Compile-verify gate (Phase 2): syntax-check restored C++ and parse diagnostics."""

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


GCC_ERROR_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?:\s*(?:fatal )?error:\s*(?P<msg>.+)$"
)
MSVC_ERROR_RE = re.compile(
    r"^(?P<file>.+?)\((?P<line>\d+)(?:,\d+)?\)\s*:\s*error\s+\w+:\s*(?P<msg>.+)$"
)

_CXX_CANDIDATES = ("g++", "clang++", "c++", "cl")
_WIN_CXX_HINTS = (
    Path(r"C:\msys64\ucrt64\bin\g++.exe"),
    Path(r"C:\msys64\mingw64\bin\g++.exe"),
    Path(r"C:\msys64\clang64\bin\clang++.exe"),
)


@dataclass
class CompileResult:
    attempted: bool = False
    ok: bool = False
    compiler: str = ""
    command: List[str] = field(default_factory=list)
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    errors: List[Dict[str, str]] = field(default_factory=list)
    skipped_reason: str = ""
    source: str = ""
    n_errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "ok": self.ok,
            "compiler": self.compiler,
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout[-8000:],
            "stderr": self.stderr[-8000:],
            "errors": self.errors[:40],
            "n_errors": self.n_errors,
            "skipped_reason": self.skipped_reason,
            "source": self.source,
        }


def parse_diagnostics(text: str) -> List[Dict[str, str]]:
    """Parse gcc/clang or MSVC error lines. Ignores notes/warnings."""
    out: List[Dict[str, str]] = []
    seen = set()
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        m = GCC_ERROR_RE.match(line) or MSVC_ERROR_RE.match(line)
        if not m:
            continue
        item = {
            "file": m.group("file"),
            "line": m.group("line"),
            "message": (m.group("msg") or "").strip(),
        }
        key = (item["file"], item["line"], item["message"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def extract_cpp(text: str) -> str:
    """Strip markdown fences from an LLM compile-fix response."""
    blob = (text or "").strip()
    fence = re.search(
        r"```(?:cpp|c\+\+|cxx|cc)?\s*\n(.*?)```",
        blob,
        re.DOTALL | re.IGNORECASE,
    )
    if fence:
        return fence.group(1).strip()
    return blob


def find_cxx_compiler(explicit: str = "") -> Optional[str]:
    """Resolve a C++ compiler: config/env, PATH, then common MinGW locations."""
    if explicit:
        p = Path(explicit)
        if p.exists():
            return str(p)
        found = shutil.which(explicit)
        if found:
            return found
        return None
    env = (os.environ.get("CXX") or "").strip()
    if env:
        found = shutil.which(env) if not Path(env).exists() else env
        if found:
            return found
    for name in _CXX_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    if sys.platform == "win32":
        for hint in _WIN_CXX_HINTS:
            if hint.exists():
                return str(hint)
    return None


def _is_msvc(compiler: str) -> bool:
    return Path(compiler).stem.lower() == "cl"


def _syntax_cmd(compiler: str, source: Path) -> List[str]:
    if _is_msvc(compiler):
        return [compiler, "/nologo", "/Zs", "/std:c++17", str(source)]
    return [compiler, "-fsyntax-only", "-std=c++17", "-Wall", str(source)]


def compile_cpp(
    source: Path,
    *,
    compiler: str = "",
    timeout_sec: int = 60,
) -> CompileResult:
    """Syntax-check a translation unit. Does not link."""
    result = CompileResult(source=str(source))
    if not source.exists():
        result.skipped_reason = f"missing source: {source}"
        return result
    cxx = find_cxx_compiler(compiler)
    if not cxx:
        result.skipped_reason = "no C++ compiler on PATH (g++/clang++/cl)"
        return result

    cmd = _syntax_cmd(cxx, source)
    result.attempted = True
    result.compiler = cxx
    result.command = cmd
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
        result.returncode = -1
        result.stderr = f"compiler timeout ({timeout_sec}s)"
        result.errors = [{"file": str(source), "line": "0", "message": result.stderr}]
        result.n_errors = 1
        return result
    except OSError as exc:
        result.skipped_reason = f"cannot exec compiler: {exc}"
        result.attempted = False
        return result

    result.returncode = int(proc.returncode)
    result.stdout = proc.stdout or ""
    result.stderr = proc.stderr or ""
    combined = (result.stderr + "\n" + result.stdout).strip()
    result.errors = parse_diagnostics(combined)
    result.n_errors = len(result.errors)
    result.ok = proc.returncode == 0
    if not result.ok and not result.errors and combined:
        result.errors = [{"file": str(source), "line": "0", "message": combined[:500]}]
        result.n_errors = 1
    return result


def compile_snippet(
    body: str,
    *,
    preamble_lines: Sequence[str],
    work_dir: Path,
    name: str = "fn",
    compiler: str = "",
    timeout_sec: int = 60,
) -> CompileResult:
    """Syntax-check one function plus preamble (Phase 2 per-function gate).

    Injects the same inferred struct / thunk stubs assemble() would add, so
    undeclared-struct-type is not a translation-unit-only win.
    """
    from src.agents.assembler import type_stubs_for_snippet
    from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

    work_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", name)[:48] or "fn"
    path = work_dir / f"{safe}.cpp"
    body = sanitize_ghidra_cpp((body or "").strip())
    preamble = list(preamble_lines)
    stubs = type_stubs_for_snippet(body, "\n".join(preamble))
    text = "\n".join(preamble + [""] + stubs + [body, ""])
    path.write_text(text, encoding="utf-8")
    return compile_cpp(path, compiler=compiler, timeout_sec=timeout_sec)


def format_errors_for_prompt(errors: Sequence[Dict[str, str]], limit: int = 20) -> str:
    if not errors:
        return "(no parsed diagnostics)"
    lines = []
    for e in list(errors)[:limit]:
        lines.append(f"{e.get('file', '?')}:{e.get('line', '?')}: {e.get('message', '')}")
    return "\n".join(lines)
