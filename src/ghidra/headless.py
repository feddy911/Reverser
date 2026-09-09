from __future__ import annotations

"""Headless dump via GhidraDecompileAll.java. No I4 pre-pass.

RecoverClassesFromRTTI, DWARF, and FID are not enabled here. Do not bump
GHIDRA_CACHE_KEY until a real pre-pass re-dump exists (see ghidra_prepass.py).
"""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("revllm.ghidra")

SCRIPT_NAME = "GhidraDecompileAll.java"


class GhidraError(RuntimeError):
    pass


def find_analyze_headless(ghidra_path: Path) -> Path:
    """Locate analyzeHeadless on Windows (.bat) or Unix (shell script)."""
    root = Path(ghidra_path)
    names = []
    if sys.platform.startswith("win"):
        names = ["analyzeHeadless.bat", "analyzeHeadless"]
    else:
        names = ["analyzeHeadless", "analyzeHeadless.bat"]

    candidates: List[Path] = []
    for name in names:
        candidates.append(root / "support" / name)
        candidates.append(root / name)

    for c in candidates:
        if c.exists():
            return c
    raise GhidraError(
        f"analyzeHeadless not found under {ghidra_path} "
        f"(tried support/ and root for: {', '.join(names)})"
    )


def run_ghidra_decompile(
    ghidra_path: Path,
    binary_path: Path,
    project_dir: Path,
    script_dirs: List[Path],
    out_json: Path,
    timeout_sec: int = 900,
) -> Dict[str, Any]:
    headless = find_analyze_headless(Path(ghidra_path))
    binary_path = Path(binary_path).resolve()

    script_dir = None
    for d in script_dirs:
        d = Path(d).resolve()
        if (d / SCRIPT_NAME).exists():
            script_dir = d
            break
    if script_dir is None:
        tried = ", ".join(str(Path(d).resolve() / SCRIPT_NAME) for d in script_dirs)
        raise GhidraError(f"Ghidra script {SCRIPT_NAME} not found. Tried: {tried}")

    logger.info("Ghidra script found at: %s", script_dir / SCRIPT_NAME)

    project_dir = Path(project_dir).resolve()
    project_dir.mkdir(parents=True, exist_ok=True)
    out_json = Path(out_json).resolve()

    project_name = "revproj"
    project_file = project_dir / (project_name + ".gpr")

    def _build_cmd(mode: str) -> List[str]:
        cmd: List[str] = [str(headless), str(project_dir), project_name]
        if mode == "process":
            cmd += ["-process", binary_path.name]
        else:
            cmd += ["-import", str(binary_path)]
        cmd += [
            "-scriptPath", str(script_dir),
            "-postScript", SCRIPT_NAME, str(out_json),
        ]
        return cmd

    # Per-binary project dirs: first run imports; later runs process.
    # Shared legacy projects may lack the file -> fall back to import.
    if project_file.exists():
        mode = "process"
        logger.info("Ghidra project exists -> -process %s", binary_path.name)
    else:
        mode = "import"
        logger.info("Ghidra project missing -> -import %s", binary_path)

    logger.info("Running Ghidra headless (may take a few minutes)...")
    try:
        proc = subprocess.run(
            _build_cmd(mode),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        raise GhidraError(f"Ghidra headless timeout ({timeout_sec}s)")

    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if (
        proc.returncode != 0
        and mode == "process"
        and "not found" in combined.lower()
    ):
        logger.warning(
            "Ghidra -process missed %s; retrying with -import into same project",
            binary_path.name,
        )
        mode = "import"
        try:
            proc = subprocess.run(
                _build_cmd(mode),
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            raise GhidraError(f"Ghidra headless timeout ({timeout_sec}s)")
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")

    log_path = out_json.with_name("ghidra_headless.log")
    try:
        log_path.write_text(
            "=== STDOUT ===\n" + (proc.stdout or "") +
            "\n=== STDERR ===\n" + (proc.stderr or ""),
            encoding="utf-8",
            errors="replace",
        )
        logger.info("Ghidra headless log: %s", log_path)
    except Exception:
        pass

    if proc.returncode != 0:
        tail = combined[-3000:]
        logger.error("Ghidra headless failed rc=%s\nstdout/stderr tail:\n%s", proc.returncode, tail)
        raise GhidraError("Ghidra headless failed rc=" + str(proc.returncode))

    if not out_json.exists():
        tail = combined[-3000:]
        logger.error("Ghidra did not produce JSON. stdout/stderr tail:\n%s", tail)
        raise GhidraError("Ghidra script did not produce output JSON (see ghidra_headless.log)")

    data = json.loads(out_json.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "functions" not in data:
        raise GhidraError("Unexpected Ghidra JSON schema (expected object with 'functions')")

    funcs = data.get("functions") or []
    if not funcs:
        raise GhidraError("Ghidra dump has 0 functions (empty analysis)")

    logger.info(
        "Ghidra dump: %d functions, %d imports, %d strings",
        len(funcs),
        len(data.get("imports", [])),
        len(data.get("strings", [])),
    )
    return data
