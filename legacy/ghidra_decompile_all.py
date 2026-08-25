from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("revllm.ghidra")

SCRIPT_NAME = "ghidra_decompile_all.py"


class GhidraError(RuntimeError):
    pass


def find_analyze_headless(ghidra_path: Path) -> Path:
    candidates = [
        ghidra_path / "support" / "analyzeHeadless.bat",
        ghidra_path / "analyzeHeadless.bat",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise GhidraError(f"analyzeHeadless.bat not found under {ghidra_path}")


def run_ghidra_decompile(
    ghidra_path: Path,
    binary_path: Path,
    project_dir: Path,
    script_dirs: List[Path],
    out_json: Path,
    timeout_sec: int = 900,
) -> List[Dict[str, Any]]:
    headless = find_analyze_headless(Path(ghidra_path))

    script_dir = None
    for d in script_dirs:
        d = Path(d).resolve()
        if (d / SCRIPT_NAME).exists():
            script_dir = d
            break

    if script_dir is None:
        raise GhidraError("Ghidra script not found in candidate dirs")

    msg = "Ghidra script found at: " + str(script_dir / SCRIPT_NAME)
    logger.info(msg)

    project_dir = Path(project_dir).resolve()
    project_dir.mkdir(parents=True, exist_ok=True)
    out_json = Path(out_json).resolve()

    project_name = "revproj"
    project_file = project_dir / (project_name + ".gpr")

    cmd: List[str] = [str(headless), str(project_dir), project_name]

    if project_file.exists():
        logger.info("Ghidra project exists -> -process %s", binary_path.name)
        cmd += ["-process", binary_path.name]
    else:
        logger.info("Ghidra project missing -> -import %s", binary_path)
        cmd += ["-import", str(binary_path)]

    cmd += [
        "-scriptPath", str(script_dir),
        "-postScript", SCRIPT_NAME, str(out_json),
    ]

    logger.info("Running Ghidra headless (may take a few minutes)...")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        raise GhidraError("Ghidra headless timeout")

    log_path = out_json.with_name("ghidra_headless.log")
    try:
        stdout_part = proc.stdout or ""
        stderr_part = proc.stderr or ""
        log_path.write_text(
            "=== STDOUT ===\n" + stdout_part + "\n=== STDERR ===\n" + stderr_part,
            encoding="utf-8",
            errors="replace",
        )
        logger.info("Ghidra headless log: %s", log_path)
    except Exception:
        pass

    if proc.returncode != 0:
        tail = (proc.stdout or "")[-3000:]
        logger.error("Ghidra headless failed rc=%s\nstdout tail:\n%s", proc.returncode, tail)
        raise GhidraError("Ghidra headless failed rc=" + str(proc.returncode))

    if not out_json.exists():
        tail = (proc.stdout or "")[-3000:]
        logger.error("Ghidra did not produce JSON. stdout tail:\n%s", tail)
        raise GhidraError("Ghidra script did not produce output JSON (see ghidra_headless.log)")

    data = json.loads(out_json.read_text(encoding="utf-8"))
    logger.info("Ghidra decompiled %d functions", len(data))
    return data