"""Gym-only Q8 I5 CLI metric on arbitrary console PE. Not live restore.

  py -m src.analysis.eval_i5_cli --dry-run
  py -m src.analysis.eval_i5_cli --run output/logs/run_<ts>

Does not bump p4/v6, does not emit corpus YAML, does not run Pin,
does not treat empty I/O as a pass, does not change critic ACCEPT.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "i5_cli_report.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _fake_pe(subsystem: int) -> bytes:
    import struct

    blob = bytearray(0x200)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<H", blob, coff + 16, 240)
    opt = coff + 20
    struct.pack_into("<H", blob, opt, 0x20B)
    struct.pack_into("<H", blob, opt + 68, subsystem)
    return bytes(blob)


def run_dry() -> Dict[str, Any]:
    from src.analysis.eval_behavior import (
        SELF_CLI,
        case_for_binary,
        cli_case_for_binary,
        observe_cli,
    )
    from src.analysis.pe_image import (
        SUBSYSTEM_WINDOWS_CUI,
        SUBSYSTEM_WINDOWS_GUI,
        pe_is_console,
        pe_subsystem,
    )
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    cui = _fake_pe(SUBSYSTEM_WINDOWS_CUI)
    gui = _fake_pe(SUBSYSTEM_WINDOWS_GUI)
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "named_pointcloud": (case_for_binary("samples/PointCloud.exe") or {}).get("id"),
        "named_unknown": case_for_binary("user.bin"),
        "cui_subsystem": pe_subsystem(cui),
        "gui_is_console": pe_is_console(gui),
        "need_pin": False,
        "ok": False,
        "note": (
            "Not a recipe source. Empty I/O is not a pass. "
            "Do not bump LLM_PROMPT_VER. Pin is not LIVE."
        ),
    }
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        console = Path(td) / "wrap.exe"
        window = Path(td) / "win.exe"
        console.write_bytes(cui)
        window.write_bytes(gui)
        cli = cli_case_for_binary(console)
        no = cli_case_for_binary(window)
        obs = observe_cli(console, timeout_sec=1.0)
        rec["self_cli_id"] = (cli or {}).get("id")
        rec["gui_case"] = no
        rec["observe_kind"] = obs.get("kind")
        rec["observe_skip"] = bool(obs.get("skipped"))
        rec["ok"] = (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and rec["named_pointcloud"] == "pointcloud_default"
            and rec["named_unknown"] is None
            and pe_is_console(cui)
            and not pe_is_console(gui)
            and (cli or {}).get("id") == SELF_CLI
            and no is None
            and obs.get("not_recipe_source")
            and not obs.get("need_pin")
        )
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.eval_behavior import (
        eval_restored,
        i5_summary,
        observe_cli,
    )
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    run_dir = Path(run_dir)
    binary_info = _load_json(run_dir / "binary_info.json") or {}
    critic = _load_json(run_dir / "critic.json") or {}
    binary = str(binary_info.get("path") or "")
    bin_path = Path(binary)
    if binary and not bin_path.is_file():
        bin_path = ROOT / binary
    obs = observe_cli(bin_path)
    restored_cpp = run_dir / "restored_final.cpp"
    restored: Dict[str, Any] = {}
    if (
        restored_cpp.exists()
        and obs.get("kind") == "observed"
        and obs.get("case")
    ):
        restored = eval_restored(
            restored_cpp,
            obs["case"],
            obs.get("stdout") or "",
        )
    slim = i5_summary(restored or obs)
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "observe_kind": obs.get("kind"),
        "observe_skip": bool(obs.get("skipped")),
        "stdout_n": obs.get("stdout_n"),
        "restored_kind": restored.get("kind") or "",
        "summary": slim,
        "critic_accept": bool(critic.get("accept")),
        "need_pin": False,
        "not_recipe_source": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and bool(slim.get("not_recipe_source"))
            and not slim.get("need_pin")
        ),
        "note": (
            "Gym apply-only. I5 is a metric, not ACCEPT and not a recipe. "
            "Empty CLI contract is skip. Pin is not LIVE. Do not bump p4."
        ),
    }
    dest = run_dir / "i5_cli.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only Q8 I5 CLI metric (not live, not Pin, not recipe)"
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
