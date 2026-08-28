"""Run Reverser pipeline on all samples/*.exe except MyCollatz (optional include)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.config import load_config
from src.pipeline.runner import run

SAMPLES = [
    "EchoFilter.exe",
    "PointCloud.exe",
    "IniMini.exe",
    "XorCipher.exe",
    "FibTimer.exe",
]


def main() -> int:
    cfg_path = ROOT / "config.yaml"
    summary_path = ROOT / "output" / "five_samples_summary.json"
    results = []
    overall = 0

    for name in SAMPLES:
        exe = ROOT / "samples" / name
        print("=" * 72)
        print(f"START {name}")
        print("=" * 72)
        if not exe.exists():
            print(f"MISSING {exe}")
            results.append({"binary": name, "ok": False, "error": "missing"})
            overall = 1
            continue

        config = load_config(cfg_path)
        config.binary_path = str(exe)
        config.domain_pack = "none"
        rc = run(config)
        entry = {"binary": name, "ok": rc == 0, "exit": rc}
        # pick latest metrics from newest run dir mentioning this md5 — runner prints path
        results.append(entry)
        if rc != 0:
            overall = 1
            print(f"FAILED {name} exit={rc}")
        else:
            print(f"OK {name}")

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("=" * 72)
    print(f"SUMMARY -> {summary_path}")
    print(json.dumps(results, indent=2))
    return overall


if __name__ == "__main__":
    sys.exit(main())
