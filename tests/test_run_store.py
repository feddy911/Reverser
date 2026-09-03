from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.run_store import (
    format_scorecard,
    ingest_logs,
    latest_scorecard,
    record_run,
)


def _write_run(root: Path, name: str, sample: str, *, gcc: int, accept: bool) -> Path:
    run = root / name
    run.mkdir()
    (run / "binary_info.json").write_text(
        json.dumps({"path": f"samples/{sample}.exe", "md5": "abc"}),
        encoding="utf-8",
    )
    (run / "metrics.json").write_text(
        json.dumps({
            "triage_profile": "gcc_pe_x64",
            "fidelity": {"mean": 1.0},
            "llm": {"cache_hit": 3},
            "compile": {
                "ok": gcc == 0,
                "n_errors": gcc,
                "fn_ok": 2 if gcc == 0 else 1,
                "fn_fail": 0 if gcc == 0 else 1,
            },
        }),
        encoding="utf-8",
    )
    (run / "critic.json").write_text(
        json.dumps({
            "accept": accept,
            "identity_ok": True,
            "fidelity_ok": True,
            "compile_ok": gcc == 0,
        }),
        encoding="utf-8",
    )
    errors = []
    if gcc:
        errors = [
            {"message": "'var_10' was not declared in this scope"},
            {"message": "'it' was not declared in this scope; did you mean 'int'?"},
        ]
    (run / "compile.json").write_text(
        json.dumps({"n_errors": gcc, "errors": errors}),
        encoding="utf-8",
    )
    return run


class TestRunStore(unittest.TestCase):
    def test_record_and_latest_scorecard(self):
        with tempfile.TemporaryDirectory() as td:
            logs = Path(td) / "logs"
            logs.mkdir()
            db = Path(td) / "runs.sqlite"
            old = _write_run(logs, "run_20260901_010101_1", "PointCloud", gcc=0, accept=True)
            new = _write_run(logs, "run_20260903_072926_1", "PointCloud", gcc=0, accept=True)
            other = _write_run(logs, "run_20260902_152110_1", "GammaFn", gcc=2, accept=False)
            n = ingest_logs(logs, db_path=db)
            self.assertEqual(n, 3)
            rows = {r["sample"]: r for r in latest_scorecard(db_path=db)}
            self.assertEqual(set(rows), {"PointCloud", "GammaFn"})
            self.assertEqual(rows["PointCloud"]["run_dir"], str(new.resolve()))
            self.assertTrue(rows["PointCloud"]["critic_accept"])
            self.assertEqual(rows["PointCloud"]["tu_gcc"], 0)
            self.assertEqual(rows["GammaFn"]["tu_gcc"], 2)
            self.assertEqual(rows["GammaFn"]["n_unknown"], 1)
            skips = json.loads(rows["GammaFn"]["skip_forever"])
            self.assertIn("undeclared ghidra temp", skips)
            text = format_scorecard(list(rows.values()))
            self.assertIn("PointCloud", text)
            self.assertIn("ACCEPT", text)
            rid = record_run(old, db_path=db, prompt_ver="p4")
            self.assertGreater(rid, 0)

    def test_it_stays_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            logs = Path(td) / "logs"
            logs.mkdir()
            db = Path(td) / "runs.sqlite"
            _write_run(logs, "run_20260902_180000_1", "IniMini", gcc=1, accept=False)
            ingest_logs(logs, db_path=db)
            row = latest_scorecard(db_path=db)[0]
            self.assertEqual(row["sample"], "IniMini")
            self.assertEqual(row["n_unknown"], 1)


if __name__ == "__main__":
    unittest.main()
