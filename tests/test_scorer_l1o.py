from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.features import FEATURE_KEYS
from src.analysis.eval_scorer_l1o import (
    MODEL_ORDER,
    assert_scoring_features,
    load_binary,
    run_l1o,
    run_manifest,
)


FIXTURE = ROOT / "tests" / "fixtures" / "mini_ghidra.json"


def _alt_dump(src: Path, dst: Path, old: str, new: str) -> None:
    data = json.loads(src.read_text(encoding="utf-8"))
    text = json.dumps(data)
    dst.write_text(text.replace(old, new), encoding="utf-8")


class TestScorerL1O(unittest.TestCase):
    def test_feature_keys_are_the_live_22_without_gcc(self):
        assert_scoring_features()
        self.assertEqual(len(FEATURE_KEYS), 22)
        blob = " ".join(FEATURE_KEYS).lower()
        self.assertNotIn("gcc", blob)
        src = (ROOT / "src" / "analysis" / "eval_scorer_l1o.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("ghidra_cpp", src)
        self.assertNotIn("compile_verify", src)
        self.assertNotIn("match_errors", src)

    def test_l1o_two_minis_all_models(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            a = td_path / "a.json"
            b = td_path / "b.json"
            a.write_bytes(FIXTURE.read_bytes())
            _alt_dump(FIXTURE, b, "FUN_140001000", "parse_ini")
            packs = [
                load_binary("mini_a", a, ["FUN_140001000"]),
                load_binary("mini_b", b, ["parse_ini"]),
            ]
            report = run_l1o(packs, top_k=15)
            self.assertTrue(report["not_compile_gate"])
            self.assertEqual(report["feature_keys"], list(FEATURE_KEYS))
            self.assertEqual(report["n_binaries"], 2)
            names = {row["name"] for row in report["table"]}
            self.assertEqual(names, {"mini_a", "mini_b"})
            for model in MODEL_ORDER:
                self.assertIn(model, report["mean_filtered_recall"])
                self.assertIsNotNone(report["mean_filtered_recall"][model])
                self.assertIn(model, report["mean_raw_recall"])
            for fold in report["folds"]:
                dtree = fold["models"]["dtree"]
                self.assertNotIn("error", dtree)
                self.assertGreaterEqual(dtree["recall_at_k_names_filtered"], 1.0)
                self.assertIn("tree_rules", dtree)
                self.assertIn("class:", dtree["tree_rules"])

    def test_address_labels_train_y(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            dump = td_path / "mini.json"
            dump.write_bytes(FIXTURE.read_bytes())
            pack = load_binary(
                "mini",
                dump,
                ["FUN_140001000"],
                labels={"0x140001000": 1},
            )
            self.assertEqual(pack.y_source, "addresses")
            self.assertEqual(int(pack.y.sum()), 1)
            rec = run_l1o([pack], top_k=15)
            fold = rec["folds"][0]
            self.assertEqual(
                fold["models"]["heuristic"].get("recall_at_k_addr_filtered"),
                1.0,
            )

    def test_manifest_skips_missing_and_runs_present(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            dump = td_path / "mini.json"
            dump.write_bytes(FIXTURE.read_bytes())
            man = td_path / "manifest.yaml"
            man.write_text(
                "\n".join([
                    "top_k: 15",
                    "entries:",
                    "  - name: present",
                    "    ghidra_json: mini.json",
                    "    user_names: [FUN_140001000]",
                    "  - name: missing",
                    "    ghidra_json: no_such.json",
                    "    user_names: [main]",
                ]),
                encoding="utf-8",
            )
            out = td_path / "l1o.json"
            report = run_manifest(man, out, top_k=15)
            self.assertEqual(report["n_binaries"], 1)
            self.assertEqual(report["n_skip"], 1)
            self.assertTrue(out.exists())
            # one binary: heuristic ok, ML has no train set
            fold = report["folds"][0]
            self.assertIsNotNone(fold["models"]["heuristic"]["recall_at_k_names_filtered"])
            self.assertEqual(fold["models"]["rf"].get("error"), "no train binaries")


if __name__ == "__main__":
    unittest.main()
