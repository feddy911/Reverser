from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.dialect_loop import (
    dump_contains_token,
    emit_minis,
    normalize_message,
    plan_from_report,
    plan_messages,
    verify_dumps,
)
from src.analysis.eval_heldout import frozen_leaks


class TestDialectLoop(unittest.TestCase):
    def test_normalize_drops_path_and_aka(self):
        raw = (
            r"D:\Hryusha\Reverser\output\x.cpp:12:4: "
            "invalid cast from type '__const_iterator' "
            "{aka 'std::__cxx11::basic_string<char>::const_iterator'} "
            "to type 'std::__cxx11::basic_string<char>*'"
        )
        got = normalize_message(raw)
        self.assertNotIn("Hryusha", got)
        self.assertNotIn("{aka", got)
        self.assertIn("__const_iterator", got)

    def test_known_fingerprint_is_skip_known(self):
        from src.analysis.eval_classifier import regex_to_probe, split_alts
        from src.analysis.corpus import load_corpus

        case = next(c for c in load_corpus() if (c.gcc_fingerprint or "").strip())
        probe = regex_to_probe(split_alts(case.gcc_fingerprint)[0])
        rec = plan_messages([probe], budget=1)
        actions = {c["action"] for c in rec["clusters"]}
        self.assertIn("skip_known", actions)
        self.assertEqual(rec["emit"], [])

    def test_catalog_proposes_string_ret_ws(self):
        msg = (
            "invalid cast from type '__const_iterator' "
            "{aka 'std::__cxx11::basic_string<char>::const_iterator'} "
            "to type 'std::__cxx11::basic_string<char>*'"
        )
        rec = plan_messages([msg], budget=1, corpus_cases=[])
        self.assertIn("string_ret_ws", rec["emit"])
        prop = next(c for c in rec["clusters"] if c["action"] == "propose_mini")
        self.assertEqual(prop["mini_id"], "string_ret_ws")
        self.assertTrue(prop["in_budget"])

    def test_budget_caps_emit(self):
        msgs = [
            "invalid cast from type '__const_iterator' to type 'std::__cxx11::basic_string<char>*'",
            "'pointer' {aka 'void*'} is not a pointer-to-object type",
        ]
        rec = plan_messages(msgs, budget=1, corpus_cases=[])
        self.assertEqual(rec["emit"], ["string_ret_ws"])
        rec2 = plan_messages(msgs, budget=2, corpus_cases=[])
        self.assertEqual(rec2["emit"], ["string_ret_ws", "umap_show_val"])

    def test_skip_forever_ios_good(self):
        rec = plan_messages(
            ["'std::ios::good' was not declared in this scope"],
            budget=1,
            corpus_cases=[],
        )
        self.assertEqual(rec["emit"], [])
        self.assertTrue(
            any(c["action"] == "skip_forever" for c in rec["clusters"])
        )

    def test_no_catalog_does_not_emit(self):
        rec = plan_messages(
            ["wholly_new_ghidra_token was not declared in this scope"],
            budget=1,
            corpus_cases=[],
        )
        self.assertEqual(rec["emit"], [])
        self.assertTrue(any(c["action"] == "no_catalog" for c in rec["clusters"]))

    def test_emit_writes_outside_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            recs = emit_minis(["string_ret_ws"], work)
            self.assertTrue(recs[0]["ok"], recs)
            path = Path(recs[0]["path"])
            self.assertTrue(path.exists())
            self.assertNotIn("eval", path.parts)
            self.assertIn("trim_copy", path.read_text(encoding="utf-8"))
        self.assertEqual(frozen_leaks(ROOT), [])

    def test_from_report_empty_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rep.json"
            p.write_text(
                json.dumps({
                    "name": "inimini",
                    "n_unknown": 0,
                    "unknown_messages": [],
                    "known_ids": ["ghidra-string-find-deref"],
                }),
                encoding="utf-8",
            )
            rec = plan_from_report(p, budget=1)
        self.assertEqual(rec["emit"], [])
        self.assertEqual(rec["n_unknown"], 0)
        self.assertIn("lab", rec["note"])
        self.assertTrue(
            any(c.get("known_ids") for c in rec["clusters"] if c["action"] == "skip_known")
        )

    def test_dump_token_check(self):
        ghidra = {
            "functions": [
                {"name": "trim_copy", "ghidra_code": "it._M_current = 0;\n"},
            ]
        }
        self.assertTrue(dump_contains_token(ghidra, "_M_current"))
        self.assertFalse(dump_contains_token(ghidra, "const_std::"))

    def test_verify_dumps_missing_and_hit(self):
        plan = {
            "clusters": [
                {
                    "action": "propose_mini",
                    "in_budget": True,
                    "mini_id": "string_ret_ws",
                    "token": "_M_current",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as td:
            ddir = Path(td)
            checks = verify_dumps(plan, ddir)
            self.assertIsNone(checks[0]["token_ok"])
            dump = ddir / "string_ret_ws.json"
            dump.write_text(
                json.dumps({
                    "functions": [{"name": "f", "ghidra_code": "x._M_current"}],
                }),
                encoding="utf-8",
            )
            checks = verify_dumps(plan, ddir)
            self.assertTrue(checks[0]["token_ok"])


if __name__ == "__main__":
    unittest.main()
