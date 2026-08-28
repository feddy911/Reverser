from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.eval_heldout import (
    eval_heldout_entry,
    frozen_leaks,
    run_manifest,
)
from src.analysis.gen_corpus import HELDOUT_PROGRAMS, compile_programs, emit_programs


class TestHeldoutFreeze(unittest.TestCase):
    def test_sanitizer_assembler_have_no_sample_names(self):
        leaks = frozen_leaks(ROOT)
        self.assertEqual(leaks, [], leaks)


class TestHeldoutEval(unittest.TestCase):
    def test_struct_fixture_runs_without_new_recipe(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            rec = eval_heldout_entry(
                "heldout_struct_fixture",
                ghidra_json=ROOT / "tests" / "fixtures" / "heldout_struct.json",
                user_names=["dist2", "closest_ix", "span_len", "main"],
                proposal_dir=work / "proposals",
                work_dir=work / "work",
            )
        self.assertFalse(rec.get("skipped"))
        self.assertGreaterEqual(rec.get("n_functions") or 0, 3)
        self.assertIn("closest_ix", rec.get("function_names") or [])
        self.assertEqual(rec.get("frozen_leaks") or [], [])
        self.assertTrue(rec.get("ok"))
        if rec.get("assembled_ok") is not None:
            self.assertTrue(
                rec.get("assembled_ok"),
                rec.get("unknown_messages") or rec.get("compile_stderr"),
            )
            self.assertTrue(
                (rec.get("critic") or {}).get("accept"),
                rec.get("critic"),
            )

    def test_unknown_token_becomes_proposal_not_recipe(self):
        from src.analysis.compile_verify import find_cxx_compiler

        if not find_cxx_compiler():
            self.skipTest("no C++ compiler on PATH")
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            rec = eval_heldout_entry(
                "heldout_unknown",
                ghidra_json=ROOT / "tests" / "fixtures" / "heldout_unknown.json",
                user_names=["go"],
                proposal_dir=work / "proposals",
                work_dir=work / "work",
            )
            self.assertTrue(rec.get("need_llm"))
            self.assertGreaterEqual(rec.get("n_unknown") or 0, 1)
            self.assertTrue(rec.get("proposals"), rec)
            text = Path(rec["proposals"][0]).read_text(encoding="utf-8")
            self.assertIn("wholly_new_ghidra_token", text)
            self.assertIn("not accepted into eval/corpus", text)
        leaks = frozen_leaks(ROOT)
        self.assertEqual(leaks, [])

    def test_manifest_includes_pointcloud(self):
        report = run_manifest(
            ROOT / "eval" / "heldout.yaml",
            out_path=ROOT / "output" / "heldout_report.json",
            proposal_dir=ROOT / "output" / "heldout_proposals",
        )
        names = [r["name"] for r in report.get("results") or []]
        self.assertIn("heldout_struct_fixture", names)
        self.assertIn("pointcloud", names)
        self.assertEqual(report.get("frozen_leaks") or [], [])
        pc = next(r for r in report["results"] if r["name"] == "pointcloud")
        if pc.get("skipped"):
            self.skipTest("PointCloud ghidra dump not in output/cache")
        self.assertGreaterEqual(pc.get("n_functions") or 0, 4)
        self.assertIn("nearest_index", pc.get("function_names") or [])
        if pc.get("assembled_ok"):
            self.assertTrue(
                (pc.get("critic") or {}).get("accept"),
                pc.get("critic"),
            )


class TestHeldoutGenerator(unittest.TestCase):
    def test_heldout_source_compiles(self):
        from src.analysis.compile_verify import find_cxx_compiler

        self.assertTrue(HELDOUT_PROGRAMS)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            emit_programs(out, programs=HELDOUT_PROGRAMS)
            if not find_cxx_compiler():
                self.skipTest("no C++ compiler on PATH")
            reports = compile_programs(out, programs=HELDOUT_PROGRAMS)
        fails = [r for r in reports if not r.get("ok") and not r.get("skipped")]
        self.assertFalse(fails, fails)


class TestLibrarian(unittest.TestCase):
    def test_propose_from_mini_dump(self):
        from src.analysis.librarian import propose_from_dump

        ghidra = json.loads(
            (ROOT / "tests" / "fixtures" / "mini_ghidra.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as td:
            rec = propose_from_dump(
                ghidra,
                program_id="mini",
                draft_dir=Path(td),
            )
            self.assertGreaterEqual(rec.get("n_user") or 0, 1)
            self.assertTrue(rec.get("path"))
            self.assertTrue(Path(rec["path"]).exists())
            self.assertNotIn("nearest_index", Path(rec["path"]).read_text(encoding="utf-8"))

    def test_refuse_heldout_id(self):
        from src.analysis.librarian import try_accept

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "ghidra-heldout_struct_math-go.yaml"
            src.write_text(
                "id: ghidra-heldout_struct_math-go\nprofile: generic\n"
                "recipe: sanitize\nghidra_cpp: |\n  void go() {}\ncontains: []\n",
                encoding="utf-8",
            )
            rec = try_accept(src, Path(td) / "out")
        self.assertFalse(rec.get("ok"))
        self.assertIn("held-out", str(rec.get("error")))

    def test_dumps_dir_writes_drafts(self):
        from src.analysis.librarian import propose_from_dumps_dir

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dump_dir = root / "dumps"
            dump_dir.mkdir()
            src = ROOT / "tests" / "fixtures" / "mini_ghidra.json"
            (dump_dir / "mini.json").write_text(
                src.read_text(encoding="utf-8"), encoding="utf-8"
            )
            recs = propose_from_dumps_dir(dump_dir, draft_dir=root / "draft")
            self.assertEqual(len(recs), 1)
            self.assertTrue(recs[0].get("path"))
            self.assertTrue(Path(recs[0]["path"]).exists())

    def test_refuse_heldout_token(self):
        from src.analysis.librarian import try_accept

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "bad.yaml"
            src.write_text(
                "id: bad\nprofile: generic\nrecipe: sanitize\n"
                "ghidra_cpp: |\n  void nearest_index() {}\ncontains: []\n",
                encoding="utf-8",
            )
            rec = try_accept(src, Path(td) / "out")
        self.assertFalse(rec.get("ok"))
        self.assertIn("nearest_index", str(rec.get("error")))


if __name__ == "__main__":
    unittest.main()
