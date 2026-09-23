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

    def test_ostream_diagnostic_is_leftover_stack(self):
        from src.analysis.run_store import build_analysis_stack

        stack = build_analysis_stack(
            [{
                "message": (
                    "no match for 'operator*' (operand type is 'std::ostream'"
                    " {aka 'std::basic_ostream<char>'})"
                ),
            }],
            tu_text='p = (&((*(std::cout)) << ("n")));\n',
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertIn("leftover", stack["counts"])
        self.assertTrue(
            any(i["reason"] == "ostream_addr" for i in stack["items"])
        )

    def test_overlay_insert_diagnostic_is_leftover_stack(self):
        from src.analysis.run_store import build_analysis_stack

        stack = build_analysis_stack(
            [{
                "message": (
                    "no matching function for call to "
                    "'operator<<(undefined1 [292], longlong&)'"
                ),
            }],
            tu_text=(
                "undefined1 local_298[292];\n"
                "operator<<(local_298, n);\n"
            ),
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertTrue(
            any(i["reason"] == "ostream_overlay" for i in stack["items"])
        )

    def test_concat71_low_compiles_is_leftover_stack(self):
        from src.analysis.run_store import build_analysis_stack

        stack = build_analysis_stack(
            [],
            tu_text=(
                "uVar1 = (((unsigned long long)((int7)((ulonglong)uVar2 >> 8)) << 8)"
                " | (unsigned char)(1));\n"
            ),
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertEqual(stack["n_unknown"], 0)
        self.assertTrue(
            any(i["reason"] == "concat71_low" for i in stack["items"])
        )

    def test_extra_star_stack_array_is_leftover_stack(self):
        from src.analysis.run_store import build_analysis_stack

        stack = build_analysis_stack(
            [],
            tu_text=(
                "longlong ****xs[8];\n"
                "p = (longlong ***)xs;\n"
                "helper((longlong *)p);\n"
            ),
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertEqual(stack["n_unknown"], 0)
        self.assertTrue(
            any(i["reason"] == "extra_star" for i in stack["items"])
        )
        self.assertNotIn("disasm_facts", stack)
        formal = build_analysis_stack(
            [],
            tu_text=(
                "void wrap(longlong ***slot)\n"
                "{\n"
                "  longlong ****xs[8];\n"
                "  slot = (longlong ***)xs;\n"
                "}\n"
            ),
        )
        self.assertTrue(
            any(i["reason"] == "extra_star_formal" for i in formal["items"])
        )

    def test_gs_cookie_slot_is_leftover_stack(self):
        from src.analysis.run_store import build_analysis_stack

        stack = build_analysis_stack(
            [],
            tu_text=(
                "undefined1 local_40[32];\n"
                "longlong n;\n"
                "n = 1;\n"
            ),
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertEqual(stack["n_unknown"], 0)
        self.assertTrue(
            any(i["reason"] == "gs_cookie" for i in stack["items"])
        )

    def test_glued_placement_new_is_leftover_stack(self):
        from src.analysis.run_store import build_analysis_stack

        stack = build_analysis_stack(
            [],
            tu_text="(void)home;new (home) std::string();\n",
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertEqual(stack["n_unknown"], 0)
        self.assertTrue(
            any(i["reason"] == "glued_new" for i in stack["items"])
        )

    def test_overlay_ptr_qword_is_leftover_stack(self):
        from src.analysis.run_store import build_analysis_stack

        msg = (
            "invalid conversion from 'undefined1*' {aka 'unsigned char*'} "
            "to 'undefined8' {aka 'long long unsigned int'} [-fpermissive]"
        )
        stack = build_analysis_stack(
            [{"message": msg}],
            tu_text=(
                "(*(undefined8 *)((char *)(auStack_20) + 8)) = &local_9;\n"
            ),
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertEqual(stack["n_unknown"], 0)
        self.assertTrue(
            any(i["reason"] == "overlay_ptr" for i in stack["items"])
        )
        self.assertIn("ghidra-overlay-ptr-qword", stack["known_ids"])

    def test_opt_in_facts_go_to_stack_not_as_c(self):
        from src.analysis.run_store import build_analysis_stack

        leftover = (
            "longlong ****xs[8];\n"
            "p = (longlong ***)xs;\n"
            "helper((longlong *)p);\n"
        )
        facts = {
            "addr": "0x1",
            "size": 16,
            "callees": [],
            "stack_alloc": 64,
            "lea_arg_slots": [-32],
            "qword_store_slots": [-32],
            "source": "dump_meta+func_bytes",
            "has_byte_facts": True,
        }
        stack = build_analysis_stack(
            [],
            tu_text=leftover,
            disasm_facts=[facts],
            restored=[{
                "cpp_code": leftover,
                "fn_facts": facts,
            }],
        )
        self.assertTrue(stack["disasm_facts"]["opt_in"])
        self.assertEqual(stack["disasm_facts"]["n"], 1)
        dumped = json.dumps(stack["disasm_facts"])
        self.assertNotIn("****", dumped)
        self.assertNotIn("ghidra_code", dumped)
        self.assertTrue(
            any(i["reason"] == "facts_disagree" for i in stack["items"])
        )

    def test_truncated_imm_overlay_promotes_leftover(self):
        from src.analysis.run_store import build_analysis_stack

        cmp_msg = (
            "too few arguments to function "
            "'int __gmpz_cmp_ui(mpz_srcptr, long unsigned int)'"
        )
        stack = build_analysis_stack(
            [{"message": cmp_msg}],
            tu_text="void wrap(void) { __gmpz_cmp_ui(param_1); }\n",
            call_sites={
                "sites": [{
                    "iat_name": "__gmpz_cmp_ui",
                    "arg_regs": ["rcx", "rdx"],
                    "imm_slots": [["rdx", 1]],
                }]
            },
            iat_facts={"protos": [{"name": "__gmpz_cmp_ui", "arity": 2}]},
        )
        self.assertGreaterEqual(stack["n_leftover"], 1)
        self.assertNotIn("ghidra truncated mpz call", stack["skip_forever"])
        self.assertTrue(
            any(i["reason"] == "call_arity" for i in stack["items"])
        )

    def test_truncated_empty_bag_stays_skip(self):
        from src.analysis.run_store import build_analysis_stack

        cmp_msg = (
            "too few arguments to function "
            "'int __gmpz_cmp_ui(mpz_srcptr, long unsigned int)'"
        )
        stack = build_analysis_stack(
            [{"message": cmp_msg}],
            tu_text="void wrap(void) { __gmpz_cmp_ui(param_1); }\n",
        )
        self.assertEqual(stack["n_leftover"], 0)
        self.assertIn("ghidra truncated mpz call", stack["skip_forever"])

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
