from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents.compiler import match_errors, proposal_payload, write_proposal
from src.agents.critic import review_compile_fix, review_function, review_run
from src.analysis.corpus import load_corpus
from src.analysis.gen_corpus import (
    MINI_PROGRAMS,
    compile_programs,
    emit_programs,
    eval_variations,
)


class TestGenerator(unittest.TestCase):
    def test_emit_and_syntax_check(self):
        from src.analysis.compile_verify import find_cxx_compiler

        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            paths = emit_programs(out)
            self.assertEqual(len(paths), len(MINI_PROGRAMS))
            for p in paths:
                self.assertTrue(p.exists())
                self.assertIn("int main", p.read_text(encoding="utf-8"))
            if not find_cxx_compiler():
                self.skipTest("no C++ compiler on PATH")
            reports = compile_programs(out)
            fails = [r for r in reports if not r.get("ok") and not r.get("skipped")]
            self.assertFalse(fails, fails)

    def test_identifier_variation_keeps_recipes(self):
        report = eval_variations()
        fails = [r for r in report["results"] if not r.get("ok")]
        self.assertGreaterEqual(report["n_cases"], 10)
        self.assertEqual(
            report["n_ok"],
            report["n_cases"],
            "\n".join(f"{r['id']}: {r.get('errors') or r.get('error')}" for r in fails),
        )


class TestCompilerAgent(unittest.TestCase):
    def test_match_known_ostream_fingerprint(self):
        cases = load_corpus()
        decision = match_errors(
            [{
                "file": "a.cpp",
                "line": "10",
                "message": (
                    "cannot convert 'std::basic_ostream<char>' to "
                    "'std::basic_ostream<char>*' in assignment"
                ),
            }],
            cases,
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("ostream-ghidra-syntax", decision.known_ids)

    def test_undeclared_struct_does_not_eat_lowercase_idents(self):
        cases = load_corpus()
        decision = match_errors(
            [{"message": "'deque' was not declared in this scope"}],
            cases,
        )
        self.assertNotIn("undeclared-struct-type", decision.known_ids)
        self.assertIn("bare-deque-template", decision.known_ids)
        cloud = match_errors(
            [{"message": "'CloudPt' was not declared in this scope"}],
            cases,
        )
        self.assertIn("undeclared-struct-type", cloud.known_ids)

    def test_optional_and_vector_member_fingerprints_split(self):
        cases = load_corpus()
        opt = match_errors(
            [{"message": "'value_or' is not a member of 'std::optional<int>'"}],
            cases,
        )
        vec = match_errors(
            [{"message": "'reserve' is not a member of 'std::vector<int>'"}],
            cases,
        )
        self.assertIn("optional-value-or", opt.known_ids)
        self.assertNotIn("member-call-rewrite", opt.known_ids)
        self.assertIn("member-call-rewrite", vec.known_ids)
        self.assertNotIn("optional-value-or", vec.known_ids)

    def test_thunk_dat_and_word_fingerprints_split(self):
        cases = load_corpus()
        thunk = match_errors(
            [{"message": "'thunk_FUN_140010000' was not declared in this scope"}],
            cases,
        )
        dat = match_errors(
            [{"message": "'DAT_14002db14' was not declared in this scope"}],
            cases,
        )
        conv = match_errors(
            [{"message": "cannot convert 'ghidra_word*' to 'undefined*'"}],
            cases,
        )
        self.assertIn("ghidra-word-thunk", thunk.known_ids)
        self.assertNotIn("thunk-dat-stubs", thunk.known_ids)
        self.assertIn("thunk-dat-stubs", dat.known_ids)
        self.assertNotIn("ghidra-word-thunk", dat.known_ids)
        self.assertIn("dat-addr-as-byte-ptr", conv.known_ids)
        self.assertNotIn("ghidra-word-thunk", conv.known_ids)

    def test_unknown_diagnostic_needs_llm_and_proposal(self):
        cases = load_corpus()
        decision = match_errors(
            [{
                "file": "a.cpp",
                "line": "3",
                "message": "wholly_new_ghidra_token was not declared in this scope",
            }],
            cases,
        )
        self.assertTrue(decision.need_llm)
        self.assertEqual(decision.known_ids, [])
        payload = proposal_payload(
            profile="gcc_pe_x64",
            errors=[{"message": "wholly_new_ghidra_token was not declared in this scope"}],
            snippet="void f() { wholly_new_ghidra_token x; }",
            addr="0x1",
        )
        self.assertTrue(str(payload["id"]).startswith("draft-"))
        self.assertIn("wholly_new_ghidra_token", payload["ghidra_cpp"])
        with tempfile.TemporaryDirectory() as td:
            path = write_proposal(
                Path(td),
                profile="gcc_pe_x64",
                errors=[{"message": "wholly_new_ghidra_token was not declared in this scope"}],
                snippet="void f() { wholly_new_ghidra_token x; }",
                addr="0x1",
            )
            self.assertTrue(path.exists())
            self.assertIn("auto-proposed", path.read_text(encoding="utf-8"))


class TestCritic(unittest.TestCase):
    def test_rejects_starts_with_replaced_by_sort(self):
        entry = {
            "address": "0x1",
            "guessed_name": "starts_with",
            "ghidra_name": "FUN_1400014b0",
            "literals": ["pre"],
            "ext_calls": [],
            "ghidra_code": (
                "bool FUN_1400014b0(string *s, string *p) {\n"
                "  return s->size() >= p->size();\n"
                "}\n"
            ),
        }
        swapped = (
            "void starts_with(std::vector<int>* v) {\n"
            "  std::sort(v->begin(), v->end());\n"
            "}\n"
        )
        verdict = review_function(entry, swapped, [])
        self.assertFalse(verdict.identity_ok)
        self.assertIn("std::sort", verdict.unexpected_algos)
        self.assertFalse(verdict.accept)

    def test_accepts_prefix_check(self):
        entry = {
            "address": "0x1",
            "guessed_name": "starts_with",
            "ghidra_name": "FUN_1400014b0",
            "literals": ["pre"],
            "ext_calls": [],
            "ghidra_code": 'bool FUN_1400014b0() { return s.find("pre")==0; }',
        }
        code = (
            'bool starts_with(const std::string& s) {\n'
            '  return s.find("pre") == 0;\n'
            "}\n"
        )
        verdict = review_function(entry, code, [])
        self.assertTrue(verdict.identity_ok)
        self.assertTrue(verdict.fidelity_ok)
        self.assertTrue(verdict.accept)

    def test_compile_fix_rejected_on_new_sort(self):
        restored = [{
            "address": "0x1",
            "guessed_name": "starts_with",
            "ghidra_code": "bool starts_with() { return true; }",
            "ext_calls": [],
        }]
        ok, reasons = review_compile_fix(
            "void starts_with() { std::sort(a.begin(), a.end()); }",
            restored,
        )
        self.assertFalse(ok)
        self.assertTrue(reasons)

    def test_run_rejects_green_tu_with_swap(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "starts_with",
            "ghidra_name": "FUN_1",
            "cpp_code": "void starts_with() { std::sort(a, a+n); }\n",
            "literals": ["needle"],
            "ext_calls": [],
            "ghidra_code": 'bool FUN_1() { return s.find("needle")==0; }',
        }]
        verdict = review_run(
            restored,
            tu_text="void starts_with() { std::sort(a, a+n); }",
            compile_ok=True,
        )
        self.assertFalse(verdict.identity_ok)
        self.assertFalse(verdict.accept)


if __name__ == "__main__":
    unittest.main()
