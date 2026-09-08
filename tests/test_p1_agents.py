from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents.compiler import (
    match_errors,
    proposal_payload,
    tu_compiler_action,
    write_proposal,
)
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

    def test_skip_forever_does_not_need_llm(self):
        decision = match_errors(
            [{"message": "'std::ios::good' was not declared in this scope"}],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertEqual(decision.unknown, [])
        self.assertEqual(decision.known_ids, [])
        self.assertIn("ios::good without object", decision.skip_forever_reasons)
        mixed = match_errors(
            [
                {"message": "'std::ios::good' was not declared in this scope"},
                {"message": "wholly_new_ghidra_token was not declared in this scope"},
            ],
            cases=[],
        )
        self.assertTrue(mixed.need_llm)
        self.assertEqual(len(mixed.unknown), 1)
        self.assertEqual(len(mixed.skip_forever), 1)

    def test_skip_forever_vector_const_iter_assign(self):
        decision = match_errors(
            [{
                "message": (
                    "no match for 'operator=' (operand types are "
                    "'std::vector<std::__cxx11::basic_string<char> >::const_iterator' "
                    "and 'const_iterator' {aka 'ghidra_word*'})"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn(
            "opaque iterator vs vector const_iterator",
            decision.skip_forever_reasons,
        )

    def test_skip_forever_ghidra_word_vs_mpz_ptr(self):
        decision = match_errors(
            [{
                "message": (
                    "invalid conversion from 'longlong' {aka 'long long int'} "
                    "to 'mpz_ptr' {aka '__mpz_struct*'} [-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("ghidra word vs mpz_ptr", decision.skip_forever_reasons)

    def test_skip_forever_char_star_vs_string_star(self):
        decision = match_errors(
            [{
                "message": (
                    "cannot convert 'char*' to 'std::string*' "
                    "{aka 'std::__cxx11::basic_string<char>*'} in initialization"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("char* vs string*", decision.skip_forever_reasons)

    def test_skip_forever_iterator_vs_string_star(self):
        decision = match_errors(
            [{
                "message": (
                    "cannot convert 'std::vector<std::__cxx11::basic_string<char> >::const_iterator' "
                    "to 'std::string*' {aka 'std::__cxx11::basic_string<char>*'}"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("iterator vs string*", decision.skip_forever_reasons)

    def test_skip_forever_truncated_mpz_call(self):
        decision = match_errors(
            [{
                "message": (
                    "too few arguments to function 'void __gmpz_set(mpz_ptr, mpz_srcptr)'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("ghidra truncated mpz call", decision.skip_forever_reasons)

    def test_skip_forever_truncated_mpfr_call(self):
        decision = match_errors(
            [{
                "message": (
                    "too few arguments to function "
                    "'int mpfr_gamma(mpfr_ptr, mpfr_srcptr, mpfr_rnd_t)'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("ghidra truncated mpfr call", decision.skip_forever_reasons)

    def test_skip_forever_truncated_mpfr_get_str_with_return_type(self):
        decision = match_errors(
            [{
                "message": (
                    "too few arguments to function "
                    "'char* mpfr_get_str(char*, mpfr_exp_t*, int, size_t, "
                    "mpfr_srcptr, mpfr_rnd_t)'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("ghidra truncated mpfr call", decision.skip_forever_reasons)

    def test_skip_forever_string_vs_char_compare_eq(self):
        decision = match_errors(
            [{
                "message": (
                    "no matching function for call to "
                    "'operator==<char, std::char_traits<char>, std::allocator<char> >("
                    "std::__cxx11::basic_string<char>*&, char*)'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("string vs char compare", decision.skip_forever_reasons)

    def test_skip_forever_this_in_prototype(self):
        decision = match_errors(
            [{
                "message": "expected ',' or '...' before 'this'",
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("this as Ghidra local", decision.skip_forever_reasons)

    def test_skip_forever_restore_template_debris(self):
        decision = match_errors(
            [
                {"message": "expected unqualified-id before ',' token"},
                {"message": "invalid declarator before '>' token"},
                {"message": "expected unqualified-id before '>' token"},
                {"message": "expected unqualified-id before '{' token"},
                {"message": "expected unqualified-id before string constant"},
                {"message": "expected declaration before '}' token"},
                {"message": "a function-definition is not allowed here before '{' token"},
                {"message": "expected '}' at end of input"},
            ],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertEqual(decision.unknown, [])
        self.assertIn("restore template debris", decision.skip_forever_reasons)

    def test_skip_forever_member_on_function_type(self):
        decision = match_errors(
            [{
                "message": (
                    "request for member 'back' in 'series_fn', which is of "
                    "non-class type 'std::vector<int>*(uint)' "
                    "{aka 'std::vector<int>*(unsigned int)'}"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("member on function type", decision.skip_forever_reasons)

    def test_echofilter_tu_classes_are_skip_forever(self):
        decision = match_errors(
            [
                {
                    "message": (
                        "no match for 'operator=' (operand types are "
                        "'std::vector<std::__cxx11::basic_string<char> >::const_iterator' "
                        "and 'const_iterator' {aka 'ghidra_word*'})"
                    ),
                },
                {
                    "message": (
                        "cannot convert 'std::vector<std::__cxx11::basic_string<char> >::const_iterator' "
                        "to 'std::string*' {aka 'std::__cxx11::basic_string<char>*'}"
                    ),
                },
                {
                    "message": (
                        "cannot convert 'char*' to 'std::string*' "
                        "{aka 'std::__cxx11::basic_string<char>*'} in initialization"
                    ),
                },
            ],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertEqual(decision.unknown, [])
        self.assertGreaterEqual(len(decision.skip_forever_reasons), 2)

    def test_skip_forever_undeclared_ghidra_temp(self):
        decision = match_errors(
            [{"message": "'pbVar3' was not declared in this scope; did you mean 'puVar2'?"}],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("undeclared ghidra temp", decision.skip_forever_reasons)

    def test_skip_forever_undeclared_ghidra_abi_temps(self):
        for msg in (
            "'in_stack_ffffffffffffff58' was not declared in this scope",
            "'in_stk_n168' was not declared in this scope",
            "'in_RCX' was not declared in this scope",
            "'in_RDX' was not declared in this scope",
            "'var_10' was not declared in this scope",
            "'var_20' was not declared in this scope",
            "'local_68' was not declared in this scope",
        ):
            decision = match_errors([{"message": msg}], cases=[])
            self.assertFalse(decision.need_llm, msg)
            self.assertIn("undeclared ghidra temp", decision.skip_forever_reasons)

    def test_undeclared_it_is_not_skip_forever(self):
        decision = match_errors(
            [{"message": "'it' was not declared in this scope; did you mean 'int'?"}],
            cases=[],
        )
        self.assertTrue(decision.need_llm)
        self.assertEqual(decision.skip_forever, [])
        self.assertEqual(len(decision.unknown), 1)

    def test_skip_forever_string_vs_string_star_assign(self):
        decision = match_errors(
            [{
                "message": (
                    "no match for 'operator=' (operand types are "
                    "'std::__cxx11::basic_string<char>' and "
                    "'std::__cxx11::basic_string<char>*')"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("string vs string* assign", decision.skip_forever_reasons)

    def test_skip_forever_map_index_by_map_star(self):
        decision = match_errors(
            [{
                "message": (
                    "no matching function for call to "
                    "'std::unordered_map<std::__cxx11::basic_string<char>, "
                    "std::__cxx11::basic_string<char> >::operator[]("
                    "std::unordered_map<std::__cxx11::basic_string<char>, "
                    "std::__cxx11::basic_string<char> >*)'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("assoc [] map* as key", decision.skip_forever_reasons)

    def test_skip_forever_beats_broad_operator_index_fingerprint(self):
        cases = load_corpus()
        decision = match_errors(
            [{
                "message": (
                    "no matching function for call to "
                    "'std::unordered_map<std::__cxx11::basic_string<char>, "
                    "std::__cxx11::basic_string<char> >::operator[]("
                    "std::unordered_map<std::__cxx11::basic_string<char>, "
                    "std::__cxx11::basic_string<char> >*)'"
                ),
            }],
            cases,
        )
        self.assertIn("assoc [] map* as key", decision.skip_forever_reasons)
        self.assertNotIn("vector-operator-index", decision.known_ids)

    def test_skip_forever_vector_star_vs_unordered_map_star(self):
        decision = match_errors(
            [{
                "message": (
                    "cannot convert 'std::vector<std::__cxx11::basic_string<char>, "
                    "std::allocator<std::__cxx11::basic_string<char> > >*' to "
                    "'std::unordered_map<std::__cxx11::basic_string<char>, "
                    "std::__cxx11::basic_string<char> >*'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("vector* vs unordered_map*", decision.skip_forever_reasons)

    def test_skip_forever_vector_star_vs_user_struct_star(self):
        for dest in ("Node*", "Tree*"):
            decision = match_errors(
                [{
                    "message": (
                        "cannot convert 'std::vector<std::__cxx11::basic_string<char> >*' "
                        f"to '{dest}'"
                    ),
                }],
                cases=[],
            )
            self.assertFalse(decision.need_llm, dest)
            self.assertIn("vector* vs user struct*", decision.skip_forever_reasons)

    def test_skip_forever_struct_before_header_typedef(self):
        decision = match_errors(
            [{
                "message": (
                    "using typedef-name '__mpfr_struct' after 'struct' "
                    "[-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("struct before header typedef", decision.skip_forever_reasons)

    def test_skip_forever_restore_quote_debris(self):
        decision = match_errors(
            [{"message": 'missing terminating " character'}],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("restore quote debris", decision.skip_forever_reasons)

    def test_skip_forever_ghidra_word_dummy_family(self):
        for msg, label in (
            ("no match for call to '(ghidra_word) ()'", "functor"),
            (
                "'using value_type = struct ghidra_word' "
                "{aka 'struct ghidra_word'} has no member named 'first'",
                "member",
            ),
            (
                "no match for 'operator[]' (operand types are "
                "'ghidra_word' and 'int')",
                "index",
            ),
            (
                "iterator_traits<ghidra_word>::iterator_category is not a type",
                "algo",
            ),
            (
                "cannot convert 'ghidra_word*' to 'std::vector<int>*'",
                "vector*",
            ),
            (
                "no match for 'operator+' (operand types are "
                "'ghidra_word' and 'int')",
                "novel",
            ),
        ):
            decision = match_errors([{"message": msg}], cases=[])
            self.assertFalse(decision.need_llm, label)
            self.assertIn("ghidra_word dummy", decision.skip_forever_reasons, label)

    def test_skip_forever_non_type_in_std_template(self):
        decision = match_errors(
            [{
                "message": (
                    "type/value mismatch at argument 1 in template parameter "
                    "list for 'template<class> class std::allocator'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("non-type in std template", decision.skip_forever_reasons)
        vector = match_errors(
            [{
                "message": (
                    "type/value mismatch at argument 1 in template parameter "
                    "list for 'template<class _Tp, class _Alloc> class std::vector'"
                ),
            }],
            cases=[],
        )
        self.assertIn("non-type in std template", vector.skip_forever_reasons)

    def test_duration_cast_targs_stay_known_not_skip_forever(self):
        cases = load_corpus()
        decision = match_errors(
            [{
                "message": (
                    "wrong number of template arguments (3, should be 1) "
                    "for 'std::chrono::duration_cast'"
                ),
            }],
            cases,
        )
        self.assertEqual(decision.skip_forever, [])
        self.assertIn("ghidra-chrono-duration-cast-targs", decision.known_ids)

    def test_netpath_template_arity_without_duration_cast_is_unknown(self):
        decision = match_errors(
            [{"message": "wrong number of template arguments (3, should be 2)"}],
            cases=[],
        )
        self.assertTrue(decision.need_llm)
        self.assertEqual(decision.skip_forever, [])

    def test_tu_compiler_action_unknown_is_proposal_not_fix(self):
        unknown = match_errors(
            [{"message": "wrong number of template arguments (3, should be 2)"}],
            cases=[],
        )
        self.assertEqual(tu_compiler_action(unknown), "proposal")
        skip = match_errors(
            [{"message": "ios::good was not declared in this scope"}],
            cases=[],
        )
        self.assertEqual(tu_compiler_action(skip), "skip")

    def test_skip_forever_vector_allocator_star_ctor(self):
        decision = match_errors(
            [{
                "message": (
                    "no matching function for call to "
                    "'std::vector<char, std::allocator<char> >::vector("
                    "size_type, std::allocator<char>*&)'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("ghidra vector allocator* ctor", decision.skip_forever_reasons)

    def test_mpfr_to_string_undeclared_is_unknown_not_skip(self):
        decision = match_errors(
            [{"message": "'mpfr_to_string' was not declared in this scope"}],
            cases=[],
        )
        self.assertTrue(decision.need_llm)
        self.assertEqual(decision.skip_forever, [])
        self.assertEqual(tu_compiler_action(decision), "proposal")

    def test_skip_forever_user_struct_star_vs_mpfr_ptr(self):
        for dest in ("mpfr_ptr", "mpfr_srcptr"):
            decision = match_errors(
                [{
                    "message": (
                        f"cannot convert 'Hold*' to '{dest}' "
                        "{aka '__mpfr_struct*'}"
                    ),
                }],
                cases=[],
            )
            self.assertFalse(decision.need_llm, dest)
            self.assertIn("user struct* vs mpfr_ptr", decision.skip_forever_reasons)

    def test_skip_forever_ident_redeclared_as_different_kind(self):
        decision = match_errors(
            [{"message": "'int is_ready' redeclared as different kind of entity"}],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("ident redeclared as different kind", decision.skip_forever_reasons)


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

    def test_mangled_sort_in_dump_allows_std_sort(self):
        entry = {
            "address": "0x1",
            "guessed_name": "rank_n",
            "ghidra_name": "FUN_1",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": (
                "void FUN_1(vector<Rec> *v) {\n"
                "  sort<__gnu_cxx::__normal_iterator<Rec*, vector<Rec> >, "
                "bool (*)(Rec const&, Rec const&)>(v->begin(), v->end(), cmp);\n"
                "}\n"
            ),
        }
        code = (
            "void rank_n(std::vector<int>* v) {\n"
            "  std::sort(v->begin(), v->end());\n"
            "}\n"
        )
        verdict = review_function(entry, code, [])
        self.assertTrue(verdict.identity_ok)
        self.assertEqual(verdict.unexpected_algos, [])

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

    def test_missing_literal_not_masked_by_high_score(self):
        """Many numeric constants must not hide a dropped dump string."""
        consts = ",".join(str(n) for n in range(100, 108))
        entry = {
            "address": "0x1",
            "guessed_name": "go",
            "ghidra_name": "FUN_1",
            "literals": ["NEEDLE"],
            "ext_calls": [],
            "ghidra_code": f"void FUN_1() {{ f({consts}); puts(\"NEEDLE\"); }}",
        }
        code = f"void go() {{ f({consts}); }}\n"
        verdict = review_function(entry, code, [])
        self.assertFalse(verdict.fidelity_ok)
        self.assertIn("NEEDLE", verdict.missing_literals)
        self.assertFalse(verdict.accept)
        self.assertGreaterEqual(verdict.fidelity, 0.85)

    def test_missing_ext_not_masked_by_high_score(self):
        consts = ",".join(str(n) for n in range(100, 108))
        entry = {
            "address": "0x1",
            "guessed_name": "go",
            "ghidra_name": "FUN_1",
            "literals": [],
            "ext_calls": ["printf"],
            "ghidra_code": f"void FUN_1() {{ f({consts}); printf(\"%d\", 1); }}",
        }
        code = f"void go() {{ f({consts}); }}\n"
        verdict = review_function(entry, code, [])
        self.assertFalse(verdict.fidelity_ok)
        self.assertIn("printf", verdict.missing_ext)
        self.assertFalse(verdict.accept)

    def test_guessed_name_need_not_match_source(self):
        """Critic does not require restoring the original repository identifier."""
        entry = {
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "FUN_140001000",
            "name": "FUN_140001000",
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": 'void FUN_140001000() { puts("k"); }',
        }
        code = 'void walk_keys() { puts("k"); }\n'
        verdict = review_function(entry, code, [])
        self.assertTrue(verdict.identity_ok)
        self.assertTrue(verdict.fidelity_ok)
        self.assertTrue(verdict.accept)

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
