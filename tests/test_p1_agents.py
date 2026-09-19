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
from src.agents.critic import (
    ROLE_RANK,
    dialect_hits,
    director_contract,
    p8_restore_contract,
    prefer_dump_if_stub,
    review_compile_fix,
    review_function,
    review_run,
)
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
        ull = match_errors(
            [{
                "message": (
                    "invalid conversion from 'long long unsigned int' "
                    "to 'mpz_ptr' {aka '__mpz_struct*'} [-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(ull.need_llm)
        self.assertIn("ghidra word vs mpz_ptr", ull.skip_forever_reasons)

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
            "'param_2' was not declared in this scope",
            "'param_1' was not declared in this scope",
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

    def test_skip_forever_value_type_vs_elem_ptr(self):
        decision = match_errors(
            [{
                "message": (
                    "cannot convert '__gnu_cxx::__alloc_traits<std::allocator<Item>, "
                    "Item>::value_type' {aka 'Item'} to 'Item*'"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("value_type T vs T*", decision.skip_forever_reasons)

    def test_skip_forever_vector_star_vs_vector_ref(self):
        for msg in (
            "invalid initialization of reference of type "
            "'const std::vector<Item>&' from expression of type "
            "'std::vector<Item>*'",
            "invalid initialization of reference of type "
            "'std::vector<Item>&' from expression of type "
            "'std::vector<Item>*'",
        ):
            decision = match_errors([{"message": msg}], cases=[])
            self.assertFalse(decision.need_llm, msg)
            self.assertIn("T* vs T&", decision.skip_forever_reasons)

    def test_skip_forever_string_star_vs_string_ref(self):
        decision = match_errors(
            [{
                "message": (
                    "invalid initialization of reference of type "
                    "'const std::string&' {aka 'const std::__cxx11::basic_string<char>&'} "
                    "from expression of type 'std::string*' "
                    "{aka 'std::__cxx11::basic_string<char>*'}"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("T* vs T&", decision.skip_forever_reasons)

    def test_skip_forever_const_string_star_vs_string_star(self):
        decision = match_errors(
            [{
                "message": (
                    "invalid conversion from 'const std::string*' "
                    "{aka 'const std::__cxx11::basic_string<char>*'} "
                    "to 'std::string*' {aka 'std::__cxx11::basic_string<char>*'} "
                    "[-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("const string* vs string*", decision.skip_forever_reasons)

    def test_skip_forever_int_vs_mpfr_rnd(self):
        decision = match_errors(
            [{"message": "invalid conversion from 'int' to 'mpfr_rnd_t' [-fpermissive]"}],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("int vs mpfr_rnd_t", decision.skip_forever_reasons)

    def test_skip_forever_word_vs_char_star(self):
        decision = match_errors(
            [{
                "message": (
                    "invalid conversion from 'undefined8' "
                    "{aka 'long long unsigned int'} to 'char*' [-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("word vs char*", decision.skip_forever_reasons)

    def test_skip_forever_undefined_vs_undefined_star(self):
        decision = match_errors(
            [{
                "message": (
                    "invalid conversion from 'undefined1' {aka 'unsigned char'} "
                    "to 'undefined1*' {aka 'unsigned char*'} [-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("undefined vs undefined*", decision.skip_forever_reasons)

    def test_skip_forever_uchar_star_vs_char_star(self):
        decision = match_errors(
            [{
                "message": (
                    "invalid conversion from 'unsigned char*' to 'char*' "
                    "[-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("unsigned char* vs char*", decision.skip_forever_reasons)
        aka = match_errors(
            [{
                "message": (
                    "invalid conversion from 'undefined*' "
                    "{aka 'unsigned char*'} to 'const char*' [-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(aka.need_llm)
        self.assertIn("unsigned char* vs char*", aka.skip_forever_reasons)

    def test_skip_forever_size_type_vs_vector_star(self):
        decision = match_errors(
            [{
                "message": (
                    "invalid conversion from 'std::vector<unsigned char>::size_type' "
                    "{aka 'long long unsigned int'} to 'std::vector<unsigned char>*' "
                    "[-fpermissive]"
                ),
            }],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("size_type vs vector*", decision.skip_forever_reasons)

    def test_skip_forever_value_type_not_member_of_user(self):
        decision = match_errors(
            [{"message": "'value_type' is not a member of 'Item'"}],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("value_type not a member of T", decision.skip_forever_reasons)

    def test_skip_forever_msvc_jmc_helper(self):
        decision = match_errors(
            [{"message": "'checkForDebuggerJustMyCode' was not declared in this scope"}],
            cases=[],
        )
        self.assertFalse(decision.need_llm)
        self.assertIn("MSVC JMC helper", decision.skip_forever_reasons)

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
                "cannot convert 'ghidra_word*' to 'const char*' in assignment",
                "const char*",
            ),
            (
                "cannot convert 'ghidra_word*' to 'char*' in assignment",
                "char*",
            ),
            (
                "invalid cast from type 'ghidra_word' to type 'const char*'",
                "reinterpret cstr",
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
        also = match_errors(
            [{"message": "'bool is_open' redeclared as different kind of entity"}],
            cases=[],
        )
        self.assertFalse(also.need_llm)
        self.assertIn("ident redeclared as different kind", also.skip_forever_reasons)


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

    def test_restore_stub_name_is_identity_fail(self):
        entry = {
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "walk_keys",
            "name": "walk_keys",
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": 'int walk_keys(int n) { puts("k"); return n; }',
        }
        verdict = review_function(entry, 'void func() { puts("k"); }\n', [])
        self.assertFalse(verdict.identity_ok)
        self.assertFalse(verdict.accept)
        self.assertTrue(any("restore stub name" in r for r in verdict.reasons))

    def test_restore_stub_vs_dump_size_is_identity_fail(self):
        pad = "".join(f"v{i}=0;" for i in range(80))
        dump = f'int walk_keys(int n) {{ puts("k"); {pad} return n; }}'
        entry = {
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "walk_keys",
            "name": "walk_keys",
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": dump,
        }
        short = 'int walk_keys(int n) { puts("k"); }\n'
        verdict = review_function(entry, short, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(any("restore stub vs dump size" in r for r in verdict.reasons))
        faithful = review_function(entry, dump + "\n", [])
        self.assertTrue(faithful.identity_ok)
        self.assertTrue(faithful.accept)
        compact = (
            'int walk_keys(int n) {\n'
            '  puts("k");\n'
            '  for (int i = 0; i < n; i++) puts("k");\n'
            '  return n;\n'
            '}\n'
        )
        kept = review_function(entry, compact, [])
        self.assertTrue(kept.identity_ok)

    def test_leftover_in_reg_is_identity_fail(self):
        entry = {
            "address": "0x1",
            "guessed_name": "show_rec",
            "ghidra_name": "show_rec",
            "name": "show_rec",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "void show_rec(Rec *p) { (void)p; }",
        }
        leftover = (
            "void show_rec(Rec *p) {\n"
            "  undefined8 *in_RCX;\n"
            "  (void)*in_RCX;\n"
            "}\n"
        )
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(any("restore leftover in_REG" in r for r in verdict.reasons))
        bound = "void show_rec(Rec *p) { (void)*p; }\n"
        ok = review_function(entry, bound, [])
        self.assertTrue(ok.identity_ok)
        stack_only = (
            "void show_rec(Rec *p) {\n"
            "  Rec *in_stack_ffffffffffffffb8;\n"
            "  (void)p;\n"
            "}\n"
        )
        stack = review_function(entry, stack_only, [])
        self.assertTrue(stack.identity_ok)
        quoted = 'void show_rec(Rec *p) { (void)p; const char *s = "in_RCX"; }\n'
        self.assertTrue(review_function(entry, quoted, []).identity_ok)
        invented_sret = (
            "string * show_rec(Rec *p) {\n"
            "  undefined8 *in_RCX;\n"
            "  (void)*in_RCX;\n"
            "}\n"
        )
        self.assertFalse(review_function(entry, invented_sret, []).identity_ok)
        sret_entry = {
            "address": "0x2",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": (
                "string * wrap(int *n)\n"
                "{\n"
                "  string *in_RCX;\n"
                "  return in_RCX;\n"
                "}\n"
            ),
        }
        sret_ok = (
            "string * wrap(int *n) {\n"
            "  string *in_RCX;\n"
            "  (void)n;\n"
            "  return in_RCX;\n"
            "}\n"
        )
        self.assertTrue(review_function(sret_entry, sret_ok, []).identity_ok)
        sret_rdx = (
            "string * wrap(int *n) {\n"
            "  string *in_RCX;\n"
            "  undefined8 in_RDX;\n"
            "  (void)in_RDX;\n"
            "  return in_RCX;\n"
            "}\n"
        )
        rdx_v = review_function(sret_entry, sret_rdx, [])
        self.assertFalse(rdx_v.identity_ok)
        self.assertTrue(any("restore leftover in_REG" in r for r in rdx_v.reasons))
        rec_entry = {
            "address": "0x3",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": (
                "struct Rec { int n; };\n"
                "Rec * wrap(int *n)\n"
                "{\n"
                "  Rec *in_RCX;\n"
                "  return in_RCX;\n"
                "}\n"
            ),
        }
        rec_ok = (
            "Rec * wrap(int *n) {\n"
            "  Rec *in_RCX;\n"
            "  (void)n;\n"
            "  return in_RCX;\n"
            "}\n"
        )
        self.assertTrue(review_function(rec_entry, rec_ok, []).identity_ok)
        extra_dump = (
            "struct Rec { int n; };\n"
            "Rec * make(void);\n"
            "Rec * wrap(void)\n"
            "{\n"
            "  Rec *extraout_RAX;\n"
            "  make();\n"
            "  return extraout_RAX;\n"
            "}\n"
        )
        extra_entry = {
            "address": "0x4",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": extra_dump,
        }
        self.assertTrue(review_function(extra_entry, extra_dump, []).identity_ok)
        invented_extra = (
            "Rec * wrap(void) {\n"
            "  Rec *extraout_RAX;\n"
            "  return extraout_RAX;\n"
            "}\n"
        )
        inv = review_function(
            {
                "address": "0x5",
                "guessed_name": "wrap",
                "ghidra_name": "wrap",
                "name": "wrap",
                "literals": [],
                "ext_calls": [],
                "ghidra_code": "Rec * wrap(void) { return p; }\n",
            },
            invented_extra,
            [],
        )
        self.assertFalse(inv.identity_ok)
        self.assertTrue(any("restore leftover extraout" in r for r in inv.reasons))

    def test_leftover_dead_array_home_is_identity_fail(self):
        from src.agents.critic import dialect_hits, review_function

        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "void wrap(void) { (void)0; }",
        }
        leftover = (
            "void use(int n);\n"
            "void wrap(void)\n"
            "{\n"
            "  int xs [4];\n"
            "  int i;\n"
            "  int in_stk_n40;\n"
            "  for (i = 0; i < 4; i = i + 1) {\n"
            "    use(in_stk_n40);\n"
            "  }\n"
            "}\n"
        )
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover dead_array xs" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.source == "compiler" and h.kind == "dead_array" and h.token == "xs"
                for h in dialect_hits(leftover)
            )
        )
        bound = (
            "void use(int n);\n"
            "void wrap(void)\n"
            "{\n"
            "  int xs[4] = {1, 2, 3, 4};\n"
            "  int i;\n"
            "  for (i = 0; i < 4; i = i + 1) {\n"
            "    use(xs[i]);\n"
            "  }\n"
            "}\n"
        )
        ok = review_function(entry, bound, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any(h.kind == "dead_array" for h in dialect_hits(bound)))
        stack_only = (
            "void wrap(void)\n"
            "{\n"
            "  int in_stk_n40;\n"
            "  (void)in_stk_n40;\n"
            "}\n"
        )
        stack = review_function(entry, stack_only, [])
        self.assertTrue(stack.identity_ok)
        self.assertFalse(any(h.kind == "dead_array" for h in dialect_hits(stack_only)))

    def test_dialect_hits_split_ghidra_compiler_human(self):
        ghidra = dialect_hits(
            "void wrap(unsigned long long x) { x = CONCAT44(a, b); (void)x; }\n"
        )
        self.assertTrue(any(h.source == "ghidra" and h.kind == "concat" for h in ghidra))
        self.assertFalse(any(h.source == "compiler" for h in ghidra))
        abi = dialect_hits(
            "void wrap(void) { undefined8 *in_RCX; (void)*in_RCX; }\n"
        )
        sources = {h.source for h in abi}
        self.assertIn("compiler", sources)
        self.assertIn("ghidra", sources)
        self.assertTrue(any(h.token == "in_RCX" for h in abi))
        human = dialect_hits(
            "void wrap(std::vector<int> *p) {\n"
            "  p->push_back(1);\n"
            "  std::cout << \"n=\" << 1;\n"
            "}\n"
        )
        self.assertEqual(human, [])
        ostream_addr = dialect_hits(
            "void wrap(int n) {\n"
            "  std::ostream *p;\n"
            "  p = (std::ostream *)(&((*((std::ostream *)p)) << (n)));\n"
            "}\n"
        )
        self.assertTrue(
            any(h.source == "ghidra" and h.kind == "ostream" for h in ostream_addr)
        )
        ostream_cout = dialect_hits(
            "void wrap(void) {\n"
            "  std::ostream *p;\n"
            "  p = (&((*(std::cout)) << (\"Number: \")));\n"
            "}\n"
        )
        self.assertTrue(
            any(h.source == "ghidra" and h.kind == "ostream" for h in ostream_cout)
        )
        ctor = dialect_hits(
            "Rec(Rec *param_2) {\n"
            "  *(undefined4 *)(in_RCX + 8) = *(undefined4 *)(in_RDX + 8);\n"
            "}\n"
        )
        self.assertTrue(
            any(h.source == "compiler" and h.kind == "special_member" and h.token == "Rec" for h in ctor)
        )
        dctor = dialect_hits(
            "Rec() {\n"
            "  std::string *in_stk_n40;\n"
            "  std::string(in_stk_n40);\n"
            "}\n"
        )
        self.assertTrue(
            any(h.source == "compiler" and h.kind == "special_member" and h.token == "Rec" for h in dctor)
        )
        human_ctor = dialect_hits(
            "Rec() {\n"
            "  id.clear();\n"
            "}\n"
        )
        self.assertFalse(any(h.kind == "special_member" for h in human_ctor))
        thiscall_copy = dialect_hits(
            "voidnew (Rec *this) Rec(Rec *param_2) {"
            "  *(undefined4 *)(in_RCX + 8) = 0;\n"
            "}\n"
        )
        self.assertTrue(
            any(
                h.source == "compiler" and h.kind == "special_member" and h.token == "Rec"
                for h in thiscall_copy
            )
        )
        thiscall_dctor = dialect_hits(
            "void __thiscallnew (Rec *this) Rec() {\n"
            "  std::string *in_stk_n40;\n"
            "  std::string(in_stk_n40);\n"
            "}\n"
        )
        self.assertTrue(
            any(
                h.source == "compiler" and h.kind == "special_member" and h.token == "Rec"
                for h in thiscall_dctor
            )
        )
        self.assertFalse(
            any(
                h.kind == "special_member"
                for h in dialect_hits("void wrap(Rec *p) { (void)p; }\n")
            )
        )
        dead = dialect_hits(
            "void use(int n);\n"
            "void wrap(void) {\n"
            "  int xs [4];\n"
            "  int i;\n"
            "  int in_stk_n40;\n"
            "  for (i = 0; i < 4; i = i + 1) {\n"
            "    use(in_stk_n40);\n"
            "  }\n"
            "}\n"
        )
        self.assertTrue(
            any(h.source == "compiler" and h.kind == "dead_array" and h.token == "xs" for h in dead)
        )
        shift = dialect_hits(
            "Rec * helper(Rec *q, int k);\n"
            "Rec * wrap(Rec *p, int n) {\n"
            "  Rec *r;\n"
            "  uint in_stk_n36;\n"
            "  r = helper((Rec *)(((unsigned)(in_stk_n36) << 32) | (unsigned)(n)), n);\n"
            "  return r;\n"
            "}\n"
        )
        self.assertTrue(
            any(
                h.source == "ghidra" and h.kind == "concat_shift" and h.token == "in_stk_n36"
                for h in shift
            )
        )

    def test_dead_array_leftover_rejects_run(self):
        leftover = (
            "void wrap(void)\n"
            "{\n"
            "  int xs [4];\n"
            "  int i;\n"
            "  int in_stk_n40;\n"
            "  puts(\"k\");\n"
            "  for (i = 0; i < 4; i = i + 1) {\n"
            "    use(in_stk_n40);\n"
            "  }\n"
            "}\n"
        )
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "FUN_1",
            "name": "FUN_1",
            "cpp_code": leftover,
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": leftover,
            "compile_ok": True,
        }]
        verdict = review_run(
            restored,
            tu_text=leftover,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(verdict.identity_ok)
        self.assertFalse(verdict.accept)
        self.assertTrue(any("dead_array" in r for r in verdict.reasons))
        self.assertTrue(director_contract(verdict))
        kinds = {s["sanction"] for s in verdict.sanctions}
        self.assertIn("run_reject", kinds)

    def test_leftover_concat_shift_ptr_is_identity_fail(self):
        from src.agents.critic import dialect_hits, review_function

        leftover = (
            "Rec * helper(Rec *q, int k);\n"
            "Rec * wrap(Rec *p, int n)\n"
            "{\n"
            "  Rec *r;\n"
            "  uint in_stk_n36;\n"
            "  r = helper((Rec *)(((unsigned)(in_stk_n36) << 32) | (unsigned)(n)), n);\n"
            "  return r;\n"
            "}\n"
        )
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
        }
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover concat_shift in_stk_n36" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.source == "ghidra"
                and h.kind == "concat_shift"
                and h.token == "in_stk_n36"
                for h in dialect_hits(leftover)
            )
        )
        bound = (
            "Rec * helper(Rec *q, int k);\n"
            "Rec * wrap(Rec *p, int n)\n"
            "{\n"
            "  Rec *r;\n"
            "  r = helper(p, n);\n"
            "  return r;\n"
            "}\n"
        )
        ok = review_function(entry, bound, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any(h.kind == "concat_shift" for h in dialect_hits(bound)))
        wide = "unsigned long long wrap(unsigned a, unsigned b) { return ((unsigned)(a) << 32) | (unsigned)(b); }\n"
        self.assertFalse(any(h.kind == "concat_shift" for h in dialect_hits(wide)))
        temp = (
            "Rec * helper(Rec *q, int k);\n"
            "Rec * wrap(Rec *p, int n)\n"
            "{\n"
            "  Rec *r;\n"
            "  uint uVar1;\n"
            "  r = helper((Rec *)CONCAT44(uVar1, n), n);\n"
            "  return r;\n"
            "}\n"
        )
        temp_v = review_function(entry, temp, [])
        self.assertFalse(temp_v.identity_ok)
        self.assertTrue(any("restore leftover concat_shift" in r for r in temp_v.reasons))

    def test_leftover_ostream_addr_insert_is_identity_fail(self):
        leftover = (
            "void wrap(void)\n"
            "{\n"
            "  std::ostream *pbVar1;\n"
            "  pbVar1 = (&((*(std::cout)) << (\"Number: \")));\n"
            "}\n"
        )
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
        }
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(any("restore leftover ostream_addr" in r for r in verdict.reasons))
        self.assertTrue(
            any(h.source == "ghidra" and h.kind == "ostream" for h in dialect_hits(leftover))
        )
        chain = (
            "void wrap(__uint64 *param_1)\n"
            "{\n"
            "  std::ostream *pbVar3;\n"
            "  std::ostream *pbVar4;\n"
            "  unsigned long long local_20;\n"
            "  pbVar3 = (&((*(std::cout)) << (\"\\rSteps: \")));\n"
            "  pbVar4 = (&((*(pbVar3)) << (*(__uint64 *)(param_1 + 0x10))));\n"
            "  pbVar3 = (&((*(pbVar4)) << (\" (\")));\n"
            "  pbVar4 = (&((*(pbVar3)) << (local_20)));\n"
            "  (void)pbVar4;\n"
            "}\n"
        )
        chain_v = review_function(entry, chain, [])
        self.assertFalse(chain_v.identity_ok)
        human = (
            "void wrap(void)\n"
            "{\n"
            "  std::cout << \"Number: \";\n"
            "}\n"
        )
        ok = review_function(entry, human, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any(h.kind == "ostream" for h in dialect_hits(human)))

    def test_tu_ostream_addr_leftover_rejects_run(self):
        clean = (
            "void wrap(void)\n"
            "{\n"
            "  std::cout << \"n\";\n"
            "}\n"
        )
        tu = (
            "void wrap(void)\n"
            "{\n"
            "  std::ostream *p;\n"
            "  p = (&((*(std::cout)) << (\"n\")));\n"
            "}\n"
        )
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "cpp_code": clean,
            "literals": ["n"],
            "ext_calls": [],
            "ghidra_code": clean,
            "compile_ok": True,
        }]
        verdict = review_run(
            restored,
            tu_text=tu,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(verdict.identity_ok)
        self.assertFalse(verdict.accept)
        self.assertTrue(any("ostream_addr" in r for r in verdict.reasons))
        self.assertTrue(director_contract(verdict))

    def test_leftover_concat71_low_is_identity_fail(self):
        leftover = (
            "unsigned long long wrap(ulonglong uVar2)\n"
            "{\n"
            "  unsigned long long uVar1;\n"
            "  uVar1 = (((unsigned long long)((int7)((ulonglong)uVar2 >> 8)) << 8)"
            " | (unsigned char)(1));\n"
            "  return uVar1;\n"
            "}\n"
        )
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
        }
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover concat71_low uVar2" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.source == "ghidra" and h.kind == "concat71_low" and h.token == "uVar2"
                for h in dialect_hits(leftover)
            )
        )
        human = (
            "unsigned long long wrap(ulonglong uVar2)\n"
            "{\n"
            "  unsigned long long uVar1;\n"
            "  uVar1 = ((uVar2 & ~0xffull) | (unsigned char)(1));\n"
            "  return uVar1;\n"
            "}\n"
        )
        ok = review_function(entry, human, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any(h.kind == "concat71_low" for h in dialect_hits(human)))
        mix = "unsigned long long wrap(int7 x, char y) { return CONCAT71((int7)x, y); }\n"
        self.assertFalse(any(h.kind == "concat71_low" for h in dialect_hits(mix)))
        tu = leftover
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "cpp_code": human,
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
            "compile_ok": True,
        }]
        run = review_run(
            restored,
            tu_text=tu,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(run.identity_ok)
        self.assertFalse(run.accept)
        self.assertTrue(any("concat71_low" in r for r in run.reasons))
        self.assertTrue(director_contract(run))

    def test_leftover_extra_star_stack_array_is_identity_fail(self):
        leftover = (
            "void helper(longlong *out);\n"
            "void wrap(void)\n"
            "{\n"
            "  longlong ***p;\n"
            "  longlong ****xs[8];\n"
            "  p = (longlong ***)xs;\n"
            "  helper((longlong *)p);\n"
            "  (void)xs[0];\n"
            "}\n"
        )
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
        }
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover extra_star xs" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.source == "ghidra" and h.kind == "extra_star" and h.token == "xs"
                for h in dialect_hits(leftover)
            )
        )
        human = (
            "void helper(longlong *out);\n"
            "void wrap(void)\n"
            "{\n"
            "  longlong xs[8];\n"
            "  helper(xs);\n"
            "  (void)xs[0];\n"
            "}\n"
        )
        ok = review_function(entry, human, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any(h.kind == "extra_star" for h in dialect_hits(human)))
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "cpp_code": human,
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
            "compile_ok": True,
        }]
        run = review_run(
            restored,
            tu_text=leftover,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(run.identity_ok)
        self.assertFalse(run.accept)
        self.assertTrue(any("extra_star" in r for r in run.reasons))
        self.assertTrue(director_contract(run))

    def test_leftover_gs_cookie_slot_is_identity_fail(self):
        leftover = (
            "void wrap(void)\n"
            "{\n"
            "  undefined1 local_40[32];\n"
            "  longlong n;\n"
            "  n = 1;\n"
            "  (void)n;\n"
            "}\n"
        )
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
        }
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover gs_cookie local_40" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.source == "compiler" and h.kind == "gs_cookie" and h.token == "local_40"
                for h in dialect_hits(leftover)
            )
        )
        human = (
            "void wrap(void)\n"
            "{\n"
            "  longlong n;\n"
            "  n = 1;\n"
            "  (void)n;\n"
            "}\n"
        )
        ok = review_function(entry, human, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any(h.kind == "gs_cookie" for h in dialect_hits(human)))
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "cpp_code": human,
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
            "compile_ok": True,
        }]
        run = review_run(
            restored,
            tu_text=leftover,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(run.identity_ok)
        self.assertFalse(run.accept)
        self.assertTrue(any("gs_cookie" in r for r in run.reasons))
        self.assertTrue(director_contract(run))

    def test_leftover_facts_disagree_is_identity_fail(self):
        leftover = (
            "void helper(longlong *out);\n"
            "void wrap(void)\n"
            "{\n"
            "  longlong ***p;\n"
            "  longlong ****xs[8];\n"
            "  p = (longlong ***)xs;\n"
            "  helper((longlong *)p);\n"
            "  (void)xs[0];\n"
            "}\n"
        )
        wrap_facts = {
            "stack_alloc": 64,
            "lea_arg_slots": [-32],
            "qword_store_slots": [-32],
        }
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
            "fn_facts": wrap_facts,
        }
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover facts_disagree xs" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.source == "ghidra" and h.kind == "facts_disagree" and h.token == "xs"
                for h in dialect_hits(leftover, facts=wrap_facts)
            )
        )
        self.assertFalse(
            any(h.kind == "facts_disagree" for h in dialect_hits(leftover))
        )
        human = (
            "void helper(longlong *out);\n"
            "void wrap(void)\n"
            "{\n"
            "  longlong xs[8];\n"
            "  helper(xs);\n"
            "  (void)xs[0];\n"
            "}\n"
        )
        ok = review_function({**entry, "fn_facts": wrap_facts}, human, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(
            any(h.kind == "facts_disagree" for h in dialect_hits(human, facts=wrap_facts))
        )
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "cpp_code": leftover,
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
            "fn_facts": wrap_facts,
            "compile_ok": True,
        }]
        run = review_run(
            restored,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(run.identity_ok)
        self.assertFalse(run.accept)
        self.assertTrue(any("facts_disagree" in r for r in run.reasons))
        self.assertTrue(director_contract(run))

    def test_leftover_ostream_overlay_insert_is_identity_fail(self):
        leftover = (
            "void wrap(longlong n)\n"
            "{\n"
            "  undefined1 local_40[40];\n"
            "  operator<<(local_40, n);\n"
            "}\n"
        )
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
        }
        verdict = review_function(entry, leftover, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(any("restore leftover ostream_overlay" in r for r in verdict.reasons))
        self.assertTrue(
            any(
                h.source == "ghidra" and h.kind == "overlay_insert"
                for h in dialect_hits(leftover)
            )
        )
        human = (
            "void wrap(longlong n)\n"
            "{\n"
            "  undefined1 local_40[40];\n"
            "  (*((std::ostream *)local_40)) << (n);\n"
            "}\n"
        )
        ok = review_function(entry, human, [])
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any(h.kind == "overlay_insert" for h in dialect_hits(human)))
        tu = leftover
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "cpp_code": human,
            "literals": [],
            "ext_calls": [],
            "ghidra_code": leftover,
            "compile_ok": True,
        }]
        run = review_run(
            restored,
            tu_text=tu,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(run.identity_ok)
        self.assertFalse(run.accept)
        self.assertTrue(any("ostream_overlay" in r for r in run.reasons))
        self.assertTrue(director_contract(run))

    def test_crt_user_entry_missing_is_identity_fail(self):
        dump = [
            {
                "address": "0x140001000",
                "name": "mainCRTStartup",
                "callees": ["0x140002000"],
                "lib_matched": False,
            },
            {
                "address": "0x140002000",
                "name": "FUN_140002000",
                "callees": [],
                "lib_matched": False,
            },
        ]
        other = {
            "classification": "user_code",
            "address": "0x140003000",
            "guessed_name": "wrap",
            "ghidra_name": "FUN_140003000",
            "name": "FUN_140003000",
            "cpp_code": 'void FUN_140003000(void) { puts("k"); }\n',
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": 'void FUN_140003000(void) { puts("k"); }\n',
            "compile_ok": True,
        }
        miss = review_run(
            [other],
            functions=dump,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(miss.identity_ok)
        self.assertTrue(any("crt_entry" in r for r in miss.reasons))
        kept = dict(other)
        kept["address"] = "0x140002000"
        kept["name"] = "FUN_140002000"
        kept["ghidra_name"] = "FUN_140002000"
        kept["cpp_code"] = 'void FUN_140002000(void) { puts("k"); }\n'
        kept["ghidra_code"] = 'void FUN_140002000(void) { puts("k"); }\n'
        ok = review_run(
            [kept],
            functions=dump,
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertTrue(ok.identity_ok)
        self.assertFalse(any("crt_entry" in r for r in ok.reasons))

    def test_restore_ellipsis_stub_is_identity_fail(self):
        entry = {
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "walk_keys",
            "name": "walk_keys",
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": 'void walk_keys() { puts("k"); }',
        }
        code = (
            'void sub_1400015af() {\n'
            '    // ... (body omitted)\n'
            '    puts("k");\n'
            '    // ... (body omitted)\n'
            '}\n'
        )
        verdict = review_function(entry, code, [])
        self.assertFalse(verdict.identity_ok)
        self.assertFalse(verdict.accept)
        blob = " ".join(verdict.reasons)
        self.assertTrue("restore stub name" in blob or "restore ellipsis stub" in blob)

    def test_prefer_dump_if_stub_replaces_ellipsis(self):
        from src.agents.critic import prefer_dump_if_stub

        dump = (
            'void walk_keys(int n) {\n'
            '  puts("k");\n'
            '  puts("k");\n'
            '  for (int i = 0; i < n; i++) puts("k");\n'
            '  return;\n'
            '}\n'
        )
        entry = {
            "guessed_name": "walk_keys",
            "ghidra_name": "walk_keys",
            "name": "walk_keys",
            "ghidra_code": dump,
        }
        stub = (
            'void sub_14000100() {\n'
            '    // ... (body omitted)\n'
            '    puts("k");\n'
            '}\n'
        )
        got = prefer_dump_if_stub(entry, stub)
        self.assertNotIn("...", got)
        self.assertNotIn("sub_14000100", got)
        self.assertIn("walk_keys", got)
        self.assertIn("for", got)
        kept = prefer_dump_if_stub(entry, dump)
        self.assertEqual(kept, dump)

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

    def test_per_fn_ok_accepts_despite_red_tu(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "FUN_1",
            "name": "FUN_1",
            "cpp_code": 'void walk_keys() { puts("k"); }\n',
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": 'void FUN_1() { puts("k"); }',
            "compile_ok": True,
        }]
        verdict = review_run(
            restored,
            tu_text="void walk_keys() { puts(\"k\"); }",
            compile_ok=False,
            assembled_ok=False,
        )
        self.assertTrue(verdict.compile_ok)
        self.assertFalse(verdict.assembled_ok)
        self.assertTrue(verdict.identity_ok)
        self.assertTrue(verdict.fidelity_ok)
        self.assertTrue(verdict.accept)
        self.assertNotIn("assembled TU did not compile", verdict.reasons)
        self.assertTrue(director_contract(verdict))
        kinds = {s["sanction"] for s in verdict.sanctions}
        self.assertIn("tu_report_fail", kinds)
        self.assertNotIn("run_reject", kinds)
        self.assertEqual(verdict.to_dict()["max_sanction_rank"], ROLE_RANK["assembler"])

    def test_per_fn_fail_rejects_despite_green_tu(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "FUN_1",
            "name": "FUN_1",
            "cpp_code": 'void walk_keys() { puts("k"); }\n',
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": 'void FUN_1() { puts("k"); }',
            "compile_ok": False,
        }]
        verdict = review_run(
            restored,
            tu_text="void walk_keys() { puts(\"k\"); }",
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(verdict.compile_ok)
        self.assertTrue(verdict.assembled_ok)
        self.assertFalse(verdict.accept)
        self.assertIn("per-fn syntax failed", verdict.reasons)
        self.assertTrue(director_contract(verdict))
        run_hit = [s for s in verdict.sanctions if s["sanction"] == "run_reject"]
        self.assertEqual(len(run_hit), 1)
        self.assertEqual(run_hit[0]["rank"], ROLE_RANK["critic"])
        self.assertEqual(verdict.to_dict()["max_sanction_rank"], ROLE_RANK["critic"])

    def test_tu_gate_when_per_fn_missing(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "FUN_1",
            "name": "FUN_1",
            "cpp_code": 'void walk_keys() { puts("k"); }\n',
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": 'void FUN_1() { puts("k"); }',
        }]
        verdict = review_run(
            restored,
            compile_ok=False,
            assembled_ok=False,
        )
        self.assertFalse(verdict.compile_ok)
        self.assertFalse(verdict.accept)
        self.assertIn("assembled TU did not compile", verdict.reasons)
        self.assertTrue(director_contract(verdict))
        self.assertEqual(verdict.to_dict()["max_sanction_rank"], ROLE_RANK["critic"])

    def test_director_contract_forbids_false_accept(self):
        from src.agents.critic import RunVerdict

        bad = RunVerdict(accept=True, compile_ok=False, identity_ok=True, fidelity_ok=True)
        self.assertFalse(director_contract(bad))
        ok = RunVerdict(accept=True, compile_ok=True, identity_ok=True, fidelity_ok=True)
        self.assertTrue(director_contract(ok))

    def test_p8_forbids_second_decompiler_c_and_arbiter(self):
        from src.agents.critic import RunVerdict
        from src.agents.restorer import USER_PROMPT, build_restore_prompt
        from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

        live = build_restore_prompt(
            {
                "address": "0x140001000",
                "name": "wrap",
                "ghidra_name": "FUN_wrap",
                "size": 16,
                "ida_code": "int wrap() { return 1; }\n",
                "hexrays_code": "int wrap() { return 2; }\n",
            },
            "void wrap(void) { }\n",
        )
        self.assertTrue(p8_restore_contract(USER_PROMPT))
        self.assertTrue(p8_restore_contract(live))
        self.assertNotIn("ida_code", live)
        self.assertNotIn("hexrays", live.lower())
        self.assertEqual(live.lower().count("декомпилированный код (ghidra)"), 1)
        self.assertFalse(
            p8_restore_contract(live + "\n=== HEX-RAYS ===\nint wrap() { return 1; }\n")
        )
        self.assertFalse(
            p8_restore_contract(live + "\nДекомпилированный код (Ghidra):\nvoid g2(){}\n")
        )
        self.assertFalse(p8_restore_contract("скажи кто прав: Ghidra или IDA\n"))
        ok = RunVerdict(accept=True, compile_ok=True, identity_ok=True, fidelity_ok=True)
        self.assertTrue(director_contract(ok, restore_prompt=live))
        self.assertFalse(
            director_contract(
                ok,
                restore_prompt=live + "\n=== IDA ===\nint wrap(){return 1;}\n",
            )
        )
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_empty_fact_bag_is_not_fidelity_ok(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "walk_keys",
            "ghidra_name": "FUN_1",
            "name": "FUN_1",
            "cpp_code": "int walk_keys() { return 1; }\n",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "int FUN_1() { return 1; }",
            "compile_ok": True,
        }]
        verdict = review_run(
            restored,
            tu_text="int walk_keys() { return 1; }",
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertFalse(verdict.fidelity_ok)
        self.assertFalse(verdict.accept)
        self.assertTrue(any("unscored" in r for r in verdict.reasons))
        self.assertTrue(director_contract(verdict))

    def test_dialect_leftover_does_not_reject_run(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "FUN_1",
            "name": "FUN_1",
            "cpp_code": (
                "void wrap(unsigned long long x) {\n"
                "  x = CONCAT44(a, b);\n"
                "  puts(\"k\");\n"
                "  (void)x;\n"
                "}\n"
            ),
            "literals": ["k"],
            "ext_calls": [],
            "ghidra_code": (
                "void FUN_1(unsigned long long x) {\n"
                "  x = CONCAT44(a, b);\n"
                "  puts(\"k\");\n"
                "  (void)x;\n"
                "}\n"
            ),
            "compile_ok": True,
        }]
        verdict = review_run(
            restored,
            tu_text=restored[0]["cpp_code"],
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertTrue(verdict.identity_ok)
        self.assertTrue(verdict.fidelity_ok)
        self.assertTrue(verdict.accept)
        self.assertFalse(verdict.dialect_ok)
        self.assertTrue(director_contract(verdict))
        kinds = {s["sanction"] for s in verdict.sanctions}
        self.assertIn("dialect_leftover", kinds)
        self.assertNotIn("run_reject", kinds)
        self.assertEqual(verdict.to_dict()["max_sanction_rank"], ROLE_RANK["polisher"])


if __name__ == "__main__":
    unittest.main()
