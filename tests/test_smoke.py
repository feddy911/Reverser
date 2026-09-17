from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents.assembler import assemble
from src.analysis.features import FEATURE_KEYS, derive_features, extract_features, FeatureIndex
from src.analysis.fidelity import check_function, dump_facts_ok
from src.analysis.scorer import GhidraFunctionScorer
from src.domains.pack import NONE_PACK


FIXTURE = Path(__file__).parent / "fixtures" / "mini_ghidra.json"


def _load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestPreamble(unittest.TestCase):
    def test_default_preamble_has_no_gmp(self):
        lines = NONE_PACK.preamble("// test")
        self.assertNotIn("#include <gmp.h>", lines)
        self.assertIn("#include <cstdint>", lines)
        self.assertIn("#include <cmath>", lines)
        self.assertFalse(any("CONCAT" in ln for ln in lines))
        self.assertTrue(any("using int7 =" in ln for ln in lines))
        self.assertTrue(any("using undefined3 =" in ln for ln in lines))


class TestFeaturesSmoke(unittest.TestCase):
    def test_derive_features_single_and_no_gmp(self):
        import src.analysis.features as feat_mod
        # единственная реализация
        self.assertTrue(callable(feat_mod.derive_features))
        ft = {
            "n_domain": 1,
            "n_literals": 0,
            "n_iostream": 0,
            "n_stdio": 0,
            "n_callers": 2,
            "hot_callers": 1,
        }
        out = derive_features(dict(ft))
        self.assertEqual(out["own_hot"], 1)
        self.assertEqual(out["hot_caller_ratio"], 0.5)
        # n_gmp больше не влияет
        cold = derive_features({"n_domain": 0, "n_gmp": 99, "n_callers": 0, "hot_callers": 0})
        self.assertEqual(cold["own_hot"], 0)

    def test_score_fixture_without_ghidra(self):
        dump = _load_fixture()
        scorer = GhidraFunctionScorer(
            dump["strings"], dump["functions"], thunks=dump["thunks"]
        )
        scored = scorer.score_all(dump["functions"])
        self.assertGreaterEqual(len(scored), 1)
        top = scored[0]
        self.assertIn("score", top)
        for k in FEATURE_KEYS:
            self.assertIn(k, top)
        # user-like FUN_ с domain DLL должен быть выше CRT
        by_name = {s["name"]: s["score"] for s in scored}
        self.assertGreater(by_name["FUN_140001000"], by_name["_RTC_CheckStackVars"])

    def test_fixture_pcode_is_dump_only_not_a_feature(self):
        from src.agents.restorer import (
            PCODE_SECTION_TITLE,
            USER_PROMPT,
            build_restore_prompt,
        )
        from src.analysis.pcode import PCODE_KEY, entry_pcode, op_lines
        from src.pipeline.runner import LLM_PROMPT_VER

        dump = _load_fixture()
        fn = dump["functions"][0]
        lines = op_lines(entry_pcode(fn))
        self.assertGreaterEqual(len(lines), 1)
        self.assertTrue(any("COPY" in ln or "RETURN" in ln for ln in lines))
        self.assertNotIn(PCODE_KEY, FEATURE_KEYS)
        from src.analysis.features import FEATURE_KEYS_V2
        self.assertNotIn(PCODE_KEY, FEATURE_KEYS_V2)
        self.assertIn("n_pcode_ops", FEATURE_KEYS_V2)
        self.assertNotIn("pcode", USER_PROMPT.lower())
        live = build_restore_prompt(fn, fn["ghidra_code"])
        self.assertNotIn(PCODE_SECTION_TITLE, live)
        self.assertNotIn("COPY", live)
        with_p = build_restore_prompt(fn, fn["ghidra_code"], pcode=fn["pcode"])
        self.assertIn(PCODE_SECTION_TITLE, with_p)
        self.assertIn("COPY", with_p)
        self.assertIn("RETURN", with_p)
        self.assertLess(
            with_p.find(PCODE_SECTION_TITLE),
            with_p.find("=== СТРОГИЕ ПРАВИЛА ==="),
        )
        self.assertEqual(LLM_PROMPT_VER, "p4")

    def test_ml_noise_penalty_sinks_crt(self):
        from src.analysis.scorer import (
            ML_NOISE_CEILING,
            apply_runtime_noise_penalty,
        )

        user = apply_runtime_noise_penalty("main", 0.9)
        crt = apply_runtime_noise_penalty("_RTC_CheckStackVars", 0.9)
        self.assertGreaterEqual(user, ML_NOISE_CEILING)
        self.assertLess(crt, ML_NOISE_CEILING)
        self.assertLessEqual(user, 1.0)
        self.assertGreaterEqual(crt, 0.0)
        # Weak user still outranks a confident CRT name (the reason we used -10).
        self.assertLess(
            apply_runtime_noise_penalty("_pei386_runtime_relocator", 1.0),
            apply_runtime_noise_penalty("main", 0.0),
        )
        self.assertEqual(len(FEATURE_KEYS), 22)


class TestAssemblerDomain(unittest.TestCase):
    def test_none_pack_no_gmp_include(self):
        restored = [{
            "classification": "user_code",
            "address": "0x140001000",
            "guessed_name": "greet",
            "ghidra_name": "FUN_140001000",
            "cpp_code": "void greet() { printf(\"hi\"); }\n",
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertNotIn("gmp.h", text)
        self.assertIn("greet", text)

    def test_assemble_keeps_types_from_code(self):
        restored = [{
            "classification": "user_code",
            "address": "0x140001000",
            "guessed_name": "step",
            "ghidra_name": "FUN_140001000",
            "cpp_code": (
                "struct MyStruct { mpz_t number; };\n"
                "void step(MyStruct* s) { (void)s; }\n"
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertIn("MyStruct", text)
        self.assertNotIn("CollatzState", text)
        self.assertNotIn("gmp.h", text)

    def test_infers_struct_from_member_access(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "init",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                "void init(Widget* obj) {\n"
                "  obj->field2 = 0;\n"
                "  obj->field3 = 1;\n"
                "}\n"
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertIn("struct Widget", text)
        self.assertIn("field2", text)
        self.assertIn("field3", text)
        self.assertNotIn("CollatzState", text)

    def test_infers_undeclared_struct_type_without_fields(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "dist2",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                "double dist2(CloudPt *a, CloudPt *b) {\n"
                "  CloudPt query;\n"
                "  (void)a; (void)b; (void)query;\n"
                "  return 0;\n"
                "}\n"
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertIn("struct CloudPt", text)

    def test_does_not_infer_ghidra_locals_as_structs(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "go",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                "void go() {\n"
                "  longlong local_110;\n"
                "  local_110 *p;\n"
                "  p = &local_110;\n"
                "}\n"
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertNotIn("struct local_110", text)

    def test_does_not_infer_gmp_mpfr_typedefs_as_structs(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "hold",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                "void hold(__mpfr_struct *x, __mpz_struct *z) {\n"
                "  mpfr_exp_t e;\n"
                "  (void)x; (void)z; (void)e;\n"
                "}\n"
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertNotIn("struct __mpfr_struct", text)
        self.assertNotIn("struct __mpz_struct", text)
        self.assertNotIn("struct mpfr_exp_t", text)

    def test_does_not_infer_ghidra_var_stack_temps_as_structs(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "go",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                "void go() {\n"
                "  var_10 *p;\n"
                "  (void)p;\n"
                "}\n"
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertNotIn("struct var_10", text)

    def test_strips_assign_from_void_function(self):
        restored = [
            {
                "classification": "user_code",
                "address": "0x1",
                "guessed_name": "step",
                "ghidra_name": "FUN_1",
                "cpp_code": "void step(int x) { (void)x; }\n",
            },
            {
                "classification": "user_code",
                "address": "0x2",
                "guessed_name": "go",
                "ghidra_name": "FUN_2",
                "cpp_code": "int go() { int u; u = step(1); return u; }\n",
            },
        ]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 2)
        self.assertIn("step(1)", text)
        self.assertNotIn("u = step", text)

    def test_thunk_and_dat_stubs(self):
        restored = [{
            "classification": "user_code",
            "address": "0x140001000",
            "guessed_name": "go",
            "ghidra_name": "FUN_140001000",
            "cpp_code": (
                "void go() {\n"
                "  thunk_FUN_140021680(\"hi\");\n"
                "  thunk_FUN_140021680(&DAT_14002db14);\n"
                "}\n"
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertIn("inline ghidra_word thunk_FUN_140021680(...)", text)
        self.assertIn("static undefined DAT_14002db14", text)

    def test_main_crt_stub(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "main",
            "ghidra_name": "main",
            "cpp_code": "int main() { __main(); return 0; }\n",
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertIn("inline void __main()", text)

    def test_adjusts_object_args_to_pointer_params(self):
        restored = [
            {
                "classification": "user_code",
                "address": "0x1",
                "guessed_name": "report",
                "ghidra_name": "FUN_1",
                "cpp_code": "void report(std::string *p) { (void)p; }\n",
            },
            {
                "classification": "user_code",
                "address": "0x2",
                "guessed_name": "go",
                "ghidra_name": "FUN_2",
                "cpp_code": (
                    "void go(std::string *q) {\n"
                    "  std::string s;\n"
                    "  report(s);\n"
                    "  report(q);\n"
                    "}\n"
                ),
            },
        ]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 2)
        self.assertIn("report(&s)", text)
        self.assertIn("report(q)", text)
        self.assertNotIn("report(&q)", text)

    def test_array_arg_decays_to_pointer_param(self):
        restored = [
            {
                "classification": "user_code",
                "address": "0x1",
                "guessed_name": "report",
                "ghidra_name": "FUN_1",
                "cpp_code": "void report(CloudPt *p) { (void)p->x; }\n",
            },
            {
                "classification": "user_code",
                "address": "0x2",
                "guessed_name": "go",
                "ghidra_name": "FUN_2",
                "cpp_code": (
                    "void go(CloudPt *q) {\n"
                    "  CloudPt cloud[2];\n"
                    "  report(cloud);\n"
                    "  report(q);\n"
                    "}\n"
                ),
            },
        ]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 2)
        self.assertIn("report(cloud)", text)
        self.assertNotIn("report(&cloud)", text)
        self.assertIn("report(q)", text)

    def test_prototypes_main_last_and_strips_includes(self):
        restored = [
            {
                "classification": "user_code",
                "address": "0x1",
                "guessed_name": "main",
                "ghidra_name": "main",
                "cpp_code": '#include <vector>\nint main() { helper(); return 0; }\n',
            },
            {
                "classification": "user_code",
                "address": "0x2",
                "guessed_name": "helper",
                "ghidra_name": "helper",
                "cpp_code": "void helper() {}\n",
            },
        ]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 2)
        self.assertIn("void helper();", text)
        self.assertIn("int main();", text)
        proto_at = text.find("// ---- prototypes ----")
        funcs_at = text.find("// ---- functions ----")
        helper_body = text.find("void helper() {", funcs_at)
        main_body = text.find("int main() {", funcs_at)
        self.assertLess(proto_at, funcs_at)
        self.assertLess(helper_body, main_body)
        # includes only in preamble, not inside function bodies
        body = text[funcs_at:]
        self.assertNotIn("#include <vector>", body)

    def test_widen_def_arity_when_calls_pass_extra_args(self):
        restored = [
            {
                "classification": "user_code",
                "address": "0x1",
                "guessed_name": "show",
                "ghidra_name": "show",
                "cpp_code": "void show() { (void)0; }\n",
            },
            {
                "classification": "user_code",
                "address": "0x2",
                "guessed_name": "main",
                "ghidra_name": "main",
                "cpp_code": "int main() { show(3); return 0; }\n",
            },
        ]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 2)
        self.assertIn("show(...)", text)
        self.assertNotIn("void show() {", text)

    def test_multiline_templated_return_prototype(self):
        restored = [
            {
                "classification": "user_code",
                "address": "0x1",
                "guessed_name": "collect",
                "ghidra_name": "collect",
                "cpp_code": (
                    "unordered_map<int,_int,_std::less<int>,"
                    "_std::allocator<std::pair<int_const,_int>_>_>\n"
                    "* collect(unordered_map<int,_int> *m)\n"
                    "{\n  return m;\n}\n"
                ),
            },
        ]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        proto = text[text.find("// ---- prototypes ----"):text.find("// ---- functions ----")]
        self.assertIn("std::unordered_map<int,int", proto)
        self.assertIn(" * collect(", proto)
        self.assertNotIn("\n* collect(", proto)
        funcs = text[text.find("// ---- functions ----"):]
        self.assertIn("std::unordered_map<int,int", funcs)
        self.assertIn("* collect(", funcs)


class TestFidelitySmoke(unittest.TestCase):
    def test_literal_present_as_c_escape(self):
        """Декодированный литерал должен находиться в C++ с \\n/\\r-эскейпами."""
        from src.analysis.fidelity import literal_in_code

        code = 'std::cout << "\\rStatus: " << n << "\\n\\n====\\n";'
        self.assertTrue(literal_in_code("\rStatus: ", code))
        self.assertTrue(literal_in_code("\n\n====\n", code))
        self.assertTrue(literal_in_code("====\n", code))  # rstrip / substring
        self.assertFalse(literal_in_code("\rMissing: ", code))

    def test_literal_trailing_whitespace_tolerant(self):
        from src.analysis.fidelity import literal_in_code

        code = 'puts("hello");'
        self.assertTrue(literal_in_code("hello\n", code))
        self.assertTrue(literal_in_code("hello  ", code))

    def test_check_function_escape_vs_missing(self):
        entry = {
            "address": "0x1",
            "literals": ["\rLabel: ", "\n\n====\n"],
            "ext_calls": ["printf"],
            "ghidra_code": 'printf("x"); // 50000',
        }
        ok_code = 'printf("\\rLabel: "); puts("\\n\\n====\\n"); // 50000'
        ok = check_function(entry, ok_code, [])
        self.assertFalse(ok["drift"])
        self.assertEqual(ok["missing_literals"], [])
        self.assertGreaterEqual(ok["fidelity"], 0.99)

        bad = check_function(entry, 'puts("x"); // 50000', [])
        self.assertTrue(bad["drift"])
        self.assertEqual(len(bad["missing_literals"]), 2)
        self.assertFalse(dump_facts_ok(bad))
        self.assertLess(bad["fidelity"], 1.0)

    def test_noise_calls_ignored(self):
        """Debug/instrumentation callees не должны портить fidelity."""
        from src.analysis.fidelity import build_call_tokens, check_function

        name_by_addr = {
            "0x1000": "__CheckForDebuggerJustMyCode",
            "0x2000": "FUN_2000",
        }
        thunk_target = {"0x0100": "0x1000", "0x0200": "0x2000"}
        toks = build_call_tokens(
            ["0x0100", "0x0200"],
            name_by_addr=name_by_addr,
            thunk_target=thunk_target,
        )
        labels = [n for n, _ in toks]
        self.assertNotIn("__CheckForDebuggerJustMyCode", labels)
        self.assertIn("FUN_2000", labels)

        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": ["__CheckForDebuggerJustMyCode", "printf"],
            "ghidra_code": "x = 0xcccccccc; printf(0); FUN_2000();",
            "callees": ["0x0100", "0x0200"],
        }
        code = 'printf("hi"); FUN_2000(); // ignore 0xcccccccc'
        rep = check_function(entry, code, toks)
        self.assertFalse(rep["drift"])
        self.assertEqual(rep["missing_calls"], [])
        self.assertEqual(rep["missing_ext"], [])
        self.assertNotIn("0xcccccccc", rep["missing_consts"])
        self.assertGreaterEqual(rep["fidelity"], 0.99)

    def test_operator_shift_not_required_as_call_name(self):
        from src.analysis.fidelity import build_call_tokens, check_function

        toks = build_call_tokens(
            ["0x10"],
            name_by_addr={"0x10": "operator<<"},
            thunk_target={},
        )
        self.assertEqual(toks, [])
        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": ["operator<<"],
            "ghidra_code": "std::cout << x;",
        }
        code = 'std::cout << "hi";'
        rep = check_function(entry, code, toks)
        self.assertEqual(rep["missing_ext"], [])
        self.assertEqual(rep["missing_calls"], [])

    def test_unresolved_addr_not_required_as_fun(self):
        from src.analysis.fidelity import build_call_tokens, check_function

        toks = build_call_tokens(["0x140008000"], name_by_addr={}, thunk_target={})
        self.assertEqual(toks, [])
        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "return hypot(x, y);",
        }
        rep = check_function(entry, "return hypot(x, y);", toks)
        self.assertFalse(rep["drift"])
        self.assertEqual(rep["missing_calls"], [])

    def test_import_thunk_name_required(self):
        from src.analysis.fidelity import (
            build_call_tokens,
            check_function,
            symbol_names_from_dump,
        )

        names = symbol_names_from_dump(
            functions=[],
            thunks=[{"address": "0x2000", "name": "hypot", "target": None}],
        )
        toks = build_call_tokens(["0x2000"], name_by_addr=names, thunk_target={})
        self.assertEqual([n for n, _ in toks], ["hypot"])
        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "return hypot(x, y);",
        }
        ok = check_function(entry, "return hypot(a, b);", toks)
        self.assertFalse(ok["drift"])
        bad = check_function(entry, "return a + b;", toks)
        self.assertTrue(bad["drift"])
        self.assertIn("hypot", bad["missing_calls"])

    def test_range_for_dump_does_not_require_begin_end(self):
        from src.analysis.fidelity import check_function, dump_facts_ok

        entry = {
            "address": "0x1",
            "literals": ["hi"],
            "ext_calls": [],
            "ghidra_code": (
                "const_iterator __for_begin;\n"
                "const_iterator __for_end;\n"
                "__for_begin = std::vector<int>::begin(p);\n"
            ),
        }
        toks = [
            ("begin", ["begin"]),
            ("end", ["end"]),
            ("print_n", ["print_n"]),
        ]
        restore = 'void f() { for (int x : *p) n += x; print_n("hi"); }\n'
        rep = check_function(entry, restore, toks)
        self.assertNotIn("begin", rep["missing_calls"])
        self.assertNotIn("end", rep["missing_calls"])
        self.assertEqual(rep["missing_calls"], [])
        self.assertFalse(rep["drift"])
        self.assertTrue(dump_facts_ok(rep))

        no_marker = dict(entry, ghidra_code="n = begin(p);")
        strict = check_function(no_marker, restore, toks)
        self.assertIn("begin", strict["missing_calls"])
        self.assertTrue(dump_facts_ok(strict))

    def test_range_for_dump_does_not_require_std_get(self):
        from src.analysis.fidelity import check_function

        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": (
                "const_iterator __for_begin;\n"
                "type *k;\n"
            ),
        }
        toks = [("get<0>", ["get<0>"]), ("dump_n", ["dump_n"])]
        restore = "void f() { for (const auto& kv : *m) dump_n(kv); }\n"
        rep = check_function(entry, restore, toks)
        self.assertNotIn("get<0>", rep["missing_calls"])

    def test_duration_cast_dump_does_not_require_mangled_callee(self):
        from src.analysis.fidelity import check_function

        entry = {
            "address": "0x1",
            "literals": ["n="],
            "ext_calls": [],
            "ghidra_code": (
                "auto us = duration_cast<std::chrono::duration<"
                "long_long_int, std::ratio<1, 1000000>>>(t1 - t0);\n"
            ),
        }
        toks = [(
            "duration_cast<std::chrono::duration<long_long_int,_std::ratio<1,_1000000>_>",
            ["duration_cast<std::chrono::duration<long_long_int,_std::ratio<1,_1000000>_>"],
        )]
        restore = (
            "int f() {\n"
            "  auto us = std::chrono::duration_cast<"
            "std::chrono::microseconds>(t1 - t0).count();\n"
            "  return (int)us;\n"
            "}\n"
        )
        rep = check_function(entry, restore, toks)
        self.assertNotIn(
            "duration_cast<std::chrono::duration<long_long_int,_std::ratio<1,_1000000>_>",
            rep["missing_calls"],
        )

    def test_mangled_make_pair_matches_untemplated_call(self):
        from src.analysis.fidelity import build_call_tokens, check_function

        toks = build_call_tokens(
            ["0xabc"],
            name_by_addr={
                "0xabc": "make_pair<const_std::__cxx11::basic_string<char>&,_int&>",
            },
        )
        entry = {"address": "0x1", "literals": [], "ext_calls": [], "ghidra_code": ""}
        restore = "void f() { g[k] = std::make_pair(k, w); }\n"
        rep = check_function(entry, restore, toks)
        self.assertNotIn(
            "make_pair<const_std::__cxx11::basic_string<char>&,_int&>",
            rep["missing_calls"],
        )

    def test_iterator_type_callee_not_required(self):
        from src.analysis.fidelity import check_function

        entry = {"address": "0x1", "literals": [], "ext_calls": [], "ghidra_code": ""}
        toks = [("_Node_const_iterator", ["_Node_const_iterator"])]
        restore = "void f() { walk(m); }\n"
        rep = check_function(entry, restore, toks)
        self.assertNotIn("_Node_const_iterator", rep["missing_calls"])

    def test_vector_type_callee_not_required(self):
        from src.analysis.fidelity import check_function

        entry = {"address": "0x1", "literals": [], "ext_calls": [], "ghidra_code": ""}
        toks = [("vector", ["vector", "FUN_140004660"])]
        restore = "int main() { std::vector<int> lines; return 0; }\n"
        rep = check_function(entry, restore, toks)
        self.assertNotIn("vector", rep["missing_calls"])
        self.assertFalse(rep["scored"])

    def test_size_t_is_not_size_call(self):
        from src.analysis.fidelity import check_function

        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "sVar2 = s->size();",
        }
        toks = [("size", ["size"])]
        bad = check_function(entry, "bool f(){ size_t x=0; return true; }", toks)
        self.assertIn("size", bad["missing_calls"])
        ok = check_function(entry, "bool f(){ return s->size()==0; }", toks)
        self.assertEqual(ok["missing_calls"], [])

    def test_for_begin_ident_is_not_begin_call(self):
        from src.analysis.fidelity import check_function

        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "n = begin(p);",
        }
        toks = [("begin", ["begin"])]
        restore = "void f() { const_iterator __for_begin; }\n"
        rep = check_function(entry, restore, toks)
        self.assertIn("begin", rep["missing_calls"])

    def test_compare_is_dump_call_not_noise(self):
        from src.analysis.fidelity import build_call_tokens, check_function

        toks = build_call_tokens(
            ["0x10"], name_by_addr={"0x10": "compare"}, thunk_target={},
        )
        self.assertEqual([n for n, _ in toks], ["compare"])
        entry = {
            "address": "0x1",
            "literals": [],
            "ext_calls": [],
            "ghidra_code": "iVar1 = s->compare(0, n, p);",
        }
        ok = check_function(
            entry, "bool f(){ return s->compare(0, n, *p)==0; }", toks,
        )
        self.assertEqual(ok["missing_calls"], [])
        bad = check_function(
            entry, "bool f(){ size_t n = s->size(); return n>0; }", toks,
        )
        self.assertIn("compare", bad["missing_calls"])

    def test_templated_emplace_back_counts_as_call(self):
        from src.analysis.fidelity import check_function

        entry = {"address": "0x1", "literals": [], "ext_calls": [], "ghidra_code": ""}
        toks = [("emplace_back<char*&>", ["emplace_back<char*&>", "emplace_back"])]
        restore = "void f() { lines->emplace_back<char*&>(p); }\n"
        rep = check_function(entry, restore, toks)
        self.assertEqual(rep["missing_calls"], [])

    def test_empty_fact_bag_is_not_perfect(self):
        from src.analysis.fidelity import check_function, dump_facts_ok, should_skip_polish

        entry = {"address": "0x1", "literals": [], "ext_calls": [], "ghidra_code": ""}
        code = "int f(){ return 1; }"
        rep = check_function(entry, code, [])
        self.assertFalse(rep["scored"])
        self.assertEqual(rep["fidelity"], 0.0)
        self.assertFalse(dump_facts_ok(rep))
        self.assertFalse(should_skip_polish(rep, code))
        self.assertFalse(should_skip_polish(rep, code, compile_ok=True))

    def test_missing_user_callee_fails_dump_facts(self):
        from src.analysis.fidelity import check_function, dump_facts_ok

        toks = [("print_n", ["print_n"])]
        entry = {
            "address": "0x1",
            "literals": ["hi"],
            "ext_calls": [],
            "ghidra_code": 'print_n("hi");',
        }
        bad = check_function(entry, 'void f(){ puts("hi"); }', toks)
        self.assertIn("print_n", bad["missing_user_calls"])
        self.assertFalse(dump_facts_ok(bad))
        ok = check_function(entry, 'void f(){ print_n("hi"); }', toks)
        self.assertTrue(dump_facts_ok(ok))

    def test_residue_blocks_polish_skip(self):
        from src.analysis.fidelity import should_skip_polish

        fid = {"fidelity": 1.0, "scored": True}
        residue = "int main(){ in_stk_n8 = 0; }"
        self.assertFalse(should_skip_polish(fid, residue))
        self.assertFalse(
            should_skip_polish(fid, "undefined1 auStack_20[16]; auStack_20._8_8_ = 1;")
        )
        self.assertTrue(should_skip_polish(fid, residue, compile_ok=True))
        self.assertFalse(should_skip_polish(fid, "int main(){ return 0; }"))
        self.assertTrue(
            should_skip_polish(fid, "int main(){ return 0; }", compile_ok=True)
        )

    def test_high_fid_does_not_skip_polish_when_compile_failed(self):
        from src.analysis.fidelity import should_skip_polish

        fid = {"fidelity": 1.0, "scored": True}
        body = "int main(){ return series_fn.back(); }"
        self.assertFalse(should_skip_polish(fid, body, compile_ok=False))
        self.assertFalse(should_skip_polish(fid, body))
        green = "int main(){ return 0; }"
        self.assertTrue(should_skip_polish(fid, green, compile_ok=True))

    def test_keep_dump_literals_comments_missing(self):
        from src.agents.restorer import keep_dump_literals
        from src.analysis.fidelity import literal_in_code
        from src.analysis.ghidra_cpp import extract_named_function

        code = "int main() { return 0; }\n"
        got = keep_dump_literals(code, ["ERROR: mode missing\n", "Selected mode: "])
        self.assertTrue(literal_in_code("ERROR: mode missing\n", got))
        self.assertTrue(literal_in_code("Selected mode: ", got))
        self.assertIn("dump-fact", got)
        extracted = extract_named_function(got, "main")
        self.assertIn("dump-fact", extracted)
        self.assertTrue(literal_in_code("Selected mode: ", extracted))

    def test_repair_restore_debris_newline_char_and_void0(self):
        from src.agents.restorer import repair_restore_debris

        src = "if (c != '" + "\n" + "') { return 1; }(void)0;\n"
        got = repair_restore_debris(src)
        self.assertIn("'\\n'", got)
        self.assertIn("(void)0; }", got)
        self.assertNotIn("}(void)0;", got)

    def test_repair_restore_debris_strips_backticks(self):
        from src.agents.restorer import repair_restore_debris

        tick = chr(96)
        src = f"int f() {{ return 1; }} {tick}extra{tick}\n"
        got = repair_restore_debris(src)
        self.assertNotIn(tick, got)
        self.assertIn("int f()", got)

    def test_repair_restore_debris_closes_unbalanced_dquote(self):
        from src.agents.restorer import repair_restore_debris

        src = 'std::string s = "hello;\nreturn 0;\n'
        got = repair_restore_debris(src)
        self.assertIn('std::string s = "hello;"', got)
        src_ok = 'std::string s = "hello";\n'
        self.assertEqual(repair_restore_debris(src_ok), src_ok)

    def test_repair_method_on_callee_uses_dump_not_local(self):
        from src.agents.restorer import repair_method_on_callee_name
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        dump = (
            "pvVar4 = std::vector<int,_std::allocator<int>_>::back\n"
            "                     (in_stack_ffffffffffffff78);\n"
        )
        names = ["series_fn", "print_series"]
        missing_recv = (
            "int main() {\n"
            "  series_fn(n);\n"
            "  std::cout << series_fn.back();\n"
            "  std::cout << local.back();\n"
            "}\n"
        )
        skipped = repair_method_on_callee_name(
            missing_recv, ghidra_code=dump, function_names=names,
        )
        self.assertIn("series_fn.back()", skipped)
        self.assertNotIn("in_stack_ffffffffffffff78", skipped)

        dump_decl = (
            "void walk_main() {\n"
            "  vector<int,_std::allocator<int>_> *in_stack_ffffffffffffff78;\n"
            "  " + dump +
            "}\n"
        )
        grafted = repair_method_on_callee_name(
            missing_recv, ghidra_code=dump_decl, function_names=names,
        )
        self.assertNotIn("series_fn.back()", grafted)
        self.assertIn("in_stack_ffffffffffffff78", grafted)
        self.assertIn(
            "std::vector<int,_std::allocator<int>_>::back(in_stack_ffffffffffffff78)",
            grafted,
        )
        self.assertIn("vector<int,_std::allocator<int>_> * in_stack_ffffffffffffff78;", grafted)
        self.assertIn("local.back()", grafted)
        san_graft = sanitize_ghidra_cpp(grafted)
        self.assertNotIn("series_fn.back()", san_graft)
        self.assertIn("back()", san_graft)

        present = (
            "int main() {\n"
            "  auto *in_stack_ffffffffffffff78 = series_fn(n);\n"
            "  std::cout << series_fn.back();\n"
            "  std::cout << local.back();\n"
            "}\n"
        )
        got = repair_method_on_callee_name(
            present, ghidra_code=dump, function_names=names,
        )
        self.assertNotIn("series_fn.back()", got)
        self.assertIn("std::vector<int,_std::allocator<int>_>::back(in_stack_ffffffffffffff78)", got)
        self.assertIn("local.back()", got)
        san = sanitize_ghidra_cpp(got)
        self.assertIn("back()", san)
        self.assertNotIn("series_fn.back()", san)

    def test_repair_calls_from_dump_pointer_proto(self):
        from src.agents.restorer import repair_calls_from_dump

        callee_dump = (
            "void show_items(vector<int,_std::allocator<int>_> *xs)\n"
            "{\n  (void)xs;\n}\n"
        )
        caller_dump = (
            "int walk_n(void)\n"
            "{\n"
            "  vector<int,_std::allocator<int>_> *in_stack_ffffffffffffff78;\n"
            "  uint n;\n"
            "  n = 3;\n"
            "  show_items(in_stack_ffffffffffffff78);\n"
            "  return (int)n;\n"
            "}\n"
        )
        restore = (
            "int walk_n(void) {\n"
            "  vector<int,_std::allocator<int>_> * in_stack_ffffffffffffff78;\n"
            "  uint n = 3;\n"
            "  show_items(n);\n"
            "  return (int)n;\n"
            "}\n"
        )
        got = repair_calls_from_dump(
            restore,
            ghidra_code=caller_dump,
            function_names=["show_items", "walk_n"],
            callee_dump_by_name={"show_items": callee_dump},
        )
        self.assertIn("show_items(in_stack_ffffffffffffff78)", got)
        self.assertNotIn("show_items(n)", got)
        keep = repair_calls_from_dump(
            "int walk_n(void) { uint n = 3; fill_n(n); return (int)n; }\n",
            ghidra_code=(
                "int walk_n(void) { uint in_stack_ffffffffffffff80; "
                "fill_n(in_stack_ffffffffffffff80); }\n"
            ),
            function_names=["fill_n"],
            callee_dump_by_name={"fill_n": "void fill_n(uint k) { (void)k; }\n"},
        )
        self.assertIn("fill_n(n)", keep)
        skipped = repair_calls_from_dump(
            "int walk_n(void) { uint n = 3; show_items(n); }\n",
            ghidra_code="int walk_n(void) { show_items(in_stack_ffffffffffffff78); }\n",
            function_names=["show_items"],
            callee_dump_by_name={"show_items": callee_dump},
        )
        self.assertIn("show_items(n)", skipped)
        self.assertNotIn("in_stack_ffffffffffffff78", skipped)

    def test_repair_calls_from_dump_pointer_elem_mismatch(self):
        from src.agents.restorer import repair_calls_from_dump

        callee_dump = (
            "double span_of(Rec *a, Rec *b)\n"
            "{\n  (void)a; (void)b; return 0;\n}\n"
        )
        caller_dump = (
            "int walk_n(vector<Rec,_std::allocator<Rec>_> *xs, Rec *q)\n"
            "{\n"
            "  Rec *in_stack_ffffffffffffffb8;\n"
            "  Rec *in_stack_ffffffffffffffc0;\n"
            "  span_of(in_stack_ffffffffffffffb8, in_stack_ffffffffffffffc0);\n"
            "  return 0;\n"
            "}\n"
        )
        restore = (
            "int walk_n(vector<Rec,_std::allocator<Rec>_> *xs, Rec *q) {\n"
            "  span_of(xs, q);\n"
            "  return 0;\n"
            "}\n"
        )
        got = repair_calls_from_dump(
            restore,
            ghidra_code=caller_dump,
            function_names=["span_of", "walk_n"],
            callee_dump_by_name={"span_of": callee_dump},
        )
        self.assertIn(
            "span_of(in_stack_ffffffffffffffb8, in_stack_ffffffffffffffc0)",
            got,
        )
        self.assertNotIn("span_of(xs, q)", got)
        keep = repair_calls_from_dump(
            "int walk_n(Rec *a, Rec *b) { span_of(a, b); return 0; }\n",
            ghidra_code=(
                "int walk_n(Rec *a, Rec *b) { "
                "span_of(in_stack_ffffffffffffffb8, in_stack_ffffffffffffffc0); }\n"
            ),
            function_names=["span_of"],
            callee_dump_by_name={"span_of": callee_dump},
        )
        self.assertIn("span_of(a, b)", keep)
        opaque = repair_calls_from_dump(
            "int walk_n(Rec *p) { undefined8 *in_RCX; span_of(in_RCX, p); return 0; }\n",
            ghidra_code=(
                "int walk_n(Rec *p) { Rec *in_stack_ffffffffffffffb8; "
                "span_of(in_stack_ffffffffffffffb8, p); }\n"
            ),
            function_names=["span_of"],
            callee_dump_by_name={"span_of": callee_dump},
        )
        self.assertIn("span_of(in_RCX, p)", opaque)

    def test_repair_calls_after_stack_home_bind(self):
        from src.agents.restorer import repair_calls_from_dump
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        callee_dump = (
            "double span_of(Rec *a, Rec *b)\n"
            "{\n  (void)a; (void)b; return 0;\n}\n"
        )
        caller = (
            "int walk_n(vector<Rec,_std::allocator<Rec>_> *xs, Rec *q)\n"
            "{\n"
            "  Rec *in_stack_ffffffffffffffb8;\n"
            "  Rec *in_stack_ffffffffffffffc0;\n"
            "  (void)*in_stack_ffffffffffffffb8;\n"
            "  (void)*in_stack_ffffffffffffffc0;\n"
            "  span_of(in_stack_ffffffffffffffb8, in_stack_ffffffffffffffc0);\n"
            "  return 0;\n"
            "}\n"
        )
        bound = sanitize_ghidra_cpp(caller)
        self.assertIn("span_of(xs, q)", bound)
        got = repair_calls_from_dump(
            bound,
            ghidra_code=caller,
            function_names=["span_of", "walk_n"],
            callee_dump_by_name={"span_of": callee_dump},
        )
        self.assertIn(
            "span_of(in_stack_ffffffffffffffb8, in_stack_ffffffffffffffc0)",
            got,
        )
        self.assertNotIn("span_of(xs, q)", got)
        again = sanitize_ghidra_cpp(got)
        self.assertNotIn("span_of(xs, q)", again)
        self.assertIn("span_of(", again)

    def test_repair_restore_debris_closes_truncated_braces(self):
        from src.agents.restorer import repair_restore_debris

        src = "int fmt_num() {\n  if (1) {\n    std::wid\n"
        got = repair_restore_debris(src)
        self.assertIn("std::wid", got)
        self.assertNotIn("std::wstring", got)
        self.assertGreaterEqual(got.count("}"), src.count("}") + 2)
        balanced = "int fmt_num() { return 1; }\n"
        self.assertEqual(repair_restore_debris(balanced), balanced)

    def test_assemble_truncated_body_does_not_swallow_next_fn(self):
        restored = [
            {
                "classification": "user_code",
                "address": "0x1",
                "guessed_name": "fmt_num",
                "ghidra_name": "FUN_1",
                "cpp_code": "int fmt_num() {\n  if (1) {\n    std::wid\n",
            },
            {
                "classification": "user_code",
                "address": "0x2",
                "guessed_name": "next_fn",
                "ghidra_name": "FUN_2",
                "cpp_code": "int next_fn() { return 2; }\n",
            },
        ]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 2)
        self.assertIn("int next_fn()", text)
        self.assertIn("std::wid", text)
        self.assertNotIn("std::wstring", text)

    def test_repair_restore_debris_unwraps_json_envelope(self):
        from src.agents.restorer import repair_restore_debris, unwrap_restore_payload

        blob = (
            '{\n'
            '  "classification": "user_code",\n'
            '  "guessed_name": "fmt_num",\n'
            '  "cpp_code": "int fmt_num() { return 1; }"\n'
            '}\n'
        )
        got = repair_restore_debris(blob)
        self.assertIn("int fmt_num() { return 1; }", got)
        self.assertNotIn("classification", got)
        compound = "{\n  int x = 1;\n  return x;\n}\n"
        self.assertEqual(repair_restore_debris(compound), compound)

        broken = (
            '{\n'
            '  "classification": "user_code",\n'
            '  "guessed_name": "fmt_num",\n'
            '  "evidence": ["std::string"],\n'
            '  "cpp_code": "int fmt_num() { return 1; }"\n'
            '  },\n'
            '  "includes": [],\n'
            '  "confidence": 100\n'
            '}\n'
        )
        self.assertIn("int fmt_num() { return 1; }", repair_restore_debris(broken))
        rec = {
            "classification": "user_code",
            "guessed_name": "-",
            "confidence": 50,
            "cpp_code": broken,
        }
        unwrap_restore_payload(rec)
        self.assertEqual(rec["guessed_name"], "fmt_num")
        self.assertIn("int fmt_num()", rec["cpp_code"])
        self.assertNotIn("classification", rec["cpp_code"])

    def test_assemble_unwraps_restore_json_envelope(self):
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "fmt_num",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                '{\n'
                '  "classification": "user_code",\n'
                '  "guessed_name": "fmt_num",\n'
                '  "cpp_code": "int fmt_num() { return 1; }"\n'
                '}\n'
            ),
        }]
        text, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertIn("int fmt_num()", text)
        self.assertNotIn('"classification"', text)

        broken = [{
            "classification": "user_code",
            "address": "0x2",
            "guessed_name": "-",
            "ghidra_name": "FUN_2",
            "cpp_code": (
                '{\n'
                '  "classification": "user_code",\n'
                '  "guessed_name": "fmt_num",\n'
                '  "cpp_code": "int fmt_num() { return 1; }"\n'
                '  },\n'
                '  "includes": []\n'
                '}\n'
            ),
        }]
        from src.agents.restorer import unwrap_restore_payload
        unwrap_restore_payload(broken[0])
        text2, n2 = assemble(broken, [], [])
        self.assertEqual(n2, 1)
        self.assertIn("int fmt_num()", text2)
        self.assertNotIn('"classification"', text2)

    def test_extract_restore_json_does_not_use_cpp_fallback(self):
        from src.agents.restorer import extract_restore_json
        from src.llm.client import extract_json

        broken = (
            '{\n'
            '  "classification": "user_code",\n'
            '  "guessed_name": "fmt_num",\n'
            '  "evidence": ["std::string"],\n'
            '  "cpp_code": "int fmt_num() { return 1; }"\n'
            '  },\n'
            '  "includes": [],\n'
            '  "confidence": 100\n'
            '}\n'
        )
        got = extract_restore_json(broken)
        self.assertIsNotNone(got)
        self.assertIn("int fmt_num() { return 1; }", got.get("cpp_code") or "")
        self.assertNotIn("classification", got.get("cpp_code") or "")
        fallback = extract_json(broken)
        self.assertIsNotNone(fallback)

    def test_continue_truncated_cpp_does_not_invent_ident(self):
        from src.agents.restorer import (
            continue_truncated_cpp,
            ident_cut_head,
            looks_truncated_cpp,
            repair_restore_debris,
        )

        class _Client:
            def __init__(self):
                self.json_mode = None
                self.prompt = ""

            def generate(self, prompt, system="", json_mode=False):
                self.json_mode = json_mode
                self.prompt = prompt
                return '{"cpp_code_tail": "  return 0;\\n}\\n}\\n"}'

        head = "int fmt_num() {\n  if (1) {\n    std::wid\n"
        self.assertTrue(looks_truncated_cpp(head))
        client = _Client()
        got = continue_truncated_cpp(client, head, "")
        self.assertTrue(client.json_mode)
        self.assertIn("std::wid", got)
        self.assertNotIn("std::wstring", got)
        self.assertIn("return 0", got)
        balanced = "int fmt_num() { return 1; }\n"
        self.assertFalse(looks_truncated_cpp(balanced))
        self.assertIsNone(ident_cut_head(balanced))
        self.assertEqual(continue_truncated_cpp(client, balanced, ""), balanced)

        debris = "int fmt_num() {\n            std::basic_st\n}}}}}}"
        self.assertTrue(looks_truncated_cpp(debris))
        repaired = repair_restore_debris(
            "int fmt_num() {\n            std::basic_st\n"
        )
        self.assertTrue(looks_truncated_cpp(repaired))
        self.assertNotIn("basic_string", repaired)
        client2 = _Client()
        got2 = continue_truncated_cpp(client2, debris, "")
        self.assertIn("std::basic_st", got2)
        self.assertNotIn("basic_string", got2)
        self.assertNotIn("}}}}}}", client2.prompt)
        self.assertIn("std::basic_st", client2.prompt)
        glued = continue_truncated_cpp(
            type("C", (), {
                "generate": staticmethod(
                    lambda prompt, system="", json_mode=False: (
                        '{"cpp_code_tail": "get_t x; return 0;\\n}"}'
                    )
                ),
            })(),
            "int f() {\n  std::wid",
            "",
        )
        self.assertIn("std::widget_t", glued)
        self.assertNotIn("std::wid\nget", glued)
        self.assertNotIn("wstring", glued)

    def test_restore_live_omits_pcode_even_if_entry_has_it(self):
        from src.agents.restorer import CodeRestorerLLM, PCODE_SECTION_TITLE

        class _Client:
            def __init__(self):
                self.prompt = ""

            def generate(self, prompt, system="", json_mode=False):
                self.prompt = prompt
                return (
                    '{"classification":"user_code",'
                    '"cpp_code":"int f(){return 0;}"}'
                )

        dump = _load_fixture()
        fn = dump["functions"][0]
        client = _Client()
        CodeRestorerLLM(client).restore(fn, fn["ghidra_code"])
        self.assertNotIn(PCODE_SECTION_TITLE, client.prompt)
        self.assertNotIn("COPY", client.prompt)
        client2 = _Client()
        CodeRestorerLLM(client2).restore(
            fn, fn["ghidra_code"], pcode=fn["pcode"]
        )
        self.assertIn(PCODE_SECTION_TITLE, client2.prompt)
        self.assertIn("COPY", client2.prompt)


class TestEvalPcodeMini(unittest.TestCase):
    def test_dry_run_and_judge_do_not_bump_live_ver(self):
        from src.analysis.eval_pcode_mini import judge_cpp, run_mini
        from src.pipeline.runner import LLM_PROMPT_VER

        rec = run_mini(dry_run=True)
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["live_prompt_ver"], "p4")
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertTrue(rec["prompt_has_pcode"])
        self.assertTrue(rec["p5_prompt_has_pcode"])
        self.assertFalse(rec["p4_prompt_has_pcode"])
        self.assertTrue(rec["compare"]["live_stays_p4"])
        self.assertFalse(rec["compare"]["p5_wins"])
        leak = judge_cpp(
            "(unique, 8, 0x1000) COPY (const, 8, 0x0)\n",
            ghidra_code="printf(\"x\");",
        )
        self.assertFalse(leak["ok"])
        self.assertTrue(leak["pcode_leak"])
        good = judge_cpp(
            "void f() { printf(\"hello\\n\"); }\n",
            ghidra_code="printf(\"hello\\n\");",
        )
        self.assertTrue(good["ok"])

    def test_restore_fixture_mock_keeps_c_not_pcode(self):
        from src.analysis.eval_pcode_mini import restore_fixture

        class _Client:
            def generate(self, prompt, system="", json_mode=False):
                self.prompt = prompt
                return (
                    '{"classification":"user_code",'
                    '"cpp_code":"void FUN_140001000(void) { printf(\\"hello\\\\n\\"); }"}'
                )

        dump = _load_fixture()
        fn = dump["functions"][0]
        rec = restore_fixture(fn, client=_Client(), use_pcode=True)
        self.assertTrue(rec["prompt_has_pcode"])
        self.assertTrue(rec["judge"]["ok"])
        self.assertNotIn("(unique,", rec["cpp_code"])

    def test_compare_ab_tie_and_p5_win_and_leak(self):
        from src.analysis.eval_pcode_mini import compare_ab

        ok = {"judge": {"ok": True, "pcode_leak": []}}
        bad = {"judge": {"ok": False, "pcode_leak": []}}
        leak = {"judge": {"ok": False, "pcode_leak": ["COPY ("]}}
        tie = compare_ab(ok, ok)
        self.assertFalse(tie["p5_wins"])
        self.assertTrue(tie["live_stays_p4"])
        win = compare_ab(bad, ok)
        self.assertTrue(win["p5_wins"])
        self.assertTrue(win["live_stays_p4"])
        leaked = compare_ab(ok, leak)
        self.assertFalse(leaked["p5_wins"])
        self.assertTrue(leaked["live_stays_p4"])


class TestEvalTruncated(unittest.TestCase):
    def test_scan_finds_basic_st_after_braces(self):
        import tempfile
        from src.analysis.eval_truncated import scan_truncated

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "llm" / "p4" / "generic" / "m" / "restore" / "0x1.json"
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps({
                    "cpp_code": "int fmt() {\n            std::basic_st\n}}}}}}",
                    "guessed_name": "fmt",
                    "address": "0x1",
                }),
                encoding="utf-8",
            )
            hits = scan_truncated(root)
        self.assertEqual(len(hits), 1)
        self.assertIn("basic_st", hits[0]["tail"])


class TestEvalBehavior(unittest.TestCase):
    def test_check_case_masks_elapsed_and_matches(self):
        from src.analysis.eval_behavior import check_case, mask_stdout

        self.assertIn("elapsed_us=<n>", mask_stdout("elapsed_us=123\n"))
        case = {
            "id": "fibtimer_n3",
            "expect_contains": ["n=3", "fib(n)=2"],
            "expect_exit": 0,
        }
        row = check_case(
            case,
            {"ok": True, "skipped": False, "stdout": "n=3\nfib(n)=2\n", "exit": 0},
        )
        self.assertTrue(row["ok"])
        row_bad = check_case(
            case,
            {"ok": True, "skipped": False, "stdout": "n=9\n", "exit": 0},
        )
        self.assertFalse(row_bad["ok"])
        self.assertIn("n=3", row_bad["missing"])

    def test_mask_paths_replaces_root_and_abs(self):
        from src.analysis.eval_behavior import ROOT, mask_paths

        got = mask_paths(str(ROOT / "sandbox"))
        self.assertNotIn(str(ROOT), got)
        self.assertTrue(got.startswith("<path>"), got)
        self.assertEqual(mask_paths(r"C:\Windows\Temp\x"), "<path>")

    def test_mask_paths_quoted_libstd_and_keeps_bin(self):
        from src.analysis.eval_behavior import ROOT, mask_paths

        doubled = str(ROOT).replace("/", "\\").replace("\\", "\\\\")
        sample = (
            f'Current path is "{doubled}"\n'
            'Current path is "C:\\\\Users\\\\user\\\\AppData\\\\Local\\\\Temp"\n'
            '"/bin\\\\cat" : No such file or directory\n'
        )
        got = mask_paths(sample)
        self.assertNotIn(str(ROOT), got)
        self.assertIn('Current path is "<path>"', got)
        self.assertIn('Current path is "<path>"', got.split("\n")[1])
        self.assertIn('"/bin\\\\cat"', got)
        self.assertNotIn("/bin<path>", got)

    def test_eval_restored_matches_and_mismatches_golden(self):
        import tempfile
        from pathlib import Path

        from src.analysis.compile_verify import find_cxx_compiler
        from src.analysis.eval_behavior import eval_restored

        cxx = find_cxx_compiler()
        if not cxx or Path(cxx).stem.lower() == "cl":
            self.skipTest("no g++/clang++ for I5 link")
        case = {
            "id": "mini_i5",
            "argv": [],
            "expect_contains": ["hello-i5"],
            "expect_exit": 0,
        }
        src = (
            "#include <cstdio>\n"
            "int main() { std::puts(\"hello-i5\"); return 0; }\n"
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "mini.cpp"
            path.write_text(src, encoding="utf-8")
            ok = eval_restored(path, case, "hello-i5\n")
            self.assertFalse(ok.get("skipped"), ok)
            self.assertTrue(ok.get("stdout_match"), ok)
            self.assertTrue(ok.get("ok"), ok)
            bad = eval_restored(path, case, "other\n")
            self.assertTrue(bad.get("contains_ok"), bad)
            self.assertFalse(bad.get("stdout_match"), bad)
            self.assertFalse(bad.get("ok"), bad)

    def test_case_for_binary_matches_stem_not_arbitrary_exe(self):
        from src.analysis.eval_behavior import case_for_binary

        self.assertEqual(
            (case_for_binary("samples/PointCloud.exe") or {}).get("id"),
            "pointcloud_default",
        )
        self.assertEqual(
            (case_for_binary("output/foo/FibTimer.exe") or {}).get("id"),
            "fibtimer_n3",
        )
        self.assertIsNone(case_for_binary("samples/EchoFilter.exe"))
        self.assertIsNone(case_for_binary("user.bin"))

    def test_eval_restored_crash_is_metric_not_gate(self):
        import tempfile
        from pathlib import Path

        from src.agents.compiler import SKIP_FOREVER
        from src.agents.critic import director_contract, review_run
        from src.analysis.compile_verify import find_cxx_compiler
        from src.analysis.eval_behavior import _crash_reason, eval_restored, i5_summary

        self.assertIsNotNone(_crash_reason(3221225477))
        self.assertIsNotNone(_crash_reason(-1073741819))
        self.assertIsNotNone(_crash_reason(-11))
        blob = " ".join(p[0] for p in SKIP_FOREVER)
        self.assertNotIn("ACCESS_VIOLATION", blob)
        self.assertNotIn("STATUS_ACCESS", blob)

        cxx = find_cxx_compiler()
        if not cxx or Path(cxx).stem.lower() == "cl":
            self.skipTest("no g++/clang++ for I5 link")
        case = {
            "id": "crash_i5",
            "argv": [],
            "expect_contains": ["never-printed"],
            "expect_exit": 0,
        }
        src = "int main() { volatile int *p = 0; return *p; }\n"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "crash.cpp"
            path.write_text(src, encoding="utf-8")
            rec = eval_restored(path, case, "never-printed\n")
        self.assertFalse(rec.get("skipped"), rec)
        self.assertTrue((rec.get("link") or {}).get("ok"), rec)
        self.assertEqual(rec.get("kind"), "crash")
        self.assertFalse(rec.get("ok"), rec)
        slim = i5_summary(rec)
        self.assertTrue(slim.get("not_compile_gate"))
        self.assertTrue(slim.get("not_recipe_source"))
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
            tu_text='void walk_keys() { puts("k"); }',
            compile_ok=True,
            assembled_ok=True,
        )
        self.assertTrue(verdict.accept)
        self.assertTrue(director_contract(verdict))

    def test_i5_probe_index_examples_exist(self):
        import yaml
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        data = yaml.safe_load(
            (root / "eval" / "i5_probe_index.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual(data.get("live_restore"), [])
        missing = []
        for bucket in data.get("buckets") or []:
            for name in bucket.get("examples") or []:
                if not (root / "samples" / name).exists():
                    missing.append(name)
        self.assertEqual(missing, [])


class TestGhidraPrepass(unittest.TestCase):
    def test_this_proto_counts_signature_not_body(self):
        from src.analysis.ghidra_prepass import (
            CACHE_KEY_NOW,
            LIVE_PREPASS,
            compare_summaries,
            proto_has_this,
            prototype_span,
            summarize_dump,
        )

        self.assertFalse(LIVE_PREPASS)
        self.assertEqual(CACHE_KEY_NOW, "ghidra_full_v6")
        body_only = "void f(int x)\n{\n  return this;\n}\n"
        self.assertFalse(proto_has_this(prototype_span(body_only)))
        sig = "void __thiscall Item::rank(Item *this)\n{\n  return;\n}\n"
        self.assertTrue(proto_has_this(prototype_span(sig)))
        left = summarize_dump(
            {
                "functions": [
                    {
                        "address": "0x1",
                        "name": "distance",
                        "ghidra_code": "double distance(Pt *a)\n{\n  return 0;\n}\n",
                    }
                ]
            }
        )
        right = summarize_dump(
            {
                "functions": [
                    {
                        "address": "0x2",
                        "name": "rank",
                        "ghidra_code": "void Item::rank(Item *this)\n{\n  return;\n}\n",
                    }
                ]
            }
        )
        self.assertEqual(left["n_this_proto"], 0)
        self.assertEqual(right["n_this_proto"], 1)
        self.assertEqual(right["n_this_proto_other"], 1)
        self.assertEqual(right["n_this_proto_stl"], 0)
        delta = compare_summaries(left, right)
        self.assertEqual(delta["delta_this_proto"], 1)
        self.assertFalse(delta["live_prepass"])
        self.assertIn("v7", delta["note"])


class TestExtractFeatures(unittest.TestCase):
    def test_domain_dll_count(self):
        dump = _load_fixture()
        idx = FeatureIndex(dump["strings"], dump["functions"], dump["thunks"])
        ft = extract_features(idx, dump["functions"][0])
        self.assertGreaterEqual(ft["n_domain"], 1)
        self.assertGreaterEqual(ft["n_iostream"], 1)
        self.assertGreaterEqual(ft["n_code_chars"], 1)
        self.assertGreaterEqual(ft["n_pcode_ops"], 1)
        self.assertIn("n_stack_dialect", ft)
        self.assertIn("n_ctrl", ft)
        self.assertIn("n_user_callees", ft)


class TestCommandments(unittest.TestCase):
    """Pipeline restore must not ingest original sources. Failure is hell."""

    _RESTORE_PATH = (
        ROOT / "src" / "analysis" / "ghidra_cpp.py",
        ROOT / "src" / "agents" / "assembler.py",
        ROOT / "src" / "agents" / "compiler.py",
        ROOT / "src" / "agents" / "restorer.py",
        ROOT / "src" / "analysis" / "prompts.py",
        ROOT / "src" / "analysis" / "fidelity.py",
    )
    _STEMS = (
        "EchoFilter", "PointCloud", "MyCollatz", "IniMini", "XorCipher",
        "FibTimer", "TaskBoard", "NetPath", "GammaFn",
    )

    def test_restore_path_has_no_application_stems(self):
        import re

        pat = re.compile(r"\b(" + "|".join(self._STEMS) + r")\b")
        hits = []
        for path in self._RESTORE_PATH:
            text = path.read_text(encoding="utf-8")
            for m in pat.finditer(text):
                hits.append(f"{path.name}:{m.group(0)}")
        self.assertEqual(hits, [], hits)

    def test_restorer_prompt_has_no_samples_tree(self):
        from src.agents.restorer import USER_PROMPT
        from src.analysis.prompts import system_prompt_for

        self.assertNotIn("samples/", USER_PROMPT)
        self.assertNotIn("samples\\", USER_PROMPT)
        for profile in ("gcc_pe_x64", "generic"):
            sp = system_prompt_for(profile)
            self.assertNotIn("samples/", sp)
            self.assertNotIn(".cpp", sp)


if __name__ == "__main__":
    unittest.main()
