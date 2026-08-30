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

    def test_ml_noise_penalty_sinks_crt(self):
        from src.analysis.scorer import apply_runtime_noise_penalty, ML_NOISE_PENALTY

        self.assertEqual(apply_runtime_noise_penalty("main", 0.9), 0.9)
        self.assertEqual(
            apply_runtime_noise_penalty("_RTC_CheckStackVars", 0.9),
            0.9 - ML_NOISE_PENALTY,
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


class TestExtractFeatures(unittest.TestCase):
    def test_domain_dll_count(self):
        dump = _load_fixture()
        idx = FeatureIndex(dump["strings"], dump["functions"], dump["thunks"])
        ft = extract_features(idx, dump["functions"][0])
        self.assertGreaterEqual(ft["n_domain"], 1)
        self.assertGreaterEqual(ft["n_iostream"], 1)


if __name__ == "__main__":
    unittest.main()
