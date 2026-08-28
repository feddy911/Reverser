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
from src.analysis.fidelity import check_function
from src.analysis.scorer import GhidraFunctionScorer
from src.domains import get_domain_pack, list_domain_packs
from src.domains.pack import NONE_PACK


FIXTURE = Path(__file__).parent / "fixtures" / "mini_ghidra.json"


def _load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestDomainPacks(unittest.TestCase):
    def test_registry(self):
        packs = list_domain_packs()
        self.assertIn("none", packs)
        self.assertIn("mycollatz", packs)
        self.assertFalse(get_domain_pack("none").has_polish_hints)
        self.assertTrue(get_domain_pack("mycollatz").has_polish_hints)

    def test_unknown_pack_raises(self):
        with self.assertRaises(ValueError):
            get_domain_pack("no_such_pack")

    def test_mycollatz_preamble_has_gmp(self):
        lines = get_domain_pack("mycollatz").preamble("// test")
        self.assertIn("#include <gmp.h>", lines)
        self.assertNotIn("#include <gmp.h>", NONE_PACK.preamble("// test"))


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


class TestAssemblerDomain(unittest.TestCase):
    def test_none_pack_no_gmp_include(self):
        restored = [{
            "classification": "user_code",
            "address": "0x140001000",
            "guessed_name": "greet",
            "ghidra_name": "FUN_140001000",
            "cpp_code": "void greet() { printf(\"hi\"); }\n",
        }]
        text, n = assemble(restored, [], [], pack=NONE_PACK)
        self.assertEqual(n, 1)
        self.assertNotIn("gmp.h", text)
        self.assertIn("greet", text)

    def test_mycollatz_pack_renames_and_gmp(self):
        pack = get_domain_pack("mycollatz")
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
        text, n = assemble(restored, [], [], pack=pack)
        self.assertEqual(n, 1)
        self.assertIn("gmp.h", text)
        self.assertIn("CollatzState", text)
        self.assertNotIn("MyStruct", text)


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


class TestExtractFeatures(unittest.TestCase):
    def test_domain_dll_count(self):
        dump = _load_fixture()
        idx = FeatureIndex(dump["strings"], dump["functions"], dump["thunks"])
        ft = extract_features(idx, dump["functions"][0])
        self.assertGreaterEqual(ft["n_domain"], 1)
        self.assertGreaterEqual(ft["n_iostream"], 1)


if __name__ == "__main__":
    unittest.main()
