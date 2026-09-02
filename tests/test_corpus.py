from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.compile_verify import find_cxx_compiler
from src.analysis.corpus import eval_corpus, load_corpus
from src.config import AppConfig
from src.pipeline.metrics import RunMetrics
from src.pipeline.runner import _llm_cache_key, _per_function_compile


class _MemCache:
    def __init__(self) -> None:
        self.puts = []

    def put(self, key, data):
        self.puts.append((key, data))


class _Fixer:
    def fix_compile(self, body, errors, compiler=""):
        return "int compile_fix_only() { return 0; }"


class TestCorpusEval(unittest.TestCase):
    def test_load_unique_ids(self):
        cases = load_corpus()
        self.assertGreaterEqual(len(cases), 10)
        ids = [c.id for c in cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn("_schema", ids)

    def test_eval_contains_and_optional_compile(self):
        report = eval_corpus()
        fails = [r for r in report["results"] if not r.get("ok")]
        self.assertEqual(
            report["n_ok"],
            report["n_cases"],
            "\n".join(f"{r['id']}: {r.get('errors')}" for r in fails),
        )

    def test_classifier_probes_self_hit(self):
        from src.analysis.eval_classifier import eval_classifier, regex_to_probe

        self.assertEqual(
            regex_to_probe("'[A-Z][A-Za-z0-9]*' was not declared in this scope"),
            "'C' was not declared in this scope",
        )
        self.assertEqual(
            regex_to_probe("cannot convert 'ghidra_word\\*' to 'undefined\\*'"),
            "cannot convert 'ghidra_word*' to 'undefined*'",
        )
        report = eval_classifier()
        self.assertGreaterEqual(report["n_with_fp"], 50)
        self.assertGreaterEqual(report["n_explicit_probe"], 10)
        self.assertEqual(
            report["n_self_miss"],
            0,
            report["self_miss"],
        )
        self.assertEqual(
            report["n_unexpected_overlaps"],
            0,
            report["unexpected_overlaps"],
        )
        self.assertTrue(report["ok"], report)
        pairs = {frozenset((o["a"], o["b"])) for o in report["overlaps"]}
        self.assertIn(
            frozenset({"ghidra-ostream-assemble", "ostream-ghidra-syntax"}),
            pairs,
        )

    def test_skip_forever_fingerprint_is_not_self_miss(self):
        from src.agents.compiler import match_errors
        from src.analysis.corpus import load_corpus
        from src.analysis.eval_classifier import probes_for_case

        cases = {c.id: c for c in load_corpus()}
        case = cases["ghidra-this-as-ident"]
        probe = probes_for_case(case)[0]
        decision = match_errors([{"message": probe}], list(cases.values()))
        self.assertTrue(decision.skip_forever_reasons)
        self.assertEqual(decision.known_ids, [])

    def test_explicit_gcc_probe_beats_synth(self):
        from src.analysis.corpus import load_corpus
        from src.analysis.eval_classifier import probes_for_case

        cases = {c.id: c for c in load_corpus()}
        ht = cases["ghidra-hashtable-priv-cur"]
        probes = probes_for_case(ht)
        self.assertEqual(len(probes), 3)
        self.assertTrue(any("_M_current" in p for p in probes))
        self.assertTrue(all("is protected" in p or "was not declared" in p for p in probes))


class TestCompileFixDoesNotTouchRestore(unittest.TestCase):
    def test_restore_body_and_cache_stay_put(self):
        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        data = {
            "classification": "user_code",
            "guessed_name": "broken",
            "ghidra_name": "FUN_1",
            "cpp_code": "int broken() { return not_a_name; }\n",
        }
        cache = _MemCache()
        metrics = RunMetrics()
        cfg = AppConfig(compile_fix=True, compile_timeout=30, cxx_compiler=cxx)
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td)
            _per_function_compile(
                data,
                restorer=_Fixer(),
                functions=[],
                run_dir=run_dir,
                config=cfg,
                metrics=metrics,
                cache=cache,
                profile="generic",
                addr="0x1400",
            )
            fix_files = list((run_dir / "compile_fn").glob("*_fix.cpp"))
            self.assertTrue(fix_files, "compile-fix snippet should be written")
            self.assertIn(
                "compile_fix_only",
                fix_files[0].read_text(encoding="utf-8"),
            )
        self.assertIn("not_a_name", data["cpp_code"])
        self.assertNotIn("compile_fix_only", data["cpp_code"])
        self.assertFalse(data.get("compile_ok"))
        self.assertTrue(data.get("compile_fix_ok"))
        self.assertEqual(metrics.compile_fn_fixed, 1)
        keys = [k for k, _ in cache.puts]
        self.assertTrue(keys, "compile-fix should cache the fixed snippet")
        self.assertTrue(all("/compile_fn_fix/" in k for k in keys))
        self.assertFalse(any("/restore/" in k for k in keys))
        expected = _llm_cache_key(
            "generic", "0x1400", "compile_fn_fix", model=cfg.model_name
        )
        self.assertIn(expected, keys)


if __name__ == "__main__":
    unittest.main()
