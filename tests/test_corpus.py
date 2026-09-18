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

    def test_value_type_mix_fixture_is_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        case = cases["ghidra-value-type-as-elem-ptr"]
        self.assertFalse(case.compile)
        self.assertEqual(case.recipe, "sanitize")
        self.assertIn("Item", "\n".join(case.gcc_probe))
        self.assertNotIn("Point", case.ghidra_cpp)
        self.assertNotIn("PointCloud", case.ghidra_cpp)

    def test_word_star_and_vector_ref_mix_fixtures_are_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        word = cases["ghidra-word-star-as-cstr"]
        self.assertFalse(word.compile)
        self.assertIn("ghidra_word", word.ghidra_cpp)
        self.assertNotIn("PointCloud", word.ghidra_cpp)
        vec = cases["ghidra-vector-star-as-const-ref"]
        self.assertFalse(vec.compile)
        self.assertIn("Item", vec.ghidra_cpp)
        self.assertNotIn("PointCloud", vec.ghidra_cpp)

    def test_evening_mix_fixtures_have_no_sample_stems(self):
        cases = {c.id: c for c in load_corpus()}
        for cid in (
            "ghidra-word-cast-as-cstr",
            "ghidra-string-star-as-const-ref",
            "ghidra-const-string-star-as-string-star",
            "ghidra-int-as-mpfr-rnd",
            "ghidra-ostream-star-ref-shift",
            "ghidra-word-as-char-star",
            "ghidra-undefined-as-undefined-star",
            "ghidra-uchar-star-as-char-star",
            "ghidra-size-type-as-vector-star",
            "ghidra-value-type-not-member-of-user",
            "msvc-jmc-helper-undeclared",
        ):
            blob = cases[cid].ghidra_cpp
            self.assertNotIn("PointCloud", blob, cid)
            self.assertNotIn("XorCipher", blob, cid)
            self.assertNotIn("MyCollatz", blob, cid)
            self.assertNotIn("GammaFn", blob, cid)

    def test_opaque_ptr_reg_fixture_is_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        case = cases["ghidra-msx64-opaque-ptr-reg"]
        self.assertTrue(case.compile)
        self.assertEqual(case.recipe, "sanitize")
        self.assertIn("undefined8 *in_RCX", case.ghidra_cpp)
        self.assertIn("(void)*in_RCX", case.ghidra_cpp)
        self.assertNotIn("Point", case.ghidra_cpp)
        self.assertNotIn("PointCloud", case.ghidra_cpp)
        self.assertNotIn("print_point", case.ghidra_cpp)
        opnew = cases["ghidra-operator-new-delete"]
        self.assertTrue(opnew.compile)
        self.assertEqual(opnew.recipe, "sanitize")
        self.assertIn("operator_new(0x18)", opnew.ghidra_cpp)
        self.assertIn("operator_delete(p, 0x18)", opnew.ghidra_cpp)
        self.assertNotIn("NestWalk", opnew.ghidra_cpp)
        self.assertNotIn("FibTimer", opnew.ghidra_cpp)
        longthis = cases["ghidra-msx64-longlong-this"]
        self.assertTrue(longthis.compile)
        self.assertEqual(longthis.recipe, "sanitize")
        self.assertIn("longlong in_RCX", longthis.ghidra_cpp)
        self.assertNotIn("NestWalk", longthis.ghidra_cpp)
        self.assertNotIn("FibTimer", longthis.ghidra_cpp)
        alias = cases["ghidra-msx64-in-reg-alias"]
        self.assertTrue(alias.compile)
        self.assertEqual(alias.recipe, "sanitize")
        self.assertIn("in_RCX = p", alias.ghidra_cpp)
        self.assertNotIn("NestWalk", alias.ghidra_cpp)
        self.assertNotIn("FibTimer", alias.ghidra_cpp)

    def test_stack_home_args_fixture_is_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        case = cases["ghidra-msx64-stack-home-args"]
        self.assertTrue(case.compile)
        self.assertEqual(case.recipe, "sanitize")
        self.assertIn("in_stack_ffffffffffffffb8", case.ghidra_cpp)
        self.assertNotIn("Point", case.ghidra_cpp)
        self.assertNotIn("PointCloud", case.ghidra_cpp)
        self.assertNotIn("nearest_index", case.ghidra_cpp)
        crlf = cases["ghidra-crlf-blank-lines"]
        self.assertEqual(crlf.recipe, "sanitize")
        self.assertTrue(crlf.compile)
        self.assertIn("\r\n", crlf.ghidra_cpp)
        self.assertNotIn("NestWalk", crlf.ghidra_cpp)
        self.assertNotIn("FibTimer", crlf.ghidra_cpp)
        self.assertNotIn("Item", crlf.ghidra_cpp)
        home_alias = cases["ghidra-msx64-stack-home-alias"]
        self.assertTrue(home_alias.compile)
        self.assertEqual(home_alias.recipe, "sanitize")
        self.assertIn("in_stk_n40 = n", home_alias.ghidra_cpp)
        self.assertNotIn("NestWalk", home_alias.ghidra_cpp)
        self.assertNotIn("FibTimer", home_alias.ghidra_cpp)
        same_ty = cases["ghidra-msx64-stack-home-same-type"]
        self.assertTrue(same_ty.compile)
        self.assertIn("int in_stk_n40;", same_ty.ghidra_cpp)
        self.assertNotIn("NestWalk", same_ty.ghidra_cpp)
        self.assertNotIn("FibTimer", same_ty.ghidra_cpp)

    def test_sret_this_fixture_is_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        case = cases["ghidra-msx64-sret-this"]
        self.assertTrue(case.compile)
        self.assertEqual(case.recipe, "sanitize")
        self.assertIn("Rec *this", case.ghidra_cpp)
        self.assertIn("in_RDX", case.ghidra_cpp)
        self.assertNotIn("Point", case.ghidra_cpp)
        self.assertNotIn("PointCloud", case.ghidra_cpp)
        self.assertNotIn("FibTimer", case.ghidra_cpp)

    def test_sret_user_type_fixture_is_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        case = cases["ghidra-msx64-sret-user-type"]
        self.assertTrue(case.compile)
        self.assertEqual(case.recipe, "sanitize")
        self.assertIn("Rec * wrap", case.ghidra_cpp)
        self.assertNotIn("vector", case.ghidra_cpp)
        self.assertNotIn("Point", case.ghidra_cpp)
        self.assertNotIn("PointCloud", case.ghidra_cpp)
        self.assertNotIn("FibTimer", case.ghidra_cpp)

    def test_extraout_fixtures_are_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        alias = cases["ghidra-msx64-extraout-alias"]
        self.assertTrue(alias.compile)
        self.assertEqual(alias.recipe, "sanitize")
        self.assertIn("extraout_RAX", alias.ghidra_cpp)
        self.assertNotIn("Point", alias.ghidra_cpp)
        self.assertNotIn("FibTimer", alias.ghidra_cpp)
        keep = cases["ghidra-msx64-extraout-unkilled"]
        self.assertTrue(keep.compile)
        self.assertIn("make()", keep.ghidra_cpp)
        self.assertNotIn("return make", keep.ghidra_cpp)

    def test_ostream_deref_and_concat_ptr_fixtures_are_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        ostream = cases["ghidra-ostream-deref-addr"]
        self.assertTrue(ostream.compile)
        self.assertIn("std::cout", ostream.ghidra_cpp)
        self.assertNotIn("Series", ostream.ghidra_cpp)
        self.assertNotIn("FibTimer", ostream.ghidra_cpp)
        concat = cases["ghidra-msx64-concat-stack-ptr"]
        self.assertTrue(concat.compile)
        self.assertIn("CONCAT44", concat.ghidra_cpp)
        self.assertNotIn("vector", concat.ghidra_cpp)
        self.assertNotIn("FibTimer", concat.ghidra_cpp)
        piece = cases["ghidra-msx64-concat-stack-piece-use"]
        self.assertTrue(piece.compile)
        self.assertIn("use(in_stk_n72)", piece.ghidra_cpp)
        self.assertNotIn("vector", piece.ghidra_cpp)
        used = cases["ghidra-msx64-concat-used-ptr-formal"]
        self.assertTrue(used.compile)
        self.assertIn("p->n = 0", used.ghidra_cpp)
        self.assertIn("CONCAT44", used.ghidra_cpp)
        chain = cases["ghidra-ostream-insert-chain"]
        self.assertTrue(chain.compile)
        self.assertIn("(*((std::ostream *)this))", chain.ghidra_cpp)
        self.assertNotIn("Series", chain.ghidra_cpp)
        self.assertNotIn("FibTimer", chain.ghidra_cpp)
        ptr_addr = cases["ghidra-ostream-ptr-addr-insert"]
        self.assertTrue(ptr_addr.compile)
        self.assertIn("(*((std::ostream *)p))", ptr_addr.ghidra_cpp)
        self.assertNotIn("NestWalk", ptr_addr.ghidra_cpp)
        self.assertNotIn("FibTimer", ptr_addr.ghidra_cpp)
        alloc = cases["ghidra-default-allocator-arg"]
        self.assertTrue(alloc.compile)
        self.assertIn("std::allocator<int>", alloc.ghidra_cpp)
        self.assertNotIn("unsigned long long", alloc.ghidra_cpp)
        self.assertNotIn("FibTimer", alloc.ghidra_cpp)
        margs = cases["ghidra-default-map-args"]
        self.assertTrue(margs.compile)
        self.assertIn("std::map<", margs.ghidra_cpp)
        self.assertIn("char_traits", margs.ghidra_cpp)
        self.assertNotIn("FibTimer", margs.ghidra_cpp)
        sargs = cases["ghidra-default-string-args"]
        self.assertTrue(sargs.compile)
        self.assertIn("basic_string<char", sargs.ghidra_cpp)
        self.assertNotIn("FibTimer", sargs.ghidra_cpp)
        umap = cases["ghidra-default-unordered-map-args"]
        self.assertTrue(umap.compile)
        self.assertIn("std::hash", umap.ghidra_cpp)
        self.assertNotIn("FibTimer", umap.ghidra_cpp)
        preamble = cases["ghidra-preamble-used-aliases"]
        self.assertTrue(preamble.compile)
        self.assertEqual(preamble.recipe, "assemble")
        self.assertIn("uint wrap", preamble.ghidra_cpp)
        self.assertNotIn("ghidra_word", preamble.ghidra_cpp)
        self.assertNotIn("FibTimer", preamble.ghidra_cpp)
        nullptr = cases["ghidra-word-assign-nullptr"]
        self.assertTrue(nullptr.compile)
        self.assertEqual(nullptr.recipe, "assemble")
        self.assertIn("p->left = nullptr", nullptr.ghidra_cpp)
        self.assertNotIn("NestWalk", nullptr.ghidra_cpp)
        self.assertNotIn("FibTimer", nullptr.ghidra_cpp)
        field_os = cases["ghidra-word-field-ostream"]
        self.assertTrue(field_os.compile)
        self.assertEqual(field_os.recipe, "assemble")
        self.assertIn("p->n", field_os.ghidra_cpp)
        self.assertNotIn("NestWalk", field_os.ghidra_cpp)
        deref = cases["ghidra-word-field-deref"]
        self.assertTrue(deref.compile)
        self.assertIn("*p->left", deref.ghidra_cpp)
        self.assertNotIn("NestWalk", deref.ghidra_cpp)
        callee = cases["ghidra-undeclared-callee-stub"]
        self.assertTrue(callee.compile)
        self.assertIn("helper(p)", callee.ghidra_cpp)
        self.assertNotIn("NestWalk", callee.ghidra_cpp)
        ctor_tu = cases["ghidra-compiler-special-member-tu"]
        self.assertEqual(ctor_tu.recipe, "assemble")
        self.assertTrue(ctor_tu.compile)
        self.assertIn("Rec(Rec *param_2)", ctor_tu.ghidra_cpp + ctor_tu.extra_functions[0]["cpp"])
        self.assertNotIn("Item", ctor_tu.ghidra_cpp)
        self.assertNotIn("FibTimer", ctor_tu.ghidra_cpp)

    def test_critic_dialect_fixtures_are_loaded(self):
        cases = {c.id: c for c in load_corpus()}
        concat = cases["critic-ghidra-concat"]
        self.assertEqual(concat.recipe, "critic")
        self.assertIn("CONCAT44", concat.ghidra_cpp)
        self.assertNotIn("FibTimer", concat.ghidra_cpp)
        abi = cases["critic-compiler-in-reg"]
        self.assertIn("in_RCX", abi.ghidra_cpp)
        self.assertNotIn("FibTimer", abi.ghidra_cpp)
        human = cases["critic-human-vector"]
        self.assertIn("push_back", human.ghidra_cpp)
        self.assertNotIn("CONCAT", human.ghidra_cpp)
        self.assertNotIn("FibTimer", human.ghidra_cpp)
        alloc = cases["critic-ghidra-default-allocator"]
        self.assertIn("std::allocator<int>", alloc.ghidra_cpp)
        self.assertNotIn("FibTimer", alloc.ghidra_cpp)
        ctor = cases["critic-compiler-copy-ctor"]
        self.assertEqual(ctor.recipe, "critic")
        self.assertIn("Rec(Rec *param_2)", ctor.ghidra_cpp)
        self.assertNotIn("Item", ctor.ghidra_cpp)
        self.assertNotIn("FibTimer", ctor.ghidra_cpp)
        dctor = cases["critic-compiler-default-ctor"]
        self.assertEqual(dctor.recipe, "critic")
        self.assertIn("Rec() {", dctor.ghidra_cpp)
        self.assertNotIn("Item", dctor.ghidra_cpp)
        thiscall = cases["critic-ghidra-thiscall-ctor"]
        self.assertEqual(thiscall.recipe, "critic")
        self.assertIn("voidnew (Rec *this)", thiscall.ghidra_cpp)
        self.assertIn("__thiscallnew (Rec *this)", thiscall.ghidra_cpp)
        self.assertNotIn("Item", thiscall.ghidra_cpp)
        self.assertNotIn("FibTimer", thiscall.ghidra_cpp)
        ostream_addr = cases["critic-ghidra-ostream-addr-insert"]
        self.assertEqual(ostream_addr.recipe, "critic")
        self.assertIn("(*((std::ostream *)p))", ostream_addr.ghidra_cpp)
        self.assertNotIn("NestWalk", ostream_addr.ghidra_cpp)
        self.assertNotIn("FibTimer", ostream_addr.ghidra_cpp)


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
