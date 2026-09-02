from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.includes import collect_dynamic_includes, includes_from_calls, includes_from_dlls
from src.analysis.prompts import PROFILES, system_prompt_for, toolchain_rules_for
from src.analysis.triage import BinaryTriage, select_profile, triage_binary
from src.ghidra.headless import find_analyze_headless, GhidraError


def _write_minimal_pe(path: Path, machine: int = 0x8664, with_rich: bool = True) -> None:
    """Minimal MZ+PE header enough for triage_binary."""
    # DOS stub
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", data, e_lfanew + 4, machine)  # Machine
    struct.pack_into("<H", data, e_lfanew + 24, 0x20B)  # PE32+ magic
    if with_rich:
        data[0x40:0x44] = b"Rich"
    # debug-ish markers
    data[0x100:0x104] = b"RSDS"
    data[0x110:0x114] = b".pdb"
    path.write_bytes(data)


def _write_minimal_elf(path: Path, machine: int = 62) -> None:
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # LE
    struct.pack_into("<H", data, 18, machine)
    # GCC hint
    data += b"GCC: (GNU) 11.2.0\0"
    path.write_bytes(data)


class TestTriage(unittest.TestCase):
    def test_pe_msvc_debug_profile(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.exe"
            _write_minimal_pe(p)
            t = triage_binary(p)
            self.assertEqual(t.format, "pe")
            self.assertEqual(t.arch, "x64")
            self.assertEqual(t.compiler, "msvc")
            self.assertEqual(t.build, "debug")
            self.assertEqual(t.profile, "msvc_x64_debug")

    def test_elf_gcc_profile(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.elf"
            _write_minimal_elf(p)
            t = triage_binary(p)
            self.assertEqual(t.format, "elf")
            self.assertEqual(t.arch, "x64")
            self.assertEqual(t.compiler, "gcc")
            self.assertTrue(t.profile.startswith("gcc_elf"))

    def test_pe_gcc_profile(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.exe"
            _write_minimal_pe(p, with_rich=False)
            # убрать MSVC debug markers из хелпера и вставить GCC
            raw = bytearray(p.read_bytes())
            raw[0x100:0x120] = b"\0" * 0x20
            raw[0x100:0x110] = b"GCC: (GNU) 1\0"
            p.write_bytes(raw)
            t = triage_binary(p)
            self.assertEqual(t.format, "pe")
            self.assertEqual(t.compiler, "gcc")
            self.assertTrue(t.profile.startswith("gcc_pe"))

    def test_select_profile_generic(self):
        t = BinaryTriage(format="unknown", compiler="unknown", arch="unknown", build="unknown")
        self.assertEqual(select_profile(t), "generic")

    def test_enrich_from_ghidra_debug(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.exe"
            _write_minimal_pe(p, with_rich=True)
            # strip debug markers from file bytes by rewriting without RSDS
            raw = bytearray(p.read_bytes())
            raw[0x100:0x120] = b"\0" * 0x20
            p.write_bytes(raw)
            ghidra = {
                "functions": [
                    {"name": "_RTC_CheckStackVars", "ext_dlls": ["vcruntime140.dll"]},
                    {"name": "FUN_1000", "ext_dlls": ["gmp.dll"]},
                ],
                "imports": [],
            }
            t = triage_binary(p, ghidra=ghidra)
            self.assertEqual(t.build, "debug")
            self.assertEqual(t.compiler, "msvc")


class TestPrompts(unittest.TestCase):
    def test_profiles_exist(self):
        for name in ("msvc_x64_debug", "msvc_x64_release", "gcc_elf_x64", "generic"):
            self.assertIn(name, PROFILES)
            sys_p = system_prompt_for(name)
            self.assertIn("JSON", sys_p)
        self.assertIn("MSVC", system_prompt_for("msvc_x64_debug"))
        self.assertEqual(
            system_prompt_for("___missing___"),
            system_prompt_for("generic"),
        )
        rules = toolchain_rules_for("gcc_pe_x64")
        self.assertIn("литералы", rules)
        self.assertIn("ярлык", rules)


class TestIncludes(unittest.TestCase):
    def test_from_calls_and_dlls(self):
        self.assertIn("#include <cstdio>", includes_from_calls(["printf"]))
        self.assertIn("#include <gmp.h>", includes_from_calls(["mpz_add"]))
        self.assertIn("#include <mpfr.h>", includes_from_calls(["mpfr_gamma"]))
        self.assertIn("#include <mpfr.h>", includes_from_dlls(["libmpfr-6.dll"]))
        self.assertIn("#include <gmp.h>", includes_from_dlls(["gmp.dll"]))
        self.assertEqual(includes_from_dlls(["kernel32.dll"]), set())

    def test_collect_gmp_from_calls_and_dlls(self):
        restored = [{"ext_calls": ["printf"], "includes": ["<vector>"]}]
        funcs = [{"ext_calls": ["mpz_init"], "ext_dlls": ["gmp.dll"]}]
        incs = collect_dynamic_includes(restored, funcs)
        self.assertIn("#include <cstdio>", incs)
        self.assertIn("#include <gmp.h>", incs)

    def test_includes_mpfr_gmp_from_ghidra_body_without_imports(self):
        from src.analysis.includes import collect_dynamic_includes

        restored = [{"cpp_code": "void f() { mpfr_gamma(y); }", "ext_calls": []}]
        funcs = [{"ghidra_code": "__gmpz_set_ui(z, 1); mpfr_lngamma(y);", "ext_calls": []}]
        incs = collect_dynamic_includes(restored, funcs)
        self.assertIn("#include <mpfr.h>", incs)
        self.assertIn("#include <gmp.h>", incs)

    def test_includes_from_gmp_mpfr_typedef_tags(self):
        from src.analysis.includes import includes_from_source

        mpfr = includes_from_source("__mpfr_struct *x; mpfr_exp_t e;")
        gmp = includes_from_source("__mpz_struct *z;")
        self.assertIn("#include <mpfr.h>", mpfr)
        self.assertIn("#include <gmp.h>", gmp)

    def test_includes_from_source_algorithm(self):
        from src.analysis.includes import includes_from_source

        got = includes_from_source("std::sort(v.begin(), v.end()); std::equal(a, b, c);")
        self.assertIn("#include <algorithm>", got)
        broken = includes_from_source("std::\n    sort<int*>(p, p + 2);")
        self.assertIn("#include <algorithm>", broken)

    def test_includes_from_source_initializer_list_and_sqrt(self):
        from src.analysis.includes import includes_from_source

        self.assertIn(
            "#include <initializer_list>",
            includes_from_source("initializer_list<Item> local_20;"),
        )
        self.assertIn(
            "#include <cmath>",
            includes_from_source("return sqrt(x * x + y * y);"),
        )
        self.assertIn("#include <set>", includes_from_source("set<int> *s;"))
        self.assertIn(
            "#include <optional>",
            includes_from_source("optional<int> *p;"),
        )
        self.assertIn(
            "#include <cstring>",
            includes_from_source("memcpy(d, s, 2);"),
        )
        self.assertIn(
            "#include <cstring>",
            includes_from_source("memmove(d, s, 2);"),
        )
        self.assertIn("#include <cstring>", includes_from_calls(["memmove"]))
        self.assertIn(
            "#include <cstring>",
            includes_from_source("strcat(d, \"b\");"),
        )
        self.assertIn(
            "#include <utility>",
            includes_from_source("std::swap(a, b);"),
        )
        self.assertIn(
            "#include <cstdio>",
            includes_from_source('sprintf(buf, "%d", n);'),
        )
        self.assertIn(
            "#include <cstdlib>",
            includes_from_source("return atoi(s);"),
        )


class TestGhidraHeadlessLocator(unittest.TestCase):
    def test_finds_unix_or_bat(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            support = root / "support"
            support.mkdir()
            script = support / ("analyzeHeadless.bat" if sys.platform.startswith("win") else "analyzeHeadless")
            script.write_text("@echo off\n" if script.suffix == ".bat" else "#!/bin/sh\n", encoding="utf-8")
            found = find_analyze_headless(root)
            self.assertEqual(found, script)

    def test_missing_raises(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(GhidraError):
                find_analyze_headless(Path(td))


class TestEvalHarnessSmoke(unittest.TestCase):
    def test_fixture_eval(self):
        from src.analysis.eval_harness import eval_entry

        fixture = ROOT / "tests" / "fixtures" / "mini_ghidra.json"
        result = eval_entry("mini", ghidra_json=fixture)
        self.assertNotIn("error", result)
        self.assertGreaterEqual(result["metrics"]["functions"], 1)
        self.assertTrue(result["top"])


class TestRuntimeNoise(unittest.TestCase):
    def test_mingw_and_stl_filtered(self):
        from src.analysis.platform import is_runtime_noise
        from src.analysis.scorer import select_llm_targets

        self.assertTrue(is_runtime_noise("__mingw_pformat"))
        self.assertTrue(is_runtime_noise("_M_construct<char_const*>"))
        self.assertTrue(is_runtime_noise("_pei386_runtime_relocator"))
        self.assertTrue(is_runtime_noise("emplace_back<char*&>"))
        self.assertTrue(is_runtime_noise("thunk_FUN_140002000"))
        self.assertFalse(is_runtime_noise("main"))
        self.assertFalse(is_runtime_noise("print_report"))
        self.assertFalse(is_runtime_noise("FUN_140001000"))
        self.assertFalse(is_runtime_noise("nearest_index"))
        self.assertTrue(is_runtime_noise("fprintf"))
        self.assertTrue(is_runtime_noise("___chkstk_ms"))
        self.assertTrue(is_runtime_noise("_GetPEImageBase"))
        self.assertTrue(is_runtime_noise("_FindPESectionByName"))
        self.assertTrue(is_runtime_noise("compare"))
        self.assertTrue(is_runtime_noise("_Alloc_hider"))
        self.assertTrue(is_runtime_noise("~vector"))
        self.assertFalse(is_runtime_noise("starts_with"))
        self.assertFalse(is_runtime_noise("collect_matches"))
        self.assertTrue(is_runtime_noise("pointer_to"))
        self.assertTrue(is_runtime_noise("dtoa_lock"))
        self.assertTrue(is_runtime_noise("uninitialized_copy<const_Point*,_Point*>"))
        self.assertTrue(is_runtime_noise("find"))
        self.assertTrue(is_runtime_noise("substr"))
        self.assertTrue(is_runtime_noise("vector<char_const*_const*>"))
        from src.analysis.platform import looks_like_user_restore_name
        self.assertTrue(looks_like_user_restore_name("starts_with"))
        self.assertTrue(looks_like_user_restore_name("parse_ini"))
        self.assertFalse(looks_like_user_restore_name("find"))
        self.assertFalse(looks_like_user_restore_name("hash"))

        scored = [
            {"name": "__mingw_pformat", "score": 0.9, "address": "0x1"},
            {"name": "main", "score": 0.8, "address": "0x2"},
            {"name": "_M_assign", "score": 0.7, "address": "0x3"},
            {"name": "fprintf", "score": 0.5, "address": "0x5"},
            {"name": "compare", "score": 0.45, "address": "0x6"},
            {"name": "_GetPEImageBase", "score": 0.4, "address": "0x7"},
            {"name": "path_length", "score": 0.4, "address": "0x4"},
            {"name": "collect_matches", "score": 0.02, "address": "0x8"},
        ]
        top, n_filt = select_llm_targets(scored, 13)
        names = [s["name"] for s in top]
        self.assertEqual(names, ["main", "path_length", "collect_matches"])
        self.assertGreaterEqual(n_filt, 5)

    def test_scoring_manifest_skips_missing_dumps(self):
        from src.analysis.eval_harness import run_manifest

        man = ROOT / "eval" / "manifest.yaml"
        text = man.read_text(encoding="utf-8")
        self.assertGreaterEqual(text.count("user_names:"), 8)
        self.assertIn("taskboard", text)
        self.assertIn("netpath", text)
        with tempfile.TemporaryDirectory() as td:
            report = run_manifest(man, Path(td) / "score.json")
        self.assertEqual(report.get("n_fail"), 0)
        self.assertGreaterEqual(report.get("n_ok") or 0, 1)
        self.assertTrue((report.get("summary") or {}).get("not_compile_gate"))
        src = (ROOT / "src" / "analysis" / "eval_harness.py").read_text(encoding="utf-8")
        self.assertNotIn("compile_verify", src)
        self.assertNotIn("ghidra_cpp", src)

    def test_eval_user_names_and_filter(self):
        from src.analysis.eval_harness import eval_entry, _name_matches

        self.assertTrue(_name_matches("main", "main"))
        self.assertTrue(_name_matches("starts_with<char>", "starts_with"))
        self.assertFalse(_name_matches("__tmainCRTStartup", "main"))
        self.assertFalse(_name_matches("WinMain", "main"))
        self.assertFalse(_name_matches("_main", "main"))

        fixture = ROOT / "tests" / "fixtures" / "mini_ghidra.json"
        result = eval_entry(
            "mini",
            ghidra_json=fixture,
            user_names=["FUN_140001000", "_RTC_CheckStackVars"],
        )
        m = result["metrics"]
        self.assertEqual(m["recall_at_k_names"], 1.0)
        self.assertEqual(m["recall_at_k_names_filtered"], 0.5)
        filtered_names = [t["name"] for t in m["top_filtered"]]
        self.assertIn("FUN_140001000", filtered_names)
        self.assertNotIn("_RTC_CheckStackVars", filtered_names)


class TestGhidraCppSanitize(unittest.TestCase):
    def test_xorcipher_prototype(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = (
            "string * from_bytes(vector<unsigned_char,_std::allocator<unsigned_char>_> *buf)"
        )
        got = sanitize_ghidra_cpp(raw)
        self.assertIn("std::string", got)
        self.assertIn("std::vector<", got)
        self.assertIn("unsigned char", got)
        self.assertIn("std::allocator<", got)
        self.assertNotIn("_std::", got)
        self.assertNotIn("_>", got)

    def test_const_ref_arrow_not_string_star(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        arrow = sanitize_ghidra_cpp(
            "void show_n(void) { const_reference rec; rec = (*((std::vector<Rec> *)p))[i]; (void)rec->n; }"
        )
        self.assertIn("ghidra_ref *rec", arrow)
        self.assertIn("rec = (ghidra_ref *)&(", arrow)
        self.assertNotIn("const_reference rec", arrow)
        star = sanitize_ghidra_cpp(
            "void is_hash(void) { const_reference pvVar2; if (*pvVar2 != '#') return; }"
        )
        self.assertIn("const_reference pvVar2", star)
        self.assertNotIn("ghidra_ref", star)

    def test_iter_name_template_args_stripped(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "void walk_it(void) {\n"
            "  _Rb_tree_const_iterator<std::pair<int_const,_int>_> *pit;\n"
            "  _Rb_tree_const_iterator<std::pair<int_const,_int>_> *qid;\n"
            "  __normal_iterator<int *,vector<int,_std::allocator<int>_> > *vit;\n"
            "  bVar1 = std::operator!=(pit, qid);\n"
            "  (void)vit;\n"
            "}"
        )
        self.assertIn("_Rb_tree_const_iterator *pit", got)
        self.assertIn("__normal_iterator *vit", got)
        self.assertIn("*(pit) != *(qid)", got)
        self.assertNotIn("_Rb_tree_const_iterator<", got)
        self.assertNotIn("__normal_iterator<", got)
        self.assertNotIn("std::operator!=", got)
        self.assertNotIn("__gnu_cxx::__normal_iterator", got)

    def test_const_iterator_begin_is_placeholder(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "int sum_n(void) {\n"
            "  const_iterator cVar1;\n"
            "  vector<int,_std::allocator<int>_> *p;\n"
            "  const_iterator __for_begin;\n"
            "  __for_begin = std::vector<int,_std::allocator<int>_>::begin(p);\n"
            "  cVar1 = std::vector<int,_std::allocator<int>_>::end(p);\n"
            "  n = n + *__for_begin._M_current;\n"
            "}"
        )
        self.assertIn("(const_iterator)(p)", got)
        self.assertNotIn("->begin()", got)
        self.assertNotIn("_M_current", got)

    def test_long_long_unsigned_int(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::vector<long_long_unsigned_int> fib_series(unsigned n);"
        )
        self.assertIn("unsigned long long", got)
        self.assertNotIn("long long_unsigned", got)

    def test_member_call_rewrite(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = """
std::vector<unsigned long long>::reserve
    ((std::vector<unsigned long long>*)p, n);
std::vector<unsigned long long>::vector((std::vector<unsigned long long>*)p);
std::vector<unsigned long long>::~vector((std::vector<unsigned long long>*)p);
"""
        got = sanitize_ghidra_cpp(raw)
        self.assertIn("->reserve(n)", got)
        self.assertIn("new (", got)
        self.assertIn("->~vector()", got)
        self.assertNotIn("::reserve", got)
        br = sanitize_ghidra_cpp(
            "std::basic_string<char>::\n                     c_str(p);\n"
        )
        self.assertIn("->c_str()", br)
        self.assertNotIn("::c_str", br)
        nested = sanitize_ghidra_cpp(
            "std::vector<unsigned char>::\n"
            "std::vector<__normal_iterator>(p, a, b, al);\n"
        )
        self.assertIn("new (", nested)
        self.assertNotIn(">::std", nested)
        self.assertNotIn("*(a)", nested)
        self.assertNotIn("*(b)", nested)

    def test_time_point_and_chrono_sub(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "time_point<std::chrono::_V2::steady_clock,"
            "std::chrono::duration<long_long_int,_std::ratio<1,_1000000000>_> > t0;\n"
            "std::chrono::\n"
            "operator-<std::chrono::_V2::steady_clock,"
            "std::chrono::duration<long long,std::ratio<1,1000000000>>,"
            "std::chrono::duration<long long,std::ratio<1,1000000000>>>(a, b);\n"
        )
        self.assertIn("std::chrono::time_point<std::chrono::steady_clock", got)
        self.assertNotIn("_V2", got)
        self.assertIn("*(a) - *(b)", got)

    def test_iterator_begin_without_extra_parens(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "iterator iVar1;\n"
            "iterator __for_begin;\n"
            "vector<unsigned char> *p;\n"
            "__for_begin = (p)->begin();\n"
            "iVar1 = p->end();\n"
        )
        self.assertIn("(iterator)(p)", got)
        self.assertNotIn("->begin()", got)
        self.assertNotIn("->end()", got)
        nested = sanitize_ghidra_cpp(
            "const_iterator __for_begin;\n"
            "const_iterator cVar2;\n"
            "__for_begin = ((std::vector<int> *)in_stack_98)->begin();\n"
            "cVar2 = ((std::vector<int> *)in_stack_98)->end();\n"
        )
        self.assertIn("(const_iterator)(in_stack_98)", nested)
        self.assertNotIn("->begin()", nested)
        self.assertNotIn("->end()", nested)

    def test_duration_cast_not_rewritten(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = "auto us = std::chrono::duration_cast<std::chrono::microseconds>(d);"
        self.assertIn("duration_cast", sanitize_ghidra_cpp(raw))
        self.assertNotIn("->duration_cast", sanitize_ghidra_cpp(raw))
        self.assertIn("duration_cast<std::chrono::microseconds>(d)", sanitize_ghidra_cpp(raw))

    def test_chrono_duration_cast_extra_targs_and_priv_r(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::chrono::duration_cast<std::chrono::duration<long_long_int,"
            "_std::ratio<1,_1000000>_>,_long_long_int,_std::ratio<1,_1000000000>_>"
            "((duration<long_long_int,_std::ratio<1,_1000000000>_> *)p);\n"
        )
        self.assertIn(
            "duration_cast<std::chrono::duration<long long,std::ratio<1,1000000>>>",
            got,
        )
        self.assertNotIn(",long long,std::ratio<1,1000000000>>", got)
        self.assertNotIn("->duration_cast", got)
        priv = sanitize_ghidra_cpp(
            "std::chrono::duration<long_long_int,_std::ratio<1,_1000000>_>::duration<int>"
            "((duration<long_long_int,_std::ratio<1,_1000000>_> *)local.__r, (int *)rep);\n"
        )
        self.assertIn("(&local)", priv)
        self.assertNotIn(".__r", priv)
        self.assertIn("new (", priv)

    def test_extract_named_drops_extras(self):
        from src.analysis.ghidra_cpp import extract_named_function

        raw = """
void fib_series(int n) { series.resize(n); }
int main(int argc, char **argv) { return 0; }
"""
        got = extract_named_function(raw, "main")
        self.assertIn("int main", got)
        self.assertNotIn("fib_series", got)

    def test_invalid_using_stripped(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = "using long long_unsigned int = unsigned long long;\nint f() { return 1; }\n"
        got = sanitize_ghidra_cpp(raw)
        self.assertNotIn("using long", got)
        self.assertIn("int f()", got)

    def test_keeps_string_literal(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = 'printf("restored: %s\\n", pcVar2);'
        self.assertEqual(sanitize_ghidra_cpp(raw), raw)
        lit = 'printf("a string of bytes");'
        self.assertEqual(sanitize_ghidra_cpp(lit), lit)

    def test_ostream_ghidra_syntax(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = (
            "pbVar1 = thunk((std::basic_ostream<char, std::char_traits<char>> *)std::cout, \"n\");\n"
            "pbVar2 = std::basic_ostream<char, std::char_traits<char>>::operator<<(pbVar1, n);\n"
        )
        got = sanitize_ghidra_cpp(raw)
        self.assertIn("&std::cout", got)
        self.assertNotIn("*)std::cout", got)
        self.assertIn("<< (", got)
        self.assertNotIn("::operator<<", got)
        self.assertIn("(&((", got)

    def test_operator_assign_rewrite(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::string::operator=(prefixPtr, (char *)inputStringPtr);\n"
            "std::vector<std::string>::operator=(&lines, &initializerList);\n"
        )
        self.assertIn("(*(prefixPtr) = ((char *)inputStringPtr))", got)
        self.assertIn("(*(&lines) = (initializerList))", got)
        self.assertNotIn("::operator=", got)

    def test_string_assign_ptr_and_plus_eq(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::string::operator=(dst, src);\n"
            "std::string::operator+=(dst, src);\n"
        )
        self.assertIn("(*(dst) = (*(src)))", got)
        self.assertIn("(*(dst) += (*(src)))", got)
        self.assertNotIn("::operator=", got)
        self.assertNotIn("::operator+=", got)

    def test_string_ctor_deref_alloc_ident(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::basic_string<char>::basic_string<>(p, (char *)s, a);\n"
        )
        self.assertIn("new (", got)
        self.assertIn("*(a)", got)
        self.assertNotIn("::basic_string<>", got)
        dump = sanitize_ghidra_cpp(
            "std::basic_string<char>::basic_string<>(p, s, a);\n"
        )
        self.assertIn("*(a)", dump)
        self.assertNotIn("*(s)", dump)

    def test_ghidra_underscore_int_template(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp("int first_of(pair<int,_int> *p);")
        self.assertIn("std::pair<int,int>", got)
        self.assertNotIn("_int", got)

    def test_map_index_key_ptr_and_split_std(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = (
            "std::\n"
            "map<int, unsigned long long>::map(m);\n"
            "std::map<int, unsigned long long>::operator[](m, (key_type *)k);\n"
        )
        got = sanitize_ghidra_cpp(raw)
        self.assertIn("new (", got)
        self.assertNotIn("std::\n  std::map", got)
        self.assertIn("[*((key_type *)k)]", got)
        self.assertNotIn("::operator[]", got)

    def test_operator_index_rewrite(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::vector<int>::operator[](p, (size_type)i);\n"
        )
        self.assertIn("(*(p))[(size_type)i]", got)
        self.assertNotIn("::operator[]", got)

    def test_bare_initializer_list(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp("initializer_list<Item> local_20;")
        self.assertIn("std::initializer_list<Item>", got)
        self.assertNotIn(" std::std::initializer_list", got)

    def test_bare_set_and_optional(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        self.assertIn("std::set<int>", sanitize_ghidra_cpp("set<int> *s;"))
        self.assertIn("std::optional<int>", sanitize_ghidra_cpp("optional<int> *p;"))
        self.assertIn("std::deque<int>", sanitize_ghidra_cpp("deque<int> *d;"))
        self.assertIn("std::list<int>", sanitize_ghidra_cpp("list<int> *l;"))
        self.assertIn(
            "std::unordered_set<int>",
            sanitize_ghidra_cpp("unordered_set<int> *s;"),
        )
        self.assertIn(
            "std::multiset<int>",
            sanitize_ghidra_cpp("multiset<int> *s;"),
        )
        sw = sanitize_ghidra_cpp("swap(a, b); (p)->swap(q);")
        self.assertIn("std::swap(a, b)", sw)
        self.assertIn("->swap(q)", sw)
        self.assertNotIn("->std::swap", sw)
        tswap = sanitize_ghidra_cpp("std::swap<int>(a, b);")
        self.assertIn("*(a)", tswap)
        self.assertIn("*(b)", tswap)
        self.assertIn(
            "->value_or(0)",
            sanitize_ghidra_cpp("std::optional<int>::value_or(p, 0);"),
        )
        ins = sanitize_ghidra_cpp("std::set<int>::insert(s, k);")
        self.assertIn("->insert(*(k))", ins)
        vec_ins = sanitize_ghidra_cpp("std::vector<int>::insert(v, it, x);")
        self.assertIn("->insert(it, x)", vec_ins)
        self.assertNotIn("*(it)", vec_ins)

    def test_map_underscore_types_and_bare_map(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = (
            "int has_key(map<int,_long_long_unsigned_int,"
            "_std::less<int>,_std::allocator<std::pair<int_const,"
            "_long_long_unsigned_int>_>_> *m);\n"
        )
        got = sanitize_ghidra_cpp(raw)
        self.assertIn("std::map<", got)
        self.assertIn("unsigned long long", got)
        self.assertIn("int const", got)
        self.assertNotIn("_unsigned", got)
        self.assertNotIn("int_const", got)

    def test_const_std_not_glued_to_conststd(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::allocator<std::pair<const_std::__cxx11::basic_string<char>, int> > *m;"
        )
        self.assertIn("const std::basic_string", got)
        self.assertNotIn("conststd", got)
        self.assertNotIn("const_std::", got)

    def test_lexical_table_drives_const_std_and_m_cur(self):
        from src.analysis.lexical import LEXICAL_PATH, apply_lexical

        self.assertTrue(LEXICAL_PATH.is_file())
        glued = apply_lexical("const_std::string x;", "before_underscore_std")
        self.assertEqual(glued, "const std::string x;")
        glued2 = apply_lexical(
            "basic_ostream<char,structstd::char_traits<char>> *p;",
            "before_underscore_std",
        )
        self.assertIn("std::char_traits", glued2)
        self.assertNotIn("structstd", glued2)
        cur = apply_lexical("it._M_cur = 0;", "after_templates")
        self.assertEqual(cur, "(it) = 0;")

    def test_bare_basic_ostream_qualified(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "void print_n(int n) {\n"
            "  basic_ostream<char,std::char_traits<char>> *pbVar3;\n"
            "  basic_ostream<char,structstd::char_traits<char>> *pbVar4;\n"
            "  pbVar3 = (basic_ostream<char,std::char_traits<char>> *)std::cout;\n"
            "  (void)n; (void)pbVar3; (void)pbVar4;\n"
            "}\n"
        )
        self.assertIn("std::basic_ostream<char,std::char_traits<char>>", got)
        self.assertNotIn("structstd", got)
        self.assertNotRegex(got, r"(?<!std::)basic_ostream")

    def test_underscore_false_true_nttp(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "_Node_iterator<std::pair<int,int>,_false,_true> *it;\n"
            "_Node_iterator<std::pair<int,int>,_bool_,_true> *flag;\n"
        )
        self.assertIn(",false,true>", got)
        self.assertIn(",bool,true>", got)
        self.assertNotIn("_false", got)
        self.assertNotIn("_bool_", got)
        self.assertNotIn("_true", got)
        self.assertIn("std::__detail::_Node_iterator<", got)

    def test_const_user_type_not_iterator(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "int take_n(const_Rec *p) { return p->n; }\n"
            "int take_n2(_const_Rec *q) { return q->n; }\n"
            "int take_n3(Rec_const *r) { return r->n; }\n"
            "const_iterator it;\n"
        )
        self.assertIn("const Rec *p", got)
        self.assertIn("const Rec *q", got)
        self.assertIn("Rec const *r", got)
        self.assertIn("const_iterator it", got)
        self.assertNotIn("const_Rec", got)
        self.assertNotIn("_const_Rec", got)
        self.assertNotIn("Rec_const", got)

    def test_node_iterator_member_star(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::__detail::\n"
            "_Node_iterator<std::pair<int,int>,_false,_true>\n"
            "::operator*(it);\n"
            "std::__detail::_Node_iterator<std::pair<int,int>,_false,_true>"
            "::operator++(it);\n"
        )
        self.assertIn("->operator*()", got)
        self.assertIn("->operator++()", got)
        self.assertNotIn("std::__detail::std::__detail::", got)
        self.assertNotIn("::operator*(", got)

    def test_string_front_ref_not_star_deref(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "pvVar2 = std::__cxx11::basic_string<char>::back(p);\n"
            "if (*pvVar2 != ' ') return;\n"
        )
        self.assertIn("->back()", got)
        self.assertIn("pvVar2 != ' '", got)
        self.assertNotIn("*pvVar2", got)

    def test_string_begin_not_cast_to_char_ptr(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "local_28 = (char *)std::__cxx11::basic_string<char>::begin(p);\n"
        )
        self.assertIn("(void)((p)->begin())", got)
        self.assertNotIn("(char *)", got)

    def test_detail_iterator_compare_is_infix(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "bVar1 = std::__detail::operator==(a, b);\n"
            "bVar2 = std::__detail::operator!=(a, b);\n"
        )
        self.assertIn("(a) == (b)", got)
        self.assertIn("(a) != (b)", got)
        self.assertNotIn("__detail::operator==", got)
        self.assertNotIn("__detail::operator!=", got)

    def test_std_string_operator_eq_not_forced_infix(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "bVar1 = std::operator==<char,_std::char_traits<char>,_std::allocator<char>_>(s, p);\n"
        )
        self.assertIn("std::operator==", got)
        self.assertNotIn("(s) == (p)", got)

    def test_hashtable_priv_cur_and_node_type(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "local_28._M_cur = (__node_type *)m->end();\n"
            "if (a._M_current == b._M_current) return;\n"
            "a._M_current = a._M_current + 1;\n"
        )
        self.assertIn("(local_28) =", got)
        self.assertIn("(a) == (b)", got)
        self.assertIn("(a) = (a) + 1", got)
        self.assertNotIn("_M_cur", got)
        self.assertNotIn("_M_current", got)
        self.assertNotIn("__node_type", got)

    def test_pointer_pair_fields_rewritten(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "pointer ppVar3;\n(void)ppVar3->second;\n"
        )
        self.assertIn("pointer ppVar3", got)
        self.assertIn("((std::pair<ghidra_word, ghidra_word> *)ppVar3)->second", got)
        self.assertNotIn("ppVar3->second", got)

    def test_nrvo_iter_as_string_dropped(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "__const_iterator it;\n"
            "basic_string<char,_std::char_traits<char>,_std::allocator<char>_> *p;\n"
            "std::__cxx11::basic_string<char,_std::char_traits<char>,_std::allocator<char>_>"
            "::basic_string(p, (basic_string<char,_std::char_traits<char>,"
            "_std::allocator<char>_> *) it._M_current);\n"
        )
        self.assertIn("(void)0", got)
        self.assertNotIn("new (", got)

    def test_mingw_fu_cout_and_s_out(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "poVar1 = std::operator<<((ostream *)__fu0__ZSt4cout, \"n=\");\n"
            "std::ofstream::ofstream(&out, path, _S_out);\n"
        )
        self.assertIn("std::cout", got)
        self.assertNotIn("__fu0__ZSt4cout", got)
        self.assertIn("std::ios::out", got)
        self.assertNotIn("_S_out", got)
        self.assertIn("std::ofstream", got)

    def test_chrono_nttp_and_bare_duration(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "duration<long_long_int,_std::ratio<1,_1000000>_> *p;\n"
            "p = duration_cast<std::chrono::microseconds>(d);\n"
        )
        self.assertIn("std::chrono::duration<long long,std::ratio<1,1000000>>", got)
        self.assertNotIn("_1000000", got)
        self.assertNotIn("_std::", got)
        self.assertNotIn("->duration_cast", got)

    def test_find_and_push_back_deref_ptr_arg(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        find_got = sanitize_ghidra_cpp(
            "std::basic_string<char>::find(hay, needle, pos);\n"
        )
        self.assertIn("->find(*(needle), pos)", find_got)
        self.assertNotIn("::find", find_got)
        push_got = sanitize_ghidra_cpp(
            "std::vector<int>::push_back(xs, item);\n"
        )
        self.assertIn("->push_back(*(item))", push_got)
        self.assertNotIn("::push_back", push_got)
        str_push = sanitize_ghidra_cpp(
            "std::basic_string<char>::push_back(s, ch);\n"
        )
        self.assertIn("->push_back(ch)", str_push)
        self.assertNotIn("*(ch)", str_push)
        count_got = sanitize_ghidra_cpp(
            "std::map<int, int>::count(m, key);\n"
        )
        self.assertIn("->count(*(key))", count_got)
        self.assertNotIn("::count", count_got)
        fill_got = sanitize_ghidra_cpp(
            "std::vector<char>::vector(p, n, val, a);\n"
        )
        self.assertIn("new (", fill_got)
        self.assertIn("*(val)", fill_got)
        self.assertNotIn("*(n)", fill_got)
        self.assertNotIn(", a)", fill_got)
        self.assertNotIn(">::vector(", fill_got)
        range_ctor = sanitize_ghidra_cpp(
            "std::vector<int>::vector(p, first, last);\n"
        )
        self.assertNotIn("*(last)", range_ctor)

    def test_free_std_operator_lshift(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "poVar1 = std::operator<<((ostream *)__fu0__ZSt4cout, \"n=\");\n"
            "std::operator<<(poVar1, \"\\n\");\n"
        )
        self.assertIn("<< (", got)
        self.assertIn("&std::cout", got)
        self.assertNotIn("std::operator<<", got)
        self.assertNotIn("__fu0__ZSt4cout", got)

    def test_ofstream_dtor_not_std_qualified(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp(
            "std::ofstream::~ofstream((ofstream *)&out);\n"
            "out.~ofstream();\n"
        )
        self.assertIn("->~ofstream()", got)
        self.assertIn("out.~ofstream()", got)
        self.assertNotIn("~std::ofstream", got)

    def test_extract_renames_first_function(self):
        from src.analysis.ghidra_cpp import extract_named_function

        raw = "int function_1400014b0(int x) { return x; }\n"
        got = extract_named_function(raw, "starts_with")
        self.assertIn("starts_with(", got)
        self.assertNotIn("function_1400014b0", got)

    def test_ostream_lshift_assign_from_cache_form(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = "pbVar2 =(*(pbVar1)) << (local_200);\n"
        got = sanitize_ghidra_cpp(raw)
        self.assertIn("(&((*(pbVar1)) << (local_200))", got)

    def test_ostream_array_and_gmp_amp(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        raw = (
            "void f(mpz_srcptr p) {\n"
            "  std::basic_ostream<char, std::char_traits<char>> *pbVar3;\n"
            "  std::basic_ostream<char, std::char_traits<char>> local_298[292];\n"
            "  __gmpz_init(&obj->field7);\n"
            "}\n"
        )
        got = sanitize_ghidra_cpp(raw)
        self.assertIn("ghidra_word p", got)
        self.assertIn("undefined1 local_298[292]", got)
        self.assertIn("*pbVar3", got)
        self.assertNotIn("basic_ostream<char, std::char_traits<char>> local_298", got)
        self.assertIn("(mpz_ptr)(&obj->field7)", got)

    def test_dat_underscore_and_mpz_t_ptr(self):
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

        got = sanitize_ghidra_cpp("void f(mpz_t *x) { (void)_DAT_14002e018; }")
        self.assertIn("ghidra_word x", got)
        self.assertNotIn("mpz_t *", got)
        self.assertIn("DAT_14002e018", got)
        self.assertNotIn("_DAT_14002e018", got)


class TestCompileVerify(unittest.TestCase):
    def test_parse_gcc_and_msvc(self):
        from src.analysis.compile_verify import extract_cpp, parse_diagnostics

        gcc = (
            "restored.cpp:12:5: error: 'foo' was not declared in this scope\n"
            "restored.cpp:12:5: note: suggested alternative: 'bar'\n"
            "restored.cpp:20:1: fatal error: missing header\n"
        )
        errs = parse_diagnostics(gcc)
        self.assertEqual(len(errs), 2)
        self.assertEqual(errs[0]["line"], "12")
        self.assertIn("not declared", errs[0]["message"])

        msvc = r"C:\tmp\a.cpp(8): error C2065: 'x': undeclared identifier"
        errs2 = parse_diagnostics(msvc)
        self.assertEqual(len(errs2), 1)
        self.assertEqual(errs2[0]["line"], "8")

        fenced = "here\n```cpp\nint main() { return 0; }\n```\n"
        self.assertEqual(extract_cpp(fenced), "int main() { return 0; }")

    def test_syntax_check_if_compiler_present(self):
        from src.analysis.compile_verify import compile_cpp, find_cxx_compiler

        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        with tempfile.TemporaryDirectory() as td:
            ok_p = Path(td) / "ok.cpp"
            bad_p = Path(td) / "bad.cpp"
            ok_p.write_text("int main() { return 0; }\n", encoding="utf-8")
            bad_p.write_text("int main() { return foo; }\n", encoding="utf-8")
            ok = compile_cpp(ok_p, compiler=cxx, timeout_sec=30)
            self.assertTrue(ok.attempted)
            self.assertTrue(ok.ok, ok.stderr)
            bad = compile_cpp(bad_p, compiler=cxx, timeout_sec=30)
            self.assertTrue(bad.attempted)
            self.assertFalse(bad.ok)
            self.assertGreaterEqual(bad.n_errors, 1)

    def test_compile_snippet(self):
        from src.analysis.compile_verify import compile_snippet, find_cxx_compiler
        from src.analysis.includes import make_preamble

        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        preamble = make_preamble("// snip", [], [])
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            ok = compile_snippet(
                "int add(int a, int b) { return a + b; }",
                preamble_lines=preamble,
                work_dir=work,
                name="0x1000",
                compiler=cxx,
            )
            self.assertTrue(ok.ok, ok.stderr)
            bad = compile_snippet(
                "int add(int a, int b) { return foo; }",
                preamble_lines=preamble,
                work_dir=work,
                name="0x2000",
                compiler=cxx,
            )
            self.assertTrue(bad.attempted)
            self.assertFalse(bad.ok)
            self.assertGreaterEqual(bad.n_errors, 1)

    def test_compile_snippet_infers_undeclared_struct(self):
        from src.agents.assembler import assemble, type_stubs_for_snippet
        from src.analysis.compile_verify import compile_snippet, find_cxx_compiler
        from src.analysis.includes import make_preamble

        body = (
            "double dist2(CloudPt *a, CloudPt *b) {\n"
            "  CloudPt query;\n"
            "  (void)a; (void)b; (void)query;\n"
            "  return 0;\n"
            "}\n"
        )
        stubs = type_stubs_for_snippet(body)
        self.assertTrue(any("struct CloudPt" in ln for ln in stubs))
        self.assertFalse(any("struct local_110" in ln for ln in stubs))
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "dist2",
            "ghidra_name": "FUN_1",
            "cpp_code": body,
        }]
        tu, n = assemble(restored, [], [])
        self.assertEqual(n, 1)
        self.assertIn("struct CloudPt", tu)

        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        preamble = make_preamble("// per-fn", restored, [])
        with tempfile.TemporaryDirectory() as td:
            rep = compile_snippet(
                body,
                preamble_lines=preamble,
                work_dir=Path(td),
                name="0x1",
                compiler=cxx,
            )
            self.assertTrue(rep.ok, rep.stderr)

    def test_compile_snippet_does_not_infer_ghidra_locals(self):
        from src.agents.assembler import type_stubs_for_snippet

        stubs = type_stubs_for_snippet(
            "void go() {\n"
            "  longlong local_110;\n"
            "  local_110 *p;\n"
            "  p = &local_110;\n"
            "}\n"
        )
        blob = "\n".join(stubs)
        self.assertNotIn("struct local_110", blob)

    def test_type_stubs_sibling_user_calls(self):
        from src.agents.assembler import type_stubs_for_snippet

        body = (
            "int nearest(CloudPt *q) {\n"
            "  return dist2(q, q) > 0.0;\n"
            "}\n"
        )
        stubs = type_stubs_for_snippet(
            body,
            sibling_names=["dist2", "nearest"],
            current_name="nearest",
        )
        blob = "\n".join(stubs)
        self.assertIn("dist2", blob)
        self.assertNotIn("inline ghidra_word nearest(", blob)

    def test_ghidra_typedefs_compile(self):
        from src.analysis.compile_verify import compile_cpp, find_cxx_compiler
        from src.analysis.includes import make_preamble

        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        preamble = make_preamble("// test", [], [])
        src = "\n".join(preamble) + (
            "int f(undefined8 x, longlong y, __uint64 z) { return (int)(x + y + z); }\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ghidra_types.cpp"
            p.write_text(src, encoding="utf-8")
            rep = compile_cpp(p, compiler=cxx, timeout_sec=30)
            self.assertTrue(rep.attempted)
            self.assertTrue(rep.ok, rep.stderr)

    def test_rewritten_member_calls_compile(self):
        from src.analysis.compile_verify import compile_snippet, find_cxx_compiler
        from src.analysis.ghidra_cpp import sanitize_ghidra_cpp
        from src.analysis.includes import make_preamble

        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        body = sanitize_ghidra_cpp(
            "void f(std::vector<int>* p, int n) {\n"
            "  std::vector<int>::reserve(p, (size_type)n);\n"
            "  std::vector<int>::push_back(p, 1);\n"
            "}\n"
        )
        preamble = make_preamble("// test", [], [])
        with tempfile.TemporaryDirectory() as td:
            rep = compile_snippet(
                body,
                preamble_lines=preamble,
                work_dir=Path(td),
                name="vec_call",
                compiler=cxx,
            )
            self.assertTrue(rep.ok, rep.stderr)

    def test_ghidra_word_thunk_assigns_to_pointer(self):
        from src.analysis.compile_verify import compile_cpp, find_cxx_compiler
        from src.agents.assembler import assemble

        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "go",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                "void go() {\n"
                "  char *p = thunk_FUN_140010000(\"x\");\n"
                "  DAT_140020000 = DAT_140020000 ^ 1ull;\n"
                "  (void)p;\n"
                "}\n"
            ),
        }]
        text, _n = assemble(restored, [], [])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "thunk.cpp"
            p.write_text(text + "\n", encoding="utf-8")
            rep = compile_cpp(p, compiler=cxx, timeout_sec=30)
            self.assertTrue(rep.ok, rep.stderr)

    def test_ghidra_ostream_rewritten_compiles(self):
        from src.analysis.compile_verify import compile_cpp, find_cxx_compiler
        from src.agents.assembler import assemble

        cxx = find_cxx_compiler()
        if not cxx:
            self.skipTest("no C++ compiler on PATH")
        restored = [{
            "classification": "user_code",
            "address": "0x1",
            "guessed_name": "go",
            "ghidra_name": "FUN_1",
            "cpp_code": (
                "void go() {\n"
                "  uint64_t n = 1;\n"
                "  std::basic_ostream<char, std::char_traits<char>> *pbVar1;\n"
                "  std::basic_ostream<char, std::char_traits<char>> *pbVar2;\n"
                "  pbVar1 = thunk_FUN_140014360(\n"
                "      (std::basic_ostream<char, std::char_traits<char>> *)std::cout, \"n\");\n"
                "  pbVar2 = std::basic_ostream<char, std::char_traits<char>>::operator<<(pbVar1, n);\n"
                "  (void)pbVar2;\n"
                "}\n"
            ),
        }]
        text, _n = assemble(restored, [], [])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "ostream.cpp"
            p.write_text(text + "\n", encoding="utf-8")
            rep = compile_cpp(p, compiler=cxx, timeout_sec=30)
            self.assertTrue(rep.ok, rep.stderr)

    def test_strip_int_dat_redecls(self):
        from src.agents.assembler import strip_int_dat_redecls

        src = (
            "static ghidra_word DAT_abc;\n"
            "uint32_t DAT_14003b02e;\n"
            "extern uint32_t DAT_14003b02e;\n"
            "extern void __CheckForDebuggerJustMyCode(uint32_t *);\n"
            "int main() { return 0; }\n"
        )
        got = strip_int_dat_redecls(src)
        self.assertIn("ghidra_word DAT_abc", got)
        self.assertNotIn("uint32_t DAT_14003b02e", got)
        self.assertNotIn("__CheckForDebuggerJustMyCode", got)


if __name__ == "__main__":
    unittest.main()
