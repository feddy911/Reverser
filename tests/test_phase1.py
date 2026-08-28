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
from src.analysis.prompts import PROFILES, system_prompt_for
from src.analysis.triage import BinaryTriage, select_profile, triage_binary
from src.ghidra.headless import find_analyze_headless, GhidraError
from src.domains import get_domain_pack


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


class TestIncludes(unittest.TestCase):
    def test_from_calls_and_dlls(self):
        self.assertIn("#include <cstdio>", includes_from_calls(["printf"]))
        self.assertIn("#include <gmp.h>", includes_from_calls(["mpz_add"]))
        self.assertIn("#include <gmp.h>", includes_from_dlls(["gmp.dll"]))
        self.assertEqual(includes_from_dlls(["kernel32.dll"]), set())

    def test_collect_merges_pack(self):
        pack = get_domain_pack("mycollatz")
        restored = [{"ext_calls": ["printf"], "includes": ["<vector>"]}]
        funcs = [{"ext_calls": ["mpz_init"], "ext_dlls": ["gmp.dll"]}]
        incs = collect_dynamic_includes(restored, funcs, pack=pack)
        self.assertIn("#include <cstdio>", incs)
        self.assertIn("#include <gmp.h>", incs)


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


if __name__ == "__main__":
    unittest.main()
