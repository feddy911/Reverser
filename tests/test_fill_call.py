from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.ghidra_cpp import fill_truncated_call_imms, leftover_call_arity, sanitize_ghidra_cpp
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


HELPER = (
    "void helper(longlong *xs);\n"
    "void wrap(void)\n"
    "{\n"
    "  longlong *xs;\n"
    "  helper(xs);\n"
    "}\n"
)
SITES = {
    "sites": [
        {
            "off": 12,
            "kind": "rel",
            "callee_va": "0x140002000",
            "iat_name": "",
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [["rdx", 2]],
            "lea_slots": [],
        }
    ]
}
LEA_ONLY = {
    "sites": [
        {
            "off": 12,
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [],
            "lea_slots": [["rdx", 2]],
            "iat_name": "",
        }
    ]
}
GMP = (
    "undefined8 __gmpz_cmp_ui(undefined8 param_1);\n"
    "void wrap(void)\n"
    "{\n"
    "  __gmpz_cmp_ui(param_1);\n"
    "  __gmpz_set(zs);\n"
    "}\n"
)
GMP_SITES = {
    "sites": [
        {
            "off": 20,
            "kind": "rip_mem",
            "iat_name": "__gmpz_cmp_ui",
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [["rdx", 1]],
        },
        {
            "off": 40,
            "kind": "rip_mem",
            "iat_name": "__gmpz_set",
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [],
        },
    ]
}
IAT = {
    "protos": [
        {
            "name": "__gmpz_cmp_ui",
            "arity": 2,
            "variadic": False,
            "slots": [["rcx", "mpz_srcptr"], ["rdx", "unsigned long"]],
        },
        {
            "name": "__gmpz_set",
            "arity": 2,
            "variadic": False,
            "slots": [["rcx", "mpz_ptr"], ["rdx", "mpz_srcptr"]],
        },
    ]
}


class TestFillCall(unittest.TestCase):
    def test_empty_bag_does_not_invent(self):
        self.assertEqual(fill_truncated_call_imms(HELPER, None, None), HELPER)
        self.assertEqual(fill_truncated_call_imms(HELPER, {}, {}), HELPER)
        self.assertEqual(
            fill_truncated_call_imms(HELPER, {"sites": []}, {"protos": []}),
            HELPER,
        )
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_helper_unique_imm(self):
        got = fill_truncated_call_imms(HELPER, SITES, None)
        self.assertIn("helper(xs, 2)", got)
        self.assertNotIn("helper(xs);", got)
        self.assertEqual(leftover_call_arity(got, SITES, None), [])
        dumped = json.dumps(SITES)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)

    def test_lea_is_not_an_immediate(self):
        self.assertEqual(fill_truncated_call_imms(HELPER, LEA_ONLY, None), HELPER)

    def test_iat_imm_not_mpz_cast(self):
        got = fill_truncated_call_imms(GMP, GMP_SITES, IAT)
        self.assertIn("__gmpz_cmp_ui(param_1, 1)", got)
        self.assertIn("__gmpz_cmp_ui(undefined8 param_1, unsigned long)", got)
        self.assertIn("__gmpz_set(zs);", got)
        self.assertNotIn("mpz_srcptr", got)
        self.assertNotIn("mpz_ptr", got)
        self.assertNotIn("__gmpz_set(zs,", got)
        hits = leftover_call_arity(got, GMP_SITES, IAT)
        self.assertEqual(hits, ["__gmpz_set"])

    def test_iat_without_sites_does_not_invent(self):
        self.assertEqual(fill_truncated_call_imms(GMP, None, IAT), GMP)

    def test_sanitize_passes_sites(self):
        got = sanitize_ghidra_cpp(HELPER, call_sites=SITES)
        self.assertIn("helper(xs, 2)", got)
        empty = sanitize_ghidra_cpp(HELPER)
        self.assertIn("helper(xs);", empty)

    def test_emit_fills_unique_imm_from_func_bytes(self):
        from src.analysis.eval_call_sites import WRAP_IMM, WRAP_VA
        from src.analysis.ghidra_cpp import emit_sanitized_restore

        raw = HELPER
        data = {
            "address": f"0x{WRAP_VA:x}",
            "cpp_code": raw,
            "func_bytes": WRAP_IMM,
        }
        emit_sanitized_restore(data)
        self.assertIn("helper(xs, 2)", data["cpp_code"])
        self.assertNotIn("helper(xs);", data["cpp_code"])
        self.assertEqual(data["cpp_code_raw"], raw)
        self.assertNotIn("call_sites", data)
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")
        bare = {"cpp_code": raw}
        emit_sanitized_restore(bare)
        self.assertIn("helper(xs);", bare["cpp_code"])
        runner = (
            Path(__file__).resolve().parents[1] / "src" / "pipeline" / "runner.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("call_sites", runner)
        self.assertNotIn("src.analysis.call_sites", runner)


if __name__ == "__main__":
    unittest.main()
