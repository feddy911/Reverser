from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents.compiler import match_errors
from src.analysis.feedback_facts import (
    ACTION_LEFTOVER,
    ACTION_SKIP,
    plan_errors,
    plan_one,
)
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

CMP_MSG = (
    "too few arguments to function "
    "'int __gmpz_cmp_ui(mpz_srcptr, long unsigned int)'"
)
SET_MSG = "too few arguments to function 'void __gmpz_set(mpz_ptr, mpz_srcptr)'"
PTR_MSG = (
    "invalid conversion from 'longlong' {aka 'long long int'} to 'mpz_ptr' "
    "{aka '__mpz_struct*'} [-fpermissive]"
)
UCHAR_MSG = (
    "invalid conversion from 'undefined*' {aka 'unsigned char*'} "
    "to 'const char*' [-fpermissive]"
)
CMP = "void wrap(void) { __gmpz_cmp_ui(param_1); }\n"
SET = "void wrap(void) { __gmpz_set(zs); }\n"
SITES_CMP = {
    "sites": [{
        "off": 20,
        "iat_name": "__gmpz_cmp_ui",
        "arg_regs": ["rcx", "rdx"],
        "imm_slots": [["rdx", 1]],
    }]
}
SITES_SET = {
    "sites": [{
        "off": 40,
        "iat_name": "__gmpz_set",
        "arg_regs": ["rcx", "rdx"],
        "imm_slots": [],
    }]
}
IAT_CMP = {
    "protos": [{
        "name": "__gmpz_cmp_ui",
        "arity": 2,
        "slots": [["rcx", "mpz_srcptr"], ["rdx", "unsigned long"]],
    }]
}
IAT_SET = {
    "protos": [{
        "name": "__gmpz_set",
        "arity": 2,
        "slots": [["rcx", "mpz_ptr"], ["rdx", "mpz_srcptr"]],
    }]
}
DAT = {
    "blobs": [{
        "va": "0x140001000",
        "kind": "format",
        "n": 4,
        "text": "n=%d",
    }]
}
FMT = (
    "void wrap(void) {\n"
    "  unsigned char *pcVar1;\n"
    "  pcVar1 = &DAT_140001000;\n"
    "  printf(pcVar1);\n"
    "}\n"
)


class TestFeedback(unittest.TestCase):
    def test_match_errors_still_skip_without_facts(self):
        decision = match_errors([{"message": CMP_MSG}], cases=[])
        self.assertFalse(decision.need_llm)
        self.assertIn("ghidra truncated mpz call", decision.skip_forever_reasons)
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_truncated_unique_imm_promotes(self):
        one = plan_one(
            "ghidra truncated mpz call",
            CMP_MSG,
            CMP,
            call_sites=SITES_CMP,
            iat_facts=IAT_CMP,
        )
        self.assertEqual(one["action"], ACTION_LEFTOVER)
        self.assertEqual(one["kind"], "call_arity")
        self.assertTrue(one["filled"])
        self.assertFalse(one["need_llm"])
        self.assertIn("__gmpz_cmp_ui(param_1, 1)", one["code"])
        self.assertNotIn("mpz_srcptr", one["code"])

    def test_empty_bag_stays_skip(self):
        one = plan_one("ghidra truncated mpz call", CMP_MSG, CMP)
        self.assertEqual(one["action"], ACTION_SKIP)
        self.assertFalse(one["filled"])
        plan = plan_errors([{"message": CMP_MSG}], CMP)
        self.assertEqual(plan["n_leftover"], 0)
        self.assertEqual(plan["n_skip"], 1)
        self.assertFalse(plan["need_llm"])
        self.assertFalse(plan["changed"])

    def test_set_without_imm_stays_skip(self):
        one = plan_one(
            "ghidra truncated mpz call",
            SET_MSG,
            SET,
            call_sites=SITES_SET,
            iat_facts=IAT_SET,
        )
        self.assertEqual(one["action"], ACTION_SKIP)
        self.assertNotIn("__gmpz_set(zs,", one.get("code") or SET)

    def test_set_does_not_ride_sibling_cmp_ui_imm(self):
        both = (
            "void wrap(void) {\n"
            "  __gmpz_cmp_ui(param_1);\n"
            "  __gmpz_set(zs);\n"
            "}\n"
        )
        sites = {"sites": SITES_CMP["sites"] + SITES_SET["sites"]}
        iat = {"protos": IAT_CMP["protos"] + IAT_SET["protos"]}
        hit = plan_one(
            "ghidra truncated mpz call",
            CMP_MSG,
            both,
            call_sites=sites,
            iat_facts=iat,
        )
        miss = plan_one(
            "ghidra truncated mpz call",
            SET_MSG,
            both,
            call_sites=sites,
            iat_facts=iat,
        )
        self.assertEqual(hit["action"], ACTION_LEFTOVER)
        self.assertIn("__gmpz_cmp_ui(param_1, 1)", hit["code"])
        self.assertIn("__gmpz_set(zs);", hit["code"])
        self.assertEqual(miss["action"], ACTION_SKIP)
        self.assertNotIn("__gmpz_set(zs,", miss.get("code") or both)

    def test_word_vs_mpz_ptr_does_not_invent_cast(self):
        one = plan_one(
            "ghidra word vs mpz_ptr",
            PTR_MSG,
            "void wrap(void) { __gmpz_init(param_1); }\n",
            iat_facts={"protos": [{"name": "__gmpz_init", "arity": 1,
                                   "slots": [["rcx", "mpz_ptr"]]}]},
        )
        self.assertEqual(one["action"], ACTION_SKIP)
        dumped = json.dumps(SITES_CMP)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)

    def test_format_dat_promotes_without_literal(self):
        one = plan_one(
            "unsigned char* vs char*",
            UCHAR_MSG,
            FMT,
            dat_facts=DAT,
        )
        self.assertEqual(one["action"], ACTION_LEFTOVER)
        self.assertEqual(one["kind"], "format_dat")
        self.assertFalse(one["filled"])
        self.assertNotIn("n=%d", one.get("code") or FMT)


if __name__ == "__main__":
    unittest.main()
