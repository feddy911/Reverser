from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.ghidra_cpp import leftover_call_arity
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


HELPER = (
    "void helper(longlong *xs);\n"
    "void wrap(void)\n"
    "{\n"
    "  longlong *xs;\n"
    "  helper(xs);\n"
    "}\n"
)
HELPER_OK = (
    "void helper(longlong *xs, int n);\n"
    "void wrap(void)\n"
    "{\n"
    "  longlong *xs;\n"
    "  helper(xs, 2);\n"
    "}\n"
)
GMP = "void wrap(void) { __gmpz_cmp_ui(param_1); }\n"
SITES = {
    "sites": [
        {
            "off": 12,
            "kind": "rel",
            "callee_va": "0x140002000",
            "iat_name": "",
            "arg_regs": ["rcx", "rdx"],
            "imm_slots": [["rdx", 2]],
        }
    ]
}
IAT = {
    "protos": [
        {
            "name": "__gmpz_cmp_ui",
            "arity": 2,
            "variadic": False,
            "slots": [["rcx", "mpz_srcptr"], ["rdx", "unsigned long"]],
        }
    ]
}


class TestCallArity(unittest.TestCase):
    def test_empty_bag_is_not_class(self):
        self.assertEqual(leftover_call_arity(HELPER, None, None), [])
        self.assertEqual(leftover_call_arity(HELPER, {}, {}), [])
        self.assertEqual(leftover_call_arity(HELPER, {"sites": []}, {"protos": []}), [])
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_helper_xs_vs_two_arg_regs(self):
        self.assertEqual(leftover_call_arity(HELPER, SITES, None), ["helper"])
        self.assertEqual(leftover_call_arity(HELPER_OK, SITES, None), [])
        dumped = json.dumps(SITES)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)

    def test_iat_proto_truncated_gmp(self):
        self.assertEqual(leftover_call_arity(GMP, None, IAT), ["__gmpz_cmp_ui"])
        alias = "void wrap(void) { mpz_cmp_ui(param_1); }\n"
        self.assertEqual(leftover_call_arity(alias, None, IAT), ["mpz_cmp_ui"])
        full = "void wrap(void) { __gmpz_cmp_ui(z, 1); }\n"
        self.assertEqual(leftover_call_arity(full, None, IAT), [])
        sleep_only = {"protos": []}
        self.assertEqual(leftover_call_arity(GMP, None, sleep_only), [])

    def test_does_not_invent_immediate(self):
        hits = leftover_call_arity(HELPER, SITES, None)
        self.assertEqual(hits, ["helper"])
        self.assertNotIn("2", hits)

    def test_critic_identity_and_dialect_tag(self):
        from src.agents.critic import dialect_hits, director_contract, review_function

        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": ["helper"],
            "ghidra_code": HELPER,
            "call_sites": SITES,
        }
        verdict = review_function(entry, HELPER, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover call_arity helper" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.kind == "call_arity" and h.token == "helper"
                for h in dialect_hits(HELPER, call_sites=SITES)
            )
        )
        self.assertFalse(
            any(h.kind == "call_arity" for h in dialect_hits(HELPER))
        )
        self.assertTrue(director_contract(verdict))


if __name__ == "__main__":
    unittest.main()
