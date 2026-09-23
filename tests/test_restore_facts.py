from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents.critic import p8_restore_contract
from src.agents.restorer import build_restore_prompt
from src.analysis.restore_facts import (
    FACTS_SECTION_TITLE,
    format_restore_facts,
    leftover_unfilled,
)
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

CMP = (
    "void wrap(void) {\n"
    "  __gmpz_cmp_ui(param_1);\n"
    "}\n"
)
SET = (
    "void wrap(void) {\n"
    "  __gmpz_set(zs);\n"
    "}\n"
)
BOTH = (
    "void wrap(void) {\n"
    "  __gmpz_cmp_ui(param_1);\n"
    "  __gmpz_set(zs);\n"
    "}\n"
)
HELPER = (
    "void helper(longlong *xs);\n"
    "void wrap(void) { longlong *xs; helper(xs); }\n"
)
SITES_CMP = {
    "sites": [{
        "iat_name": "__gmpz_cmp_ui",
        "arg_regs": ["rcx", "rdx"],
        "imm_slots": [["rdx", 1]],
    }]
}
SITES_SET = {
    "sites": [{
        "iat_name": "__gmpz_set",
        "arg_regs": ["rcx", "rdx"],
        "imm_slots": [],
    }]
}
SITES_HELPER = {
    "sites": [{
        "iat_name": "",
        "arg_regs": ["rcx", "rdx"],
        "imm_slots": [["rdx", 2]],
    }]
}
IAT = {
    "protos": [
        {
            "name": "__gmpz_cmp_ui",
            "arity": 2,
            "slots": [["rcx", "mpz_srcptr"], ["rdx", "unsigned long"]],
        },
        {
            "name": "__gmpz_set",
            "arity": 2,
            "slots": [["rcx", "mpz_ptr"], ["rdx", "mpz_srcptr"]],
        },
    ]
}
WRAP = {
    "address": "0x140001000",
    "name": "wrap",
    "ghidra_name": "FUN_wrap",
    "size": 16,
}


class TestRestoreFacts(unittest.TestCase):
    def test_empty_bag_omits_section(self):
        self.assertEqual(format_restore_facts(SET), "")
        live = build_restore_prompt(WRAP, SET)
        self.assertNotIn(FACTS_SECTION_TITLE, live)
        self.assertTrue(p8_restore_contract(live))
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_unique_imm_is_sanitizer_not_prompt(self):
        self.assertEqual(leftover_unfilled(CMP, SITES_CMP, IAT), [])
        self.assertEqual(format_restore_facts(CMP, SITES_CMP, IAT), "")
        self.assertEqual(format_restore_facts(HELPER, SITES_HELPER, None), "")

    def test_set_without_imm_is_gated_facts(self):
        names = leftover_unfilled(SET, SITES_SET, IAT)
        self.assertEqual(names, ["__gmpz_set"])
        block = format_restore_facts(SET, SITES_SET, IAT)
        self.assertIn(FACTS_SECTION_TITLE, block)
        self.assertIn("CALL __gmpz_set", block)
        self.assertIn("iat_arity=2", block)
        self.assertIn("no unique imm", block)
        self.assertNotIn("mpz_ptr", block)
        self.assertNotIn("mpz_srcptr", block)
        self.assertNotIn("MyCollatz", block)
        self.assertNotIn("NestWalk", block)

    def test_sibling_cmp_ui_imm_does_not_drop_set(self):
        sites = {"sites": SITES_CMP["sites"] + SITES_SET["sites"]}
        names = leftover_unfilled(BOTH, sites, IAT)
        self.assertEqual(names, ["__gmpz_set"])
        block = format_restore_facts(BOTH, sites, IAT)
        self.assertIn("CALL __gmpz_set", block)
        self.assertNotIn("CALL __gmpz_cmp_ui", block)

    def test_prompt_kwargs_insert_before_rules(self):
        live = build_restore_prompt(WRAP, SET)
        gated = build_restore_prompt(
            WRAP, SET, call_sites=SITES_SET, iat_facts=IAT
        )
        self.assertNotIn(FACTS_SECTION_TITLE, live)
        self.assertIn(FACTS_SECTION_TITLE, gated)
        self.assertLess(
            gated.find(FACTS_SECTION_TITLE),
            gated.find("=== СТРОГИЕ ПРАВИЛА ==="),
        )
        self.assertTrue(p8_restore_contract(gated))
        self.assertNotIn("mpz_ptr", gated)
        poisoned = dict(WRAP)
        poisoned["call_sites"] = SITES_SET
        poisoned["iat_facts"] = IAT
        still = build_restore_prompt(poisoned, SET)
        self.assertNotIn(FACTS_SECTION_TITLE, still)

    def test_live_restore_omits_even_if_entry_has_bags(self):
        from src.agents.restorer import CodeRestorerLLM

        class _Client:
            def __init__(self):
                self.prompt = ""

            def generate(self, prompt, system="", json_mode=False):
                self.prompt = prompt
                return (
                    '{"classification":"user_code",'
                    '"cpp_code":"int f(){return 0;}"}'
                )

        entry = dict(WRAP)
        entry["call_sites"] = SITES_SET
        entry["iat_facts"] = IAT
        client = _Client()
        CodeRestorerLLM(client).restore(entry, SET)
        self.assertNotIn(FACTS_SECTION_TITLE, client.prompt)
        client2 = _Client()
        CodeRestorerLLM(client2).restore(
            entry, SET, call_sites=SITES_SET, iat_facts=IAT
        )
        self.assertIn(FACTS_SECTION_TITLE, client2.prompt)
        dumped = json.dumps(SITES_SET)
        self.assertNotIn("MyCollatz", dumped)


if __name__ == "__main__":
    unittest.main()
