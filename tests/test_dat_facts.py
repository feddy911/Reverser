from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.dat_facts import (
    SOURCE_EMPTY,
    SOURCE_PE_BYTES,
    ascii_cstring,
    dat_facts_from_blob,
    dat_vas_from_dump,
    format_va_set,
)
from src.analysis.eval_dat_facts import WRAP_FMT, WRAP_VA, _pe_with_cstring, run_dry
from src.analysis.ghidra_cpp import leftover_format_from_pe
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


WRAP_C = (
    "void wrap(void)\n"
    "{\n"
    "  unsigned char *pcVar1;\n"
    "  pcVar1 = &DAT_140001000;\n"
    "  printf(pcVar1);\n"
    "}\n"
)


class TestDatFacts(unittest.TestCase):
    def test_empty_bag_is_not_pass(self):
        facts = dat_facts_from_blob(b"", (WRAP_VA,))
        self.assertFalse(facts.has_byte_facts)
        self.assertFalse(facts.has_format)
        self.assertEqual(facts.source, SOURCE_EMPTY)
        self.assertEqual(ascii_cstring(b""), None)
        self.assertEqual(leftover_format_from_pe(WRAP_C, None), [])
        self.assertEqual(leftover_format_from_pe(WRAP_C, {}), [])

    def test_ascii_percent_nul_is_format_not_cpp(self):
        pe, va = _pe_with_cstring(WRAP_FMT)
        facts = dat_facts_from_blob(pe, (va,))
        self.assertEqual(va, WRAP_VA)
        self.assertTrue(facts.has_format)
        self.assertEqual(facts.source, SOURCE_PE_BYTES)
        self.assertEqual(facts.blobs[0].text, WRAP_FMT)
        self.assertEqual(facts.blobs[0].kind, "format")
        dumped = json.dumps(facts.to_dict())
        self.assertNotIn("ghidra_code", dumped)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)
        self.assertNotIn(".cpp", dumped)
        hello_pe, hello_va = _pe_with_cstring("hello")
        hello = dat_facts_from_blob(hello_pe, (hello_va,))
        self.assertEqual(hello.blobs[0].kind, "c_string")
        self.assertFalse(hello.has_format)
        self.assertIsNone(ascii_cstring(b"\xff\x00"))

    def test_leftover_needs_format_blob_and_printf(self):
        pe, va = _pe_with_cstring(WRAP_FMT)
        facts = dat_facts_from_blob(pe, (va,))
        self.assertEqual(format_va_set(facts), {WRAP_VA})
        self.assertEqual(leftover_format_from_pe(WRAP_C, facts), ["DAT_140001000"])
        self.assertEqual(dat_vas_from_dump(WRAP_C), (WRAP_VA,))
        hello_pe, hello_va = _pe_with_cstring("hello")
        hello = dat_facts_from_blob(hello_pe, (hello_va,))
        self.assertEqual(leftover_format_from_pe(WRAP_C, hello), [])
        no_printf = "void wrap(void) { (void)&DAT_140001000; }\n"
        self.assertEqual(leftover_format_from_pe(no_printf, facts), [])

    def test_critic_identity_fails_when_format_blob_unique(self):
        from src.agents.critic import dialect_hits, director_contract, review_function

        pe, va = _pe_with_cstring(WRAP_FMT)
        facts = dat_facts_from_blob(pe, (va,))
        bag = facts.to_dict()
        entry = {
            "address": "0x1",
            "guessed_name": "wrap",
            "ghidra_name": "wrap",
            "name": "wrap",
            "literals": [],
            "ext_calls": ["printf"],
            "ghidra_code": WRAP_C,
            "dat_facts": bag,
        }
        verdict = review_function(entry, WRAP_C, [])
        self.assertFalse(verdict.identity_ok)
        self.assertTrue(
            any("restore leftover format_dat DAT_140001000" in r for r in verdict.reasons)
        )
        self.assertTrue(
            any(
                h.source == "ghidra" and h.kind == "format_dat" and h.token == "DAT_140001000"
                for h in dialect_hits(WRAP_C, dat_facts=bag)
            )
        )
        self.assertFalse(
            any(h.kind == "format_dat" for h in dialect_hits(WRAP_C))
        )
        self.assertTrue(director_contract(verdict))

    def test_dry_run_holds_p4_v6(self):
        rec = run_dry()
        self.assertTrue(rec["ok"])
        self.assertTrue(rec["dry_run"])
        self.assertEqual(rec["live_prompt_ver"], "p4")
        self.assertEqual(rec["ghidra_cache_key"], "ghidra_full_v6")
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")
        self.assertEqual(rec["leftover"], ["DAT_140001000"])
        self.assertEqual(rec["leftover_empty"], [])


if __name__ == "__main__":
    unittest.main()
