from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.call_sites import call_sites_from_bytes
from src.analysis.eval_call_sites import WRAP_CALLEE, WRAP_IMM, WRAP_LEA, WRAP_VA
from src.analysis.second_decode import (
    SOURCE_OBJDUMP,
    call_sites_from_objdump,
    objdump_available,
    scan_and_objdump,
)
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


class TestSecondDecode(unittest.TestCase):
    def test_empty_blob_is_not_pass(self):
        self.assertIsNone(call_sites_from_objdump(b""))
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_wrap_imm_agrees_with_pe_image(self):
        if not objdump_available():
            self.skipTest("objdump not on PATH")
        scan = call_sites_from_bytes(
            WRAP_IMM, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        other = call_sites_from_objdump(
            WRAP_IMM, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertIsNotNone(other)
        self.assertEqual(other.source, SOURCE_OBJDUMP)
        self.assertEqual(len(other.sites), 1)
        site = other.sites[0]
        self.assertEqual(site.kind, "rel")
        self.assertEqual(site.callee_va, f"0x{WRAP_CALLEE:x}")
        self.assertEqual(site.iat_name, "")
        self.assertEqual(site.arg_regs, scan.sites[0].arg_regs)
        self.assertEqual(site.imm_slots, scan.sites[0].imm_slots)
        rec = scan_and_objdump(
            WRAP_IMM,
            addr=f"0x{WRAP_VA:x}",
            func_va=WRAP_VA,
            dump_code="void wrap(void) { helper(xs); }\n",
        )
        self.assertTrue(rec["compare"]["agree"])
        self.assertTrue(rec["ignored_c"])
        self.assertFalse(rec["c_leaked_into_facts"])
        dumped = json.dumps(other.to_dict())
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)
        self.assertNotIn("pdc", dumped)

    def test_wrap_lea_agrees_with_pe_image(self):
        if not objdump_available():
            self.skipTest("objdump not on PATH")
        rec = scan_and_objdump(
            WRAP_LEA, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertTrue(rec["compare"]["agree"])
        lea = rec["objdump"]["sites"][0]["lea_slots"]
        self.assertEqual(lea, [["rcx", -32]])


if __name__ == "__main__":
    unittest.main()
