from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.call_sites import (
    SOURCE_BYTES,
    call_sites_from_bytes,
    call_sites_from_capstone,
    capstone_available,
    scan_and_capstone,
)
from src.analysis.eval_call_sites import WRAP_CALLEE, WRAP_IMM, WRAP_LEA, WRAP_VA, run_dry
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


class TestCallSites(unittest.TestCase):
    def test_empty_bag_is_not_pass(self):
        facts = call_sites_from_bytes(b"", addr="0x1")
        self.assertFalse(facts.has_byte_facts)
        self.assertEqual(facts.sites, ())
        self.assertEqual(facts.source, SOURCE_BYTES)

    def test_imm_call_is_not_c(self):
        facts = call_sites_from_bytes(
            WRAP_IMM, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertTrue(facts.has_byte_facts)
        self.assertEqual(len(facts.sites), 1)
        site = facts.sites[0]
        self.assertEqual(site.kind, "rel")
        self.assertEqual(site.callee_va, f"0x{WRAP_CALLEE:x}")
        self.assertEqual(site.iat_name, "")
        self.assertEqual(site.arg_regs, ("rcx", "rdx"))
        self.assertEqual(site.imm_slots, (("rcx", 1), ("rdx", 2)))
        dumped = json.dumps(facts.to_dict())
        self.assertNotIn("****", dumped)
        self.assertNotIn("ghidra_code", dumped)
        self.assertNotIn("mpz_ptr", dumped)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)
        self.assertNotIn("wrap", dumped)

    def test_lea_rcx_xor_edx_call(self):
        facts = call_sites_from_bytes(
            WRAP_LEA, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        site = facts.sites[0]
        self.assertEqual(site.callee_va, f"0x{WRAP_CALLEE:x}")
        self.assertEqual(site.arg_regs, ("rcx", "rdx"))
        self.assertEqual(site.lea_slots, (("rcx", -0x20),))
        self.assertEqual(site.imm_slots, (("rdx", 0),))

    def test_optional_capstone_agrees(self):
        rec = scan_and_capstone(
            WRAP_IMM, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertFalse(rec["c_leaked_into_facts"])
        cap = call_sites_from_capstone(
            WRAP_IMM, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        if not capstone_available():
            self.assertIsNone(cap)
            return
        self.assertIsNotNone(cap)
        self.assertTrue(rec["compare"]["agree"])
        lea = scan_and_capstone(
            WRAP_LEA, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertTrue(lea["compare"]["agree"])

    def test_embedded_e8_in_sub_imm_is_not_call(self):
        # sub rsp, 0xe8; mov ecx, 1; call wrap_callee; ret
        prefix = bytes.fromhex("4881ece8000000b901000000")
        from src.analysis.eval_call_sites import _rel_call

        blob = _rel_call(prefix, WRAP_VA, WRAP_CALLEE)
        facts = call_sites_from_bytes(
            blob, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertEqual(len(facts.sites), 1)
        self.assertEqual(facts.sites[0].off, len(prefix))
        self.assertEqual(facts.sites[0].callee_va, f"0x{WRAP_CALLEE:x}")
        self.assertEqual(facts.sites[0].arg_regs, ("rcx",))
        self.assertEqual(facts.sites[0].imm_slots, (("rcx", 1),))

    def test_arg_writes_reset_after_call(self):
        from src.analysis.eval_call_sites import _rel_call

        first = _rel_call(bytes.fromhex("b901000000"), WRAP_VA, WRAP_CALLEE)
        # drop trailing ret; second mov edx,2; call; ret
        body = first[:-1] + bytes.fromhex("ba02000000")
        blob = _rel_call(body, WRAP_VA, WRAP_CALLEE)
        facts = call_sites_from_bytes(
            blob, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertEqual(len(facts.sites), 2)
        self.assertEqual(facts.sites[0].arg_regs, ("rcx",))
        self.assertEqual(facts.sites[0].imm_slots, (("rcx", 1),))
        self.assertEqual(facts.sites[1].arg_regs, ("rdx",))
        self.assertEqual(facts.sites[1].imm_slots, (("rdx", 2),))

    def test_rip_relative_lea_rcx(self):
        # lea rcx, [rip+0]; call wrap_callee; ret
        prefix = bytes.fromhex("488d0d00000000")
        from src.analysis.eval_call_sites import _rel_call

        blob = _rel_call(prefix, WRAP_VA, WRAP_CALLEE)
        facts = call_sites_from_bytes(
            blob, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertEqual(facts.sites[0].arg_regs, ("rcx",))
        self.assertEqual(facts.sites[0].lea_slots, (("rcx", 0),))
        if capstone_available():
            rec = scan_and_capstone(blob, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA)
            self.assertTrue(rec["compare"]["agree"])

    def test_c7_mod3_r9_imm(self):
        # mov r9, -1; call wrap_callee; ret
        prefix = bytes.fromhex("49c7c1ffffffff")
        from src.analysis.eval_call_sites import _rel_call

        blob = _rel_call(prefix, WRAP_VA, WRAP_CALLEE)
        facts = call_sites_from_bytes(
            blob, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA
        )
        self.assertEqual(facts.sites[0].arg_regs, ("r9",))
        self.assertEqual(facts.sites[0].imm_slots, (("r9", 0xFFFFFFFF),))
        if capstone_available():
            rec = scan_and_capstone(blob, addr=f"0x{WRAP_VA:x}", func_va=WRAP_VA)
            self.assertTrue(rec["compare"]["agree"])

    def test_dry_run_holds_p4_v6(self):
        rec = run_dry()
        self.assertTrue(rec["ok"])
        self.assertTrue(rec["dry_run"])
        self.assertEqual(rec["live_prompt_ver"], "p4")
        self.assertEqual(rec["ghidra_cache_key"], "ghidra_full_v6")
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

if __name__ == "__main__":
    unittest.main()
