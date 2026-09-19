from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.disasm_facts import (
    SOURCE_CAPSTONE,
    capstone_available,
    facts_vs_c,
    fn_facts_from_capstone,
    scan_and_capstone,
)
from src.analysis.eval_disasm_facts import WRAP_BYTES, run_dry
from src.analysis.fn_facts import SOURCE_BYTES, fn_facts_from_dump_entry
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


class TestDisasmFacts(unittest.TestCase):
    def test_wrap_scan_and_optional_capstone_agree(self):
        entry = {
            "address": "0x140001000",
            "size": len(WRAP_BYTES),
            "callees": ["0x140002000"],
            "ghidra_code": "longlong ****xs[8];\n",
        }
        scan = fn_facts_from_dump_entry(entry, func_bytes=WRAP_BYTES)
        self.assertEqual(scan.source, SOURCE_BYTES)
        self.assertEqual(scan.stack_alloc, 0x40)
        self.assertEqual(scan.lea_arg_slots, (-0x20,))
        cap = fn_facts_from_capstone(
            WRAP_BYTES,
            addr=scan.addr,
            size=scan.size,
            callees=scan.callees,
        )
        if not capstone_available():
            self.assertIsNone(cap)
            return
        self.assertIsNotNone(cap)
        self.assertEqual(cap.source, SOURCE_CAPSTONE)
        self.assertEqual(cap.stack_alloc, scan.stack_alloc)
        self.assertEqual(cap.lea_arg_slots, scan.lea_arg_slots)
        self.assertEqual(cap.qword_store_slots, scan.qword_store_slots)
        dumped = json.dumps(cap.to_dict())
        self.assertNotIn("****", dumped)
        self.assertNotIn("ghidra_code", dumped)

    def test_empty_blob_is_not_capstone_pass(self):
        self.assertIsNone(fn_facts_from_capstone(b""))

    def test_dump_crlf_extra_star_hint(self):
        code = "  longlong ****local_740 [8];\r\n"
        wrap = fn_facts_from_dump_entry(
            {"address": "0x1", "size": len(WRAP_BYTES)},
            func_bytes=WRAP_BYTES,
        )
        self.assertIn("extra_star_vs_outparam", facts_vs_c(wrap, code))
        code = "longlong ****xs[8];\n"
        empty = fn_facts_from_dump_entry({"address": "0x1", "size": 1})
        self.assertEqual(facts_vs_c(empty, code), [])
        wrap = fn_facts_from_dump_entry(
            {"address": "0x1", "size": len(WRAP_BYTES)},
            func_bytes=WRAP_BYTES,
        )
        self.assertIn("extra_star_vs_outparam", facts_vs_c(wrap, code))

    def test_gs_slot_hint_on_unused_undefined1_32(self):
        code = "undefined1 local_7f8[32];\n"
        wrap = fn_facts_from_dump_entry(
            {"address": "0x1", "size": len(WRAP_BYTES)},
            func_bytes=WRAP_BYTES,
        )
        self.assertIn("gs_slot_vs_frame", facts_vs_c(wrap, code))

    def test_scan_record_does_not_leak_c(self):
        rec = scan_and_capstone(
            {
                "address": "0x140001000",
                "size": len(WRAP_BYTES),
                "callees": [],
                "ghidra_code": "longlong ****xs[8]; wrap();\n",
                "cpp_code": "int wrap() { return 0; }\n",
            },
            func_bytes=WRAP_BYTES,
        )
        self.assertFalse(rec["c_leaked_into_facts"])
        self.assertNotIn("wrap", json.dumps(rec["scan"]))
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_dry_run_holds_p4_v6(self):
        rec = run_dry()
        self.assertTrue(rec["ok"])
        self.assertEqual(rec["live_prompt_ver"], "p4")
        self.assertEqual(rec["ghidra_cache_key"], "ghidra_full_v6")
        self.assertTrue(rec["dry_run"])


if __name__ == "__main__":
    unittest.main()
