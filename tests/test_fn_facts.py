from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.fn_facts import (
    SOURCE_BYTES,
    SOURCE_DUMP,
    fn_facts_from_dump_entry,
    fn_facts_from_entries,
)
from src.analysis.pe_image import (
    rbp_lea_arg_slots,
    rbp_qword_store_slots,
    sub_rsp_imms,
)
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


class TestFnFacts(unittest.TestCase):
    def test_wrap_bytes_are_not_c(self):
        # sub rsp, 0x40; lea rcx, [rbp-0x20]; mov [rbp-0x20], rax; ret
        blob = bytes.fromhex("4883ec40 488d4de0 488945e0 c3".replace(" ", ""))
        self.assertEqual(sub_rsp_imms(blob), [0x40])
        self.assertEqual(rbp_lea_arg_slots(blob), [-0x20])
        self.assertEqual(rbp_qword_store_slots(blob), [-0x20])
        entry = {
            "address": "0x140001000",
            "size": len(blob),
            "callees": ["0x140002000"],
            "name": "wrap",
            "ghidra_code": "longlong ****xs[8];\nxs[0] = 1;\n",
            "cpp_code": "int wrap() { return 0; }\n",
        }
        facts = fn_facts_from_dump_entry(entry, func_bytes=blob)
        self.assertEqual(facts.addr, "0x140001000")
        self.assertEqual(facts.size, len(blob))
        self.assertEqual(facts.callees, ("0x140002000",))
        self.assertEqual(facts.stack_alloc, 0x40)
        self.assertEqual(facts.lea_arg_slots, (-0x20,))
        self.assertEqual(facts.qword_store_slots, (-0x20,))
        self.assertEqual(facts.source, SOURCE_BYTES)
        self.assertTrue(facts.has_byte_facts)
        dumped = json.dumps(facts.to_dict())
        self.assertNotIn("****", dumped)
        self.assertNotIn("wrap", dumped)
        self.assertNotIn("ghidra_code", dumped)
        self.assertNotIn("cpp_code", dumped)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)

    def test_empty_byte_bag_is_not_pass(self):
        facts = fn_facts_from_dump_entry(
            {"address": "0x1", "size": 8, "callees": []},
            func_bytes=b"",
        )
        self.assertEqual(facts.source, SOURCE_DUMP)
        self.assertFalse(facts.has_byte_facts)
        self.assertEqual(facts.stack_alloc, 0)
        self.assertEqual(facts.lea_arg_slots, ())

    def test_entries_map_and_versions_hold(self):
        blob = bytes.fromhex("c3")
        found = fn_facts_from_entries(
            [{"address": "0x10", "size": 1, "callees": []}],
            bytes_by_addr={"0x10": blob},
        )
        self.assertEqual(set(found), {"0x10"})
        self.assertEqual(found["0x10"].size, 1)
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_attach_fn_facts_opt_in_default_off(self):
        from src.analysis.fn_facts import attach_fn_facts
        from src.config import AppConfig, load_config

        blob = bytes.fromhex("4883ec40488d4de0488945e0c3")
        entry = {
            "address": "0x140001000",
            "size": len(blob),
            "callees": ["0x2"],
            "ghidra_code": "longlong ****xs[8];\n",
        }
        dest: dict = {}
        attach_fn_facts(dest, entry, func_bytes=blob, enabled=False)
        self.assertNotIn("fn_facts", dest)
        attach_fn_facts(dest, entry, func_bytes=blob, enabled=True)
        facts = dest["fn_facts"]
        self.assertEqual(facts["stack_alloc"], 0x40)
        self.assertEqual(facts["lea_arg_slots"], [-0x20])
        dumped = json.dumps(facts)
        self.assertNotIn("****", dumped)
        self.assertNotIn("ghidra_code", dumped)
        self.assertNotIn("xs", dumped)
        self.assertFalse(AppConfig().use_disasm_facts)
        self.assertFalse(load_config(ROOT / "config.yaml").use_disasm_facts)

    def test_lea_rax_is_not_an_arg_slot(self):
        # lea rax, [rbp-0x10]
        blob = bytes.fromhex("488d45f0")
        self.assertEqual(rbp_lea_arg_slots(blob), [])


if __name__ == "__main__":
    unittest.main()
