from __future__ import annotations

import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.call_sites import call_sites_from_bytes
from src.analysis.eval_iat_proto import _pe_with_imports, run_dry
from src.analysis.iat_proto import (
    SOURCE_EMPTY,
    SOURCE_PE_IAT,
    SOURCE_PE_IAT_PROTO,
    iat_facts_from_pe_bytes,
    proto_for_name,
)
from src.analysis.pe_image import pe_iat_name_by_va
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


class TestIatProto(unittest.TestCase):
    def test_empty_bag_is_not_pass(self):
        facts = iat_facts_from_pe_bytes(b"")
        self.assertFalse(facts.has_entries)
        self.assertFalse(facts.has_protos)
        self.assertEqual(facts.source, SOURCE_EMPTY)
        self.assertIsNone(proto_for_name("main"))
        self.assertIsNone(proto_for_name(""))

    def test_platform_dict_not_sample(self):
        clear = proto_for_name("__gmpz_clear")
        self.assertIsNotNone(clear)
        self.assertEqual(clear.arity, 1)
        self.assertEqual(clear.slots, (("rcx", "mpz_ptr"),))
        alias = proto_for_name("mpz_clear")
        self.assertIsNotNone(alias)
        self.assertEqual(alias.slots, clear.slots)
        printf = proto_for_name("printf")
        self.assertTrue(printf.variadic)
        self.assertEqual(printf.arity, 1)
        self.assertEqual(printf.slots[0], ("rcx", "char*"))
        self.assertIsNone(proto_for_name("Sleep"))
        self.assertIsNone(proto_for_name("wrap"))
        dumped = json.dumps(clear.to_dict())
        self.assertNotIn("ghidra_code", dumped)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)
        self.assertNotIn("gmp.h", dumped)

    def test_proto_binds_only_if_in_this_pe_iat(self):
        pe, vas = _pe_with_imports("libgmp-10.dll", ("__gmpz_clear", "printf"))
        facts = iat_facts_from_pe_bytes(pe)
        self.assertTrue(facts.has_entries)
        self.assertTrue(facts.has_protos)
        self.assertEqual(facts.source, SOURCE_PE_IAT_PROTO)
        self.assertEqual({e["name"] for e in facts.entries}, {"__gmpz_clear", "printf"})
        self.assertEqual({p.name for p in facts.protos}, {"__gmpz_clear", "printf"})
        self.assertEqual(tuple(e["va"] for e in facts.entries), vas)
        sleep_pe, _ = _pe_with_imports("kernel32.dll", ("Sleep",))
        sleep = iat_facts_from_pe_bytes(sleep_pe)
        self.assertTrue(sleep.has_entries)
        self.assertFalse(sleep.has_protos)
        self.assertEqual(sleep.source, SOURCE_PE_IAT)
        self.assertEqual(sleep.entries[0]["name"], "Sleep")
        self.assertFalse(any("mpz" in p.name for p in sleep.protos))

    def test_rip_mem_call_names_from_iat_map_only(self):
        pe, vas = _pe_with_imports("ucrtbase.dll", ("printf",))
        iat_map = pe_iat_name_by_va(pe)
        func_va = 0x140001000
        disp = vas[0] - (func_va + 6)
        blob = b"\xff\x15" + struct.pack("<i", disp) + b"\xc3"
        named = call_sites_from_bytes(
            blob, addr=f"0x{func_va:x}", func_va=func_va, iat_by_va=iat_map
        )
        self.assertEqual(len(named.sites), 1)
        self.assertEqual(named.sites[0].kind, "rip_mem")
        self.assertEqual(named.sites[0].iat_name, "printf")
        self.assertEqual(named.sites[0].callee_va, f"0x{vas[0]:x}")
        bare = call_sites_from_bytes(
            blob, addr=f"0x{func_va:x}", func_va=func_va
        )
        self.assertEqual(bare.sites[0].iat_name, "")
        dumped = json.dumps(named.to_dict())
        self.assertNotIn("mpz_ptr", dumped)
        self.assertNotIn("ghidra_code", dumped)

    def test_dry_run_holds_p4_v6(self):
        rec = run_dry()
        self.assertTrue(rec["ok"])
        self.assertTrue(rec["dry_run"])
        self.assertEqual(rec["live_prompt_ver"], "p4")
        self.assertEqual(rec["ghidra_cache_key"], "ghidra_full_v6")
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")
        self.assertFalse(rec["invented_main"])
        self.assertEqual(rec["named_iat"], "__gmpz_clear")
        self.assertEqual(rec["unnamed_without_map"], "")


if __name__ == "__main__":
    unittest.main()
