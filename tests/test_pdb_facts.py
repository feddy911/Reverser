from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.analysis.eval_pdb_facts import (
    _mini_msf_pdb,
    _pe_with_rsds,
    _s_pub32,
    run_dry,
)
from src.analysis.pdb_facts import (
    SOURCE_EMPTY,
    SOURCE_PDB_PUB,
    SOURCE_PE_RSDS,
    names_from_pdb_bytes,
    parse_rsds_blob,
    rsds_from_exe,
    rsds_from_pe_bytes,
    sibling_pdb_path,
)
from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER


class TestPdbFacts(unittest.TestCase):
    def test_rsds_blob_takes_pdb_leaf_not_cpp(self):
        guid = bytes(range(16))
        ok = parse_rsds_blob(
            b"RSDS" + guid + struct.pack("<I", 3) + b"C:\\src\\wrap.pdb\x00"
        )
        self.assertEqual(ok.source, SOURCE_PE_RSDS)
        self.assertEqual(ok.pdb_name, "wrap.pdb")
        self.assertEqual(ok.age, 3)
        self.assertEqual(ok.guid, guid.hex())
        self.assertFalse(ok.has_names)
        cpp = parse_rsds_blob(
            b"RSDS" + guid + struct.pack("<I", 1) + b"C:\\src\\wrap.cpp\x00"
        )
        self.assertEqual(cpp.source, SOURCE_EMPTY)
        self.assertFalse(cpp.has_rsds)
        self.assertEqual(parse_rsds_blob(b"").source, SOURCE_EMPTY)

    def test_pe_rsds_and_sibling_not_cpp(self):
        pe = _pe_with_rsds(r"C:\build\wrap.pdb")
        facts = rsds_from_pe_bytes(pe)
        self.assertTrue(facts.has_rsds)
        self.assertEqual(facts.pdb_name, "wrap.pdb")
        self.assertFalse(facts.pdb_present)
        self.assertFalse(facts.has_names)
        dumped = json.dumps(facts.to_dict())
        self.assertNotIn("****", dumped)
        self.assertNotIn("ghidra_code", dumped)
        self.assertNotIn("wrap.cpp", dumped)
        self.assertNotIn("MyCollatz", dumped)
        self.assertNotIn("NestWalk", dumped)
        with tempfile.TemporaryDirectory() as td:
            exe = Path(td) / "wrap.exe"
            exe.write_bytes(pe)
            missing = rsds_from_exe(exe)
            self.assertTrue(missing.has_rsds)
            self.assertFalse(missing.pdb_present)
            sib = sibling_pdb_path(exe, "wrap.pdb")
            self.assertEqual(sib, Path(td) / "wrap.pdb")
            sib.write_bytes(b"not-a-parsed-pdb")
            present = rsds_from_exe(exe)
            self.assertTrue(present.pdb_present)
            self.assertFalse(present.has_names)
            self.assertIsNone(sibling_pdb_path(exe, "wrap.cpp"))
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_empty_pe_is_not_pass(self):
        facts = rsds_from_pe_bytes(b"MZ")
        self.assertFalse(facts.has_rsds)
        self.assertFalse(facts.has_names)
        self.assertEqual(facts.source, SOURCE_EMPTY)

    def test_sibling_pdb_pubs_are_names_not_invented_main(self):
        pe = _pe_with_rsds(r"C:\build\wrap.pdb")
        pdb = _mini_msf_pdb(_s_pub32("wrap", off=0, seg=1) + _s_pub32("bad.cpp", 8, 1))
        names = names_from_pdb_bytes(
            pdb, image_base=0x140000000, section_rvas=(0x1000,)
        )
        by_name = {n: a for a, n in names}
        self.assertEqual(by_name.get("wrap"), "0x140001000")
        self.assertNotIn("bad.cpp", by_name)
        self.assertNotIn("main", by_name)
        with tempfile.TemporaryDirectory() as td:
            exe = Path(td) / "wrap.exe"
            exe.write_bytes(pe)
            (Path(td) / "wrap.pdb").write_bytes(pdb)
            facts = rsds_from_exe(exe)
            self.assertTrue(facts.pdb_present)
            self.assertTrue(facts.has_names)
            self.assertEqual(facts.source, SOURCE_PDB_PUB)
            self.assertEqual(dict(facts.names_by_addr).get("0x140001000"), "wrap")
            dumped = json.dumps(facts.to_dict())
            self.assertNotIn("main", dumped)
            self.assertNotIn("wrap.cpp", dumped)
            self.assertNotIn("MyCollatz", dumped)
            self.assertNotIn("NestWalk", dumped)
        self.assertEqual(LLM_PROMPT_VER, "p4")
        self.assertEqual(GHIDRA_CACHE_KEY, "ghidra_full_v6")

    def test_eval_dry_run_holds_p4_v6_and_does_not_invent_main(self):
        rec = run_dry()
        self.assertTrue(rec["ok"])
        self.assertTrue(rec["dry_run"])
        self.assertTrue(rec["empty_bag_is_not_pass"])
        self.assertFalse(rec["invented_main"])
        self.assertFalse(rec["leaked_cpp"])
        self.assertEqual(rec["live_prompt_ver"], "p4")
        self.assertEqual(rec["ghidra_cache_key"], "ghidra_full_v6")


if __name__ == "__main__":
    unittest.main()
