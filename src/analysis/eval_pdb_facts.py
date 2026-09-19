"""Gym-only RSDS/PDB publics vs this exe. Not live.

  py -m src.analysis.eval_pdb_facts --dry-run
  py -m src.analysis.eval_pdb_facts --run output/logs/run_<ts>

Reads binary_info.json from a run directory. Writes pdb_facts.json next to
the run. Does not call runner, does not bump p4/v6, does not rename FUN_,
does not emit corpus YAML, does not invent main.
"""

from __future__ import annotations

import argparse
import json
import struct
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "pdb_facts_report.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _pe_with_rsds(pdb_path: str) -> bytes:
    guid = bytes(range(16))
    cv = b"RSDS" + guid + struct.pack("<I", 7) + pdb_path.encode("ascii") + b"\x00"
    debug_ent = struct.pack(
        "<IIHHIIII",
        0,
        0,
        0,
        0,
        2,
        len(cv),
        0x101C,
        0x41C,
    )
    blob = bytearray(0x600)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<H", blob, coff, 0x8664)
    struct.pack_into("<H", blob, coff + 2, 1)
    struct.pack_into("<H", blob, coff + 16, 0xF0)
    opt = coff + 20
    struct.pack_into("<H", blob, opt, 0x20B)
    struct.pack_into("<Q", blob, opt + 24, 0x140000000)
    struct.pack_into("<I", blob, opt + 108, 16)
    struct.pack_into("<I", blob, opt + 112 + 6 * 8, 0x1000)
    struct.pack_into("<I", blob, opt + 112 + 6 * 8 + 4, 28)
    sec = opt + 0xF0
    blob[sec : sec + 6] = b".rdata"
    struct.pack_into("<I", blob, sec + 8, 0x200)
    struct.pack_into("<I", blob, sec + 12, 0x1000)
    struct.pack_into("<I", blob, sec + 16, 0x200)
    struct.pack_into("<I", blob, sec + 20, 0x400)
    blob[0x400:0x400 + 28] = debug_ent
    blob[0x41C:0x41C + len(cv)] = cv
    return bytes(blob)


def _s_pub32(name: str, off: int = 0, seg: int = 1) -> bytes:
    payload = struct.pack("<HIIH", 0x110E, 0, off, seg) + name.encode("ascii") + b"\x00"
    pad = (4 - ((2 + len(payload)) % 4)) % 4
    payload += b"\x00" * pad
    return struct.pack("<H", len(payload)) + payload


def _mini_msf_pdb(pub: bytes) -> bytes:
    bs = 512
    dbi = struct.pack("<iIIHHH", -1, 19990903, 1, 0, 0, 4) + bytes(46)
    nstreams = 5
    sizes = [0, 0, 0, 64, len(pub)]
    directory = struct.pack("<I", nstreams)
    directory += b"".join(struct.pack("<I", s) for s in sizes)
    directory += struct.pack("<II", 4, 5)
    nblocks = 6
    blob = bytearray(nblocks * bs)
    blob[0:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    struct.pack_into("<IIIIII", blob, 32, bs, 1, nblocks, len(directory), 0, 2)
    blob[bs : 2 * bs] = b"\xff" * bs
    struct.pack_into("<I", blob, 2 * bs, 3)
    blob[3 * bs : 3 * bs + len(directory)] = directory
    blob[4 * bs : 4 * bs + 64] = dbi[:64]
    blob[5 * bs : 5 * bs + len(pub)] = pub
    return bytes(blob)


def run_dry() -> Dict[str, Any]:
    from src.analysis.pdb_facts import SOURCE_PDB_PUB, rsds_from_exe, rsds_from_pe_bytes
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    empty = rsds_from_pe_bytes(b"MZ")
    pe = _pe_with_rsds(r"C:\build\wrap.pdb")
    pdb = _mini_msf_pdb(_s_pub32("wrap", off=0, seg=1) + _s_pub32("bad.cpp", 8, 1))
    with tempfile.TemporaryDirectory() as td:
        exe = Path(td) / "wrap.exe"
        exe.write_bytes(pe)
        (Path(td) / "wrap.pdb").write_bytes(pdb)
        facts = rsds_from_exe(exe)
        dumped = json.dumps(facts.to_dict())
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "empty_has_names": empty.has_names,
        "empty_bag_is_not_pass": not empty.has_names,
        "has_rsds": facts.has_rsds,
        "pdb_present": facts.pdb_present,
        "has_names": facts.has_names,
        "source": facts.source,
        "names_by_addr": [list(p) for p in facts.names_by_addr],
        "invented_main": "main" in dumped,
        "leaked_cpp": "wrap.cpp" in dumped or "bad.cpp" in dumped,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and not empty.has_names
            and facts.has_names
            and facts.source == SOURCE_PDB_PUB
            and dict(facts.names_by_addr).get("0x140001000") == "wrap"
            and "main" not in dumped
            and "wrap.cpp" not in dumped
            and "MyCollatz" not in dumped
            and "NestWalk" not in dumped
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "Do not invent main. Do not rename FUN_."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.pdb_facts import rsds_from_exe
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    run_dir = Path(run_dir)
    binary_info = _load_json(run_dir / "binary_info.json") or {}
    binary = str(binary_info.get("path") or "")
    bin_path = Path(binary)
    if binary and not bin_path.is_file():
        bin_path = ROOT / binary
    facts = rsds_from_exe(bin_path) if bin_path.is_file() else rsds_from_exe("")
    payload = facts.to_dict()
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "empty_bag_is_not_pass": not facts.has_names,
        "invented_main": any(n == "main" for _a, n in facts.names_by_addr),
        "ok": LLM_PROMPT_VER == "p4" and GHIDRA_CACHE_KEY == "ghidra_full_v6",
        "note": "Gym apply-only. Not a recipe catalog. Not live restore. Not FUN_ rename.",
        "facts": payload,
    }
    dest = run_dir / "pdb_facts.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only sibling PDB publics (not live, not rename)"
    )
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--run", type=Path, default=None, help="output/logs/run_* directory")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = p.parse_args(argv)
    if args.dry_run or not args.run:
        rec = run_dry()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        rec["out"] = str(args.out)
    else:
        rec = run_on_dir(args.run)
    skip = ("facts", "names_by_addr")
    print(json.dumps({k: rec[k] for k in rec if k not in skip}, indent=2))
    return 0 if rec.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
