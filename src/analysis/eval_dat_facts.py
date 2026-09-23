"""Gym-only DAT/format blobs vs this exe. Not live.

  py -m src.analysis.eval_dat_facts --dry-run
  py -m src.analysis.eval_dat_facts --run output/logs/run_<ts>

Reads binary_info.json from a run directory. Writes dat_facts.json next to
the run. Does not call runner, does not bump p4/v6, does not emit corpus
YAML from sample names, does not invent a format literal when bytes miss.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "dat_facts_report.json"
WRAP_VA = 0x140001000
WRAP_FMT = "n=%d"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _pe_with_cstring(text: str, *, image_base: int = 0x140000000, rva: int = 0x1000) -> Tuple[bytes, int]:
    payload = text.encode("ascii") + b"\x00"
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
    struct.pack_into("<Q", blob, opt + 24, image_base)
    struct.pack_into("<I", blob, opt + 108, 16)
    sec = opt + 0xF0
    blob[sec : sec + 6] = b".rdata"
    struct.pack_into("<I", blob, sec + 8, 0x200)
    struct.pack_into("<I", blob, sec + 12, rva)
    struct.pack_into("<I", blob, sec + 16, 0x200)
    struct.pack_into("<I", blob, sec + 20, 0x400)
    blob[0x400 : 0x400 + len(payload)] = payload
    return bytes(blob), image_base + rva


def run_dry() -> Dict[str, Any]:
    from src.analysis.dat_facts import (
        SOURCE_EMPTY,
        SOURCE_PE_BYTES,
        ascii_cstring,
        dat_facts_from_blob,
        dat_vas_from_dump,
    )
    from src.analysis.ghidra_cpp import leftover_format_from_pe
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    empty = dat_facts_from_blob(b"MZ", (WRAP_VA,))
    pe, va = _pe_with_cstring(WRAP_FMT)
    facts = dat_facts_from_blob(pe, (va,))
    hello_pe, hello_va = _pe_with_cstring("hello")
    hello = dat_facts_from_blob(hello_pe, (hello_va,))
    binary_pe, bin_va = _pe_with_cstring("x")
    binary_pe = bytearray(binary_pe)
    binary_pe[0x400:0x402] = b"\xff\x00"
    binary = dat_facts_from_blob(bytes(binary_pe), (bin_va,))
    wrap_c = (
        "void wrap(void) {\n"
        "  unsigned char *pcVar1;\n"
        "  pcVar1 = &DAT_140001000;\n"
        "  printf(pcVar1);\n"
        "}\n"
    )
    leftover = leftover_format_from_pe(wrap_c, facts)
    leftover_empty = leftover_format_from_pe(wrap_c, None)
    leftover_hello = leftover_format_from_pe(wrap_c, hello)
    dumped = json.dumps(facts.to_dict())
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "empty_has_format": empty.has_format,
        "empty_bag_is_not_pass": not empty.has_byte_facts,
        "empty_source": empty.source,
        "format_text": facts.blobs[0].text if facts.blobs else "",
        "format_kind": facts.blobs[0].kind if facts.blobs else "",
        "hello_kind": hello.blobs[0].kind if hello.blobs else "",
        "binary_has_blob": binary.has_byte_facts,
        "dump_vas": list(dat_vas_from_dump(wrap_c)),
        "ascii_ok": ascii_cstring(WRAP_FMT.encode("ascii") + b"\x00") == WRAP_FMT,
        "leftover": leftover,
        "leftover_empty": leftover_empty,
        "leftover_hello": leftover_hello,
        "invented_from_cpp": False,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and empty.source == SOURCE_EMPTY
            and not empty.has_byte_facts
            and facts.source == SOURCE_PE_BYTES
            and facts.has_format
            and facts.blobs[0].text == WRAP_FMT
            and hello.blobs
            and hello.blobs[0].kind == "c_string"
            and not binary.has_byte_facts
            and leftover == ["DAT_140001000"]
            and leftover_empty == []
            and leftover_hello == []
            and "MyCollatz" not in dumped
            and "NestWalk" not in dumped
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "Do not invent a format literal when PE bytes miss."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.dat_facts import candidate_vas_for_fn, dat_facts_from_exe
    from src.analysis.pe_image import read_va
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    run_dir = Path(run_dir)
    binary_info = _load_json(run_dir / "binary_info.json") or {}
    functions = _load_json(run_dir / "functions.json") or []
    restored = _load_json(run_dir / "restored.json") or []
    restored_by = {
        str(r.get("address") or ""): r
        for r in restored
        if isinstance(r, dict)
    }
    binary = str(binary_info.get("path") or "")
    bin_path = Path(binary)
    if binary and not bin_path.is_file():
        bin_path = ROOT / binary
    want = {
        addr
        for addr, r in restored_by.items()
        if r.get("classification") in (None, "user_code")
        and (r.get("cpp_code") or "").strip()
    }
    vas: List[int] = []
    have = set()
    for fn in functions:
        addr = str(fn.get("address") or "")
        if want and addr not in want:
            continue
        try:
            va = int(addr, 16)
            sz = int(fn.get("size") or 0)
        except (TypeError, ValueError):
            continue
        dump = str(fn.get("ghidra_code") or "")
        blob = read_va(bin_path, va, sz) if bin_path.is_file() else b""
        for cand in candidate_vas_for_fn(dump_code=dump, func_bytes=blob, func_va=va):
            if cand not in have:
                have.add(cand)
                vas.append(cand)
    facts = dat_facts_from_exe(bin_path, vas) if bin_path.is_file() else dat_facts_from_exe("", ())
    payload = facts.to_dict()
    dumped = json.dumps(payload)
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "n_va": len(vas),
        "n_blob": len(facts.blobs),
        "n_format": sum(1 for b in facts.blobs if b.kind == "format"),
        "n_c_string": sum(1 for b in facts.blobs if b.kind == "c_string"),
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "empty_bag_is_not_pass": not facts.has_byte_facts,
        "invented_cpp": ".cpp" in dumped,
        "ok": LLM_PROMPT_VER == "p4" and GHIDRA_CACHE_KEY == "ghidra_full_v6",
        "note": (
            "Gym apply-only. Not a recipe catalog. Not live restore. "
            "No string at VA is not a literal."
        ),
        "format_vas": [b.va for b in facts.blobs if b.kind == "format"],
        "facts": payload,
    }
    dest = run_dir / "dat_facts.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only DAT/format blobs (not live, not sample .cpp)"
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
        skip = ()
    else:
        rec = run_on_dir(args.run)
        skip = ("facts",)
    print(json.dumps({k: rec[k] for k in rec if k not in skip}, indent=2))
    return 0 if rec.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
