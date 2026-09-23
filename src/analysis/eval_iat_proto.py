"""Gym-only IAT prototype sinks vs this exe. Not live.

  py -m src.analysis.eval_iat_proto --dry-run
  py -m src.analysis.eval_iat_proto --run output/logs/run_<ts>

Reads binary_info.json from a run directory. Writes iat_proto.json next to
the run. Does not call runner, does not bump p4/v6, does not emit corpus
YAML, does not invent mpz_ptr for names missing from this PE's IAT.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "output" / "iat_proto_report.json"


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _pe_with_imports(
    dll: str, names: Sequence[str], *, image_base: int = 0x140000000
) -> Tuple[bytes, Tuple[int, ...]]:
    """Minimal PE32+ with one import DLL. Wrap bytes, not a sample."""
    n = len(names)
    rva0 = 0x1000
    raw0 = 0x400
    desc_rva = rva0
    ilt_rva = desc_rva + 40
    iat_rva = ilt_rva + (n + 1) * 8
    dll_rva = iat_rva + (n + 1) * 8
    name_rvas: List[int] = []
    name_blobs: List[Tuple[int, bytes]] = []
    cursor = dll_rva + len(dll) + 1
    if cursor % 2:
        cursor += 1
    for nm in names:
        if cursor % 2:
            cursor += 1
        raw = struct.pack("<H", 0) + nm.encode("ascii") + b"\x00"
        name_rvas.append(cursor)
        name_blobs.append((cursor, raw))
        cursor += len(raw)
    payload_end = cursor - rva0
    blob = bytearray(max(0x800, raw0 + payload_end + 0x40))
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
    struct.pack_into("<I", blob, opt + 112 + 8, desc_rva)
    struct.pack_into("<I", blob, opt + 112 + 8 + 4, 40)
    sec = opt + 0xF0
    blob[sec : sec + 6] = b".rdata"
    struct.pack_into("<I", blob, sec + 8, 0x400)
    struct.pack_into("<I", blob, sec + 12, rva0)
    struct.pack_into("<I", blob, sec + 16, 0x400)
    struct.pack_into("<I", blob, sec + 20, raw0)
    def _at(rva: int) -> int:
        return raw0 + (rva - rva0)

    struct.pack_into("<IIIII", blob, _at(desc_rva), ilt_rva, 0, 0, dll_rva, iat_rva)
    for i, nrva in enumerate(name_rvas):
        struct.pack_into("<Q", blob, _at(ilt_rva) + i * 8, nrva)
        struct.pack_into("<Q", blob, _at(iat_rva) + i * 8, nrva)
    dll_off = _at(dll_rva)
    blob[dll_off : dll_off + len(dll)] = dll.encode("ascii")
    for nrva, raw in name_blobs:
        off = _at(nrva)
        blob[off : off + len(raw)] = raw
    vas = tuple(image_base + iat_rva + i * 8 for i in range(n))
    return bytes(blob), vas


def run_dry() -> Dict[str, Any]:
    from src.analysis.call_sites import call_sites_from_bytes
    from src.analysis.iat_proto import (
        SOURCE_EMPTY,
        SOURCE_PE_IAT_PROTO,
        iat_facts_from_pe_bytes,
        proto_for_name,
    )
    from src.analysis.pe_image import pe_iat_name_by_va
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    empty = iat_facts_from_pe_bytes(b"MZ")
    pe, vas = _pe_with_imports(
        "libgmp-10.dll", ("__gmpz_clear", "printf")
    )
    facts = iat_facts_from_pe_bytes(pe)
    names = {p.name for p in facts.protos}
    slots = {p.name: p.slots for p in facts.protos}
    no_gmp_pe, _ = _pe_with_imports("kernel32.dll", ("Sleep",))
    no_gmp = iat_facts_from_pe_bytes(no_gmp_pe)
    iat_map = pe_iat_name_by_va(pe)
    slot = vas[0]
    func_va = 0x140001000
    disp = slot - (func_va + 6)
    blob = b"\xff\x15" + struct.pack("<i", disp) + b"\xc3"
    named = call_sites_from_bytes(
        blob, addr=f"0x{func_va:x}", func_va=func_va, iat_by_va=iat_map
    )
    unnamed = call_sites_from_bytes(
        blob, addr=f"0x{func_va:x}", func_va=func_va
    )
    printf = proto_for_name("printf")
    dumped = json.dumps(facts.to_dict())
    rec = {
        "dry_run": True,
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "empty_has_protos": empty.has_protos,
        "empty_bag_is_not_pass": not empty.has_protos,
        "empty_source": empty.source,
        "n_entries": len(facts.entries),
        "n_protos": len(facts.protos),
        "source": facts.source,
        "printf_arity": printf.arity if printf else 0,
        "clear_slots": [list(p) for p in slots.get("__gmpz_clear") or ()],
        "sleep_has_gmp_proto": any("mpz" in p.name for p in no_gmp.protos),
        "named_iat": named.sites[0].iat_name if named.sites else "",
        "unnamed_without_map": unnamed.sites[0].iat_name if unnamed.sites else "x",
        "invented_main": proto_for_name("main") is not None or "main" in dumped,
        "ok": (
            LLM_PROMPT_VER == "p4"
            and GHIDRA_CACHE_KEY == "ghidra_full_v6"
            and empty.source == SOURCE_EMPTY
            and not empty.has_protos
            and facts.source == SOURCE_PE_IAT_PROTO
            and names == {"__gmpz_clear", "printf"}
            and slots.get("__gmpz_clear") == (("rcx", "mpz_ptr"),)
            and printf is not None
            and printf.arity == 1
            and printf.variadic
            and not any("mpz" in p.name for p in no_gmp.protos)
            and named.sites
            and named.sites[0].iat_name == "__gmpz_clear"
            and unnamed.sites
            and unnamed.sites[0].iat_name == ""
            and proto_for_name("main") is None
            and "MyCollatz" not in dumped
            and "NestWalk" not in dumped
        ),
        "note": (
            "Not live. Do not bump LLM_PROMPT_VER. runner.py does not consume this. "
            "Do not invent mpz_ptr without this PE's IAT. Do not invent main."
        ),
    }
    return rec


def run_on_dir(run_dir: Path) -> Dict[str, Any]:
    from src.analysis.call_sites import scan_and_capstone
    from src.analysis.iat_proto import iat_facts_from_exe
    from src.analysis.pe_image import pe_iat_name_by_va, read_va
    from src.pipeline.runner import GHIDRA_CACHE_KEY, LLM_PROMPT_VER

    run_dir = Path(run_dir)
    binary_info = _load_json(run_dir / "binary_info.json") or {}
    ghidra_imp = _load_json(run_dir / "imports.json") or []
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
    facts = iat_facts_from_exe(bin_path) if bin_path.is_file() else iat_facts_from_exe("")
    pe_names = {str(e.get("name") or "") for e in facts.entries if e.get("name")}
    ghidra_names = {str(x) for x in ghidra_imp if x}
    overlap = pe_names & ghidra_names
    iat_map = pe_iat_name_by_va(bin_path.read_bytes()) if bin_path.is_file() else {}
    want = {
        addr
        for addr, r in restored_by.items()
        if r.get("classification") in (None, "user_code")
        and (r.get("cpp_code") or "").strip()
    }
    n_named = 0
    n_sites = 0
    n_agree = 0
    for fn in functions:
        addr = str(fn.get("address") or "")
        if want and addr not in want:
            continue
        try:
            va = int(addr, 16)
            sz = int(fn.get("size") or 0)
        except (TypeError, ValueError):
            continue
        blob = read_va(bin_path, va, sz) if bin_path.is_file() else b""
        rec = scan_and_capstone(blob, addr=addr, func_va=va, iat_by_va=iat_map)
        sites = (rec.get("scan") or {}).get("sites") or []
        n_sites += len(sites)
        n_named += sum(1 for s in sites if s.get("iat_name"))
        if rec.get("compare") and rec["compare"].get("agree"):
            n_agree += 1
    payload = facts.to_dict()
    out = {
        "run_dir": str(run_dir.resolve()),
        "binary": str(bin_path),
        "n_iat": len(facts.entries),
        "n_proto": len(facts.protos),
        "n_gmp_proto": sum(1 for p in facts.protos if "mpz" in p.name),
        "n_named_calls": n_named,
        "n_sites": n_sites,
        "n_call_agree": n_agree,
        "n_ghidra_imports": len(ghidra_names),
        "n_overlap_ghidra": len(overlap),
        "live_prompt_ver": LLM_PROMPT_VER,
        "ghidra_cache_key": GHIDRA_CACHE_KEY,
        "dry_run": False,
        "empty_bag_is_not_pass": not facts.has_protos,
        "invented_main": any(p.name == "main" for p in facts.protos),
        "ok": LLM_PROMPT_VER == "p4" and GHIDRA_CACHE_KEY == "ghidra_full_v6",
        "note": (
            "Gym apply-only. Not a recipe catalog. Not live restore. "
            "mpz_ptr only if this PE imports a GMP symbol."
        ),
        "proto_names": [p.name for p in facts.protos],
        "facts": payload,
    }
    dest = run_dir / "iat_proto.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    out["out"] = str(dest)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Gym-only IAT proto sinks (not live, not second C)"
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
