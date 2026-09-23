from __future__ import annotations

"""Call-site facts from func_bytes. Not Ghidra C and not a live restorer input.

Q0 of the compare-oracles plan: MS x64 CALL at instruction starts plus last
writes to RCX/RDX/R8/R9 (imm or lea). Q1 fills iat_name only for rip-mem
slots present in this PE's IAT. Empty bag is not a pass token. Live restore
stays p4. Q7 may pass this bag into build_restore_prompt as an opt-in
kwarg; CodeRestorerLLM.restore live omits it. runner.py does not import
this module. emit_sanitized_restore scans func_bytes for the unique-imm fill.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from src.analysis.pe_image import scan_ms64_call_sites

SOURCE_BYTES = "func_bytes"
SOURCE_CAPSTONE = "capstone"

_ARG_REGS = ("rcx", "rdx", "r8", "r9")
_ARG_ALIASES = {
    "rcx": "rcx",
    "ecx": "rcx",
    "rdx": "rdx",
    "edx": "rdx",
    "r8": "r8",
    "r8d": "r8",
    "r9": "r9",
    "r9d": "r9",
}


@dataclass(frozen=True)
class CallSite:
    """One CALL. No C, no guessed_name. iat_name is the PE IAT slot or empty."""

    off: int
    kind: str
    callee_va: str
    iat_name: str
    arg_regs: Tuple[str, ...]
    imm_slots: Tuple[Tuple[str, int], ...]
    lea_slots: Tuple[Tuple[str, int], ...]
    stack_disp: Tuple[int, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "off": self.off,
            "kind": self.kind,
            "callee_va": self.callee_va,
            "iat_name": self.iat_name,
            "arg_regs": list(self.arg_regs),
            "imm_slots": [list(p) for p in self.imm_slots],
            "lea_slots": [list(p) for p in self.lea_slots],
            "stack_disp": list(self.stack_disp),
        }


@dataclass(frozen=True)
class CallSiteFacts:
    """Bag of call sites for one function. Empty is not a pass."""

    addr: str
    sites: Tuple[CallSite, ...]
    source: str

    @property
    def has_byte_facts(self) -> bool:
        return bool(self.sites)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "addr": self.addr,
            "sites": [s.to_dict() for s in self.sites],
            "source": self.source,
            "has_byte_facts": self.has_byte_facts,
        }


def _site_from_raw(raw: Mapping[str, Any] | None) -> CallSite:
    data = dict(raw or {})
    imm = tuple(
        (str(a), int(b))
        for a, b in (data.get("imm_slots") or ())
    )
    lea = tuple(
        (str(a), int(b))
        for a, b in (data.get("lea_slots") or ())
    )
    return CallSite(
        off=int(data.get("off") or 0),
        kind=str(data.get("kind") or ""),
        callee_va=str(data.get("callee_va") or ""),
        iat_name=str(data.get("iat_name") or ""),
        arg_regs=tuple(str(r) for r in (data.get("arg_regs") or ())),
        imm_slots=imm,
        lea_slots=lea,
        stack_disp=tuple(int(x) for x in (data.get("stack_disp") or ())),
    )


def call_sites_from_bytes(
    blob: bytes | bytearray | None,
    *,
    addr: str = "",
    func_va: int = 0,
    iat_by_va: Mapping[int, str] | None = None,
) -> CallSiteFacts:
    """Q0 pe_image scan. Ignores ghidra_code. Q1 names only via iat_by_va."""
    va = func_va
    if not va and addr:
        try:
            va = int(str(addr), 16)
        except ValueError:
            va = 0
    raw = bytes(blob or b"")
    sites = tuple(
        _site_from_raw(s)
        for s in scan_ms64_call_sites(raw, func_va=va, iat_by_va=iat_by_va)
    )
    return CallSiteFacts(addr=addr, sites=sites, source=SOURCE_BYTES)


def capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except ImportError:
        return False


def _canon_reg(name: str) -> str:
    return _ARG_ALIASES.get((name or "").lower(), "")


def call_sites_from_capstone(
    blob: bytes | bytearray | None,
    *,
    addr: str = "",
    func_va: int = 0,
) -> Optional[CallSiteFacts]:
    """Decode x64 CALL sites. None if capstone missing or blob empty."""
    raw = bytes(blob or b"")
    if not raw:
        return None
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ImportError:
        return None
    va = func_va
    if not va and addr:
        try:
            va = int(str(addr), 16)
        except ValueError:
            va = 0
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    writes: Dict[str, Dict[str, Any]] = {}
    stack: List[int] = []
    sites: List[CallSite] = []
    for insn in md.disasm(raw, va or 0):
        mnem = (insn.mnemonic or "").lower()
        ops = list(insn.operands)
        off = int(insn.address - (va or 0))
        if mnem in ("mov", "xor") and len(ops) >= 2 and ops[0].type == X86_OP_REG:
            dest = _canon_reg(insn.reg_name(ops[0].reg) or "")
            if dest:
                rec: Dict[str, Any] = {"off": off}
                if mnem == "xor" and ops[1].type == X86_OP_REG:
                    src = _canon_reg(insn.reg_name(ops[1].reg) or "")
                    if src == dest:
                        rec["imm"] = 0
                elif ops[1].type == X86_OP_IMM:
                    rec["imm"] = int(ops[1].imm) & 0xFFFFFFFF
                writes[dest] = rec
            elif ops[0].type == X86_OP_MEM:
                pass
        if mnem == "mov" and ops and ops[0].type == X86_OP_MEM:
            base = (insn.reg_name(ops[0].mem.base) or "").lower()
            if base in ("rsp", "esp"):
                disp = int(ops[0].mem.disp)
                if disp not in stack:
                    stack.append(disp)
        if mnem == "lea" and len(ops) >= 2 and ops[0].type == X86_OP_REG:
            dest = _canon_reg(insn.reg_name(ops[0].reg) or "")
            if dest and ops[1].type == X86_OP_MEM:
                writes[dest] = {"off": off, "lea": int(ops[1].mem.disp)}
        if mnem != "call":
            continue
        kind = "rel"
        callee = ""
        if ops and ops[0].type == X86_OP_IMM:
            callee = f"0x{int(ops[0].imm):x}"
            kind = "rel"
        elif ops and ops[0].type == X86_OP_MEM:
            kind = "rip_mem"
            disp = int(ops[0].mem.disp)
            if va:
                callee = f"0x{(int(insn.address) + int(insn.size) + disp) & 0xFFFFFFFFFFFFFFFF:x}"
        arg_regs = tuple(r for r in _ARG_REGS if r in writes)
        imm_slots = tuple(
            (r, int(writes[r]["imm"]))
            for r in arg_regs
            if "imm" in writes[r]
        )
        lea_slots = tuple(
            (r, int(writes[r]["lea"]))
            for r in arg_regs
            if "lea" in writes[r]
        )
        sites.append(
            CallSite(
                off=off,
                kind=kind,
                callee_va=callee,
                iat_name="",
                arg_regs=arg_regs,
                imm_slots=imm_slots,
                lea_slots=lea_slots,
                stack_disp=tuple(stack),
            )
        )
        writes = {}
        stack = []
    if not sites:
        return CallSiteFacts(addr=addr, sites=(), source=SOURCE_CAPSTONE)
    return CallSiteFacts(addr=addr, sites=tuple(sites), source=SOURCE_CAPSTONE)


def compare_call_sites(scan: CallSiteFacts, cap: CallSiteFacts) -> Dict[str, Any]:
    """Agreement between pe_image and capstone. Not an arbiter of C."""
    a = [s.to_dict() for s in scan.sites]
    b = [s.to_dict() for s in cap.sites]
    keys = ("off", "kind", "callee_va", "arg_regs", "imm_slots", "lea_slots")
    slim_a = [{k: s[k] for k in keys} for s in a]
    slim_b = [{k: s[k] for k in keys} for s in b]
    return {
        "n_scan": len(a),
        "n_capstone": len(b),
        "agree": slim_a == slim_b,
    }


def scan_and_capstone(
    blob: bytes | bytearray | None,
    *,
    addr: str = "",
    func_va: int = 0,
    dump_code: str = "",
    restored_code: str = "",
    iat_by_va: Mapping[int, str] | None = None,
) -> Dict[str, Any]:
    """One function: pe_image sites, optional capstone. Never a prompt."""
    scan = call_sites_from_bytes(
        blob, addr=addr, func_va=func_va, iat_by_va=iat_by_va
    )
    cap = call_sites_from_capstone(blob, addr=addr, func_va=func_va)
    rec: Dict[str, Any] = {
        "scan": scan.to_dict(),
        "capstone": cap.to_dict() if cap else None,
        "capstone_available": capstone_available(),
        "compare": compare_call_sites(scan, cap) if cap else None,
        "source_scan": SOURCE_BYTES,
    }
    dumped = json.dumps(
        {"scan": scan.to_dict(), "capstone": cap.to_dict() if cap else None}
    )
    rec["c_leaked_into_facts"] = (
        "****" in dumped
        or "ghidra_code" in dumped
        or "cpp_code" in dumped
        or "mpz_ptr" in dumped
    )
    rec["c_in_inputs"] = bool(dump_code or restored_code)
    rec["ignored_c"] = True
    return rec
