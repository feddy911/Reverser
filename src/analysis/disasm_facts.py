from __future__ import annotations

"""Optional capstone facts from func_bytes. Gym-only; not live restore input.

Same FnFacts fields as pe_image scanners. Capstone is a decoder, not a
second C dialect. Missing capstone returns None (eval skips that engine).
"""

import json
from typing import Any, Dict, List, Optional, Sequence

from src.analysis.fn_facts import SOURCE_BYTES, FnFacts, fn_facts_from_dump_entry

SOURCE_CAPSTONE = "capstone"

_ARG_REGS = frozenset({"rcx", "rdx", "r8", "r9", "ecx", "edx", "r8d", "r9d"})
_RSP = frozenset({"rsp", "esp"})
_RBP = frozenset({"rbp", "ebp"})


def capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except ImportError:
        return False


def fn_facts_from_capstone(
    blob: bytes | bytearray | None,
    *,
    addr: str = "",
    size: int = 0,
    callees: Sequence[str] = (),
) -> Optional[FnFacts]:
    """Decode x64 bytes. None if capstone is missing or blob is empty."""
    raw = bytes(blob or b"")
    if not raw:
        return None
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ImportError:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    allocs: List[int] = []
    lea_slots: List[int] = []
    qstores: List[int] = []
    seen_lea: set[int] = set()
    seen_q: set[int] = set()
    for insn in md.disasm(raw, 0):
        ops = list(insn.operands)
        mnem = (insn.mnemonic or "").lower()
        if mnem == "sub" and len(ops) >= 2:
            if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
                name = (insn.reg_name(ops[0].reg) or "").lower()
                if name in _RSP and ops[1].imm:
                    allocs.append(int(ops[1].imm) & 0xFFFFFFFF)
        if mnem == "lea" and len(ops) >= 2:
            if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
                dest = (insn.reg_name(ops[0].reg) or "").lower()
                base = (insn.reg_name(ops[1].mem.base) or "").lower()
                if dest in _ARG_REGS and base in _RBP:
                    disp = int(ops[1].mem.disp)
                    if disp not in seen_lea:
                        seen_lea.add(disp)
                        lea_slots.append(disp)
        if mnem == "mov" and len(ops) >= 1 and ops[0].type == X86_OP_MEM:
            base = (insn.reg_name(ops[0].mem.base) or "").lower()
            if base in _RBP and int(ops[0].size) == 8:
                disp = int(ops[0].mem.disp)
                if disp not in seen_q:
                    seen_q.add(disp)
                    qstores.append(disp)
    return FnFacts(
        addr=addr,
        size=size or len(raw),
        callees=tuple(str(c).strip() for c in callees if str(c).strip()),
        stack_alloc=max(allocs) if allocs else 0,
        lea_arg_slots=tuple(lea_slots),
        qword_store_slots=tuple(qstores),
        source=SOURCE_CAPSTONE,
    )


def compare_fn_facts(scan: FnFacts, cap: FnFacts) -> Dict[str, Any]:
    """Agreement between pe_image scan and capstone. Not an arbiter of C."""
    return {
        "stack_alloc_match": scan.stack_alloc == cap.stack_alloc,
        "lea_arg_match": scan.lea_arg_slots == cap.lea_arg_slots,
        "qword_store_match": scan.qword_store_slots == cap.qword_store_slots,
        "agree": (
            scan.stack_alloc == cap.stack_alloc
            and scan.lea_arg_slots == cap.lea_arg_slots
            and scan.qword_store_slots == cap.qword_store_slots
        ),
    }


def facts_vs_c(facts: FnFacts, code: str) -> List[str]:
    """Gym hints: leftover C vs byte facts. Critic REJECT is leftover_facts_disagree."""
    from src.analysis.ghidra_cpp import (
        leftover_facts_disagree,
        leftover_gs_cookie_slot,
        leftover_ostream_overlay_insert,
    )

    hints: List[str] = []
    if leftover_facts_disagree(code or "", facts):
        hints.append("extra_star_vs_outparam")
    if leftover_ostream_overlay_insert(code or ""):
        hints.append("overlay_insert")
    if leftover_gs_cookie_slot(code or "") and facts.stack_alloc:
        hints.append("gs_slot_vs_frame")
    return hints


def scan_and_capstone(
    entry: Dict[str, Any] | None,
    *,
    func_bytes: bytes | bytearray | None = None,
    dump_code: str = "",
    restored_code: str = "",
) -> Dict[str, Any]:
    """One function: dump+scan facts, optional capstone, leftover hints."""
    data = entry or {}
    blob = bytes(func_bytes or b"")
    scan = fn_facts_from_dump_entry(data, func_bytes=blob)
    cap = fn_facts_from_capstone(
        blob,
        addr=scan.addr,
        size=scan.size,
        callees=scan.callees,
    )
    dump_c = dump_code or str(data.get("ghidra_code") or "")
    rest_c = restored_code or str(data.get("cpp_code") or "")
    vs_dump = facts_vs_c(scan, dump_c)
    vs_rest = facts_vs_c(scan, rest_c)
    rec: Dict[str, Any] = {
        "scan": scan.to_dict(),
        "capstone": cap.to_dict() if cap else None,
        "capstone_available": capstone_available(),
        "compare": compare_fn_facts(scan, cap) if cap else None,
        "vs_c_dump": vs_dump,
        "vs_c_restored": vs_rest,
        "vs_c": vs_dump or vs_rest,
        "source_scan": SOURCE_BYTES if blob else scan.source,
    }
    fact_blob = json_dumps_facts(scan, cap)
    rec["c_leaked_into_facts"] = (
        "****" in fact_blob
        or "ghidra_code" in fact_blob
        or "cpp_code" in fact_blob
    )
    return rec


def json_dumps_facts(scan: FnFacts, cap: Optional[FnFacts]) -> str:
    payload = {"scan": scan.to_dict(), "capstone": cap.to_dict() if cap else None}
    return json.dumps(payload)
