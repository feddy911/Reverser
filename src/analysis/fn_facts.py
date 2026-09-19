from __future__ import annotations

"""Instruction/meta facts for a function. Not Ghidra C and not a restorer input.

P0/P1 of the disasm-oracle plan: schema plus extract from dump metadata
(address, size, callees) and ``func_bytes``. Live restore stays p4. Empty
byte bag is not a pass token. Live opt-in ``use_disasm_facts`` (default
false) attaches these to critic / analysis_stack, never the restore prompt.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

from src.analysis.pe_image import (
    rbp_lea_arg_slots,
    rbp_qword_store_slots,
    sub_rsp_imms,
)

SOURCE_DUMP = "dump_meta"
SOURCE_BYTES = "dump_meta+func_bytes"


@dataclass(frozen=True)
class FnFacts:
    """Byte/meta facts. No C, no guessed_name, no Ghidra type spelling."""

    addr: str
    size: int
    callees: Tuple[str, ...]
    stack_alloc: int
    lea_arg_slots: Tuple[int, ...]
    qword_store_slots: Tuple[int, ...]
    source: str

    @property
    def has_byte_facts(self) -> bool:
        return bool(
            self.stack_alloc
            or self.lea_arg_slots
            or self.qword_store_slots
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "addr": self.addr,
            "size": self.size,
            "callees": list(self.callees),
            "stack_alloc": self.stack_alloc,
            "lea_arg_slots": list(self.lea_arg_slots),
            "qword_store_slots": list(self.qword_store_slots),
            "source": self.source,
            "has_byte_facts": self.has_byte_facts,
        }


def fn_facts_from_dump_entry(
    entry: Mapping[str, Any] | None,
    *,
    func_bytes: bytes | bytearray | None = None,
) -> FnFacts:
    """P1: dump JSON fields plus func_bytes. Ignores ghidra_code / cpp_code."""
    data = entry or {}
    addr = str(data.get("address") or "").strip()
    try:
        size = int(data.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    callees = tuple(
        str(c).strip()
        for c in (data.get("callees") or [])
        if str(c).strip()
    )
    blob = bytes(func_bytes or b"")
    if not blob and isinstance(data.get("func_bytes"), (bytes, bytearray)):
        blob = bytes(data.get("func_bytes") or b"")
    allocs = sub_rsp_imms(blob)
    stack_alloc = max(allocs) if allocs else 0
    if size <= 0:
        size = len(blob)
    source = SOURCE_BYTES if blob else SOURCE_DUMP
    return FnFacts(
        addr=addr,
        size=size,
        callees=callees,
        stack_alloc=stack_alloc,
        lea_arg_slots=tuple(rbp_lea_arg_slots(blob)),
        qword_store_slots=tuple(rbp_qword_store_slots(blob)),
        source=source,
    )


def fn_facts_from_entries(
    entries: Sequence[Mapping[str, Any]] | None,
    *,
    bytes_by_addr: Mapping[str, bytes] | None = None,
) -> Dict[str, FnFacts]:
    """Map address → facts. Gym extractor; not a live runner hook."""
    found: Dict[str, FnFacts] = {}
    extra = bytes_by_addr or {}
    for raw in entries or []:
        addr = str(raw.get("address") or "").strip()
        blob = extra.get(addr)
        facts = fn_facts_from_dump_entry(raw, func_bytes=blob)
        if facts.addr:
            found[facts.addr] = facts
    return found


def attach_fn_facts(
    dest: Dict[str, Any] | None,
    entry: Mapping[str, Any] | None,
    *,
    func_bytes: bytes | bytearray | None = None,
    enabled: bool = False,
) -> None:
    """Opt-in: put JSON FnFacts on dest. Default off. Never C, never a prompt."""
    data = dest if dest is not None else {}
    if not enabled:
        data.pop("fn_facts", None)
        return
    facts = fn_facts_from_dump_entry(entry, func_bytes=func_bytes)
    payload = facts.to_dict()
    dumped = json.dumps(payload)
    if "****" in dumped or "ghidra_code" in dumped or "cpp_code" in dumped:
        data.pop("fn_facts", None)
        return
    data["fn_facts"] = payload
