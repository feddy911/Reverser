from __future__ import annotations

"""DAT / format-string facts from THIS PE. Not Ghidra C, not samples/*.cpp.

Q2 of the compare-oracles plan: bytes at a VA are a C-string if ASCII+NUL,
and a format blob if they also contain %. Addresses come from DAT_* in the
dump (VA encoding) or RIP-relative LEA into an arg reg. Empty bag is not a
pass token. No string — not a leftover and not a literal to invent. Live
restore stays p4. Gym-only; runner does not consume this.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from src.analysis.pe_image import bytes_at_va, rip_lea_arg_vas

SOURCE_EMPTY = "empty"
SOURCE_PE_BYTES = "pe_bytes"

_MAX_CSTRING = 512
_RE_DAT = re.compile(r"\bDAT_([0-9A-Fa-f]+)\b")
_PRINTABLE = frozenset({9, 10, 13} | set(range(0x20, 0x7F)))
_RE_PRINTF_CONV = re.compile(
    r"%(?:[-+0 #]*)?(?:\d+|\*)?(?:\.(?:\d+|\*))?[diouxXeEfFgGaAcspn%]"
)


@dataclass(frozen=True)
class DatBlob:
    """One NUL-terminated ASCII span in this PE. text is from bytes, not C."""

    va: str
    kind: str
    n: int
    text: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "va": self.va,
            "kind": self.kind,
            "n": self.n,
            "text": self.text,
        }


@dataclass(frozen=True)
class DatFacts:
    """Bag of DAT/format blobs. Empty is not a pass."""

    blobs: Tuple[DatBlob, ...]
    source: str

    @property
    def has_byte_facts(self) -> bool:
        return bool(self.blobs)

    @property
    def has_format(self) -> bool:
        return any(b.kind == "format" for b in self.blobs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blobs": [b.to_dict() for b in self.blobs],
            "source": self.source,
            "has_byte_facts": self.has_byte_facts,
            "has_format": self.has_format,
        }


def _empty() -> DatFacts:
    return DatFacts((), SOURCE_EMPTY)


def ascii_cstring(raw: bytes | bytearray | None, *, maxn: int = _MAX_CSTRING) -> Optional[str]:
    """NUL-terminated ASCII, or None. Does not invent a literal."""
    data = bytes(raw or b"")
    if not data:
        return None
    end = data.find(b"\x00", 0, maxn)
    if end < 0:
        return None
    span = data[:end]
    if any(b not in _PRINTABLE for b in span):
        return None
    try:
        return span.decode("ascii")
    except UnicodeDecodeError:
        return None


def classify_cstring(text: str | None) -> str:
    if not text:
        return ""
    if _RE_PRINTF_CONV.search(text):
        return "format"
    return "c_string"


def dat_vas_from_dump(code: str) -> Tuple[int, ...]:
    """DAT_<hex> encodings in dump C. The hex is a VA, not a sample name."""
    seen: List[int] = []
    have = set()
    for m in _RE_DAT.finditer(code or ""):
        try:
            va = int(m.group(1), 16)
        except ValueError:
            continue
        if va and va not in have:
            have.add(va)
            seen.append(va)
    return tuple(seen)


def dat_blob_from_bytes(raw: bytes | bytearray | None, *, va: int = 0) -> Optional[DatBlob]:
    text = ascii_cstring(raw)
    kind = classify_cstring(text)
    if not kind or text is None:
        return None
    return DatBlob(va=f"0x{va:x}" if va else "", kind=kind, n=len(text), text=text)


def dat_facts_from_blob(
    blob: bytes | bytearray | None,
    vas: Sequence[int],
    *,
    maxn: int = _MAX_CSTRING,
) -> DatFacts:
    data = bytes(blob or b"")
    if not data or not vas:
        return _empty()
    out: List[DatBlob] = []
    seen = set()
    for va in vas:
        addr = int(va)
        if addr in seen:
            continue
        seen.add(addr)
        rec = dat_blob_from_bytes(bytes_at_va(data, addr, maxn), va=addr)
        if rec is not None:
            out.append(rec)
    if not out:
        return _empty()
    return DatFacts(tuple(out), SOURCE_PE_BYTES)


def dat_facts_from_exe(
    path: str | Path,
    vas: Sequence[int],
    *,
    maxn: int = _MAX_CSTRING,
) -> DatFacts:
    p = Path(path) if path else Path()
    if not p.is_file() or not vas:
        return _empty()
    return dat_facts_from_blob(p.read_bytes(), vas, maxn=maxn)


def format_va_set(facts: object | None) -> set[int]:
    """VAs whose PE bytes are format blobs. Empty is not a pass."""
    out: set[int] = set()
    if facts is None:
        return out
    blobs: Iterable[Any] = ()
    if hasattr(facts, "blobs"):
        if not getattr(facts, "has_format", False) and not getattr(
            facts, "has_byte_facts", False
        ):
            return out
        blobs = getattr(facts, "blobs") or ()
    elif isinstance(facts, dict):
        blobs = facts.get("blobs") or ()
    else:
        return out
    for item in blobs:
        if hasattr(item, "kind"):
            kind = str(getattr(item, "kind") or "")
            va_s = str(getattr(item, "va") or "")
        elif isinstance(item, dict):
            kind = str(item.get("kind") or "")
            va_s = str(item.get("va") or "")
        else:
            continue
        if kind != "format":
            continue
        try:
            va = int(va_s, 16) if va_s.startswith("0x") else int(va_s or "0")
        except ValueError:
            continue
        if va:
            out.add(va)
    return out


def candidate_vas_for_fn(
    *,
    dump_code: str = "",
    func_bytes: bytes | bytearray | None = None,
    func_va: int = 0,
) -> Tuple[int, ...]:
    vas = list(dat_vas_from_dump(dump_code))
    have = set(vas)
    for va in rip_lea_arg_vas(bytes(func_bytes or b""), func_va=func_va):
        if va and va not in have:
            have.add(va)
            vas.append(va)
    return tuple(vas)
