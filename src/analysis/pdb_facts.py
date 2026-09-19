from __future__ import annotations

"""RSDS/PDB identity from THIS PE. Not Ghidra C, not samples/*.cpp.

P6 extractor: CodeView RSDS in the exe bytes (guid, age, pdb basename) and
whether a sibling .pdb sits next to the exe. Publics from that PDB fill
names_by_addr. Empty bag is not a pass token. Live restore stays p4.
Do not invent main. Do not bump v6.
"""

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.analysis.pe_image import pe_debug_codeview, pe_image_base, pe_section_rvas

SOURCE_EMPTY = "empty"
SOURCE_PE_RSDS = "pe_rsds"
SOURCE_PDB_PUB = "pe_rsds+pdb_pub"

_MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
_S_PUB32 = 0x110E
_RE_PUB_NAME = re.compile(r"^[A-Za-z_?][A-Za-z0-9_@?$]*$")
_MAX_PUBS = 4096
_MAX_STREAMS = 4096


@dataclass(frozen=True)
class RsdsFacts:
    """Debug identity of this binary. No C, no guessed_name, no sample stems."""

    guid: str
    age: int
    pdb_name: str
    pdb_present: bool
    names_by_addr: Tuple[Tuple[str, str], ...]
    source: str

    @property
    def has_rsds(self) -> bool:
        return bool(self.guid and self.pdb_name)

    @property
    def has_names(self) -> bool:
        return bool(self.names_by_addr)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guid": self.guid,
            "age": self.age,
            "pdb_name": self.pdb_name,
            "pdb_present": self.pdb_present,
            "names_by_addr": [list(p) for p in self.names_by_addr],
            "source": self.source,
            "has_rsds": self.has_rsds,
            "has_names": self.has_names,
        }


def _empty() -> RsdsFacts:
    return RsdsFacts("", 0, "", False, (), SOURCE_EMPTY)


def _pdb_basename(raw: str) -> str:
    """Only a .pdb leaf. Never a .cpp path, never parent traversal."""
    t = (raw or "").replace("\\", "/").split("/")[-1].strip()
    if not t or ".." in t:
        return ""
    if not t.lower().endswith(".pdb"):
        return ""
    return t


def parse_rsds_blob(blob: bytes | bytearray | None) -> RsdsFacts:
    raw = bytes(blob or b"")
    if len(raw) < 24 or raw[:4] != b"RSDS":
        return _empty()
    guid = raw[4:20].hex()
    age = int.from_bytes(raw[20:24], "little")
    path = raw[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    name = _pdb_basename(path)
    if not name:
        return _empty()
    return RsdsFacts(guid, age, name, False, (), SOURCE_PE_RSDS)


def sibling_pdb_path(exe: str | Path, pdb_name: str) -> Path | None:
    """Sibling of THIS exe only. Does not open samples/*.cpp."""
    name = _pdb_basename(pdb_name)
    if not name:
        return None
    return Path(exe).resolve().parent / name


def rsds_from_pe_bytes(blob: bytes | bytearray | None) -> RsdsFacts:
    return parse_rsds_blob(pe_debug_codeview(bytes(blob or b"")))


def _ok_pub_name(name: str) -> bool:
    if not name or len(name) > 256:
        return False
    low = name.lower()
    if low.endswith((".cpp", ".c", ".h", ".hpp", ".cc", ".cxx")):
        return False
    if "/" in name or "\\" in name or "." in name:
        return False
    return bool(_RE_PUB_NAME.fullmatch(name))


def _pub_va(
    seg: int,
    off: int,
    image_base: int,
    section_rvas: Sequence[int],
) -> int:
    if off < 0 or seg <= 0:
        return 0
    if section_rvas and seg <= len(section_rvas):
        return int(image_base) + int(section_rvas[seg - 1]) + int(off)
    if seg == 1 and image_base:
        return int(image_base) + int(off)
    return 0


def _walk_cv_pub32(stream: bytes) -> List[Tuple[int, int, str]]:
    out: List[Tuple[int, int, str]] = []
    i = 0
    n = len(stream)
    while i + 4 <= n and len(out) < _MAX_PUBS:
        reclen, rectyp = struct.unpack_from("<HH", stream, i)
        if reclen < 2:
            break
        rec_end = i + 2 + reclen
        if rec_end > n:
            break
        if rectyp == _S_PUB32 and reclen >= 12:
            off = int(struct.unpack_from("<I", stream, i + 8)[0])
            seg = int(struct.unpack_from("<H", stream, i + 12)[0])
            raw = stream[i + 14 : rec_end].split(b"\x00", 1)[0]
            try:
                name = raw.decode("ascii")
            except UnicodeDecodeError:
                name = ""
            if _ok_pub_name(name):
                out.append((seg, off, name))
        i = rec_end
        pad = (4 - (i % 4)) % 4
        i += pad
    return out


def _msf_streams(blob: bytes) -> Optional[List[bytes]]:
    if len(blob) < 56 or blob[:32] != _MSF_MAGIC:
        return None
    block_size, _fpm, nblocks, dir_bytes, _unk, block_map = struct.unpack_from(
        "<IIIIII", blob, 32
    )
    if block_size not in (512, 1024, 2048, 4096, 8192):
        return None
    if nblocks < 3 or dir_bytes == 0 or dir_bytes > 1_000_000:
        return None
    n_dir_blocks = (dir_bytes + block_size - 1) // block_size
    map_off = int(block_map) * block_size
    if map_off < 0 or map_off + 4 * n_dir_blocks > len(blob):
        return None
    directory = bytearray()
    for i in range(n_dir_blocks):
        idx = struct.unpack_from("<I", blob, map_off + 4 * i)[0]
        start = int(idx) * block_size
        if start < 0 or start >= len(blob):
            return None
        directory.extend(blob[start : start + block_size])
    directory = directory[:dir_bytes]
    if len(directory) < 4:
        return None
    nstreams = struct.unpack_from("<I", directory, 0)[0]
    if nstreams == 0 or nstreams > _MAX_STREAMS:
        return None
    if 4 + 4 * nstreams > len(directory):
        return None
    sizes = [
        struct.unpack_from("<I", directory, 4 + 4 * i)[0] for i in range(nstreams)
    ]
    cursor = 4 + 4 * nstreams
    streams: List[bytes] = []
    for sz in sizes:
        if sz == 0xFFFFFFFF:
            streams.append(b"")
            continue
        nblk = (int(sz) + block_size - 1) // block_size if sz else 0
        if cursor + 4 * nblk > len(directory):
            return None
        chunks = bytearray()
        for j in range(nblk):
            bidx = struct.unpack_from("<I", directory, cursor + 4 * j)[0]
            start = int(bidx) * block_size
            if start < 0:
                return None
            chunks.extend(blob[start : start + block_size])
        cursor += 4 * nblk
        streams.append(bytes(chunks[: int(sz)]))
    return streams


def names_from_pdb_bytes(
    blob: bytes | bytearray | None,
    *,
    image_base: int = 0,
    section_rvas: Sequence[int] = (),
) -> Tuple[Tuple[str, str], ...]:
    """S_PUB32 names from a sibling PDB. Empty bag is not a pass."""
    streams = _msf_streams(bytes(blob or b""))
    if not streams:
        return ()
    targets: List[bytes] = []
    if len(streams) > 3 and len(streams[3]) >= 18:
        sig, _ver, _age, _gsi, _build, pub = struct.unpack_from(
            "<iIIHHH", streams[3], 0
        )
        if sig == -1 and 0 <= pub < len(streams) and streams[pub]:
            targets.append(streams[pub])
    if not targets:
        targets = [s for s in streams if s]
    seen: set[Tuple[str, str]] = set()
    pairs: List[Tuple[str, str]] = []
    for st in targets:
        hits = _walk_cv_pub32(st)
        if not hits and len(st) > 28:
            hits = _walk_cv_pub32(st[28:])
        for seg, off, name in hits:
            va = _pub_va(seg, off, image_base, section_rvas)
            if not va:
                continue
            key = (f"0x{va:x}", name)
            if key in seen:
                continue
            seen.add(key)
            pairs.append(key)
            if len(pairs) >= _MAX_PUBS:
                return tuple(pairs)
    return tuple(pairs)


def rsds_from_exe(path: str | Path) -> RsdsFacts:
    p = Path(path)
    if not p.is_file():
        return _empty()
    pe = p.read_bytes()
    facts = rsds_from_pe_bytes(pe)
    if not facts.has_rsds:
        return facts
    sib = sibling_pdb_path(p, facts.pdb_name)
    present = bool(sib and sib.is_file() and sib.suffix.lower() == ".pdb")
    names: Tuple[Tuple[str, str], ...] = ()
    if present and sib is not None:
        names = names_from_pdb_bytes(
            sib.read_bytes(),
            image_base=pe_image_base(pe),
            section_rvas=pe_section_rvas(pe),
        )
    source = SOURCE_PDB_PUB if names else facts.source
    return RsdsFacts(
        facts.guid,
        facts.age,
        facts.pdb_name,
        present,
        names,
        source,
    )
