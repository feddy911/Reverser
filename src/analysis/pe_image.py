from __future__ import annotations

"""Read PE bytes at a virtual address. No sample names, no Ghidra."""

import struct
from pathlib import Path
from typing import List, Sequence, Tuple


def read_va(path: str | Path, va: int, size: int) -> bytes:
    """File bytes mapped at `va` for `size`. Empty if the PE/section misses."""
    if size <= 0 or va <= 0:
        return b""
    blob = Path(path).read_bytes()
    if blob[:2] != b"MZ" or len(blob) < 0x40:
        return b""
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if e_lfanew + 24 > len(blob) or blob[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return b""
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", blob, coff + 2)[0]
    opt_sz = struct.unpack_from("<H", blob, coff + 16)[0]
    opt = coff + 20
    if opt + 2 > len(blob):
        return b""
    magic = struct.unpack_from("<H", blob, opt)[0]
    if magic == 0x20B:
        if opt + 32 > len(blob):
            return b""
        image_base = struct.unpack_from("<Q", blob, opt + 24)[0]
    elif magic == 0x10B:
        if opt + 28 > len(blob):
            return b""
        image_base = struct.unpack_from("<I", blob, opt + 28)[0]
    else:
        return b""
    sec0 = opt + opt_sz
    rva = va - int(image_base)
    if rva < 0:
        return b""
    for i in range(nsec):
        off = sec0 + i * 40
        if off + 40 > len(blob):
            break
        vsz = struct.unpack_from("<I", blob, off + 8)[0]
        vaddr = struct.unpack_from("<I", blob, off + 12)[0]
        raw_sz = struct.unpack_from("<I", blob, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", blob, off + 20)[0]
        span = max(vsz, raw_sz)
        if not (vaddr <= rva < vaddr + span):
            continue
        delta = rva - vaddr
        start = raw_ptr + delta
        return blob[start : start + size]
    return b""


_DIR_DEBUG = 6


def _pe_opt(blob: bytes) -> Tuple[int, int, int, int, int] | None:
    """coff, nsec, opt, magic, image_base. None if not a PE."""
    if blob[:2] != b"MZ" or len(blob) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if e_lfanew + 24 > len(blob) or blob[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", blob, coff + 2)[0]
    opt_sz = struct.unpack_from("<H", blob, coff + 16)[0]
    opt = coff + 20
    if opt + 2 > len(blob):
        return None
    magic = struct.unpack_from("<H", blob, opt)[0]
    if magic == 0x20B:
        if opt + 32 > len(blob):
            return None
        image_base = struct.unpack_from("<Q", blob, opt + 24)[0]
    elif magic == 0x10B:
        if opt + 28 > len(blob):
            return None
        image_base = struct.unpack_from("<I", blob, opt + 28)[0]
    else:
        return None
    if opt + opt_sz > len(blob):
        return None
    return coff, nsec, opt, magic, int(image_base)


def pe_rva_to_off(blob: bytes, rva: int) -> int:
    """File offset for RVA. -1 if the section misses."""
    if rva < 0:
        return -1
    layout = _pe_opt(blob)
    if layout is None:
        return -1
    coff, nsec, opt, _magic, _base = layout
    opt_sz = struct.unpack_from("<H", blob, coff + 16)[0]
    sec0 = opt + opt_sz
    for i in range(nsec):
        off = sec0 + i * 40
        if off + 40 > len(blob):
            break
        vsz = struct.unpack_from("<I", blob, off + 8)[0]
        vaddr = struct.unpack_from("<I", blob, off + 12)[0]
        raw_sz = struct.unpack_from("<I", blob, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", blob, off + 20)[0]
        span = max(vsz, raw_sz)
        if not (vaddr <= rva < vaddr + span):
            continue
        return raw_ptr + (rva - vaddr)
    return -1


def pe_data_directory(blob: bytes, index: int) -> Tuple[int, int]:
    """(rva, size) for data-directory index. (0, 0) if missing."""
    layout = _pe_opt(blob)
    if layout is None or index < 0:
        return 0, 0
    _coff, _nsec, opt, magic, _base = layout
    if magic == 0x20B:
        n_rva_off, dir0 = 108, 112
    else:
        n_rva_off, dir0 = 92, 96
    if opt + n_rva_off + 4 > len(blob):
        return 0, 0
    n_rva = struct.unpack_from("<I", blob, opt + n_rva_off)[0]
    if index >= n_rva:
        return 0, 0
    ent = opt + dir0 + index * 8
    if ent + 8 > len(blob):
        return 0, 0
    rva, size = struct.unpack_from("<II", blob, ent)
    return int(rva), int(size)


def pe_debug_codeview(blob: bytes) -> bytes:
    """Raw CodeView blob from IMAGE_DEBUG_TYPE_CODEVIEW. Empty if missing."""
    rva, size = pe_data_directory(blob, _DIR_DEBUG)
    if not rva or size < 28:
        return b""
    off = pe_rva_to_off(blob, rva)
    if off < 0 or off + 28 > len(blob):
        return b""
    n = min(size // 28, 16)
    for i in range(n):
        base = off + i * 28
        if base + 28 > len(blob):
            break
        dtype, dsize, _addr, ptr = struct.unpack_from("<IIII", blob, base + 12)
        if dtype != 2 or dsize < 24 or ptr <= 0:
            continue
        end = ptr + dsize
        if end > len(blob):
            continue
        return bytes(blob[ptr:end])
    return b""


def pe_image_base(blob: bytes) -> int:
    layout = _pe_opt(blob)
    return layout[4] if layout else 0


def pe_section_rvas(blob: bytes) -> Tuple[int, ...]:
    """Section VirtualAddress list in file order. Empty if not PE."""
    layout = _pe_opt(blob)
    if layout is None:
        return ()
    coff, nsec, opt, _magic, _base = layout
    opt_sz = struct.unpack_from("<H", blob, coff + 16)[0]
    sec0 = opt + opt_sz
    out: List[int] = []
    for i in range(nsec):
        off = sec0 + i * 40
        if off + 16 > len(blob):
            break
        out.append(int(struct.unpack_from("<I", blob, off + 12)[0]))
    return tuple(out)


def rbp_imm32_stores(code: bytes) -> List[Tuple[int, int]]:
    """MOV dword [RBP+disp], imm32 (ModRM /0, rm=RBP)."""
    blob = code or b""
    out: List[Tuple[int, int]] = []
    i = 0
    n = len(blob)
    while i + 7 <= n:
        if blob[i] == 0xC7:
            if i > 0 and blob[i - 1] in (0x48, 0x49):
                i += 1
                continue
            modrm = blob[i + 1]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm = modrm & 7
            if reg == 0 and rm == 5:
                if mod == 1:
                    disp = struct.unpack_from("<b", blob, i + 2)[0]
                    imm = struct.unpack_from("<I", blob, i + 3)[0]
                    out.append((disp, imm))
                    i += 7
                    continue
                if mod == 2 and i + 10 <= n:
                    disp = struct.unpack_from("<i", blob, i + 2)[0]
                    imm = struct.unpack_from("<I", blob, i + 6)[0]
                    out.append((disp, imm))
                    i += 10
                    continue
        i += 1
    return out


def consecutive_i32_runs(stores: Sequence[Tuple[int, int]]) -> List[List[int]]:
    """Immediate runs whose displacements step by 4 (dword array fill)."""
    if not stores:
        return []
    ordered = sorted(stores, key=lambda x: x[0])
    runs: List[List[int]] = []
    start_disp, vals = ordered[0][0], [_as_i32(ordered[0][1])]
    for disp, imm in ordered[1:]:
        if disp == start_disp + 4 * len(vals):
            vals.append(_as_i32(imm))
            continue
        if len(vals) >= 2:
            runs.append(vals)
        start_disp, vals = disp, [_as_i32(imm)]
    if len(vals) >= 2:
        runs.append(vals)
    return runs


def _as_i32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


def _unique_int(xs: Sequence[int]) -> List[int]:
    seen: set[int] = set()
    out: List[int] = []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def sub_rsp_imms(code: bytes) -> List[int]:
    """``sub rsp, imm`` frame sizes. First-match scan, not a full decoder."""
    blob = code or b""
    out: List[int] = []
    i = 0
    n = len(blob)
    while i + 4 <= n:
        if blob[i] == 0x48 and blob[i + 1] == 0x83 and blob[i + 2] == 0xEC:
            out.append(blob[i + 3])
            i += 4
            continue
        if blob[i] == 0x48 and blob[i + 1] == 0x81 and blob[i + 2] == 0xEC and i + 7 <= n:
            out.append(struct.unpack_from("<I", blob, i + 3)[0])
            i += 7
            continue
        i += 1
    return out


# Microsoft x64 integer args: RCX, RDX, R8, R9. (rex, ModRM.reg) for LEA.
_MS64_LEA_ARG = frozenset({
    (0x48, 1),
    (0x48, 2),
    (0x4C, 0),
    (0x4C, 1),
})


def rbp_lea_arg_slots(code: bytes) -> List[int]:
    """RBP-relative LEA into RCX/RDX/R8/R9 (out-param address)."""
    blob = code or b""
    out: List[int] = []
    i = 0
    n = len(blob)
    while i + 4 <= n:
        rex = blob[i]
        if rex in (0x48, 0x4C) and blob[i + 1] == 0x8D:
            modrm = blob[i + 2]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm = modrm & 7
            if rm == 5 and (rex, reg) in _MS64_LEA_ARG:
                if mod == 1:
                    out.append(struct.unpack_from("<b", blob, i + 3)[0])
                    i += 4
                    continue
                if mod == 2 and i + 7 <= n:
                    out.append(struct.unpack_from("<i", blob, i + 3)[0])
                    i += 7
                    continue
        i += 1
    return _unique_int(out)


def rbp_qword_store_slots(code: bytes) -> List[int]:
    """RBP-relative 8-byte stores (MOV r64 / MOV imm32 sign-extended)."""
    blob = code or b""
    out: List[int] = []
    i = 0
    n = len(blob)
    while i + 4 <= n:
        rex = blob[i]
        if rex in (0x48, 0x4C, 0x49, 0x4D) and i + 2 < n and blob[i + 1] == 0x89:
            modrm = blob[i + 2]
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            if rm == 5 and mod == 1:
                out.append(struct.unpack_from("<b", blob, i + 3)[0])
                i += 4
                continue
            if rm == 5 and mod == 2 and i + 7 <= n:
                out.append(struct.unpack_from("<i", blob, i + 3)[0])
                i += 7
                continue
        if blob[i] == 0x48 and i + 2 < n and blob[i + 1] == 0xC7:
            modrm = blob[i + 2]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm = modrm & 7
            if reg == 0 and rm == 5 and mod == 1 and i + 8 <= n:
                out.append(struct.unpack_from("<b", blob, i + 3)[0])
                i += 8
                continue
            if reg == 0 and rm == 5 and mod == 2 and i + 11 <= n:
                out.append(struct.unpack_from("<i", blob, i + 3)[0])
                i += 11
                continue
        i += 1
    return _unique_int(out)
