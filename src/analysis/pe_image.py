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
