from __future__ import annotations

"""Read PE bytes at a virtual address. No sample names, no Ghidra."""

import struct
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple


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
_DIR_IMPORT = 1
_MAX_IMPORT_DESC = 512
_MAX_IMPORT_THUNK = 4096


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


SUBSYSTEM_UNKNOWN = 0
SUBSYSTEM_WINDOWS_GUI = 2
SUBSYSTEM_WINDOWS_CUI = 3


def pe_subsystem(blob: bytes | bytearray | None) -> int:
    """IMAGE_SUBSYSTEM from the optional header. 0 if not a PE."""
    raw = bytes(blob or b"")
    layout = _pe_opt(raw)
    if layout is None:
        return SUBSYSTEM_UNKNOWN
    _coff, _nsec, opt, _magic, _base = layout
    if opt + 70 > len(raw):
        return SUBSYSTEM_UNKNOWN
    return int(struct.unpack_from("<H", raw, opt + 68)[0])


def pe_is_console(blob: bytes | bytearray | None) -> bool:
    """Windows CUI subsystem. GUI and non-PE are not a CLI contract."""
    return pe_subsystem(blob) == SUBSYSTEM_WINDOWS_CUI


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


def _pe_cstr(blob: bytes, off: int, maxn: int = 256) -> str:
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off, min(len(blob), off + maxn))
    if end < 0:
        return ""
    raw = blob[off:end]
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError:
        return ""
    if not name or len(name) > 256:
        return ""
    low = name.lower()
    if low.endswith((".cpp", ".c", ".h", ".hpp", ".cc", ".cxx")):
        return ""
    if "/" in name or "\\" in name:
        return ""
    return name


def pe_iat_entries(blob: bytes | bytearray | None) -> List[Dict[str, Any]]:
    """IAT slots of this PE: va, name, dll, ordinal. Empty is not a pass."""
    data = bytes(blob or b"")
    layout = _pe_opt(data)
    if layout is None:
        return []
    _coff, _nsec, _opt, magic, image_base = layout
    rva, size = pe_data_directory(data, _DIR_IMPORT)
    if not rva or size < 20:
        return []
    desc_off = pe_rva_to_off(data, rva)
    if desc_off < 0:
        return []
    thunk_sz = 8 if magic == 0x20B else 4
    ordinal_bit = 1 << (63 if thunk_sz == 8 else 31)
    out: List[Dict[str, Any]] = []
    n = len(data)
    for di in range(min(_MAX_IMPORT_DESC, size // 20 + 1)):
        base = desc_off + di * 20
        if base + 20 > n:
            break
        ilt_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", data, base)
        if ilt_rva == 0 and iat_rva == 0 and name_rva == 0:
            break
        dll = _pe_cstr(data, pe_rva_to_off(data, name_rva)) if name_rva else ""
        names_rva = ilt_rva or iat_rva
        if not names_rva or not iat_rva:
            continue
        names_off = pe_rva_to_off(data, names_rva)
        if names_off < 0:
            continue
        for ti in range(_MAX_IMPORT_THUNK):
            tpos = names_off + ti * thunk_sz
            if tpos + thunk_sz > n:
                break
            thunk = (
                struct.unpack_from("<Q", data, tpos)[0]
                if thunk_sz == 8
                else struct.unpack_from("<I", data, tpos)[0]
            )
            if thunk == 0:
                break
            slot_va = int(image_base) + int(iat_rva) + ti * thunk_sz
            ordinal = 0
            name = ""
            if thunk & ordinal_bit:
                ordinal = int(thunk & 0xFFFF)
            else:
                ibn = pe_rva_to_off(data, int(thunk & 0x7FFFFFFF))
                if ibn >= 0 and ibn + 2 < n:
                    name = _pe_cstr(data, ibn + 2)
            out.append(
                {
                    "va": slot_va,
                    "va_hex": f"0x{slot_va:x}",
                    "name": name,
                    "dll": dll,
                    "ordinal": ordinal,
                }
            )
    return out


def pe_iat_name_by_va(blob: bytes | bytearray | None) -> Dict[int, str]:
    """IAT slot VA → import name. Missing name omitted."""
    out: Dict[int, str] = {}
    for ent in pe_iat_entries(blob):
        name = str(ent.get("name") or "")
        va = int(ent.get("va") or 0)
        if name and va:
            out[va] = name
    return out


def bytes_at_va(blob: bytes | bytearray | None, va: int, size: int) -> bytes:
    """Image bytes at virtual address. Empty if the PE/section misses."""
    data = bytes(blob or b"")
    if size <= 0 or va <= 0:
        return b""
    base = pe_image_base(data)
    if not base or va < base:
        return b""
    off = pe_rva_to_off(data, va - base)
    if off < 0:
        return b""
    return data[off : off + size]


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


# Microsoft x64 CALL + last writes to RCX/RDX/R8/R9. Walk instruction
# lengths so E8/FF /2 inside another encoding are not CALL.
_PFX = frozenset(
    {0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67}
)
_ARG_FROM_ID = {1: "rcx", 2: "rdx", 8: "r8", 9: "r9"}
_MODRM1 = frozenset(
    {
        *range(0x00, 0x04), *range(0x08, 0x0C), *range(0x10, 0x14),
        *range(0x18, 0x1C), *range(0x20, 0x24), *range(0x28, 0x2C),
        *range(0x30, 0x34), *range(0x38, 0x3C),
        0x62, 0x63, 0x69, 0x6B, *range(0x80, 0x90),
        0xC0, 0xC1, 0xC6, 0xC7, *range(0xD0, 0xD4), *range(0xD8, 0xE0),
        0xF6, 0xF7, 0xFE, 0xFF,
    }
)
_IMM8_1 = frozenset(
    {
        0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C,
        0x6A, *range(0x70, 0x80), *range(0xB0, 0xB8),
        0xA8, 0xCD, *range(0xE0, 0xE8), 0xEB,
        0x80, 0x82, 0x83, 0xC0, 0xC1, 0xC6, 0x6B,
    }
)
_IMM32_1 = frozenset(
    {
        0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D,
        0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9,
    }
)
_NOMOD_0F = frozenset(
    {
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0B,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37,
        0x77, 0xA0, 0xA1, 0xA8, 0xA9, 0xAA,
        *range(0xC8, 0xD0),
    }
)
_IMM32_0F = frozenset(range(0x80, 0x90))
_IMM8_0F = frozenset(
    {0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6}
)


def _i32(blob: bytes, off: int) -> int:
    v = struct.unpack_from("<i", blob, off)[0]
    return int(v)


def _u32(blob: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", blob, off)[0])


def _x64_prefixes(blob: bytes, offset: int) -> Tuple[int, int, bool, bool] | None:
    """(opcode_off, rex, p66, p67). None if truncated."""
    n = len(blob)
    i = offset
    rex = 0
    p66 = False
    p67 = False
    seen = 0
    while i < n and seen < 14:
        b = blob[i]
        if b in _PFX:
            if b == 0x66:
                p66 = True
            elif b == 0x67:
                p67 = True
            i += 1
            seen += 1
            continue
        if 0x40 <= b <= 0x4F:
            rex = b
            i += 1
            break
        break
    if i >= n:
        return None
    return i, rex, p66, p67


def _modrm_len(blob: bytes, pos: int) -> int | None:
    n = len(blob)
    if pos >= n:
        return None
    modrm = blob[pos]
    mod = (modrm >> 6) & 3
    rm = modrm & 7
    used = 1
    sib = None
    if mod != 3 and rm == 4:
        if pos + 1 >= n:
            return None
        sib = blob[pos + 1]
        used += 1
    if mod == 1:
        used += 1
    elif mod == 2:
        used += 4
    elif mod == 0:
        if rm == 5:
            used += 4
        elif rm == 4 and sib is not None and (sib & 7) == 5:
            used += 4
    if pos + used > n:
        return None
    return used


def _mem_disp(blob: bytes, modrm_pos: int) -> int:
    modrm = blob[modrm_pos]
    mod = (modrm >> 6) & 3
    rm = modrm & 7
    pos = modrm_pos + 1
    if mod != 3 and rm == 4:
        sib = blob[pos]
        pos += 1
        if mod == 0 and (sib & 7) == 5:
            return _i32(blob, pos)
    if mod == 1:
        return int(struct.unpack_from("<b", blob, pos)[0])
    if mod == 2:
        return _i32(blob, pos)
    if mod == 0 and rm == 5:
        return _i32(blob, pos)
    return 0


def _x64_insn_len(blob: bytes, offset: int) -> int | None:
    """Length of one x64 insn, or None if truncated/undecodable."""
    n = len(blob)
    pfx = _x64_prefixes(blob, offset)
    if pfx is None:
        return None
    i, rex, p66, p67 = pfx
    op = blob[i]
    i += 1
    two = False
    three_38 = False
    three_3a = False
    if op == 0x0F:
        two = True
        if i >= n:
            return None
        op = blob[i]
        i += 1
        if op == 0x38:
            three_38 = True
            if i >= n:
                return None
            op = blob[i]
            i += 1
        elif op == 0x3A:
            three_3a = True
            if i >= n:
                return None
            op = blob[i]
            i += 1
    elif op == 0xC5 and rex == 0:
        if i >= n:
            return None
        i += 1
        if i >= n:
            return None
        op = blob[i]
        i += 1
        two = True
    elif op == 0xC4 and rex == 0:
        if i + 1 >= n:
            return None
        mmmmm = blob[i] & 0x1F
        i += 2
        if i >= n:
            return None
        op = blob[i]
        i += 1
        two = True
        if mmmmm == 2:
            three_38 = True
        elif mmmmm == 3:
            three_3a = True
    need_modrm = False
    imm = 0
    if not two:
        if op in _MODRM1:
            need_modrm = True
        if (op & 0xF8) == 0xB8:
            imm = 8 if (rex & 8) else (2 if p66 else 4)
        elif op in _IMM8_1:
            imm = 1
        elif op in _IMM32_1:
            imm = 2 if p66 and op not in (0xE8, 0xE9) else 4
        elif op in (0xC2, 0xCA):
            imm = 2
        elif op == 0xC8:
            imm = 3
        elif op in (0xA0, 0xA1, 0xA2, 0xA3):
            imm = 4 if p67 else 8
        if op == 0xF6:
            imm = 0
        elif op == 0xF7:
            imm = 0
    elif three_3a:
        need_modrm = True
        imm = 1
    elif three_38:
        need_modrm = True
    elif op in _IMM32_0F:
        imm = 4
    elif op in _NOMOD_0F:
        need_modrm = False
    else:
        need_modrm = True
        if op in _IMM8_0F:
            imm = 1
    if need_modrm:
        extra = _modrm_len(blob, i)
        if extra is None:
            return None
        if not two and op in (0xF6, 0xF7):
            g = (blob[i] >> 3) & 7
            if g in (0, 1):
                imm = 1 if op == 0xF6 else (2 if p66 else 4)
        i += extra
    if i + imm > n:
        return None
    return i + imm - offset


def _reg_r(rex: int, modrm: int) -> int:
    return ((modrm >> 3) & 7) + (8 if rex & 0x4 else 0)


def _reg_b(rex: int, modrm: int) -> int:
    return (modrm & 7) + (8 if rex & 0x1 else 0)


def _reg_opcode(rex: int, op: int) -> int:
    return (op & 7) + (8 if rex & 0x1 else 0)


def _ms64_call_at(
    blob: bytes, off: int, ln: int, func_va: int
) -> Tuple[str, int] | None:
    pfx = _x64_prefixes(blob, off)
    if pfx is None:
        return None
    i, _rex, _p66, _p67 = pfx
    op = blob[i]
    if op == 0xE8 and ln >= 5:
        rel = _i32(blob, i + 1)
        callee = int(func_va) + off + ln + rel if func_va else 0
        return "rel", callee
    if op == 0xFF and i + 1 < off + ln:
        modrm = blob[i + 1]
        if ((modrm >> 3) & 7) != 2:
            return None
        rel = _mem_disp(blob, i + 1)
        callee = 0
        if func_va:
            callee = (int(func_va) + off + ln + rel) & 0xFFFFFFFFFFFFFFFF
        return "rip_mem", callee
    return None


def _ms64_apply_writes(
    blob: bytes,
    off: int,
    ln: int,
    writes: Dict[str, Dict[str, Any]],
    stack: List[int],
) -> None:
    """Last mov/xor/lea into RCX/RDX/R8/R9. Same filter as capstone."""
    pfx = _x64_prefixes(blob, off)
    if pfx is None:
        return
    i, rex, p66, _p67 = pfx
    if p66 or i >= off + ln:
        return
    op = blob[i]
    if op == 0x0F:
        return
    end = off + ln
    if op == 0x8D and i + 1 < end:
        modrm = blob[i + 1]
        dest = _ARG_FROM_ID.get(_reg_r(rex, modrm))
        if dest:
            writes[dest] = {"off": off, "lea": _mem_disp(blob, i + 1)}
        return
    if op == 0x8B and i + 1 < end:
        dest = _ARG_FROM_ID.get(_reg_r(rex, blob[i + 1]))
        if dest:
            writes[dest] = {"off": off}
        return
    if op == 0x89 and i + 1 < end:
        modrm = blob[i + 1]
        mod = (modrm >> 6) & 3
        if mod == 3:
            dest = _ARG_FROM_ID.get(_reg_b(rex, modrm))
            if dest:
                writes[dest] = {"off": off}
        elif (modrm & 7) == 4 and i + 2 < end:
            sib = blob[i + 2]
            if (sib & 7) == 4 and not (rex & 0x1):
                disp = _mem_disp(blob, i + 1)
                if disp not in stack:
                    stack.append(disp)
        return
    if op == 0x33 and i + 1 < end:
        modrm = blob[i + 1]
        dest = _ARG_FROM_ID.get(_reg_r(rex, modrm))
        if dest:
            rec: Dict[str, Any] = {"off": off}
            if ((modrm >> 6) & 3) == 3 and _reg_r(rex, modrm) == _reg_b(rex, modrm):
                rec["imm"] = 0
            writes[dest] = rec
        return
    if op == 0x31 and i + 1 < end:
        modrm = blob[i + 1]
        if ((modrm >> 6) & 3) == 3:
            dest = _ARG_FROM_ID.get(_reg_b(rex, modrm))
            if dest:
                rec = {"off": off}
                if _reg_r(rex, modrm) == _reg_b(rex, modrm):
                    rec["imm"] = 0
                writes[dest] = rec
        return
    if (op & 0xF8) == 0xB8 and i + 4 < end:
        dest = _ARG_FROM_ID.get(_reg_opcode(rex, op))
        if dest:
            writes[dest] = {"off": off, "imm": _u32(blob, i + 1) & 0xFFFFFFFF}
        return
    if op == 0xC7 and i + 5 <= end:
        modrm = blob[i + 1]
        if ((modrm >> 3) & 7) != 0:
            return
        if ((modrm >> 6) & 3) == 3:
            dest = _ARG_FROM_ID.get(_reg_b(rex, modrm))
            if dest:
                writes[dest] = {"off": off, "imm": _u32(blob, i + 2) & 0xFFFFFFFF}
        return


def scan_ms64_call_sites(
    code: bytes,
    *,
    func_va: int = 0,
    iat_by_va: Mapping[int, str] | None = None,
) -> List[Dict[str, Any]]:
    """CALL sites with MS x64 arg writes. Empty list is not a pass token.

    Relative CALL (E8) and CALL r/m64 (FF /2) at instruction starts.
    ``iat_name`` is filled only for rip-relative IAT slots present in
    ``iat_by_va`` (Q1). No C, no sample stems.
    """
    blob = code or b""
    names = iat_by_va or {}
    out: List[Dict[str, Any]] = []
    writes: Dict[str, Dict[str, Any]] = {}
    stack: List[int] = []
    i = 0
    n = len(blob)
    while i < n:
        ln = _x64_insn_len(blob, i)
        if not ln or i + ln > n:
            i += 1
            continue
        _ms64_apply_writes(blob, i, ln, writes, stack)
        call = _ms64_call_at(blob, i, ln, int(func_va) if func_va else 0)
        if call:
            kind, callee = call
            iat_name = ""
            if kind == "rip_mem" and callee:
                iat_name = str(names.get(int(callee)) or "")
            arg_regs = tuple(r for r in ("rcx", "rdx", "r8", "r9") if r in writes)
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
            out.append(
                {
                    "off": i,
                    "kind": kind,
                    "callee_va": f"0x{callee:x}" if callee else "",
                    "iat_name": iat_name,
                    "arg_regs": arg_regs,
                    "imm_slots": imm_slots,
                    "lea_slots": lea_slots,
                    "stack_disp": tuple(stack),
                }
            )
            writes = {}
            stack = []
        i += ln
    return out


def rip_lea_arg_vas(code: bytes, *, func_va: int = 0) -> List[int]:
    """RIP-relative LEA into RCX/RDX/R8/R9. Empty is not a pass token."""
    blob = code or b""
    out: List[int] = []
    i = 0
    n = len(blob)
    va0 = int(func_va) if func_va else 0
    while i < n:
        ln = _x64_insn_len(blob, i)
        if not ln or i + ln > n:
            i += 1
            continue
        pfx = _x64_prefixes(blob, i)
        if pfx is not None:
            op_off, rex, _p66, _p67 = pfx
            if op_off < i + ln and blob[op_off] == 0x8D and op_off + 1 < i + ln:
                modrm = blob[op_off + 1]
                dest = _ARG_FROM_ID.get(_reg_r(rex, modrm))
                if dest and ((modrm >> 6) & 3) == 0 and (modrm & 7) == 5:
                    disp = _mem_disp(blob, op_off + 1)
                    if va0:
                        out.append((va0 + i + ln + disp) & 0xFFFFFFFFFFFFFFFF)
        i += ln
    return out
