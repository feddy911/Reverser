from __future__ import annotations

"""Second x64 decoder on func_bytes. Gym-only DisCo vs pe_image.

Q5 of the compare-oracles plan: GNU objdump intel text on the same blob as
pe_image LDE. Not a C decompiler. Not r2 pdc / RetDec / Hex-Rays. Missing
objdump returns None (eval skips that engine). Live restore stays p4.
runner.py does not consume this.
"""

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.analysis.call_sites import (
    SOURCE_BYTES,
    CallSite,
    CallSiteFacts,
    call_sites_from_bytes,
    compare_call_sites,
)

SOURCE_OBJDUMP = "objdump"

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
_ARG_REGS = ("rcx", "rdx", "r8", "r9")
_RE_INSN = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(.*)$"
)
_RE_RIP_DISP = re.compile(
    r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]",
    re.I,
)
_RE_LEA_DISP = re.compile(
    r"\[(?:rip|rbp|ebp)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\]",
    re.I,
)
_RE_HEX_VA = re.compile(r"^(0x[0-9a-fA-F]+)$", re.I)
_RE_COMMENT_VA = re.compile(r"#\s*(0x[0-9a-fA-F]+)", re.I)


def objdump_available() -> bool:
    return shutil.which("objdump") is not None


def _canon_reg(name: str) -> str:
    return _ARG_ALIASES.get((name or "").strip().lower().rstrip(","), "")


def _parse_int(tok: str) -> Optional[int]:
    t = (tok or "").strip().rstrip(",")
    if not t:
        return None
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 10)
    except ValueError:
        return None


def _signed_disp(n: int) -> int:
    """Objdump prints 32-bit RIP disp as unsigned 32 or 64 hex."""
    v = int(n) & 0xFFFFFFFFFFFFFFFF
    if v >= 1 << 63:
        return v - (1 << 64)
    if v > 0x7FFFFFFF:
        return v - (1 << 32)
    return v


def _split_ops(blob: str) -> List[str]:
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    for c in blob or "":
        if c == "[":
            depth += 1
        elif c == "]":
            depth = max(0, depth - 1)
        if c == "," and depth == 0:
            part = "".join(buf).strip()
            if part:
                out.append(part)
            buf = []
            continue
        buf.append(c)
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def _fmt_va(n: int) -> str:
    return f"0x{n & 0xFFFFFFFFFFFFFFFF:x}"


def _parse_objdump_intel(text: str, *, addr: str, func_va: int) -> List[CallSite]:
    """Instruction lines only. Continuation byte dumps have no mnemonic."""
    writes: Dict[str, Dict[str, Any]] = {}
    stack: List[int] = []
    sites: List[CallSite] = []
    for raw_line in (text or "").splitlines():
        m = _RE_INSN.match(raw_line)
        if not m:
            continue
        va = int(m.group(1), 16)
        hex_bytes = m.group(2).split()
        rest = m.group(3).strip()
        comment_va = ""
        cm = _RE_COMMENT_VA.search(rest)
        if cm:
            comment_va = _fmt_va(int(cm.group(1), 16))
        if "#" in rest:
            rest = rest.split("#", 1)[0].strip()
        if not rest:
            continue
        parts = rest.split(None, 1)
        mnem = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        off = va - func_va if func_va else va
        if mnem in ("mov", "xor") and args:
            ops = _split_ops(args)
            if len(ops) >= 2:
                dest = _canon_reg(ops[0])
                if dest:
                    rec: Dict[str, Any] = {"off": off}
                    if mnem == "xor" and _canon_reg(ops[1]) == dest:
                        rec["imm"] = 0
                    else:
                        imm = _parse_int(ops[1])
                        if imm is not None:
                            rec["imm"] = imm & 0xFFFFFFFF
                    writes[dest] = rec
        if mnem == "lea" and args:
            ops = _split_ops(args)
            if len(ops) >= 2:
                dest = _canon_reg(ops[0])
                disp_m = _RE_LEA_DISP.search(ops[1])
                if dest and disp_m:
                    sign, num = disp_m.group(1), disp_m.group(2)
                    disp = _parse_int(num) if num else 0
                    if disp is None:
                        disp = 0
                    else:
                        disp = _signed_disp(disp)
                    if sign == "-":
                        disp = -disp
                    writes[dest] = {"off": off, "lea": disp}
        if mnem != "call":
            continue
        ops = _split_ops(args)
        target = ops[0] if ops else ""
        kind = "rel"
        callee = ""
        if _RE_RIP_DISP.search(target) or "ptr" in target.lower():
            kind = "rip_mem"
            if comment_va:
                callee = comment_va
            else:
                rip_m = _RE_RIP_DISP.search(target)
                if rip_m:
                    disp = _parse_int(rip_m.group(2)) or 0
                    if rip_m.group(1) == "-":
                        disp = -disp
                    callee = _fmt_va(va + len(hex_bytes) + disp)
        elif _RE_HEX_VA.match(target.strip()):
            kind = "rel"
            callee = _fmt_va(int(target.strip(), 16))
        else:
            writes = {}
            stack = []
            continue
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
    return sites


def _run_objdump(blob: bytes, func_va: int) -> Optional[str]:
    exe = shutil.which("objdump")
    if not exe:
        return None
    raw = bytes(blob or b"")
    if not raw:
        return None
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "fn.bin"
        path.write_bytes(raw)
        vma = f"0x{int(func_va):x}" if func_va else "0"
        cmd = [
            exe,
            "-D",
            "-b",
            "binary",
            "-m",
            "i386:x86-64",
            "-M",
            "intel",
            f"--adjust-vma={vma}",
            str(path),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout or ""


def call_sites_from_objdump(
    blob: bytes | bytearray | None,
    *,
    addr: str = "",
    func_va: int = 0,
) -> Optional[CallSiteFacts]:
    """Decode x64 CALL sites via objdump. None if the tool or blob is missing."""
    raw = bytes(blob or b"")
    if not raw:
        return None
    va = func_va
    if not va and addr:
        try:
            va = int(str(addr), 16)
        except ValueError:
            va = 0
    text = _run_objdump(raw, va)
    if text is None:
        return None
    sites = tuple(_parse_objdump_intel(text, addr=addr, func_va=va))
    return CallSiteFacts(addr=addr, sites=sites, source=SOURCE_OBJDUMP)


def scan_and_objdump(
    blob: bytes | bytearray | None,
    *,
    addr: str = "",
    func_va: int = 0,
    dump_code: str = "",
    restored_code: str = "",
) -> Dict[str, Any]:
    """pe_image vs objdump. Never a prompt. C inputs are ignored."""
    scan = call_sites_from_bytes(blob, addr=addr, func_va=func_va)
    other = call_sites_from_objdump(blob, addr=addr, func_va=func_va)
    cmp = None
    if other is not None:
        raw_cmp = compare_call_sites(scan, other)
        cmp = {
            "n_scan": raw_cmp["n_scan"],
            "n_objdump": raw_cmp["n_capstone"],
            "agree": raw_cmp["agree"],
        }
    rec: Dict[str, Any] = {
        "scan": scan.to_dict(),
        "objdump": other.to_dict() if other else None,
        "objdump_available": objdump_available(),
        "compare": cmp,
        "source_scan": SOURCE_BYTES,
        "source_second": SOURCE_OBJDUMP if other else "",
    }
    dumped = json.dumps(
        {"scan": scan.to_dict(), "objdump": other.to_dict() if other else None}
    )
    rec["c_leaked_into_facts"] = (
        "****" in dumped
        or "ghidra_code" in dumped
        or "cpp_code" in dumped
        or "mpz_ptr" in dumped
        or "pdc" in dumped
    )
    rec["c_in_inputs"] = bool(dump_code or restored_code)
    rec["ignored_c"] = True
    return rec
