from __future__ import annotations

import logging
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("revllm.triage")

# PE Machine
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01C0
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# ELF e_machine
EM_386 = 3
EM_X86_64 = 62
EM_ARM = 40
EM_AARCH64 = 183

UPX_MARKERS = (b"UPX!", b"UPX0", b"UPX1", b"UPX2")
MSVC_STRING_HINTS = (
    "Microsoft Visual C++",
    "Runtime Error!",
    "RSDS",
    ".pdb",
)
GCC_STRING_HINTS = (
    "GCC:",
    "GNU C",
    ".gcc_except_table",
)
CLANG_STRING_HINTS = ("clang version", "Apple clang")
DEBUG_NAME_RE = re.compile(
    r"(_RTC_|__CheckForDebuggerJustMyCode|_security_check_cookie|__GSHandlerCheck)",
)
PACKER_NAME_RE = re.compile(r"(upx|themida|vmprotect|aspack|fsg|petite)", re.I)


@dataclass
class BinaryTriage:
    """Fingerprint бинарника для выбора промпт-профиля и эвристик."""

    format: str = "unknown"  # pe | elf | macho | unknown
    arch: str = "unknown"  # x86 | x64 | arm | arm64 | unknown
    bits: int = 0
    endian: str = "unknown"  # le | be | unknown
    compiler: str = "unknown"  # msvc | gcc | clang | unknown
    build: str = "unknown"  # debug | release | unknown
    packed_suspect: bool = False
    profile: str = "generic"
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def summary(self) -> str:
        parts = [
            self.format.upper() if self.format != "unknown" else "BIN",
            f"{self.arch}/{self.bits or '?'}",
            self.compiler,
            self.build,
        ]
        if self.packed_suspect:
            parts.append("packed?")
        return " ".join(parts)


def _add(ev: List[str], msg: str) -> None:
    if msg not in ev:
        ev.append(msg)


def _arch_from_pe_machine(machine: int) -> tuple[str, int]:
    if machine == IMAGE_FILE_MACHINE_AMD64:
        return "x64", 64
    if machine == IMAGE_FILE_MACHINE_I386:
        return "x86", 32
    if machine == IMAGE_FILE_MACHINE_ARM64:
        return "arm64", 64
    if machine == IMAGE_FILE_MACHINE_ARM:
        return "arm", 32
    return "unknown", 0


def _arch_from_elf_machine(machine: int) -> tuple[str, int]:
    if machine == EM_X86_64:
        return "x64", 64
    if machine == EM_386:
        return "x86", 32
    if machine == EM_AARCH64:
        return "arm64", 64
    if machine == EM_ARM:
        return "arm", 32
    return "unknown", 0


def _triage_pe(data: bytes, ev: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "pe", "endian": "le"}
    if len(data) < 0x40:
        _add(ev, "PE too short")
        return out
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 6 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        _add(ev, "MZ present but PE signature missing")
        out["format"] = "unknown"
        return out
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    arch, bits = _arch_from_pe_machine(machine)
    out["arch"] = arch
    out["bits"] = bits
    _add(ev, f"PE machine=0x{machine:04X} -> {arch}/{bits}")

    # Optional header magic: PE32=0x10B, PE32+=0x20B
    opt_off = e_lfanew + 24
    if opt_off + 2 <= len(data):
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x20B:
            out["bits"] = 64
            if out["arch"] == "unknown":
                out["arch"] = "x64"
        elif magic == 0x10B:
            out["bits"] = 32

    # Rich header → MSVC toolchain
    if b"Rich" in data[:0x400]:
        out["compiler"] = "msvc"
        _add(ev, "PE Rich header -> msvc")

    return out


def _triage_elf(data: bytes, ev: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "elf"}
    if len(data) < 52:
        _add(ev, "ELF too short")
        return out
    ei_class = data[4]
    ei_data = data[5]
    out["bits"] = 64 if ei_class == 2 else 32 if ei_class == 1 else 0
    out["endian"] = "le" if ei_data == 1 else "be" if ei_data == 2 else "unknown"
    endian_fmt = "<" if out["endian"] == "le" else ">"
    machine = struct.unpack_from(endian_fmt + "H", data, 18)[0]
    arch, bits = _arch_from_elf_machine(machine)
    out["arch"] = arch
    if bits:
        out["bits"] = bits
    _add(ev, f"ELF e_machine={machine} -> {arch}/{out['bits']}")
    return out


def _triage_macho(data: bytes, ev: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"format": "macho", "endian": "le"}
    magic = struct.unpack_from("<I", data, 0)[0]
    # MH_MAGIC_64 / CIGAM, MH_MAGIC / CIGAM
    if magic in (0xFEEDFACF, 0xCFFAEDFE):
        out["bits"] = 64
        out["arch"] = "x64"
        _add(ev, "Mach-O 64-bit")
    elif magic in (0xFEEDFACE, 0xCEFAEDFE):
        out["bits"] = 32
        out["arch"] = "x86"
        _add(ev, "Mach-O 32-bit")
    if magic in (0xCFFAEDFE, 0xCEFAEDFE):
        out["endian"] = "be"
    return out


def _scan_bytes_hints(data: bytes, out: Dict[str, Any], ev: List[str]) -> None:
    sample = data[: min(len(data), 2_000_000)]
    text = sample.decode("latin-1", errors="ignore")

    if any(m in sample for m in UPX_MARKERS) or PACKER_NAME_RE.search(text[:50000]):
        out["packed_suspect"] = True
        _add(ev, "packer marker (UPX/name)")

    if out.get("compiler") == "unknown" or not out.get("compiler"):
        if any(h in text for h in MSVC_STRING_HINTS) or b"vcruntime" in sample.lower():
            out["compiler"] = "msvc"
            _add(ev, "MSVC string/import hint")
        elif any(h in text for h in CLANG_STRING_HINTS):
            out["compiler"] = "clang"
            _add(ev, "clang version string")
        elif any(h in text for h in GCC_STRING_HINTS) or b"libgcc" in sample:
            out["compiler"] = "gcc"
            _add(ev, "GCC string hint")

    # Debug vs release heuristics
    debug_hits = 0
    if b".pdb" in sample or b"RSDS" in sample:
        debug_hits += 2
        _add(ev, "PDB/RSDS present")
    if b"_RTC_" in sample or b"__CheckForDebuggerJustMyCode" in sample:
        debug_hits += 2
        _add(ev, "RTC/JustMyCode symbols")
    if b"0xcccccccc" in sample or b"\xcc\xcc\xcc\xcc" in sample[:65536]:
        debug_hits += 1
        _add(ev, "MSVC debug fill pattern")
    if debug_hits >= 2:
        out["build"] = "debug"
    elif out.get("format") == "pe" and out.get("compiler") == "msvc":
        out["build"] = "release"
        _add(ev, "MSVC PE without strong debug markers -> release")


def _enrich_from_ghidra(ghidra: Optional[Dict[str, Any]], out: Dict[str, Any], ev: List[str]) -> None:
    if not ghidra:
        return
    names = " ".join(
        (f.get("name") or "") for f in (ghidra.get("functions") or [])[:2000]
    )
    imports = " ".join(str(x) for x in (ghidra.get("imports") or [])[:500]).lower()
    dlls = set()
    for f in ghidra.get("functions") or []:
        for d in f.get("ext_dlls") or []:
            dlls.add((d or "").lower())

    if DEBUG_NAME_RE.search(names):
        out["build"] = "debug"
        _add(ev, "Ghidra: RTC/GS debug symbols")

    if any("vcruntime" in d or "msvcp" in d or "ucrtbase" in d for d in dlls):
        if out.get("compiler") in (None, "unknown"):
            out["compiler"] = "msvc"
            _add(ev, "Ghidra: MSVC CRT DLLs")
    if "libstdc++" in imports or any("libstdc++" in d or "libgcc" in d for d in dlls):
        if out.get("compiler") in (None, "unknown"):
            out["compiler"] = "gcc"
            _add(ev, "Ghidra: libstdc++/libgcc")
    if any("libc++" in d for d in dlls):
        if out.get("compiler") in (None, "unknown"):
            out["compiler"] = "clang"
            _add(ev, "Ghidra: libc++")


def select_profile(triage: BinaryTriage) -> str:
    """Имя промпт-профиля restorer/polisher."""
    fmt, comp, arch, build = triage.format, triage.compiler, triage.arch, triage.build
    if fmt == "pe" and comp == "msvc":
        if arch in ("x64", "x86"):
            return f"msvc_{arch}_{build if build != 'unknown' else 'release'}"
        return "msvc_generic"
    if fmt == "pe" and comp in ("gcc", "clang"):
        # MinGW / Clang-CL PE
        return f"{comp}_pe_{arch if arch != 'unknown' else 'generic'}"
    if fmt == "elf" and comp in ("gcc", "clang"):
        return f"{comp}_elf_{arch if arch != 'unknown' else 'generic'}"
    if fmt == "elf":
        return "elf_generic"
    if fmt == "macho":
        return "macho_generic"
    if fmt == "pe":
        return "pe_generic"
    return "generic"


def triage_binary(
    binary_path: Path,
    ghidra: Optional[Dict[str, Any]] = None,
) -> BinaryTriage:
    """Статический triage файла (+ опционально обогащение из Ghidra dump)."""
    path = Path(binary_path)
    ev: List[str] = []
    out: Dict[str, Any] = {
        "format": "unknown",
        "arch": "unknown",
        "bits": 0,
        "endian": "unknown",
        "compiler": "unknown",
        "build": "unknown",
        "packed_suspect": False,
    }

    try:
        data = path.read_bytes()
    except OSError as exc:
        _add(ev, f"cannot read binary: {exc}")
        t = BinaryTriage(evidence=ev, profile="generic")
        return t

    if len(data) >= 2 and data[:2] == b"MZ":
        out.update(_triage_pe(data, ev))
    elif len(data) >= 4 and data[:4] == b"\x7fELF":
        out.update(_triage_elf(data, ev))
    elif len(data) >= 4 and data[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ):
        out.update(_triage_macho(data, ev))
    else:
        _add(ev, "unknown file magic")

    _scan_bytes_hints(data, out, ev)
    _enrich_from_ghidra(ghidra, out, ev)

    triage = BinaryTriage(
        format=str(out.get("format", "unknown")),
        arch=str(out.get("arch", "unknown")),
        bits=int(out.get("bits") or 0),
        endian=str(out.get("endian", "unknown")),
        compiler=str(out.get("compiler", "unknown")),
        build=str(out.get("build", "unknown")),
        packed_suspect=bool(out.get("packed_suspect")),
        evidence=ev,
    )
    triage.profile = select_profile(triage)
    _add(ev, f"profile={triage.profile}")
    logger.info("Triage: %s (%s)", triage.summary, triage.profile)
    return triage
