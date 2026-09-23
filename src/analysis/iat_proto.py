from __future__ import annotations

"""IAT prototype sinks from THIS PE. Not Ghidra C, not samples/*.cpp.

Q1 of the compare-oracles plan: a platform dictionary (printf, mpz_*, CRT)
binds arity and slot types only for names that appear in this PE's import
table. Empty bag is not a pass token. Do not invent main. Do not read
gmp.h from samples. Live restore stays p4. Gym-only; runner does not
consume this.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from src.analysis.pe_image import pe_iat_entries

SOURCE_EMPTY = "empty"
SOURCE_PE_IAT = "pe_iat"
SOURCE_PE_IAT_PROTO = "pe_iat+proto"

_MS64 = ("rcx", "rdx", "r8", "r9")


@dataclass(frozen=True)
class IatProto:
    """Platform prototype for one imported name. Not a sample signature."""

    name: str
    arity: int
    variadic: bool
    slots: Tuple[Tuple[str, str], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "arity": self.arity,
            "variadic": self.variadic,
            "slots": [list(p) for p in self.slots],
        }


@dataclass(frozen=True)
class IatFacts:
    """IAT of this PE plus dictionary hits. Empty is not a pass."""

    entries: Tuple[Dict[str, Any], ...]
    protos: Tuple[IatProto, ...]
    source: str

    @property
    def has_entries(self) -> bool:
        return bool(self.entries)

    @property
    def has_protos(self) -> bool:
        return bool(self.protos)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entries": [dict(e) for e in self.entries],
            "protos": [p.to_dict() for p in self.protos],
            "source": self.source,
            "has_entries": self.has_entries,
            "has_protos": self.has_protos,
        }


def _proto(
    name: str,
    types: Sequence[str],
    *,
    variadic: bool = False,
) -> IatProto:
    slots = tuple((reg, ty) for reg, ty in zip(_MS64, types))
    return IatProto(
        name=name,
        arity=len(types),
        variadic=variadic,
        slots=slots,
    )


# Public C ABI. Not parsed from samples/gmp.h and not a restorer input.
_PROTO: Dict[str, IatProto] = {
    "printf": _proto("printf", ("char*",), variadic=True),
    "sprintf": _proto("sprintf", ("char*", "char*"), variadic=True),
    "snprintf": _proto("snprintf", ("char*", "size_t", "char*"), variadic=True),
    "fprintf": _proto("fprintf", ("FILE*", "char*"), variadic=True),
    "vprintf": _proto("vprintf", ("char*", "va_list")),
    "vfprintf": _proto("vfprintf", ("FILE*", "char*", "va_list")),
    "vsprintf": _proto("vsprintf", ("char*", "char*", "va_list")),
    "__stdio_common_vsprintf_s": _proto(
        "__stdio_common_vsprintf_s",
        ("unsigned long long", "char*", "size_t", "char*"),
        variadic=True,
    ),
    "puts": _proto("puts", ("char*",)),
    "putchar": _proto("putchar", ("int",)),
    "scanf": _proto("scanf", ("char*",), variadic=True),
    "malloc": _proto("malloc", ("size_t",)),
    "free": _proto("free", ("void*",)),
    "calloc": _proto("calloc", ("size_t", "size_t")),
    "realloc": _proto("realloc", ("void*", "size_t")),
    "memcpy": _proto("memcpy", ("void*", "void*", "size_t")),
    "memmove": _proto("memmove", ("void*", "void*", "size_t")),
    "memset": _proto("memset", ("void*", "int", "size_t")),
    "memcmp": _proto("memcmp", ("void*", "void*", "size_t")),
    "strlen": _proto("strlen", ("char*",)),
    "exit": _proto("exit", ("int",)),
    "abort": _proto("abort", ()),
    "__gmpz_init": _proto("__gmpz_init", ("mpz_ptr",)),
    "__gmpz_init2": _proto("__gmpz_init2", ("mpz_ptr", "unsigned long")),
    "__gmpz_clear": _proto("__gmpz_clear", ("mpz_ptr",)),
    "__gmpz_set": _proto("__gmpz_set", ("mpz_ptr", "mpz_srcptr")),
    "__gmpz_set_ui": _proto("__gmpz_set_ui", ("mpz_ptr", "unsigned long")),
    "__gmpz_set_si": _proto("__gmpz_set_si", ("mpz_ptr", "long")),
    "__gmpz_set_str": _proto("__gmpz_set_str", ("mpz_ptr", "char*", "int")),
    "__gmpz_get_str": _proto("__gmpz_get_str", ("char*", "int", "mpz_srcptr")),
    "__gmpz_get_ui": _proto("__gmpz_get_ui", ("mpz_srcptr",)),
    "__gmpz_get_si": _proto("__gmpz_get_si", ("mpz_srcptr",)),
    "__gmpz_add": _proto("__gmpz_add", ("mpz_ptr", "mpz_srcptr", "mpz_srcptr")),
    "__gmpz_add_ui": _proto(
        "__gmpz_add_ui", ("mpz_ptr", "mpz_srcptr", "unsigned long")
    ),
    "__gmpz_sub": _proto("__gmpz_sub", ("mpz_ptr", "mpz_srcptr", "mpz_srcptr")),
    "__gmpz_sub_ui": _proto(
        "__gmpz_sub_ui", ("mpz_ptr", "mpz_srcptr", "unsigned long")
    ),
    "__gmpz_mul": _proto("__gmpz_mul", ("mpz_ptr", "mpz_srcptr", "mpz_srcptr")),
    "__gmpz_mul_ui": _proto(
        "__gmpz_mul_ui", ("mpz_ptr", "mpz_srcptr", "unsigned long")
    ),
    "__gmpz_tdiv_q": _proto(
        "__gmpz_tdiv_q", ("mpz_ptr", "mpz_srcptr", "mpz_srcptr")
    ),
    "__gmpz_tdiv_r": _proto(
        "__gmpz_tdiv_r", ("mpz_ptr", "mpz_srcptr", "mpz_srcptr")
    ),
    "__gmpz_cmp": _proto("__gmpz_cmp", ("mpz_srcptr", "mpz_srcptr")),
    "__gmpz_cmp_ui": _proto("__gmpz_cmp_ui", ("mpz_srcptr", "unsigned long")),
    "__gmpz_cmp_si": _proto("__gmpz_cmp_si", ("mpz_srcptr", "long")),
    "__gmpz_neg": _proto("__gmpz_neg", ("mpz_ptr", "mpz_srcptr")),
    "__gmpz_abs": _proto("__gmpz_abs", ("mpz_ptr", "mpz_srcptr")),
    "__gmpz_swap": _proto("__gmpz_swap", ("mpz_ptr", "mpz_ptr")),
    "__gmpz_sizeinbase": _proto("__gmpz_sizeinbase", ("mpz_srcptr", "int")),
}

_ALIAS = {
    "mpz_init": "__gmpz_init",
    "mpz_init2": "__gmpz_init2",
    "mpz_clear": "__gmpz_clear",
    "mpz_set": "__gmpz_set",
    "mpz_set_ui": "__gmpz_set_ui",
    "mpz_set_si": "__gmpz_set_si",
    "mpz_set_str": "__gmpz_set_str",
    "mpz_get_str": "__gmpz_get_str",
    "mpz_get_ui": "__gmpz_get_ui",
    "mpz_get_si": "__gmpz_get_si",
    "mpz_add": "__gmpz_add",
    "mpz_add_ui": "__gmpz_add_ui",
    "mpz_sub": "__gmpz_sub",
    "mpz_sub_ui": "__gmpz_sub_ui",
    "mpz_mul": "__gmpz_mul",
    "mpz_mul_ui": "__gmpz_mul_ui",
    "mpz_tdiv_q": "__gmpz_tdiv_q",
    "mpz_tdiv_r": "__gmpz_tdiv_r",
    "mpz_cmp": "__gmpz_cmp",
    "mpz_cmp_ui": "__gmpz_cmp_ui",
    "mpz_cmp_si": "__gmpz_cmp_si",
    "mpz_neg": "__gmpz_neg",
    "mpz_abs": "__gmpz_abs",
    "mpz_swap": "__gmpz_swap",
    "mpz_sizeinbase": "__gmpz_sizeinbase",
}


def _canon_import_name(name: str) -> str:
    n = (name or "").strip()
    if not n or n.lower() == "main":
        return ""
    if n in _PROTO:
        return n
    alias = _ALIAS.get(n, "")
    if alias:
        return alias
    if n.startswith("mpz_") and ("__gmpz_" + n[4:]) in _PROTO:
        return "__gmpz_" + n[4:]
    return ""


def proto_for_name(name: str) -> Optional[IatProto]:
    """Platform proto or None. main and unknown names stay None."""
    key = _canon_import_name(name)
    if not key:
        return None
    return _PROTO.get(key)


def _empty() -> IatFacts:
    return IatFacts((), (), SOURCE_EMPTY)


def iat_facts_from_pe_bytes(blob: bytes | bytearray | None) -> IatFacts:
    """Bind protos only for names in this PE's IAT. Dictionary miss stays out."""
    raw = bytes(blob or b"")
    entries = tuple(pe_iat_entries(raw))
    if not entries:
        return _empty()
    protos: list[IatProto] = []
    seen = set()
    for ent in entries:
        name = str(ent.get("name") or "")
        if name in seen:
            continue
        proto = proto_for_name(name)
        if proto is None:
            continue
        seen.add(name)
        protos.append(
            IatProto(
                name=name,
                arity=proto.arity,
                variadic=proto.variadic,
                slots=proto.slots,
            )
        )
    source = SOURCE_PE_IAT_PROTO if protos else SOURCE_PE_IAT
    return IatFacts(entries=entries, protos=tuple(protos), source=source)


def iat_facts_from_exe(path: str | Path) -> IatFacts:
    p = Path(path) if path else Path()
    if not p.is_file():
        return _empty()
    return iat_facts_from_pe_bytes(p.read_bytes())


def iat_name_by_va(blob: bytes | bytearray | None) -> Dict[int, str]:
    out: Dict[int, str] = {}
    for ent in pe_iat_entries(bytes(blob or b"")):
        name = str(ent.get("name") or "")
        va = int(ent.get("va") or 0)
        if name and va:
            out[va] = name
    return out


def proto_by_import_name(facts: IatFacts) -> Mapping[str, IatProto]:
    return {p.name: p for p in facts.protos}
