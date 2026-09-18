from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple


# Базовые includes для любого восстановленного C++.
BASE_INCLUDES: Tuple[str, ...] = (
    "#include <cstdint>",
    "#include <cmath>",
    "#include <cstdio>",
    "#include <cstring>",
    "#include <cstdarg>",
    "#include <iostream>",
    "#include <string>",
    "#include <vector>",
    "#include <chrono>",
    "#include <fstream>",
    "#include <new>",
)

_SIMPLE_USINGS: Tuple[Tuple[str, str], ...] = (
    ("byte", "using byte = std::uint8_t;"),
    ("uchar", "using uchar = unsigned char;"),
    ("ushort", "using ushort = unsigned short;"),
    ("uint", "using uint = unsigned int;"),
    ("ulong", "using ulong = unsigned long;"),
    ("ulonglong", "using ulonglong = unsigned long long;"),
    ("longlong", "using longlong = long long;"),
    ("undefined", "using undefined = std::uint8_t;"),
    ("undefined1", "using undefined1 = std::uint8_t;"),
    ("undefined2", "using undefined2 = std::uint16_t;"),
    ("undefined3", "using undefined3 = std::uint32_t;"),
    ("undefined4", "using undefined4 = std::uint32_t;"),
    ("undefined5", "using undefined5 = std::uint64_t;"),
    ("undefined6", "using undefined6 = std::uint64_t;"),
    ("undefined7", "using undefined7 = std::uint64_t;"),
    ("undefined8", "using undefined8 = std::uint64_t;"),
    ("int1", "using int1 = std::int8_t;"),
    ("int2", "using int2 = std::int16_t;"),
    ("int3", "using int3 = std::int32_t;"),
    ("int4", "using int4 = std::int32_t;"),
    ("int5", "using int5 = std::int64_t;"),
    ("int6", "using int6 = std::int64_t;"),
    ("int7", "using int7 = std::int64_t;"),
    ("int8", "using int8 = std::int64_t;"),
    ("uint1", "using uint1 = std::uint8_t;"),
    ("uint2", "using uint2 = std::uint16_t;"),
    ("uint3", "using uint3 = std::uint32_t;"),
    ("uint4", "using uint4 = std::uint32_t;"),
    ("uint5", "using uint5 = std::uint64_t;"),
    ("uint6", "using uint6 = std::uint64_t;"),
    ("uint7", "using uint7 = std::uint64_t;"),
    ("uint8", "using uint8 = std::uint64_t;"),
    ("__uint64", "using __uint64 = unsigned long long;"),
    ("pointer", "using pointer = void *;"),
    ("PBYTE", "using PBYTE = unsigned char *;"),
    ("PIMAGE_SECTION_HEADER", "using PIMAGE_SECTION_HEADER = void *;"),
    ("string", "using string = std::string;"),
    ("unsigned_char", "using unsigned_char = unsigned char;"),
    ("size_type", "using size_type = std::size_t;"),
    ("duration", "using duration = std::chrono::nanoseconds;"),
    ("rep", "using rep = long long;"),
    ("ostream", "using ostream = std::ostream;"),
    ("istream", "using istream = std::istream;"),
    ("ofstream", "using ofstream = std::ofstream;"),
    ("ifstream", "using ifstream = std::ifstream;"),
    ("fstream", "using fstream = std::fstream;"),
    ("iostream", "using iostream = std::iostream;"),
)

_WORD_USINGS: Tuple[Tuple[str, str], ...] = (
    ("value_type", "using value_type = ghidra_word;"),
    ("value_type_conflict", "using value_type_conflict = ghidra_word;"),
    ("reference", "using reference = ghidra_word;"),
    ("iterator", "using iterator = ghidra_word *;"),
    ("const_iterator", "using const_iterator = ghidra_word *;"),
    ("__const_iterator", "using __const_iterator = std::string::const_iterator;"),
    ("const_reference", "using const_reference = ghidra_word;"),
    ("__normal_iterator", "using __normal_iterator = ghidra_word;"),
    ("_Rb_tree_const_iterator", "using _Rb_tree_const_iterator = ghidra_word;"),
    ("__iterator", "using __iterator = ghidra_word;"),
    ("__node_type", "using __node_type = void;"),
    ("key_type", "using key_type = ghidra_word;"),
    ("mapped_type", "using mapped_type = ghidra_word;"),
    ("first_type", "using first_type = ghidra_word;"),
    ("allocator_type", "using allocator_type = ghidra_word;"),
)

_MINGW_PRINTF: Tuple[str, ...] = (
    "#ifndef __mingw_printf",
    "#define __mingw_printf printf",
    "#endif",
)

GHIDRA_ALIAS_NAMES: frozenset[str] = frozenset(
    n for n, _ln in (_SIMPLE_USINGS + _WORD_USINGS)
) | frozenset({"ghidra_word", "__mingw_printf"})


def _name_used(blob: str, name: str) -> bool:
    """True if `name` is a token, not the tail of std::string / uint64_t."""
    return bool(re.search(rf"(?<![:\w]){re.escape(name)}\b", blob or ""))


def _ghidra_word_lines(
    *,
    arrow: bool = True,
    inc: bool = True,
    index: bool = True,
    call: bool = True,
    pair: bool = True,
    stream: bool = True,
    star: bool = True,
) -> List[str]:
    lines = [
        "struct ghidra_word {",
        "  unsigned long long v{};",
        "  ghidra_word() = default;",
        "  ghidra_word(unsigned long long x) : v(x) {}",
        "  template<class T> explicit ghidra_word(T *p)",
        "      : v((unsigned long long)(std::uintptr_t)p) {}",
        "  template<class T> ghidra_word &operator=(T *p) {",
        "    v = (unsigned long long)(std::uintptr_t)p;",
        "    return *this;",
        "  }",
        "  ghidra_word &operator=(decltype(nullptr)) { v = 0; return *this; }",
        "  operator unsigned long long() const { return v; }",
        "  explicit operator bool() const { return v != 0; }",
        "  template<class T> operator T *() const {",
        "    return (T *)(std::uintptr_t)v;",
        "  }",
    ]
    if arrow:
        lines.append(
            "  void *operator->() const { return (void *)(std::uintptr_t)v; }"
        )
    if inc:
        lines.append("  ghidra_word &operator++() { ++v; return *this; }")
        lines.append(
            "  ghidra_word operator++(int) { ghidra_word t(*this); ++v; return t; }"
        )
    if index:
        lines.append("  template<class I> ghidra_word &operator[](I) { return *this; }")
    if star:
        lines.append("  ghidra_word operator*() const { return *this; }")
    if call:
        lines.append(
            "  template<class... A> ghidra_word operator()(A &&...) const { return {}; }"
        )
    if pair:
        lines.append("  unsigned long long first{};")
        lines.append("  unsigned long long second{};")
    lines.append("};")
    if stream:
        lines.append("inline std::ostream &operator<<(std::ostream &os, ghidra_word w) {")
        lines.append("  return os << w.v;")
        lines.append("}")
    return lines


def _idents_typed(blob: str, ty: str) -> list[str]:
    """Variables of `ty`, not functions that return it (`ghidra_word thunk(...)`)."""
    return re.findall(
        rf"(?<![:\w]){re.escape(ty)}\s+\**\s*([A-Za-z_]\w*)(?!\s*\()",
        blob or "",
    )


def _ident_called(blob: str, ident: str) -> bool:
    for m in re.finditer(rf"\b{re.escape(ident)}\s*\(", blob or ""):
        rest = blob[m.end() :]
        depth = 1
        i = 0
        while i < len(rest) and depth:
            if rest[i] == "(":
                depth += 1
            elif rest[i] == ")":
                depth -= 1
            i += 1
        after = rest[i:].lstrip()
        if after.startswith("{") or after.startswith("const") or after.startswith("override"):
            continue
        return True
    return False


def _word_features(blob: str, word_idents: list[str]) -> dict[str, bool]:
    call = any(_ident_called(blob, ident) for ident in word_idents)
    index = any(
        re.search(rf"\b{re.escape(ident)}\s*\[", blob or "") for ident in word_idents
    )
    arrow = any(
        re.search(rf"\b{re.escape(ident)}\s*->", blob or "") for ident in word_idents
    )
    inc = any(
        re.search(
            rf"(?:\+\+\s*{re.escape(ident)}\b|\b{re.escape(ident)}\s*\+\+)",
            blob or "",
        )
        for ident in word_idents
    )
    pair = any(
        re.search(
            rf"\b{re.escape(ident)}\s*\.\s*(?:first|second)\b",
            blob or "",
        )
        for ident in word_idents
    )
    stream = any(
        re.search(
            rf"(?:<<\s*{re.escape(ident)}\b|\b{re.escape(ident)}\s*<<)",
            blob or "",
        )
        for ident in word_idents
    )
    field_stream = bool(
        re.search(r"<<\s*[A-Za-z_]\w*\s*(?:->|\.)\s*[A-Za-z_]\w*", blob or "")
    )
    star = any(
        re.search(
            rf"(?<![\w.])\*\s*(?:\(\s*)*{re.escape(ident)}\b",
            blob or "",
        )
        for ident in word_idents
    )
    field_star = bool(
        re.search(r"\*\s*[A-Za-z_]\w*\s*->\s*[A-Za-z_]\w*", blob or "")
    )
    return {
        "call": call,
        "index": index,
        "arrow": arrow,
        "inc": inc,
        "pair": pair,
        "stream": stream or field_stream,
        "star": star or field_star,
    }


def typedefs_for_source(blob: str) -> List[str]:
    """Assembler glue for Ghidra spellings that actually appear in the TU."""
    text = blob or ""
    out: List[str] = []
    for name, line in _SIMPLE_USINGS:
        if _name_used(text, name):
            out.append(line)
    word_aliases: List[str] = []
    need_word = _name_used(text, "ghidra_word")
    for name, line in _WORD_USINGS:
        if _name_used(text, name):
            word_aliases.append(line)
            if "ghidra_word" in line:
                need_word = True
    if need_word:
        idents = _idents_typed(text, "ghidra_word")
        for name, line in _WORD_USINGS:
            if "ghidra_word" in line and _name_used(text, name):
                idents.extend(_idents_typed(text, name))
        feat = _word_features(text, idents)
        out.extend(_ghidra_word_lines(**feat))
        out.extend(word_aliases)
    elif word_aliases:
        out.extend(word_aliases)
    if _name_used(text, "__mingw_printf"):
        out.extend(_MINGW_PRINTF)
    return out


def missing_typedefs(have: str, extra: str) -> List[str]:
    """Glue names that `extra` still needs and `have` does not already spell.

    Scan only `extra` (restored bodies / stubs). The include preamble contains
    `<string>` / `<iostream>` tokens that must not become `using string`.
    Brace-only lines are kept when they close a block we just started.
    """
    needed = typedefs_for_source(extra or "")
    blob = have or ""
    out: List[str] = []
    depth = 0
    for ln in needed:
        stripped = ln.strip()
        brace_only = stripped in {"}", "};", "{"}
        if (not brace_only) and ln not in blob:
            out.append(ln)
            depth += ln.count("{") - ln.count("}")
            if depth < 0:
                depth = 0
        elif depth > 0:
            out.append(ln)
            depth += ln.count("{") - ln.count("}")
            if depth < 0:
                depth = 0
    return out


# Full catalog for DomainPack / tests that compile the glue itself.
GHIDRA_TYPEDEFS: Tuple[str, ...] = tuple(
    [ln for _n, ln in _SIMPLE_USINGS]
    + _ghidra_word_lines()
    + [ln for _n, ln in _WORD_USINGS]
    + list(_MINGW_PRINTF)
)


@dataclass(frozen=True)
class DomainPack:
    """Пreamble helpers only. No per-sample maps or includes."""

    name: str = "none"

    def preamble(self, comment: str) -> List[str]:
        lines = [comment]
        lines.extend(BASE_INCLUDES)
        lines.append("")
        lines.extend(GHIDRA_TYPEDEFS)
        lines.append("")
        return lines


NONE_PACK = DomainPack(name="none")
