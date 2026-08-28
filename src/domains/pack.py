from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


# Базовые includes для любого восстановленного C++.
BASE_INCLUDES: Tuple[str, ...] = (
    "#include <cstdint>",
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

# Ghidra decompiler types — without these, compile-verify fails on restored C++.
GHIDRA_TYPEDEFS: Tuple[str, ...] = (
    "using byte = std::uint8_t;",
    "using uchar = unsigned char;",
    "using ushort = unsigned short;",
    "using uint = unsigned int;",
    "using ulong = unsigned long;",
    "using ulonglong = unsigned long long;",
    "using longlong = long long;",
    "using undefined = std::uint8_t;",
    "using undefined1 = std::uint8_t;",
    "using undefined2 = std::uint16_t;",
    "using undefined4 = std::uint32_t;",
    "using undefined8 = std::uint64_t;",
    "using int1 = std::int8_t;",
    "using int2 = std::int16_t;",
    "using int4 = std::int32_t;",
    "using int8 = std::int64_t;",
    "using uint1 = std::uint8_t;",
    "using uint2 = std::uint16_t;",
    "using uint4 = std::uint32_t;",
    "using uint8 = std::uint64_t;",
    "using pointer = void *;",
    "using PBYTE = unsigned char *;",
    "using PIMAGE_SECTION_HEADER = void *;",
    "using string = std::string;",
    "using unsigned_char = unsigned char;",
    "using size_type = std::size_t;",
    "using duration = std::chrono::nanoseconds;",
    "using rep = long long;",
    "using ostream = std::ostream;",
    "using istream = std::istream;",
    "using ofstream = std::ofstream;",
    "using ifstream = std::ifstream;",
    "using fstream = std::fstream;",
    "using iostream = std::iostream;",
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
    "  operator unsigned long long() const { return v; }",
    "  explicit operator bool() const { return v != 0; }",
    "  template<class T> operator T *() const {",
    "    return (T *)(std::uintptr_t)v;",
    "  }",
    "};",
    "using value_type = ghidra_word;",
    "using value_type_conflict = ghidra_word;",
    "using reference = ghidra_word *;",
    "using iterator = ghidra_word *;",
    "using key_type = ghidra_word;",
    "using mapped_type = ghidra_word;",
    "using first_type = ghidra_word;",
    "using allocator_type = ghidra_word;",
    "#ifndef CONCAT71",
    "#define CONCAT11(a, b) (((unsigned)(unsigned char)(a) << 8) | (unsigned char)(b))",
    "#define CONCAT71(a, b) (((unsigned long long)(a) << 8) | (unsigned char)(b))",
    "#define CONCAT17(a, b) (((unsigned long long)(unsigned char)(a) << 56) | (unsigned long long)(b))",
    "#define CONCAT44(a, b) (((unsigned long long)(unsigned)(a) << 32) | (unsigned)(b))",
    "#endif",
    "#ifndef __mingw_printf",
    "#define __mingw_printf printf",
    "#endif",
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
