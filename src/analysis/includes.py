from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from src.analysis.platform import is_system_dll
from src.domains.pack import BASE_INCLUDES, GHIDRA_TYPEDEFS

# Имя внешней функции / префикс -> include
_CALL_INCLUDE_RULES: List[tuple] = [
    (re.compile(r"^(printf|sprintf|fprintf|scanf|puts|putchar|snprintf)$"), "#include <cstdio>"),
    (re.compile(
        r"^(sqrt|pow|fabs|sin|cos|tan|log|exp|floor|ceil|round|hypot|fmod|atan2|asin|acos)$"
    ), "#include <cmath>"),
    (re.compile(r"^(memcpy|memmove|memset|memcmp|strlen|strcpy|strncpy|strcmp|strcat)$"), "#include <cstring>"),
    (re.compile(r"^(malloc|free|calloc|realloc|atoi|exit|abort)$"), "#include <cstdlib>"),
    (re.compile(r"^(open|read|write|close|stat)$"), "#include <unistd.h>"),
    (re.compile(r"^operator<<"), "#include <iostream>"),
    (re.compile(r"^(std::)?(cout|cerr|cin)$"), "#include <iostream>"),
    (re.compile(r"^mpz_|^__gmpz_"), "#include <gmp.h>"),
    (re.compile(r"^mpf_|^__gmpf_"), "#include <gmp.h>"),
    (re.compile(r"^mpfr_|^__gmpfr_"), "#include <mpfr.h>"),
]

# Domain DLL stem -> include
_DLL_INCLUDE: Dict[str, str] = {
    "gmp": "#include <gmp.h>",
    "libgmp": "#include <gmp.h>",
    "libgmp-10": "#include <gmp.h>",
    "mpfr": "#include <mpfr.h>",
    "ssl": "#include <openssl/ssl.h>",
    "crypto": "#include <openssl/crypto.h>",
    "libssl": "#include <openssl/ssl.h>",
    "libcrypto": "#include <openssl/crypto.h>",
    "z": "#include <zlib.h>",
    "zlib": "#include <zlib.h>",
    "zlib1": "#include <zlib.h>",
}


def _norm_dll_stem(name: str) -> str:
    n = (name or "").strip().lower()
    for suf in (".dll", ".so", ".dylib", ".exe"):
        if n.endswith(suf):
            n = n[: -len(suf)]
    # libfoo.so.1.2 -> libfoo / foo
    n = re.sub(r"\.so(\.\d+)*$", "", n)
    if n.startswith("lib") and len(n) > 3:
        return n
    return n


def includes_from_calls(ext_calls: Iterable[str]) -> Set[str]:
    found: Set[str] = set()
    for raw in ext_calls or []:
        name = (raw or "").strip()
        if not name:
            continue
        for rx, inc in _CALL_INCLUDE_RULES:
            if rx.search(name):
                found.add(inc)
                break
    return found


def includes_from_dlls(dlls: Iterable[str]) -> Set[str]:
    found: Set[str] = set()
    for d in dlls or []:
        if not d or is_system_dll(d):
            continue
        stem = _norm_dll_stem(d)
        if stem in _DLL_INCLUDE:
            found.add(_DLL_INCLUDE[stem])
            continue
        # libgmp-10 -> try prefix keys
        for key, inc in _DLL_INCLUDE.items():
            if stem == key or stem.startswith(key + "-") or stem.startswith("lib" + key):
                found.add(inc)
                break
    return found


_CODE_INCLUDE_RULES: List[tuple] = [
    (re.compile(r"\bstd::\s*(sort|stable_sort|partial_sort|equal|find|copy|fill|min|max|swap|reverse|count)\b"),
     "#include <algorithm>"),
    (re.compile(r"\b(?:std::)?swap\s*\("), "#include <utility>"),
    (re.compile(r"\b(?:memcpy|memmove|memset|memcmp|strlen|strcpy|strncpy|strcmp|strcat)\s*\("),
     "#include <cstring>"),
    (re.compile(r"\b(?:printf|sprintf|snprintf|fprintf|puts|putchar)\s*\("),
     "#include <cstdio>"),
    (re.compile(r"\b(?:atoi|malloc|free|calloc|realloc|exit|abort)\s*\("),
     "#include <cstdlib>"),
    (re.compile(r"\b(?:std::)?initializer_list\b"), "#include <initializer_list>"),
    (re.compile(
        r"\b(?:std::)?(sqrt|pow|fabs|sin|cos|tan|log|exp|floor|ceil|round|hypot|fmod|atan2|asin|acos)\s*\("
    ), "#include <cmath>"),
    (re.compile(r"\bstd::unordered_map\b"), "#include <unordered_map>"),
    (re.compile(r"\bstd::unordered_set\b"), "#include <unordered_set>"),
    (re.compile(r"\b(?:std::)?unordered_map\s*<"), "#include <unordered_map>"),
    (re.compile(r"\b(?:std::)?unordered_set\s*<"), "#include <unordered_set>"),
    (re.compile(r"\b(?:std::)?map\s*<"), "#include <map>"),
    (re.compile(r"\b(?:std::)?multiset\s*<"), "#include <set>"),
    (re.compile(r"\b(?:std::)?set\s*<"), "#include <set>"),
    (re.compile(r"\b(?:std::)?list\s*<"), "#include <list>"),
    (re.compile(r"\b(?:std::)?deque\s*<"), "#include <deque>"),
    (re.compile(r"\b(?:std::)?pair\s*<"), "#include <utility>"),
    (re.compile(r"\b(?:std::)?optional\s*<"), "#include <optional>"),
    (re.compile(r"\b(?:std::)?(ofstream|ifstream|fstream)\b"), "#include <fstream>"),
    (re.compile(r"\bstd::set\b"), "#include <set>"),
    (re.compile(r"\bstd::optional\b"), "#include <optional>"),
]


def includes_from_source(text: str) -> Set[str]:
    """Headers implied by tokens in restored C++ (not only Ghidra ext_calls)."""
    found: Set[str] = set()
    blob = text or ""
    for rx, inc in _CODE_INCLUDE_RULES:
        if rx.search(blob):
            found.add(inc)
    return found


def collect_dynamic_includes(
    restored: Sequence[Dict[str, Any]],
    functions: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[str]:
    """Собрать #include для preamble из вызовов и DLL бинарника."""
    incs: Set[str] = set(BASE_INCLUDES)

    for r in restored or []:
        incs |= includes_from_calls(r.get("ext_calls") or [])
        incs |= includes_from_source(r.get("cpp_code") or "")
        for inc in r.get("includes") or []:
            s = str(inc).strip()
            if not s:
                continue
            if s.startswith("#include"):
                incs.add(s)
            elif s.startswith("<") or s.startswith('"'):
                incs.add(f"#include {s}")
            else:
                incs.add(f"#include <{s}>")

    for f in functions or []:
        incs |= includes_from_calls(f.get("ext_calls") or [])
        incs |= includes_from_dlls(f.get("ext_dlls") or [])

    # Стабильный порядок: BASE first, then the rest alpha
    base_set = set(BASE_INCLUDES)
    ordered = [x for x in BASE_INCLUDES if x in incs]
    rest = sorted(x for x in incs if x not in base_set)
    return ordered + rest


def make_preamble(
    comment: str,
    restored: Sequence[Dict[str, Any]],
    functions: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[str]:
    lines = [comment]
    lines.extend(collect_dynamic_includes(restored, functions))
    lines.append("")
    lines.extend(GHIDRA_TYPEDEFS)
    lines.append("")
    return lines
