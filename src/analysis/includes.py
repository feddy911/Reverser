from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from src.analysis.platform import is_system_dll
from src.domains.pack import BASE_INCLUDES, DomainPack

# Имя внешней функции / префикс -> include
_CALL_INCLUDE_RULES: List[tuple] = [
    (re.compile(r"^(printf|sprintf|fprintf|scanf|puts|putchar|snprintf)$"), "#include <cstdio>"),
    (re.compile(r"^(memcpy|memset|memcmp|strlen|strcpy|strncpy|strcmp)$"), "#include <cstring>"),
    (re.compile(r"^(malloc|free|calloc|realloc|atoi|exit|abort)$"), "#include <cstdlib>"),
    (re.compile(r"^(open|read|write|close|stat)$"), "#include <unistd.h>"),
    (re.compile(r"^operator<<"), "#include <iostream>"),
    (re.compile(r"^(std::)?(cout|cerr|cin)$"), "#include <iostream>"),
    (re.compile(r"^mpz_|^__gmpz_"), "#include <gmp.h>"),
    (re.compile(r"^mpf_|^__gmpf_"), "#include <gmp.h>"),
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


def collect_dynamic_includes(
    restored: Sequence[Dict[str, Any]],
    functions: Optional[Sequence[Dict[str, Any]]] = None,
    pack: Optional[DomainPack] = None,
) -> List[str]:
    """Собрать #include для preamble из вызовов/DLL + domain pack."""
    incs: Set[str] = set(BASE_INCLUDES)
    if pack:
        incs.update(pack.extra_includes)

    for r in restored or []:
        incs |= includes_from_calls(r.get("ext_calls") or [])
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
    pack: Optional[DomainPack] = None,
) -> List[str]:
    lines = [comment]
    lines.extend(collect_dynamic_includes(restored, functions, pack))
    lines.append("")
    return lines
