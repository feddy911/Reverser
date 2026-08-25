from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

# --- словари -------------------------------------------------------------

# GMP: MSVC-импорт приходит как "__gmpz_*", в коде встречается "__gmpz_*("/"mpz_*("
GMP_NAME_RE = re.compile(r"^_{0,2}g?mp(?:z|f|q|n)_", re.IGNORECASE)
GMP_CODE_RE = re.compile(r"\b_{0,2}g?mp(?:z|f|q|n)_[a-z0-9_]+(?=\s*\()", re.IGNORECASE)

# C stdio — маркер пользовательского IO
STDIO_IMPORTS: Set[str] = {
    "printf", "puts", "putchar", "scanf", "fprintf", "sprintf",
    "vprintf", "vfprintf", "vsprintf",
    "__stdio_common_vfprintf", "__stdio_common_vsprintf_s",
    "__acrt_iob_func",
}

# файловый IO (пользуется и STL filebuf — держим отдельным признаком)
FILE_IMPORTS: Set[str] = {
    "fopen", "fclose", "fread", "fwrite", "fgetc", "fputc",
    "fgets", "fputs", "setvbuf", "fgetpos", "fsetpos", "_fseeki64", "ungetc",
}

CRT_IMPORTS: Set[str] = {
    "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
    "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress",
    "VirtualAlloc", "VirtualFree", "HeapAlloc", "HeapFree",
    "TlsAlloc", "TlsFree", "Sleep", "TerminateProcess",
    "_CrtDbgReport", "_CrtDbgReportW", "_invalid_parameter", "_invalid_parameter_noinfo",
}

MIN_LITERAL_LEN = 6

# [хотфикс 2.5] debug-строки MSVC: пути исходников STL/CRT — не маркер user-кода
PATH_RE = re.compile(
    r"(:\\|\\include\\|Program Files|_work\\|\.(cpp|c|h|hpp|cc|cxx|inl|dll|exe|pdb)$)",
    re.IGNORECASE,
)

def c_escape(s: str) -> str:
    """Приводит строку к виду, в котором Ghidra печатает литерал в C-коде."""
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


class FeatureIndex:
    """Индексы по всему дампу: литералы, имена, thunk-карта, граф вызовов."""

    def __init__(self, strings, functions, thunks=None):
        self.all_functions: List[Dict[str, Any]] = list(functions or [])

        seen: Set[str] = set()
        self.lit_needles: List[Tuple[str, str]] = []
        for s in strings or []:
            v = s.get("string") or ""
            if len(v) >= MIN_LITERAL_LEN and v not in seen and not PATH_RE.search(v):
                seen.add(v)
                needle = ('"' + c_escape(v) + '"').replace(" ", "")
                self.lit_needles.append((v, needle))

        # thunk: адрес -> цель (уже разрешённая до реальной функции)
        self.thunk_target: Dict[str, str] = {}
        for t in thunks or []:
            a = (t.get("address") or "").strip()
            tg = (t.get("target") or "").strip()
            if a and tg:
                self.thunk_target[a] = tg

        # имена: реальные функции + thunk'и (оживит thunk_ratio)
        self.name_by_addr: Dict[str, str] = {
            f.get("address"): (f.get("name") or "") for f in self.all_functions
        }
        for t in thunks or []:
            a = (t.get("address") or "").strip()
            if a:
                self.name_by_addr[a] = t.get("name") or ""

        # граф с прозрачностью сквозь thunk'и:
        # callers[X] = кто вызывает X (напрямую ИЛИ через thunk)
        # resolved_callees[X] = кого вызывает X (цели thunk'ов добавлены)
        self.callers: Dict[str, List[str]] = {}
        self.resolved_callees: Dict[str, List[str]] = {}
        for f in self.all_functions:
            a = f.get("address")
            lst: List[str] = []
            for c in f.get("callees") or []:
                self.callers.setdefault(c, []).append(a)
                lst.append(c)
                t = self.thunk_target.get(c)
                if t:
                    self.callers.setdefault(t, []).append(a)
                    lst.append(t)
            self.resolved_callees[a] = lst

def extract_features(index: FeatureIndex, f: Dict[str, Any]) -> Dict[str, Any]:
    code = f.get("ghidra_code") or ""
    name = f.get("name") or ""
    # нормализация имён внешних вызовов (в дампе бывает "operator < <")
    ext = [(n or "").replace(" ", "") for n in (f.get("ext_calls") or [])]
    callees = list(f.get("callees") or [])

    gmp = [n for n in ext if GMP_NAME_RE.match(n)] or sorted(set(GMP_CODE_RE.findall(code)))
    stdio = [n for n in ext if n in STDIO_IMPORTS]
    fileio = [n for n in ext if n in FILE_IMPORTS]
    iostream = [n for n in ext if n.startswith("operator<<")]
    if "cout" in code or "cerr" in code:
        iostream.append("cout/cerr")

    code_ns = re.sub(r"\s+", "", code)
    literals = [v for v, needle in index.lit_needles if needle in code_ns]

    crt = [n for n in ext if n in CRT_IMPORTS]
    thunk_callees = [
        c for c in callees if index.name_by_addr.get(c, "").startswith("thunk_")
    ]

    return {
        "address": f.get("address"),
        "name": name,
        "size": int(f.get("size") or 0),
        "n_local_callees": len(callees),
        "n_ext_calls": len(ext),
        "n_gmp": len(gmp),
        "n_stdio": len(stdio),
        "n_fileio": len(fileio),
        "n_iostream": len(iostream),
        "n_literals": len(literals),
        "n_crt": len(crt),
        "crt_ratio": round(len(crt) / max(1, len(ext)), 3),
        "thunk_ratio": round(len(thunk_callees) / max(1, len(callees)), 3),
        "is_fun_name": int(name.startswith("FUN_")),
        "is_thunk_name": int(name.startswith("thunk_")),
        "is_named": int(bool(name) and not name.startswith(("FUN_", "thunk_", "_"))),
        "is_named": int(bool(name) and not name.startswith(("FUN_", "thunk_", "_"))),
        "is_crt_name": int(name.startswith("_")),
        "is_stl_name": int("std::" in name),
        "is_lib_name": int(
            bool(name)
            and not name.startswith(("FUN_", "thunk_", "_"))
            and "std::" not in name
        ),
        "n_callers": len(index.callers.get(f.get("address"), [])),
        "literals": literals[:8],
        "gmp_calls": gmp[:8],

    }