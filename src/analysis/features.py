from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from src.analysis.platform import (
    CRT_NAMES, STDIO_NAMES, is_system_dll, is_user_literal,
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
            if v not in seen and is_user_literal(v):
                seen.add(v)
                needle = ('"' + c_escape(v) + '"').replace(" ", "")
                self.lit_needles.append((v, needle))

        self.thunk_target: Dict[str, str] = {}
        for t in thunks or []:
            a = (t.get("address") or "").strip()
            tg = (t.get("target") or "").strip()
            if a and tg:
                self.thunk_target[a] = tg

        self.name_by_addr: Dict[str, str] = {
            f.get("address"): (f.get("name") or "") for f in self.all_functions
        }
        for t in thunks or []:
            a = (t.get("address") or "").strip()
            if a:
                self.name_by_addr[a] = t.get("name") or ""

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
    ext = [(n or "").replace(" ", "") for n in (f.get("ext_calls") or [])]
    dlls = [(d or "").strip() for d in (f.get("ext_dlls") or [])]
    callees = list(f.get("callees") or [])

    # происхождение вызовов — из дампа, без знаний о цели
    n_domain = sum(1 for d in dlls if d and not is_system_dll(d))
    n_system = sum(1 for d in dlls if is_system_dll(d))
    stdio = [n for n in ext if n in STDIO_NAMES]
    iostream = [n for n in ext if n.startswith("operator<<")]
    if "cout" in code or "cerr" in code:
        iostream.append("cout/cerr")

    code_ns = re.sub(r"\s+", "", code)
    literals = [v for v, needle in index.lit_needles if needle in code_ns]

    crt = [n for n in ext if n in CRT_NAMES]
    thunk_callees = [
        c for c in callees if index.name_by_addr.get(c, "").startswith("thunk_")
    ]

    return {
        "address": f.get("address"),
        "name": name,
        "size": int(f.get("size") or 0),
        "n_local_callees": len(callees),
        "n_ext_calls": len(ext),
        "n_domain": n_domain,
        "n_system": n_system,
        "n_stdio": len(stdio),
        "n_iostream": len(iostream),
        "n_literals": len(literals),
        "n_crt": len(crt),
        "crt_ratio": round(len(crt) / max(1, len(ext)), 3),
        "thunk_ratio": round(len(thunk_callees) / max(1, len(callees)), 3),
        "is_fun_name": int(name.startswith("FUN_")),
        "is_thunk_name": int(name.startswith("thunk_")),
        "is_named": int(bool(name) and not name.startswith(("FUN_", "thunk_", "_"))),
        "is_crt_name": int(name.startswith("_")),
        "is_stl_name": int("std::" in name),
        "is_lib_name": int(
            bool(name)
            and not name.startswith(("FUN_", "thunk_", "_"))
            and "std::" not in name
        ),
        "lib_matched": int(bool(f.get("lib_matched")) or "Library Function" in code),
        "n_callers": len(index.callers.get(f.get("address"), [])),
        "literals": literals[:8],
        "domain_dlls": sorted({d for d in dlls if d and not is_system_dll(d)})[:4],
    }

FEATURE_KEYS = (
    "size", "n_local_callees", "n_ext_calls", "n_domain", "n_system",
    "n_stdio", "n_iostream", "n_literals", "n_crt", "crt_ratio",
    "thunk_ratio", "is_fun_name", "is_thunk_name", "is_named", "n_callers",
    "is_crt_name", "is_stl_name", "is_lib_name",
    "hot_callers", "hot_callees",
    "own_hot", "hot_caller_ratio",
)


def derive_features(ft: Dict[str, Any]) -> Dict[str, Any]:
    """Производные признаки. ЕДИНСТВЕННАЯ реализация для обучения и инференса.

    Мутирует и возвращает тот же dict (как ожидает scorer.score_all).
    """
    ft["own_hot"] = int(
        ft.get("n_domain", 0) > 0
        or ft.get("n_literals", 0) > 0
        or ft.get("n_iostream", 0) > 0
        or ft.get("n_stdio", 0) > 0
    )
    nc = int(ft.get("n_callers", 0) or 0)
    hc = int(ft.get("hot_callers", 0) or 0)
    ft["hot_caller_ratio"] = round(hc / nc, 3) if nc > 0 else 0.0
    return ft