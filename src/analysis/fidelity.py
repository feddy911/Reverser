from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from src.analysis.platform import is_noise_call, is_noise_constant

NUM_RE = re.compile(r"\b(?:0x[0-9a-fA-F]{3,}|[1-9][0-9]{2,})\b")
GMP_PREFIX_RE = re.compile(r"^_+g?mpz_")

# Ghidra lowers range-for to __for_begin / __for_end; callees still list begin/end.
_RANGE_FOR_MARKERS = ("__for_begin", "__for_end", "__for_range")
_RANGE_FOR_METHODS = frozenset({
    "begin", "end", "cbegin", "cend", "rbegin", "rend",
})


def dump_has_range_for(ghidra_code: str) -> bool:
    """True if Ghidra printed a lowered range-for, not a named begin() call."""
    blob = ghidra_code or ""
    return any(m in blob for m in _RANGE_FOR_MARKERS)


def dump_has_duration_cast(ghidra_code: str) -> bool:
    """True if the dump already has duration_cast; callee token may be mangled."""
    return "duration_cast" in (ghidra_code or "")


def _is_duration_cast_callee(name: str) -> bool:
    return "duration_cast" in (name or "")


def _call_base(name: str) -> str:
    return (name or "").split("<", 1)[0].strip()


def _is_range_for_method(name: str) -> bool:
    return _call_base(name) in _RANGE_FOR_METHODS


def _gmp_key(t: str) -> str:
    return GMP_PREFIX_RE.sub("mpz_", t)


def _constants(code: str) -> set:
    return {
        m.lower()
        for m in NUM_RE.findall(code or "")
        if not is_noise_constant(m)
    }


def _c_escape(s: str) -> str:
    """Представление строки как в C/C++ исходнике внутри кавычек (\\n, \\r, \\\" …)."""
    return json.dumps(s, ensure_ascii=False)[1:-1]


def literal_in_code(lit: str, code: str) -> bool:
    """True, если литерал присутствует в восстановленном C++.

    Literals из Ghidra — декодированные байты; в .cpp они обычно лежат
    как C-escape последовательности. Сравниваем оба вида и допускаем
    отсутствие хвостовых whitespace у ожидаемого литерала.
    """
    if not lit:
        return True
    code = code or ""
    candidates = (
        lit,
        lit.rstrip(),
        _c_escape(lit),
        _c_escape(lit.rstrip()),
    )
    return any(c and c in code for c in candidates)


def symbol_names_from_dump(
    functions: Optional[Sequence[Dict[str, Any]]] = None,
    thunks: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, str]:
    """address → Ghidra symbol (user, STL method, or import thunk)."""
    names: Dict[str, str] = {}
    for f in functions or []:
        a = str(f.get("address") or "").strip()
        n = str(f.get("name") or "").strip()
        if a and n:
            names[a] = n
    for t in thunks or []:
        a = str(t.get("address") or "").strip()
        n = str(t.get("name") or "").strip()
        if a and n:
            names.setdefault(a, n)
    return names


def build_call_tokens(
    callees: Iterable[str],
    name_by_addr: Optional[Dict[str, str]] = None,
    thunk_target: Optional[Dict[str, str]] = None,
) -> List[Tuple[str, List[str]]]:
    """Единый builder токенов вызовов для refine / polish / final.

    Пропускает compiler/debug instrumentation (JustMyCode, RTC, GS, …).
    Unresolved addresses (import thunks without a name) are not required as
    FUN_<addr>: Ghidra already printed the C symbol (sqrt, memcpy, …).
    """
    name_by_addr = name_by_addr or {}
    thunk_target = thunk_target or {}
    out: List[Tuple[str, List[str]]] = []
    for c in callees or []:
        if not c:
            continue
        tgt = thunk_target.get(c, c)
        primary = (name_by_addr.get(tgt) or name_by_addr.get(c) or "").strip()
        if not primary:
            continue
        tokens = []
        for t in (
            primary,
            f"thunk_FUN_{tgt[2:]}" if tgt.startswith("0x") else "",
            f"thunk_FUN_{c[2:]}" if c.startswith("0x") else "",
            f"FUN_{tgt[2:]}" if tgt.startswith("0x") else "",
        ):
            if t and t not in tokens:
                tokens.append(t)
        if not tokens:
            continue
        if is_noise_call(primary) or all(is_noise_call(t) for t in tokens):
            continue
        out.append((primary, tokens))
    return out


def check_function(
    entry: Dict[str, Any],
    polished: str,
    call_tokens: List[Tuple[str, List[str]]],
) -> Dict[str, Any]:
    code = polished or ""
    code_lc = code.lower()

    missing_literals = [
        l for l in (entry.get("literals") or [])
        if l and not literal_in_code(l, code)
    ]

    # внешние вызовы: operator<< -> '<<'; __gmpz_* -> mpz_*
    missing_ext = []
    for e in (entry.get("ext_calls") or []):
        if not e or is_noise_call(e):
            continue
        if e.startswith("operator"):
            if "<<" not in code and "operator" not in code_lc:
                missing_ext.append(e)
        elif _gmp_key(e).lower() not in code_lc:
            missing_ext.append(e)

    skip_range = dump_has_range_for(entry.get("ghidra_code") or "")
    skip_duration = dump_has_duration_cast(entry.get("ghidra_code") or "")
    required_calls = [
        (name, toks) for name, toks in call_tokens
        if not is_noise_call(name)
        and not (skip_range and _is_range_for_method(name))
        and not (skip_range and _call_base(name) == "get")
        and not (skip_duration and _is_duration_cast_callee(name))
    ]
    missing_calls = [
        name for name, toks in required_calls
        if not any(t in code for t in toks)
    ]

    gconsts = _constants(entry.get("ghidra_code") or "")
    missing_consts = sorted(c for c in gconsts if c not in _constants(code))

    drift = bool(missing_calls or missing_literals or missing_ext)
    total = (
        len([l for l in (entry.get("literals") or []) if l])
        + len([e for e in (entry.get("ext_calls") or []) if e and not is_noise_call(e)])
        + len(required_calls)
        + len(gconsts)
    )
    missing = (
        len(missing_literals) + len(missing_ext)
        + len(missing_calls) + len(missing_consts)
    )
    return {
        "address": entry.get("address"),
        "fidelity": round(1.0 - missing / total, 3) if total else 1.0,
        "drift": drift,
        "missing_literals": missing_literals,
        "missing_ext": missing_ext,
        "missing_calls": missing_calls,
        "missing_consts": missing_consts[:10],
    }


def dump_facts_ok(fid: Dict[str, Any]) -> bool:
    """Literals and ext_calls from the dump must appear in restore.

    The numeric score is not a substitute: many constants can keep
    fidelity >= 0.85 while a string or import is gone.
    """
    return not (fid.get("missing_literals") or fid.get("missing_ext"))
