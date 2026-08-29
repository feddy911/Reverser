from __future__ import annotations

"""Critic: accept / reject / rollback. Does not generate C++.

A green TU is not enough. Reject if restore swapped the function for a
different well-known algorithm (starts_with → std::sort) or dropped
Ghidra facts (fidelity).
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.analysis.fidelity import build_call_tokens, check_function, dump_facts_ok
from src.analysis.ghidra_cpp import _first_function_span

FAMOUS_ALGOS: Tuple[str, ...] = (
    "std::sort",
    "std::stable_sort",
    "std::partial_sort",
    "std::nth_element",
    "std::make_heap",
    "std::sort_heap",
    "std::push_heap",
    "std::pop_heap",
    "std::inplace_merge",
    "std::next_permutation",
    "std::prev_permutation",
    "std::unique",
    "std::remove_if",
    "std::partition",
    "std::stable_partition",
    "std::binary_search",
)

FAMOUS_FN_NAMES = frozenset({
    "sort", "stable_sort", "partial_sort", "nth_element",
    "make_heap", "sort_heap", "inplace_merge", "remove_if",
    "partition", "stable_partition",
})

_FIDELITY_OK = 0.85


def _haystacks(entry: Dict[str, Any]) -> str:
    parts = [
        entry.get("ghidra_code") or "",
        " ".join(str(x) for x in (entry.get("ext_calls") or [])),
        " ".join(str(x) for x in (entry.get("callees") or [])),
        " ".join(str(x) for x in (entry.get("literals") or [])),
    ]
    return "\n".join(parts)


def unexpected_algos(code: str, allowed_blob: str) -> List[str]:
    blob = (allowed_blob or "").lower()
    found = []
    for algo in FAMOUS_ALGOS:
        if algo in (code or "") and algo.lower() not in blob:
            found.append(algo)
    return found


def defined_function_name(code: str) -> str:
    span = _first_function_span(code or "")
    if not span:
        return ""
    return span[2] or ""


def identity_issues(entry: Dict[str, Any], code: str) -> List[str]:
    reasons: List[str] = []
    allowed = _haystacks(entry)
    unexpected = unexpected_algos(code, allowed)
    if unexpected:
        reasons.append("unexpected " + ", ".join(unexpected))
    defined = defined_function_name(code)
    guessed = (entry.get("guessed_name") or "").strip()
    ghidra = (entry.get("ghidra_name") or entry.get("name") or "").strip()
    if defined and defined in FAMOUS_FN_NAMES:
        allowed_names = {guessed, ghidra, (entry.get("name") or "").strip()}
        if defined not in allowed_names and defined.lower() not in allowed.lower():
            reasons.append(f"function renamed to algorithm {defined}")
    return reasons


@dataclass
class FunctionVerdict:
    address: str = ""
    accept: bool = True
    identity_ok: bool = True
    fidelity_ok: bool = True
    fidelity: float = 1.0
    reasons: List[str] = field(default_factory=list)
    unexpected_algos: List[str] = field(default_factory=list)
    missing_literals: List[str] = field(default_factory=list)
    missing_calls: List[str] = field(default_factory=list)
    missing_ext: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "accept": self.accept,
            "identity_ok": self.identity_ok,
            "fidelity_ok": self.fidelity_ok,
            "fidelity": self.fidelity,
            "reasons": list(self.reasons),
            "unexpected_algos": list(self.unexpected_algos),
            "missing_literals": list(self.missing_literals)[:8],
            "missing_calls": list(self.missing_calls)[:8],
            "missing_ext": list(self.missing_ext)[:8],
        }


@dataclass
class RunVerdict:
    accept: bool = True
    compile_ok: Optional[bool] = None
    identity_ok: bool = True
    fidelity_ok: bool = True
    functions: List[FunctionVerdict] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accept": self.accept,
            "compile_ok": self.compile_ok,
            "identity_ok": self.identity_ok,
            "fidelity_ok": self.fidelity_ok,
            "reasons": list(self.reasons),
            "n_functions": len(self.functions),
            "n_reject": sum(1 for f in self.functions if not f.accept),
            "functions": [f.to_dict() for f in self.functions],
        }


def review_function(
    entry: Dict[str, Any],
    code: str,
    call_tokens: Optional[Sequence[Tuple[str, List[str]]]] = None,
) -> FunctionVerdict:
    addr = str(entry.get("address") or "")
    toks = list(call_tokens or [])
    fid = check_function(entry, code, toks)
    ident_reasons = identity_issues(entry, code)
    unexpected = unexpected_algos(code, _haystacks(entry))
    identity_ok = not ident_reasons
    score_ok = (not fid.get("drift")) or float(fid.get("fidelity") or 0) >= _FIDELITY_OK
    facts_ok = dump_facts_ok(fid)
    fidelity_ok = bool(facts_ok and score_ok)
    reasons = list(ident_reasons)
    if not facts_ok:
        if fid.get("missing_literals"):
            reasons.append(
                "missing literals: "
                + ", ".join(str(x) for x in (fid.get("missing_literals") or [])[:3])
            )
        if fid.get("missing_ext"):
            reasons.append(
                "missing ext_calls: "
                + ", ".join(str(x) for x in (fid.get("missing_ext") or [])[:3])
            )
    elif not score_ok:
        reasons.append(
            f"fidelity {fid.get('fidelity')} drift={fid.get('drift')}"
        )
    return FunctionVerdict(
        address=addr,
        accept=identity_ok and fidelity_ok,
        identity_ok=identity_ok,
        fidelity_ok=fidelity_ok,
        fidelity=float(fid.get("fidelity") or 0),
        reasons=reasons,
        unexpected_algos=unexpected,
        missing_literals=list(fid.get("missing_literals") or []),
        missing_calls=list(fid.get("missing_calls") or []),
        missing_ext=list(fid.get("missing_ext") or []),
    )


def review_run(
    restored: Sequence[Dict[str, Any]],
    *,
    ghidra_by_addr: Optional[Dict[str, Dict[str, Any]]] = None,
    name_by_addr: Optional[Dict[str, str]] = None,
    thunk_target: Optional[Dict[str, str]] = None,
    tu_text: str = "",
    compile_ok: Optional[bool] = None,
    functions: Optional[Sequence[Dict[str, Any]]] = None,
    thunks: Optional[Sequence[Dict[str, Any]]] = None,
) -> RunVerdict:
    from src.analysis.fidelity import symbol_names_from_dump

    ghidra_by_addr = ghidra_by_addr or {}
    names = symbol_names_from_dump(functions, thunks)
    names.update(name_by_addr or {})
    name_by_addr = names
    thunk_target = thunk_target or {}
    fns: List[FunctionVerdict] = []
    allowed_all = []
    for r in restored or []:
        if r.get("classification") not in (None, "user_code"):
            continue
        if not (r.get("cpp_code") or "").strip():
            continue
        src = ghidra_by_addr.get(r.get("address") or "") or {}
        entry = dict(r)
        if src.get("ghidra_code") and not entry.get("ghidra_code"):
            entry["ghidra_code"] = src.get("ghidra_code")
        for key in ("literals", "ext_calls", "callees", "name"):
            if not entry.get(key) and src.get(key):
                entry[key] = src.get(key)
        toks = build_call_tokens(
            entry.get("callees") or [],
            name_by_addr=name_by_addr,
            thunk_target=thunk_target,
        )
        fns.append(review_function(entry, r.get("cpp_code") or "", toks))
        allowed_all.append(_haystacks(entry))

    tu_reasons: List[str] = []
    if tu_text:
        tu_unexpected = unexpected_algos(tu_text, "\n".join(allowed_all))
        if tu_unexpected:
            tu_reasons.append("TU unexpected " + ", ".join(tu_unexpected))

    identity_ok = all(f.identity_ok for f in fns) and not tu_reasons
    fidelity_ok = all(f.fidelity_ok for f in fns) if fns else True
    reasons = list(tu_reasons)
    for f in fns:
        if not f.accept:
            reasons.append(f"{f.address}: " + "; ".join(f.reasons[:3]))
    accept = identity_ok and fidelity_ok
    if compile_ok is False:
        reasons.append("assembled TU did not compile")
        accept = False
    return RunVerdict(
        accept=accept,
        compile_ok=compile_ok,
        identity_ok=identity_ok,
        fidelity_ok=fidelity_ok,
        functions=fns,
        reasons=reasons,
    )


def review_compile_fix(
    fixed_text: str,
    restored: Sequence[Dict[str, Any]],
    *,
    ghidra_by_addr: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[bool, List[str]]:
    """True if compile-fix did not swap in a famous algorithm absent from Ghidra."""
    ghidra_by_addr = ghidra_by_addr or {}
    blobs = []
    for r in restored or []:
        src = ghidra_by_addr.get(r.get("address") or "") or {}
        blobs.append(_haystacks({**src, **r}))
    unexpected = unexpected_algos(fixed_text, "\n".join(blobs))
    if unexpected:
        return False, ["compile-fix introduced " + ", ".join(unexpected)]
    return True, []
