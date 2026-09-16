from __future__ import annotations

"""Critic: accept / reject / rollback. Does not generate C++.

Director of the existing-agent department: may punish subordinates
(function reject, run REJECT) and may not write C++. A green glued TU
is not the compile gate. ``compile_ok`` is per-function syntax of LLM
user_code targets. The assembled TU is ``assembled_ok`` (report only)
and does not block ACCEPT.

Higher rank → harsher sanction (see ROLE_RANK). Director's own crime
(ACCEPT while identity/fidelity/per-fn failed) is illegal; tests assert
``director_contract``.

Reject if restore swapped the function for a different well-known
algorithm (starts_with to std::sort) or dropped Ghidra facts (fidelity).
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

# Higher number = harsher punishment. Director (5) may REJECT the run.
# Assembler (3) only fails the TU report; per-fn green still ACCEPT.
ROLE_RANK = {
    "polisher": 1,
    "restorer": 2,
    "assembler": 3,
    "compiler": 4,
    "critic": 5,
}


def _haystacks(entry: Dict[str, Any]) -> str:
    parts = [
        entry.get("ghidra_code") or "",
        " ".join(str(x) for x in (entry.get("ext_calls") or [])),
        " ".join(str(x) for x in (entry.get("callees") or [])),
        " ".join(str(x) for x in (entry.get("literals") or [])),
    ]
    return "\n".join(parts)


def _algo_attested_in_dump(algo: str, blob: str) -> bool:
    """True if the dump already names this algorithm (including Ghidra mangling).

    Restore may print ``std::sort`` while Ghidra printed ``sort<Item*>``.
    A bare substring ``sort`` is not enough (too many false friends).
    """
    b = (blob or "").lower()
    if not algo:
        return False
    if algo.lower() in b:
        return True
    tail = algo.rsplit("::", 1)[-1].lower()
    if not tail:
        return False
    return f"{tail}<" in b or f"::{tail}(" in b or f"::{tail}<" in b


def unexpected_algos(code: str, allowed_blob: str) -> List[str]:
    blob = allowed_blob or ""
    found = []
    for algo in FAMOUS_ALGOS:
        if algo in (code or "") and not _algo_attested_in_dump(algo, blob):
            found.append(algo)
    return found


def defined_function_name(code: str) -> str:
    span = _first_function_span(code or "")
    if not span:
        return ""
    return span[2] or ""


_STUB_DEF_NAMES = frozenset({"func", "function", "f", "foo", "bar"})
_RE_STUB_ADDR_NAME = re.compile(r"^(?:func|sub)_[0-9a-fA-F]+$", re.I)
_RE_ELLIPSIS_STUB = re.compile(r"//\s*\.\.\.|/\*[^*]*\.\.\.[^*]*\*/")
_STUB_DUMP_MIN = 400
_STUB_DUMP_RATIO = 8
_STUB_MAX_BARE_STMTS = 2


def _code_size(blob: str) -> int:
    return len(re.sub(r"\s+", "", blob or ""))


def _bare_stmt_count(code: str) -> int:
    s = re.sub(r"/\*.*?\*/", " ", code or "", flags=re.S)
    s = re.sub(r"//.*?$", " ", s, flags=re.M)
    return s.count(";")


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
    want = guessed or ghidra
    if defined and want and defined != want:
        low = defined.lower()
        if low in _STUB_DEF_NAMES or _RE_STUB_ADDR_NAME.match(defined):
            reasons.append("restore stub name " + defined)
    if _RE_ELLIPSIS_STUB.search(code or ""):
        reasons.append("restore ellipsis stub")
    dump = entry.get("ghidra_code") or ""
    n_dump = _code_size(dump)
    n_code = _code_size(code)
    if (
        n_dump >= _STUB_DUMP_MIN
        and n_code * _STUB_DUMP_RATIO < n_dump
        and _bare_stmt_count(code) <= _STUB_MAX_BARE_STMTS
    ):
        reasons.append("restore stub vs dump size")
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
    assembled_ok: Optional[bool] = None
    identity_ok: bool = True
    fidelity_ok: bool = True
    functions: List[FunctionVerdict] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    sanctions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        ranks = [int(s.get("rank") or 0) for s in self.sanctions]
        return {
            "accept": self.accept,
            "compile_ok": self.compile_ok,
            "assembled_ok": self.assembled_ok,
            "identity_ok": self.identity_ok,
            "fidelity_ok": self.fidelity_ok,
            "reasons": list(self.reasons),
            "n_functions": len(self.functions),
            "n_reject": sum(1 for f in self.functions if not f.accept),
            "functions": [f.to_dict() for f in self.functions],
            "sanctions": list(self.sanctions),
            "max_sanction_rank": max(ranks) if ranks else 0,
        }


def per_fn_compile_ok(restored: Sequence[Dict[str, Any]]) -> Optional[bool]:
    """Syntax-ok of LLM user_code targets that were compile-checked.

    Missing ``compile_ok`` on every target means per-fn was not run (None).
    The glued TU is not this signal.
    """
    flags: List[bool] = []
    for r in restored or []:
        if r.get("classification") not in (None, "user_code"):
            continue
        if not (r.get("cpp_code") or "").strip():
            continue
        if "compile_ok" not in r:
            continue
        flags.append(bool(r.get("compile_ok")))
    if not flags:
        return None
    return all(flags)


def collect_sanctions(verdict: RunVerdict) -> List[Dict[str, Any]]:
    """Map gates to punishments. Higher rank is a harsher sentence.

    Rank 3 (assembler TU) does not REJECT the run. Rank 5 (director)
    REJECT is identity, fidelity, or per-fn compile failure.
    """
    out: List[Dict[str, Any]] = []
    for fn in verdict.functions:
        if fn.identity_ok and fn.fidelity_ok:
            continue
        out.append({
            "issuer": "critic",
            "target": "restorer",
            "rank": ROLE_RANK["restorer"],
            "scope": "function",
            "sanction": "function_reject",
            "address": fn.address,
            "reason": "; ".join(fn.reasons[:3]),
        })
    if verdict.assembled_ok is False:
        out.append({
            "issuer": "critic",
            "target": "assembler",
            "rank": ROLE_RANK["assembler"],
            "scope": "tu",
            "sanction": "tu_report_fail",
            "reason": "assembled TU failed syntax; not the ACCEPT gate",
        })
    if not verdict.accept:
        reason = ""
        for item in verdict.reasons:
            if "syntax" in item or "compile" in item or "TU " in item:
                reason = item
                break
        if not reason:
            reason = (verdict.reasons[0] if verdict.reasons else "run rejected")
        out.append({
            "issuer": "critic",
            "target": "restorer",
            "rank": ROLE_RANK["critic"],
            "scope": "run",
            "sanction": "run_reject",
            "reason": reason,
        })
    return out


def director_contract(verdict: RunVerdict) -> bool:
    """Director must not ACCEPT a run that failed identity, fidelity, or per-fn."""
    if verdict.accept and verdict.compile_ok is False:
        return False
    if verdict.accept and not verdict.identity_ok:
        return False
    if verdict.accept and not verdict.fidelity_ok:
        return False
    return True


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
        if not fid.get("scored"):
            reasons.append("empty dump-fact bag (unscored)")
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
        if fid.get("missing_user_calls"):
            reasons.append(
                "missing calls: "
                + ", ".join(str(x) for x in (fid.get("missing_user_calls") or [])[:3])
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
    assembled_ok: Optional[bool] = None,
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
    fn_gate = per_fn_compile_ok(restored)
    gate = fn_gate if fn_gate is not None else compile_ok
    accept = identity_ok and fidelity_ok
    if gate is False:
        if fn_gate is False:
            reasons.append("per-fn syntax failed")
        else:
            reasons.append("assembled TU did not compile")
        accept = False
    verdict = RunVerdict(
        accept=accept,
        compile_ok=gate,
        assembled_ok=assembled_ok,
        identity_ok=identity_ok,
        fidelity_ok=fidelity_ok,
        functions=fns,
        reasons=reasons,
    )
    verdict.sanctions = collect_sanctions(verdict)
    return verdict


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
