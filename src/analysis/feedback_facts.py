from __future__ import annotations

"""Q6: skip-forever gcc → query Q0–Q2 facts. Hit → leftover + Q4. Miss stays.

Planner of classes, not a chat and not compile-fix LLM. Empty bag is not a
hit. Does not invent mpz_ptr or a missing immediate. Live restore stays p4.
runner.py does not import this.
"""

import re
from typing import Any, Dict, List, Sequence

from src.agents.compiler import match_errors
from src.analysis.ghidra_cpp import (
    fill_truncated_call_imms,
    leftover_call_arity,
    leftover_format_from_pe,
)

ACTION_SKIP = "skip_forever"
ACTION_LEFTOVER = "leftover"

_TRUNCATED = frozenset({
    "ghidra truncated mpz call",
    "ghidra truncated mpfr call",
})
_FORMAT = "unsigned char* vs char*"
_NO_CAST = frozenset({
    "ghidra word vs mpz_ptr",
    "word vs char*",
})
_RE_TOO_FEW = re.compile(
    r"too few arguments to function\s+'[^']*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.I,
)


def callee_from_gcc(message: str) -> str:
    """Callee ident in a truncated-call gcc line. Empty if not that class."""
    m = _RE_TOO_FEW.search(message or "")
    return m.group(1) if m else ""


def _site_iat_name(site: object) -> str:
    if hasattr(site, "iat_name"):
        return str(getattr(site, "iat_name") or "")
    if isinstance(site, dict):
        return str(site.get("iat_name") or "")
    return ""


def sites_for_callee(call_sites: object | None, callee: str) -> object | None:
    """Keep only sites whose IAT name is this gcc callee. Empty is not a hit."""
    if not callee or call_sites is None:
        return call_sites
    if hasattr(call_sites, "sites"):
        raw = list(getattr(call_sites, "sites") or ())
    elif isinstance(call_sites, dict):
        raw = list(call_sites.get("sites") or [])
    elif isinstance(call_sites, (list, tuple)):
        raw = list(call_sites)
    else:
        return {"sites": []}
    keep = [s for s in raw if _site_iat_name(s) == callee]
    return {"sites": keep}


def plan_one(
    reason: str,
    message: str,
    code: str,
    *,
    call_sites: object | None = None,
    iat_facts: object | None = None,
    dat_facts: object | None = None,
) -> Dict[str, Any]:
    """Ask byte/IAT/DAT facts for one skip-forever diagnostic.

    Unique imm fill (Q4) promotes truncated mpz/mpfr. Format leftover is
    DAT identity, not an invented literal. Word vs mpz_ptr stays skip-forever.
    """
    rec: Dict[str, Any] = {
        "reason": reason,
        "message": message,
        "action": ACTION_SKIP,
        "kind": "",
        "filled": False,
        "need_llm": False,
    }
    blob = code or ""
    if reason in _TRUNCATED:
        callee = callee_from_gcc(message)
        rec["callee"] = callee
        scoped = sites_for_callee(call_sites, callee)
        filled = fill_truncated_call_imms(blob, scoped, iat_facts)
        toks = leftover_call_arity(blob, scoped, iat_facts)
        if callee:
            toks = [t for t in toks if t == callee]
        rec["tokens"] = toks
        if filled != blob:
            rec["action"] = ACTION_LEFTOVER
            rec["kind"] = "call_arity"
            rec["filled"] = True
            rec["code"] = filled
            return rec
        return rec
    if reason == _FORMAT:
        toks = leftover_format_from_pe(blob, dat_facts)
        if toks:
            rec["action"] = ACTION_LEFTOVER
            rec["kind"] = "format_dat"
            rec["tokens"] = toks
            rec["code"] = blob
            return rec
        rec["tokens"] = []
        return rec
    if reason in _NO_CAST:
        rec["tokens"] = []
        return rec
    rec["tokens"] = []
    return rec


def plan_errors(
    errors: Sequence[Dict[str, str]],
    code: str,
    *,
    call_sites: object | None = None,
    iat_facts: object | None = None,
    dat_facts: object | None = None,
) -> Dict[str, Any]:
    """Overlay skip-forever with Q0–Q2. Never sets need_llm."""
    decision = match_errors(list(errors or []), cases=[])
    rows: List[Dict[str, Any]] = []
    filled_code = code or ""
    n_leftover = 0
    n_skip = 0
    for hit in decision.skip_forever:
        one = plan_one(
            hit.reason,
            hit.message,
            filled_code,
            call_sites=call_sites,
            iat_facts=iat_facts,
            dat_facts=dat_facts,
        )
        if one["action"] == ACTION_LEFTOVER:
            n_leftover += 1
            if one.get("filled") and one.get("code"):
                filled_code = str(one["code"])
        else:
            n_skip += 1
        rows.append(one)
    for hit in decision.known:
        rows.append({
            "reason": ",".join(hit.case_ids),
            "message": hit.message,
            "action": "known",
            "kind": "",
            "filled": False,
            "need_llm": False,
        })
    for msg in decision.unknown:
        rows.append({
            "reason": "",
            "message": msg,
            "action": "unknown",
            "kind": "",
            "filled": False,
            "need_llm": False,
        })
    return {
        "rows": rows,
        "n_leftover": n_leftover,
        "n_skip": n_skip,
        "n_known": len(decision.known),
        "n_unknown": len(decision.unknown),
        "need_llm": False,
        "code": filled_code,
        "changed": filled_code != (code or ""),
    }


def format_feedback_report(plan: Dict[str, Any]) -> str:
    """Corpus needle surface. Taxonomy tags, not sample names."""
    lines: List[str] = []
    for row in plan.get("rows") or []:
        action = str(row.get("action") or ACTION_SKIP)
        extra = str(row.get("kind") or row.get("reason") or "")
        lines.append(f"==feedback:{action}:{extra}==")
        if row.get("filled"):
            lines.append("==feedback:filled==")
    if plan.get("changed"):
        lines.append((plan.get("code") or "").rstrip())
    elif plan.get("code"):
        lines.append(str(plan.get("code")).rstrip())
    return "\n".join(lines) + "\n"
