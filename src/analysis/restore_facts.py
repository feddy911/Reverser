from __future__ import annotations

"""Q7 gated CallSiteFacts / IAT arity for build_restore_prompt. Not live.

Only leftover truncated calls that unique-imm fill cannot fold. Empty bag
omits the section (not a pass token). Does not print pointer types or
mpz_ptr. Does not invent a missing immediate. Live restore omits this;
do not bump LLM_PROMPT_VER. runner.py does not import this.
"""

from typing import Any, List

FACTS_SECTION_TITLE = "CALL-SITE / IAT FACTS (байты этого exe; не C)"


def _sites_list(call_sites: object | None) -> list[object]:
    if call_sites is None:
        return []
    if hasattr(call_sites, "sites"):
        return list(getattr(call_sites, "sites") or ())
    if isinstance(call_sites, dict):
        return list(call_sites.get("sites") or [])
    if isinstance(call_sites, (list, tuple)):
        return list(call_sites)
    return []


def _site_iat_name(site: object) -> str:
    if hasattr(site, "iat_name"):
        return str(getattr(site, "iat_name") or "")
    if isinstance(site, dict):
        return str(site.get("iat_name") or "")
    return ""


def sites_for_callee(call_sites: object | None, callee: str) -> dict[str, list[object]]:
    raw = _sites_list(call_sites)
    if not callee:
        return {"sites": raw}
    named = [s for s in raw if _site_iat_name(s) == callee]
    if named:
        return {"sites": named}
    unnamed = [s for s in raw if not _site_iat_name(s)]
    if len(unnamed) == 1:
        return {"sites": unnamed}
    return {"sites": []}


def _bound_arity(iat_facts: object | None, name: str) -> int:
    if not name or iat_facts is None:
        return 0
    if hasattr(iat_facts, "protos"):
        protos = list(getattr(iat_facts, "protos") or ())
    elif isinstance(iat_facts, dict):
        protos = list(iat_facts.get("protos") or [])
    else:
        return 0
    names: dict[str, int] = {}
    for p in protos:
        if hasattr(p, "name"):
            nm = str(getattr(p, "name") or "")
            try:
                arity = int(getattr(p, "arity") or 0)
            except (TypeError, ValueError):
                continue
        elif isinstance(p, dict):
            nm = str(p.get("name") or "")
            try:
                arity = int(p.get("arity") or 0)
            except (TypeError, ValueError):
                continue
        else:
            continue
        if nm and arity > 0:
            names[nm] = arity
    if name in names:
        return names[name]
    from src.analysis.iat_proto import proto_for_name

    proto = proto_for_name(name)
    if proto and proto.name in names:
        return names[proto.name]
    return 0


def _can_fold(
    code: str,
    call_sites: object | None,
    iat_facts: object | None,
    callee: str,
) -> bool:
    from src.analysis.ghidra_cpp import fill_truncated_call_imms

    blob = code or ""
    filled = fill_truncated_call_imms(
        blob, sites_for_callee(call_sites, callee), iat_facts
    )
    return filled != blob


def leftover_unfilled(
    code: str,
    call_sites: object | None = None,
    iat_facts: object | None = None,
) -> List[str]:
    """Callee idents leftover_call_arity hits that Q4 cannot fold."""
    from src.analysis.ghidra_cpp import leftover_call_arity

    toks = leftover_call_arity(code, call_sites, iat_facts)
    out: List[str] = []
    seen: set[str] = set()
    for name in toks:
        if not name or name in seen:
            continue
        if _can_fold(code, call_sites, iat_facts, name):
            continue
        seen.add(name)
        out.append(name)
    return out


def format_restore_facts(
    code: str,
    call_sites: object | None = None,
    iat_facts: object | None = None,
) -> str:
    """Prompt section or empty. Empty bag and unique-imm leftover omit."""
    names = leftover_unfilled(code, call_sites, iat_facts)
    if not names:
        return ""
    lines: List[str] = []
    for name in names:
        regs: List[str] = []
        for site in sites_for_callee(call_sites, name)["sites"]:
            if hasattr(site, "arg_regs"):
                raw = tuple(getattr(site, "arg_regs") or ())
            elif isinstance(site, dict):
                raw = tuple(site.get("arg_regs") or ())
            else:
                raw = ()
            for r in raw:
                s = str(r or "").lower()
                if s and s not in regs:
                    regs.append(s)
        parts = [f"CALL {name}"]
        if regs:
            parts.append("regs=" + ",".join(regs))
        arity = _bound_arity(iat_facts, name)
        if arity:
            parts.append(f"iat_arity={arity}")
        parts.append("no unique imm")
        lines.append(" ".join(parts))
    body = "\n".join(lines)
    return (
        f"=== {FACTS_SECTION_TITLE} ===\n"
        "Ограничения arity с байт и IAT этого PE. Это не второй декомпилятор.\n"
        "Не выдумывай недостающий immediate. Не касти параметр к типу указателя.\n"
        f"{body}"
    )


def insert_restore_facts(prompt: str, block: str) -> str:
    """Place the facts section before the strict-rules marker."""
    blob = (block or "").strip()
    if not blob:
        return prompt or ""
    chunk = "\n" + blob + "\n\n"
    marker = "=== СТРОГИЕ ПРАВИЛА ==="
    if marker in (prompt or ""):
        return (prompt or "").replace(marker, chunk + marker, 1)
    return (prompt or "") + chunk
