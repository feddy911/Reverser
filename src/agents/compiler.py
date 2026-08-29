from __future__ import annotations

"""Compiler agent: classify gcc diagnostics against the corpus.

Match fingerprint → known recipe (already applied by sanitizer/assembler).
Miss → at most one LLM compile-fix. Success → draft YAML, not a sanitizer patch.
Never writes the restore cache.
"""

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.analysis.corpus import CorpusCase, load_corpus


@dataclass
class DiagnosticHit:
    message: str
    case_ids: List[str]


@dataclass
class CompilerDecision:
    known: List[DiagnosticHit] = field(default_factory=list)
    unknown: List[str] = field(default_factory=list)
    need_llm: bool = False

    @property
    def known_ids(self) -> List[str]:
        ids: List[str] = []
        for hit in self.known:
            for cid in hit.case_ids:
                if cid not in ids:
                    ids.append(cid)
        return ids


def _safe_search(pattern: str, text: str) -> bool:
    if not pattern or not text:
        return False
    try:
        return bool(re.search(pattern, text, re.DOTALL))
    except re.error:
        return pattern in text


def match_errors(
    errors: Sequence[Dict[str, str]],
    cases: Optional[Sequence[CorpusCase]] = None,
) -> CompilerDecision:
    loaded: Sequence[CorpusCase] = cases if cases is not None else load_corpus()
    with_fp = [c for c in loaded if (c.gcc_fingerprint or "").strip()]
    decision = CompilerDecision()
    for err in errors or []:
        msg = str(err.get("message") or "").strip()
        if not msg:
            continue
        hits = [c.id for c in with_fp if _safe_search(c.gcc_fingerprint, msg)]
        if hits:
            decision.known.append(DiagnosticHit(message=msg, case_ids=hits))
        else:
            decision.unknown.append(msg)
    decision.need_llm = bool(decision.unknown)
    return decision


def _slug(text: str, n: int = 10) -> str:
    return hashlib.sha1((text or "").encode("utf-8")).hexdigest()[:n]


def proposal_payload(
    *,
    profile: str,
    errors: Sequence[Dict[str, str]],
    snippet: str,
    addr: str = "",
) -> Dict[str, Any]:
    msgs = [str(e.get("message") or "") for e in (errors or []) if e.get("message")]
    joined = " | ".join(msgs[:3])
    fp = re.escape(msgs[0][:160]) if msgs else ""
    cid = "draft-" + _slug(joined + (snippet or "")[:200])
    return {
        "id": cid,
        "profile": profile or "generic",
        "gcc_fingerprint": fp,
        "recipe": "sanitize",
        "ghidra_cpp": (snippet or "")[:4000],
        "contains": [],
        "not_contains": [],
        "compile": False,
        "notes": (
            "auto-proposed by Compiler agent from unknown gcc diagnostic"
            + (f" @ {addr}" if addr else "")
            + "; not accepted into eval/corpus"
        ),
        "gcc_messages": msgs[:8],
    }


def write_proposal(
    out_dir: Path,
    *,
    profile: str,
    errors: Sequence[Dict[str, str]],
    snippet: str,
    addr: str = "",
) -> Path:
    import yaml

    out_dir.mkdir(parents=True, exist_ok=True)
    payload = proposal_payload(
        profile=profile, errors=errors, snippet=snippet, addr=addr
    )
    path = out_dir / f"{payload['id']}.yaml"
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return path
