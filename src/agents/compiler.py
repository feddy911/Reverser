from __future__ import annotations

"""Compiler agent: classify gcc diagnostics against the corpus.

Match fingerprint → known recipe (already applied by sanitizer/assembler).
Skip-forever (invent-semantics) → no LLM, no catalog mini.
Miss → at most one LLM compile-fix. Success → draft YAML, not a sanitizer patch.
Never writes the restore cache.
"""

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.analysis.corpus import CorpusCase, load_corpus

# Invent-semantics: do not call LLM compile-fix. Shared with dialect_loop.
SKIP_FOREVER: Sequence[tuple[str, str]] = (
    (r"ios::good|std::ios.*::good", "ios::good without object"),
    (r"remove_cv", "libstdc++ remove_cv_t"),
    (r"__fill_a1", "libstdc++ __fill_a1"),
    (
        r"invalid initialization of non-const reference of type '.*mapped_type",
        "operator[] T& vs T*",
    ),
    (
        r"invalid conversion from '.*mapped_type'.*to 'mapped_type\s*\*'",
        "operator[] T& vs T*",
    ),
    (r"'this' was not declared in this scope", "this in STL signature"),
    (
        r"expected ',' or '\.\.\.' before 'this'|"
        r"expected unqualified-id before 'this'|"
        r"invalid use of 'this' in non-member",
        "this as Ghidra local",
    ),
    (
        r"invalid conversion from 'const char\*' to 'char\*'",
        "c_str const char*",
    ),
    (r"::<lambda", "ghidra lambda type in template"),
    (
        r"no matching function for call to 'sort<__normal_iterator",
        "ghidra sort placeholder iterators",
    ),
    (
        r"no match for 'operator\[\]' \(operand types are 'std::(?:map|unordered_map).+' and '(?:key_type|__normal_iterator)'",
        "assoc [] placeholder key",
    ),
    (
        r"no match for 'operator[=!]=' \(operand types are 'std::__cxx11::basic_string<char>' and 'char'|"
        r"operator[=!]=<char, std::char_traits<char>, std::allocator<char> >\(std::__cxx11::basic_string<char>\*&",
        "string vs char compare",
    ),
    (
        r"no match for 'operator\*' \(operand type is '__normal_iterator'",
        "opaque iterator dereference",
    ),
    (
        r"no match for 'operator=' \(operand types are 'std::vector.+' and 'const_iterator'",
        "opaque iterator vs vector const_iterator",
    ),
    (
        r"invalid conversion from '(?:longlong|undefined8)' .+ to 'mpz_(?:ptr|srcptr)'",
        "ghidra word vs mpz_ptr",
    ),
    (
        r"too few arguments to function '(?:int |void )?__gmpz_",
        "ghidra truncated mpz call",
    ),
    (
        r"too few arguments to function '[^']*\b(?:mpfr_|__gmpfr_)",
        "ghidra truncated mpfr call",
    ),
    (
        r"using typedef-name '[^']+' after 'struct'",
        "struct before header typedef",
    ),
    (
        r"cannot convert '.*const_iterator' to 'std::string\*'",
        "iterator vs string*",
    ),
    (
        r"cannot convert 'char\*' to 'std::string\*'",
        "char* vs string*",
    ),
    (
        r"to 'std::string\*' \{aka 'std::__cxx11::basic_string<char>\*'\} in assignment",
        "string value vs string*",
    ),
    (
        r"invalid conversion from 'const void\*' to 'pointer'",
        "const void* vs pointer",
    ),
    (
        r"'(?:p[bcilus]Var\d+|var_\d+|local_\d+|in_stk_n?\d+|"
        r"in_stack_[0-9A-Fa-f]+|in_RCX|in_RDX|"
        r"in_R8D|in_R9D|in_RAX|in_R8|in_R9)' was not declared in this scope",
        "undeclared ghidra temp",
    ),
    (
        r"no match for 'operator=' \(operand types are 'std::__cxx11::basic_string<char>' and 'std::__cxx11::basic_string<char>\*'",
        "string vs string* assign",
    ),
    (
        r"::operator\[\]\(std::(?:unordered_)?map<",
        "assoc [] map* as key",
    ),
    (
        r"cannot convert 'std::vector<.*\*' to 'std::unordered_map<",
        "vector* vs unordered_map*",
    ),
    (
        r"cannot convert 'std::vector<.*\*' to '[A-Z][A-Za-z0-9_]*\*'",
        "vector* vs user struct*",
    ),
    (
        r"base operand of '->' has non-pointer type '.*value_type' \{aka 'std::pair",
        "arrow on pair value",
    ),
    (
        r"comparison between distinct pointer types 'std::__detail::_Node_const_iterator",
        "hashtable iterator* vs ghidra_word*",
    ),
    (
        r"expected unqualified-id before ',' token|"
        r"expected unqualified-id before '>' token|"
        r"expected unqualified-id before '\{' token|"
        r"expected unqualified-id before string constant|"
        r"expected declaration before '\}' token|"
        r"invalid declarator before ',' token|"
        r"invalid declarator before '>' token|"
        r"a function-definition is not allowed here before '\{' token|"
        r"expected '\}' at end of input",
        "restore template debris",
    ),
    (
        r"no matching function for call to 'std::vector<.+>::vector\("
        r"size_type, std::allocator<[^>]+>\*",
        "ghidra vector allocator* ctor",
    ),
    (
        r"missing terminating ['\"] character",
        "restore quote debris",
    ),
    (
        r"iterator_traits<ghidra_word>|iterator_category.*ghidra_word|"
        r"cannot convert 'ghidra_word\*' to 'std::vector<|"
        r"no match for call to '\(ghidra_word\) \(\)'|"
        r"'using value_type = struct ghidra_word' \{aka 'struct ghidra_word'\} "
        r"has no member named|"
        r"no match for 'operator\[\]' \(operand types are 'ghidra_word' and "
        r"'(?:int|unsigned|long|size_t|size_type)'|"
        r"no match for 'operator[+\-*/]' \(operand types are 'ghidra_word'",
        "ghidra_word dummy",
    ),
    (
        r"cannot convert '[A-Z][A-Za-z0-9_]*\*' to 'mpfr_(?:ptr|srcptr)'",
        "user struct* vs mpfr_ptr",
    ),
    (
        r"'int [A-Za-z_]\w*' redeclared as different kind of entity",
        "ident redeclared as different kind",
    ),
    (
        r"type/value mismatch at argument \d+ in template parameter list for "
        r"'template<class[^']*> class std::(?:allocator|vector)",
        "non-type in std template",
    ),
    (
        r"request for member '[^']+' in '[^']+', which is of non-class type '.+\([^)]*\)'",
        "member on function type",
    ),
)


@dataclass
class DiagnosticHit:
    message: str
    case_ids: List[str]


@dataclass
class SkipForeverHit:
    message: str
    reason: str


@dataclass
class CompilerDecision:
    known: List[DiagnosticHit] = field(default_factory=list)
    unknown: List[str] = field(default_factory=list)
    skip_forever: List[SkipForeverHit] = field(default_factory=list)
    need_llm: bool = False

    @property
    def known_ids(self) -> List[str]:
        ids: List[str] = []
        for hit in self.known:
            for cid in hit.case_ids:
                if cid not in ids:
                    ids.append(cid)
        return ids

    @property
    def skip_forever_reasons(self) -> List[str]:
        out: List[str] = []
        for hit in self.skip_forever:
            if hit.reason not in out:
                out.append(hit.reason)
        return out


def _safe_search(pattern: str, text: str) -> bool:
    if not pattern or not text:
        return False
    try:
        return bool(re.search(pattern, text, re.DOTALL))
    except re.error:
        return pattern in text


def skip_forever_reason(msg: str) -> Optional[str]:
    """Invent-semantics gcc: do not LLM-fix and do not catalog a mini."""
    for pat, reason in SKIP_FOREVER:
        if _safe_search(pat, msg):
            return reason
    return None


def tu_compiler_action(decision: CompilerDecision) -> str:
    """Live assembled TU never LLM-patches.

    ``skip``: known dialect and/or skip-forever only.
    ``proposal``: at least one unknown gcc — draft YAML, do not compile-fix.
    Per-function compile-fix still uses ``need_llm``.
    """
    if decision.need_llm:
        return "proposal"
    return "skip"


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
        forever = skip_forever_reason(msg)
        if forever:
            decision.skip_forever.append(SkipForeverHit(message=msg, reason=forever))
            continue
        hits = [c.id for c in with_fp if _safe_search(c.gcc_fingerprint, msg)]
        if hits:
            decision.known.append(DiagnosticHit(message=msg, case_ids=hits))
            continue
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
