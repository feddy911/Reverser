from __future__ import annotations

"""Eval gcc_fingerprint → recipe_id (P3). Not scoring ML.

  py -m src.analysis.eval_classifier
  py -m src.analysis.eval_classifier --out output/classifier_report.json

Cases with an empty fingerprint are compile-ok regressions and are not
classified. Duplicate fingerprint strings fail. Invalid regex fails.
Each synthesized (or explicit gcc_probe) message must hit its own case.
Probe collisions are reported; they do not fail the default gate — related
recipes may share a skip-LLM diagnostic (e.g. ostream sanitize vs assemble).
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.agents.compiler import _safe_search, match_errors
from src.analysis.corpus import CorpusCase, DEFAULT_CORPUS_DIR, load_corpus

# One gcc diagnostic, two recipes (sanitize vs assemble). Default gate stays
# green; --fail-on-overlap ignores this pair only.
EXPECTED_OVERLAP_PAIRS = {
    frozenset({"ghidra-ostream-assemble", "ostream-ghidra-syntax"}),
}


def _with_fp(cases: Sequence[CorpusCase]) -> List[CorpusCase]:
    return [c for c in cases if (c.gcc_fingerprint or "").strip()]


def split_alts(pattern: str) -> List[str]:
    """Split a fingerprint on top-level unescaped ``|`` (not inside ``[]``)."""
    parts: List[str] = []
    buf: List[str] = []
    in_class = False
    escaped = False
    for ch in pattern or "":
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            continue
        if ch == "[" and not in_class:
            in_class = True
            buf.append(ch)
            continue
        if ch == "]" and in_class:
            in_class = False
            buf.append(ch)
            continue
        if ch == "|" and not in_class:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return [p for p in parts if p]


def _class_token(cls: str) -> str:
    body = cls[1:] if cls.startswith("^") else cls
    if "0-9" in body and "A-Z" not in body and "a-z" not in body:
        return "0"
    if "A-Z" in body:
        return "C"
    if "a-z" in body:
        return "a"
    return "A"


def regex_to_probe(pattern: str) -> str:
    """Build a gcc-like string that ``pattern`` should match.

    Fingerprints in this corpus are diagnostic regexes, not arbitrary REs.
    ``.*`` becomes a space; character classes become one representative char.
    """
    s = pattern or ""
    out: List[str] = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\" and i + 1 < n:
            out.append(s[i + 1])
            i += 2
            continue
        if ch == "[":
            j = i + 1
            if j < n and s[j] == "^":
                j += 1
            while j < n and s[j] != "]":
                if s[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            cls = s[i + 1 : j]
            token = _class_token(cls)
            i = j + 1 if j < n else n
            if i < n and s[i] in "*+?":
                q = s[i]
                i += 1
                if q == "+":
                    out.append(token)
            else:
                out.append(token)
            continue
        if ch == "." and i + 1 < n and s[i + 1] == "*":
            out.append(" ")
            i += 2
            continue
        if ch == "." and i + 1 < n and s[i + 1] == "+":
            out.append("X")
            i += 2
            continue
        if ch == ".":
            out.append("X")
            i += 1
            continue
        if ch in "*+?":
            i += 1
            continue
        if ch in "()":
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def probes_for_case(case: CorpusCase) -> List[str]:
    explicit = [p.strip() for p in (case.gcc_probe or []) if str(p).strip()]
    if explicit:
        return explicit
    return [regex_to_probe(alt) for alt in split_alts(case.gcc_fingerprint)]


def _regex_error(pattern: str) -> Optional[str]:
    try:
        re.compile(pattern)
    except re.error as exc:
        return str(exc)
    return None


def _duplicate_groups(cases: Sequence[CorpusCase]) -> List[List[str]]:
    buckets: Dict[str, List[str]] = {}
    for c in cases:
        buckets.setdefault(c.gcc_fingerprint.strip(), []).append(c.id)
    return [ids for ids in buckets.values() if len(ids) > 1]


def unexpected_overlaps(collisions: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Overlaps that are not the known ostream sanitize/assemble pair."""
    out: List[Dict[str, Any]] = []
    for item in collisions or []:
        pair = frozenset((item.get("a"), item.get("b")))
        if pair in EXPECTED_OVERLAP_PAIRS:
            continue
        out.append(dict(item))
    return out


def eval_classifier(
    directory: Optional[Path] = None,
    *,
    ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    cases = load_corpus(directory)
    if ids:
        want = set(ids)
        cases = [c for c in cases if c.id in want]
    labeled = _with_fp(cases)
    invalid = [
        {"id": c.id, "error": _regex_error(c.gcc_fingerprint)}
        for c in labeled
        if _regex_error(c.gcc_fingerprint)
    ]
    duplicates = _duplicate_groups(labeled)

    self_miss: List[Dict[str, Any]] = []
    collisions: List[Dict[str, Any]] = []
    seen_pairs = set()
    for case in labeled:
        probes = probes_for_case(case)
        if not probes:
            self_miss.append({"id": case.id, "probe": "", "hits": []})
            continue
        for probe in probes:
            if not _safe_search(case.gcc_fingerprint, probe):
                self_miss.append({
                    "id": case.id,
                    "probe": probe,
                    "hits": [],
                    "reason": "fingerprint does not match synthesized probe",
                })
                continue
            decision = match_errors([{"message": probe}], labeled)
            hits = decision.known_ids
            if case.id not in hits:
                self_miss.append({"id": case.id, "probe": probe, "hits": hits})
                continue
            extra = [h for h in hits if h != case.id]
            for other in extra:
                pair = tuple(sorted((case.id, other)))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                collisions.append({
                    "a": case.id,
                    "b": other,
                    "probe": probe,
                })

    n_explicit = sum(1 for c in labeled if any(str(p).strip() for p in (c.gcc_probe or [])))
    n_fail = int(bool(invalid) or bool(duplicates) or bool(self_miss))
    unexpected = unexpected_overlaps(collisions)
    return {
        "n_cases": len(cases),
        "n_with_fp": len(labeled),
        "n_empty_fp": len(cases) - len(labeled),
        "n_explicit_probe": n_explicit,
        "n_invalid_regex": len(invalid),
        "invalid_regex": invalid,
        "n_duplicate_groups": len(duplicates),
        "duplicate_fingerprints": duplicates,
        "n_self_miss": len(self_miss),
        "self_miss": self_miss,
        "n_overlaps": len(collisions),
        "overlaps": collisions,
        "n_unexpected_overlaps": len(unexpected),
        "unexpected_overlaps": unexpected,
        "ok": n_fail == 0,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Eval gcc_fingerprint classifier (P3, not scoring ML)"
    )
    parser.add_argument("--dir", default=str(DEFAULT_CORPUS_DIR))
    parser.add_argument("--out", default="output/classifier_report.json")
    parser.add_argument("--id", action="append", dest="ids")
    parser.add_argument(
        "--fail-on-overlap",
        action="store_true",
        help=(
            "Fail on unexpected probe collisions. The ostream sanitize/assemble "
            "pair is allowlisted (one gcc, two recipes). Not the default gate."
        ),
    )
    parser.add_argument(
        "--list-probes",
        action="store_true",
        help="Print each fingerprint class probe (explicit gcc_probe or synthesized)",
    )
    args = parser.parse_args(argv)

    report = eval_classifier(Path(args.dir), ids=args.ids)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    overlap_fail = bool(args.fail_on_overlap and report["n_unexpected_overlaps"])
    ok = report["ok"] and not overlap_fail
    status = "OK" if ok else "FAIL"
    print(
        f"{status}: classifier fp={report['n_with_fp']}/{report['n_cases']} "
        f"self_miss={report['n_self_miss']} dup={report['n_duplicate_groups']} "
        f"overlaps={report['n_overlaps']} unexpected={report['n_unexpected_overlaps']} "
        f"explicit_probe={report['n_explicit_probe']} -> {out}"
    )
    for item in report["invalid_regex"]:
        print(f"  INVALID {item['id']}: {item['error']}")
    for group in report["duplicate_fingerprints"]:
        print(f"  DUP  {', '.join(group)}")
    for miss in report["self_miss"]:
        print(
            f"  MISS {miss['id']}: probe={miss.get('probe')!r} "
            f"hits={miss.get('hits')} {miss.get('reason') or ''}"
        )
    for pair in report["overlaps"]:
        tag = (
            "expected"
            if frozenset((pair["a"], pair["b"])) in EXPECTED_OVERLAP_PAIRS
            else "unexpected"
        )
        print(f"  OVER [{tag}] {pair['a']} ~ {pair['b']}  probe={pair['probe']!r}")
    if args.list_probes:
        cases = load_corpus(Path(args.dir))
        if args.ids:
            want = set(args.ids)
            cases = [c for c in cases if c.id in want]
        for case in _with_fp(cases):
            src = (
                "explicit"
                if any(str(p).strip() for p in (case.gcc_probe or []))
                else "synth"
            )
            for probe in probes_for_case(case):
                print(f"  PROBE {case.id} [{src}] {probe!r}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
