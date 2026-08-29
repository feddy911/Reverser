from __future__ import annotations

"""Eval gcc_fingerprint → recipe_id (P3). Not scoring ML.

  py -m src.analysis.eval_classifier
  py -m src.analysis.eval_classifier --out output/classifier_report.json

Cases with an empty fingerprint are compile-ok regressions and are not
classified. Duplicate fingerprint strings fail. Invalid regex fails.
Pairwise overlaps are reported; they do not fail the gate (several
diagnostics can share a skip-LLM hit).
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.agents.compiler import match_errors
from src.analysis.corpus import CorpusCase, DEFAULT_CORPUS_DIR, load_corpus


def _with_fp(cases: Sequence[CorpusCase]) -> List[CorpusCase]:
    return [c for c in cases if (c.gcc_fingerprint or "").strip()]


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


def _pairwise_overlaps(cases: Sequence[CorpusCase]) -> List[Tuple[str, str]]:
    """Pattern A matches pattern-string B (or vice versa)."""
    from src.agents.compiler import _safe_search

    out: List[Tuple[str, str]] = []
    items = list(cases)
    for i, a in enumerate(items):
        for b in items[i + 1 :]:
            if _safe_search(a.gcc_fingerprint, b.gcc_fingerprint) or _safe_search(
                b.gcc_fingerprint, a.gcc_fingerprint
            ):
                out.append((a.id, b.id))
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
    overlaps = _pairwise_overlaps(labeled)
    self_miss = []
    from src.agents.compiler import _safe_search

    for c in labeled:
        if not _safe_search(c.gcc_fingerprint, c.gcc_fingerprint):
            self_miss.append(c.id)

    n_fail = int(bool(invalid) or bool(duplicates))
    return {
        "n_cases": len(cases),
        "n_with_fp": len(labeled),
        "n_empty_fp": len(cases) - len(labeled),
        "n_invalid_regex": len(invalid),
        "invalid_regex": invalid,
        "n_duplicate_groups": len(duplicates),
        "duplicate_fingerprints": duplicates,
        "n_overlaps": len(overlaps),
        "overlaps": [{"a": a, "b": b} for a, b in overlaps],
        "n_self_miss": len(self_miss),
        "self_miss": self_miss,
        "ok": n_fail == 0,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Eval gcc_fingerprint classifier (P3, not scoring ML)"
    )
    parser.add_argument("--dir", default=str(DEFAULT_CORPUS_DIR))
    parser.add_argument("--out", default="output/classifier_report.json")
    parser.add_argument("--id", action="append", dest="ids")
    args = parser.parse_args(argv)

    report = eval_classifier(Path(args.dir), ids=args.ids)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    status = "OK" if report["ok"] else "FAIL"
    print(
        f"{status}: classifier fp={report['n_with_fp']}/{report['n_cases']} "
        f"dup={report['n_duplicate_groups']} overlaps={report['n_overlaps']} "
        f"-> {out}"
    )
    for item in report["invalid_regex"]:
        print(f"  INVALID {item['id']}: {item['error']}")
    for group in report["duplicate_fingerprints"]:
        print(f"  DUP  {', '.join(group)}")
    for pair in report["overlaps"]:
        print(f"  OVER {pair['a']} ~ {pair['b']}")
    if report["self_miss"]:
        print("  self-miss (pattern does not match its own text):")
        for cid in report["self_miss"]:
            print(f"    {cid}")

    # Smoke: known ostream message still classified.
    decision = match_errors(
        [{
            "message": (
                "cannot convert 'std::basic_ostream<char>' to "
                "'std::basic_ostream<char>*' in assignment"
            )
        }],
        load_corpus(Path(args.dir)),
    )
    if "ostream-ghidra-syntax" not in decision.known_ids:
        print("FAIL  smoke: ostream-ghidra-syntax missed")
        return 1
    print("  OK   smoke ostream-ghidra-syntax")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
