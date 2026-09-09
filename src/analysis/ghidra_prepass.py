"""I4: count Ghidra ``this`` in prototypes. Pre-pass analyzers are not live.

RecoverClassesFromRTTI, DWARF (when present), and FID libraries are *design*
notes only. ``src/ghidra/headless.py`` still runs import/process plus
``GhidraDecompileAll.java``. Do not bump ``GHIDRA_CACHE_KEY`` from this
module — a real pre-pass would re-dump caches as ``ghidra_full_v7``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

LIVE_PREPASS = False
CACHE_KEY_NOW = "ghidra_full_v6"
# Not enabled in headless.py. Listed so a later dump bump is an explicit choice.
DESIGN_ANALYZERS = (
    "RecoverClassesFromRTTI",
    "DWARF",
    "FID",
)

_RE_STL_NS = re.compile(r"\bstd::|__gnu_cxx::")
_RE_DWARF = re.compile(r"DWARF original prototype")
_RE_THIS_PARAM = re.compile(
    r"[(,]\s*(?:(?:[A-Za-z_][\w:]*)\s*\*+\s*)?this\s*[,)]"
)
_RE_THISCALL = re.compile(r"\b__thiscall\b")


def prototype_span(ghidra_code: str) -> str:
    """Text before the first body ``{``. Comments in the body are ignored."""
    s = (ghidra_code or "").replace("\r\n", "\n").replace("\r", "\n")
    idx = s.find("{")
    return s[:idx] if idx >= 0 else s


def proto_has_this(proto: str) -> bool:
    """True for Ghidra thiscall / ``Type *this`` in the signature, not the body."""
    blob = proto or ""
    if _RE_THISCALL.search(blob):
        return True
    return _RE_THIS_PARAM.search(blob) is not None


def hit_is_stl(hit: Dict[str, str]) -> bool:
    blob = f"{hit.get('proto') or ''} {hit.get('name') or ''}"
    return _RE_STL_NS.search(blob) is not None


def hit_has_dwarf(hit: Dict[str, str]) -> bool:
    return _RE_DWARF.search(hit.get("proto") or "") is not None


def this_proto_hits(functions: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    for fn in functions or []:
        proto = prototype_span(str(fn.get("ghidra_code") or ""))
        if not proto_has_this(proto):
            continue
        hits.append(
            {
                "address": str(fn.get("address") or ""),
                "name": str(fn.get("name") or ""),
                "proto": " ".join(proto.split())[:240],
            }
        )
    return hits


def summarize_dump(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    funcs = list((data or {}).get("functions") or [])
    hits = this_proto_hits(funcs)
    n_stl = sum(1 for h in hits if hit_is_stl(h))
    n_dwarf = sum(1 for h in hits if hit_has_dwarf(h))
    return {
        "n_functions": len(funcs),
        "n_this_proto": len(hits),
        "n_this_proto_stl": n_stl,
        "n_this_proto_other": len(hits) - n_stl,
        "n_this_proto_dwarf": n_dwarf,
        "live_prepass": LIVE_PREPASS,
        "cache_key": CACHE_KEY_NOW,
        "design_analyzers": list(DESIGN_ANALYZERS),
        "hits": hits,
    }


def compare_summaries(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Delta of this-proto counts. Not a live before/after Ghidra pre-pass."""
    return {
        "left_n_this_proto": int(left.get("n_this_proto") or 0),
        "right_n_this_proto": int(right.get("n_this_proto") or 0),
        "delta_this_proto": int(right.get("n_this_proto") or 0)
        - int(left.get("n_this_proto") or 0),
        "live_prepass": LIVE_PREPASS,
        "note": (
            "Same v6 dumps, no RTTI/DWARF/FID. "
            "Do not bump cache to v7 until a real pre-pass dump exists."
        ),
    }


def main(argv: Optional[List[str]] = None) -> int:
    paths = [Path(p) for p in (argv if argv is not None else sys.argv[1:])]
    if not paths:
        print("usage: py -m src.analysis.ghidra_prepass <ghidra_full_v6.json> ...")
        return 2
    summaries: List[Dict[str, Any]] = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        summary = summarize_dump(data)
        summary["path"] = str(path)
        summaries.append(summary)
        print(
            f"{path}: this-proto {summary['n_this_proto']}/"
            f"{summary['n_functions']} "
            f"stl={summary['n_this_proto_stl']} "
            f"other={summary['n_this_proto_other']} "
            f"dwarf={summary['n_this_proto_dwarf']} "
            f"(live_prepass={LIVE_PREPASS})"
        )
        for hit in summary["hits"][:12]:
            print(f"  {hit['address']} {hit['name']}: {hit['proto']}")
    if len(summaries) == 2:
        delta = compare_summaries(summaries[0], summaries[1])
        print(
            "compare: delta_this_proto="
            f"{delta['delta_this_proto']} ({summaries[0].get('path')} vs "
            f"{summaries[1].get('path')})"
        )
        print(delta["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
