from __future__ import annotations

"""Data-driven lexical rewrites for Ghidra C++ (not structural parsers)."""

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Pattern, Tuple

import yaml

LEXICAL_PATH = Path(__file__).with_name("lexical_rewrites.yaml")


@lru_cache(maxsize=1)
def _steps() -> Dict[str, Tuple[List[Tuple[str, str]], List[Tuple[Pattern[str], str]]]]:
    data = yaml.safe_load(LEXICAL_PATH.read_text(encoding="utf-8")) or {}
    out: Dict[str, Tuple[List[Tuple[str, str]], List[Tuple[Pattern[str], str]]]] = {}
    for step in data.get("steps") or []:
        when = str(step.get("when") or "")
        repl = [
            (str(x["find"]), str(x["replace"]))
            for x in (step.get("replacements") or [])
            if x.get("find") is not None
        ]
        rx = [
            (re.compile(str(x["pattern"])), str(x["replace"]))
            for x in (step.get("regex") or [])
            if x.get("pattern")
        ]
        out[when] = (repl, rx)
    return out


def apply_lexical(chunk: str, when: str) -> str:
    """Apply YAML replacements for one `_types` slot."""
    t = chunk or ""
    repl, rx = _steps().get(when, ([], []))
    for old, new in repl:
        t = t.replace(old, new)
    for cre, new in rx:
        t = cre.sub(new, t)
    return t
