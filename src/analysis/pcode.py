from __future__ import annotations

"""High p-code from the Ghidra dump. Restore p5 is not live (p4 still uses C).

The headless script may attach ``pcode`` next to ``ghidra_code``. Cached
``ghidra_full_v6`` dumps without the field stay valid. Do not bump
LLM_PROMPT_VER until the restore prompt consumes these ops.
"""

from typing import Any, Dict, List, Optional

PCODE_KEY = "pcode"
MAX_PCODE_CHARS = 12_000
MAX_PCODE_OPS = 500


def clip_pcode(text: str, limit: int = MAX_PCODE_CHARS) -> str:
    raw = text or ""
    if len(raw) <= limit:
        return raw
    return raw[:limit]


def op_lines(text: str) -> List[str]:
    """Non-empty p-code op lines. Not a dialect recipe and not FEATURE_KEYS."""
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]


def entry_pcode(entry: Optional[Dict[str, Any]]) -> str:
    if not isinstance(entry, dict):
        return ""
    return clip_pcode(str(entry.get(PCODE_KEY) or ""))
