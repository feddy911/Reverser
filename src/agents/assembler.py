from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

RE_THUNK_CALL = re.compile(r"\bthunk_FUN_([0-9a-fA-F]+)\s*\(")
RE_DEBUG_LINE = re.compile(
    r"^[ \t]*(__CheckForDebuggerJustMyCode|_RTC_CheckStackVars2?|DebuggerProbe|DebuggerRuntime)\(.*$"
)
RE_CCC_LOOP = re.compile(
    r"^[ \t]*[A-Za-z_]\w*[ \t]*=[ \t]*&?[A-Za-z_]\w*[ \t]*;\s*\n"
    r"[ \t]*for[ \t]*\([^\n]*\)[ \t]*\{\s*\n"
    r"[ \t]*\*?[A-Za-z_]\w*(?:\[[^\]]*\])?[ \t]*=[ \t]*0xcccccccc[ \t]*;\s*\n"
    r"[ \t]*[A-Za-z_]\w*[ \t]*=[ \t]*[A-Za-z_]\w*[ \t]*\+[ \t]*1[ \t]*;\s*\n"
    r"[ \t]*\}",
    re.MULTILINE,
)
RE_STRUCT = re.compile(r"struct\s+[A-Za-z_]\w*\s*\{[^{}]*\}\s*;", re.DOTALL)

# локальные "структуры-виды" не должны затенять реальные типы
RENAME = {"mpz_t": "mpz_view", "MyStruct": "CollatzState"}

HEADER = [
    "// restored_v2.cpp: symbol linking + struct dedup + noise removal",
    "#include <cstdio>",
    "#include <cstring>",
    "#include <iostream>",
    "#include <string>",
    "#include <vector>",
    "#include <chrono>",
    "#include <fstream>",
    "#include <gmp.h>",
    "",
]


def _ren(text: str) -> str:
    for old, new in RENAME.items():
        text = re.sub(r"\b" + old + r"\b", new, text)
    return text


def _clean_code(code: str) -> str:
    code = RE_CCC_LOOP.sub("", code)
    lines = [ln for ln in code.splitlines() if not RE_DEBUG_LINE.match(ln)]
    text = "\n".join(lines)
    text = text.replace("cout_exref", "std::cout").replace("cerr_exref", "std::cerr")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def assemble(restored: List[Dict[str, Any]], functions, thunks) -> Tuple[str, int]:
    user = [r for r in restored or []
            if r.get("classification") == "user_code" and (r.get("cpp_code") or "").strip()]

    # 1) адрес -> излучаемый символ (guessed или ghidra-fallback) — РЕЗОЛВИМ ВСЕХ
    sym: Dict[str, str] = {}
    for r in user:
        a = (r.get("address") or "").strip()
        g = (r.get("guessed_name") or "").strip()
        sym[a] = g or (r.get("ghidra_name") or "").strip() or ("sub_" + a)

    # 2) структуры: вынимаем из тел, держим самую детальную на имя, переименовываем
    best: Dict[str, str] = {}
    bodies: List[Tuple[str, str, str]] = []
    for r in user:
        code = r["cpp_code"]
        for block in RE_STRUCT.findall(code):
            m = re.match(r"struct\s+([A-Za-z_]\w*)", block)
            if not m:
                continue
            name = m.group(1)
            if name not in best or block.count(";") > best[name].count(";"):
                best[name] = block
        code = _ren(RE_STRUCT.sub("", code))
        bodies.append((r.get("address", ""), sym[(r.get("address") or "").strip()], code))

    # 3) резолв thunk-вызовов по sym; остальное — в unresolved
    unresolved: set = set()

    def repl(mo: re.Match) -> str:
        t = "0x" + mo.group(1)
        if t in sym:
            return sym[t] + "("
        unresolved.add(t)
        return mo.group(0)

    parts: List[str] = list(HEADER)
    parts.append("// ---- types (dedup) ----")
    for name in sorted(best):
        parts.append(_ren(best[name]).strip())
        parts.append("")
    parts.append("// ---- functions ----")
    for addr, name, code in bodies:
        code = RE_THUNK_CALL.sub(repl, code)
        code = _clean_code(code)
        parts.append("// " + "=" * 60)
        parts.append(f"// {name} @ {addr}")
        parts.append("// " + "=" * 60)
        parts.append(code)
        parts.append("")
    if unresolved:
        parts.append("// unresolved (STL/CRT wrappers): " + ", ".join(sorted(unresolved)))
    return "\n".join(parts), len(bodies)