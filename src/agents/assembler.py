"""Link restored functions into one TU: order, prototypes, stubs.

Freeze: do not add assembler heuristics from a single exe run.
Capture the dialect as eval/corpus/<id>.yaml, then a recipe
(see src/analysis/corpus.py). Assembler must not rewrite function
semantics; Compiler agent applies corpus recipes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from src.analysis.ghidra_cpp import (
    extract_named_function,
    named_function_span,
    sanitize_ghidra_cpp,
    _match_forward,
    _split_top_args,
)
from src.domains.pack import NONE_PACK


def _default_preamble() -> List[str]:
    return NONE_PACK.preamble(
        "// restored_v2.cpp: symbol linking + struct dedup + noise removal"
    )

RE_THUNK_CALL = re.compile(r"\bthunk_FUN_([0-9a-fA-F]+)\s*\(")
RE_THUNK_ID = re.compile(r"\bthunk_FUN_([0-9a-fA-F]+)\b")
RE_DAT_ID = re.compile(r"\bDAT_([0-9a-fA-F]+)\b")
RE_DEBUG_LINE = re.compile(
    r"^[ \t]*(__CheckForDebuggerJustMyCode|_RTC_CheckStackVars2?|DebuggerProbe|DebuggerRuntime)\(.*$"
)
# MSVC Debug stack-fill (0xcccccccc) — compiler artefact, не domain-specific.
RE_CCC_LOOP = re.compile(
    r"^[ \t]*[A-Za-z_]\w*[ \t]*=[ \t]*&?[A-Za-z_]\w*[ \t]*;\s*\n"
    r"[ \t]*for[ \t]*\([^\n]*\)[ \t]*\{\s*\n"
    r"[ \t]*\*?[A-Za-z_]\w*(?:\[[^\]]*\])?[ \t]*=[ \t]*0xcccccccc[ \t]*;\s*\n"
    r"[ \t]*[A-Za-z_]\w*[ \t]*=[ \t]*[A-Za-z_]\w*[ \t]*\+[ \t]*1[ \t]*;\s*\n"
    r"[ \t]*\}",
    re.MULTILINE,
)
RE_STRUCT = re.compile(r"struct\s+[A-Za-z_]\w*\s*\{[^{}]*\}\s*;", re.DOTALL)
RE_INCLUDE = re.compile(r"^[ \t]*#include\b.*\n?", re.MULTILINE)
RE_PTR_PARAM = re.compile(r"\b([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)")
RE_ARROW_FIELD = re.compile(r"\b([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)")
RE_DOT_FIELD = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)")
RE_VALUE_DECL = re.compile(
    r"\b([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?;"
)

_KNOWN_TYPE_HEADS = frozenset({
    "void", "char", "int", "long", "short", "unsigned", "signed", "bool",
    "float", "double", "auto", "const", "volatile", "struct", "class",
    "std", "size_t", "size_type", "string", "wstring",
    "mpz_t", "mpz_ptr", "mpz_srcptr", "mpf_t", "mpq_t",
    "mpf_ptr", "mpq_ptr",
    "__mpz_struct", "__mpf_struct", "__mpq_struct",
    "__mpfr_struct", "mpfr_t", "mpfr_ptr", "mpfr_srcptr",
    "mpfr_exp_t", "mpfr_prec_t", "mpfr_rnd_t",
    "byte", "uchar", "ushort", "uint", "ulong", "ulonglong", "longlong",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined7", "undefined8",
    "int1", "int2", "int4", "int8", "uint1", "uint2", "uint4", "uint8",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "uintptr_t", "ptrdiff_t", "intmax_t", "uintmax_t",
    "pointer", "PBYTE", "PIMAGE_SECTION_HEADER", "unsigned_char",
    "ghidra_word",
    "initializer_list", "map", "set", "multiset", "list", "optional", "deque", "pair",
    "unordered_map", "unordered_set",
    "ostream", "ofstream", "istream", "ifstream",
    "duration", "ratio", "rep",
    "value_type", "value_type_conflict", "reference", "iterator",
    "const_iterator", "__const_iterator", "const_reference", "__node_type",
    "__normal_iterator", "_Rb_tree_const_iterator", "__iterator",
    "key_type", "mapped_type", "first_type", "allocator_type",
})


_NOT_STRUCT_TYPES = frozenset({
    "return", "else", "sizeof", "throw", "new", "delete", "case", "goto",
    "typedef", "using", "static", "extern", "register", "auto", "const",
    "volatile", "if", "for", "while", "switch", "do", "break", "continue",
    "void", "true", "false", "nullptr", "this", "operator",
})

_GHIDRA_TEMP_TYPE = re.compile(
    r"^(local_|param_|in_stack|in_stk_|auStack|stack_|var_\d+|lVar|uVar|iVar|sVar|"
    r"pcVar|puVar|pbVar|plVar|unaff_|register_)",
    re.IGNORECASE,
)


def _skip_infer_type(typ: str, already: Set[str]) -> bool:
    if not typ or typ in _KNOWN_TYPE_HEADS or typ in already:
        return True
    if typ in _NOT_STRUCT_TYPES:
        return True
    if _GHIDRA_TEMP_TYPE.match(typ):
        return True
    return False


def _infer_structs(text: str, already: Set[str]) -> Dict[str, Set[str]]:
    """Unknown `T` used as a Ghidra type → struct T (pointer, value, or array)."""
    var_type: Dict[str, str] = {}
    types_seen: Set[str] = set()
    blob = text or ""
    for typ, var in RE_PTR_PARAM.findall(blob):
        if _skip_infer_type(typ, already):
            continue
        var_type[var] = typ
        types_seen.add(typ)
    for typ, var in RE_VALUE_DECL.findall(blob):
        if _skip_infer_type(typ, already):
            continue
        var_type.setdefault(var, typ)
        types_seen.add(typ)
    fields: Dict[str, Set[str]] = {t: set() for t in types_seen}
    for var, field in RE_ARROW_FIELD.findall(blob):
        typ = var_type.get(var)
        if typ:
            fields[typ].add(field)
    for var, field in RE_DOT_FIELD.findall(blob):
        typ = var_type.get(var)
        if typ:
            fields[typ].add(field)
    return fields


def _format_inferred_struct(name: str, fields: Set[str]) -> str:
    lines = [f"struct {name} {{"]
    if fields:
        for f in sorted(fields):
            lines.append(f"  ghidra_word {f};")
        lines.append("  undefined1 _opaque[0x80];")
    else:
        lines.append("  undefined1 _opaque[0x100];")
    lines.append("};")
    return "\n".join(lines)


def _clean_code(code: str, name: str = "") -> str:
    code = RE_INCLUDE.sub("", code or "")
    if name:
        code = extract_named_function(code, name)
    code = RE_CCC_LOOP.sub("", code)
    lines = [ln for ln in code.splitlines() if not RE_DEBUG_LINE.match(ln)]
    text = "\n".join(lines)
    text = text.replace("cout_exref", "std::cout").replace("cerr_exref", "std::cerr")
    text = sanitize_ghidra_cpp(text)
    from src.agents.restorer import repair_restore_debris
    text = repair_restore_debris(text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _strip_void_result_assigns(code: str, void_names: Set[str]) -> str:
    """`x = void_fn(` is invalid C++; drop the assignment (Ghidra/LLM)."""
    if not code or not void_names:
        return code
    names = "|".join(re.escape(n) for n in sorted(void_names, key=len, reverse=True))
    return re.sub(
        rf"(^|[;{{]\s*)[A-Za-z_]\w*\s*=\s*({names})\s*\(",
        r"\1\2(",
        code,
        flags=re.MULTILINE,
    )


def _proto_wants_ptr(proto: str) -> List[bool]:
    m = re.search(r"\((.*)\)\s*;?\s*$", proto or "", re.DOTALL)
    if not m:
        return []
    inner = m.group(1).strip()
    if not inner or inner == "void":
        return []
    flags: List[bool] = []
    for p in _split_top_args(inner):
        t = p.strip()
        flags.append(bool(re.search(r"\*\s*[A-Za-z_]\w*\s*$", t) or t.endswith("*")))
    return flags


def _declares_pointer(code: str, ident: str) -> bool:
    return bool(re.search(rf"\*\s*{re.escape(ident)}\b", code or ""))


def _declares_array(code: str, ident: str) -> bool:
    """`T name[N]` decays to T*; do not take its address."""
    return bool(
        re.search(rf"\b[A-Za-z_]\w*\s+{re.escape(ident)}\s*\[", code or "")
    )


def _adjust_one_arg(arg: str, wants_ptr: bool, code: str = "") -> str:
    a = (arg or "").strip()
    if not wants_ptr or not a:
        return arg
    if a.startswith("*") and not a.startswith("**"):
        return a[1:].strip()
    if a.startswith("&"):
        return arg
    if re.match(r"^[A-Za-z_]\w*$", a):
        if _declares_pointer(code, a) or _declares_array(code, a):
            return arg
        return "&" + a
    return arg


def _adjust_calls_to_ptrs(code: str, self_name: str, ptrs: Dict[str, List[bool]]) -> str:
    """If callee proto takes T*, pass a pointer (`&x` / drop extra `*`)."""
    s = code or ""
    for callee, flags in ptrs.items():
        if callee == self_name or not flags:
            continue
        out: list[str] = []
        copied = 0
        for m in re.finditer(rf"\b{re.escape(callee)}\s*\(", s):
            open_p = m.end() - 1
            close = _match_forward(s, open_p, "(", ")")
            if close < 0:
                continue
            after = s[close + 1:].lstrip()
            if after.startswith("{"):
                continue
            args = _split_top_args(s[open_p + 1:close])
            new_args = []
            changed = False
            for i, a in enumerate(args):
                want = flags[i] if i < len(flags) else False
                adj = _adjust_one_arg(a, want, s)
                new_args.append(adj)
                if adj.strip() != a.strip():
                    changed = True
            if not changed:
                continue
            out.append(s[copied:open_p + 1])
            out.append(", ".join(new_args))
            out.append(")")
            copied = close + 1
        out.append(s[copied:])
        s = "".join(out)
    return s


def _prototype(name: str, code: str) -> Optional[str]:
    """First function signature for `name` as a forward declaration."""
    if not name or not code:
        return None
    blob = RE_INCLUDE.sub("", code)
    span = named_function_span(blob, name, skip_qualified=True)
    if not span:
        return None
    t0, close, _end = span
    sig = re.sub(r"\s+", " ", blob[t0:close + 1]).strip()
    sig = sanitize_ghidra_cpp(sig)
    if not sig.endswith(";"):
        sig += ";"
    return sig


def _nargs_in_parens(inner: str) -> int:
    t = (inner or "").strip()
    if not t or t == "void":
        return 0
    return len(_split_top_args(t))


def _max_call_arity(name: str, blob: str) -> int:
    """Max args at call sites of `name` (definitions, with '{{' after, skipped)."""
    if not name or name == "main":
        return 0
    s = blob or ""
    best = 0
    for m in re.finditer(rf"\b{re.escape(name)}\s*\(", s):
        open_p = m.end() - 1
        close = _match_forward(s, open_p, "(", ")")
        if close < 0:
            continue
        after = s[close + 1:].lstrip()
        if after.startswith("{"):
            continue
        inner = s[open_p + 1:close].strip()
        n = 0 if not inner else len(_split_top_args(inner))
        if n > best:
            best = n
    return best


def _widen_def_arity(name: str, code: str, blob: str) -> str:
    """If call sites pass more args than the def, accept extras via ellipsis.

    Restore often drops parameters. Arity only; no new control flow.
    """
    src = code or ""
    if not name or name == "main":
        return src
    need = _max_call_arity(name, blob)
    if need <= 0:
        return src
    span = named_function_span(src, name, skip_qualified=True)
    if not span:
        return src
    t0, close, _end = span
    open_p = -1
    i = t0
    while i <= close:
        if src[i] == "(" and _match_forward(src, i, "(", ")") == close:
            open_p = i
            break
        i += 1
    if open_p < 0:
        return src
    inner = src[open_p + 1:close].strip()
    if "..." in inner:
        return src
    have = _nargs_in_parens(inner)
    if have >= need:
        return src
    fill = "..." if (not inner or inner == "void") else inner + ", ..."
    return src[:open_p + 1] + fill + src[close:]


def _ghidra_stubs(text: str) -> List[str]:
    """Declarations for leftover Ghidra thunks/DAT so the TU can parse."""
    thunks = sorted(set(RE_THUNK_ID.findall(text or "")))
    dats = sorted(set(RE_DAT_ID.findall(text or "")))
    need_main = bool(re.search(r"\b__main\s*\(", text or ""))
    if not thunks and not dats and not need_main:
        return []
    lines = ["// ---- ghidra thunk/data stubs ----"]
    for h in dats:
        # Ghidra takes &DAT_* as a byte/string pointer (undefined*).
        lines.append(f"static undefined DAT_{h};")
    for h in thunks:
        lines.append(f"inline ghidra_word thunk_FUN_{h}(...) {{ return {{}}; }}")
    if need_main:
        lines.append("inline void __main() {}")
    lines.append("")
    return lines


_RE_STRUCT_NAME = re.compile(r"\bstruct\s+([A-Za-z_]\w*)")


def type_stubs_for_snippet(
    code: str,
    preamble: str = "",
    sibling_names: Optional[Sequence[str]] = None,
    current_name: str = "",
) -> List[str]:
    """Same inferred structs + thunk/DAT stubs assemble() prepends, for one fn.

    Per-function compile uses includes preamble only; without these stubs
    known dialect undeclared-struct-type is a TU-only win. Sibling names
    come from the Ghidra dump, not hard-coded sample symbols.
    """
    blob = code or ""
    already = set(_RE_STRUCT_NAME.findall(preamble or ""))
    already |= set(_RE_STRUCT_NAME.findall(blob))
    inferred = _infer_structs(blob, already)
    lines: List[str] = []
    names = [n for n in sorted(inferred) if n not in already]
    if names:
        lines.append("// ---- inferred types (per-fn) ----")
        for name in names:
            lines.append(_format_inferred_struct(name, inferred[name]))
            lines.append("")
    lines.extend(_ghidra_stubs(blob))
    lines.extend(_sibling_call_stubs(blob, sibling_names or [], current_name))
    return lines


def _sibling_call_stubs(
    code: str,
    sibling_names: Sequence[str],
    current_name: str = "",
) -> List[str]:
    """Prototypes for other user functions this snippet calls (per-fn only)."""
    from src.analysis.platform import is_runtime_noise

    blob = code or ""
    cur = (current_name or "").strip()
    lines: List[str] = []
    seen: Set[str] = set()
    for raw in sibling_names:
        name = (raw or "").strip()
        if not name or name == cur or name in seen:
            continue
        if is_runtime_noise(name) or name.startswith(("FUN_", "thunk_", "_")):
            continue
        if not re.search(rf"\b{re.escape(name)}\s*\(", blob):
            continue
        seen.add(name)
        lines.append(f"inline ghidra_word {name}(...) {{ return {{}}; }}")
    if not lines:
        return []
    return ["// ---- sibling user calls (per-fn) ----"] + lines + [""]


_RE_INT_DAT = re.compile(
    r"^[ \t]*(?:extern(?:\s+\"C\")?\s+|static\s+)?(?:(?:std::)?u?int(?:8|16|32|64)_t|"
    r"undefined\d*|unsigned(?:\s+long(?:\s+long)?)?|long(?:\s+long)?|int)\s+"
    r"DAT_[0-9A-Fa-f]+\s*;\s*\n?",
    re.MULTILINE | re.IGNORECASE,
)
_RE_DEBUG_EXTERN = re.compile(
    r"^[ \t]*extern\s+void\s+__"
    r"(?:CheckForDebuggerJustMyCode|RTC_CheckStackVars2?)\s*\([^;]*\)\s*;\s*\n?",
    re.MULTILINE,
)


def strip_int_dat_redecls(source: str) -> str:
    """Drop integer DAT_* / debugger lines that clash with assembler stubs."""
    t = _RE_INT_DAT.sub("", source or "")
    return _RE_DEBUG_EXTERN.sub("", t)


def user_emit_order(user: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Callees before callers: keep `main` last so the TU can compile."""

    def key(r: Dict[str, Any]) -> Tuple[int, str]:
        n = (r.get("guessed_name") or r.get("ghidra_name") or "").strip()
        return (1 if n == "main" else 0, n)

    return sorted(user or [], key=key)


def assemble(
    restored: List[Dict[str, Any]],
    functions,
    thunks,
    preamble_lines: Optional[List[str]] = None,
) -> Tuple[str, int]:
    user = [
        r for r in restored or []
        if r.get("classification") == "user_code" and (r.get("cpp_code") or "").strip()
    ]
    user = user_emit_order(user)

    # 1) адрес -> излучаемый символ
    sym: Dict[str, str] = {}
    for r in user:
        a = (r.get("address") or "").strip()
        g = (r.get("guessed_name") or "").strip()
        sym[a] = g or (r.get("ghidra_name") or "").strip() or ("sub_" + a)

    # 2) структуры: вынимаем из тел, держим самую детальную на имя
    best: Dict[str, str] = {}
    bodies: List[Tuple[str, str, str]] = []
    for r in user:
        addr = (r.get("address") or "").strip()
        fname = sym[addr]
        code = extract_named_function(RE_INCLUDE.sub("", r["cpp_code"] or ""), fname)
        for block in RE_STRUCT.findall(code):
            m = re.match(r"struct\s+([A-Za-z_]\w*)", block)
            if not m:
                continue
            name = m.group(1)
            if name not in best or block.count(";") > best[name].count(";"):
                best[name] = block
        code = RE_STRUCT.sub("", code)
        bodies.append((r.get("address", ""), fname, code))

    # 3) резолв thunk-вызовов по sym
    unresolved: set = set()

    def repl(mo: re.Match) -> str:
        t = "0x" + mo.group(1)
        if t in sym:
            return sym[t] + "("
        unresolved.add(t)
        return mo.group(0)

    cleaned: List[Tuple[str, str, str]] = []
    for addr, name, code in bodies:
        code = RE_THUNK_CALL.sub(repl, code)
        code = strip_int_dat_redecls(_clean_code(code, name=name))
        cleaned.append((addr, name, code))

    void_names = set()
    for _addr, name, code in cleaned:
        proto = _prototype(name, code)
        if proto and proto.lstrip().startswith("void "):
            void_names.add(name)
    if void_names:
        cleaned = [
            (addr, name, _strip_void_result_assigns(code, void_names))
            for addr, name, code in cleaned
        ]

    ptrs: Dict[str, List[bool]] = {}
    for _addr, name, code in cleaned:
        proto = _prototype(name, code)
        if proto:
            flags = _proto_wants_ptr(proto)
            if any(flags):
                ptrs[name] = flags
    if ptrs:
        cleaned = [
            (addr, name, _adjust_calls_to_ptrs(code, name, ptrs))
            for addr, name, code in cleaned
        ]

    all_code = "\n".join(c for _, _, c in cleaned)
    cleaned = [
        (addr, name, _widen_def_arity(name, code, all_code))
        for addr, name, code in cleaned
    ]

    parts: List[str] = list(preamble_lines) if preamble_lines is not None else _default_preamble()
    parts.append("// ---- types (dedup) ----")
    for name in sorted(best):
        parts.append(best[name].strip())
        parts.append("")
    blob = "\n".join(c for _, _, c in cleaned)
    inferred = _infer_structs(blob, set(best))
    for name in sorted(inferred):
        if name in best:
            continue
        parts.append(_format_inferred_struct(name, inferred[name]))
        parts.append("")
    parts.extend(_ghidra_stubs(blob))
    parts.append("// ---- prototypes ----")
    for addr, name, code in cleaned:
        proto = _prototype(name, code)
        if proto:
            parts.append(proto)
    parts.append("")
    parts.append("// ---- functions ----")
    for addr, name, code in cleaned:
        parts.append("// " + "=" * 60)
        parts.append(f"// {name} @ {addr}")
        parts.append("// " + "=" * 60)
        parts.append(code)
        parts.append("")
    if unresolved:
        parts.append("// unresolved (STL/CRT wrappers): " + ", ".join(sorted(unresolved)))
    return "\n".join(parts), len(cleaned)
