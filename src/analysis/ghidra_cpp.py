"""Normalize Ghidra-decompiler C++ so a real compiler can parse it.

Freeze: do not add rewrite rules from a single binary run. New dialects go
into eval/corpus/ as a fixture first; only then a recipe (see
src/analysis/corpus.py).
"""

from __future__ import annotations

import re

from src.analysis.lexical import apply_lexical

# Ghidra prints `unsigned_char`, `_long_long_unsigned_int`, `int_const`.
_UNDERSCORE_TYPE_BASE = (
    ("unsigned_long_long", "unsigned long long"),
    ("long_long_unsigned_int", "unsigned long long"),
    ("long_long_int", "long long"),
    ("unsigned_char_const", "unsigned char const"),
    ("unsigned_char", "unsigned char"),
    ("signed_char", "signed char"),
    ("long_long", "long long"),
    ("unsigned_int", "unsigned int"),
    ("unsigned_long", "unsigned long"),
    ("unsigned_short", "unsigned short"),
    ("__int64", "long long"),
    ("int_const", "int const"),
    ("char_const", "char const"),
    ("void_const", "void const"),
)
# Leading underscore leftover after `_std::` / template noise (`_long_long_unsigned_int`).
_UNDERSCORE_TYPES = tuple(
    item
    for old, new in _UNDERSCORE_TYPE_BASE
    for item in (("_" + old, new), (old, new))
)

_BARE_TEMPLATE = (
    (re.compile(r"(?<![:\w])vector\s*<"), "std::vector<"),
    (re.compile(r"(?<![:\w])basic_string\s*<"), "std::basic_string<"),
    (re.compile(r"(?<![:\w])allocator\s*<"), "std::allocator<"),
    (re.compile(r"(?<![:\w])char_traits\s*<"), "std::char_traits<"),
    (re.compile(r"(?<![:\w])initializer_list\s*<"), "std::initializer_list<"),
    (re.compile(r"(?<![:\w])unordered_map\s*<"), "std::unordered_map<"),
    (re.compile(r"(?<![:\w])unordered_set\s*<"), "std::unordered_set<"),
    (re.compile(r"(?<![:\w])map\s*<"), "std::map<"),
    (re.compile(r"(?<![:\w])multiset\s*<"), "std::multiset<"),
    (re.compile(r"(?<![:\w])set\s*<"), "std::set<"),
    (re.compile(r"(?<![:\w])list\s*<"), "std::list<"),
    (re.compile(r"(?<![:\w])deque\s*<"), "std::deque<"),
    (re.compile(r"(?<![:\w])optional\s*<"), "std::optional<"),
    (re.compile(r"(?<![:\w])less\s*<"), "std::less<"),
    (re.compile(r"(?<![:\w])pair\s*<"), "std::pair<"),
    (re.compile(r"(?<![:\w])duration\s*<"), "std::chrono::duration<"),
    (re.compile(r"(?<![:\w])time_point\s*<"), "std::chrono::time_point<"),
    (re.compile(r"(?<![:\w])_?ratio\s*<"), "std::ratio<"),
)
# Ghidra already prints std::__detail:: on the line before a hashtable iterator.
_RE_DETAIL_NODE = re.compile(
    r"std::__detail::\s+(_Node_(?:const_iterator|iterator_base|iterator)\s*<)"
)
_BARE_NODE_ITER = (
    (re.compile(r"(?<![:\w])_Node_iterator_base\s*<"), "std::__detail::_Node_iterator_base<"),
    (re.compile(r"(?<![:\w])_Node_const_iterator\s*<"), "std::__detail::_Node_const_iterator<"),
    (re.compile(r"(?<![:\w])_Node_iterator\s*<"), "std::__detail::_Node_iterator<"),
)
_OPERATOR_TAILS = (
    "+=", "!=", "==", "<=", ">=", "->", "++", "--", "[]", "=", "*", "-",
)

_BARE_IOS = re.compile(
    r"(?<!~)(?<![:\w])\b(ostream|istream|ofstream|ifstream|iostream|ios_base|ios)\b"
)
_RE_IOS_OPENMODE = (
    (re.compile(r"\b_S_out\b"), "std::ios::out"),
    (re.compile(r"\b_S_in\b"), "std::ios::in"),
    (re.compile(r"\b_S_app\b"), "std::ios::app"),
)
_RE_MINGW_STDIO_OBJ = re.compile(
    r"__fu\d+__ZSt4(cout|cerr|cin|clog)\b"
)
# Ghidra NTTP: std::ratio<1,_1000000> → std::ratio<1, 1000000>
_RE_GHIDRA_NTTP = re.compile(r"\b_(\d{3,})\b")

# Type uses only: `string *`, `string&`, `string name` — applied outside string literals.
_BARE_STRING = re.compile(r"(?<![:\w])\bstring\b(?=\s*[\*&]|\s+[A-Za-z_])")
_USING_STD = re.compile(r"^[ \t]*using\s+namespace\s+std\s*;\s*\n?", re.MULTILINE)
_QUOTED = re.compile(r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')')

_KNOWN_CLASSES = frozenset({
    "vector", "basic_string", "string", "allocator", "__new_allocator",
    "unordered_map", "unordered_set", "map", "set", "multiset", "list", "deque", "array",
    "__normal_iterator", "_Node_iterator", "_Node_const_iterator",
    "_Node_iterator_base", "_Rb_tree_const_iterator", "_Rb_tree_iterator",
    "char_traits", "optional", "pair",
    "initializer_list", "map", "less", "ostream", "ofstream",
    "duration", "ratio",
})
_KNOWN_MEMBERS = frozenset({
    "begin", "end", "cbegin", "cend", "rbegin", "rend",
    "size", "empty", "clear", "data", "c_str", "reserve", "resize",
    "push_back", "pop_back", "emplace_back", "emplace", "insert", "erase",
    "swap", "assign", "append", "find", "substr", "compare", "at",
    "back", "front", "length", "capacity", "max_size", "shrink_to_fit",
    "get_allocator", "release", "get", "count", "operator",
    "value_or", "has_value", "reset",
})


def _outside_strings(text: str, transform) -> str:
    parts = _QUOTED.split(text)
    out = []
    for i, p in enumerate(parts):
        out.append(p if i % 2 else transform(p))
    return "".join(out)


def _match_forward(s: str, i: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    n = len(s)
    for j in range(i, n):
        if s[j] == open_ch:
            depth += 1
        elif s[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j
    return -1


_GHIDRA_ITER_TEMPLATE = re.compile(
    r"(?:(?:std|__gnu_cxx)::\s*)*"
    r"(__normal_iterator|_Rb_tree_const_iterator|_Rb_tree_iterator|__iterator)\b"
)


def _strip_ghidra_iter_templates(s: str) -> str:
    """Drop iterator <...> so preamble aliases (ghidra_word) stay non-templates.

    Real __gnu_cxx / std::_Rb_tree types reject Ghidra's iterator-to-T* casts.
    """
    blob = s or ""
    n = len(blob)
    out: list[str] = []
    copied = 0
    i = 0
    while i < n:
        m = _GHIDRA_ITER_TEMPLATE.search(blob, i)
        if not m:
            break
        k = m.end()
        while k < n and blob[k] in " \t\n\r":
            k += 1
        if k < n and blob[k] == "<":
            close = _match_forward(blob, k, "<", ">")
            if close >= 0:
                out.append(blob[copied:m.start()])
                out.append(m.group(1))
                copied = close + 1
                i = copied
                continue
        i = m.end()
    out.append(blob[copied:])
    return "".join(out)


def _match_angle_back(s: str, i: int) -> int:
    depth = 0
    j = i
    while j >= 0:
        if s[j] == ">":
            depth += 1
        elif s[j] == "<":
            depth -= 1
            if depth == 0:
                return j
        j -= 1
    return -1


def _skip_ws_back(s: str, i: int) -> int:
    while i > 0 and s[i - 1] in " \t\n\r":
        i -= 1
    return i


def _decl_end_before_name(s: str, name_start: int) -> int:
    """Index just after a return type (stars/newlines sit between type and name)."""
    k = name_start
    while k > 0 and s[k - 1] in " \t\n\r":
        k -= 1
    while k > 0 and s[k - 1] == "*":
        k -= 1
        while k > 0 and s[k - 1] in " \t\n\r":
            k -= 1
    return k


def _brace_after_params(s: str, close_paren: int) -> int:
    k = close_paren + 1
    while k < len(s) and s[k] in " \t\n\r":
        k += 1
    if s.startswith("const", k):
        k += 5
        while k < len(s) and s[k] in " \t\n\r":
            k += 1
    if k < len(s) and s[k] == "{":
        return k
    return -1


def _iter_function_defs(code: str, *, skip_qualified: bool):
    """Yield (ident, type_start, close_paren, body_end) for `{`-bodied functions."""
    blob = code or ""
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", blob):
        ident = m.group(1)
        if ident in _NOT_FN_NAMES:
            continue
        if skip_qualified and m.start() >= 2 and blob[m.start() - 2:m.start()] == "::":
            continue
        open_p = m.end() - 1
        close = _match_forward(blob, open_p, "(", ")")
        if close < 0:
            continue
        brace = _brace_after_params(blob, close)
        if brace < 0:
            continue
        end = _match_forward(blob, brace, "{", "}")
        if end < 0:
            continue
        k = _decl_end_before_name(blob, m.start())
        t0 = _type_start(blob, k)
        yield ident, t0, close, end


def named_function_span(code: str, name: str, *, skip_qualified: bool = False):
    """(type_start, close_paren, body_end) for the named definition, if any."""
    if not name or not code:
        return None
    for ident, t0, close, end in _iter_function_defs(code, skip_qualified=skip_qualified):
        if ident == name:
            return t0, close, end
    return None


def _type_start(s: str, colon_pos: int) -> int:
    """Start index of the qualified type before `::method`."""
    i = colon_pos
    while True:
        i = _skip_ws_back(s, i)
        if i > 0 and s[i - 1] == ">":
            a = _match_angle_back(s, i - 1)
            if a < 0:
                return i
            i = _skip_ws_back(s, a)
            j = i
            while j > 0 and (s[j - 1].isalnum() or s[j - 1] == "_"):
                j -= 1
            if j == i:
                return i
            i = j
        else:
            j = i
            while j > 0 and (s[j - 1].isalnum() or s[j - 1] == "_"):
                j -= 1
            if j == i:
                return i
            i = j
        i = _skip_ws_back(s, i)
        if i >= 2 and s[i - 2:i] == "::":
            i -= 2
            continue
        return i


def _last_type_ident(type_str: str) -> str:
    s = (type_str or "").strip()
    if not s:
        return ""
    if s.endswith(">"):
        a = _match_angle_back(s, len(s) - 1)
        if a >= 0:
            s = s[:a].rstrip()
    if "::" in s:
        s = s.rsplit("::", 1)[-1]
    return s.strip()


def _split_top_args(inner: str) -> list[str]:
    args: list[str] = []
    depth_p = depth_a = 0
    start = 0
    for i, c in enumerate(inner):
        if c == "(":
            depth_p += 1
        elif c == ")":
            depth_p -= 1
        elif c == "<":
            depth_a += 1
        elif c == ">":
            depth_a -= 1
        elif c == "," and depth_p == 0 and depth_a == 0:
            args.append(inner[start:i].strip())
            start = i + 1
    tail = inner[start:].strip()
    if tail:
        args.append(tail)
    return args


def _deref_if_ident(expr: str) -> str:
    """Ghidra often passes T* where the real API wants T / T const&."""
    t = (expr or "").strip()
    if re.fullmatch(r"[A-Za-z_]\w*", t):
        return f"*({t})"
    return t


def _deref_ptrish(expr: str) -> str:
    t = (expr or "").strip()
    if re.fullmatch(r"[A-Za-z_]\w*", t) or _RE_PTR_CAST.match(t):
        return f"*({t})"
    return t


_ASSOC_INDEX = frozenset({
    "map", "set", "multimap", "multiset",
    "unordered_map", "unordered_set", "unordered_multimap", "unordered_multiset",
})
_RE_PTR_CAST = re.compile(r"^\(\s*[^()]*\*\s*\)")


def _rewrite_one_call(
    typ: str,
    meth: str,
    dtor: bool,
    args: list[str],
    *,
    had_targs: bool = False,
) -> str | None:
    last = _last_type_ident(typ)
    if not last:
        return None
    if meth == "operator=" and len(args) >= 2:
        recv, rhs = args[0], args[1].strip()
        if rhs.startswith("&"):
            rhs = rhs[1:].strip()
        else:
            rhs = _deref_if_ident(rhs)
        return f"(*({recv}) = ({rhs}))"
    if meth == "operator+=" and len(args) >= 2:
        recv, rhs = args[0], args[1].strip()
        if rhs.startswith("&"):
            rhs = rhs[1:].strip()
        else:
            rhs = _deref_if_ident(rhs)
        return f"(*({recv}) += ({rhs}))"
    if meth == "operator[]" and len(args) >= 2:
        idx = args[1].strip()
        if last in _ASSOC_INDEX:
            if re.fullmatch(r"[A-Za-z_]\w*", idx) or _RE_PTR_CAST.match(idx):
                idx = f"*({idx})"
        return f"(*({args[0]}))[{idx}]"
    if meth in {"operator*", "operator->", "operator++", "operator--"} and args:
        recv = args[0]
        if meth == "operator*":
            return f"({recv})->operator*()"
        if meth == "operator->":
            return f"({recv})->operator->()"
        if meth == "operator++":
            return f"({recv})->operator++()"
        return f"({recv})->operator--()"
    if meth in {"operator==", "operator!="} and len(args) >= 2:
        op = "==" if meth == "operator==" else "!="
        if last == "__detail":
            # Ghidra: std::__detail::operator==(it, end) — not a member of __detail.
            return f"(({args[0]}) {op} ({args[1]}))"
        if last == "std":
            # Bare std::operator!=(iter*, iter*) — libstdc++ takes refs.
            # Templated std::operator==<char,...> is string compare; keep it.
            if had_targs:
                return None
            return f"(*({args[0]}) {op} *({args[1]}))"
    if meth == "operator-" and last == "chrono" and len(args) >= 2:
        return f"(*({args[0]}) - *({args[1]}))"
    if meth.startswith("operator"):
        return None
    if not args:
        return None
    recv = args[0]
    extra = [a.strip() for a in args[1:]]
    # Ghidra often passes T* where the real method takes T/T const&.
    if extra and meth in {
        "find", "compare", "append", "push_back", "push_front", "count",
    }:
        a0 = extra[0]
        if re.fullmatch(r"[A-Za-z_]\w*", a0):
            # string::push_back takes char by value; vector::push_back gets T*.
            if not (meth == "push_back" and last in {"basic_string", "string"}):
                extra[0] = f"*({a0})"
    if extra and meth == "insert" and last in _ASSOC_INDEX:
        a0 = extra[0]
        if re.fullmatch(r"[A-Za-z_]\w*", a0):
            extra[0] = f"*({a0})"
    rest = ", ".join(extra)
    rest = re.sub(
        r",\s*\(\s*(?:std::)?allocator\s*<[^>]*>\s*\*\s*\)[^,]*$",
        "",
        rest,
    )
    if dtor or meth == last:
        if dtor:
            return f"({recv})->~{last}()"
        if last in {"basic_string", "string"}:
            extra = list(extra)
            if had_targs and len(extra) >= 3:
                extra = extra[:2]
            elif extra:
                extra[-1] = _deref_if_ident(extra[-1])
            rest = ", ".join(extra)
            rest = re.sub(
                r",\s*\(\s*(?:std::)?allocator\s*<[^>]*>\s*\*\s*\)[^,]*$",
                "",
                rest,
            )
        if last == "duration":
            extra = [_deref_ptrish(a) for a in extra]
            rest = ", ".join(extra)
        if last == "vector" and extra:
            extra = list(extra)
            if had_targs:
                if len(extra) >= 3:
                    extra = extra[:2]
            elif len(extra) >= 3:
                extra[1] = _deref_if_ident(extra[1])
                extra = extra[:2]
            elif len(extra) == 2 and re.fullmatch(r"\d+", extra[0].strip()):
                extra[1] = _deref_if_ident(extra[1])
            rest = ", ".join(extra)
        if rest:
            return f"new ({recv}) {typ}({rest})"
        return f"new ({recv}) {typ}()"
    if last in _KNOWN_CLASSES and meth in _KNOWN_MEMBERS:
        if rest:
            return f"({recv})->{meth}({rest})"
        return f"({recv})->{meth}()"
    return None


def rewrite_ghidra_member_calls(code: str) -> str:
    """Type::method(this, args) → (this)->method(args); ctors → placement new."""
    s = code or ""
    n = len(s)
    out: list[str] = []
    copied = 0
    i = 0
    while i < n:
        if s[i:i + 2] != "::":
            i += 1
            continue
        j = i + 2
        while j < n and s[j] in " \t\n\r":
            j += 1
        dtor = False
        if j < n and s[j] == "~":
            dtor = True
            j += 1
            while j < n and s[j] in " \t\n\r":
                j += 1
        k = j
        while k < n and (s[k].isalnum() or s[k] == "_"):
            k += 1
        if k == j:
            i += 1
            continue
        meth = s[j:k]
        if meth == "operator":
            for op in _OPERATOR_TAILS:
                if s.startswith(op, k):
                    meth = "operator" + op
                    k += len(op)
                    break
        t = k
        had_targs = False
        if t < n and s[t] == "<":
            close_a = _match_forward(s, t, "<", ">")
            if close_a >= 0:
                had_targs = True
                t = close_a + 1
        while t < n and s[t] in " \t\n\r":
            t += 1
        if t >= n or s[t] != "(":
            i += 1
            continue
        close_p = _match_forward(s, t, "(", ")")
        if close_p < 0:
            i += 1
            continue
        t0 = _type_start(s, i)
        if not (0 <= t0 < i):
            i += 1
            continue
        typ = s[t0:i].strip()
        rewritten = _rewrite_one_call(
            typ, meth, dtor, _split_top_args(s[t + 1:close_p]), had_targs=had_targs
        )
        if rewritten is None:
            i += 1
            continue
        out.append(s[copied:t0])
        out.append(rewritten)
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    return "".join(out)


_RE_FRONT_BACK_ASSIGN = re.compile(
    r"\b(\w+)\s*=\s*\(\s*[A-Za-z_]\w*\s*\)\s*->\s*(?:front|back)\s*\(\s*\)"
)
_RE_ITER_CHAR_CAST = re.compile(
    r"\b\w+\s*=\s*\(\s*char\s*\*\s*\)\s*"
    r"(\(\s*[A-Za-z_]\w*\s*\)\s*->\s*(?:begin|end|cbegin|cend)\s*\(\s*\))"
)


def _rewrite_string_ref_deref(code: str) -> str:
    """Ghidra types string/vector front/back (T&) as a pointer and star-derefs."""
    t = code or ""
    ids = {m.group(1) for m in _RE_FRONT_BACK_ASSIGN.finditer(t)}
    ids.update(re.findall(r"\b(?:const_)?reference\s+(\w+)\s*;", t))
    for ident in ids:
        t = re.sub(rf"(?<!\*)\*{ident}\b", ident, t)
    return t


_RE_CONST_REF_DECL = re.compile(r"\bconst_reference\s+(\w+)\s*;")


def _rewrite_const_ref_arrow(code: str) -> str:
    """Ghidra types vector/map element refs as const_reference then uses ->field.

    String operator[] keeps const_reference as a scalar (star-deref rewrite).
    Do not invent a named struct from a user binary; assembler infers fields
    on the placeholder type ghidra_ref. Assignment from T (operator[]) is
    taken by address so the placeholder is a pointer, not ghidra_word = T.
    """
    t = code or ""
    ids = []
    for m in _RE_CONST_REF_DECL.finditer(t):
        ident = m.group(1)
        if re.search(rf"\b{re.escape(ident)}\s*->", t):
            ids.append(ident)
    for ident in ids:
        t = re.sub(
            rf"\bconst_reference\s+{re.escape(ident)}\s*;",
            f"ghidra_ref *{ident};",
            t,
        )
        t = re.sub(
            rf"\b{re.escape(ident)}\s*=\s*(?!\(ghidra_ref\s*\*\s*\)\s*&)([^;]+);",
            rf"{ident} = (ghidra_ref *)&(\1);",
            t,
        )
    return t


_RE_PLACEHOLDER_ITER_DECL = re.compile(r"\b(const_iterator|iterator)\s+(\w+)\s*;")


def _rewrite_const_iter_begin_assign(code: str) -> str:
    """Ghidra types vector range-for as iterator/const_iterator then assigns begin/end.

    Preamble iterator aliases are placeholder pointers, not string::iterator.
    Keep the container address as the cursor; do not invent a zero iterator.
    """
    t = code or ""
    ids = [(m.group(1), m.group(2)) for m in _RE_PLACEHOLDER_ITER_DECL.finditer(t)]
    for kind, ident in ids:
        def _repl(m: re.Match, *, _ident: str = ident, _kind: str = kind) -> str:
            rhs = (m.group(1) or "").strip()
            names = re.findall(r"[A-Za-z_]\w*", rhs)
            if not names:
                return m.group(0)
            return f"{_ident} = ({_kind})({names[-1]});"

        t = re.sub(
            rf"\b{re.escape(ident)}\s*=\s*([^=;]+?)->"
            rf"(?:begin|end|cbegin|cend)\s*\(\s*\)\s*;",
            _repl,
            t,
        )
    return t


def _rewrite_iter_char_cast(code: str) -> str:
    """Ghidra casts string::iterator from begin/end to char*."""
    return _RE_ITER_CHAR_CAST.sub(r"(void)(\1)", code or "")


_RE_POINTER_DECL = re.compile(r"\bpointer\s+(\w+)\s*;")


def _rewrite_pointer_pair_fields(code: str) -> str:
    """Ghidra types pair* as `pointer` (void*) then uses ->first/->second."""
    t = code or ""
    ids = []
    for m in _RE_POINTER_DECL.finditer(t):
        ident = m.group(1)
        if re.search(rf"\b{re.escape(ident)}\s*->\s*(?:first|second)\b", t):
            ids.append(ident)
    for ident in ids:
        t = re.sub(
            rf"\b{re.escape(ident)}\s*->\s*(first|second)\b",
            rf"((std::pair<ghidra_word, ghidra_word> *){ident})->\1",
            t,
        )
    return t


_RE_NRVO_STR_FROM_ITER = re.compile(
    r"new\s*\(\s*[A-Za-z_]\w*\s*\)\s*"
    r"std::(?:basic_string\s*<[^;]*?>|string)\s*"
    r"\(\s*\(\s*std::(?:basic_string\s*<[^;]*?>|string)\s*\*\s*\)\s*"
    r"\(\s*([A-Za-z_]\w*)\s*\)\s*\)\s*;",
    re.DOTALL,
)


def _rewrite_nrvo_iter_as_string(code: str) -> str:
    """Drop Ghidra NRVO copy-ctor from (string*)(const_iterator). Do not invent a copy."""
    t = code or ""
    ids = set(re.findall(r"\b(?:__const_iterator|const_iterator)\s+(\w+)\s*;", t))
    if not ids:
        return t

    def repl(m: re.Match) -> str:
        if m.group(1) in ids:
            return "(void)0;"
        return m.group(0)

    return _RE_NRVO_STR_FROM_ITER.sub(repl, t)


def extract_named_function(code: str, name: str) -> str:
    """Keep the function named `name`, or the first definition renamed to `name`."""
    if not name or not code:
        return code or ""
    named = named_function_span(code, name)
    if named:
        start, _close, end = named
        return code[start:end + 1]
    span = _first_function_span(code)
    if not span:
        return code
    start, end, ident = span
    body = code[start:end + 1]
    if ident != name:
        body = re.sub(rf"\b{re.escape(ident)}\s*\(", name + "(", body, count=1)
    return body


_NOT_FN_NAMES = frozenset({
    "if", "for", "while", "switch", "catch", "return", "sizeof", "do",
})


def _first_function_span(code: str):
    for ident, t0, _close, end in _iter_function_defs(code or "", skip_qualified=False):
        return t0, end, ident
    return None


def _strip_invalid_using(text: str) -> str:
    lines = []
    for ln in text.splitlines(True):
        raw = ln.lstrip()
        if raw.startswith("using ") and not raw.startswith("using namespace "):
            rest = raw[len("using "):]
            if "=" not in rest:
                continue
            alias = rest.split("=", 1)[0].strip()
            alias_id = alias.replace("::", "")
            if " " in alias_id or not alias_id:
                continue
        lines.append(ln)
    return "".join(lines)


_RE_OSTREAM_OBJ_CAST = re.compile(
    r"\(\s*(?:std::)?(?:basic_)?ostream(?:\s*<[^()]*>)?\s*\*\s*\)\s*"
    r"(?:std::)?(cout|cerr|clog)\b"
)
_RE_DAT_UNDERSCORE = re.compile(r"\b_DAT_([0-9A-Fa-f]+)\b")
_RE_MPZ_T_PTR = re.compile(r"\bmpz_t\s*\*")
_RE_STL_PRIV_FIELD = re.compile(
    r"^[ \t]*[A-Za-z_]\w*\s*\.\s*_M_(?:array|len)\s*=.*$",
    re.MULTILINE,
)
_RE_STACK_ADDR_ASSIGN = re.compile(
    r"\b(?:padding|auStack\w*|local_[0-9A-Fa-f]+)\s*\[[^\]]+\]\s*=\s*&"
)
_RE_STACK_PTR_ASSIGN = re.compile(
    r"\b(padding|auStack\w*|local_[0-9A-Fa-f]+)\s*\[[^\]]+\]\s*=\s*(\1\s*\+[^;]+)"
)


def _rewrite_duration_cast(code: str) -> str:
    """Ghidra `duration_cast<To, Rep, Period>(T*)` → `duration_cast<To>(*ptr)`."""
    needle = "duration_cast<"
    s = code or ""
    n = len(s)
    out: list[str] = []
    copied = 0
    i = 0
    while True:
        k = s.find(needle, i)
        if k < 0:
            break
        t = k + len("duration_cast")
        close_a = _match_forward(s, t, "<", ">")
        if close_a < 0:
            i = k + 2
            continue
        targs = _split_top_args(s[t + 1:close_a])
        if not targs:
            i = k + 2
            continue
        p = close_a + 1
        while p < n and s[p] in " \t\n\r":
            p += 1
        if p >= n or s[p] != "(":
            i = k + 2
            continue
        close_p = _match_forward(s, p, "(", ")")
        if close_p < 0:
            i = k + 2
            continue
        args = _split_top_args(s[p + 1:close_p])
        if len(args) != 1:
            i = k + 2
            continue
        arg = args[0].strip()
        if _RE_PTR_CAST.match(arg):
            arg = f"*({arg})"
        out.append(s[copied:k])
        out.append(f"duration_cast<{targs[0]}>({arg})")
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    return "".join(out)


def _rewrite_std_swap(code: str) -> str:
    """Ghidra `std::swap<T>(T*, T*)` → `std::swap<T>(*a, *b)` when T is not a pointer."""
    needle = "std::swap"
    s = code or ""
    n = len(s)
    out: list[str] = []
    copied = 0
    i = 0
    while True:
        k = s.find(needle, i)
        if k < 0:
            break
        t = k + len(needle)
        while t < n and s[t] in " \t\n\r":
            t += 1
        targs: list[str] = []
        if t < n and s[t] == "<":
            close_a = _match_forward(s, t, "<", ">")
            if close_a < 0:
                i = k + 2
                continue
            targs = _split_top_args(s[t + 1:close_a])
            t = close_a + 1
            while t < n and s[t] in " \t\n\r":
                t += 1
        if t >= n or s[t] != "(":
            i = k + 2
            continue
        close_p = _match_forward(s, t, "(", ")")
        if close_p < 0:
            i = k + 2
            continue
        args = _split_top_args(s[t + 1:close_p])
        if len(args) != 2:
            i = k + 2
            continue
        if targs and "*" not in targs[0]:
            args = [_deref_ptrish(a) for a in args]
        else:
            i = close_p + 1
            continue
        out.append(s[copied:k])
        tpart = f"<{','.join(targs)}>" if targs else ""
        out.append(f"std::swap{tpart}({args[0]}, {args[1]})")
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    return "".join(out)


def rewrite_ghidra_ostream(code: str) -> str:
    """Ghidra prints `(ostream*)cout` and `ostream::operator<<(this, x)`."""
    s = _RE_OSTREAM_OBJ_CAST.sub(r"(&std::\1)", code or "")
    needle = "::operator<<"
    n = len(s)
    out: list[str] = []
    copied = 0
    i = 0
    while True:
        k = s.find(needle, i)
        if k < 0:
            break
        t = k + len(needle)
        while t < n and s[t] in " \t\n\r":
            t += 1
        if t >= n or s[t] != "(":
            i = k + 2
            continue
        close_p = _match_forward(s, t, "(", ")")
        if close_p < 0:
            i = k + 2
            continue
        t0 = _type_start(s, k)
        if not (0 <= t0 < k):
            i = k + 2
            continue
        last = _last_type_ident(s[t0:k])
        if last not in {"ostream", "basic_ostream", "wostream", "basic_wostream"}:
            i = k + 2
            continue
        args = _split_top_args(s[t + 1:close_p])
        if len(args) != 2:
            i = k + 2
            continue
        out.append(s[copied:t0])
        out.append(f"(&((*({args[0]})) << ({args[1]})))")
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    s = _rewrite_std_free_lshift("".join(out))
    s = _wrap_ostream_lshift_assign(s)
    s = _RE_OSTREAM_ARRAY.sub(r"undefined1 \1\2", s)
    return s


def _rewrite_std_free_lshift(s: str) -> str:
    """Ghidra `std::operator<<(ostream*, x)` → `&((*lhs) << rhs)`."""
    needle = "std::operator<<"
    n = len(s)
    out: list[str] = []
    copied = 0
    i = 0
    while True:
        k = s.find(needle, i)
        if k < 0:
            break
        t = k + len(needle)
        while t < n and s[t] in " \t\n\r":
            t += 1
        if t >= n or s[t] != "(":
            i = k + 2
            continue
        close_p = _match_forward(s, t, "(", ")")
        if close_p < 0:
            i = k + 2
            continue
        args = _split_top_args(s[t + 1:close_p])
        if len(args) != 2:
            i = k + 2
            continue
        out.append(s[copied:k])
        out.append(f"(&((*({args[0]})) << ({args[1]})))")
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    return "".join(out)


_RE_OSTREAM_LSHIFT_ASSIGN = re.compile(
    r"(=\s*)\(\s*\*\s*\(([A-Za-z_]\w*)\)\s*\)\s*<<\s*\("
)
_RE_OSTREAM_ARRAY = re.compile(
    r"(?:std::)?basic_ostream\s*<[^\n]*>\s+([A-Za-z_]\w*)\s*(\[\s*\d+\s*\])"
)
_RE_GMP_CALL = re.compile(r"\b(?:__g)?mpz_[A-Za-z0-9_]+\s*\(")
_RE_MPZ_PARAM = re.compile(r"\b(?:mpz_srcptr|mpz_ptr)\s+([A-Za-z_]\w*)\s*([,)])")


def _wrap_ostream_lshift_assign(s: str) -> str:
    """`p = (*q) << x` → `p = &((*q) << x)` so ostream* assignment type-checks."""
    out: list[str] = []
    copied = 0
    for m in _RE_OSTREAM_LSHIFT_ASSIGN.finditer(s or ""):
        open_rhs = m.end() - 1
        close = _match_forward(s, open_rhs, "(", ")")
        if close < 0:
            continue
        start_expr = m.start() + len(m.group(1))
        if s[start_expr:start_expr + 2] == "(&":
            continue
        out.append(s[copied:m.start()])
        out.append(m.group(1))
        out.append("(&(")
        out.append(s[start_expr:close + 1])
        out.append("))")
        copied = close + 1
    out.append(s[copied:])
    return "".join(out)


def rewrite_gmp_amp_args(code: str) -> str:
    """`mpz_foo(&x)` → `mpz_foo((mpz_ptr)&x)` (Ghidra takes address of a word)."""
    s = code or ""
    out: list[str] = []
    copied = 0
    for m in _RE_GMP_CALL.finditer(s):
        open_p = m.end() - 1
        close = _match_forward(s, open_p, "(", ")")
        if close < 0:
            continue
        args = _split_top_args(s[open_p + 1:close])
        new_args = []
        changed = False
        for a in args:
            t = a.strip()
            if t.startswith("&") and not t.startswith("(mpz_ptr)"):
                new_args.append(f"(mpz_ptr)({t})")
                changed = True
            else:
                new_args.append(a)
        if not changed:
            continue
        out.append(s[copied:open_p + 1])
        out.append(", ".join(new_args))
        out.append(")")
        copied = close + 1
    out.append(s[copied:])
    return "".join(out)


def sanitize_ghidra_cpp(code: str) -> str:
    """Rewrite Ghidra type spellings and member-call syntax into parseable C++."""
    t = code or ""

    def _types(chunk: str) -> str:
        # Ghidra: pair<const_std::basic_string,…>. Strip _std:: only after
        # splitting const from std, or it becomes the token conststd.
        chunk = apply_lexical(chunk, "before_underscore_std")
        chunk = chunk.replace("_std::", "std::")
        chunk = chunk.replace("std::__cxx11::", "std::")
        chunk = re.sub(r"_+(?=>)", "", chunk)
        for old, new in _UNDERSCORE_TYPES:
            chunk = chunk.replace(old, new)
        # Ghidra NTTP: `_bool_,` — trailing `_` is part of the ident, so
        # `\b_(bool)\b` does not match. Strip both-sided `_prim_` first.
        chunk = re.sub(
            r"\b_((?:int|char|bool|void|float|double|short|long|const|false|true))_\b",
            r"\1",
            chunk,
        )
        # Ghidra: pair<int,_int> / map<int,_int,…> — '_' before a primitive targ.
        chunk = re.sub(
            r"\b_(int|char|bool|void|float|double|short|long|const|false|true)\b",
            r"\1",
            chunk,
        )
        # Ghidra: const_Rec / _const_Rec / Rec_const (user struct, not const_iterator).
        chunk = re.sub(r"\b_const_([A-Z][A-Za-z0-9]*)\b", r"const \1", chunk)
        chunk = re.sub(r"\bconst_([A-Z][A-Za-z0-9]*)\b", r"const \1", chunk)
        chunk = re.sub(r"\b([A-Z][A-Za-z0-9]*)_const\b", r"\1 const", chunk)
        chunk = _RE_DETAIL_NODE.sub(r"std::__detail::\1", chunk)
        for rx, repl in _BARE_NODE_ITER:
            chunk = rx.sub(repl, chunk)
        for rx, repl in _BARE_TEMPLATE:
            chunk = rx.sub(repl, chunk)
        chunk = _strip_ghidra_iter_templates(chunk)
        chunk = re.sub(r"\bstd::\s+std::", "std::", chunk)
        chunk = re.sub(r"\bstd::chrono::_V2::", "std::chrono::", chunk)
        chunk = re.sub(
            r"::\s+std::(?:__cxx11::|chrono::|__gnu_cxx::)*([A-Za-z_]\w+)\s*<",
            r"::\1<",
            chunk,
        )
        chunk = re.sub(
            r"::\s+std::(?:__cxx11::|chrono::|__gnu_cxx::)*([A-Za-z_]\w+)\s*\(",
            r"::\1(",
            chunk,
        )
        chunk = re.sub(r"\b([A-Za-z_]\w*)\s*\.\s*__r\b", r"(&\1)", chunk)
        chunk = apply_lexical(chunk, "after_templates")
        chunk = re.sub(r"\(__node_type\s*\*\)", "", chunk)
        chunk = _BARE_IOS.sub(r"std::\1", chunk)
        chunk = _BARE_STRING.sub("std::string", chunk)
        for rx, repl in _RE_IOS_OPENMODE:
            chunk = rx.sub(repl, chunk)
        chunk = _RE_MINGW_STDIO_OBJ.sub(r"std::\1", chunk)
        chunk = re.sub(r"(?<!::)(?<![.>])\bswap\s*([<(])", r"std::swap\1", chunk)
        chunk = _RE_GHIDRA_NTTP.sub(r"\1", chunk)
        chunk = _RE_DAT_UNDERSCORE.sub(r"DAT_\1", chunk)
        chunk = _RE_MPZ_T_PTR.sub("mpz_ptr ", chunk)
        chunk = _RE_MPZ_PARAM.sub(r"ghidra_word \1\2", chunk)
        chunk = re.sub(r"(?<!~)(?<!::)__new_allocator\b", "std::__new_allocator", chunk)
        return chunk

    t = _outside_strings(t, _types)
    t = _USING_STD.sub("", t)
    t = _strip_invalid_using(t)
    t = rewrite_ghidra_member_calls(t)
    t = _rewrite_const_iter_begin_assign(t)
    t = _rewrite_string_ref_deref(t)
    t = _rewrite_const_ref_arrow(t)
    t = _rewrite_iter_char_cast(t)
    t = _rewrite_pointer_pair_fields(t)
    t = _rewrite_nrvo_iter_as_string(t)
    t = _rewrite_duration_cast(t)
    t = _rewrite_std_swap(t)
    t = rewrite_ghidra_ostream(t)
    t = rewrite_gmp_amp_args(t)
    t = _RE_STL_PRIV_FIELD.sub("", t)
    t = _RE_STACK_ADDR_ASSIGN.sub(r"(void)&", t)
    t = _RE_STACK_PTR_ASSIGN.sub(r"(void)(\2)", t)
    return t
