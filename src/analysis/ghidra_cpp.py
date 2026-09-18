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
    (re.compile(r"(?<![:\w])basic_ostream\s*<"), "std::basic_ostream<"),
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
    "&=", "|=", "^=", "&", "|", "^", "~", "+=", "!=", "==", "<=", ">=",
    "->", "++", "--", "[]", "=", "*", "-",
)

_BARE_IOS = re.compile(
    r"(?<!~)(?<![:\w])\b(basic_ostream|ostream|istream|ofstream|ifstream|iostream|ios_base|ios)\b"
)
_RE_IOS_OPENMODE = (
    (re.compile(r"\b_S_out\b"), "std::ios::out"),
    (re.compile(r"\b_S_in\b"), "std::ios::in"),
    (re.compile(r"\b_S_app\b"), "std::ios::app"),
)
_RE_MINGW_STDIO_OBJ = re.compile(
    r"(?:__fu\d+|_refptr)__ZSt4(cout|cerr|cin|clog)\b"
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
    "initializer_list", "map", "less", "ostream", "basic_ostream", "ofstream",
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
    """Match a closer; do not count parens inside string/char literals.

    ``operator<<(os, " (")`` must close on the call's ``)``, not a ``(``
    that lives in the literal.
    """
    depth = 0
    n = len(s)
    j = i
    quote = ""
    escape = False
    while j < n:
        c = s[j]
        if quote:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = ""
            j += 1
            continue
        if c in "\"'":
            quote = c
            j += 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j
        j += 1
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


def _norm_targ(s: str) -> str:
    t = re.sub(r"\s+", "", s or "")
    t = t.replace("std::", "")
    return t.replace("__cxx11::", "")


_SEQ_ALLOC = frozenset({"vector", "list", "deque", "forward_list", "basic_string"})
_SET_ALLOC = frozenset({
    "set", "multiset", "unordered_set", "unordered_multiset",
})
_MAP_ALLOC = frozenset({
    "map", "multimap", "unordered_map", "unordered_multimap",
})
_ASSOC_LESS = frozenset({"set", "multiset", "map", "multimap"})
_UNORDERED = frozenset({
    "unordered_map", "unordered_multimap",
    "unordered_set", "unordered_multiset",
})
_TRAITS_HEAD = frozenset({
    "basic_string", "basic_ostream", "basic_istream", "basic_iostream",
    "basic_ofstream", "basic_ifstream", "basic_fstream",
})
_STRING_ALIAS = {
    "char": "string",
    "wchar_t": "wstring",
    "char8_t": "u8string",
    "char16_t": "u16string",
    "char32_t": "u32string",
}
_STREAM_ALIAS = {
    ("basic_ostream", "char"): "ostream",
    ("basic_istream", "char"): "istream",
    ("basic_iostream", "char"): "iostream",
    ("basic_ofstream", "char"): "ofstream",
    ("basic_ifstream", "char"): "ifstream",
    ("basic_fstream", "char"): "fstream",
}


def _unary_inner(arg: str, names: tuple[str, ...]) -> str | None:
    t = (arg or "").strip()
    for n in names:
        if not re.match(rf"(?:std::)?{n}\s*<", t):
            continue
        open_a = t.find("<")
        close_a = _match_forward(t, open_a, "<", ">")
        if close_a == len(t) - 1:
            return t[open_a + 1 : close_a].strip()
    return None


def _is_map_alloc_elem(elem: str, key: str, val: str) -> bool:
    e = _norm_targ(elem)
    k = _norm_targ(key)
    v = _norm_targ(val)
    return e in {f"pair<const{k},{v}>", f"pair<{k}const,{v}>"}


def _tpl_head(blob: str, angle: int) -> tuple[int, str]:
    """Start index and unqualified name of `[std::[__cxx11::]]Foo<`."""
    j = angle
    while j > 0 and blob[j - 1].isspace():
        j -= 1
    end = j
    while j > 0 and (blob[j - 1].isalnum() or blob[j - 1] == "_"):
        j -= 1
    name = blob[j:end]
    head = j
    while head >= 2 and blob[head - 2 : head] == "::":
        k = head - 2
        q = k
        while q > 0 and (blob[q - 1].isalnum() or blob[q - 1] == "_"):
            q -= 1
        qual = blob[q:k]
        if qual not in {"std", "__cxx11"}:
            break
        head = q
    return head, name


def _drop_default_last(name: str, args: list[str]) -> list[str] | None:
    if len(args) < 2:
        return None
    last = args[-1]
    alloc_elem = _unary_inner(last, ("allocator",))
    if alloc_elem is not None:
        if name in _MAP_ALLOC and len(args) >= 2 and _is_map_alloc_elem(
            alloc_elem, args[0], args[1]
        ):
            return args[:-1]
        if name in _SEQ_ALLOC | _SET_ALLOC | {"basic_string"}:
            if _norm_targ(alloc_elem) == _norm_targ(args[0]):
                return args[:-1]
    less_key = _unary_inner(last, ("less",))
    if less_key is not None and name in _ASSOC_LESS:
        if _norm_targ(less_key) == _norm_targ(args[0]):
            return args[:-1]
    equal_key = _unary_inner(last, ("equal_to",))
    if equal_key is not None and name in _UNORDERED:
        if _norm_targ(equal_key) == _norm_targ(args[0]):
            return args[:-1]
    hash_key = _unary_inner(last, ("hash",))
    if hash_key is not None and name in _UNORDERED:
        if _norm_targ(hash_key) == _norm_targ(args[0]):
            return args[:-1]
    traits_c = _unary_inner(last, ("char_traits",))
    if traits_c is not None and name in _TRAITS_HEAD:
        if _norm_targ(traits_c) == _norm_targ(args[0]):
            return args[:-1]
    return None


def _elide_default_allocator_args(chunk: str) -> str:
    """Drop ISO default Compare/Traits/Allocator; alias basic_string<char> to string.

    Ghidra prints every default template argument. A person writes map of
    string to int, not allocator<pair<const basic_string<char, char_traits<char>>, int>>.
    """
    blob = chunk or ""
    changed = True
    while changed:
        changed = False
        i = 0
        while i < len(blob):
            if blob[i] != "<":
                i += 1
                continue
            close = _match_forward(blob, i, "<", ">")
            if close < 0:
                i += 1
                continue
            start, name = _tpl_head(blob, i)
            args = [a.strip() for a in _split_top_args(blob[i + 1 : close])]
            dropped = _drop_default_last(name, args)
            if dropped is not None:
                inner = ", ".join(dropped)
                blob = blob[: i + 1] + inner + blob[close:]
                changed = True
                break
            if len(args) == 1:
                alias = None
                if name == "basic_string":
                    alias = _STRING_ALIAS.get(_norm_targ(args[0]))
                else:
                    alias = _STREAM_ALIAS.get((name, _norm_targ(args[0])))
                if alias:
                    prefix = "std::" if "std" in blob[start:i] or "__cxx11" in blob[start:i] else ""
                    blob = blob[:start] + prefix + alias + blob[close + 1 :]
                    changed = True
                    break
            i += 1
    return blob


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
    if meth == "operator&=" and len(args) >= 2:
        recv, rhs = args[0], args[1].strip()
        if rhs.startswith("&"):
            rhs = rhs[1:].strip()
        else:
            rhs = _deref_if_ident(rhs)
        return f"(*({recv}) &= ({rhs}))"
    if meth == "operator|=" and len(args) >= 2:
        recv, rhs = args[0], args[1].strip()
        if rhs.startswith("&"):
            rhs = rhs[1:].strip()
        else:
            rhs = _deref_if_ident(rhs)
        return f"(*({recv}) |= ({rhs}))"
    if meth == "operator&" and len(args) >= 2:
        # ISO bitand / Ghidra std::operator&<N>(T*, T*).
        return f"(*({args[0]}) & *({args[1]}))"
    if meth == "operator|" and len(args) >= 2:
        # ISO bitor / Ghidra std::operator|<N>(T*, T*).
        return f"(*({args[0]}) | *({args[1]}))"
    if meth == "operator~" and args:
        return f"(~(*({args[0]})))"
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
    r"&?\s*(?:std::)?(cout|cerr|clog)\b"
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
_RE_STACK_OVERLAY = re.compile(
    r"\b((?:auStack\w*|padding|local_[0-9A-Fa-f]+))\._(\d+)_(\d+)_"
)
_OVERLAY_TYPE = {
    "1": "undefined1",
    "2": "undefined2",
    "3": "undefined3",
    "4": "undefined4",
    "5": "undefined5",
    "6": "undefined6",
    "7": "undefined7",
    "8": "undefined8",
}


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
        out.append(_lshift_insert_expr(args[0], args[1]))
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    s = _rewrite_std_free_lshift("".join(out))
    s = _rewrite_unqualified_ostream_ptr_lshift(s)
    s = _wrap_ostream_lshift_assign(s)
    s = _wrap_cout_lshift_assign(s)
    s = _RE_OSTREAM_STAR_AROUND_ADDR.sub(r"\1", s)
    s = _collapse_deref_addr(s)
    s = _collapse_deref_iostream_obj(s)
    s = _fold_ostream_self_ptr_insert(s)
    s = _drop_unused_lshift_addr(s)
    s = _fold_ostream_insert_chain(s)
    s = _drop_unused_lshift_addr_assign(s)
    s = _collapse_deref_iostream_obj(s)
    s = _RE_OSTREAM_ARRAY.sub(r"undefined1 \1\2", s)
    return s


_RE_LSHIFT_LINEBREAK = re.compile(
    r"(std(?:::\w+)*::)\s+(operator<<)"
)


def _rewrite_std_free_lshift(s: str) -> str:
    """Ghidra `std::operator<<(ostream*, x)` → `&((*lhs) << rhs)`.

    Also `std::operator<<_<char, traits, _N>` (bitset),
    `std::__detail::operator<<_` (quoted), and
    `std::filesystem::operator<<_` (path insert; __cxx11 stripped earlier).
    Ghidra may break `std::__detail::` and `operator<<_` across lines.
    """
    s = _RE_LSHIFT_LINEBREAK.sub(r"\1\2", s)
    for needle in (
        "std::filesystem::operator<<",
        "std::__detail::operator<<",
        "std::operator<<",
    ):
        s = _rewrite_free_lshift_needle(s, needle)
    return s


def _rewrite_free_lshift_needle(s: str, needle: str) -> str:
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
        if t < n and s[t] == "_":
            t += 1
            while t < n and s[t] in " \t\n\r":
                t += 1
        if t < n and s[t] == "<":
            close_a = _match_forward(s, t, "<", ">")
            if close_a < 0:
                i = k + 2
                continue
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
        out.append(s[copied:k])
        out.append(_lshift_insert_expr(args[0], args[1]))
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    return "".join(out)


def _rewrite_unqualified_ostream_ptr_lshift(s: str) -> str:
    """Ghidra `operator<<((ostream *&)os, x)` without std:: / Type:: prefix."""
    needle = "operator<<"
    n = len(s)
    out: list[str] = []
    copied = 0
    i = 0
    while True:
        k = s.find(needle, i)
        if k < 0:
            break
        if k >= 2 and s[k - 2:k] == "::":
            i = k + 2
            continue
        t = k + len(needle)
        while t < n and s[t] in " \t\n\r":
            t += 1
        if t < n and s[t] == "_":
            i = k + 2
            continue
        if t < n and s[t] == "<":
            i = k + 2
            continue
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
        a0 = args[0]
        obj = _iostream_object_expr(a0)
        if obj:
            out.append(s[copied:k])
            out.append(f"({obj} << ({args[1]}))")
            copied = close_p + 1
            i = copied
            continue
        if "ostream" not in a0 or "*" not in a0:
            i = k + 2
            continue
        this = _ostream_ptr_this(a0)
        out.append(s[copied:k])
        out.append(f"(&((*({this})) << ({args[1]})))")
        copied = close_p + 1
        i = copied
    out.append(s[copied:])
    return "".join(out)


_RE_IOSTREAM_OBJ = re.compile(
    r"^\(\s*&\s*(?:std::)?(cout|cerr|clog)\s*\)$"
    r"|^(?:std::)?(cout|cerr|clog)$"
)


def _iostream_object_expr(arg: str) -> str:
    """cout/cerr/clog is a stream object, including ``(ostream*)std::cout``."""
    t = re.sub(r"\s+", "", (arg or "").strip())
    m = re.fullmatch(
        r"\(?\*?\(?&?(?:std::)?(cout|cerr|clog)\)*",
        t,
    )
    if m:
        return "std::" + m.group(1)
    m = re.search(r"(?:std::)?(cout|cerr|clog)$", t)
    if m:
        i = m.start()
        if i > 0 and (t[i - 1].isalnum() or t[i - 1] == "_"):
            return ""
        if "*" in t[:i] and "ostream" in t.lower():
            return "std::" + m.group(1)
    return ""


def _lshift_insert_expr(lhs: str, rhs: str) -> str:
    """Inserter on a stream object is ``obj << x``; on a pointer, addr-wrap."""
    obj = _iostream_object_expr(lhs)
    if obj:
        return f"({obj} << ({rhs}))"
    return f"(&((*({lhs})) << ({rhs})))"


_RE_OSTREAM_PTR_THIS = re.compile(
    r"^\(\s*(?:std::)?(?:basic_)?w?ostream(?:\s*<[^>]*>)?\s*\*&?\s*\)\s*"
    r"([A-Za-z_]\w*)\s*$"
)


def _ostream_ptr_this(arg: str) -> str:
    m = _RE_OSTREAM_PTR_THIS.match((arg or "").strip())
    return m.group(1) if m else arg


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


_RE_OSTREAM_STAR_AROUND_ADDR = re.compile(
    r"\(\s*(?:std::)?(?:basic_)?w?ostream(?:\s*<[^>]*>)?\s*\*\s*\)\s*(\(&)"
)
_RE_COUT_LSHIFT_ASSIGN = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(\(?\s*(?:std::)?c(?:out|err|log)\s*<<)"
)


def _stmt_semi(s: str, i: int) -> int:
    """Index of the next `;` at paren-depth 0, skipping strings."""
    n = len(s)
    depth = 0
    q = ""
    j = i
    while j < n:
        ch = s[j]
        if q:
            if ch == "\\" and j + 1 < n:
                j += 2
                continue
            if ch == q:
                q = ""
            j += 1
            continue
        if ch in "'\"":
            q = ch
            j += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == ";" and depth <= 0:
            return j
        j += 1
    return -1


def _wrap_cout_lshift_assign(s: str) -> str:
    """`p = cout << x` returns ostream&, not ostream*. Keep the address."""
    blob = s or ""
    out: list[str] = []
    copied = 0
    for m in _RE_COUT_LSHIFT_ASSIGN.finditer(blob):
        lead = blob[m.start():m.start(2)]
        if "&(" in lead.replace(" ", ""):
            continue
        semi = _stmt_semi(blob, m.start(2))
        if semi < 0:
            continue
        out.append(blob[copied:m.start(2)])
        out.append("&(")
        out.append(blob[m.start(2):semi])
        out.append(")")
        copied = semi
    out.append(blob[copied:])
    return "".join(out)


def _fold_ostream_self_ptr_insert(s: str) -> str:
    """`p = &((*((ostream*)p)) << x)` is `*p << x`. Inserter returns *this."""
    blob = s or ""
    out: list[str] = []
    copied = 0
    i = 0
    while True:
        k = blob.find("(&(", i)
        if k < 0:
            break
        lhs = re.search(
            r"([A-Za-z_]\w*)\s*=\s*"
            r"(?:\(\s*(?:std::)?(?:basic_)?w?ostream(?:\s*<[^>]*>)?\s*\*\s*\)\s*)?$",
            blob[:k],
        )
        if not lhs:
            i = k + 2
            continue
        ident = lhs.group(1)
        start = lhs.start(1)
        open_inner = k + 2
        close_inner = _match_forward(blob, open_inner, "(", ")")
        if close_inner < 0 or close_inner + 1 >= len(blob) or blob[close_inner + 1] != ")":
            i = k + 2
            continue
        inner = blob[open_inner + 1 : close_inner]
        parsed = _parse_deref_ostream_insert(inner, 0)
        if not parsed or parsed[1] != ident:
            i = k + 2
            continue
        end = close_inner + 2
        while end < len(blob) and blob[end] in " \t":
            end += 1
        semi = ""
        if end < len(blob) and blob[end] == ";":
            semi = ";"
            end += 1
        _end, _name, rhs = parsed
        out.append(blob[copied:start])
        out.append(f"*{ident} << {rhs}{semi}")
        copied = end
        i = copied
    out.append(blob[copied:])
    return "".join(out)


_RE_DEREF_ADDR = re.compile(r"\(\*\(\(&([^()]+)\)\)\)")
_RE_DEREF_ADDR_SM = re.compile(r"\(\*\(&([^()]+)\)\)")
_RE_DEREF_IOSTREAM_OBJ = re.compile(
    r"\(\s*\*\s*\(\s*(?:std::)?(c(?:out|err|log))\s*\)\s*\)"
    r"|\*\s*\(\s*(?:std::)?(c(?:out|err|log))\s*\)"
)
_RE_PAREN_IOSTREAM_LSHIFT = re.compile(
    r"\(\s*(std::c(?:out|err|log))\s*\)\s*<<"
)


def _collapse_deref_addr(s: str) -> str:
    """(*((&x))) is x. Ghidra wraps ostream this as &cout then deref."""
    prev = None
    t = s or ""
    while t != prev:
        prev = t
        t = _RE_DEREF_ADDR.sub(r"\1", t)
        t = _RE_DEREF_ADDR_SM.sub(r"\1", t)
    return t


def _collapse_deref_iostream_obj(s: str) -> str:
    """`*(std::cout)` is the stream. `(std::cout) <<` is `std::cout <<`."""
    def repl(m: re.Match[str]) -> str:
        return "std::" + (m.group(1) or m.group(2))

    prev = None
    t = s or ""
    while t != prev:
        prev = t
        t = _RE_DEREF_IOSTREAM_OBJ.sub(repl, t)
        t = _RE_PAREN_IOSTREAM_LSHIFT.sub(r"\1 <<", t)
    return t


def _ident_after_ostream_ptr_cast(inner: str) -> str | None:
    t = (inner or "").strip()
    while t.startswith("("):
        close = _match_forward(t, 0, "(", ")")
        if close < 0:
            break
        cast = t[: close + 1]
        rest = t[close + 1 :].strip()
        if "*" in cast and rest:
            t = rest
            continue
        break
    t = t.strip().strip("()")
    if re.fullmatch(r"[A-Za-z_]\w*", t):
        return t
    return None


def _parse_addr_insert_assign(s: str, i: int) -> tuple[int, str, str] | None:
    m = re.match(r"\s*([A-Za-z_]\w*)\s*=\s*\(&\(", s[i:])
    if not m:
        return None
    ident = m.group(1)
    open_inner = i + m.end() - 1
    close_inner = _match_forward(s, open_inner, "(", ")")
    if close_inner < 0:
        return None
    if close_inner + 1 >= len(s) or s[close_inner + 1] != ")":
        return None
    inner = s[open_inner + 1 : close_inner].strip()
    if "<<" not in inner:
        return None
    j = close_inner + 2
    while j < len(s) and s[j] in " \t":
        j += 1
    if j < len(s) and s[j] == ";":
        j += 1
    return j, ident, inner


def _parse_deref_ostream_insert(s: str, i: int) -> tuple[int, str, str] | None:
    """(*((ostream *)id)) << rhs, (*(id)) << rhs, or (*id) << rhs."""
    n = len(s)
    j = i
    while j < n and s[j] in " \t\n\r":
        j += 1
    if j >= n or s[j] != "(":
        return None
    j += 1
    while j < n and s[j] in " \t":
        j += 1
    if j >= n or s[j] != "*":
        return None
    j += 1
    while j < n and s[j] in " \t\n\r":
        j += 1
    if j < n and s[j] == "(":
        inner_close = _match_forward(s, j, "(", ")")
        if inner_close < 0:
            return None
        ident = _ident_after_ostream_ptr_cast(s[j + 1 : inner_close])
        if not ident:
            ident = _iostream_object_expr(s[j + 1 : inner_close])
        j = inner_close + 1
    else:
        m = re.match(r"([A-Za-z_]\w*)", s[j:])
        if not m:
            return None
        ident = m.group(1)
        j += len(ident)
    if not ident:
        return None
    while j < n and s[j] in " \t\n\r":
        j += 1
    if j >= n or s[j] != ")":
        return None
    j += 1
    while j < n and s[j] in " \t\n\r":
        j += 1
    if not s.startswith("<<", j):
        return None
    j += 2
    while j < n and s[j] in " \t\n\r":
        j += 1
    if j < n and s[j] == "(":
        rhs_close = _match_forward(s, j, "(", ")")
        if rhs_close < 0:
            return None
        rhs = s[j : rhs_close + 1]
        end = rhs_close + 1
    else:
        m = re.match(
            r"([A-Za-z_]\w*|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")",
            s[j:],
        )
        if not m:
            return None
        rhs = m.group(1)
        end = j + len(rhs)
    return end, ident, rhs


def _ident_span_uses(s: str, name: str) -> list[int]:
    return [m.start() for m in re.finditer(rf"\b{re.escape(name)}\b", s)]


def _fold_ostream_insert_chain(s: str) -> str:
    """p = &(a << b); *p << c  is  a << b << c. Inserter returns *this."""
    blob = s or ""
    changed = True
    while changed:
        changed = False
        i = 0
        while True:
            k = blob.find("(&(", i)
            if k < 0:
                break
            lhs = re.search(r"([A-Za-z_]\w*)\s*=\s*$", blob[:k])
            if not lhs:
                i = k + 2
                continue
            start = lhs.start(1)
            parsed = _parse_addr_insert_assign(blob, start)
            if not parsed:
                i = k + 2
                continue
            after_asgn, ident, inner = parsed
            nxt = _parse_deref_ostream_insert(blob, after_asgn)
            chained_end = None
            chained = None
            if nxt and nxt[1] == ident:
                chained_end, _name, rhs = nxt
                chained = f"{inner} << {rhs}"
            else:
                asgn2 = _parse_addr_insert_assign(blob, after_asgn)
                if asgn2:
                    end2, ident2, inner2 = asgn2
                    d = _parse_deref_ostream_insert(inner2.lstrip(), 0)
                    if d and d[1] == ident:
                        stripped = inner2.lstrip()
                        tail = stripped[d[0]:]
                        semi = ";" if end2 > 0 and blob[end2 - 1] == ";" else ""
                        chained_end = end2
                        chained = f"{ident2} = (&({inner} << {d[2]}{tail})){semi}"
            if chained_end is None or chained is None:
                i = k + 2
                continue
            end = chained_end
            uses = _ident_span_uses(blob, ident)
            allowed: set[int] = {start}
            for u in uses:
                if _at_local_decl_name(blob, u, ident):
                    allowed.add(u)
            insert_ident = None
            for u in uses:
                if after_asgn <= u < end:
                    insert_ident = u
                    allowed.add(u)
            if insert_ident is None or any(u not in allowed for u in uses):
                i = k + 2
                continue
            blob = blob[:start] + chained + blob[end:]
            trial = re.sub(
                rf"^[ \t]*[A-Za-z_:][\w:\s\*&<>,]*\b{re.escape(ident)}\s*;[ \t]*\n?",
                "",
                blob,
                count=1,
                flags=re.M,
            )
            if not re.search(rf"\b{re.escape(ident)}\b", trial):
                blob = trial
            changed = True
            i = start
            break
    return blob


def _drop_unused_lshift_addr(s: str) -> str:
    """Discarded `&(a << b)` is `a << b`. Keep the address on assignment."""
    blob = s or ""
    out: list[str] = []
    copied = 0
    i = 0
    while True:
        k = blob.find("(&(", i)
        if k < 0:
            break
        open_inner = k + 2
        close_inner = _match_forward(blob, open_inner, "(", ")")
        if close_inner < 0 or close_inner + 1 >= len(blob) or blob[close_inner + 1] != ")":
            i = k + 2
            continue
        inner = blob[open_inner + 1 : close_inner]
        if "<<" not in inner:
            i = k + 2
            continue
        prev = blob[:k].rstrip()
        prev_ch = prev[-1:] if prev else ""
        if prev_ch not in ("", ";", "{", "}"):
            i = k + 2
            continue
        out.append(blob[copied:k])
        out.append(inner)
        copied = close_inner + 2
        i = copied
    out.append(blob[copied:])
    return "".join(out)


def _drop_unused_lshift_addr_assign(s: str) -> str:
    """`p = &(a << b);` with p unread is `a << b;` — ostream* glue temp."""
    blob = s or ""
    changed = True
    while changed:
        changed = False
        i = 0
        while True:
            k = blob.find("(&(", i)
            if k < 0:
                break
            lhs = re.search(r"([A-Za-z_]\w*)\s*=\s*$", blob[:k])
            if not lhs:
                i = k + 2
                continue
            start = lhs.start(1)
            parsed = _parse_addr_insert_assign(blob, start)
            if not parsed:
                i = k + 2
                continue
            end, ident, inner = parsed
            uses = _ident_span_uses(blob, ident)
            decl_hits = [u for u in uses if _at_local_decl_name(blob, u, ident)]
            if not decl_hits:
                i = k + 2
                continue
            allowed: set[int] = {start, *decl_hits}
            if any(u not in allowed for u in uses):
                i = k + 2
                continue
            semi = ";" if end > 0 and blob[end - 1] == ";" else ""
            blob = blob[:start] + inner + semi + blob[end:]
            trial = re.sub(
                rf"^[ \t]*[A-Za-z_:][\w:\s\*&<>,]*\b{re.escape(ident)}\s*;[ \t]*\n?",
                "",
                blob,
                count=1,
                flags=re.M,
            )
            if not re.search(rf"\b{re.escape(ident)}\b", trial):
                blob = trial
            changed = True
            i = start
            break
    return blob


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


_RE_IN_STACK = re.compile(r"\bin_stack_([0-9A-Fa-f]+)\b")


def readable_in_stack_name(hexpart: str) -> str:
    """Decode Ghidra ``in_stack_<hex>`` to a C identifier.

    Long hex is a sign-extended 64-bit frame offset: ``ffffffffffffff58`` is
    -168, not a unique token. Short hex (``in_stack_98``) stays as Ghidra
    printed it. Does not invent a source name.
    """
    raw = (hexpart or "").strip()
    if len(raw) < 8:
        return "in_stack_" + raw
    val = int(raw, 16)
    bits = min(len(raw) * 4, 64)
    sign_bit = 1 << (bits - 1)
    mask = (1 << bits) - 1
    val &= mask
    if val & sign_bit:
        return f"in_stk_n{abs(val - (1 << bits))}"
    return f"in_stk_{val}"


def _rewrite_in_stack_temps(chunk: str) -> str:
    return _RE_IN_STACK.sub(lambda m: readable_in_stack_name(m.group(1)), chunk or "")


def _rewrite_stack_overlay(chunk: str) -> str:
    """Ghidra ``auStack._off_width_`` overlay on ``undefined1[N]`` → byte offset."""

    def repl(m: re.Match[str]) -> str:
        name, off, wid = m.group(1), m.group(2), m.group(3)
        ty = _OVERLAY_TYPE.get(wid, "undefined8")
        return f"(*({ty} *)((char *)({name}) + {off}))"

    return _RE_STACK_OVERLAY.sub(repl, chunk or "")


# Ghidra Help (Decompiler Concepts) + typeop.cc print names. Not a per-sample
# dictionary. PIECE→CONCAT, INT_ZEXT→ZEXT, INT_SEXT→SEXT, SUBPIECE→SUB (two size
# digits: CONCAT44 = 4+4, ZEXT14 = 1→4, CONCAT412 = 4+12). INT_CARRY→CARRY,
# INT_SCARRY→SCARRY, INT_SBORROW→SBORROW append one size (CARRY4). Unary
# TypeOpFunc tokens have no size suffix. BOOL_XOR prints as ^^.
_RE_GHIDRA_PIECE = re.compile(
    r"\b(CONCAT|ZEXT|SEXT|SBORROW|SCARRY|CARRY|SUB)(\d+)\s*\("
)
_RE_GHIDRA_FUNC = re.compile(
    r"\b(POPCOUNT|LZCOUNT|ABS|SQRT|NAN|CEIL|FLOOR|ROUND|TRUNC|INT2FLOAT|FLOAT2FLOAT)\s*\("
)
_UINT_CAST = {1: "unsigned char", 2: "unsigned short", 4: "unsigned", 8: "unsigned long long"}
_SINT_CAST = {1: "signed char", 2: "short", 4: "int", 8: "long long"}


def _piece_sizes(digits: str) -> tuple[int, int] | None:
    """First digit = first size (bytes); remainder = second size."""
    if len(digits) < 2 or not digits.isdigit():
        return None
    a = int(digits[0])
    b = int(digits[1:])
    if a < 1 or b < 1:
        return None
    return a, b


def _split_call_args(inner: str) -> list[str]:
    """Split C++ call args on top-level commas. Shifts (`<<`) are not templates."""
    args: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(inner):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            args.append(inner[start:i].strip())
            start = i + 1
    tail = inner[start:].strip()
    if tail:
        args.append(tail)
    return args


def _uint_cast(expr: str, nbytes: int) -> str:
    ty = _UINT_CAST.get(nbytes, "unsigned long long")
    return f"({ty})({expr})"


def _sint_cast(expr: str, nbytes: int) -> str:
    ty = _SINT_CAST.get(nbytes, "long long")
    return f"({ty})({expr})"


def _overflow_size(digits: str) -> int | None:
    if not digits.isdigit():
        return None
    n = int(digits)
    if n not in _UINT_CAST:
        return None
    return n


def _expand_piece_call(kind: str, digits: str, args: list[str]) -> str | None:
    if kind in ("CARRY", "SCARRY", "SBORROW"):
        n = _overflow_size(digits)
        if n is None or len(args) != 2:
            return None
        x, y = args[0], args[1]
        ux, uy = _uint_cast(x, n), _uint_cast(y, n)
        if kind == "CARRY":
            return f"(({ux} + {uy}) < {ux})"
        if kind == "SCARRY":
            inner = f"~({ux} ^ {uy}) & ({ux} ^ ({ux} + {uy}))"
            return f"({_sint_cast(inner, n)} < 0)"
        inner = f"({ux} ^ {uy}) & ({ux} ^ ({ux} - {uy}))"
        return f"({_sint_cast(inner, n)} < 0)"
    sizes = _piece_sizes(digits)
    if not sizes:
        return None
    a_n, b_n = sizes
    if kind == "CONCAT":
        if len(args) != 2:
            return None
        hi, lo = args[0], args[1]
        return f"(({_uint_cast(hi, min(a_n, 8))} << {b_n * 8}) | {_uint_cast(lo, min(b_n, 8))})"
    if kind == "ZEXT":
        if len(args) != 1:
            return None
        return _uint_cast(args[0], min(b_n, 8))
    if kind == "SEXT":
        if len(args) != 1:
            return None
        signed = _SINT_CAST.get(a_n, "long long")
        outer = "unsigned long long" if b_n > 4 else "unsigned"
        return f"({outer})({signed})({args[0]})"
    if kind == "SUB":
        if len(args) != 2:
            return None
        drop = args[1].strip()
        if not re.fullmatch(r"\d+", drop):
            drop = f"(int)({args[1]})"
        return f"(({_uint_cast(args[0], 8)} >> (8 * {drop})) & {_uint_cast('~0ull', min(b_n, 8))})"
    return None


def _expand_func_call(kind: str, args: list[str]) -> str | None:
    if len(args) != 1:
        return None
    x = args[0]
    if kind == "POPCOUNT":
        return (
            "([](unsigned long long _v){int _n=0;for(;_v;_v>>=1)_n+=(int)(_v&1ull);"
            "return _n;})((unsigned long long)(" + x + "))"
        )
    if kind == "LZCOUNT":
        return (
            "([](unsigned long long _v,int _bits){if(_v==0)return _bits;int _n=0;"
            "for(int _i=_bits-1;_i>=0;--_i){if(_v&(1ull<<_i))break;++_n;}return _n;})"
            f"((unsigned long long)({x}),(int)(sizeof(({x}))*8))"
        )
    if kind == "ABS":
        return f"std::fabs((double)({x}))"
    if kind == "SQRT":
        return f"std::sqrt((double)({x}))"
    if kind == "NAN":
        return f"std::isnan((double)({x}))"
    if kind == "CEIL":
        return f"std::ceil((double)({x}))"
    if kind == "FLOOR":
        return f"std::floor((double)({x}))"
    if kind == "ROUND":
        return f"std::round((double)({x}))"
    if kind == "TRUNC":
        return f"(long long)({x})"
    if kind in ("INT2FLOAT", "FLOAT2FLOAT"):
        return f"(double)({x})"
    return None


def _rewrite_calls(code: str, rx: re.Pattern[str], expand) -> str:
    s = code or ""
    skipped: set[int] = set()
    for _ in range(128):
        matches = list(rx.finditer(s))
        if not matches:
            return s
        progressed = False
        for cand in reversed(matches):
            if cand.start() in skipped:
                continue
            close = _match_forward(s, cand.end() - 1, "(", ")")
            if close < cand.end():
                skipped.add(cand.start())
                continue
            args = _split_call_args(s[cand.end() : close])
            exp = expand(cand, args)
            if not exp:
                skipped.add(cand.start())
                continue
            s = s[: cand.start()] + exp + s[close + 1 :]
            skipped.clear()
            progressed = True
            break
        if not progressed:
            return s
    return s


def _rewrite_ghidra_piece_ops(code: str) -> str:
    """Expand CONCAT/ZEXT/SEXT/SUB/CARRY/SCARRY/SBORROW to C++."""
    return _rewrite_calls(
        code,
        _RE_GHIDRA_PIECE,
        lambda m, args: _expand_piece_call(m.group(1), m.group(2), args),
    )


def _rewrite_ghidra_func_ops(code: str) -> str:
    """Expand POPCOUNT/ABS/NAN/SQRT and other TypeOpFunc tokens to C++."""
    return _rewrite_calls(
        code, _RE_GHIDRA_FUNC, lambda m, args: _expand_func_call(m.group(1), args)
    )


def _rewrite_bool_xor(chunk: str) -> str:
    """BOOL_XOR token ^^ is not C++ (Decompiler Concepts)."""
    return (chunk or "").replace("^^", "!=")


_RE_NEW_ALLOC_DTOR = re.compile(
    r"[ \t]*[^;\n]*~__new_allocator\s*(?:<[^>]*>)?\s*\([^;]*\)\s*;"
)

# Microsoft Learn x64: integer args RCX, RDX, R8, R9. MinGW PE uses this ABI.
_MS64_INT_REGS = (
    ("in_RCX", "in_ECX", "in_CX"),
    ("in_RDX", "in_EDX", "in_DX"),
    ("in_R8D", "in_R8W", "in_R8"),
    ("in_R9D", "in_R9W", "in_R9"),
)
_PTR_AS_INT = frozenset({
    "undefined8", "ulonglong", "unsignedlonglong", "__uint64", "uint8",
    "longlong", "int64", "__int64",
})
# Ghidra types a pointer register as undefined8* / void* / longlong*; that is the formal.
_OPAQUE_PTR_BASE = frozenset({
    "undefined", "undefined8", "ulonglong", "unsignedlonglong", "__uint64",
    "void", "longlong", "int64", "__int64",
})
_INT_AS_INT = frozenset({
    "int", "uint", "unsigned", "unsignedint", "int4", "uint4", "undefined4",
    "unsignedchar", "uchar", "char", "byte", "short", "ushort", "undefined2",
    "int2", "uint2",
})


def _strip_empty_allocator_dtors(chunk: str) -> str:
    """Drop libstdc++ empty-base ~__new_allocator after a ctor (no human equivalent)."""
    return _RE_NEW_ALLOC_DTOR.sub("", chunk or "")


def _norm_abi_type(ty: str) -> str:
    s = re.sub(r"\s+", "", ty or "")
    s = s.replace("std::", "")
    return s


def _abi_types_compatible(decl_ty: str, param_ty: str) -> bool:
    a, b = _norm_abi_type(decl_ty), _norm_abi_type(param_ty)
    if not a or not b:
        return False
    if a == b:
        return True
    if a in _PTR_AS_INT and "*" in b:
        return True
    if b in _PTR_AS_INT and "*" in a:
        return True
    if a in _INT_AS_INT and b in _INT_AS_INT:
        return True
    if "*" in a and "*" in b:
        a_base, b_base = a.replace("*", ""), b.replace("*", "")
        if a_base in _OPAQUE_PTR_BASE or b_base in _OPAQUE_PTR_BASE:
            return True
    return False


_SRET_SLOT_REGS = frozenset({"in_RCX", "in_ECX", "in_CX"})


def _first_fn_return_type(code: str) -> str:
    blob = code or ""
    for ident, t0, close, _end in _iter_function_defs(blob, skip_qualified=True):
        mname = re.search(rf"\b{re.escape(ident)}\s*\(", blob[t0 : close + 1])
        if not mname:
            continue
        return blob[t0 : t0 + mname.start()].strip()
    return ""


def leftover_msx64_in_regs(code: str, *, dump: str = "") -> list[str]:
    """Incoming-register aliases still in the body after msx64 bind.

    String literals and // comments are ignored. in_stack_* is not this lever.
    Microsoft x64 sret keeps RCX as the hidden return slot; that is not leftover.
    """
    blob = re.sub(r'"(?:\\.|[^"\\])*"', " ", code or "")
    blob = re.sub(r"//.*?$", " ", blob, flags=re.M)
    found: list[str] = []
    for aliases in _MS64_INT_REGS:
        for name in aliases:
            if re.search(rf"\b{re.escape(name)}\b", blob):
                found.append(name)
    if not found:
        return found
    sig = dump if str(dump).strip() else code
    if _code_is_msx64_sret(sig):
        found = [n for n in found if n not in _SRET_SLOT_REGS]
    return found


_RE_EXTRAOUT_NAME = re.compile(r"\bextraout_[A-Za-z][A-Za-z0-9]*\b")


def _list_extraout_names(body: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _RE_EXTRAOUT_NAME.finditer(body or ""):
        name = m.group(0)
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _extraout_alias_ident(body: str, name: str) -> str | None:
    """Dump assigned extraout from a simple ident. A CALL is not an ident."""
    m = re.search(
        rf"^[ \t]*{re.escape(name)}\s*=\s*([A-Za-z_]\w*)\s*;",
        body or "",
        re.M,
    )
    if not m:
        return None
    ident = m.group(1)
    if ident == name or ident.startswith("extraout_"):
        return None
    if ident in _NOT_FN_NAMES or ident in ("true", "false", "nullptr"):
        return None
    return ident


def leftover_msx64_extraout(code: str, *, dump: str = "") -> list[str]:
    """extraout_* still in restore: invented, or dump assigned an ident.

    Ghidra extraout after a CALL with no assignment is dump-faithful.
    """
    blob = re.sub(r'"(?:\\.|[^"\\])*"', " ", code or "")
    blob = re.sub(r"//.*?$", " ", blob, flags=re.M)
    found = _list_extraout_names(blob)
    if not found:
        return found
    dump_blob = dump if str(dump).strip() else ""
    out: list[str] = []
    for name in found:
        if dump_blob and re.search(rf"\b{re.escape(name)}\b", dump_blob):
            if _extraout_alias_ident(dump_blob, name) is None:
                continue
        out.append(name)
    return out


def emit_sanitized_restore(data: dict) -> None:
    """Sanitize the run body. Does not write the restore cache key.

    Keeps cpp_code_raw once so the cached LLM text stays comparable.
    Optional func_bytes recover dword array fills Ghidra dead-stored.
    """
    raw = data.get("cpp_code") or ""
    if not str(raw).strip():
        return
    emitted = sanitize_ghidra_cpp(raw, func_bytes=data.get("func_bytes") or b"")
    if emitted == raw:
        return
    data.setdefault("cpp_code_raw", raw)
    data["cpp_code"] = emitted


def _looks_msx64_sret(ret: str) -> bool:
    r = _norm_abi_type(ret)
    if "*" not in r:
        return False
    return any(k in r for k in ("string", "vector", "pair", "map", "set", "list"))


def _rcx_decl_type(body: str) -> str | None:
    for name in ("in_RCX", "in_ECX", "in_CX"):
        ty = _in_reg_decl_type(body, name)
        if ty is not None:
            return ty
    return None


def _is_msx64_sret(
    ret: str, formals: list[tuple[str, str]], body: str
) -> bool:
    """Hidden return in RCX: container name or dump shape.

    Ghidra prints T* for a by-value return. strcpy-like T* copy(T*) keeps
    RCX as the first formal (same type). User T* vs int* first formal is sret.
    """
    if _looks_msx64_sret(ret):
        return True
    if "*" not in _norm_abi_type(ret):
        return False
    rcx_ty = _rcx_decl_type(body)
    if rcx_ty is None:
        return False
    if not _abi_types_compatible(rcx_ty, ret):
        return False
    if not formals:
        return True
    first_pty, first_pn = formals[0]
    if first_pn == "this":
        return bool(re.search(r"\bin_(?:RDX|EDX|DX)\b", body or ""))
    return not _abi_types_compatible(rcx_ty, first_pty)


def _code_is_msx64_sret(code: str) -> bool:
    blob = code or ""
    for ident, t0, close, end in _iter_function_defs(blob, skip_qualified=True):
        mname = re.search(rf"\b{re.escape(ident)}\s*\(", blob[t0 : close + 1])
        if not mname:
            continue
        ret = blob[t0 : t0 + mname.start()].strip()
        open_p = t0 + mname.end() - 1
        formals = _parse_param_decls(blob[open_p + 1 : close])
        brace = _brace_after_params(blob, close)
        if brace < 0:
            continue
        return _is_msx64_sret(ret, formals, blob[brace : end + 1])
    return False


def _parse_param_decls(inner: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for raw in _split_top_args(inner):
        p = raw.split("=")[0].strip()
        if not p or p == "void" or p == "...":
            continue
        m = re.search(r"([A-Za-z_]\w*)\s*$", p)
        if not m or m.group(1) == "void":
            continue
        out.append((p[: m.start()].strip(), m.group(1)))
    return out


_STMT_LEAD = re.compile(
    r"^(?:return|goto|break|continue|delete|throw|co_return|co_yield)\b"
)


def _in_reg_decl_type(body: str, name: str) -> str | None:
    m = re.search(
        rf"^[ \t]*([A-Za-z_:][\w:\s\*&<>,]*)\b{re.escape(name)}\s*(?:=\s*[^;]+)?;",
        body,
        re.M,
    )
    if not m:
        return None
    ty = m.group(1).strip()
    if _STMT_LEAD.match(ty):
        return None
    return ty


def _drop_in_reg_decl(body: str, alias: str) -> str:
    """Drop `T in_RCX;` or `T in_RCX = p;`. Keep `return in_RCX;`."""

    def repl(m: re.Match) -> str:
        if _STMT_LEAD.match(m.group(1).strip()):
            return m.group(0)
        return ""

    return re.sub(
        rf"^[ \t]*([A-Za-z_:][\w:\s\*&<>,]*)\b{re.escape(alias)}\s*(?:=\s*[^;]+)?;[ \t]*\r?\n?",
        repl,
        body,
        count=1,
        flags=re.M,
    )


def _strip_dup_formal_decl(body: str, pname: str) -> str:
    """Drop a leftover local that now shadows the formal. Keep `return n;`."""

    def repl(m: re.Match) -> str:
        if _STMT_LEAD.match(m.group(1).strip()):
            return m.group(0)
        return ""

    return re.sub(
        rf"^[ \t]*([A-Za-z_:][\w:\s\*&<>,]*)\b{re.escape(pname)}\s*;[ \t]*\r?\n?",
        repl,
        body,
        count=1,
        flags=re.M,
    )


def _rewrite_one_msx64_fn(blob: str, ident: str, t0: int, close: int, end: int) -> str:
    if ident == "main":
        return blob
    mname = re.search(rf"\b{re.escape(ident)}\s*\(", blob[t0 : close + 1])
    if not mname:
        return blob
    name_at = t0 + mname.start()
    open_p = t0 + mname.end() - 1
    ret = blob[t0:name_at].strip()
    formals = _parse_param_decls(blob[open_p + 1 : close])
    brace = _brace_after_params(blob, close)
    if brace < 0:
        return blob
    body = blob[brace : end + 1]
    if "in_" not in body:
        return blob
    start_slot = 1 if _is_msx64_sret(ret, formals, body) else 0
    this_local = _in_reg_decl_type(body, "this") is not None
    if not formals and not (start_slot and this_local):
        return blob
    repl: dict[str, str] = {}
    for i, (_pty, pname) in enumerate(formals):
        slot = start_slot + i
        if slot >= len(_MS64_INT_REGS):
            break
        aliases = _MS64_INT_REGS[slot]
        for alias in aliases:
            if not re.search(rf"\b{re.escape(alias)}\b", body):
                continue
            decl_ty = _in_reg_decl_type(body, alias)
            if decl_ty is None:
                if not start_slot:
                    continue
                decl_ty = _pty
            if not _abi_types_compatible(decl_ty, _pty):
                continue
            repl[alias] = pname
    if start_slot and this_local and all(pn != "this" for _pt, pn in formals):
        for alias in _MS64_INT_REGS[1]:
            if alias in repl:
                continue
            if not re.search(rf"\b{re.escape(alias)}\b", body):
                continue
            repl[alias] = "this"
    if not repl:
        return blob
    new_body = body
    for alias, pname in sorted(repl.items(), key=lambda kv: -len(kv[0])):
        new_body = _drop_in_reg_decl(new_body, alias)
        new_body = re.sub(rf"\b{re.escape(alias)}\b", pname, new_body)
        if pname == "this":
            continue
        new_body = _strip_dup_formal_decl(new_body, pname)
    return blob[:brace] + new_body + blob[end + 1 :]


def _rewrite_msx64_incoming(code: str) -> str:
    """Bind Ghidra in_RCX/in_RDX to formals (Microsoft x64 / MinGW PE)."""
    blob = code or ""
    spans = list(_iter_function_defs(blob, skip_qualified=True))
    for ident, t0, close, end in reversed(spans):
        blob = _rewrite_one_msx64_fn(blob, ident, t0, close, end)
    return blob


_RE_STACK_HOME_IDENT = re.compile(
    r"\b(in_stack_[0-9A-Fa-f]+|in_stk_n?\d+)\b"
)


def _abi_both_pointers(decl_ty: str, param_ty: str) -> bool:
    a, b = _norm_abi_type(decl_ty), _norm_abi_type(param_ty)
    return "*" in a and "*" in b


def _list_stack_home_decls(body: str) -> list[tuple[str, str]]:
    """Dump-declared in_stack / in_stk locals, first-occurrence order."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for m in _RE_STACK_HOME_IDENT.finditer(body or ""):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        ty = _in_reg_decl_type(body, name)
        if ty is None:
            continue
        out.append((name, ty))
    return out


def _home_init_ident(body: str, name: str) -> str | None:
    """Dump copied a formal into the home: `T in_stk_n40 = n;`."""
    m = re.search(
        rf"^[ \t]*[A-Za-z_:][\w:\s\*&<>,]*\b{re.escape(name)}\s*=\s*([A-Za-z_]\w*)\s*;",
        body or "",
        re.M,
    )
    if not m:
        return None
    ident = m.group(1)
    if ident == name:
        return None
    if ident.startswith((
        "in_stk", "in_stack", "extraout_", "in_RCX", "in_RDX", "in_R8",
        "in_R9", "in_ECX", "in_EDX", "in_CX", "in_DX",
    )):
        return None
    if ident in _NOT_FN_NAMES or ident in ("true", "false", "nullptr"):
        return None
    return ident


def _formal_used_in_body(body: str, pname: str) -> bool:
    return bool(re.search(rf"\b{re.escape(pname)}\b", body or ""))


def _rewrite_one_msx64_stack_homes(
    blob: str, ident: str, t0: int, close: int, end: int
) -> str:
    """Bind dump-declared stack homes to formals. Skip main.

    Ghidra often types the home pointee unlike the formal (T* vs vector*).
    Both-pointer is enough on the same slot; do not invent a source identifier.
    No decl — no bind (undeclared in_stack transplant is a known regression).

    Same-type spill: `T in_stk = formal` is that argument. A leftover home
    may also match the unique unused formal of a compatible type (not
    T* vs U* field-0). Two ints and one home stay leftover.
    """
    if ident == "main":
        return blob
    mname = re.search(rf"\b{re.escape(ident)}\s*\(", blob[t0 : close + 1])
    if not mname:
        return blob
    open_p = t0 + mname.end() - 1
    formals = _parse_param_decls(blob[open_p + 1 : close])
    if not formals:
        return blob
    brace = _brace_after_params(blob, close)
    if brace < 0:
        return blob
    body = blob[brace : end + 1]
    homes = _list_stack_home_decls(body)
    if not homes:
        return blob
    formal_ty = {pname: pty for pty, pname in formals}
    repl: dict[str, str] = {}
    bound_formals: set[str] = set()
    for alias, decl_ty in homes:
        src = _home_init_ident(body, alias)
        if src is None or src not in formal_ty:
            continue
        if not _abi_types_compatible(decl_ty, formal_ty[src]):
            continue
        repl[alias] = src
        bound_formals.add(src)
    for i, (_pty, pname) in enumerate(formals):
        if i >= len(homes):
            break
        alias, decl_ty = homes[i]
        if alias in repl or pname in bound_formals:
            continue
        if _formal_used_in_body(body, pname):
            continue
        if not (
            _abi_types_compatible(decl_ty, _pty) or _abi_both_pointers(decl_ty, _pty)
        ):
            continue
        repl[alias] = pname
        bound_formals.add(pname)
    unused = [
        (pty, pname)
        for pty, pname in formals
        if pname not in bound_formals and not _formal_used_in_body(body, pname)
    ]
    for alias, decl_ty in homes:
        if alias in repl:
            continue
        matches = [
            (pty, pname)
            for pty, pname in unused
            if _abi_types_compatible(decl_ty, pty)
        ]
        if len(matches) != 1:
            continue
        _pty, pname = matches[0]
        repl[alias] = pname
        unused = [(t, n) for t, n in unused if n != pname]
    if not repl:
        return blob
    new_body = body
    for alias, pname in sorted(repl.items(), key=lambda kv: -len(kv[0])):
        new_body = _drop_in_reg_decl(new_body, alias)
        new_body = re.sub(rf"\b{re.escape(alias)}\b", pname, new_body)
        new_body = _strip_dup_formal_decl(new_body, pname)
    return blob[:brace] + new_body + blob[end + 1 :]


def _rewrite_msx64_stack_homes(code: str) -> str:
    """Bind Ghidra in_stack homes to formals when the dump declared them."""
    blob = code or ""
    spans = list(_iter_function_defs(blob, skip_qualified=True))
    for ident, t0, close, end in reversed(spans):
        blob = _rewrite_one_msx64_stack_homes(blob, ident, t0, close, end)
    return blob


def _rewrite_one_extraout(
    blob: str, _ident: str, t0: int, close: int, end: int
) -> str:
    """Collapse extraout_* when the dump assigned it from a simple ident."""
    brace = _brace_after_params(blob, close)
    if brace < 0:
        return blob
    body = blob[brace : end + 1]
    names = _list_extraout_names(body)
    if not names:
        return blob
    repl: dict[str, str] = {}
    for name in names:
        ident = _extraout_alias_ident(body, name)
        if ident is None:
            continue
        repl[name] = ident
    if not repl:
        return blob
    new_body = body
    for name, ident in sorted(repl.items(), key=lambda kv: -len(kv[0])):
        new_body = re.sub(
            rf"^[ \t]*[A-Za-z_:][\w:\s\*&<>,]*\b{re.escape(name)}\s*;[ \t]*\n?",
            "",
            new_body,
            count=1,
            flags=re.M,
        )
        new_body = re.sub(
            rf"^[ \t]*{re.escape(name)}\s*=\s*{re.escape(ident)}\s*;[ \t]*\n?",
            "",
            new_body,
            count=1,
            flags=re.M,
        )
        new_body = re.sub(rf"\b{re.escape(name)}\b", ident, new_body)
        if ident != "this":
            new_body = _strip_dup_formal_decl(new_body, ident)
    return blob[:brace] + new_body + blob[end + 1 :]


def _rewrite_msx64_extraout(code: str) -> str:
    """Bind dump-assigned extraout_* aliases. Do not invent a CALL return."""
    blob = code or ""
    spans = list(_iter_function_defs(blob, skip_qualified=False))
    for ident, t0, close, end in reversed(spans):
        blob = _rewrite_one_extraout(blob, ident, t0, close, end)
    return blob


def _ptr_cast_lparen(s: str, i: int) -> int | None:
    j = i - 1
    while j >= 0 and s[j] in " \t\n\r":
        j -= 1
    if j < 0 or s[j] != ")":
        return None
    depth = 0
    k = j
    while k >= 0:
        ch = s[k]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                if "*" in s[k + 1 : j]:
                    return k
                return None
        k -= 1
    return None


def _strip_concat_operand(a: str) -> str:
    a = (a or "").strip()
    prev = None
    while a != prev:
        prev = a
        a = re.sub(r"^\([^()]*\)\s*", "", a).strip()
        if len(a) >= 2 and a[0] == "(" and a[-1] == ")":
            a = a[1:-1].strip()
    return a


_RE_PIECE_TEMP = re.compile(
    r"^(?:in_stack_[0-9A-Fa-f]+|in_stk_n?\d+|"
    r"(?:[usil]|pu|pb|pc|pi|pl|ps|pp|pf|pd)?Var\d+)$"
)


def _is_piece_temp(name: str) -> bool:
    """Stack home or Ghidra temp. Not a source-level formal like n."""
    return bool(name and _RE_PIECE_TEMP.match(name))


def _stack_home_arg(a: str) -> str | None:
    """CONCAT operand that is a 4-byte incoming stack home (casts stripped)."""
    hit = _RE_STACK_HOME_IDENT.fullmatch(_strip_concat_operand(a))
    return hit.group(1) if hit else None


_RE_INT_CAST_TYPE = re.compile(
    r"(?:unsigned(?:\s+(?:long\s+)?long)?|signed(?:\s+int)?|"
    r"uint(?:32_t|64_t)?|uint|int|long|short|char)"
)


def _is_int_cast_type(s: str) -> bool:
    return bool(_RE_INT_CAST_TYPE.fullmatch((s or "").strip()))


def _simple_ident_arg(a: str) -> str | None:
    """CONCAT operand that is a bare ident after Ghidra/C casts."""
    a = _strip_concat_operand(a)
    if not re.fullmatch(r"[A-Za-z_]\w*", a) or a in _NOT_FN_NAMES:
        return None
    if _is_int_cast_type(a):
        return None
    return a


def _match_open_paren(s: str, close_i: int) -> int | None:
    if close_i < 0 or close_i >= len(s) or s[close_i] != ")":
        return None
    depth = 0
    k = close_i
    while k >= 0:
        if s[k] == ")":
            depth += 1
        elif s[k] == "(":
            depth -= 1
            if depth == 0:
                return k
        k -= 1
    return None


def _ident_span_left(s: str, i: int) -> tuple[str, int] | None:
    """Ident immediately left of ``i``, through Ghidra/C casts and parens."""
    j = i
    while j > 0 and s[j - 1] in " \t\n\r":
        j -= 1
    while j > 0 and s[j - 1] == ")":
        open_p = _match_open_paren(s, j - 1)
        if open_p is None:
            return None
        inner = s[open_p + 1 : j - 1].strip()
        if _is_int_cast_type(inner):
            j = open_p
            while j > 0 and s[j - 1] in " \t\n\r":
                j -= 1
            continue
        ident = _simple_ident_arg(inner)
        if ident:
            start = open_p
            k = open_p
            while k > 0 and s[k - 1] in " \t\n\r":
                k -= 1
            while k > 0 and s[k - 1] == ")":
                o2 = _match_open_paren(s, k - 1)
                if o2 is None:
                    break
                cast = s[o2 + 1 : k - 1].strip()
                if not _is_int_cast_type(cast):
                    break
                start = o2
                k = o2
                while k > 0 and s[k - 1] in " \t\n\r":
                    k -= 1
            return ident, start
        return None
    k = j
    while k > 0 and (s[k - 1].isalnum() or s[k - 1] == "_"):
        k -= 1
    ident = s[k:j]
    if re.fullmatch(r"[A-Za-z_]\w*", ident) and ident not in _NOT_FN_NAMES:
        return ident, k
    return None


def _ident_span_right(s: str, i: int) -> tuple[str, int] | None:
    """Ident immediately right of ``i``, through Ghidra/C casts and parens."""
    j = i
    while j < len(s) and s[j] in " \t\n\r":
        j += 1
    while j < len(s) and s[j] == "(":
        close = _match_forward(s, j, "(", ")")
        if close < 0:
            return None
        inner = s[j + 1 : close].strip()
        if _is_int_cast_type(inner):
            j = close + 1
            while j < len(s) and s[j] in " \t\n\r":
                j += 1
            continue
        ident = _simple_ident_arg(inner)
        if ident:
            return ident, close + 1
        return None
    m = re.match(r"[A-Za-z_]\w*", s[j:])
    if not m or m.group(0) in _NOT_FN_NAMES:
        return None
    return m.group(0), j + len(m.group(0))


def _wrap_shift32_span(blob: str, start: int, end: int) -> tuple[int, int]:
    """Absorb grouping parens around ``hi<<32|lo``, not a surrounding call."""
    while start > 0:
        i = start
        while i > 0 and blob[i - 1] in " \t\n\r":
            i -= 1
        if i == 0 or blob[i - 1] != "(":
            break
        close = _match_forward(blob, i - 1, "(", ")")
        if close < 0:
            break
        start = i - 1
        if close >= end - 1:
            end = close + 1
    return start, end


def _next_shift32_or_span(body: str) -> tuple[int, int, str, str] | None:
    """``hi << 32 | lo`` of two idents: Ghidra CONCAT44 expand / restorer arithmetic."""
    for m in re.finditer(r"<<\s*32\b", body):
        left = _ident_span_left(body, m.start())
        if left is None:
            continue
        hi, start = left
        j = m.end()
        while j < len(body) and body[j] in " \t\n\r":
            j += 1
        if j < len(body) and body[j] == ")":
            j += 1
            while j < len(body) and body[j] in " \t\n\r":
                j += 1
        if j >= len(body) or body[j] != "|":
            continue
        right = _ident_span_right(body, j + 1)
        if right is None:
            continue
        lo, end = right
        start, end = _wrap_shift32_span(body, start, end)
        return start, end, hi, lo
    return None


def _piece_used_as_ptr(body: str, start: int) -> bool:
    if _ptr_cast_lparen(body, start) is not None:
        return True
    after = body[start:].lstrip()
    return after.startswith("->") or (start > 0 and body[start - 1 : start + 2] == "->")


def _next_concat_ptr_span(body: str) -> tuple[int, int, list[str]] | None:
    """8-byte PIECE used as T*: CONCAT or shift-or. Piece names may be homes, formals, temps."""
    for m in _RE_GHIDRA_PIECE.finditer(body):
        if m.group(1) != "CONCAT":
            continue
        sizes = _piece_sizes(m.group(2))
        if not sizes or sizes[0] + sizes[1] != 8:
            continue
        open_c = m.end() - 1
        close_c = _match_forward(body, open_c, "(", ")")
        if close_c < 0:
            continue
        args = [a.strip() for a in _split_top_args(body[open_c + 1 : close_c])]
        if len(args) != 2:
            continue
        hi_id = _simple_ident_arg(args[0])
        lo_id = _simple_ident_arg(args[1])
        if hi_id is None or lo_id is None:
            continue
        start = m.start()
        end = close_c + 1
        hi_home = _stack_home_arg(args[0])
        lo_home = _stack_home_arg(args[1])
        both_homes = bool(hi_home and lo_home)
        cast_l = _ptr_cast_lparen(body, start)
        if cast_l is not None:
            start = cast_l
        elif not both_homes and not _piece_used_as_ptr(body, start):
            continue
        if not both_homes and cast_l is None:
            continue
        return start, end, [hi_id, lo_id]
    hit = _next_shift32_or_span(body)
    if hit is None:
        return None
    start, end, hi, lo = hit
    cast_l = _ptr_cast_lparen(body, start)
    if cast_l is None:
        return None
    return cast_l, end, [hi, lo]


def _at_ptr_cast(s: str, i: int) -> bool:
    if _ptr_cast_lparen(s, i) is not None:
        return True
    if i < 0 or i >= len(s) or s[i] != "(":
        return False
    close = _match_forward(s, i, "(", ")")
    return close > i and "*" in s[i + 1 : close]


def leftover_concat_shift_ptr(code: str) -> list[str]:
    """8-byte PIECE still written as pointer arithmetic (CONCAT expand / restorer)."""
    seen: set[str] = set()
    out: list[str] = []
    blob = code or ""
    pos = 0
    while pos < len(blob):
        hit = _next_concat_ptr_span(blob[pos:])
        if hit is None:
            break
        start, end, names = hit
        start += pos
        end += pos
        if not _at_ptr_cast(blob, start):
            pos = max(end, pos + 1)
            continue
        for name in names:
            if name and name not in seen:
                seen.add(name)
                out.append(name)
        pos = max(end, pos + 1)
    return out


_RE_OSTREAM_ADDR_INSERT = re.compile(
    r"\(\s*&\s*\(\s*\(\s*\*\s*\("
    r"|\(\s*\*\s*\(\s*(?:std::)?c(?:out|err|log)\s*\)"
    r"|\*\s*\(\s*(?:std::)?c(?:out|err|log)\s*\)"
)


def leftover_ostream_addr_insert(code: str) -> list[str]:
    """Address-of inserter with a deref, or deref of a stream object.

    Human writes ``std::cout << x`` / ``*p << x``. Leftover
    ``p = (&((*(std::cout)) << x)`` is the same ostream-addr-insert class.
    """
    seen: set[str] = set()
    out: list[str] = []
    for m in _RE_OSTREAM_ADDR_INSERT.finditer(code or ""):
        tok = re.sub(r"\s+", "", m.group(0))[:48]
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def _concat_ptr_target(
    ret: str, formals: list[tuple[str, str]], body: str
) -> str | None:
    # Microsoft x64: 8-byte pointer in RCX (sret) or the next pointer formal.
    # Ghidra x86-64-win integer_size is 4, so the home is two PIECE varnodes.
    if _is_msx64_sret(ret, formals, body):
        for name in ("in_RCX", "in_ECX", "in_CX"):
            if re.search(rf"\b{re.escape(name)}\b", body or ""):
                return name
    unused: str | None = None
    used: str | None = None
    for _pty, pname in formals:
        if "*" not in _norm_abi_type(_pty):
            continue
        if pname == "this":
            continue
        if re.search(rf"\b{re.escape(pname)}\b", body or ""):
            if used is None:
                used = pname
        elif unused is None:
            unused = pname
    return unused or used


def _callee_formals_map(blob: str) -> dict[str, list[tuple[str, str]]]:
    """Definitions and prototypes in this blob. Microsoft x64 types, not gym names."""
    found: dict[str, list[tuple[str, str]]] = {}
    for ident, t0, close, _end in _iter_function_defs(blob, skip_qualified=False):
        mname = re.search(rf"\b{re.escape(ident)}\s*\(", blob[t0 : close + 1])
        if not mname:
            continue
        open_p = t0 + mname.end() - 1
        found[ident] = _parse_param_decls(blob[open_p + 1 : close])
    for m in re.finditer(
        r"(?:^|[;{}])\s*(?:[A-Za-z_:][\w:\s\*&<>,]*)\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*;",
        blob or "",
        re.M,
    ):
        ident = m.group(1)
        if ident in _NOT_FN_NAMES or ident in found:
            continue
        found[ident] = _parse_param_decls(m.group(2))
    return found


def _arg_index_in_call(s: str, pos: int) -> tuple[str, int] | None:
    i = pos
    depth = 0
    commas = 0
    while i > 0:
        i -= 1
        ch = s[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                j = i
                while j > 0 and s[j - 1] in " \t\n\r":
                    j -= 1
                m = re.search(r"([A-Za-z_]\w*)\s*$", s[:j])
                if not m or m.group(1) in _NOT_FN_NAMES:
                    return None
                return m.group(1), commas
            depth -= 1
        elif ch == "," and depth == 0:
            commas += 1
        elif ch in "{};" and depth == 0:
            return None
    return None


def _at_local_decl_name(s: str, start: int, name: str) -> bool:
    ls = s.rfind("\n", 0, start) + 1
    le = s.find("\n", start)
    if le < 0:
        le = len(s)
    return bool(
        re.match(
            rf"^[ \t]*[A-Za-z_:][\w:\s\*&<>,]*\b{re.escape(name)}\s*;[ \t]*$",
            s[ls:le],
        )
    )


def _home_use_is_ptr(
    s: str, start: int, end: int, formals_map: dict[str, list[tuple[str, str]]]
) -> bool:
    after = s[end:].lstrip()
    if after.startswith("->") or after.startswith("."):
        return True
    if _ptr_cast_lparen(s, start) is not None:
        return True
    j = start
    while j > 0 and s[j - 1] in " \t":
        j -= 1
    if j > 0 and s[j - 1] == "*":
        return True
    info = _arg_index_in_call(s, start)
    if not info:
        return False
    callee, idx = info
    formals = formals_map.get(callee) or []
    if idx >= len(formals):
        return False
    return "*" in _norm_abi_type(formals[idx][0])


def _rewrite_one_concat_stack_ptr(
    blob: str, ident: str, t0: int, close: int, end: int
) -> str:
    """8-byte PIECE used as T* is that pointer. Pieces may already be formals or temps."""
    if ident == "main":
        return blob
    mname = re.search(rf"\b{re.escape(ident)}\s*\(", blob[t0 : close + 1])
    if not mname:
        return blob
    name_at = t0 + mname.start()
    open_p = t0 + mname.end() - 1
    ret = blob[t0:name_at].strip()
    formals = _parse_param_decls(blob[open_p + 1 : close])
    brace = _brace_after_params(blob, close)
    if brace < 0:
        return blob
    fn_end = end
    body = blob[brace : fn_end + 1]
    target = _concat_ptr_target(ret, formals, body)
    if not target:
        return blob
    new_body = body
    homes: list[str] = []
    while True:
        hit = _next_concat_ptr_span(new_body)
        if hit is None:
            break
        start, stop, extra = hit
        homes.extend(n for n in extra if _is_piece_temp(n))
        new_body = new_body[:start] + target + new_body[stop:]
    if new_body == body:
        return blob
    new_body = re.sub(
        rf"\({re.escape(target)}\)\s*->",
        f"{target}->",
        new_body,
    )
    formals_map = _callee_formals_map(blob)
    seen: set[str] = set()
    for name in homes:
        if name in seen:
            continue
        seen.add(name)
        for m in reversed(list(re.finditer(rf"\b{re.escape(name)}\b", new_body))):
            if _at_local_decl_name(new_body, m.start(), name):
                continue
            if _home_use_is_ptr(new_body, m.start(), m.end(), formals_map):
                new_body = new_body[: m.start()] + target + new_body[m.end() :]
        trial = re.sub(
            rf"^[ \t]*[A-Za-z_:][\w:\s\*&<>,]*\b{re.escape(name)}\s*;[ \t]*\n?",
            "",
            new_body,
            count=1,
            flags=re.M,
        )
        if re.search(rf"\b{re.escape(name)}\b", trial):
            continue
        new_body = trial
    formal_names = {pname for _pty, pname in formals}
    if target in formal_names:
        new_body = _strip_dup_formal_decl(new_body, target)
    return blob[:brace] + new_body + blob[fn_end + 1 :]


def _rewrite_msx64_concat_stack_ptr(code: str) -> str:
    """Bind an 8-byte PIECE (CONCAT / shift-or) used as T* to that pointer."""
    blob = code or ""
    spans = list(_iter_function_defs(blob, skip_qualified=True))
    for ident, t0, close, end in reversed(spans):
        blob = _rewrite_one_concat_stack_ptr(blob, ident, t0, close, end)
    return blob


def _rewrite_one_this_local(
    blob: str, _ident: str, t0: int, close: int, end: int
) -> str:
    """Ghidra `T *this;` in a free function is a local, not C++ this."""
    from src.analysis.ghidra_prepass import proto_has_this

    brace = _brace_after_params(blob, close)
    if brace < 0:
        return blob
    if proto_has_this(blob[t0:brace]):
        return blob
    body = blob[brace : end + 1]
    if _in_reg_decl_type(body, "this") is None:
        return blob
    new_body = re.sub(r"\bthis\b", "ghidra_this", body)
    return blob[:brace] + new_body + blob[end + 1 :]


def _rewrite_ghidra_this_local(code: str) -> str:
    blob = code or ""
    spans = list(_iter_function_defs(blob, skip_qualified=False))
    for ident, t0, close, end in reversed(spans):
        blob = _rewrite_one_this_local(blob, ident, t0, close, end)
    return blob


_TRAP_CALL = re.compile(
    r"^(?:abort|__builtin_trap|__builtin_unreachable|__stack_chk_fail|"
    r"___stack_chk_fail|__report_rangecheckfailure|_invalid_parameter|"
    r"__ubsan_handle_[A-Za-z0-9_]+)\s*\([^;]*\)\s*;?\s*$",
    re.I,
)
_RE_OVF_OP = re.compile(r"\b(?:CARRY|SCARRY|SBORROW)\d+\s*\(")
_RE_COMPILER_GUARD = re.compile(
    r"stack_chk|security_cookie|security_check_cookie|_RTC_",
    re.I,
)
_RE_CHKSTK = re.compile(
    r"[ \t]*\b_{0,3}(?:chkstk_ms|chkstk|alloca_probe)\s*\(\s*\)\s*;[ \t]*\n?",
    re.I,
)
_RE_COOKIE_CALL = re.compile(
    r"[ \t]*\b(?:__security_check_cookie|__security_init_cookie)\s*\([^;]*\)\s*;[ \t]*\n?"
)


def _is_trap_body(inner: str) -> bool:
    s = re.sub(r"/\*.*?\*/", "", inner or "", flags=re.S)
    s = re.sub(r"//.*?$", "", s, flags=re.M).strip()
    if not s:
        return True
    stmts = [p.strip() + ";" for p in s.split(";") if p.strip()]
    return bool(stmts) and all(_TRAP_CALL.match(st) for st in stmts)


def _is_instrument_cond(cond: str) -> bool:
    c = cond or ""
    return bool(_RE_OVF_OP.search(c) or _RE_COMPILER_GUARD.search(c))


def _strip_instrument_ifs(code: str) -> str:
    """Drop compiler overflow/canary ifs whose body is only abort/trap/SSP fail."""
    s = code or ""
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        m = re.search(r"\bif\s*\(", s[i:])
        if not m:
            out.append(s[i:])
            break
        start = i + m.start()
        open_p = i + m.end() - 1
        close_p = _match_forward(s, open_p, "(", ")")
        if close_p < 0:
            out.append(s[i : start + 1])
            i = start + 1
            continue
        cond = s[open_p + 1 : close_p]
        k = close_p + 1
        while k < n and s[k] in " \t\n\r":
            k += 1
        end = -1
        if _is_instrument_cond(cond):
            if k < n and s[k] == "{":
                close_b = _match_forward(s, k, "{", "}")
                if close_b >= 0 and _is_trap_body(s[k + 1 : close_b]):
                    end = close_b + 1
            else:
                semi = s.find(";", k)
                if semi >= 0 and _is_trap_body(s[k : semi + 1]):
                    end = semi + 1
        if end < 0:
            out.append(s[i : close_p + 1])
            i = close_p + 1
            continue
        out.append(s[i:start])
        i = end
        while i < n and s[i] in " \t\n\r":
            i += 1
            if i < n and s[i] == "\n":
                i += 1
                break
    return "".join(out)


def _strip_compiler_instrumentation(code: str) -> str:
    """Remove GCC/MSVC probes and overflow traps. Recompilation reinserts them."""
    t = _strip_instrument_ifs(code or "")
    t = _RE_CHKSTK.sub("", t)
    t = _RE_COOKIE_CALL.sub("", t)
    return t


_RE_INT_ARRAY_DECL = re.compile(
    r"^([ \t]*)((?:unsigned\s+)?(?:int|uint|undefined4|uint32_t))\s+"
    r"([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*;[ \t]*$",
    re.M,
)
_RE_ARRAY_ELEM_ASSIGN = re.compile(
    r"^([ \t]*)([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*=\s*"
    r"(-?\d+|0x[0-9A-Fa-f]+)\s*;[ \t]*$",
    re.M,
)
_RE_FOR_COUNT = re.compile(
    r"for\s*\(\s*([A-Za-z_]\w*)\s*=\s*0\s*;\s*\1\s*<\s*(\d+)\s*;"
    r"\s*\1\s*=\s*\1\s*\+\s*1\s*\)"
)
_RE_INT_HOME_DECL = re.compile(
    r"^([ \t]*)((?:unsigned\s+)?(?:int|uint|undefined4|uint32_t))\s+"
    r"(in_stk_\w+|in_stack_[0-9A-Fa-f]+)\s*;[ \t]*$",
    re.M,
)


def _parse_int_lit(raw: str) -> int:
    s = (raw or "").strip()
    if s.lower().startswith("0x"):
        v = int(s, 16)
        return v - 0x100000000 if v >= 0x80000000 else v
    return int(s, 10)


def _array_has_init(decl_line: str) -> bool:
    return "=" in (decl_line or "")


def _rewrite_local_array_elem_inits(code: str) -> str:
    """Ghidra often prints `xs[0]=1; xs[1]=2;` for a local array fill."""
    blob = code or ""
    decls = list(_RE_INT_ARRAY_DECL.finditer(blob))
    if not decls:
        return blob
    assigns: dict[str, list[tuple[int, int, int, int]]] = {}
    for m in _RE_ARRAY_ELEM_ASSIGN.finditer(blob):
        name = m.group(2)
        idx = int(m.group(3))
        val = _parse_int_lit(m.group(4))
        assigns.setdefault(name, []).append((idx, val, m.start(), m.end()))
    reps: list[tuple[int, int, str]] = []
    for d in decls:
        name = d.group(3)
        n = int(d.group(4))
        hits = assigns.get(name) or []
        if len(hits) != n:
            continue
        idxs = sorted(i for i, _v, _a, _b in hits)
        if idxs != list(range(n)):
            continue
        by_i = {i: v for i, v, _a, _b in hits}
        vals = ", ".join(str(by_i[i]) for i in range(n))
        indent, ty = d.group(1), d.group(2)
        reps.append((d.start(), d.end(), f"{indent}{ty} {name}[{n}] = {{{vals}}};"))
        for _i, _v, a, b in hits:
            line_start = blob.rfind("\n", 0, a) + 1
            line_end = blob.find("\n", b)
            line_end = len(blob) if line_end < 0 else line_end + 1
            reps.append((line_start, line_end, ""))
    if not reps:
        return blob
    out = blob
    for a, b, text in sorted(reps, key=lambda r: -r[0]):
        out = out[:a] + text + out[b:]
    return out


def _for_body_span(blob: str, header_end: int) -> tuple[int, int] | None:
    i = header_end
    while i < len(blob) and blob[i] in " \t\r\n":
        i += 1
    if i >= len(blob) or blob[i] != "{":
        return None
    depth = 0
    for j in range(i, len(blob)):
        if blob[j] == "{":
            depth += 1
        elif blob[j] == "}":
            depth -= 1
            if depth == 0:
                return i, j + 1
    return None


def _iter_dead_array_homes(
    code: str,
) -> list[tuple[str, str, str, int]]:
    """Unused `T xs[N]` plus `for (i=0; i<N)` reading a unique int home.

    Ghidra dead-stores the fill; the indexed load looks like in_stk.
    Unique array and unique int home only. Not T* vs U*.
    """
    blob = code or ""
    arrays = {
        m.group(3): int(m.group(4))
        for m in _RE_INT_ARRAY_DECL.finditer(blob)
    }
    if not arrays:
        return []
    homes = [m.group(3) for m in _RE_INT_HOME_DECL.finditer(blob)]
    if not homes:
        return []
    stripped = _RE_INT_ARRAY_DECL.sub("", blob)
    found: list[tuple[str, str, str, int]] = []
    for hm in _RE_FOR_COUNT.finditer(blob):
        idx, n_s = hm.group(1), hm.group(2)
        n = int(n_s)
        matches = [name for name, sz in arrays.items() if sz == n]
        if len(matches) != 1:
            continue
        arr = matches[0]
        if re.search(rf"\b{re.escape(arr)}\s*\[", stripped):
            continue
        span = _for_body_span(blob, hm.end())
        if span is None:
            continue
        body = blob[span[0] : span[1]]
        used = [h for h in homes if re.search(rf"\b{re.escape(h)}\b", body)]
        if len(used) != 1:
            continue
        found.append((arr, used[0], idx, n))
    return found


def leftover_dead_array_home(code: str) -> list[str]:
    """Array names still unused while a same-width int home is the loop load."""
    seen: set[str] = set()
    out: list[str] = []
    for arr, _home, _idx, _n in _iter_dead_array_homes(code):
        if arr in seen:
            continue
        seen.add(arr)
        out.append(arr)
    return out


def _rewrite_local_array_loop_index(code: str) -> str:
    """Unused `T xs[N]` plus `for (i=0; i<N)` using an int home is `xs[i]`."""
    blob = code or ""
    hits = _iter_dead_array_homes(blob)
    if not hits:
        return blob
    arr, home, idx, _n = hits[0]
    for hm in _RE_FOR_COUNT.finditer(blob):
        if hm.group(1) != idx or int(hm.group(2)) != _n:
            continue
        span = _for_body_span(blob, hm.end())
        if span is None:
            continue
        a, b = span
        new_body = re.sub(
            rf"\b{re.escape(home)}\b", f"{arr}[{idx}]", blob[a:b]
        )
        blob = blob[:a] + new_body + blob[b:]
        blob = re.sub(
            rf"^[ \t]*(?:unsigned\s+)?(?:int|uint|undefined4|uint32_t)\s+"
            rf"{re.escape(home)}\s*;[ \t]*\r?\n?",
            "",
            blob,
            count=1,
            flags=re.M,
        )
        return blob
    return blob


def _rewrite_local_array_imm_stores(code: str, func_bytes: bytes | bytearray) -> str:
    """Fill `T xs[N];` from consecutive RBP dword immediates Ghidra DSE dropped.

    Machine stores are dump-faithful. Sample source is not consulted.
    Unique matching array only.
    """
    blob = code or ""
    if not func_bytes:
        return blob
    from src.analysis.pe_image import consecutive_i32_runs, rbp_imm32_stores

    runs = consecutive_i32_runs(rbp_imm32_stores(bytes(func_bytes)))
    if not runs:
        return blob
    decls = list(_RE_INT_ARRAY_DECL.finditer(blob))
    if not decls:
        return blob
    for run in runs:
        n = len(run)
        hits = [d for d in decls if int(d.group(4)) == n and "=" not in d.group(0)]
        if len(hits) != 1:
            continue
        d = hits[0]
        vals = ", ".join(str(v) for v in run)
        indent, ty, name = d.group(1), d.group(2), d.group(3)
        new_decl = f"{indent}{ty} {name}[{n}] = {{{vals}}};"
        blob = blob[: d.start()] + new_decl + blob[d.end() :]
        decls = list(_RE_INT_ARRAY_DECL.finditer(blob))
    return blob


def sanitize_ghidra_cpp(
    code: str, *, func_bytes: bytes | bytearray | None = None
) -> str:
    """Rewrite Ghidra type spellings and member-call syntax into parseable C++."""
    t = (code or "").replace("\r\n", "\n").replace("\r", "\n")
    # Even if an earlier quote makes _outside_strings skip a chunk.
    t = t.replace("structstd::", "std::")

    def _types(chunk: str) -> str:
        # Ghidra: pair<const_std::basic_string,…>. Strip _std:: only after
        # splitting const from std, or it becomes the token conststd.
        chunk = apply_lexical(chunk, "before_underscore_std")
        chunk = chunk.replace("_std::", "std::")
        chunk = chunk.replace("::__cxx11::", "::")
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
    t = _outside_strings(t, _strip_empty_allocator_dtors)
    t = _rewrite_msx64_incoming(t)
    t = _rewrite_msx64_concat_stack_ptr(t)
    t = _rewrite_msx64_stack_homes(t)
    t = _rewrite_msx64_extraout(t)
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
    t = _outside_strings(t, _rewrite_stack_overlay)
    t = _outside_strings(t, _rewrite_in_stack_temps)
    t = _outside_strings(t, _strip_compiler_instrumentation)
    t = _rewrite_msx64_concat_stack_ptr(t)
    t = _outside_strings(t, _rewrite_ghidra_piece_ops)
    t = _rewrite_msx64_concat_stack_ptr(t)
    t = _outside_strings(t, _rewrite_ghidra_func_ops)
    t = _outside_strings(t, _rewrite_bool_xor)
    t = _rewrite_ghidra_this_local(t)
    t = _outside_strings(t, _elide_default_allocator_args)
    t = _rewrite_local_array_elem_inits(t)
    t = _rewrite_local_array_loop_index(t)
    t = _rewrite_local_array_imm_stores(t, func_bytes or b"")
    t = _outside_strings(t, lambda chunk: re.sub(r"\n[ \t]*\n+", "\n", chunk))
    return t
