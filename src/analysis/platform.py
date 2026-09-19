from __future__ import annotations

import re

# Системные DLL Windows/MSVC: всё, что НЕ попало сюда, считаем "доменной" библиотекой
SYSTEM_DLL_RE = re.compile(
    r"^(kernel32|kernelbase|ntdll|user32|advapi32|ucrtbase|ucrtbased|"
    r"vcruntime\w*|msvcp\w*|msvcm\w*|concrt\w*|api-ms-win-.*|ws2_32|"
    r"shell32|ole32|oleaut32|comctl32|gdi32|dbghelp|psapi|bcrypt|crypt32)$",
    re.IGNORECASE,
)

_DLL_SUFFIX_RE = re.compile(r"\.(dll|exe|so|dylib)$", re.IGNORECASE)

def norm_dll(name: str) -> str:
    return _DLL_SUFFIX_RE.sub("", (name or "").strip().lower())

SYSTEM_DLL_PREFIXES = (
    "kernel32", "kernelbase", "ntdll", "user32", "advapi32", "ucrtbase",
    "vcruntime", "msvcp", "msvcm", "msvcrt", "concrt", "api-ms-win", "ws2_32",
    "shell32", "ole32", "oleaut32", "comctl32", "gdi32", "dbghelp",
    "psapi", "bcrypt", "crypt32",
)

def is_system_dll(name: str) -> bool:
    return bool(name) and norm_dll(name).startswith(SYSTEM_DLL_PREFIXES)

# C stdio — имена платформы (тулчейн), не цели
STDIO_NAMES = {
    "printf", "puts", "putchar", "scanf", "fprintf", "sprintf",
    "vprintf", "vfprintf", "vsprintf",
    "__stdio_common_vfprintf", "__stdio_common_vsprintf_s",
    "__acrt_iob_func",
}

# CRT-диагностика/рантайм — имена платформы
CRT_NAMES = {
    "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
    "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress",
    "VirtualAlloc", "VirtualFree", "HeapAlloc", "HeapFree",
    "TlsAlloc", "TlsFree", "Sleep", "TerminateProcess",
    "_CrtDbgReport", "_CrtDbgReportW",
    "_invalid_parameter", "_invalid_parameter_noinfo",
}

# Compiler/runtime instrumentation — не требуем в восстановленном user-коде
_NOISE_CALL_EXACT = {
    "__CheckForDebuggerJustMyCode",
    "__security_check_cookie",
    "__security_init_cookie",
    "__GSHandlerCheck",
    "__GSHandlerCheck_SEH",
    "__report_rangecheckfailure",
    "_RTC_CheckStackVars",
    "_RTC_CheckStackVars2",
    "_RTC_InitBase",
    "_RTC_Shutdown",
    "DebuggerProbe",
    "DebuggerRuntime",
    "__main",
    "__mingw_printf",
}
_NOISE_CALL_PREFIXES = (
    "__CheckForDebugger",
    "_RTC_",
    "__GSHandler",
    "__security_",
    "__vcrt_",
    "__scrt_",
    "operator",
    "basic_string",
    "~",
    "__mingw",
)

# Константы-заполнители Debug-хипов/стека (не семантика программы)
NOISE_CONSTANTS = {
    "0xcccccccc", "0xcdcdcdcd", "0xdddddddd", "0xfeeefeee",
    "0xabababab", "0xbadcafe", "0xdeadbeef",
}


def is_noise_call(name: str) -> bool:
    """True для debug/CRT instrumentation, которую restorer должен выкидывать."""
    n = (name or "").strip()
    if not n:
        return False
    if n in _NOISE_CALL_EXACT or n in CRT_NAMES:
        return True
    return n.startswith(_NOISE_CALL_PREFIXES)


def is_noise_constant(tok: str) -> bool:
    return (tok or "").lower() in NOISE_CONSTANTS


# Имена, которые не стоит кормить LLM: CRT/startup, libstdc++ internals, MinGW printf.
_RUNTIME_NOISE_PREFIXES = (
    "_M_", "_S_",
    "__mingw", "__pformat", "__gnu", "__gdtoa", "__diff_", "__tmain",
    "__cxa_", "__gxx_", "__acrt", "__scrt", "__vcrt",
    "__GSHandler", "__security_", "__CheckFor",
    "_RTC_", "_pei386",
    "_FindPE", "_GetPE", "___chkstk", "_chkstk", "_Alloc_hider",
    "__getmainargs", "_amsg_", "__relocate", "_Guard_alloc",
    "dtoa_", "uninitialized_",
    "std::", "thunk_", "~",
)
_RUNTIME_NOISE_EXACT = {
    "_matherr", "mark_section_writable",     "DllMainCRTStartup",
    "WinMainCRTStartup",
    "mainCRTStartup", "__report_error", "register_frame_info",
    "basic_string", "basic_string<>", "operator=", "operator<<",
    "operator_delete", "operator new", "operator new[]",
    "__main", "fprintf", "vfprintf", "printf", "sprintf",
    "memcpy", "memset", "malloc", "free", "exit", "abort",
    "cpp_unhandled_exception_filter",
    # demangled one-word STL/container methods (not user restore names)
    "compare", "back", "front", "end", "begin", "size", "empty",
    "clear", "data", "c_str", "reserve", "resize", "push_back",
    "pop_back", "insert", "erase", "swap", "assign", "append", "allocate",
    "deallocate", "max_size", "length", "capacity", "move",
    "vector", "string", "copy", "release", "pointer_to",
    "dtoa_lock", "dtoa_lock_cleanup",
    "substr", "find", "hash", "unordered_map", "map", "set", "list",
    "count", "key_comp", "value_comp", "lower_bound", "upper_bound",
    "equal_range", "tuple", "get", "forward",
}
def is_runtime_noise(name: str) -> bool:
    """True для CRT/STL/MinGW internals — не целевой user-код для restore."""
    n = (name or "").strip()
    if not n:
        return False
    if n in _RUNTIME_NOISE_EXACT:
        return True
    # MinGW/PE helpers and unnamed CRT: _GetPEImageBase, ___chkstk_ms, …
    if n.startswith("_"):
        return True
    if n.startswith("operator"):
        return True
    if n.startswith(_RUNTIME_NOISE_PREFIXES):
        return True
    if "<" in n:
        return True
    return False


def looks_like_user_restore_name(name: str) -> bool:
    """True if a demangled name is likely user code, not a one-word STL method."""
    n = (name or "").strip()
    if not n or is_runtime_noise(n):
        return False
    base = n.split("<", 1)[0]
    if base == "main" or base.startswith("FUN_"):
        return True
    return "_" in base


def _norm_fn_addr(addr: object) -> str:
    a = str(addr or "").strip().lower()
    if not a:
        return ""
    try:
        if a.startswith("0x"):
            return "0x" + format(int(a, 16), "x")
        return "0x" + format(int(a, 16), "x")
    except ValueError:
        return a


_CRT_ENTRY_NAMES = frozenset({
    "mainCRTStartup",
    "__tmainCRTStartup",
    "WinMainCRTStartup",
    "wWinMainCRTStartup",
    "__scrt_common_main",
    "__scrt_common_main_seh",
})


def crt_user_entry_addrs(functions: object) -> list[str]:
    """User FUN_ addresses reached from named CRT startup. Empty if no CRT.

    Walks dump callees through runtime-noise / CRT names. First non-thunk
    FUN_/user-shaped callee is the entry the restored set must keep. Not a
    sample identifier: the dump already named the CRT stub.
    """
    by_addr: dict[str, dict] = {}
    starts: list[dict] = []
    for f in functions or []:
        if not isinstance(f, dict):
            continue
        addr = _norm_fn_addr(f.get("address"))
        if addr:
            by_addr[addr] = f
        name = str(f.get("name") or "").strip()
        if name in _CRT_ENTRY_NAMES:
            starts.append(f)
    if not starts:
        return []
    found: list[str] = []
    seen: set[str] = set()
    queue = list(starts)
    while queue:
        cur = queue.pop(0)
        for raw in cur.get("callees") or []:
            addr = _norm_fn_addr(raw)
            if not addr or addr in seen:
                continue
            seen.add(addr)
            child = by_addr.get(addr)
            if not child:
                continue
            cname = str(child.get("name") or "").strip()
            if cname in _CRT_ENTRY_NAMES or is_runtime_noise(cname):
                queue.append(child)
                continue
            if cname.startswith("thunk_"):
                continue
            if child.get("lib_matched") in (True, 1, "true"):
                continue
            if looks_like_user_restore_name(cname) or cname.startswith("FUN_"):
                if addr not in found:
                    found.append(addr)
                continue
            queue.append(child)
    return found


def leftover_crt_user_entry(
    functions: object,
    restored_addrs: object,
) -> list[str]:
    """CRT reached a user FUN_ and none of those addresses were restored."""
    want = crt_user_entry_addrs(functions)
    if not want:
        return []
    have = {_norm_fn_addr(a) for a in (restored_addrs or [])}
    have.discard("")
    if any(a in have for a in want):
        return []
    return want


# Ghidra / IAT external → a C++ call ident. Empty = still anonymous FUN_/thunk.
_RE_FOLD_OPERATOR = re.compile(
    r"operator\s*(?:<<|>>|\+\+|--|->\*?|\(\)|\[\]|==|!=|<=|>=|[+\-*/%^&|~!=<>])"
)
_RE_FOLD_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def fold_library_ident(name: str) -> str:
    """Named import/STL/CRT spelling from a dump symbol. Not a sample name.

    FUN_/thunk_FUN_/DAT_ stay empty: those are addresses, not a library
    dictionary hit. Demangled ``std::basic_ostream<...>::operator<<``
    folds to ``operator<<``. Bare IAT names (printf, __gmpz_init) pass.
    """
    n = (name or "").strip()
    if not n or n.startswith(("FUN_", "thunk_FUN_", "DAT_", "LAB_")):
        return ""
    op = _RE_FOLD_OPERATOR.search(n)
    if op:
        return re.sub(r"\s+", "", op.group(0))
    if "::" in n:
        n = n.rsplit("::", 1)[-1].strip()
    if "<" in n:
        n = n.split("<", 1)[0].strip()
    if _RE_FOLD_IDENT.fullmatch(n):
        return n
    return ""


def _prototype_span(code: str) -> str:
    s = (code or "").replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.DOTALL)
    s = re.sub(r"//.*?$", " ", s, flags=re.MULTILINE)
    i = s.find("{")
    return " ".join((s[:i] if i >= 0 else s).split())


def _split_proto_params(inner: str) -> list[str]:
    args: list[str] = []
    depth_p = depth_a = 0
    start = 0
    blob = inner or ""
    for i, c in enumerate(blob):
        if c == "(":
            depth_p += 1
        elif c == ")":
            depth_p -= 1
        elif c == "<":
            depth_a += 1
        elif c == ">":
            depth_a -= 1
        elif c == "," and depth_p == 0 and depth_a == 0:
            args.append(blob[start:i].strip())
            start = i + 1
    tail = blob[start:].strip()
    if tail:
        args.append(tail)
    return args


def _proto_param_types(proto: str) -> list[str]:
    blob = proto or ""
    start = blob.rfind("(")
    if start < 0:
        return []
    depth = 0
    close = -1
    for i in range(start, len(blob)):
        if blob[i] == "(":
            depth += 1
        elif blob[i] == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
    if close < 0:
        return []
    return _split_proto_params(blob[start + 1:close])


def _is_ostream_ptr_type(typ: str) -> bool:
    t = re.sub(r"\s+", "", typ or "").lower()
    if "*" not in t:
        return False
    if "streambuf" in t:
        return False
    return "basic_ostream" in t or bool(
        re.search(r"(?<![a-z])w?ostream(?![a-z_])", t)
    )


def fold_ident_from_dump_fn(fn: dict) -> str:
    """In-image dump function → ISO/CRT call ident, or '' if still anonymous.

    Ghidra prints ``thunk_FUN_<addr>(`` even when ``<addr>`` is a static
    STL inserter / CRT printf in the PE, not an IAT thunk. Named symbols
    and two-arg ``ostream*`` prototypes fold; extra-arity ostream helpers
    stay unmapped (no invented ISO name).
    """
    ident = fold_library_ident(str((fn or {}).get("name") or ""))
    if ident:
        return ident
    proto = _prototype_span(str((fn or {}).get("ghidra_code") or ""))
    params = _proto_param_types(proto)
    if len(params) == 2 and _is_ostream_ptr_type(params[0]):
        return "operator<<"
    ext = [(e or "").replace(" ", "") for e in ((fn or {}).get("ext_calls") or [])]
    for e in ext:
        if e in {"printf", "fprintf", "sprintf", "puts", "putchar"}:
            return e
        if e in STDIO_NAMES and not e.startswith("__"):
            return e
    if any(e == "__acrt_iob_func" or e.startswith("__stdio_common") for e in ext):
        return "printf"
    if len(params) == 1 and _is_ostream_ptr_type(params[0]):
        low = {e.lower() for e in ext}
        if "flush" in low:
            return "std::flush"
        if "endl" in low:
            return "std::endl"
    return ""

# Универсальные детекторы строк (без привязки к MSVC-путям)
PATH_RE = re.compile(
    r"(^[A-Za-z]:[\\/]|^/|\\include\\|/usr/|/opt/|Program Files|"
    r"\.(cpp|c|h|hpp|cc|cxx|inl|pdb|dll|so|exe)$)",
    re.IGNORECASE,
)
RTTI_RE = re.compile(r"^\.?\?AV|^\.?\?AU|^\.?\?\$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PUNCT_RE = re.compile(r"[\s%.,:;!?=+\-*/\\()\[\]<>{}]")

def is_user_literal(s: str) -> bool:
    """Строка, похожая на пользовательский литерал (не путь/RTTI/идентификатор)."""
    if not s or len(s) < 4 or len(s) > 200:
        return False
    if PATH_RE.search(s):
        return False
    if RTTI_RE.match(s):
        return False
    if IDENT_RE.match(s):
        return False
    return bool(PUNCT_RE.search(s)) or s[:1].isdigit()