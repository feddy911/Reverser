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
    "compare",
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
    # demangled STL/container methods (EchoFilter leftover in LLM top)
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