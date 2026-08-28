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
}
_NOISE_CALL_PREFIXES = (
    "__CheckForDebugger",
    "_RTC_",
    "__GSHandler",
    "__security_",
    "__vcrt_",
    "__scrt_",
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