from __future__ import annotations

from typing import Dict, Tuple

# (system_prompt_suffix describing toolchain, extra user rules)
PromptProfile = Tuple[str, str]

_COMMON_RULES = (
    "Переводи код буквально, блок за блоком. НЕ выдумывай логику. "
    "Сохрани ВСЕ литералы, внешние вызовы и числовые константы точно. "
    "goto замени на if/while/for без смены семантики. "
    "Если первый аргумент — this/указатель на объект, опиши struct по смещениям."
)

PROFILES: Dict[str, PromptProfile] = {
    "msvc_x64_debug": (
        "MSVC x64 Debug (возможны _security_check_cookie, RTC*, thunk*, 0xcccccccc).",
        "Убирай RTC/JustMyCode шум, сохраняя пользовательскую логику. " + _COMMON_RULES,
    ),
    "msvc_x86_debug": (
        "MSVC x86 Debug (RTC*, stack cookies, thiscall).",
        "Учитывай thiscall (this в ECX). " + _COMMON_RULES,
    ),
    "msvc_x64_release": (
        "MSVC x64 Release (оптимизации, inlining, меньше символов).",
        "Ожидай оптимизированный код: схлопнутые ветки, register reuse. "
        "Не восстанавливай удалённые debug-проверки. " + _COMMON_RULES,
    ),
    "msvc_x86_release": (
        "MSVC x86 Release.",
        "Ожидай оптимизированный x86 MSVC код. " + _COMMON_RULES,
    ),
    "msvc_generic": (
        "MSVC PE binary (архитектура/конфиг уточнены слабо).",
        _COMMON_RULES,
    ),
    "gcc_elf_x64": (
        "GCC ELF x86-64 (System V ABI, DWARF/libstdc++ возможны).",
        "Имена могут быть Itanium-mangled. " + _COMMON_RULES,
    ),
    "gcc_elf_x86": (
        "GCC ELF x86.",
        _COMMON_RULES,
    ),
    "gcc_elf_generic": (
        "GCC ELF binary.",
        _COMMON_RULES,
    ),
    "gcc_pe_x64": (
        "GCC/MinGW PE x64 (DWARF/libstdc++ возможны, не MSVC CRT).",
        "Не ожидай MSVC RTC/JustMyCode. Имена могут быть mangled. " + _COMMON_RULES,
    ),
    "gcc_pe_x86": (
        "GCC/MinGW PE x86.",
        "Не ожидай MSVC RTC/JustMyCode. " + _COMMON_RULES,
    ),
    "gcc_pe_generic": (
        "GCC/MinGW PE binary.",
        "Не ожидай MSVC Debug артефакты. " + _COMMON_RULES,
    ),
    "clang_pe_x64": (
        "Clang PE x64.",
        _COMMON_RULES,
    ),
    "clang_pe_generic": (
        "Clang PE binary.",
        _COMMON_RULES,
    ),
    "pe_generic": (
        "Windows PE (compiler unknown).",
        "Не предполагай MSVC Debug артефакты, если их нет во входе. " + _COMMON_RULES,
    ),
    "clang_elf_x64": (
        "Clang ELF x86-64.",
        _COMMON_RULES,
    ),
    "clang_elf_generic": (
        "Clang ELF binary.",
        _COMMON_RULES,
    ),
    "elf_generic": (
        "ELF binary (compiler unknown).",
        _COMMON_RULES,
    ),
    "macho_generic": (
        "Mach-O binary.",
        _COMMON_RULES,
    ),
    "generic": (
        "Unknown toolchain/format (декомпил Ghidra).",
        "Не предполагай MSVC Debug артефакты, если их нет во входе. " + _COMMON_RULES,
    ),
}


def resolve_profile(name: str) -> PromptProfile:
    return PROFILES.get(name) or PROFILES["generic"]


def system_prompt_for(profile_name: str) -> str:
    desc, _ = resolve_profile(profile_name)
    return (
        "Ты эксперт по реверс-инжинирингу. Ты получаешь декомпилированный Ghidra-код "
        f"одной функции из бинарника: {desc} "
        "Твоя задача — буквально перевести его в читаемый C++, не выдумывая логику. "
        "Отвечай ТОЛЬКО JSON.\n\n"
        "КРИТИЧЕСКИ ВАЖНО: Сохрани ВСЕ элементы из входных данных. "
        "Пропуск литералов, вызовов или констант = ошибка."
    )


def toolchain_rules_for(profile_name: str) -> str:
    _, rules = resolve_profile(profile_name)
    return rules
