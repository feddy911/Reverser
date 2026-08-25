from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from src.llm.client import OllamaClient, extract_json

logger = logging.getLogger("revllm.polisher")

SYSTEM_PROMPT = (
    "Ты финальный полировщик восстановленного C++ (MSVC x64 Debug, Ghidra). "
    "Переписывай код в читаемый C++17, НЕ меняя семантику и НЕ выдумывая логику. "
    "Отвечай ТОЛЬКО JSON."
)

OFFSET_MAP = (
    "+0x00 -> mpz_t number; +0x10 -> unsigned long long steps; "
    "+0x18 -> std::chrono::time_point startTime; +0x20 -> time_point endTime; "
    "+0x28 -> std::vector<std::string> history; +0x48 -> bool saveHistory; "
    "+0x49 -> bool verbose; +0x50 -> mpz_t milestone"
)

IDIOM_MAP = (
    "(*(int*)(p+4)!=0)&**(uint**)(p+8) -> mpz_odd_p(number); "
    "CONCAT71(x,1) -> true/(bool); thunk_FUN_140021680 -> printf; "
    "thunk_FUN_14001e1b0 -> std::chrono::high_resolution_clock::now(); "
    "thunk_FUN_140014360/thunk_FUN_1400142e0 -> operator<< (cout/cerr); "
    "thunk_FUN_1400170b0 -> std::flush; thunk_FUN_140019050 -> ~std::string(); "
    "thunk_FUN_14001f100 -> history.push_back(...); "
    "thunk_FUN_14001d470 -> history.empty(); thunk_FUN_14001fb30 -> history.size()"
)

USER_PROMPT = """Карта полей (первый аргумент-указатель = this):
{offset_map}

Идиомы для замены:
{idiom_map}

Черновой код функции:
{code}

ПРАВИЛА:
1. Смещения -> поля из карты (this->steps, this->saveHistory и т.д.).
2. Замени идиомы; убери артефакты Ghidra (CONCAT*, undefined*, extraout_*, goto LAB_*, uVar/pbVar) — введи осмысленные имена.
3. Сохрани ВСЕ литералы и константы точно; не выдумывай логику.
4. Свободные функции (find/main-подобные) оформляй как свободные.
Ответь JSON: {{"cpp_code": "..."}}
"""


class CodePolisher:
    def __init__(self, client: OllamaClient):
        self.client = client

    def polish(self, code: str) -> Optional[Dict[str, Any]]:
        prompt = USER_PROMPT.format(
            offset_map=OFFSET_MAP, idiom_map=IDIOM_MAP, code=(code or "")[:7000])
        raw = self.client.generate(prompt, system=SYSTEM_PROMPT)
        return extract_json(raw)