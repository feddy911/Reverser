from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from src.domains.pack import NONE_PACK, DomainPack
from src.llm.client import OllamaClient, extract_json

logger = logging.getLogger("revllm.polisher")

SYSTEM_PROMPT = (
    "Ты финальный полировщик восстановленного C++ (декомпил Ghidra). "
    "Переписывай код в читаемый C++17, НЕ меняя семантику и НЕ выдумывая логику. "
    "Отвечай ТОЛЬКО JSON."
)

USER_PROMPT_GENERIC = """Черновой код функции:
{code}

ПРАВИЛА:
1. Убери артефакты Ghidra (CONCAT*, undefined*, extraout_*, goto LAB_*, uVar/pbVar) — введи осмысленные имена.
2. Если видишь this/смещения — опиши struct по наблюдаемым полям; не выдумывай поля без свидетельств в коде.
3. Сохрани ВСЕ литералы и константы точно; не выдумывай логику.
4. Свободные функции (find/main-подобные) оформляй как свободные.
Ответь JSON: {{"cpp_code": "..."}}
"""

USER_PROMPT_WITH_HINTS = """Карта полей (первый аргумент-указатель = this):
{offset_map}

Идиомы для замены:
{idiom_map}

Черновой код функции:
{code}

ПРАВИЛА:
1. Смещения -> поля из карты (если карта не пуста).
2. Замени идиомы; убери артефакты Ghidra (CONCAT*, undefined*, extraout_*, goto LAB_*, uVar/pbVar) — введи осмысленные имена.
3. Сохрани ВСЕ литералы и константы точно; не выдумывай логику.
4. Свободные функции (find/main-подобные) оформляй как свободные.
Ответь JSON: {{"cpp_code": "..."}}
"""


class CodePolisher:
    def __init__(self, client: OllamaClient, pack: Optional[DomainPack] = None):
        self.client = client
        self.pack = pack or NONE_PACK

    def polish(self, code: str) -> Optional[Dict[str, Any]]:
        snippet = (code or "")[:7000]
        if self.pack.has_polish_hints:
            prompt = USER_PROMPT_WITH_HINTS.format(
                offset_map=self.pack.offset_map or "(нет карты)",
                idiom_map=self.pack.idiom_map or "(нет идиом)",
                code=snippet,
            )
        else:
            prompt = USER_PROMPT_GENERIC.format(code=snippet)
        raw = self.client.generate(prompt, system=SYSTEM_PROMPT)
        return extract_json(raw)
