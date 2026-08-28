from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from src.llm.client import OllamaClient, extract_json

logger = logging.getLogger("revllm.polisher")

SYSTEM_PROMPT = (
    "Ты финальный полировщик восстановленного C++ (декомпил Ghidra). "
    "Переписывай код в читаемый C++17, НЕ меняя семантику и НЕ выдумывая логику. "
    "Отвечай ТОЛЬКО JSON."
)

USER_PROMPT = """Черновой код функции:
{code}

ПРАВИЛА:
1. Убери артефакты Ghidra (CONCAT*, undefined*, extraout_*, goto LAB_*, uVar/pbVar) — введи осмысленные имена.
2. Если видишь this/смещения — опиши struct по наблюдаемым полям; не выдумывай поля без свидетельств в коде.
3. Сохрани ВСЕ литералы и константы точно; не выдумывай логику.
4. Свободные функции (find/main-подобные) оформляй как свободные.
Ответь JSON: {{"cpp_code": "..."}}
"""


class CodePolisher:
    def __init__(self, client: OllamaClient):
        self.client = client

    def polish(self, code: str) -> Optional[Dict[str, Any]]:
        snippet = (code or "")[:7000]
        prompt = USER_PROMPT.format(code=snippet)
        raw = self.client.generate(prompt, system=SYSTEM_PROMPT)
        return extract_json(raw)
