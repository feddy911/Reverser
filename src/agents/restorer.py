from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional, Set
from pathlib import Path

from src.llm.client import OllamaClient, extract_json

logger = logging.getLogger("revllm.restorer")

SYSTEM_PROMPT = (
    "Ты эксперт по реверс-инжинирингу. Ты получаешь декомпилированный Ghidra-код "
    "одной функции из MSVC x64 бинарника (Debug-сборка: возможны "
    "__security_check_cookie, _RTC_*, thunk_*). Твоя задача — буквально перевести "
    "его в читаемый C++, не выдумывая логику. Отвечай ТОЛЬКО JSON."
)

USER_PROMPT = """Адрес функции: {address}
Имя в r2: {name}
Имя в Ghidra: {ghidra_name}
Размер: {size} байт

Строки, на которые ссылается ЭТА функция (точные литералы):
{func_strings}

Внешние вызовы, найденные в коде ЭТОЙ функции:
{called_imports}

Декомпилированный код (Ghidra):
{ghidra_code}

СТРОГИЕ ПРАВИЛА:
1. Переводи данный код буквально, блок за блоком. НЕ выдумывай логику, которой нет во входном коде.
2. Сохрани ВСЕ числовые константы точно как во входе (например 50000, 256, 3, 4, 0xcccccccc).
3. Сохрани ВСЕ внешние вызовы с теми же именами и аргументами (printf, mpz_mul_ui, mpz_get_str, операторы std::cout и т.д.).
4. Если выше указаны строковые литералы — выходной код обязан содержать ровно эти литералы.
5. goto замени на if/while/for, семантика должна остаться идентичной.
6. Если первый аргумент — указатель на структуру (this), опиши struct/класс с полями по наблюдаемым смещениям и используй его.
7. НЕ выдавай учебные или обобщённые реализации — только то, что реально присутствует во входном коде.
8. Если это библиотечная функция (STL/CRT), classification = stl/crt, cpp_code может быть пустым.

Ответь ТОЛЬКО JSON с полями:
{{
  "classification": "user_code|stl|crt|unknown",
  "guessed_name": "..." или null,
  "purpose": "кратко, на русском, что делает функция",
  "evidence": ["конкретные маркеры из входного кода: литералы, константы, вызовы"],
  "cpp_code": "C++ код или пустая строка",
  "includes": ["<cstdio>"],
  "confidence": 0-100
}}"""

DUP_NOTE = (
    "\n\nВАЖНО: твой предыдущий ответ для ДРУГОЙ функции оказался идентичным. "
    "Это ДРУГАЯ функция по другому адресу. Переведи её код буквально и независимо, "
    "не повторяя предыдущие ответы."
)


def _norm(code: str) -> str:
    return re.sub(r"\s+", "", code or "")


class CodeRestorerLLM:
    def __init__(self, client: OllamaClient, dump_dir: Optional[Path] = None):
        self.client = client
        self.seen: Set[str] = set()
        self.dump_dir = Path(dump_dir) if dump_dir else None
        if self.dump_dir:
            self.dump_dir.mkdir(parents=True, exist_ok=True)

    def _dump(self, addr: str, prompt: str, raw: str) -> None:
        if not self.dump_dir:
            return
        safe = (addr or "unknown").replace("0x", "")
        (self.dump_dir / (safe + ".prompt.txt")).write_text(prompt, encoding="utf-8")
        (self.dump_dir / (safe + ".response.txt")).write_text(raw, encoding="utf-8")

    def restore(self, entry: Dict[str, Any], ghidra_code: str) -> Optional[Dict[str, Any]]:
        func_strings = entry.get("string_matches") or entry.get("literals") or []
        called = entry.get("called_imports") or sorted(set(entry.get("ext_calls") or []))

        prompt = USER_PROMPT.format(
            address=entry.get("address"),
            name=entry.get("name"),
            ghidra_name=entry.get("ghidra_name", ""),
            size=entry.get("size"),
            func_strings="\n".join(f'- "{s}"' for s in func_strings[:10]) or "(нет)",
            called_imports=", ".join(called[:20]) or "(нет)",
            ghidra_code=(ghidra_code or "")[:6000],
        )

        raw = self.client.generate(prompt, system=SYSTEM_PROMPT)
        self._dump(entry.get("address", ""), prompt, raw)
        parsed = extract_json(raw)
        if not parsed:
            logger.warning("LLM JSON parse failed for %s -> retry", entry.get("address"))
            raw = self.client.generate(
                prompt + "\n\nВАЖНО: предыдущий ответ не был валидным JSON. "
                         "Верни СТРОГО один валидный JSON-объект, без пояснений и markdown.",
                system=SYSTEM_PROMPT,
            )
            self._dump(entry.get("address", ""), prompt, raw)
            parsed = extract_json(raw)
        if not parsed:
            return None

        code = parsed.get("cpp_code") or ""
        if parsed.get("classification") == "user_code" and _norm(code) in self.seen:
            logger.info("Duplicate restoration for %s -> re-prompt", entry.get("address"))
            raw2 = self.client.generate(prompt + DUP_NOTE, system=SYSTEM_PROMPT)
            parsed2 = extract_json(raw2)
            if parsed2 and _norm(parsed2.get("cpp_code") or "") not in self.seen:
                parsed = parsed2

        if parsed.get("classification") == "user_code":
            self.seen.add(_norm(parsed.get("cpp_code") or ""))
        return parsed