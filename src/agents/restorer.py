from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from src.analysis.prompts import system_prompt_for, toolchain_rules_for
from src.llm.client import OllamaClient, extract_json

logger = logging.getLogger("revllm.restorer")

USER_PROMPT = """Адрес функции: {address}
Имя: {name}
Имя в Ghidra: {ghidra_name}
Размер: {size} байт
Профиль toolchain: {profile}

=== ВХОДНЫЕ ДАННЫЕ ИЗ GHIDRA (ОБЯЗАТЕЛЬНО СОХРАНИТЬ) ===

Строки, на которые ссылается ЭТА функция (точные литералы):
{func_strings}

Внешние вызовы, найденные в коде ЭТОЙ функции:
{called_imports}

Декомпилированный код (Ghidra):
{ghidra_code}

=== СТРОГИЕ ПРАВИЛА ===

{toolchain_rules}

1. Переводи данный код буквально, блок за блоком. НЕ выдумывай логику, которой нет во входном коде.

2. СОХРАНИ ВСЕ строковые литералы из списка "Строки" выше ПОСИМВОЛЬНО ТОЧНО.
ОСОБОЕ ВНИМАНИЕ к литералам с управляющими символами:
- \\r (carriage return) НЕ заменяй на \\n
- Последовательности одинаковых символов (====, ----, ****) сохраняй ПОЛНОСТЬЮ, не сокращай
- Хвостовые \\n в конце литерала обязательны, не удаляй их
- Пробелы в начале/конце литерала сохраняй
Проверь каждый литерал посимвольно перед ответом.

3. СОХРАНИ ВСЕ внешние вызовы из списка "Внешние вызовы" с теми же именами и аргументами.

4. СОХРАНИ ВСЕ числовые константы точно как во входе.

5. Если в Ghidra-коде есть вызовы по адресам (thunk_FUN_*, FUN_*) — сохрани вызов.
   Не подставляй другое библиотечное имя «по смыслу» и не угадывай имена из исходников.

6. Если это библиотечная функция (STL/CRT/libc), classification = stl/crt, cpp_code может быть пустым.

=== ПРОВЕРКА ПЕРЕД ОТВЕТОМ ===
Перед генерацией JSON проверь:
- Все литералы из списка "Строки" присутствуют в коде?
- Все вызовы из списка "Внешние вызовы" присутствуют?
- Все числовые константы из Ghidra-кода сохранены?

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


def keep_dump_literals(code: str, literals: Sequence[str]) -> str:
    """Re-attach dump-fact string literals the LLM dropped. No new control flow.

    Notes go inside the last function body so extract_named_function / assemble
    keep them. Trailing comments after '}' are stripped.
    """
    from src.analysis.fidelity import _c_escape, literal_in_code

    missing = [l for l in (literals or []) if l and not literal_in_code(l, code)]
    if not missing:
        return code or ""
    notes = "\n".join(f'// dump-fact: "{_c_escape(l)}"' for l in missing)
    body = (code or "").rstrip()
    if not body:
        return notes + "\n"
    if body.endswith("}"):
        return body[:-1].rstrip() + "\n  " + notes.replace("\n", "\n  ") + "\n}\n"
    return body + "\n" + notes + "\n"


_RE_RAW_NL_CHAR = re.compile(r"'(?:\r\n|\n|\r)'?")
_RE_GLUED_VOID0 = re.compile(r"\}[ \t]*\(void\)0;")


def repair_restore_debris(code: str) -> str:
    """Lexical LLM debris: raw newline in a char literal, `(void)0` glued to `}`,
    and markdown backticks. No new control flow. Not a Ghidra-dialect recipe.
    """
    t = code or ""
    t = _RE_RAW_NL_CHAR.sub(r"'\\n'", t)
    t = _RE_GLUED_VOID0.sub("(void)0; }", t)
    t = t.replace("`", "")
    return t


def _norm(code: str) -> str:
    return re.sub(r"\s+", "", code or "")


class CodeRestorerLLM:
    def __init__(
        self,
        client: OllamaClient,
        dump_dir: Optional[Path] = None,
        profile: str = "generic",
    ):
        self.client = client
        self.seen: Set[str] = set()
        self.profile = profile or "generic"
        self.system_prompt = system_prompt_for(self.profile)
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
            profile=self.profile,
            func_strings="\n".join(f'- "{s}"' for s in func_strings[:10]) or "(нет)",
            called_imports=", ".join(called[:20]) or "(нет)",
            ghidra_code=(ghidra_code or "")[:6000],
            toolchain_rules=toolchain_rules_for(self.profile),
        )
        raw = self.client.generate(prompt, system=self.system_prompt)
        self._dump(entry.get("address", ""), prompt, raw)
        parsed = extract_json(raw)
        if not parsed:
            logger.warning("LLM JSON parse failed for %s -> retry", entry.get("address"))
            raw = self.client.generate(
                prompt + "\n\nВАЖНО: предыдущий ответ не был валидным JSON. "
                         "Верни СТРОГО один валидный JSON-объект, без пояснений и markdown.",
                system=self.system_prompt,
            )
            self._dump(entry.get("address", ""), prompt, raw)
            parsed = extract_json(raw)
        if not parsed:
            return None
        code = parsed.get("cpp_code") or ""
        if parsed.get("classification") == "user_code" and _norm(code) in self.seen:
            logger.info("Duplicate restoration for %s -> re-prompt", entry.get("address"))
            raw2 = self.client.generate(prompt + DUP_NOTE, system=self.system_prompt)
            parsed2 = extract_json(raw2)
            if parsed2 and _norm(parsed2.get("cpp_code") or "") not in self.seen:
                parsed = parsed2
        if parsed.get("classification") == "user_code":
            self.seen.add(_norm(parsed.get("cpp_code") or ""))
        return parsed

    def restore_with_refinement(
        self,
        entry: Dict[str, Any],
        ghidra_code: str,
        max_attempts: int = 2,
        guess_by_addr: Optional[Dict[str, str]] = None,
        thunk_target: Optional[Dict[str, str]] = None,
        best_of: int = 1,
    ) -> Optional[Dict[str, Any]]:
        """Восстановление с итеративным улучшением на основе fidelity check."""
        from src.analysis.fidelity import build_call_tokens, check_function

        data = self.restore(entry, ghidra_code)
        if not data:
            return None

        call_tokens = build_call_tokens(
            entry.get("callees") or [],
            name_by_addr=guess_by_addr,
            thunk_target=thunk_target,
        )
        fidelity = check_function(entry, data.get("cpp_code", ""), call_tokens)

        if fidelity["fidelity"] >= 0.85:
            return data

        logger.info(
            "Initial fidelity for %s: %.3f",
            entry.get("address"), fidelity["fidelity"],
        )

        attempt = 1
        while fidelity["fidelity"] < 0.85 and attempt < max_attempts:
            from src.analysis.platform import is_noise_call

            feedback_parts = []
            if fidelity["missing_literals"]:
                feedback_parts.append(
                    f"Пропущены строковые литералы из Ghidra: {fidelity['missing_literals']}"
                )
            if fidelity["missing_ext"]:
                feedback_parts.append(
                    f"Пропущены внешние вызовы: {fidelity['missing_ext']}"
                )
            missing_calls_filtered = [
                c for c in fidelity["missing_calls"]
                if not is_noise_call(c)
            ]
            if missing_calls_filtered:
                feedback_parts.append(
                    f"Пропущены вызовы функций: {missing_calls_filtered}"
                )
            if fidelity["missing_consts"]:
                feedback_parts.append(
                    f"Пропущены числовые константы: {fidelity['missing_consts'][:5]}"
                )
            if not feedback_parts:
                break

            refinement_prompt = (
                f"Твой предыдущий код для функции {entry.get('address')} "
                f"пропустил элементы, которые ЕСТЬ в Ghidra-дампе:\n\n"
                + "\n".join(feedback_parts)
                + "\n\nИсправь код, добавив ВСЕ пропущенные элементы.\n"
                "НЕ выдумывай ничего нового — только добавь то, что показано выше.\n"
                "Сохрани всю остальную логику без изменений.\n\n"
                'Ответь ТОЛЬКО JSON: {"cpp_code": "исправленный C++ код"}'
            )

            raw = self.client.generate(refinement_prompt, system=self.system_prompt)
            self._dump(
                (entry.get("address") or "") + f"_refine_{attempt}",
                refinement_prompt,
                raw,
            )
            parsed = extract_json(raw)
            if not parsed:
                break
            new_code = parsed.get("cpp_code", "")
            if not new_code:
                break

            new_fidelity = check_function(entry, new_code, call_tokens)
            if new_fidelity["fidelity"] > fidelity["fidelity"]:
                data["cpp_code"] = new_code
                fidelity = new_fidelity
                logger.info(
                    "Refinement attempt %d: fidelity %.3f",
                    attempt, fidelity["fidelity"],
                )
            else:
                logger.info(
                    "Refinement attempt %d: no improvement (%.3f <= %.3f)",
                    attempt, new_fidelity["fidelity"], fidelity["fidelity"],
                )
                break
            attempt += 1

        n_extra = max(1, int(best_of)) - 1
        while n_extra > 0 and fidelity["fidelity"] < 0.85:
            n_extra -= 1
            alt = self.restore(entry, ghidra_code)
            if not alt:
                continue
            alt_fid = check_function(entry, alt.get("cpp_code", ""), call_tokens)
            if alt_fid["fidelity"] > fidelity["fidelity"]:
                data = alt
                fidelity = alt_fid
                logger.info(
                    "best-of: fidelity %.3f for %s",
                    fidelity["fidelity"], entry.get("address"),
                )

        return data

    def fix_compile(
        self,
        source: str,
        errors: List[Dict[str, str]],
        compiler: str = "",
    ) -> Optional[str]:
        """One-shot LLM pass: keep semantics, fix compiler diagnostics."""
        from src.analysis.compile_verify import extract_cpp, format_errors_for_prompt

        src = (source or "").strip()
        if not src:
            return None
        if len(src) > 80_000:
            src = src[:80_000] + "\n// ... truncated ...\n"
        prompt = (
            "Ниже C++ (восстановленный из бинарника) и ошибки компилятора.\n"
            "Исправь ТОЛЬКО то, что мешает компиляции: типы, скобки, лишние "
            "идентификаторы Ghidra, отсутствующие include.\n"
            "НЕ повторяй using/typedef, которые уже есть в начале файла.\n"
            "НЕ объявляй заново DAT_* и thunk_FUN_* — они уже в начале файла.\n"
            "НЕ выдумывай структуры, typedef и using, которых нет во входном исходнике.\n"
            "Не пиши `using long ...` — это невалидный C++.\n"
            "Если во входе уже есть struct — оставь одно объявление до функций.\n"
            "НЕ меняй литералы, константы и смысл алгоритма.\n"
            "НЕ добавляй новую логику. Верни ПОЛНЫЙ исправленный файл.\n\n"
            f"Компилятор: {compiler or 'c++'}\n"
            f"Ошибки:\n{format_errors_for_prompt(errors)}\n\n"
            "Исходник:\n```cpp\n"
            f"{src}\n"
            "```\n\n"
            "Ответь ТОЛЬКО C++ кодом (можно в ```cpp блоке)."
        )
        raw = self.client.generate(prompt, system=self.system_prompt)
        self._dump("compilefix", prompt, raw)
        parsed = extract_json(raw)
        if parsed and (parsed.get("cpp_code") or "").strip():
            return str(parsed["cpp_code"]).strip()
        fixed = extract_cpp(raw)
        return fixed if fixed and fixed != src else None

    # _build_call_tokens удалён: используйте src.analysis.fidelity.build_call_tokens
