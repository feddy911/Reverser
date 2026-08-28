from __future__ import annotations
import json
import logging
import re
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger("revllm.llm")


class LLMError(RuntimeError):
    pass


class OllamaClient:
    """Минимальный HTTP-клиент Ollama (без новых зависимостей)."""

    def __init__(
            self,
            base_url: str,
            model: str,
            timeout_sec: int = 300,
            num_ctx: int = 8192,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_sec = timeout_sec
        self.num_ctx = num_ctx

    def generate(self, prompt: str, system: str = "") -> str:
        url = self.base_url + "/api/generate"
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": self.num_ctx,
            },
        }
        if system:
            payload["system"] = system
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc
        try:
            out = json.loads(body)
        except Exception as exc:
            raise LLMError(f"Cannot parse Ollama response: {exc}") from exc
        text = out.get("response", "")
        if not text:
            raise LLMError("Ollama returned empty response")
        return text


def _sanitize_control_chars(s: str) -> str:
    """Экранирует сырые \n \r \t внутри строковых значений JSON."""
    out = []
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            if esc:
                out.append(ch);
                esc = False;
                continue
            if ch == "\\":
                out.append(ch);
                esc = True;
                continue
            if ch == '"':
                in_str = False;
                out.append(ch);
                continue
            if ch == "\n": out.append("\\n"); continue
            if ch == "\r": out.append("\\r"); continue
            if ch == "\t": out.append("\\t"); continue
            out.append(ch)
        else:
            if ch == '"':
                in_str = True
            out.append(ch)
    return "".join(out)


def _fix_invalid_escapes(s: str) -> str:
    """Исправляет невалидные escape-последовательности в JSON."""
    # Валидные escape в JSON: \" \\ \/ \b \f \n \r \t \uXXXX
    # Заменяем \0, \x, \a и т.д. на \\0, \\x, \\a
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            next_ch = s[i + 1]
            if next_ch in '"\\/\bfnrt':
                result.append(s[i:i + 2])
                i += 2
            elif next_ch == 'u' and i + 5 < len(s):
                # \uXXXX
                result.append(s[i:i + 6])
                i += 6
            else:
                # Невалидный escape — экранируем обратный слэш
                result.append('\\\\')
                result.append(next_ch)
                i += 2
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Достает JSON-объект из ответа LLM (возможно, в ```-скобках)."""
    text = text.strip()

    # Попытка 1: markdown code block с JSON (GREEDY поиск!)
    fence = re.search(r"```(?:json)?\s*({.*})\s*```", text, re.DOTALL)
    if fence:
        candidate = fence.group(1)
        try:
            return json.loads(candidate)
        except Exception:
            pass
        try:
            return json.loads(_sanitize_control_chars(candidate))
        except Exception:
            pass
        # Попытка 1.3: исправить невалидные escape-последовательности
        try:
            fixed = _fix_invalid_escapes(candidate)
            return json.loads(fixed)
        except Exception:
            pass
        # Попытка 1.4: sanitize + fix escapes
        try:
            fixed = _fix_invalid_escapes(_sanitize_control_chars(candidate))
            return json.loads(fixed)
        except Exception:
            pass

    # Попытка 2: найти первый { и последний } (без markdown)
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start:end + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass
        try:
            return json.loads(_sanitize_control_chars(candidate))
        except Exception:
            pass
        # Попытка 2.3: исправить trailing commas
        try:
            fixed = re.sub(r",\s*}", "}", candidate)
            fixed = re.sub(r",\s*]", "]", fixed)
            return json.loads(fixed)
        except Exception:
            pass
        # Попытка 2.4: исправить невалидные escape-последовательности
        try:
            fixed = _fix_invalid_escapes(candidate)
            return json.loads(fixed)
        except Exception:
            pass
        # Попытка 2.5: sanitize + fix escapes + trailing commas
        try:
            fixed = _fix_invalid_escapes(_sanitize_control_chars(candidate))
            fixed = re.sub(r",\s*}", "}", fixed)
            fixed = re.sub(r",\s*]", "]", fixed)
            return json.loads(fixed)
        except Exception:
            pass

    # Попытка 3: Fallback — извлечь C++ код из markdown-блока
    cpp_fence = re.search(r"```(?:cpp|c|c\+\+)?\s*\n([\s\S]*?)\n```", text)
    if cpp_fence:
        code = cpp_fence.group(1).strip()
        if code and len(code) > 20:
            return {
                "classification": "user_code",
                "guessed_name": None,
                "purpose": "extracted from raw response",
                "evidence": [],
                "cpp_code": code,
                "includes": [],
                "confidence": 60,
            }

    # Попытка 4: Fallback — извлечь C++ код из текста (если есть ключевые слова)
    if any(kw in text for kw in ["#include", "return ", "void ", "int ", "std::", "mpz_"]):
        # Найти первое { и последнее }
        start = text.find("{")
        if start != -1:
            brace_level = 0
            code_end = len(text)
            for i, ch in enumerate(text[start:], start):
                if ch == "{":
                    brace_level += 1
                elif ch == "}":
                    brace_level -= 1
                    if brace_level == 0:
                        code_end = i + 1
                        break
            code = text[start:code_end].strip()
            if len(code) > 20:
                return {
                    "classification": "user_code",
                    "guessed_name": None,
                    "purpose": "extracted from raw C++ response",
                    "evidence": [],
                    "cpp_code": code,
                    "includes": [],
                    "confidence": 50,
                }

    return None