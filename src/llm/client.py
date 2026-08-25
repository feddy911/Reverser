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
                out.append(ch); esc = False; continue
            if ch == "\\":
                out.append(ch); esc = True; continue
            if ch == '"':
                in_str = False; out.append(ch); continue
            if ch == "\n": out.append("\\n"); continue
            if ch == "\r": out.append("\\r"); continue
            if ch == "\t": out.append("\\t"); continue
            out.append(ch)
        else:
            if ch == '"':
                in_str = True
            out.append(ch)
    return "".join(out)

def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Достает JSON-объект из ответа LLM (возможно, в ```-скобках)."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        text = text[start:end + 1]
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        return json.loads(_sanitize_control_chars(text))
    except Exception:
        return None