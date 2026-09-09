from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

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

PCODE_SECTION_TITLE = "HIGH P-CODE (порядок операций; не копировать как C++)"


def build_restore_prompt(
    entry: Dict[str, Any],
    ghidra_code: str,
    *,
    profile: str = "generic",
    pcode: str = "",
) -> str:
    """p4 user prompt. Optional pcode is mini/p5 only — live restore omits it."""
    from src.analysis.pcode import clip_pcode, op_lines

    func_strings = entry.get("string_matches") or entry.get("literals") or []
    called = entry.get("called_imports") or sorted(set(entry.get("ext_calls") or []))
    prompt = USER_PROMPT.format(
        address=entry.get("address"),
        name=entry.get("name"),
        ghidra_name=entry.get("ghidra_name", ""),
        size=entry.get("size"),
        profile=profile,
        func_strings="\n".join(f'- "{s}"' for s in func_strings[:10]) or "(нет)",
        called_imports=", ".join(called[:20]) or "(нет)",
        ghidra_code=(ghidra_code or "")[:6000],
        toolchain_rules=toolchain_rules_for(profile),
    )
    ops = op_lines(clip_pcode(pcode))
    if not ops:
        return prompt
    block = (
        f"\n=== {PCODE_SECTION_TITLE} ===\n"
        "Используй эти ops только как порядок вычисления. "
        "Не печатай синтаксис p-code как C++. "
        "Имена, типы и строковые литералы бери из блока Ghidra C выше, не из IR.\n"
        + "\n".join(ops[:80])
        + "\n\n"
    )
    marker = "=== СТРОГИЕ ПРАВИЛА ==="
    if marker in prompt:
        return prompt.replace(marker, block + marker, 1)
    return prompt + block


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


def _close_unbalanced_dquotes(text: str) -> str:
    """Close a line with an odd number of unescaped double quotes (LLM debris)."""
    out: List[str] = []
    for line in (text or "").splitlines(keepends=True):
        core = line.rstrip("\r\n")
        n = 0
        i = 0
        while i < len(core):
            if core[i] == "\\":
                i += 2
                continue
            if core[i] == '"':
                n += 1
            i += 1
        if n % 2 == 1:
            out.append(core + '"' + line[len(core):])
        else:
            out.append(line)
    return "".join(out)


def _scan_cpp_state(text: str) -> Tuple[int, bool, bool]:
    """Brace depth and open string/char at EOF. Not a dialect recipe."""
    s = text or ""
    depth = 0
    i = 0
    n = len(s)
    in_str = False
    in_char = False
    in_sl = False
    in_ml = False
    while i < n:
        ch = s[i]
        nxt = s[i + 1] if i + 1 < n else ""
        if in_sl:
            if ch == "\n":
                in_sl = False
            i += 1
            continue
        if in_ml:
            if ch == "*" and nxt == "/":
                in_ml = False
                i += 2
                continue
            i += 1
            continue
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if in_char:
            if ch == "\\":
                i += 2
                continue
            if ch == "'":
                in_char = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_sl = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_ml = True
            i += 2
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "'":
            in_char = True
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
        i += 1
    return depth, in_str, in_char


def _close_unbalanced_braces(text: str) -> str:
    """Close leftover `{` at EOF (truncated LLM body). Do not invent identifiers."""
    s = text or ""
    depth, _in_str, _in_char = _scan_cpp_state(s)
    if depth <= 0:
        return s
    nl = "" if s.endswith("\n") else "\n"
    return s + nl + ("}" * depth) + "\n"


CONTINUE_PROMPT = (
    "The previous restore cpp_code was cut off before a complete function body.\n"
    "Continue ONLY the missing tail of that C++ body.\n"
    "Do not invent identifiers that are not already started in the bytes so far.\n"
    'Return JSON with a single field cpp_code_tail (the remainder only).'
)


_QUAL_IDENT_END = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*::)+[A-Za-z_][A-Za-z0-9_]*\s*$"
)


def ident_cut_head(code: str) -> Optional[str]:
    """If a nested-name ident was cut off, body without trailing brace-close debris.

    After ``_close_unbalanced_braces``, ``std::basic_st\\n}}}}}}`` is still a cut.
    Do not rewrite the ident.
    """
    s = code or ""
    _depth, in_str, in_char = _scan_cpp_state(s)
    if in_str or in_char:
        return None
    core = s.rstrip()
    while core.endswith("}"):
        core = core[:-1].rstrip()
    if not core or not _QUAL_IDENT_END.search(core):
        return None
    return core


def looks_truncated_cpp(code: str) -> bool:
    """True when the restored body was cut off. No ident rewrite."""
    s = code or ""
    if not s.strip():
        return False
    depth, in_str, in_char = _scan_cpp_state(s)
    if depth > 0 or in_str or in_char:
        return True
    return ident_cut_head(s) is not None


def _is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def merge_cpp_continuation(head: str, tail: str) -> str:
    """Append a continue-tail. Glue a cut ident; do not rewrite it."""
    h = head or ""
    t = tail or ""
    if not t.strip():
        return h
    hs = h.strip()
    ts = t.strip()
    prefix = hs[: min(32, len(hs))]
    if prefix and ts.startswith(prefix) and len(ts) >= len(hs):
        return t if t.endswith("\n") else t + "\n"
    left = h.rstrip()
    right = t.lstrip("\n")
    if left and right and _is_ident_char(left[-1]) and _is_ident_char(right[0]):
        out = left + right
    else:
        out = left + "\n" + right
    if not out.endswith("\n"):
        out += "\n"
    return out


def extract_restore_json(text: str) -> Optional[Dict[str, Any]]:
    """Parse restore JSON. Never treat a JSON envelope `{` as C++."""
    from src.llm.client import parse_json_object

    parsed = parse_json_object(text or "")
    if isinstance(parsed, dict) and (
        "cpp_code" in parsed
        or "cpp_code_tail" in parsed
        or parsed.get("classification")
    ):
        return parsed
    code = _json_string_field(text, "cpp_code")
    tail = _json_string_field(text, "cpp_code_tail")
    if code is None and tail is None:
        return None
    rec: Dict[str, Any] = {
        "classification": _json_string_field(text, "classification") or "user_code",
        "purpose": _json_string_field(text, "purpose") or "",
        "evidence": [],
        "includes": [],
        "confidence": 50,
    }
    if code is not None:
        rec["cpp_code"] = code
    if tail is not None:
        rec["cpp_code_tail"] = tail
    name = _json_string_field(text, "guessed_name")
    if name:
        rec["guessed_name"] = name
    return rec


def continue_truncated_cpp(client: Any, code: str, system: str = "") -> str:
    """Ask the model for the cut-off tail. Does not complete ident via regex."""
    raw_head = code or ""
    if not looks_truncated_cpp(raw_head):
        return raw_head
    head = ident_cut_head(raw_head) or raw_head
    prompt = CONTINUE_PROMPT + "\n\n--- cpp_code so far ---\n" + head[-4000:]
    try:
        raw = client.generate(prompt, system=system, json_mode=True)
    except Exception as exc:
        logger.warning("restore continue failed: %s", exc)
        return raw_head
    parsed = extract_restore_json(raw) or {}
    tail = parsed.get("cpp_code_tail")
    if not isinstance(tail, str) or not tail.strip():
        alt = parsed.get("cpp_code")
        tail = alt if isinstance(alt, str) else ""
    return merge_cpp_continuation(head, tail)


_JSON_STR_ESC = {
    "n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
    '"': '"', "\\": "\\", "/": "/",
}
_EMPTY_GUESS = frozenset({"", "-", "null"})


def _json_string_field(text: str, key: str) -> Optional[str]:
    """Read a JSON string field even when the surrounding object is invalid."""
    m = re.search(rf'"{re.escape(key)}"\s*:\s*"', text or "")
    if not m:
        return None
    i = m.end()
    out: List[str] = []
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            if i + 1 >= len(text):
                break
            nxt = text[i + 1]
            if nxt == "u" and i + 5 < len(text):
                hexpart = text[i + 2:i + 6]
                try:
                    out.append(chr(int(hexpart, 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(_JSON_STR_ESC.get(nxt, nxt))
            i += 2
            continue
        if ch == '"':
            return "".join(out)
        out.append(ch)
        i += 1
    return "".join(out) if out else None


def _looks_like_restore_envelope(s: str) -> bool:
    t = (s or "").strip()
    return t.startswith("{") and '"cpp_code"' in t and '"classification"' in t


def _unwrap_restore_json(code: str) -> str:
    """If the LLM stored the whole restore envelope as cpp_code, take the inner C++.

    Gate on restore keys so a C++ compound statement is left alone. Unwrap at most
    twice (double-wrapped envelope). Invalid JSON still yields the cpp_code field.
    Not a Ghidra-dialect recipe.
    """
    t = code or ""
    for _ in range(2):
        s = t.strip()
        if not _looks_like_restore_envelope(s):
            return t
        # Do not call extract_json: its C++ fallback treats the envelope `{` as
        # a compound statement when evidence lists mention std::.
        inner = _json_string_field(s, "cpp_code") or ""
        if not inner.strip():
            try:
                parsed = json.loads(s)
            except (json.JSONDecodeError, TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                cand = parsed.get("cpp_code")
                if isinstance(cand, str):
                    inner = cand
        if not inner.strip():
            return t
        t = inner
    return t


def unwrap_restore_payload(data: Dict[str, Any]) -> None:
    """Recover cpp_code and guessed_name when the restore envelope was stored as the body."""
    if not isinstance(data, dict):
        return
    code = str(data.get("cpp_code") or "")
    if not _looks_like_restore_envelope(code):
        return
    guess = str(data.get("guessed_name") or "").strip()
    if guess.lower() in _EMPTY_GUESS:
        name = (_json_string_field(code, "guessed_name") or "").strip()
        if not name:
            try:
                parsed = json.loads(code.strip())
            except (json.JSONDecodeError, TypeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                cand = parsed.get("guessed_name")
                if isinstance(cand, str):
                    name = cand.strip()
        if name and name.lower() not in _EMPTY_GUESS:
            data["guessed_name"] = name
    data["cpp_code"] = _unwrap_restore_json(code)


def repair_restore_debris(code: str) -> str:
    """Lexical LLM debris: restore JSON envelope, raw newline in a char literal,
    `(void)0` glued to `}`, markdown backticks, an unclosed `"` on a line, and
    leftover `{` at EOF. No new identifiers or control flow.
    Not a Ghidra-dialect recipe.
    """
    t = _unwrap_restore_json(code)
    t = _RE_RAW_NL_CHAR.sub(r"'\\n'", t)
    t = _RE_GLUED_VOID0.sub("(void)0; }", t)
    t = t.replace("`", "")
    t = _close_unbalanced_dquotes(t)
    t = _close_unbalanced_braces(t)
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

    def restore(
        self,
        entry: Dict[str, Any],
        ghidra_code: str,
        *,
        pcode: str = "",
    ) -> Optional[Dict[str, Any]]:
        prompt = build_restore_prompt(
            entry, ghidra_code, profile=self.profile, pcode=pcode
        )
        raw = self.client.generate(prompt, system=self.system_prompt, json_mode=True)
        self._dump(entry.get("address", ""), prompt, raw)
        parsed = extract_restore_json(raw)
        if not parsed:
            logger.warning("LLM JSON parse failed for %s -> retry", entry.get("address"))
            raw = self.client.generate(
                prompt + "\n\nВАЖНО: предыдущий ответ не был валидным JSON. "
                         "Верни СТРОГО один валидный JSON-объект, без пояснений и markdown.",
                system=self.system_prompt,
                json_mode=True,
            )
            self._dump(entry.get("address", ""), prompt, raw)
            parsed = extract_restore_json(raw)
        if not parsed:
            return None
        code = parsed.get("cpp_code") or ""
        if parsed.get("classification") == "user_code" and _norm(code) in self.seen:
            logger.info("Duplicate restoration for %s -> re-prompt", entry.get("address"))
            raw2 = self.client.generate(
                prompt + DUP_NOTE, system=self.system_prompt, json_mode=True
            )
            parsed2 = extract_restore_json(raw2)
            if parsed2 and _norm(parsed2.get("cpp_code") or "") not in self.seen:
                parsed = parsed2
        code = parsed.get("cpp_code") or ""
        if parsed.get("classification") == "user_code" and looks_truncated_cpp(code):
            parsed["cpp_code"] = continue_truncated_cpp(
                self.client, code, self.system_prompt
            )
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

            raw = self.client.generate(
                refinement_prompt, system=self.system_prompt, json_mode=True
            )
            self._dump(
                (entry.get("address") or "") + f"_refine_{attempt}",
                refinement_prompt,
                raw,
            )
            parsed = extract_restore_json(raw)
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
