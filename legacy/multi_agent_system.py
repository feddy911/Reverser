# multi_agent_llm_full.py
from typing import TypedDict, List, Dict, Optional, Literal
from langgraph.graph import StateGraph, END
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
import os
import json
import r2pipe
import re
import time
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

os.environ['R2GHIDRA_SLEIGHHOME'] = r"C:\Users\user\.local\share\radare2\plugins\r2ghidra_sleigh\r2ghidra_sleigh-6.2.0"


# ==================== МОДЕЛИ ДАННЫХ ====================

class FunctionData(BaseModel):
    """Данные о функции"""
    name: str
    address: str
    size: int
    decompiled_code: str = ""
    importance: int = 0
    is_user_code: bool = False
    filter_reason: str = ""


class FilterDecision(BaseModel):
    """Решение агента фильтрации"""
    is_user_code: bool = Field(description="Является ли функция пользовательским кодом (true/false)")
    importance: int = Field(description="Важность функции от 0 до 100")
    category: str = Field(description="Категория: user_code/library/runtime/system/unknown")
    reason: str = Field(description="Подробное объяснение решения")


class FunctionAnalysis(BaseModel):
    """Результат анализа функции"""
    purpose: str = Field(description="Назначение функции на русском языке")
    category: str = Field(description="Категория: main/utility/class_method/helper/callback")
    parameters: List[str] = Field(description="Список параметров с типами")
    return_type: str = Field(description="Тип возвращаемого значения")
    complexity: str = Field(description="Сложность: simple/medium/complex")
    calls_api: List[str] = Field(description="Список вызываемых API функций")
    description: str = Field(description="Подробное описание что делает функция")


class RestoredCode(BaseModel):
    """Восстановленный код"""
    cpp_code: str = Field(description="Восстановленный C++ код функции. НЕ ДОЛЖЕН БЫТЬ ПУСТЫМ!")
    function_signature: str = Field(description="Сигнатура функции (например: int main(int argc, char** argv))")
    includes: List[str] = Field(description="Необходимые #include директивы")


class CodeValidation(BaseModel):
    """Результат валидации кода"""
    is_valid: bool = Field(description="Код корректен и компилируется")
    errors: List[str] = Field(description="Список ошибок")
    warnings: List[str] = Field(description="Список предупреждений")
    suggestions: List[str] = Field(description="Предложения по улучшению")
    quality_score: int = Field(description="Оценка качества кода от 0 до 100")


class CodeImprovement(BaseModel):
    """Улучшенный код"""
    improved_code: str = Field(description="Улучшенная версия кода")
    changes_made: List[str] = Field(description="Список внесенных изменений")
    explanation: str = Field(description="Объяснение улучшений")


# ==================== СОСТОЯНИЕ СИСТЕМЫ ====================

class AgentState(TypedDict):
    """Состояние мультиагентной системы"""
    binary_path: str
    all_functions: List[FunctionData]
    filtered_functions: List[FunctionData]
    current_function: Optional[FunctionData]
    function_index: int
    analysis: Optional[FunctionAnalysis]
    restored_code: Optional[str]
    validation: Optional[CodeValidation]
    improved_code: Optional[str]
    iteration: int
    max_iterations: int
    errors: List[str]
    final_functions: Dict[str, str]
    status: str


# ==================== БАЗОВЫЙ КЛАСС АГЕНТА ====================

class BaseAgent:
    """Базовый класс для всех агентов"""

    def __init__(self, name: str, role: str, timeout: int = 180):
        self.name = name
        self.role = role
        self.timeout = timeout
        self.llm = ChatOllama(
            model="qwen2.5-coder:14b-instruct-q5_K_M",
            temperature=0.1,
            timeout=timeout
        )

    def invoke_with_progress(self, chain, inputs: Dict, max_wait: int = None) -> Optional[object]:
        """Вызов LLM с индикатором прогресса"""
        if max_wait is None:
            max_wait = self.timeout

        def _invoke():
            return chain.invoke(inputs)

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_invoke)

                print(f"  ⏳ LLM обрабатывает запрос", end='', flush=True)
                for i in range(max_wait):
                    time.sleep(1)
                    if future.done():
                        break
                    if i % 10 == 0:
                        print(f".", end='', flush=True)

                if future.done():
                    result = future.result()
                    print(f"\n  ✅ Завершено")
                    return result
                else:
                    print(f"\n   Таймаут ({max_wait} сек)")
                    return None

        except Exception as e:
            print(f"\n  ❌ Ошибка: {str(e)[:100]}")
            return None


# ==================== АГЕНТ 1: FUNCTION FINDER ====================

class FunctionFinderAgent(BaseAgent):
    """
    АГЕНТ ПОИСКА ФУНКЦИЙ

    Роль: Обнаружение всех функций в бинарном файле
    Поведение:
    - Использует Radare2 для анализа бинарника
    - Извлекает список всех функций
    - Применяет базовую фильтрацию (размер > 20 байт)
    - Возвращает полный список функций
    """

    def __init__(self):
        super().__init__(
            name="Function Finder",
            role="Binary function discovery",
            timeout=60
        )

    def find_functions(self, binary_path: str) -> List[FunctionData]:
        """Находит все функции в бинарнике"""
        print(f"\n{'=' * 70}")
        print(f"🔍 [{self.name}]")
        print(f"{'=' * 70}")
        print(f"  Роль: {self.role}")
        print(f"  Задача: Обнаружение всех функций в бинарнике")
        print(f"  Файл: {binary_path}")
        print()

        if not os.path.exists(binary_path):
            print(f"  ❌ ОШИБКА: Файл не найден")
            return []

        print(f"  ⏳ Запуск Radare2...")
        time.sleep(0.5)

        try:
            r2 = r2pipe.open(binary_path, flags=['-e', 'scr.color=0'])

            print(f"  ⏳ Анализ бинарника (aaa)...")
            r2.cmd('aaa')
            time.sleep(1)

            print(f"  ⏳ Получение списка функций...")

            try:
                funcs_json = r2.cmd('aflj')
                funcs_list = json.loads(funcs_json)

                functions = []

                for func in funcs_list:
                    addr = func.get('offset', 0)
                    size = func.get('size', 0)
                    name = func.get('name', f'fcn.{addr:x}')

                    # Базовая фильтрация
                    if size < 20:
                        continue

                    func_data = FunctionData(
                        name=name,
                        address=hex(addr),
                        size=size
                    )
                    functions.append(func_data)

                r2.quit()

                print(f"  ✅ Найдено {len(functions)} функций")
                print(f"   Размер бинарника: {os.path.getsize(binary_path)} байт")

                return functions

            except Exception as e:
                print(f"  ❌ Ошибка парсинга JSON: {e}")
                return []

        except Exception as e:
            print(f"  ❌ Ошибка: {e}")
            return []


# ==================== АГЕНТ 2: FUNCTION FILTER ====================

class FunctionFilterAgent(BaseAgent):
    """
    АГЕНТ ФИЛЬТРАЦИИ ФУНКЦИЙ

    Роль: Определение пользовательского кода
    Поведение:
    - Анализирует каждую функцию через LLM
    - Определяет является ли функция пользовательским кодом
    - Оценивает важность функции (0-100)
    - Классифицирует по категориям
    - Отсеивает библиотечные и системные функции

    Критерии пользовательского кода:
    ✅ Функции с понятными именами (main, calculate, process)
    ✅ Функции с префиксом sym. (кроме sym.imp.)
    ✅ Функции которые выглядят как бизнес-логика
    ✅ Функции размером > 100 байт

    Критерии библиотечного кода:
    ❌ Функции std::, method.std::
    ❌ Функции imp., sym.imp.
    ❌ Функции runtime (bad_cast, bad_alloc)
    ❌ Функции размером < 50 байт
    """

    def __init__(self):
        super().__init__(
            name="Function Filter",
            role="User code identification",
            timeout=120
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """Ты эксперт по анализу бинарного кода и реверс-инжинирингу.

ТВОЯ ЗАДАЧА: Определить, является ли функция ПОЛЬЗОВАТЕЛЬСКИМ кодом или библиотечной/системной функцией.

КРИТЕРИИ ПОЛЬЗОВАТЕЛЬСКОГО КОДА (is_user_code = true):
✅ Функции с понятными именами: main, calculate, process, find, step, и т.д.
✅ Функции с префиксом sym. (кроме sym.imp.)
✅ Функции которые содержат бизнес-логику
✅ Функции размером > 100 байт с осмысленным кодом
✅ Функции которые работают с пользовательскими данными

КРИТЕРИИ БИБЛИОТЕЧНОГО/СИСТЕМНОГО КОДА (is_user_code = false):
❌ Функции std::, method.std:: (библиотека C++)
❌ Функции imp., sym.imp. (импорты)
❌ Функции dbg., fcn. с короткими именами
❌ Функции runtime: bad_cast, bad_alloc, type_info, virtual
❌ Функции размером < 50 байт (обычно trampolines)
❌ Функции с именами: entry0, init, term, _start
❌ Функции которые просто вызывают другие функции через goto

КАТЕГОРИИ:
- user_code: пользовательский код
- library: библиотечный код (std, boost, и т.д.)
- runtime: runtime код (исключения, virtual methods)
- system: системный код (entry point, init)
- unknown: неизвестно

ВАЖНОСТЬ (0-100):
- 90-100: main функция, точка входа
- 70-89: основные функции бизнес-логики
- 50-69: вспомогательные функции
- 30-49: утилитарные функции
- 0-29: низкоуровневые функции

Отвечай ТОЛЬКО в формате JSON."""),

            ("human", """Проанализируй функцию и определи, является ли она пользовательским кодом:

Имя функции: {name}
Размер: {size} байт
Адрес: {address}

Пример декомпилированного кода (первые 800 символов):
{code_sample}

Является ли это пользовательским кодом?""")
        ])

        self.chain = self.prompt | self.llm.with_structured_output(FilterDecision)

    def filter_functions(self, functions: List[FunctionData], binary_path: str) -> List[FunctionData]:
        """Фильтрует функции через LLM"""
        print(f"\n{'=' * 70}")
        print(f"🎯 [{self.name}]")
        print(f"{'=' * 70}")
        print(f"  Роль: {self.role}")
        print(f"  Задача: Фильтрация функций через LLM")
        print(f"  Всего функций: {len(functions)}")
        print(f"  Будет проанализировано: {min(len(functions), 50)}")
        print()

        filtered = []
        skipped_user = 0
        skipped_library = 0

        # Анализируем первые 50 функций
        functions_to_analyze = functions[:50]

        for i, func in enumerate(functions_to_analyze):
            print(f"  [{i + 1}/{len(functions_to_analyze)}] {func.name}...", end='', flush=True)

            # Получаем образец кода
            code_sample = self._get_code_sample(func, binary_path)

            if not code_sample or len(code_sample) < 50:
                print(f" пропущена (нет кода)")
                skipped_library += 1
                continue

            # Анализируем через LLM
            result = self._analyze_function(func, code_sample)

            func.is_user_code = result.is_user_code
            func.importance = result.importance
            func.filter_reason = result.reason

            if result.is_user_code:
                print(f" ✅ {result.category} (важность: {result.importance})")
                filtered.append(func)
                skipped_user += 1
            else:
                print(f" ❌ {result.category}")
                skipped_library += 1

        print(f"\n  📊 Результаты фильтрации:")
        print(f"    Пользовательских функций: {len(filtered)}")
        print(f"    Отсеяно библиотечных: {skipped_library}")

        # Сортируем по важности
        filtered.sort(key=lambda f: f.importance, reverse=True)

        print(f"\n  🏆 ТОП-10 важных функций:")
        for i, f in enumerate(filtered[:10]):
            print(f"    {i + 1}. {f.name} (важность: {f.importance}, размер: {f.size})")

        return filtered

    def _get_code_sample(self, func: FunctionData, binary_path: str) -> str:
        """Получает образец кода функции"""
        try:
            r2 = r2pipe.open(binary_path, flags=['-e', 'scr.color=0'])
            r2.cmd('aaa')

            afl_output = r2.cmd('afl')
            func_addr = None

            for line in afl_output.strip().split('\n'):
                parts = line.strip().split()
                if len(parts) >= 4:
                    name = ' '.join(parts[3:])
                    if name == func.name:
                        func_addr = int(parts[0], 16)
                        break

            if func_addr:
                r2.cmd(f's {hex(func_addr)}')
                code = r2.cmd('pdc')
                r2.quit()
                return code[:800] if code else ""

            r2.quit()
            return ""

        except:
            return ""

    def _analyze_function(self, func: FunctionData, code_sample: str) -> FilterDecision:
        """Анализирует функцию через LLM"""
        result = self.invoke_with_progress(
            self.chain,
            {
                "name": func.name,
                "size": func.size,
                "address": func.address,
                "code_sample": code_sample
            },
            max_wait=120
        )

        if result:
            return result

        # Fallback: эвристическая фильтрация
        return self._heuristic_filter(func)

    def _heuristic_filter(self, func: FunctionData) -> FilterDecision:
        """Эвристическая фильтрация если LLM не сработал"""
        name = func.name
        size = func.size

        # Явно пользовательский код
        if name in ['main', 'sym.main', 'WinMain']:
            return FilterDecision(
                is_user_code=True,
                importance=100,
                category="user_code",
                reason="Main function"
            )

        # Явно библиотечный код
        if any(x in name for x in ['std::', 'imp.', 'dbg.', 'bad_cast', 'bad_alloc', 'type_info', 'virtual']):
            return FilterDecision(
                is_user_code=False,
                importance=0,
                category="library",
                reason="Library function"
            )

        # По размеру
        if size < 50:
            return FilterDecision(
                is_user_code=False,
                importance=0,
                category="runtime",
                reason="Too small"
            )

        # По умолчанию
        return FilterDecision(
            is_user_code=True,
            importance=50,
            category="user_code",
            reason="Heuristic: likely user code"
        )


# ==================== АГЕНТ 3: STATIC ANALYST ====================

class StaticAnalystAgent(BaseAgent):
    """
    АГЕНТ СТАТИЧЕСКОГО АНАЛИЗА

    Роль: Глубокий анализ функций
    Поведение:
    - Анализирует декомпилированный код
    - Определяет назначение функции
    - Извлекает параметры и тип возврата
    - Оценивает сложность
    - Определяет вызываемые API

    Модель поведения:
    - Внимательно изучает код
    - Ищет паттерны (циклы, условия, вызовы)
    - Определяет бизнес-логику
    - Классифицирует функцию
    """

    def __init__(self):
        super().__init__(
            name="Static Analyst",
            role="Deep function analysis",
            timeout=180
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """Ты эксперт по реверс-инжинирингу C++ бинарников с 20-летним опытом.

ТВОЯ ЗАДАЧА: Провести глубокий анализ декомпилированной функции и извлечь всю возможную информацию.

АНАЛИЗИРУЙ:
1. Назначение функции - что она делает (на русском языке)
2. Категорию - main/utility/class_method/helper/callback
3. Параметры - список параметров с типами (int, char*, void*, и т.д.)
4. Тип возврата - что возвращает функция
5. Сложность - simple/medium/complex
6. Вызываемые API - список внешних функций
7. Подробное описание - как работает функция

ВАЖНО:
- Будь точным в определении типов параметров
- Определяй бизнес-логику, а не технические детали
- Описывай назначение на русском языке
- Если функция сложная, опиши алгоритм

Отвечай ТОЛЬКО в формате JSON."""),

            ("human", """Функция: {name}
Размер: {size} байт
Адрес: {address}

Декомпилированный код:
{code}

Проведи глубокий анализ функции.""")
        ])

        self.chain = self.prompt | self.llm.with_structured_output(FunctionAnalysis)

    def analyze(self, func: FunctionData) -> Optional[FunctionAnalysis]:
        """Анализирует функцию"""
        print(f"\n{'=' * 70}")
        print(f"🧠 [{self.name}]")
        print(f"{'=' * 70}")
        print(f"  Роль: {self.role}")
        print(f"  Задача: Анализ функции {func.name}")
        print(f"  Размер: {func.size} байт")
        print(f"  Адрес: {func.address}")
        print(f"  Важность: {func.importance}")
        print()

        result = self.invoke_with_progress(
            self.chain,
            {
                "name": func.name,
                "size": func.size,
                "address": func.address,
                "code": func.decompiled_code[:2000]
            },
            max_wait=180
        )

        if result:
            print(f"  📋 Назначение: {result.purpose[:80]}")
            print(f"  📊 Категория: {result.category}")
            print(f"  🔧 Сложность: {result.complexity}")
            return result

        # Fallback
        return FunctionAnalysis(
            purpose="Неизвестная функция",
            category="utility",
            parameters=[],
            return_type="void",
            complexity="simple",
            calls_api=[],
            description="Не удалось проанализировать"
        )


# ==================== АГЕНТ 4: CODE RESTORER ====================

class CodeRestorerAgent(BaseAgent):
    """
    АГЕНТ ВОССТАНОВЛЕНИЯ КОДА

    Роль: Преобразование декомпилированного кода в чистый C++
    Поведение:
    - Убирает все goto и метки
    - Заменяет на нормальные конструкции (if/while/for)
    - Убирает комментарии с адресами и XREF
    - Добавляет правильные типы
    - Сохраняет логику функции
    - Возвращает ЧИСТЫЙ рабочий код

    Правила:
    1. НИКОГДА не возвращать пустой код
    2. Убрать все технические детали
    3. Сделать код читаемым
    4. Если не можешь восстановить - создать заглушку
    """

    def __init__(self):
        super().__init__(
            name="Code Restorer",
            role="Clean C++ code restoration",
            timeout=180
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """Ты эксперт по C++ программированию и реверс-инжинирингу.

ТВОЯ ЗАДАЧА: Преобразовать ДЕКОМПИЛИРОВАННЫЙ код в ЧИСТЫЙ, ЧИТАЕМЫЙ C++ код.

КРИТИЧЕСКИ ВАЖНЫЕ ПРАВИЛА:
1. УБЕРИ все goto и метки - замени на if/while/for/switch
2. УБЕРИ все комментарии с адресами (0x...), XREF, CALL XREF
3. УБЕРИ все reloc. и технические детали
4. ЗАМЕНИ вызовы API на понятные функции
5. ДОБАВЬ правильные типы параметров (int, void*, char*, и т.д.)
6. СОХРАНИ логику функции, но сделай код читаемым
7. ДОБАВЬ необходимые #include директивы
8. КОД НЕ ДОЛЖЕН БЫТЬ ПУСТЫМ - это критическая ошибка!

ПРИМЕРЫ ПРЕОБРАЗОВАНИЯ:

ДЕКОМПИЛИРОВАННЫЙ:
  goto loc_0x140025e12;
  loc_0x140025e12:
  goto (void*)0x140038658;

ЧИСТЫЙ C++:
  return some_function_call();

ДЕКОМПИЛИРОВАННЫЙ:
  if (var_8h == 0) goto loc_0x14001234;
  loc_0x14001234:
  return 1;

ЧИСТЫЙ C++:
  if (condition == 0) {
      return 1;
  }

ЕСЛИ НЕ МОЖЕШЬ ВОССТАНОВИТЬ:
Создай заглушку с комментарием:
  // Function: function_name
  // Note: Complex function - placeholder
  void function_name_placeholder(void) {
      // TODO: Implement
  }

Отвечай ТОЛЬКО в формате JSON с полями: cpp_code, function_signature, includes"""),

            ("human", """Анализ функции:
Название: {func_name}
Назначение: {purpose}
Категория: {category}
Параметры: {parameters}
Возврат: {return_type}
Сложность: {complexity}

Декомпилированный код:
{decompiled_code}

{error_context}

Преобразуй в чистый C++ код. ПОМНИ: код НЕ ДОЛЖЕН БЫТЬ ПУСТЫМ!""")
        ])

        self.chain = self.prompt | self.llm.with_structured_output(RestoredCode)

    def restore(self, func: FunctionData, analysis: FunctionAnalysis,
                errors: List[str] = None) -> str:
        """Восстанавливает код"""
        print(f"\n{'=' * 70}")
        print(f" [{self.name}]")
        print(f"{'=' * 70}")
        print(f"  Роль: {self.role}")
        print(f"  Задача: Восстановление кода {func.name}")
        print(f"  На основе: {analysis.purpose[:70]}")
        print()

        error_context = ""
        if errors:
            error_context = f"\nОШИБКИ ПРЕДЫДУЩИХ ВЕРСИЙ (исправь их):\n" + "\n".join(errors)

        result = self.invoke_with_progress(
            self.chain,
            {
                "func_name": func.name,
                "purpose": analysis.purpose,
                "category": analysis.category,
                "parameters": analysis.parameters if analysis.parameters else "unknown",
                "return_type": analysis.return_type,
                "complexity": analysis.complexity,
                "decompiled_code": func.decompiled_code[:2500],
                "error_context": error_context
            },
            max_wait=180
        )

        if result and result.cpp_code and len(result.cpp_code.strip()) > 10:
            # Очищаем код
            clean_code = self._clean_code(result.cpp_code, func.name)

            if len(clean_code.strip()) > 10:
                print(f"  ✅ Код восстановлен ({len(clean_code)} символов)")
                return clean_code

        print(f"  ⚠️ LLM вернул пустой или короткий код")
        return self._generate_fallback_code(func, analysis)

    def _clean_code(self, code: str, func_name: str) -> str:
        """Очищает код от мусора"""
        if not code:
            return ""

        # Убираем XREF
        code = re.sub(r'//\s*(CALL|CODE)\s*XREF.*', '', code, flags=re.IGNORECASE)
        # Убираем адреса
        code = re.sub(r'//\s*\[0x[0-9a-fA-F]+:[0-9]+\].*', '', code)
        # Убираем reloc
        code = re.sub(r'\s*reloc\.[^\s]+', '', code)
        # Убираем пустые строки
        lines = [line for line in code.split('\n') if line.strip()]

        clean_code = '\n'.join(lines).strip()

        # Если много goto - заглушка
        if clean_code.count('goto') > 2:
            return self._generate_fallback_code(
                FunctionData(name=func_name, address="", size=0),
                FunctionAnalysis(purpose="Complex function", category="utility")
            )

        return clean_code

    def _generate_fallback_code(self, func: FunctionData, analysis: FunctionAnalysis) -> str:
        """Генерирует fallback код"""
        print(f"  → Генерируем fallback код")

        clean_name = func.name.replace('.', '_').replace(':', '_')

        return f"""// Function: {func.name}
// Address: {func.address}
// Size: {func.size} bytes
// Purpose: {analysis.purpose}
// Note: Auto-generated placeholder

void {clean_name}_fallback(void) {{
    // TODO: Implement function logic
    // Original decompiled code was too complex or unavailable
}}"""


# ==================== АГЕНТ 5: CODE VALIDATOR ====================

class CodeValidatorAgent(BaseAgent):
    """
    АГЕНТ ВАЛИДАЦИИ КОДА

    Роль: Проверка качества восстановленного кода
    Поведение:
    - Проверяет синтаксис C++
    - Ищет ошибки компиляции
    - Оценивает качество кода (0-100)
    - Дает предложения по улучшению
    - Определяет нужно ли улучшать код

    Критерии качества:
    - 90-100: Отличный код, готов к использованию
    - 70-89: Хороший код, minor issues
    - 50-69: Средний код, нужно улучшить
    - 0-49: Плохой код, требует переработки
    """

    def __init__(self):
        super().__init__(
            name="Code Validator",
            role="Code quality assessment",
            timeout=120
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """Ты компилятор C++ и код-ревьюер с опытом 15 лет.

ТВОЯ ЗАДАЧА: Проверить восстановленный код на ошибки и оценить его качество.

ПРОВЕРЯЙ:
1. Синтаксические ошибки (непарные скобки, missing semicolons)
2. Логические ошибки (неинициализированные переменные)
3. Стиль кода (читаемость, именование)
4. Наличие goto и меток (должно быть 0)
5. Наличие технических комментариев (адреса, XREF)
6. Полноту кода (не пустой ли)

ОЦЕНКА КАЧЕСТВА (0-100):
- 90-100: Отличный код, готов к компиляции
- 70-89: Хороший код, minor issues
- 50-69: Средний код, нужно улучшить
- 30-49: Плохой код, много проблем
- 0-29: Очень плохой код, требует переработки

Отвечай ТОЛЬКО в формате JSON."""),

            ("human", "Код:\n{code}\n\nПроверь код и оцени качество.""")
        ])

        self.chain = self.prompt | self.llm.with_structured_output(CodeValidation)

    def validate(self, code: str) -> CodeValidation:
        """Проверяет код"""
        print(f"\n{'=' * 70}")
        print(f"🔍 [{self.name}]")
        print(f"{'=' * 70}")
        print(f"  Роль: {self.role}")
        print(f"  Задача: Проверка качества кода")
        print()

        # Быстрая проверка
        errors = []

        if not code or len(code.strip()) < 10:
            errors.append("Code is empty or too short")

        if code.count('{') != code.count('}'):
            errors.append("Unbalanced braces")

        if code.count('goto') > 3:
            errors.append("Too many goto statements")

        if errors:
            print(f"  ⚠️ Найдено критических ошибок: {len(errors)}")
            return CodeValidation(
                is_valid=False,
                errors=errors,
                warnings=[],
                suggestions=["Generate fallback code"],
                quality_score=0
            )

        result = self.invoke_with_progress(
            self.chain,
            {"code": code},
            max_wait=120
        )

        if result:
            if result.is_valid and result.quality_score >= 70:
                print(f"  ✅ Код принят (оценка: {result.quality_score}/100)")
            else:
                print(f"  ⚠️ Код требует улучшения (оценка: {result.quality_score}/100)")
                if result.errors:
                    print(f"     Ошибки: {len(result.errors)}")
            return result

        # Fallback
        return CodeValidation(
            is_valid=True,
            errors=[],
            warnings=["LLM validation timeout"],
            suggestions=[],
            quality_score=50
        )


# ==================== АГЕНТ 6: CODE REFINER ====================

class CodeRefinerAgent(BaseAgent):
    """
    АГЕНТ УЛУЧШЕНИЯ КОДА

    Роль: Улучшение кода на основе замечаний валидатора
    Поведение:
    - Анализирует ошибки и предупреждения
    - Исправляет найденные проблемы
    - Улучшает стиль кода
    - Убирает оставшиеся goto
    - Повышает читаемость

    Работает только если валидатор нашел проблемы
    """

    def __init__(self):
        super().__init__(
            name="Code Refiner",
            role="Code improvement and refinement",
            timeout=180
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """Ты эксперт по C++ и рефакторингу кода.

ТВОЯ ЗАДАЧА: Улучшить код на основе замечаний валидатора.

ЧТО ДЕЛАТЬ:
1. Исправить все ошибки из списка errors
2. Учесть все предупреждения из warnings
3. Применить все предложения из suggestions
4. Убрать все оставшиеся goto и метки
5. Улучшить стиль кода
6. Повысить читаемость
7. Сохранить логику функции

ВАЖНО:
- Код НЕ ДОЛЖЕН БЫТЬ ПУСТЫМ
- Сохрани всю функциональность
- Сделай код максимально чистым

Отвечай ТОЛЬКО в формате JSON."""),

            ("human", """Оригинальный код:
{original_code}

Ошибки:
{errors}

Предупреждения:
{warnings}

Предложения:
{suggestions}

Улучши код.""")
        ])

        self.chain = self.prompt | self.llm.with_structured_output(CodeImprovement)

    def refine(self, code: str, validation: CodeValidation) -> Optional[str]:
        """Улучшает код"""
        print(f"\n{'=' * 70}")
        print(f"✨ [{self.name}]")
        print(f"{'=' * 70}")
        print(f"  Роль: {self.role}")
        print(f"  Задача: Улучшение кода")
        print(f"  Ошибок для исправления: {len(validation.errors)}")
        print(f"  Предложений: {len(validation.suggestions)}")
        print()

        result = self.invoke_with_progress(
            self.chain,
            {
                "original_code": code,
                "errors": "\n".join(validation.errors) if validation.errors else "None",
                "warnings": "\n".join(validation.warnings) if validation.warnings else "None",
                "suggestions": "\n".join(validation.suggestions) if validation.suggestions else "None"
            },
            max_wait=180
        )

        if result and result.improved_code and len(result.improved_code.strip()) > 10:
            print(f"  ✅ Код улучшен")
            print(f"  📝 Внесено изменений: {len(result.changes_made)}")
            return result.improved_code

        print(f"  ⚠️ Не удалось улучшить код")
        return None


# ==================== НОДЫ ГРАФА ====================

def find_functions_node(state: AgentState) -> AgentState:
    """Нода поиска функций"""
    finder = FunctionFinderAgent()
    functions = finder.find_functions(state['binary_path'])

    if not functions:
        print(f"\n  ❌ Функции не найдены!")
        state['status'] = "error"
        state['all_functions'] = []
        state['filtered_functions'] = []
        return state

    state['all_functions'] = functions
    state['filtered_functions'] = []

    return state


def filter_functions_node(state: AgentState) -> AgentState:
    """Нода фильтрации функций"""
    if state['status'] == "error":
        return state

    print(f"\n{'=' * 70}")
    print(f"🎯 ПЕРЕХОД К АГЕНТУ 2: Function Filter")
    print(f"{'=' * 70}")

    filter_agent = FunctionFilterAgent()
    filtered = filter_agent.filter_functions(state['all_functions'], state['binary_path'])

    if not filtered:
        print(f"\n  ❌ После фильтрации не осталось функций!")
        state['status'] = "error"
        state['filtered_functions'] = []
        return state

    state['filtered_functions'] = filtered[:10]  # Топ-10
    state['function_index'] = 0
    state['final_functions'] = {}
    state['status'] = "running"

    print(f"\n{'=' * 70}")
    print(f"📊 РЕЗУЛЬТАТ АГЕНТА 2")
    print(f"{'=' * 70}")
    print(f"  Будет проанализировано: {len(state['filtered_functions'])} функций")
    print()
    for i, f in enumerate(state['filtered_functions']):
        print(f"  {i + 1}. {f.name} (важность: {f.importance})")

    return state


def analyze_function_node(state: AgentState) -> AgentState:
    """Нода анализа функции"""
    if state['status'] in ['error', 'completed']:
        return state

    idx = state['function_index']
    if idx >= len(state['filtered_functions']):
        state['status'] = 'completed'
        return state

    func = state['filtered_functions'][idx]
    state['current_function'] = func
    state['iteration'] = 0
    state['errors'] = []

    print(f"\n{'=' * 70}")
    print(f"📦 ФУНКЦИЯ [{idx + 1}/{len(state['filtered_functions'])}]: {func.name}")
    print(f"{'=' * 70}")
    print(f"  Важность: {func.importance}")
    print(f"  Размер: {func.size} байт")

    # Декомпиляция
    print(f"\n  ⏳ Декомпиляция через pdc...")
    try:
        r2 = r2pipe.open(state['binary_path'], flags=['-e', 'scr.color=0'])
        r2.cmd('aaa')

        afl_output = r2.cmd('afl')
        func_addr = None

        for line in afl_output.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) >= 4:
                name = ' '.join(parts[3:])
                if name == func.name:
                    func_addr = int(parts[0], 16)
                    break

        if func_addr:
            r2.cmd(f's {hex(func_addr)}')
            code = r2.cmd('pdc')
            func.decompiled_code = code if code else ""

        r2.quit()

        if func.decompiled_code and len(func.decompiled_code) > 20:
            print(f"  ✅ Декомпиляция: {len(func.decompiled_code)} байт")
        else:
            print(f"  ❌ Пустой код")
            state['function_index'] = idx + 1
            return state

    except Exception as e:
        print(f"  ❌ Ошибка: {e}")
        state['function_index'] = idx + 1
        return state

    # Анализ через LLM
    analyst = StaticAnalystAgent()
    analysis = analyst.analyze(func)
    state['analysis'] = analysis

    return state


def restore_code_node(state: AgentState) -> AgentState:
    """Нода восстановления кода"""
    func = state.get('current_function')
    analysis = state.get('analysis')
    errors = state.get('errors', [])

    if not func or not analysis:
        state['function_index'] = state['function_index'] + 1
        return state

    restorer = CodeRestorerAgent()
    code = restorer.restore(func, analysis, errors)
    state['restored_code'] = code

    return state


def validate_code_node(state: AgentState) -> AgentState:
    """Нода валидации кода"""
    code = state.get('restored_code', '')

    validator = CodeValidatorAgent()
    validation = validator.validate(code)
    state['validation'] = validation

    return state


def should_refine_or_next(state: AgentState) -> Literal["refine", "next", "end"]:
    """Решение: улучшить, продолжить или завершить"""
    if state['status'] in ['error', 'completed']:
        return "end"

    if state['function_index'] >= len(state['filtered_functions']):
        return "end"

    validation = state.get('validation')
    iteration = state.get('iteration', 0)
    max_iter = 2

    # Если код хороший
    if validation and validation.is_valid and validation.quality_score >= 70:
        return "next"

    # Если достигнут лимит итераций
    if iteration >= max_iter:
        print(f"\n  ⚠️ Лимит итераций ({max_iter}), принимаем код")
        return "next"

    # Если есть что улучшать
    if validation and (not validation.is_valid or validation.quality_score < 70):
        state['errors'] = validation.errors
        state['iteration'] = iteration + 1
        print(f"\n  🔄 Улучшение кода (итерация {iteration + 1}/{max_iter})")
        return "refine"

    return "next"


def refine_code_node(state: AgentState) -> AgentState:
    """Нода улучшения кода"""
    code = state.get('restored_code', '')
    validation = state.get('validation')

    if not code or not validation:
        return state

    refiner = CodeRefinerAgent()
    improved = refiner.refine(code, validation)

    if improved:
        state['restored_code'] = improved
        print(f"  ✅ Код улучшен")
    else:
        print(f"  ⚠️ Код не улучшен, оставляем как есть")

    return state


def finalize_function_node(state: AgentState) -> AgentState:
    """Нода завершения функции"""
    func = state.get('current_function')
    code = state.get('restored_code')

    if func and code and len(code.strip()) > 10:
        state['final_functions'][func.name] = code
        print(f"\n{'=' * 70}")
        print(f"✅ ФУНКЦИЯ ЗАВЕРШЕНА: {func.name}")
        print(f"{'=' * 70}")
        print(f"  Код сохранен ({len(code)} символов)")
    else:
        print(f"\n  ⚠️ Функция {func.name if func else 'unknown'} не восстановлена")

    state['function_index'] = state['function_index'] + 1

    if state['function_index'] >= len(state['filtered_functions']):
        state['status'] = 'completed'
        print(f"\n{'=' * 70}")
        print(f"🎉 ВСЕ ФУНКЦИИ ПРОАНАЛИЗИРОВАНЫ")
        print(f"{'=' * 70}")

    return state


# ==================== ГРАФ ====================

def build_graph():
    """Строит граф с 6 агентами"""
    workflow = StateGraph(AgentState)

    # Добавляем ноды
    workflow.add_node("find_functions", find_functions_node)
    workflow.add_node("filter_functions", filter_functions_node)
    workflow.add_node("analyze_function", analyze_function_node)
    workflow.add_node("restore_code", restore_code_node)
    workflow.add_node("validate_code", validate_code_node)
    workflow.add_node("refine_code", refine_code_node)
    workflow.add_node("finalize_function", finalize_function_node)

    # Точка входа
    workflow.set_entry_point("find_functions")

    # Последовательные переходы
    workflow.add_edge("find_functions", "filter_functions")
    workflow.add_edge("filter_functions", "analyze_function")
    workflow.add_edge("analyze_function", "restore_code")
    workflow.add_edge("restore_code", "validate_code")

    # Условный переход после валидации
    workflow.add_conditional_edges(
        "validate_code",
        should_refine_or_next,
        {
            "refine": "refine_code",
            "next": "finalize_function",
            "end": END
        }
    )

    # После улучшения - снова валидация
    workflow.add_edge("refine_code", "validate_code")

    # После завершения функции - следующая
    workflow.add_edge("finalize_function", "analyze_function")

    return workflow.compile()


# ==================== ЗАПУСК ====================

def main():
    print("\n" + "=" * 70)
    print("    МУЛЬТИАГЕНТНАЯ СИСТЕМА (6 АГЕНТОВ ЧЕРЕЗ LLM)")
    print("=" * 70)
    print()
    print("   Агенты:")
    print("   1. Function Finder - поиск функций")
    print("   2. Function Filter - фильтрация через LLM")
    print("   3. Static Analyst - анализ через LLM")
    print("   4. Code Restorer - восстановление через LLM")
    print("   5. Code Validator - валидация через LLM")
    print("   6. Code Refiner - улучшение через LLM")
    print("=" * 70)

    binary = "MyCollatz.exe"
    if not os.path.exists(binary):
        print(f" ERROR: {binary} not found!")
        return

    graph = build_graph()

    initial_state = {
        "binary_path": binary,
        "all_functions": [],
        "filtered_functions": [],
        "current_function": None,
        "function_index": 0,
        "analysis": None,
        "restored_code": None,
        "validation": None,
        "improved_code": None,
        "iteration": 0,
        "max_iterations": 2,
        "errors": [],
        "final_functions": {},
        "status": "init"
    }

    print(f"\n🚀 Запуск мультиагентной системы...")
    print(f" Бинарник: {binary}")
    print(f"🎯 Максимум функций: 10")
    print(f"⏱ Timeout LLM: 180 сек")
    print()

    # Запуск с общим таймаутом
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(graph.invoke, initial_state)
        try:
            result = future.result(timeout=3600)  # 60 минут
        except FuturesTimeoutError:
            print(f"\n❌ ТАЙМАУТ! Прерывание...")
            return

    print(f"\n{'=' * 70}")
    print(f"🏁 ЗАВЕРШЕНИЕ РАБОТЫ")
    print(f"{'=' * 70}")
    print(f"  Статус: {result['status']}")
    print(f"  Восстановлено функций: {len(result['final_functions'])}")

    if result['final_functions']:
        with open("../restored_llm_full.cpp", 'w', encoding='utf-8') as f:
            f.write("// Восстановленный код (6 LLM АГЕНТОВ)\n")
            f.write("// Полностью мультиагентная система\n\n")
            f.write("#include <cstdint>\n#include <iostream>\n\n")

            for name, code in result['final_functions'].items():
                f.write(f"\n// {'=' * 60}\n")
                f.write(f"// Function: {name}\n")
                f.write(f"// {'=' * 60}\n")
                f.write(f"{code}\n\n")

        print(f"\n✅ Файл: restored_llm_full.cpp")
        print(f"   Функций: {len(result['final_functions'])}")
    else:
        print(f"\n⚠️ Ни одна функция не восстановлена!")


if __name__ == "__main__":
    main()