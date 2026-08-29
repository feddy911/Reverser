# Reverser

Мультистадийный пайплайн восстановления C++ из произвольного исполняемого файла:
**triage → Ghidra → score → LLM restore → assemble → (optional) polish / fidelity**.

## Требования

- Python 3.10+
- [Ghidra](https://ghidra-sre.org/) (headless; Windows `.bat` или Unix `analyzeHeadless`)
- [Ollama](https://ollama.com/) + модель из `config.yaml` (по умолчанию `qwen2.5-coder:14b-instruct-q5_K_M`)

```bash
pip install -r requirements.txt
```

## Быстрый старт

1. Отредактируйте `config.yaml`: `binary_path`, `ghidra_path`, `ollama_url`.
2. Запустите пайплайн. Подсказок под конкретный сэмпл нет: бинарник считается неизвестным.

```bash
py main.py --config config.yaml
# или
py main.py --binary path/to/app.exe
```

Артефакты прогона: `output/logs/run_<timestamp>/`  
(`triage.json`, `ghidra_raw.json`, `features.json`, `restored*.cpp`, `fidelity.json`, `metrics.json`).

Пустой Ghidra-дамп — ошибка (fail-hard), пайплайн не продолжает «вхолостую».

## Triage и промпт-профили

`src/analysis/triage.py` определяет format (PE/ELF/Mach-O), arch, compiler, Debug/Release
и выбирает профиль (`msvc_x64_debug`, `gcc_elf_x64`, `generic`, …).

Restorer берёт system/user rules из `src/analysis/prompts.py` по этому профилю.

## Includes

`#include` собираются динамически из `ext_calls` / `ext_dlls` бинарника
(`src/analysis/includes.py`). GMP появляется, если в дампе есть `mpz_*` или `gmp.dll` —
не из заранее известного имени сэмпла.

## Скоринг

- `scoring_mode: heuristic` — веса в `src/analysis/scorer.py`
- `scoring_mode: ml` — модель из `ml_weights_path` (meta JSON + joblib)

```bash
py -m src.analysis.train_scorer --help
```

## Eval harness (scoring-only)

Манифест: `eval/manifest.example.yaml`. Добавляйте бинарники + `ghidra_json` + labels.

```bash
py -m src.analysis.eval_harness --manifest eval/manifest.example.yaml
py -m src.analysis.eval_harness --fixture tests/fixtures/mini_ghidra.json
```

Отчёт: `output/eval_report.json` (precision/recall@k при наличии labels).

## Корпус диалекта Ghidra (compile-gate)

Новые rewrite в `ghidra_cpp.py` / `assembler.py` не добавляются по итогам одного exe.
Сначала фикстура в `eval/corpus/<id>.yaml` (сниппет + recipe + contains / not_contains), затем рецепт.
Схема полей: `eval/corpus/_schema.yaml`. Сейчас **134** загружаемых фикстур.

```bash
py -m src.analysis.eval_corpus
py -m src.analysis.eval_corpus --dir eval/corpus --out output/corpus_report.json
py -m src.analysis.eval_classifier
```

Заморозка: не писать имена PointCloud / EchoFilter / MyCollatz / `starts_with` в sanitizer или assembler.
Per-function compile-fix пишет `compile_fn/*_fix.cpp` и кэш `kind=compile_fn_fix`.
Он **не** перезаписывает restore-кэш и не подменяет `cpp_code` для assemble.

## Генератор, librarian, Compiler agent, Critic

Наполнение базы — мини-программы (string/vector/iostream/chrono/GMP/main), не пользовательский exe:

```bash
py -m src.analysis.gen_corpus --out output/corpus_gen --compile --vary
# Ghidra-дампы мини-программ (нужен ghidra_path в config.yaml):
py -m src.analysis.gen_corpus --ghidra --config config.yaml
```

`--vary` переименовывает идентификаторы в фикстурах: рецепт не должен быть приклеен к `prefixPtr`.

Правило наполнения (Q1): дамп принимают в корпус, если он зелёный **без нового regex**, либо есть честный
`gcc_fingerprint` и фикстура **до** рецепта. Не плодить compile-ok YAML с пустым отпечатком ради счётчика.
Красные generator-дампы ниже не чинить.

Q3b (план, не restore): тот же цикл unknown→мини→фикстура можно крутить офлайн (`dialect_loop`) —
очередь нормализованных диагностик, каталог мини, Ghidra, YAML до рецепта. Лексика — таблица замен;
структурный патч без автомержа; семантика красной восьмёрки (`T&` vs `T*`, `ios::good()` без объекта) —
skip-forever. Live `main.py` только применяет корпус и пишет `corpus_proposals`.

```bash
py -m src.analysis.dialect_loop --from-report output/apply_inimini_report.json
py -m src.analysis.dialect_loop --message "invalid cast from type '__const_iterator'..." --emit
py -m src.analysis.dialect_loop --message "..." --emit --dumps-dir output/corpus_gen/ghidra_dumps
# опционально: --ghidra --config config.yaml  (дамп + проверка токена)
```

Команда не патчит `ghidra_cpp.py` и не копирует YAML в `eval/corpus/`. Бюджет по умолчанию — один мини.
Известный fingerprint → skip; красная восьмёрка → skip-forever; остальное — каталог или `no_catalog`.

Librarian собирает черновик YAML из дампа и принимает его в `eval/corpus/` только после зелёного `eval_case`.
Имена held-out / сэмплов (`heldout`, `pointcloud`, `echofilter`, `mycollatz`, …) отклоняются.

```bash
py -m src.analysis.librarian --dumps-dir output/corpus_gen/ghidra_dumps --draft-dir output/librarian_draft
py -m src.analysis.librarian --dumps-dir output/corpus_gen/ghidra_dumps --draft-dir output/librarian_draft --accept-compiled
```

Целиком зелёные generator-дампы (assemble + gcc, без held-out): `hypot_sqrt`, `mingw_main`, `vector_reserve`, `iostream_shift`, `string_assign`, `string_find`, `set_count`, `algo_sort`, `chrono_cast`, `pair_first`, `string_substr`, `umap_count`, `vector_empty`, `string_compare`, `list_size`, `map_emplace`, `algo_reverse`, `string_append`, `vector_clear`, `cmath_fabs`, `string_erase`, `vector_resize`, `cstring_memcpy`, `cstring_memcmp`, `string_length`, `vector_pop_back`, `utility_swap`, `cstring_strlen`, `cstring_memset`, `string_c_str`, `vector_size`, `cmath_pow`, `cstring_strcmp`, `cstring_memmove`, `cstring_strcpy`, `string_clear`, `string_data`, `string_empty`, `vector_capacity`, `cmath_floor`, `cmath_sin`, `cstdio_printf`, `cmath_ceil`, `cmath_cos`, `cstring_strncpy`, `cstdio_sprintf`, `cstdlib_atoi`, `string_resize`, `string_reserve`, `pair_second`, `list_empty`, `set_empty`, `cmath_log`, `cmath_exp`, `cmath_round`, `cstring_strcat`, `cstdio_puts`, `cstdio_snprintf`, `string_push_back`, `map_size`, `set_size`, `list_clear`.

Compiler agent классифицирует gcc-диагностики по `gcc_fingerprint` корпуса
(`src/agents/compiler.py` `match_errors`). Это и есть P3: детерминированный
gcc→recipe_id, уже включён в per-fn и TU compile-fix. Известный класс — без LLM.
Неизвестный — один LLM-проход и YAML-черновик (не патч sanitizer).
Scoring ML (`train_scorer`) не используется как compile-oracle.

Из 134 фикстур 68 с `gcc_fingerprint` (классификатор), остальные — compile-ok
регрессия рецепта. Гейт классификатора синтезирует probe-сообщение из regex
(или берёт `gcc_probe`) и проверяет, что `match_errors` попадает в свой id.

Critic (`critic.json`) принимает прогон только при compile ∧ fidelity ∧ identity:
подмена `starts_with` на `std::sort` — reject, даже если TU зелёный.
`compile_ok` считается по собранному TU, не по compile-fix.

## Held-out (P2)

PointCloud и сгенерированный `heldout_struct_math` **не** используются, чтобы писать regex.
Eval только применяет корпус, Compiler agent и Critic.

```bash
py -m src.analysis.eval_heldout
```

Отчёт: `output/heldout_report.json`. Красный TU — очередь в корпус, не патч `ghidra_cpp.py`.
`--accept` на дампы с `heldout` в id запрещён.

## Метрики прогона

`RUN METRICS` + `metrics.json`: latency стадий, LLM ok/fail/fallback, polish, fidelity,
compile-verify, triage profile.

## Compile-verify (Фаза 2)

После restore каждая **user_code** функция проходит syntax-check отдельно
(`compile_fn/`). LLM compile-fix остаётся диагностикой (файл `*_fix.cpp`),
тело restore для assemble не подменяется. Затем собирается TU и проверяется
`restored_final.cpp`. `llm_best_of: 2` — второй restore при fidelity < 0.85.

CRT/STL/MinGW internals (`__mingw_*`, `_M_*`, `_pei386_*`, `fprintf`, …) **не**
попадают в LLM top.

В `config.yaml`: `compile_verify`, `compile_fix`, `compile_per_function`,
опционально `cxx_compiler` / `llm_best_of`.

## Тесты (без Ghidra/Ollama)

```bash
py -m unittest tests.test_heldout tests.test_corpus tests.test_p1_agents tests.test_phase1 tests.test_smoke -q
py -m unittest discover -s tests -v
```

Ghidra нужна только для `--ghidra` / полного пайплайна / held-out PointCloud (дамп уже в `output/cache/`).

## Структура

```
main.py
config.yaml
eval/                   # scoring-манифесты, corpus/*.yaml, heldout.yaml
scripts/                # Ghidra Java
src/
  pipeline/             # runner, metrics
  agents/               # restorer, assembler, polisher, compiler, critic
  analysis/             # triage, prompts, includes, features, scorer, fidelity, compile_verify, corpus, gen_corpus, eval_*
  domains/              # generic C++ preamble / Ghidra typedefs
  ghidra/               # cross-platform headless launcher
  llm/
legacy/                 # старый r2/LangGraph (не используется)
tests/
```

## Замечания

- Не запускайте недоверенные бинарники без изоляции: Ghidra загружает файл целиком.
- Полный multi-binary ML-датасет (5–10 labeled) — следующий шаг: наполните `eval/` и переобучите scorer.
- Generator-дампы, которые ещё не собираются целиком (очередь корпуса, не PointCloud):
  `map_count` (`mapped_type*` для `operator[]`, это `T&`),
  `init_list_vector` (`reference` как `T&`, не `T*`),
  `deque_push` / `uset_count` / `mset_count` (`this` в сигнатуре),
  `fstream_write` (`ios::good()` без объекта — без честного receiver не чинить),
  `optional_value` / `algo_fill` (внутренности `remove_cv_t` / `__fill_a1`).
