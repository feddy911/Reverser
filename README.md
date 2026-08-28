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
2. Для эталона MyCollatz оставьте `domain_pack: mycollatz`.
3. Для **произвольного** бинарника поставьте `domain_pack: none` (без GMP/Collatz-подсказок).

```bash
py main.py --config config.yaml
# или
py main.py --binary path/to/app.exe --domain-pack none
```

Артефакты прогона: `output/logs/run_<timestamp>/`  
(`triage.json`, `ghidra_raw.json`, `features.json`, `restored*.cpp`, `fidelity.json`, `metrics.json`).

Пустой Ghidra-дамп — ошибка (fail-hard), пайплайн не продолжает «вхолостую».

## Triage и промпт-профили

`src/analysis/triage.py` определяет format (PE/ELF/Mach-O), arch, compiler, Debug/Release
и выбирает профиль (`msvc_x64_debug`, `gcc_elf_x64`, `generic`, …).

Restorer берёт system/user rules из `src/analysis/prompts.py` по этому профилю.

## Domain packs и includes

| Pack | Назначение |
|------|------------|
| `none` | Произвольный бинарник |
| `mycollatz` | Эталон MyCollatz (GMP renames + polish maps) |

`#include` собираются динамически из `ext_calls` / `ext_dlls` + pack
(`src/analysis/includes.py`).

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

## Метрики прогона

`RUN METRICS` + `metrics.json`: latency стадий, LLM ok/fail/fallback, polish, fidelity, triage profile.

## Тесты (без Ghidra/Ollama)

```bash
py -m unittest discover -s tests -v
```

## Структура

```
main.py
config.yaml
eval/                   # манифесты eval
scripts/                # Ghidra Java
src/
  pipeline/             # runner, metrics
  agents/               # restorer, assembler, polisher
  analysis/             # triage, prompts, includes, features, scorer, fidelity, eval_harness
  domains/              # optional domain packs
  ghidra/               # cross-platform headless launcher
  llm/
legacy/                 # старый r2/LangGraph (не используется)
tests/
```

## Замечания

- Не запускайте недоверенные бинарники без изоляции: Ghidra загружает файл целиком.
- Полный multi-binary ML-датасет (5–10 labeled) — следующий шаг: наполните `eval/` и переобучите scorer.
