# Reverser

A multi-stage pipeline that recovers C++ from an arbitrary executable:
**triage → Ghidra → score → LLM restore → assemble → (optional) polish / fidelity**.

## Requirements

- Python 3.10+
- [Ghidra](https://ghidra-sre.org/) (headless; Windows `.bat` or Unix `analyzeHeadless`)
- [Ollama](https://ollama.com/) plus the model in `config.yaml` (default `qwen2.5-coder:14b-instruct-q5_K_M`)

```bash
pip install -r requirements.txt
```

## Quick start

1. Edit `config.yaml`: `binary_path`, `ghidra_path`, `ollama_url`.
2. Run the pipeline. There are no sample-specific hints: the binary is treated as unknown.

```bash
py main.py --config config.yaml
# or
py main.py --binary path/to/app.exe
```

Run artifacts land in `output/logs/run_<timestamp>/`
(`triage.json`, `ghidra_raw.json`, `features.json`, `restored*.cpp`, `fidelity.json`, `metrics.json`).

An empty Ghidra dump is a hard failure; the pipeline does not continue with a blank restore.

## Triage and prompt profiles

`src/analysis/triage.py` detects format (PE/ELF/Mach-O), arch, compiler, Debug/Release
and selects a profile (`msvc_x64_debug`, `gcc_elf_x64`, `generic`, …).

The restorer loads system/user rules from `src/analysis/prompts.py` for that profile.

## Includes

`#include` lines are collected dynamically from the binary's `ext_calls` / `ext_dlls`
(`src/analysis/includes.py`). GMP is added when the dump has `mpz_*` or `gmp.dll`,
MPFR when it has `mpfr_*` / `libmpfr` — not from a hard-coded sample name.

## Scoring

- `scoring_mode: heuristic` — weights in `src/analysis/scorer.py` (unbounded; CRT names get large negatives)
- `scoring_mode: ml` — model from `ml_weights_path` (meta JSON + joblib). `predict_proba` is already in `[0, 1]`. Runtime-noise names are mapped into `[0, 0.5)` so they never outrank a user function; user scores occupy `[0.5, 1]`. The old `p - 10` (CRT at `-9.7` in TOP-15) was the same ranking, not a broken model. Not a 23rd feature.

```bash
py -m src.analysis.train_scorer --help
py -m src.analysis.eval_scorer_l1o --manifest eval/manifest.yaml
```

`eval_scorer_l1o` is leave-one-binary-out over `eval/manifest.yaml`: heuristic / logreg / RF /
a tree with `max_depth=4`, the same 22 `FEATURE_KEYS`. Named dumps report filtered name recall@15.
FUN_* dumps (`mycollatz`, `fibtimer_nosym`) report address recall@15 from a labels JSON.
A named/stripped twin shares `family` and is dropped from that fold's train set so ML cannot
see the same functions with symbols. gcc text is not a feature, and this track is not a compile-gate.

## Eval harness (scoring-only, Q6)

A separate track from the compile-gate. Manifest: `eval/manifest.yaml` — named dumps plus
two FUN_* dumps with address labels (`labels_MyCollatz.json`, `eval/labels_fibtimer_nosym.json`).
If there is no dump in `output/cache/`, the entry is skipped (CI without Ghidra). No assemble, no gcc, no recipes.

```bash
py -m src.analysis.eval_harness --manifest eval/manifest.yaml
py -m src.analysis.eval_harness --fixture tests/fixtures/mini_ghidra.json
```

Report: `output/eval_report.json` (name recall@k, including after the CRT filter).
L1O: `output/scorer_l1o.json`. `train_scorer` is not a compile oracle and does not train on gcc diagnostics.

## Ghidra dialect corpus (compile-gate)

New rewrites in `ghidra_cpp.py` / `assembler.py` are not added from a single exe run.
First a fixture in `eval/corpus/<id>.yaml` (snippet + recipe + contains / not_contains), then the recipe.
Field schema: `eval/corpus/_schema.yaml`. There are currently **161** loadable fixtures.

```bash
py -m src.analysis.eval_corpus
py -m src.analysis.eval_corpus --dir eval/corpus --out output/corpus_report.json
py -m src.analysis.eval_classifier
```

Freeze: do not put PointCloud / EchoFilter / MyCollatz / IniMini /
TaskBoard / NetPath / GammaFn / `starts_with` names into the sanitizer or assembler.
Per-function compile-fix writes `compile_fn/*_fix.cpp` and cache `kind=compile_fn_fix`.
It does **not** overwrite the restore cache and does not replace `cpp_code` used by assemble.

## Generator, librarian, Compiler agent, Critic

The corpus is filled from mini-programs (string/vector/iostream/chrono/GMP/main), not from a user exe:

```bash
py -m src.analysis.gen_corpus --out output/corpus_gen --compile --vary
# Ghidra dumps of mini-programs (needs ghidra_path in config.yaml):
py -m src.analysis.gen_corpus --ghidra --config config.yaml
```

`--vary` renames identifiers in fixtures: a recipe must not be glued to `prefixPtr`.

Fill rule (Q1): accept a dump into the corpus if it is green **without a new regex**, or if there is an honest
`gcc_fingerprint` and the fixture exists **before** the recipe. Do not mint compile-ok YAML with an empty
fingerprint just to grow the count. Do not patch the red generator dumps listed below.

Q3b (lab, not restore): the same unknown→mini→fixture loop can run offline (`dialect_loop`) —
a queue of normalized diagnostics, a mini catalog, Ghidra, YAML before any recipe. Lexical changes are a
replacement table; structural patches are not auto-merged; red-eight semantics (`T&` vs `T*`, `ios::good()`
with no object) and placeholder iterators / keys (`sort<__normal_iterator`, `key_type` as `ghidra_word`)
are skip-forever. Live `match_errors` uses the same rule: no LLM. `main.py` does not patch the sanitizer.

```bash
py -m src.analysis.dialect_loop --from-report output/apply_inimini_report.json
py -m src.analysis.dialect_loop --message "invalid cast from type '__const_iterator'..." --emit
py -m src.analysis.dialect_loop --message "..." --emit --dumps-dir output/corpus_gen/ghidra_dumps
# optional: --ghidra --config config.yaml  (dump + token check)
```

The command does not patch `ghidra_cpp.py` and does not copy YAML into `eval/corpus/`. Default budget is one mini.
A known fingerprint → skip; red eight → skip-forever; restore/compile TU (`compile.json` with `assembled_ok`) is refused;
missing quotes / `else` without `if` are restore debris, not catalog; otherwise catalog or `no_catalog`.

The librarian drafts YAML from a dump and accepts it into `eval/corpus/` only after a green `eval_case`.
Held-out / sample names (`heldout`, `pointcloud`, `echofilter`, `mycollatz`, …) are refused.

```bash
py -m src.analysis.librarian --dumps-dir output/corpus_gen/ghidra_dumps --draft-dir output/librarian_draft
py -m src.analysis.librarian --dumps-dir output/corpus_gen/ghidra_dumps --draft-dir output/librarian_draft --accept-compiled
```

Fully green generator dumps (assemble + gcc, not held-out): `hypot_sqrt`, `mingw_main`, `vector_reserve`, `iostream_shift`, `string_assign`, `string_find`, `set_count`, `algo_sort`, `chrono_cast`, `pair_first`, `string_substr`, `umap_count`, `vector_empty`, `string_compare`, `list_size`, `map_emplace`, `algo_reverse`, `string_append`, `vector_clear`, `cmath_fabs`, `string_erase`, `vector_resize`, `cstring_memcpy`, `cstring_memcmp`, `string_length`, `vector_pop_back`, `utility_swap`, `cstring_strlen`, `cstring_memset`, `string_c_str`, `vector_size`, `cmath_pow`, `cstring_strcmp`, `cstring_memmove`, `cstring_strcpy`, `string_clear`, `string_data`, `string_empty`, `vector_capacity`, `cmath_floor`, `cmath_sin`, `cstdio_printf`, `cmath_ceil`, `cmath_cos`, `cstring_strncpy`, `cstdio_sprintf`, `cstdlib_atoi`, `string_resize`, `string_reserve`, `pair_second`, `list_empty`, `set_empty`, `cmath_log`, `cmath_exp`, `cmath_round`, `cstring_strcat`, `cstdio_puts`, `cstdio_snprintf`, `string_push_back`, `map_size`, `set_size`, `list_clear`.

The Compiler agent classifies gcc diagnostics against corpus `gcc_fingerprint`
(`src/agents/compiler.py` `match_errors`). That is P3: deterministic
gcc→recipe_id, already wired into per-fn and TU compile-fix. A known class skips the LLM.
Skip-forever (red eight, placeholder iterators, `this` as a local, iterator/`char*` vs `string*`,
truncated `mpz_*` / `mpfr_*` calls, `struct` before a header typedef, undeclared Ghidra temps
`pbVarN` / `in_stack_*` / `in_RCX`, string vs `string*` assign, `operator[]` with a map pointer
as key, `vector*` vs `unordered_map*` or a user struct `T*`, `this` in a prototype, member access
on a function type) also skips the LLM: do not patch and do not call compile-fix. Unknown → one LLM pass and
a YAML draft (not a sanitizer patch).
Scoring ML (`train_scorer`) is not used as a compile oracle.

Of 161 fixtures, 95 have `gcc_fingerprint` (classifier); the rest are compile-ok
recipe regression. The gate synthesizes a probe from the regex or uses an explicit `gcc_probe`
(a realistic gcc message, when `.*` / a truncated alt would lie) and
checks that `match_errors` hits its own id. The ostream sanitize/assemble collision
is one gcc, two recipes: the gate is green by default;
`--fail-on-overlap` fails only on unexpected overlaps (the ostream pair is allowlisted).
`--list-probes` prints explicit vs synth. Do not train RF/sklearn on diagnostics.

The critic (`critic.json`) accepts a run only when compile ∧ fidelity ∧ identity hold.
Fidelity does not paper over a missing literal or `ext_calls` with a mean score ≥ 0.85 —
those are dump facts. Identity catches replacing `starts_with` with `std::sort`.
The critic does not require guessing the original source name. `compile_ok` is the assembled
TU, not compile-fix. Restore cache: `LLM_PROMPT_VER=p4`.

## Held-out (P2)

PointCloud and generated `heldout_struct_math` are **not** used to write regex.
Eval only applies the corpus, Compiler agent, and Critic.

```bash
py -m src.analysis.eval_heldout
```

Report: `output/heldout_report.json`. A red TU is a corpus queue item, not a `ghidra_cpp.py` patch.
`--accept` is forbidden on dumps whose id contains `heldout`.

## Run metrics

`RUN METRICS` plus `metrics.json`: stage latency, LLM ok/fail/fallback, polish, fidelity,
compile-verify, triage profile.

## Compile-verify (Phase 2)

After restore, each **user_code** function is syntax-checked on its own
(`compile_fn/`). LLM compile-fix stays a diagnostic (`*_fix.cpp`);
the restore body used by assemble is not replaced. Then the TU is assembled and
`restored_final.cpp` is checked. `llm_best_of: 2` runs a second restore when fidelity < 0.85.

CRT/STL/MinGW internals (`__mingw_*`, `_M_*`, `_pei386_*`, `fprintf`, …) do **not**
enter the LLM top.

In `config.yaml`: `compile_verify`, `compile_fix`, `compile_per_function`,
optional `cxx_compiler` / `llm_best_of`.

## Tests (no Ghidra/Ollama)

```bash
py -m unittest tests.test_heldout tests.test_corpus tests.test_p1_agents tests.test_phase1 tests.test_smoke -q
py -m unittest discover -s tests -v
```

Ghidra is needed only for `--ghidra` / the full pipeline / held-out PointCloud (dump already in `output/cache/`).

## Layout

```
main.py
config.yaml
eval/                   # scoring manifests, corpus/*.yaml, heldout.yaml
scripts/                # Ghidra Java
src/
  pipeline/             # runner, metrics
  agents/               # restorer, assembler, polisher, compiler, critic
  analysis/             # triage, prompts, includes, features, scorer, fidelity, compile_verify, corpus, gen_corpus, eval_*
  domains/              # generic C++ preamble / Ghidra typedefs
  ghidra/               # cross-platform headless launcher
  llm/
legacy/                 # old r2/LangGraph (unused)
tests/
```

## Notes

- Do not run untrusted binaries without isolation: Ghidra loads the whole file.
- A full multi-binary ML dataset (5–10 labeled) is a later step: fill `eval/` and retrain the scorer.
- Generator dumps that still do not assemble as a whole TU (corpus queue, not PointCloud):
  `map_count` (`mapped_type*` for `operator[]`, which is `T&`),
  `init_list_vector` (`reference` as `T&`, not `T*`),
  `deque_push` / `uset_count` / `mset_count` (`this` in the signature),
  `fstream_write` (`ios::good()` with no object — do not invent a receiver),
  `optional_value` / `algo_fill` (`remove_cv_t` / `__fill_a1` internals).
