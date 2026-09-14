# Sample binaries for multi-binary eval

Built with MinGW (`samples/build_samples.ps1`): `-std=c++17 -O0 -g`.

| Binary | Focus for Reverser |
|--------|--------------------|
| `EchoFilter.exe` | strings, iostream, filtering |
| `PointCloud.exe` | **held-out (P2)**: structs, math, printf. Рецепты по нему не пишут. |
| `IniMini.exe` | parsing, maps, branching |
| `XorCipher.exe` | byte loops, buffers |
| `FibTimer.exe` | numeric loops, chrono |
| `TaskBoard.exe` | structs, vector, map, sort (apply-only; рецепты по нему не пишут) |
| `NetPath.exe` | graph, pair, unordered_map (apply-only; do not write recipes from it) |
| `GammaFn.exe` | MPFR Gamma + GMP factorial (Collatz-level library types; freeze; do not write recipes) |
| `MyCollatz.exe` | legacy GMP/MSVC Debug reference |

## ISO language probes (sources only, 09.09)

Eighteen `.cpp` files named after keywords / alternative tokens (cppreference-style).
**Not in live p4.** Batch via `py -m src.analysis.probe_cohort --cohort iso_cxx17 --compile --ghidra --scan`.
Do not freeze keyword filenames (`break`, `const`, `case`, …) as sample tokens.
14.09 cohort: 15/15 C++17 dumps covered after alt-token recipes.
14.09 `iso_cxx20`: 3/3 leftover 0 (`consteval1`, `co_await`, `co_yield`).
ISO keywords never appear in Ghidra, including coroutine tokens.
Control / EH / casts / lambdas / coroutines: no new leftover ops.
Do not freeze `co_await` / `co_yield` / `consteval1`. Not live p4.

| Group | Files | Why it matters for restore |
|-------|--------|----------------------------|
| Alternative tokens | `and_eq`, `bitand`, `bitor`, `compl` | ISO `&=` / `&` / `\|` / `~`. Cohort dump: tokens gone. Corpus `ghidra-operator-and-eq`, `ghidra-operator-bitand`, `ghidra-operator-bitor`, `ghidra-operator-compl`, plus `ghidra-operator-or-eq` / `ghidra-operator-lshift-targs`. Not live. |
| Control flow | `break`, `case`, `continue` | fallthrough, nested break vs continue |
| Exceptions | `catch1`, `catch2`, `const` (function-try) | try/catch vs Ghidra EH; ctor function-try |
| cv / casts | `const_cast` | Must not become a c_str recipe |
| Compile-time | `consteval1`, `constexpr1` | Often folded away; restore may lack the helper |
| Closures | `consteval2`, `consteval3`, `constexpr2` | Lambdas / `std::function`; `consteval2` is captures, not consteval. `constexpr2` ≈ `consteval3` |
| Coroutines C++20 | `co_await`, `co_yield` | Compiler FSM; `-std=c++20`. 14.09 dump: tokens gone, leftover 0. Not live. |

## Stdlib and filesystem probes (14.09)

274 `std_*.cpp` plus 26 `fs_*.cpp` (cppreference-style). **No `.exe`.**
Not in live p4, not in `build_samples.ps1`. Golden stdout / dialect classes,
not a 300-binary restore queue. Do not write sanitizer recipes from their
dumps. Do not freeze filenames (`isnan`, `exists`, …) as sample tokens.

Batch: `py -m src.analysis.probe_cohort --cohort std_repr --compile` (one
file per header, not 274 Ghidra dumps). 14.09: std_repr 29/29 leftover 0;
fs_repr 3/3 leftover 0 after `ghidra-filesystem-operator-lshift-targs`
(generic mix, not `exists`). Do not write recipes from printed filesystem
paths. i5_first_wave 6/6 leftover 0; fs_repr golden: `file_size` /
`current_path` masked, `fs_exists` skipped (`create_symlink`
unimplemented on this MinGW). Expect snippets in
`eval/i5_probe_index.yaml`, not in `eval_behavior.CASES`. `std_count.cpp`
needs C++20 constexpr `count_if`. 14.09 `std_cxx20` 6/6 leftover 0 after
`ghidra-detail-operator-lshift-linebreak` (generic mix, not `erase1`).
14.09 `iso_cxx20` 3/3 leftover 0; coroutine keywords absent from Ghidra.
Do not add fs/std/iso exe to live 9.

Total in `samples/`: 327 `.cpp`, 9 `.exe` (application cohort only).


Rebuild application samples:

```powershell
powershell -ExecutionPolicy Bypass -File samples/build_samples.ps1
```

Pipeline smoke (after Ghidra+Ollama up):

```powershell
py main.py --binary samples/EchoFilter.exe
```
