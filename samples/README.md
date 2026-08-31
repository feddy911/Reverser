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

Rebuild:

```powershell
powershell -ExecutionPolicy Bypass -File samples/build_samples.ps1
```

Pipeline smoke (after Ghidra+Ollama up):

```powershell
py main.py --binary samples/EchoFilter.exe
```
