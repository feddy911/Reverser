# Sample binaries for multi-binary eval

Built with MinGW (`samples/build_samples.ps1`): `-std=c++17 -O0 -g`.

| Binary | Focus for Reverser |
|--------|--------------------|
| `EchoFilter.exe` | strings, iostream, filtering |
| `PointCloud.exe` | structs, math, printf |
| `IniMini.exe` | parsing, maps, branching |
| `XorCipher.exe` | byte loops, buffers |
| `FibTimer.exe` | numeric loops, chrono |
| `MyCollatz.exe` | legacy GMP/MSVC Debug эталон |

Rebuild:

```powershell
powershell -ExecutionPolicy Bypass -File samples/build_samples.ps1
```

Pipeline smoke (after Ghidra+Ollama up):

```powershell
py main.py --binary samples/EchoFilter.exe --domain-pack none
```
