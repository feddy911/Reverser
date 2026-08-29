# Build sample PE binaries for Reverser eval (MinGW/MSYS2 g++).
# Usage: powershell -File samples/build_samples.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }
$Samples = Join-Path $Root "samples"

$Gpp = "C:\msys64\ucrt64\bin\c++.exe"
if (-not (Test-Path $Gpp)) {
    $Gpp = (Get-Command c++ -ErrorAction SilentlyContinue).Source
}
if (-not $Gpp) {
    throw "c++/g++ not found. Install MSYS2 ucrt64 toolchain or fix PATH."
}

$Targets = @(
    "EchoFilter",
    "PointCloud",
    "IniMini",
    "XorCipher",
    "FibTimer",
    "TaskBoard",
    "NetPath"
)

Write-Host "Compiler: $Gpp"
foreach ($name in $Targets) {
    $src = Join-Path $Samples "$name.cpp"
    $exe = Join-Path $Samples "$name.exe"
    if (-not (Test-Path $src)) {
        throw "Missing source: $src"
    }
    # Debug-ish: -O0 -g for richer decompilation; PE via MinGW.
    & $Gpp -std=c++17 -O0 -g -Wall -Wextra -o $exe $src
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed: $name"
    }
    $size = (Get-Item $exe).Length
    Write-Host ("OK  {0}.exe ({1} bytes)" -f $name, $size)
}

Write-Host ""
Write-Host "Smoke-run:"
& (Join-Path $Samples "EchoFilter.exe") "TODO:" | Out-Host
& (Join-Path $Samples "PointCloud.exe") | Select-Object -First 5 | Out-Host
& (Join-Path $Samples "IniMini.exe") | Select-Object -First 6 | Out-Host
& (Join-Path $Samples "XorCipher.exe") | Out-Host
& (Join-Path $Samples "FibTimer.exe") 10 | Out-Host
& (Join-Path $Samples "TaskBoard.exe") | Out-Host
& (Join-Path $Samples "NetPath.exe") | Out-Host
Write-Host "Done."
