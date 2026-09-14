from __future__ import annotations

"""Batch compile + Ghidra dump of samples/*.cpp cohorts. Not live restore.

Drafts stay under output/; they are not auto-accepted into eval/corpus/.
One representative per dialect class, not 327 restores.

  py -m src.analysis.probe_cohort --list
  py -m src.analysis.probe_cohort --cohort iso_cxx17 --compile
  py -m src.analysis.probe_cohort --cohort iso_cxx17 --ghidra --config config.yaml
  py -m src.analysis.probe_cohort --cohort iso_cxx17 --scan
  py -m src.analysis.probe_cohort --cohort i5_first_wave --compile --golden
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples"
DEFAULT_OUT = ROOT / "output" / "iso_probes"

_STD_CXX20_HDR = frozenset({"format", "span", "bit", "compare"})
_STD_CXX20_STEMS = frozenset({
    "std_format", "std_bit_cast", "std_as_bytes", "std_cmp",
    "std_erase1", "std_compare_weak_order_fallback",
})
_ISO_CXX20 = frozenset({"co_await", "co_yield", "consteval1"})
_ISO_ALL = (
    "and_eq", "bitand", "bitor", "compl",
    "break", "case", "continue",
    "catch1", "catch2", "const",
    "const_cast",
    "consteval1", "constexpr1",
    "consteval2", "consteval3", "constexpr2",
    "co_await", "co_yield",
)

_ISO_KW = (
    "and_eq", "bitand", "bitor", "compl", "or_eq", "xor_eq",
    "co_await", "co_yield", "co_return",
)

_OP_LEFTOVER = (
    "std::operator&",
    "std::operator|",
    "std::operator~",
    "std::operator^",
    "::operator&=",
    "::operator|=",
    "::operator^=",
    "::operator~",
    "operator<<_",
    "__detail::operator<<",
    "filesystem::operator<<",
)

_USER_NAME = re.compile(
    r"^(main|show|demo_\w+)$|operator[&|^~]"
)


def _iso_cxx17() -> List[str]:
    return [s for s in _ISO_ALL if s not in _ISO_CXX20]


def _index_bucket(bucket_id: str) -> Dict[str, Any]:
    path = ROOT / "eval" / "i5_probe_index.yaml"
    import yaml

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for bucket in data.get("buckets") or []:
        if str(bucket.get("id") or "") == bucket_id:
            return dict(bucket)
    return {}


def _stems_from_index(bucket_id: str) -> List[str]:
    out: List[str] = []
    for name in _index_bucket(bucket_id).get("examples") or []:
        stem = Path(str(name)).stem
        if stem:
            out.append(stem)
    return out


def _expect_for_stem(bucket_id: str, stem: str) -> Dict[str, Any]:
    expect = _index_bucket(bucket_id).get("expect") or {}
    rec = expect.get(stem)
    return dict(rec) if isinstance(rec, dict) else {}


def _std_repr_stems() -> List[str]:
    """One std_* file per primary #include. Not a 274-dump queue."""
    inc_re = re.compile(r"#include\s*<([^>]+)>")
    by_hdr: Dict[str, str] = {}
    for path in sorted(SAMPLES.glob("std_*.cpp")):
        if path.stem in _STD_CXX20_STEMS:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        found = inc_re.findall(text)
        key = (found[0] if found else path.stem).split("/")[-1]
        hdr = key.split(".")[0]
        if hdr in _STD_CXX20_HDR:
            continue
        by_hdr.setdefault(key, path.stem)
    return [by_hdr[k] for k in sorted(by_hdr)]


def _fs_repr_stems() -> List[str]:
    return _stems_from_index("fs_mask_paths") or [
        "fs_exists", "fs_file_size", "fs_current_path",
    ]


def cohort_stems(name: str) -> List[str]:
    key = (name or "").strip().lower()
    if key == "iso_cxx17":
        return _iso_cxx17()
    if key == "iso_cxx20":
        return list(_ISO_CXX20)
    if key == "iso_alt":
        return ["and_eq", "bitand", "bitor", "compl"]
    if key == "iso_all":
        return list(_ISO_ALL)
    if key == "i5_first_wave":
        return _stems_from_index("first_wave_cxx17")
    if key == "std_repr":
        return _std_repr_stems()
    if key == "std_cxx20":
        return sorted(_STD_CXX20_STEMS)
    if key == "fs_repr":
        return _fs_repr_stems()
    raise KeyError(f"unknown cohort {name!r}")


def list_cohorts() -> Dict[str, List[str]]:
    names = (
        "iso_alt", "iso_cxx17", "iso_cxx20", "iso_all",
        "i5_first_wave", "std_repr", "std_cxx20", "fs_repr",
    )
    return {n: cohort_stems(n) for n in names}


def compile_stem(
    stem: str,
    *,
    out_dir: Path,
    cxx: str,
    std: str = "c++17",
) -> Dict[str, Any]:
    src = SAMPLES / f"{stem}.cpp"
    rec: Dict[str, Any] = {"id": stem, "src": str(src)}
    if not src.exists():
        rec["ok"] = False
        rec["error"] = "missing source"
        return rec
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = out_dir / f"{stem}.exe"
    proc = subprocess.run(
        [cxx, f"-std={std}", "-O0", "-g", str(src), "-o", str(exe)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    rec["ok"] = proc.returncode == 0
    rec["exe"] = str(exe)
    if proc.returncode != 0:
        rec["stderr"] = (proc.stderr or "")[-800:]
    return rec


def dump_path(out_dir: Path, stem: str) -> Path:
    return out_dir / f"{stem}_ghidra.json"


def ghidra_stem(
    stem: str,
    *,
    out_dir: Path,
    ghidra_path: Path,
    timeout_sec: int,
    force: bool = False,
) -> Dict[str, Any]:
    from src.ghidra.headless import run_ghidra_decompile

    exe = out_dir / f"{stem}.exe"
    rec: Dict[str, Any] = {"id": stem, "exe": str(exe)}
    if not exe.exists():
        rec["ok"] = False
        rec["error"] = "missing exe; compile first"
        return rec
    dump = dump_path(out_dir, stem)
    rec["dump"] = str(dump)
    if dump.exists() and not force:
        rec["ok"] = True
        rec["cached"] = True
        return rec
    try:
        run_ghidra_decompile(
            ghidra_path,
            exe,
            out_dir / f"{stem}_proj",
            [ROOT / "scripts", ROOT / "src" / "ghidra"],
            dump,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        rec["ok"] = False
        rec["error"] = str(exc)
        return rec
    rec["ok"] = True
    rec["cached"] = False
    return rec


def _interesting(fn: Dict[str, Any]) -> bool:
    name = str(fn.get("name") or "")
    if _USER_NAME.search(name):
        return True
    if name in {"main", "show"}:
        return True
    return False


def scan_dump(path: Path) -> Dict[str, Any]:
    from src.analysis.ghidra_cpp import sanitize_ghidra_cpp
    from src.analysis.platform import is_runtime_noise

    data = json.loads(path.read_text(encoding="utf-8"))
    fns = data.get("functions") or []
    iso_hits: List[str] = []
    leftover: List[str] = []
    names: List[str] = []
    chunks: List[str] = []
    for fn in fns:
        name = str(fn.get("name") or "")
        code = str(fn.get("ghidra_code") or "")
        if not code:
            continue
        if _interesting(fn) or (
            not is_runtime_noise(name) and name in {"main", "show"}
        ):
            names.append(name)
            chunks.append(code)
        for kw in _ISO_KW:
            if re.search(rf"\b{re.escape(kw)}\b", code) and kw not in iso_hits:
                iso_hits.append(kw)
    blob = "\n".join(chunks)
    got = sanitize_ghidra_cpp(blob) if blob else ""
    for tok in _OP_LEFTOVER:
        if tok in got and tok not in leftover:
            leftover.append(tok)
    return {
        "n_functions": len(fns),
        "user_fns": names[:20],
        "iso_in_ghidra": iso_hits,
        "sanitize_leftover": leftover,
    }


def scan_out_dir(stems: Sequence[str], out_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for stem in stems:
        dump = dump_path(out_dir, stem)
        rec: Dict[str, Any] = {"id": stem}
        if not dump.exists():
            rec["ok"] = False
            rec["error"] = "dump missing"
            rows.append(rec)
            continue
        rec["ok"] = True
        rec.update(scan_dump(dump))
        rows.append(rec)
    return rows


def _std_flag(cohort: str) -> str:
    if cohort in {"iso_cxx20", "std_cxx20"}:
        return "c++20"
    return "c++17"


_COHORT_BUCKET = {
    "i5_first_wave": "first_wave_cxx17",
    "fs_repr": "fs_mask_paths",
}


def _cohort_mask(cohort: str) -> str:
    bucket_id = _COHORT_BUCKET.get(cohort)
    if not bucket_id:
        return "none"
    return str(_index_bucket(bucket_id).get("mask") or "none")


def golden_stem(
    stem: str,
    *,
    out_dir: Path,
    mask: str = "none",
    expect: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from src.analysis.eval_behavior import mask_paths, mask_stdout, run_exe

    exe = out_dir / (f"{stem}.exe" if sys.platform == "win32" else stem)
    rec: Dict[str, Any] = {"id": stem, "exe": str(exe), "mask": mask}
    want = expect or {}
    if want.get("skip"):
        rec["ok"] = True
        rec["skipped"] = True
        rec["skip_reason"] = str(want["skip"])
        rec["reason"] = rec["skip_reason"]
        rec["stdout"] = ""
        rec["stdout_masked"] = ""
        return rec
    if not exe.exists():
        rec["ok"] = False
        rec["error"] = "exe missing (compile first)"
        return rec
    run = run_exe(exe, [], cwd=ROOT)
    stdout = mask_stdout(run.get("stdout") or "")
    body = mask_paths(stdout) if mask == "paths" else stdout
    rec["ok"] = not run.get("skipped")
    rec["skipped"] = bool(run.get("skipped"))
    rec["exit"] = run.get("exit")
    rec["reason"] = run.get("reason") or ""
    rec["stdout"] = stdout
    rec["stdout_masked"] = body
    rec["stderr"] = (run.get("stderr") or "")[-400:]
    if rec.get("exit") not in (0, None) and want.get("exit") is None:
        rec["ok"] = False
        code = rec.get("exit")
        if code == 3221225477:
            rec["error"] = "process crashed (STATUS_ACCESS_VIOLATION)"
        elif code == 3221226505:
            rec["error"] = "process aborted (STATUS_STACK_BUFFER_OVERRUN)"
        else:
            rec["error"] = f"exit={code}"
    if want.get("empty") and body:
        rec["ok"] = False
        rec["error"] = "expected empty stdout"
    missing = [s for s in (want.get("contains") or []) if s not in body]
    if missing:
        rec["ok"] = False
        rec["missing"] = missing
    want_exit = want.get("exit")
    if want_exit is not None and rec.get("exit") != want_exit:
        rec["ok"] = False
        rec["error"] = f"exit={rec.get('exit')} want={want_exit}"
    return rec


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Batch probe compile/dump/scan")
    parser.add_argument("--cohort", default="iso_cxx17")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--compile", action="store_true")
    parser.add_argument("--ghidra", action="store_true")
    parser.add_argument("--scan", action="store_true")
    parser.add_argument(
        "--golden",
        action="store_true",
        help="run compiled probes and write masked stdout (not live restore)",
    )
    parser.add_argument("--force-ghidra", action="store_true")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list:
        for name, stems in list_cohorts().items():
            print(f"{name}\t{len(stems)}\t{', '.join(stems[:8])}"
                  + ("..." if len(stems) > 8 else ""))
        return 0

    try:
        stems = cohort_stems(args.cohort)
    except KeyError as exc:
        print(f"FAIL: {exc}")
        return 2

    out_dir = Path(args.out)
    std = _std_flag(args.cohort)
    rc = 0
    print(f"cohort {args.cohort} n={len(stems)} std={std} out={out_dir}")

    if args.compile or args.ghidra:
        from src.analysis.compile_verify import find_cxx_compiler

        cxx = find_cxx_compiler()
        if not cxx:
            print("FAIL: no C++ compiler")
            return 2
        for stem in stems:
            rec = compile_stem(stem, out_dir=out_dir, cxx=cxx, std=std)
            if rec.get("ok"):
                print(f"  compile OK {stem}")
            else:
                rc = 1
                print(f"  compile FAIL {stem}: {rec.get('error') or rec.get('stderr')}")

    if args.ghidra:
        from src.config import load_config

        cfg = load_config(args.config)
        if not cfg.ghidra_path:
            print("FAIL: ghidra_path missing")
            return 2
        for stem in stems:
            rec = ghidra_stem(
                stem,
                out_dir=out_dir,
                ghidra_path=Path(cfg.ghidra_path),
                timeout_sec=cfg.ghidra_timeout,
                force=args.force_ghidra,
            )
            tag = "cached" if rec.get("cached") else ("OK" if rec.get("ok") else "FAIL")
            extra = rec.get("error") or ""
            print(f"  ghidra {tag} {stem} {extra}")
            if not rec.get("ok"):
                rc = 1

    if args.scan:
        rows = scan_out_dir(stems, out_dir)
        n_left = sum(1 for r in rows if r.get("sanitize_leftover"))
        n_iso = sum(1 for r in rows if r.get("iso_in_ghidra"))
        print(f"scan leftover_ops={n_left} iso_tokens={n_iso}/{len(rows)}")
        for r in rows:
            if not r.get("ok"):
                print(f"  MISS {r['id']}: {r.get('error')}")
                rc = 1
                continue
            left = r.get("sanitize_leftover") or []
            iso = r.get("iso_in_ghidra") or []
            mark = "NEW" if left or iso else "covered"
            print(
                f"  {mark} {r['id']} fns={r.get('n_functions')} "
                f"iso={iso} leftover={left} user={r.get('user_fns')}"
            )
        report = out_dir / f"scan_{args.cohort}.json"
        report.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"wrote {report}")

    if args.golden:
        mask = _cohort_mask(args.cohort)
        bucket_id = _COHORT_BUCKET.get(args.cohort, "")
        gold: List[Dict[str, Any]] = []
        n_ok = 0
        n_skip = 0
        for stem in stems:
            rec = golden_stem(
                stem,
                out_dir=out_dir,
                mask=mask,
                expect=_expect_for_stem(bucket_id, stem) if bucket_id else {},
            )
            gold.append(rec)
            if rec.get("skip_reason"):
                n_skip += 1
                print(f"  golden SKIP {stem}: {rec.get('skip_reason')}")
            elif rec.get("ok"):
                n_ok += 1
                print(f"  golden OK {stem} exit={rec.get('exit')} bytes={len(rec.get('stdout_masked') or rec.get('stdout') or '')}")
            else:
                rc = 1
                extra = rec.get("missing") or rec.get("error") or rec.get("reason")
                print(f"  golden FAIL {stem}: {extra}")
        report = out_dir / f"golden_{args.cohort}.json"
        report.write_text(json.dumps(gold, indent=2), encoding="utf-8")
        print(f"golden {n_ok}/{len(stems)} skip={n_skip} mask={mask} wrote {report}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
