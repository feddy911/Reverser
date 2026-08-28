from __future__ import annotations

"""Error-class corpus: Ghidra dialect snippets + recipes, not user binaries.

A case is one dialect class (ostream cast, mpz_t*, DAT stub, …). Regression
is `py -m src.analysis.eval_corpus`, not a green TU on the last sample.

YAML fields:
  id, profile, recipe, ghidra_cpp
  gcc_fingerprint   optional regex (for a future Compiler agent)
  contains / not_contains
  compile           syntax-check the recipe output (skipped if no compiler)
  requires          e.g. [gmp] — skip compile if the header is missing
  guessed_name      assemble: emitted function name (default: f)
  extra_functions   assemble: [{name, cpp}, ...] other TU members
  notes

Recipes (do not add sanitizer regex here):
  sanitize                 sanitize_ghidra_cpp
  assemble                 assembler.assemble
  sanitize_then_assemble   sanitize each body, then assemble
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

RECIPES = ("sanitize", "assemble", "sanitize_then_assemble")
DEFAULT_CORPUS_DIR = Path(__file__).resolve().parents[2] / "eval" / "corpus"


@dataclass
class CorpusCase:
    id: str
    profile: str
    recipe: str
    ghidra_cpp: str
    path: Path
    gcc_fingerprint: str = ""
    contains: List[str] = field(default_factory=list)
    not_contains: List[str] = field(default_factory=list)
    compile: bool = False
    requires: List[str] = field(default_factory=list)
    guessed_name: str = "f"
    extra_functions: List[Dict[str, str]] = field(default_factory=list)
    notes: str = ""


def _as_str_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(x) for x in value]


def load_case(path: Path) -> CorpusCase:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping")
    cid = str(data.get("id") or path.stem).strip()
    recipe = str(data.get("recipe") or "sanitize").strip()
    if recipe not in RECIPES:
        raise ValueError(f"{path}: unknown recipe {recipe!r}")
    cpp = data.get("ghidra_cpp")
    if not isinstance(cpp, str) or not cpp.strip():
        raise ValueError(f"{path}: ghidra_cpp is required")
    extras: List[Dict[str, str]] = []
    for item in data.get("extra_functions") or []:
        extras.append({
            "name": str(item.get("name") or "").strip(),
            "cpp": str(item.get("cpp") or ""),
        })
    return CorpusCase(
        id=cid,
        profile=str(data.get("profile") or "generic").strip(),
        recipe=recipe,
        ghidra_cpp=cpp,
        path=path,
        gcc_fingerprint=str(data.get("gcc_fingerprint") or ""),
        contains=_as_str_list(data.get("contains")),
        not_contains=_as_str_list(data.get("not_contains")),
        compile=bool(data.get("compile", False)),
        requires=_as_str_list(data.get("requires")),
        guessed_name=str(data.get("guessed_name") or "f").strip() or "f",
        extra_functions=extras,
        notes=str(data.get("notes") or ""),
    )


def load_corpus(directory: Optional[Path] = None) -> List[CorpusCase]:
    root = Path(directory) if directory is not None else DEFAULT_CORPUS_DIR
    if not root.is_dir():
        raise FileNotFoundError(f"corpus dir missing: {root}")
    cases: List[CorpusCase] = []
    seen: Dict[str, Path] = {}
    for path in sorted(root.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        case = load_case(path)
        if case.id in seen:
            raise ValueError(
                f"duplicate corpus id {case.id!r}: {seen[case.id]} and {path}"
            )
        seen[case.id] = path
        cases.append(case)
    return cases


def _restored_entry(name: str, cpp: str, addr: str) -> Dict[str, Any]:
    return {
        "classification": "user_code",
        "address": addr,
        "guessed_name": name,
        "ghidra_name": f"FUN_{addr}",
        "cpp_code": cpp,
    }


def _assemble_text(case: CorpusCase, bodies_sanitized: bool) -> str:
    from src.agents.assembler import assemble
    from src.analysis.ghidra_cpp import sanitize_ghidra_cpp
    from src.analysis.includes import make_preamble

    def maybe(text: str) -> str:
        return sanitize_ghidra_cpp(text) if bodies_sanitized else text

    restored = [
        _restored_entry(case.guessed_name, maybe(case.ghidra_cpp), "0x1")
    ]
    for i, extra in enumerate(case.extra_functions, start=2):
        name = extra.get("name") or f"extra_{i}"
        restored.append(
            _restored_entry(name, maybe(extra.get("cpp") or ""), f"0x{i}")
        )
    preamble = make_preamble(f"// corpus {case.id}", restored, [])
    text, _n = assemble(restored, [], [], preamble_lines=preamble)
    return text


def apply_recipe(case: CorpusCase) -> str:
    from src.analysis.ghidra_cpp import sanitize_ghidra_cpp

    if case.recipe == "sanitize":
        return sanitize_ghidra_cpp(case.ghidra_cpp)
    if case.recipe == "assemble":
        return _assemble_text(case, bodies_sanitized=False)
    if case.recipe == "sanitize_then_assemble":
        return _assemble_text(case, bodies_sanitized=True)
    raise ValueError(f"unknown recipe {case.recipe!r}")


def _looks_like_unit(text: str) -> bool:
    return bool(
        text.lstrip().startswith("#")
        or "struct " in text[:400]
        or "inline " in text[:800]
    )


def _as_compile_body(got: str) -> str:
    blob = (got or "").strip()
    if not blob:
        return "void corpus_fn() {}\n"
    if _looks_like_unit(blob) or "{" in blob:
        return blob
    if blob.rstrip().endswith(";") and "(" in blob:
        return blob
    return f"void corpus_fn() {{\n{blob}\n}}\n"


def _gmp_available(compiler: str) -> bool:
    from src.analysis.compile_verify import compile_cpp

    import tempfile

    src = "#include <gmp.h>\nint corpus_gmp_probe() { return 0; }\n"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "gmp_probe.cpp"
        p.write_text(src, encoding="utf-8")
        return bool(compile_cpp(p, compiler=compiler, timeout_sec=20).ok)


def eval_case(
    case: CorpusCase,
    *,
    compiler: str = "",
    do_compile: bool = True,
) -> Dict[str, Any]:
    from src.analysis.compile_verify import compile_cpp, compile_snippet, find_cxx_compiler
    from src.analysis.includes import make_preamble

    result: Dict[str, Any] = {
        "id": case.id,
        "profile": case.profile,
        "recipe": case.recipe,
        "path": str(case.path),
        "ok": True,
        "errors": [],
        "compile": {"skipped": True, "reason": "not requested"},
    }
    try:
        got = apply_recipe(case)
    except Exception as exc:
        result["ok"] = False
        result["errors"].append(f"recipe failed: {exc}")
        return result

    result["got_preview"] = got[:1200]
    for needle in case.contains:
        if needle not in got:
            result["ok"] = False
            result["errors"].append(f"missing contains: {needle!r}")
    for needle in case.not_contains:
        if needle in got:
            result["ok"] = False
            result["errors"].append(f"hit not_contains: {needle!r}")

    if not (do_compile and case.compile):
        return result

    cxx = find_cxx_compiler(compiler)
    if not cxx:
        result["compile"] = {"skipped": True, "reason": "no C++ compiler"}
        return result
    if "gmp" in case.requires and not _gmp_available(cxx):
        result["compile"] = {"skipped": True, "reason": "gmp.h not available"}
        return result

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        if case.recipe == "sanitize":
            preamble = make_preamble(
                "// corpus",
                [{"cpp_code": got, "ext_calls": [], "includes": []}],
                [],
            )
            crep = compile_snippet(
                _as_compile_body(got),
                preamble_lines=preamble,
                work_dir=work,
                name=case.id,
                compiler=cxx,
            )
        else:
            src = work / f"{case.id}.cpp"
            src.write_text(got + "\n", encoding="utf-8")
            crep = compile_cpp(src, compiler=cxx, timeout_sec=30)
    result["compile"] = {
        "skipped": False,
        "ok": bool(crep.ok),
        "n_errors": crep.n_errors,
        "stderr": (crep.stderr or "")[-1500:],
    }
    if not crep.attempted:
        result["compile"]["skipped"] = True
        result["compile"]["reason"] = crep.skipped_reason
        return result
    if not crep.ok:
        result["ok"] = False
        result["errors"].append(
            f"compile failed ({crep.n_errors} errors)"
        )
    return result


def eval_corpus(
    directory: Optional[Path] = None,
    *,
    compiler: str = "",
    do_compile: bool = True,
    ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    want = set(ids) if ids else None
    cases = load_corpus(directory)
    results = []
    for case in cases:
        if want is not None and case.id not in want:
            continue
        results.append(
            eval_case(case, compiler=compiler, do_compile=do_compile)
        )
    n_ok = sum(1 for r in results if r.get("ok"))
    return {
        "n_cases": len(results),
        "n_ok": n_ok,
        "n_fail": len(results) - n_ok,
        "results": results,
    }
