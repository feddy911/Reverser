from __future__ import annotations

"""P2 held-out eval: apply corpus + Compiler agent + Critic. Do not write recipes.

  py -m src.analysis.eval_heldout
  py -m src.analysis.eval_heldout --manifest eval/heldout.yaml --out output/heldout_report.json

A held-out binary (PointCloud, or a generated program) is scored by whether
unknown gcc diagnostics become corpus *proposals*, not sanitizer patches.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

from src.agents.assembler import assemble
from src.agents.compiler import match_errors, write_proposal
from src.agents.critic import review_run
from src.analysis.corpus import load_corpus
from src.analysis.eval_harness import _load_ghidra, _score_dump
from src.analysis.fidelity import symbol_names_from_dump
from src.analysis.includes import make_preamble
from src.analysis.scorer import select_llm_targets

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "eval" / "heldout.yaml"

# Sample / function names that must not appear in sanitizer or assembler.
FROZEN_TOKENS: Sequence[str] = (
    "PointCloud",
    "nearest_index",
    "path_length",
    "print_point",
    "EchoFilter",
    "starts_with",
    "collect_matches",
    "MyCollatz",
    "CollatzState",
    "IniMini",
    "parse_ini",
    "XorCipher",
    "xor_inplace",
    "FibTimer",
    "fib_series",
    "TaskBoard",
    "rank_open",
    "tally_owners",
    "NetPath",
    "link_cities",
    "cheapest_path",
)

FROZEN_PATHS: Sequence[Path] = (
    ROOT / "src" / "analysis" / "ghidra_cpp.py",
    ROOT / "src" / "agents" / "assembler.py",
)


def _resolve(path: str, base: Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return (base / p).resolve()


def _name_eq(got: str, want: str) -> bool:
    g = (got or "").split("<", 1)[0].strip()
    return g == (want or "").strip()


def frozen_leaks(root: Optional[Path] = None) -> List[str]:
    """Tokens from held-out/sample binaries found in sanitizer/assembler."""
    hits: List[str] = []
    base = root or ROOT
    paths = (
        base / "src" / "analysis" / "ghidra_cpp.py",
        base / "src" / "agents" / "assembler.py",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for tok in FROZEN_TOKENS:
            if tok in text:
                hits.append(f"{path.name}: {tok}")
    return hits


def _select_functions(
    ghidra: Dict[str, Any],
    *,
    user_names: Optional[Sequence[str]],
    top_k: int,
) -> List[Dict[str, Any]]:
    functions = list(ghidra.get("functions") or [])
    if user_names:
        want = [n for n in user_names if n]
        picked = [
            f for f in functions
            if any(_name_eq(f.get("name") or "", n) for n in want)
        ]
        if picked:
            return picked
    scored = _score_dump(ghidra)
    top, _n = select_llm_targets(scored, top_k)
    return list(top)


def _to_restored(fn: Dict[str, Any]) -> Dict[str, Any]:
    code = (fn.get("ghidra_code") or fn.get("code") or "").strip()
    name = (fn.get("name") or "f").strip()
    return {
        "classification": "user_code",
        "address": fn.get("address") or "",
        "guessed_name": name,
        "ghidra_name": name,
        "name": name,
        "cpp_code": code,
        "ghidra_code": code,
        "literals": list(fn.get("literals") or []),
        "ext_calls": list(fn.get("ext_calls") or []),
        "callees": list(fn.get("callees") or []),
    }


def eval_heldout_entry(
    name: str,
    *,
    ghidra_json: Path,
    binary: Optional[Path] = None,
    user_names: Optional[Sequence[str]] = None,
    top_k: int = 15,
    compiler: str = "",
    proposal_dir: Optional[Path] = None,
    work_dir: Optional[Path] = None,
    corpus_cases: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """Assemble+compile Ghidra dump with frozen recipes. Unknown → proposal."""
    from src.analysis.compile_verify import compile_cpp, find_cxx_compiler
    from src.analysis.triage import triage_binary

    result: Dict[str, Any] = {
        "name": name,
        "ok": True,
        "skipped": False,
        "n_functions": 0,
        "assembled_ok": None,
        "n_errors": 0,
        "known_ids": [],
        "n_unknown": 0,
        "need_llm": False,
        "proposals": [],
        "critic": {},
        "errors": [],
        "note": "do not add sanitizer/assembler recipes from this run",
    }
    if not ghidra_json.exists():
        result["ok"] = True
        result["skipped"] = True
        result["errors"].append(f"missing ghidra_json: {ghidra_json}")
        return result

    ghidra = _load_ghidra(ghidra_json)
    selected = _select_functions(ghidra, user_names=user_names, top_k=top_k)
    restored = [_to_restored(f) for f in selected if (f.get("ghidra_code") or f.get("code") or "").strip()]
    result["n_functions"] = len(restored)
    result["function_names"] = [r.get("guessed_name") for r in restored]
    if not restored:
        result["ok"] = False
        result["errors"].append("no user functions selected")
        return result

    profile = "generic"
    if binary and binary.exists():
        profile = triage_binary(binary, ghidra=ghidra).profile

    functions = ghidra.get("functions") or []
    thunks = ghidra.get("thunks") or []
    preamble = make_preamble(
        f"// held-out {name}: corpus recipes only [profile={profile}]",
        restored,
        functions,
    )
    tu_text, n_emit = assemble(restored, functions, thunks, preamble_lines=preamble)
    result["n_emitted"] = n_emit

    work = work_dir or Path("output") / "heldout_work" / name
    work.mkdir(parents=True, exist_ok=True)
    src = work / "heldout_assembled.cpp"
    src.write_text(tu_text + "\n", encoding="utf-8")

    cases = corpus_cases if corpus_cases is not None else load_corpus()
    cxx = find_cxx_compiler(compiler)
    if not cxx:
        result["compile_skipped"] = "no C++ compiler"
        verdict = review_run(
            restored,
            ghidra_by_addr={r["address"]: r for r in restored},
            tu_text=tu_text,
            compile_ok=None,
        )
        result["critic"] = verdict.to_dict()
        return result

    crep = compile_cpp(src, compiler=cxx, timeout_sec=60)
    result["assembled_ok"] = bool(crep.ok) if crep.attempted else None
    result["n_errors"] = crep.n_errors
    result["compile_stderr"] = (crep.stderr or "")[-2000:]
    if crep.attempted and not crep.ok:
        decision = match_errors(crep.errors, cases)
        result["known_ids"] = decision.known_ids
        result["n_unknown"] = len(decision.unknown)
        result["n_skip_forever"] = len(decision.skip_forever)
        result["skip_forever"] = decision.skip_forever_reasons
        result["need_llm"] = decision.need_llm
        result["unknown_messages"] = decision.unknown[:12]
        if decision.need_llm and proposal_dir is not None:
            path = write_proposal(
                proposal_dir,
                profile=profile,
                errors=crep.errors,
                snippet=tu_text[:4000],
                addr=name,
            )
            result["proposals"].append(str(path))

    name_by_addr = symbol_names_from_dump(functions, thunks)
    for r in restored:
        g = (r.get("guessed_name") or r.get("ghidra_name") or "").strip()
        if g and r.get("address"):
            name_by_addr[r["address"]] = g
    thunk_target = {
        t["address"]: t["target"] for t in thunks if t.get("target") and t.get("address")
    }
    verdict = review_run(
        restored,
        ghidra_by_addr={r["address"]: r for r in restored},
        name_by_addr=name_by_addr,
        thunk_target=thunk_target,
        tu_text=tu_text,
        compile_ok=result["assembled_ok"],
        functions=functions,
        thunks=thunks,
    )
    result["critic"] = verdict.to_dict()
    leaks = frozen_leaks()
    result["frozen_leaks"] = leaks
    if leaks:
        result["ok"] = False
        result["errors"].append("sanitizer/assembler contains held-out tokens: " + ", ".join(leaks))
    return result


def load_manifest(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"bad heldout manifest: {path}")
    return data


def run_manifest(
    manifest_path: Path,
    *,
    out_path: Path,
    compiler: str = "",
    proposal_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    man = load_manifest(manifest_path)
    base = manifest_path.parent.parent
    cases = load_corpus()
    proposal_dir = proposal_dir or (out_path.parent / "heldout_proposals")
    work_root = out_path.parent / "heldout_work"
    results = []
    for entry in man.get("entries") or []:
        name = str(entry.get("name") or "entry")
        gj = entry.get("ghidra_json")
        binary = entry.get("binary")
        rec = eval_heldout_entry(
            name,
            ghidra_json=_resolve(str(gj), base) if gj else Path(""),
            binary=_resolve(str(binary), base) if binary else None,
            user_names=list(entry.get("user_names") or []),
            top_k=int(man.get("top_k") or entry.get("top_k") or 15),
            compiler=compiler,
            proposal_dir=proposal_dir,
            work_dir=work_root / name,
            corpus_cases=cases,
        )
        results.append(rec)
    n_run = sum(1 for r in results if not r.get("skipped"))
    n_skip = sum(1 for r in results if r.get("skipped"))
    n_fail = sum(1 for r in results if not r.get("ok"))
    report = {
        "n_entries": len(results),
        "n_run": n_run,
        "n_skip": n_skip,
        "n_fail": n_fail,
        "frozen_leaks": frozen_leaks(),
        "results": results,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Held-out eval: corpus + compiler agent + critic (no new recipes)"
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--out", default="output/heldout_report.json")
    parser.add_argument("--compiler", default="")
    parser.add_argument("--proposals", default="output/heldout_proposals")
    args = parser.parse_args(argv)

    leaks = frozen_leaks()
    if leaks:
        print("FAIL: frozen sanitizer/assembler contains held-out tokens:")
        for hit in leaks:
            print(f"  {hit}")
        return 2

    report = run_manifest(
        Path(args.manifest),
        out_path=Path(args.out),
        compiler=args.compiler,
        proposal_dir=Path(args.proposals),
    )
    print(
        f"OK: heldout run={report['n_run']} skip={report['n_skip']} "
        f"fail={report['n_fail']} -> {args.out}"
    )
    for r in report.get("results") or []:
        if r.get("skipped"):
            print(f"  SKIP {r['name']}: {'; '.join(r.get('errors') or [])}")
            continue
        flag = "OK  " if r.get("ok") else "FAIL"
        print(
            f"  {flag} {r['name']}: fn={r.get('n_functions')} "
            f"assembled={r.get('assembled_ok')} errors={r.get('n_errors')} "
            f"known={r.get('known_ids')} unknown={r.get('n_unknown')} "
            f"proposals={len(r.get('proposals') or [])} "
            f"critic_accept={(r.get('critic') or {}).get('accept')}"
        )
        if r.get("unknown_messages"):
            for msg in r["unknown_messages"][:4]:
                print(f"      unknown: {msg}")
    print("note: do not add ghidra_cpp/assembler recipes from this report")
    return 0 if report.get("n_fail") == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
