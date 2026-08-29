from __future__ import annotations

"""Librarian: Ghidra dump → corpus candidate. Accept only after recipe eval.

  py -m src.analysis.librarian --dump output/corpus_gen/ghidra_dumps/vector_reserve.json
  py -m src.analysis.librarian --dump ... --accept-dir eval/corpus

Does not patch ghidra_cpp.py. Held-out sample names are not written as recipes.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

from src.agents.assembler import assemble
from src.analysis.compile_verify import compile_cpp, find_cxx_compiler
from src.analysis.corpus import eval_case, load_case
from src.analysis.eval_heldout import FROZEN_TOKENS
from src.analysis.includes import make_preamble
from src.analysis.platform import is_runtime_noise

ROOT = Path(__file__).resolve().parents[2]

# Generator held-out / sample names: drafts only, never eval/corpus.
_REFUSE_ID_SUBSTR = (
    "heldout", "pointcloud", "echofilter", "mycollatz", "xorcipher",
    "inimini", "taskboard", "netpath", "fibtimer",
)


def _refused_identity(case_id: str, blob: str) -> Optional[str]:
    cid = (case_id or "").lower()
    for tok in _REFUSE_ID_SUBSTR:
        if tok in cid:
            return f"refusing held-out/sample id {case_id!r}"
    for tok in FROZEN_TOKENS:
        if tok in blob:
            return f"refusing held-out/sample token {tok!r}"
    return None


def _user_functions(ghidra: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for fn in ghidra.get("functions") or []:
        name = str(fn.get("name") or "")
        code = (fn.get("ghidra_code") or fn.get("code") or "").strip()
        size = int(fn.get("size") or 0)
        if not code or size < 8:
            continue
        if is_runtime_noise(name):
            continue
        out.append(fn)
    return out


def _restored_from_fn(fn: Dict[str, Any]) -> Dict[str, Any]:
    code = (fn.get("ghidra_code") or fn.get("code") or "").strip()
    name = str(fn.get("name") or "f")
    return {
        "classification": "user_code",
        "address": fn.get("address") or "",
        "guessed_name": name,
        "ghidra_name": name,
        "cpp_code": code,
        "ghidra_code": code,
        "literals": list(fn.get("literals") or []),
        "ext_calls": list(fn.get("ext_calls") or []),
        "callees": list(fn.get("callees") or []),
    }


def _fingerprint(errors: Sequence[Dict[str, str]]) -> str:
    msg = ""
    for e in errors or []:
        m = str(e.get("message") or "").strip()
        if m:
            msg = m
            break
    if not msg:
        return ""
    return re.escape(msg[:160])


def propose_from_dump(
    ghidra: Dict[str, Any],
    *,
    program_id: str,
    draft_dir: Path,
    compiler: str = "",
) -> Dict[str, Any]:
    """Assemble user functions from a dump; write one YAML candidate."""
    user = _user_functions(ghidra)
    rec: Dict[str, Any] = {
        "program_id": program_id,
        "n_user": len(user),
        "accepted": False,
        "path": None,
        "assembled_ok": None,
    }
    if not user:
        rec["error"] = "no user functions"
        return rec

    restored = [_restored_from_fn(f) for f in user]
    functions = ghidra.get("functions") or []
    thunks = ghidra.get("thunks") or []
    preamble = make_preamble(f"// librarian {program_id}", restored, functions)
    tu, n = assemble(restored, functions, thunks, preamble_lines=preamble)
    rec["n_emitted"] = n

    primary = restored[0]
    extras = [
        {"name": r["guessed_name"], "cpp": r["cpp_code"]}
        for r in restored[1:]
    ]
    payload: Dict[str, Any] = {
        "id": f"ghidra-{program_id}-{primary['guessed_name']}",
        "profile": "generic",
        "recipe": "assemble",
        "ghidra_cpp": primary["cpp_code"],
        "guessed_name": primary["guessed_name"],
        "extra_functions": extras,
        "contains": [primary["guessed_name"]],
        "not_contains": [],
        "compile": True,
        "notes": f"librarian candidate from generator dump {program_id}; review before accept",
    }

    cxx = find_cxx_compiler(compiler)
    errors: List[Dict[str, str]] = []
    if cxx:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / f"{program_id}.cpp"
            src.write_text(tu + "\n", encoding="utf-8")
            crep = compile_cpp(src, compiler=cxx, timeout_sec=45)
        rec["assembled_ok"] = bool(crep.ok) if crep.attempted else None
        rec["n_errors"] = crep.n_errors
        errors = list(crep.errors or [])
        if crep.ok:
            payload["gcc_fingerprint"] = ""
            rec["accepted"] = True
        else:
            payload["compile"] = False
            payload["gcc_fingerprint"] = _fingerprint(errors)
            payload["notes"] += "; compile failed — draft only"
    else:
        payload["compile"] = False
        rec["compile_skipped"] = "no compiler"

    draft_dir.mkdir(parents=True, exist_ok=True)
    path = draft_dir / f"{payload['id']}.yaml"
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    rec["path"] = str(path)
    rec["unknown_messages"] = [
        str(e.get("message") or "") for e in errors[:8] if e.get("message")
    ]
    return rec


def try_accept(yaml_path: Path, dest_dir: Path) -> Dict[str, Any]:
    case = load_case(yaml_path)
    blob = case.ghidra_cpp + " " + " ".join(case.contains) + " " + case.id
    hit = _refused_identity(case.id, blob)
    if hit:
        return {"ok": False, "error": hit, "path": str(yaml_path)}
    result = eval_case(case, do_compile=True)
    if not result.get("ok"):
        return {
            "ok": False,
            "error": result.get("errors") or ["eval failed"],
            "path": str(yaml_path),
        }
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / yaml_path.name
    dest.write_text(yaml_path.read_text(encoding="utf-8"), encoding="utf-8")
    return {"ok": True, "path": str(dest)}


def propose_from_dumps_dir(
    dump_dir: Path,
    *,
    draft_dir: Path,
    compiler: str = "",
) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    for path in sorted(dump_dir.glob("*.json")):
        try:
            ghidra = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            recs.append({"dump": str(path), "error": str(exc)})
            continue
        rec = propose_from_dump(
            ghidra,
            program_id=path.stem,
            draft_dir=draft_dir,
            compiler=compiler,
        )
        rec["dump"] = str(path)
        recs.append(rec)
    return recs


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Librarian: dump → corpus candidate")
    parser.add_argument("--dump", help="Ghidra JSON dump")
    parser.add_argument("--dumps-dir", help="Process every *.json dump in a directory")
    parser.add_argument("--program-id", default="")
    parser.add_argument("--draft-dir", default="output/corpus_draft")
    parser.add_argument("--accept", help="YAML candidate to copy into --accept-dir if eval passes")
    parser.add_argument("--accept-dir", default=str(ROOT / "eval" / "corpus"))
    parser.add_argument(
        "--accept-compiled",
        action="store_true",
        help="After --dumps-dir/--dump, try_accept drafts that assembled",
    )
    parser.add_argument("--compiler", default="")
    args = parser.parse_args(argv)

    if args.accept:
        rec = try_accept(Path(args.accept), Path(args.accept_dir))
        print(("OK  " if rec.get("ok") else "FAIL ") + json.dumps(rec, ensure_ascii=False))
        return 0 if rec.get("ok") else 1

    recs: List[Dict[str, Any]] = []
    if args.dumps_dir:
        recs = propose_from_dumps_dir(
            Path(args.dumps_dir),
            draft_dir=Path(args.draft_dir),
            compiler=args.compiler,
        )
    elif args.dump:
        dump_path = Path(args.dump)
        ghidra = json.loads(dump_path.read_text(encoding="utf-8"))
        pid = args.program_id or dump_path.stem
        recs = [propose_from_dump(
            ghidra,
            program_id=pid,
            draft_dir=Path(args.draft_dir),
            compiler=args.compiler,
        )]
    else:
        parser.error("Provide --dump, --dumps-dir, or --accept")
        return 2

    for rec in recs:
        print(json.dumps(rec, indent=2, ensure_ascii=False))

    if args.accept_compiled:
        dest = Path(args.accept_dir)
        for rec in recs:
            if not rec.get("assembled_ok") or not rec.get("path"):
                continue
            acc = try_accept(Path(rec["path"]), dest)
            rec["accept"] = acc
            print(("OK  " if acc.get("ok") else "FAIL ") + json.dumps(acc, ensure_ascii=False))

    n_path = sum(1 for r in recs if r.get("path"))
    return 0 if n_path == len(recs) and recs else 1


if __name__ == "__main__":
    sys.exit(main())
