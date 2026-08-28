from __future__ import annotations

"""Regression for Ghidra-dialect recipes (not user binaries).

  py -m src.analysis.eval_corpus
  py -m src.analysis.eval_corpus --dir eval/corpus --out output/corpus_report.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from src.analysis.corpus import DEFAULT_CORPUS_DIR, eval_corpus


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Eval Ghidra-dialect error corpus (compile-gate recipes)"
    )
    parser.add_argument(
        "--dir",
        default=str(DEFAULT_CORPUS_DIR),
        help="Directory of YAML fixtures",
    )
    parser.add_argument(
        "--out",
        default="output/corpus_report.json",
        help="JSON report path",
    )
    parser.add_argument(
        "--no-compile",
        action="store_true",
        help="Skip g++ -fsyntax-only even when a case has compile: true",
    )
    parser.add_argument("--id", action="append", dest="ids", help="Run only these ids")
    parser.add_argument("--compiler", default="", help="g++/clang++/cl path")
    args = parser.parse_args(argv)

    report = eval_corpus(
        Path(args.dir),
        compiler=args.compiler,
        do_compile=not args.no_compile,
        ids=args.ids,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    slim = {
        "n_cases": report["n_cases"],
        "n_ok": report["n_ok"],
        "n_fail": report["n_fail"],
        "results": [
            {
                "id": r["id"],
                "ok": r["ok"],
                "recipe": r["recipe"],
                "errors": r.get("errors") or [],
                "compile": r.get("compile") or {},
            }
            for r in report.get("results") or []
        ],
    }
    out.write_text(json.dumps(slim, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"OK: corpus {report['n_ok']}/{report['n_cases']} -> {out}")
    for r in report.get("results") or []:
        status = "OK  " if r.get("ok") else "FAIL"
        extra = ""
        if r.get("errors"):
            extra = "  " + "; ".join(r["errors"][:3])
        print(f"  {status} {r['id']}{extra}")
    return 0 if report["n_ok"] == report["n_cases"] else 1


if __name__ == "__main__":
    sys.exit(main())
