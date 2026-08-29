from __future__ import annotations

"""Scoring-only eval (Q6). Not the compile-gate.

  py -m src.analysis.eval_harness --manifest eval/manifest.yaml
  py -m src.analysis.eval_harness --fixture tests/fixtures/mini_ghidra.json --name mini

Missing ghidra_json paths are skipped (CI without output/cache).
Does not assemble, compile, or write corpus recipes.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.analysis.features import FEATURE_KEYS
from src.analysis.scorer import GhidraFunctionScorer, select_llm_targets
from src.analysis.triage import triage_binary


def _load_ghidra(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "functions" not in data:
        raise ValueError(f"Bad ghidra JSON: {path}")
    return data


def _score_dump(
    ghidra: Dict[str, Any],
    min_size: int = 20,
    seed_score: int = 60,
) -> List[Dict[str, Any]]:
    functions = ghidra.get("functions") or []
    strings = ghidra.get("strings") or []
    thunks = ghidra.get("thunks") or []
    candidates = [
        f for f in functions
        if min_size <= int(f.get("size") or 0) <= 50_000
    ]
    scorer = GhidraFunctionScorer(
        strings, functions, seed_score=seed_score, thunks=thunks
    )
    return scorer.score_all(candidates)


def _name_matches(got: str, want: str) -> bool:
    g = (got or "").lower()
    w = (want or "").lower()
    base = g.split("<", 1)[0]
    return w == g or w == base or base.startswith(w) or w in base


def eval_entry(
    name: str,
    *,
    binary: Optional[Path] = None,
    ghidra_json: Optional[Path] = None,
    labels_path: Optional[Path] = None,
    user_names: Optional[List[str]] = None,
    top_k: int = 15,
) -> Dict[str, Any]:
    if ghidra_json is None and binary is None:
        raise ValueError(f"{name}: need binary or ghidra_json")

    triage = None
    if binary and binary.exists():
        triage = triage_binary(binary)

    if ghidra_json and ghidra_json.exists():
        ghidra = _load_ghidra(ghidra_json)
        if binary and binary.exists():
            triage = triage_binary(binary, ghidra=ghidra)
    else:
        raise ValueError(
            f"{name}: scoring eval requires ghidra_json "
            "(full pipeline with Ghidra is out of scope for this harness)"
        )

    scored = _score_dump(ghidra)
    top = [
        {
            "address": s["address"],
            "name": s["name"],
            "score": s["score"],
            "reasons": (s.get("reasons") or [])[:3],
            "features": {k: s.get(k, 0) for k in FEATURE_KEYS},
        }
        for s in scored[:top_k]
    ]

    labels: Dict[str, int] = {}
    if labels_path and labels_path.exists():
        raw = json.loads(labels_path.read_text(encoding="utf-8"))
        # labels_MyCollatz.json: { "0x...": 0|1 } or list
        if isinstance(raw, dict):
            labels = {str(k): int(v) for k, v in raw.items()}
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict) and "address" in item:
                    labels[str(item["address"])] = int(item.get("label", item.get("y", 0)))

    metrics: Dict[str, Any] = {
        "functions": len(ghidra.get("functions") or []),
        "candidates": len(scored),
        "top_k": len(top),
    }
    if labels:
        # precision@k среди помеченных адресов
        labeled_top = [t for t in top if t["address"] in labels]
        tp = sum(1 for t in labeled_top if labels[t["address"]] == 1)
        metrics["labeled_in_top"] = len(labeled_top)
        metrics["precision_at_labeled_top"] = (
            round(tp / len(labeled_top), 3) if labeled_top else None
        )
        # recall: доля label=1, попавших в top_k
        positives = {a for a, y in labels.items() if y == 1}
        hit = sum(1 for t in top if t["address"] in positives)
        metrics["positive_labels"] = len(positives)
        metrics["recall_at_k"] = (
            round(hit / len(positives), 3) if positives else None
        )

    if user_names:
        hits = sum(
            1 for want in user_names
            if any(_name_matches(t["name"], want) for t in top)
        )
        metrics["user_names"] = list(user_names)
        metrics["recall_at_k_names"] = round(hits / len(user_names), 3)
        filtered, n_noise = select_llm_targets(scored, top_k)
        f_hits = sum(
            1 for want in user_names
            if any(_name_matches(t["name"], want) for t in filtered)
        )
        metrics["runtime_filtered"] = n_noise
        metrics["recall_at_k_names_filtered"] = round(f_hits / len(user_names), 3)
        metrics["top_filtered"] = [
            {"address": t["address"], "name": t["name"], "score": t["score"]}
            for t in filtered
        ]

    return {
        "name": name,
        "binary": str(binary) if binary else None,
        "ghidra_json": str(ghidra_json) if ghidra_json else None,
        "triage": triage.to_dict() if triage else None,
        "metrics": metrics,
        "top": top,
    }


ROOT = Path(__file__).resolve().parents[2]


def _resolve_path(p: Optional[Path], manifest_path: Path) -> Optional[Path]:
    if p is None:
        return None
    if p.is_absolute():
        return p
    for base in (manifest_path.parent, manifest_path.parent.parent, Path.cwd(), ROOT):
        cand = (base / p).resolve()
        if cand.exists():
            return cand
    return (ROOT / p).resolve()


def _mean(values: List[Optional[float]]) -> Optional[float]:
    nums = [float(v) for v in values if v is not None]
    if not nums:
        return None
    return round(sum(nums) / len(nums), 3)


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    skipped = [r for r in results if r.get("skipped")]
    failed = [r for r in results if r.get("error") and not r.get("skipped")]
    scored = [
        r for r in results
        if not r.get("skipped") and not r.get("error")
    ]
    return {
        "track": "scoring",
        "not_compile_gate": True,
        "n_scored": len(scored),
        "n_skip": len(skipped),
        "n_fail": len(failed),
        "mean_recall_at_k_names": _mean(
            [(r.get("metrics") or {}).get("recall_at_k_names") for r in scored]
        ),
        "mean_recall_at_k_names_filtered": _mean(
            [
                (r.get("metrics") or {}).get("recall_at_k_names_filtered")
                for r in scored
            ]
        ),
        "scored_names": [r.get("name") for r in scored],
        "skipped_names": [r.get("name") for r in skipped],
    }


def run_manifest(manifest_path: Path, out_path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    entries = data.get("entries") or []
    results: List[Dict[str, Any]] = []
    for e in entries:
        name = str(e.get("name") or f"entry_{len(results)}")
        binary = Path(e["binary"]) if e.get("binary") else None
        ghidra_json = Path(e["ghidra_json"]) if e.get("ghidra_json") else None
        labels = Path(e["labels"]) if e.get("labels") else None
        gj = _resolve_path(ghidra_json, manifest_path)
        if gj is None or not gj.exists():
            results.append({
                "name": name,
                "skipped": True,
                "reason": f"missing ghidra_json: {ghidra_json}",
            })
            continue
        try:
            results.append(
                eval_entry(
                    name,
                    binary=_resolve_path(binary, manifest_path),
                    ghidra_json=gj,
                    labels_path=_resolve_path(labels, manifest_path),
                    user_names=list(e.get("user_names") or []) or None,
                    top_k=int(e.get("top_k") or data.get("top_k") or 15),
                )
            )
        except Exception as exc:
            results.append({"name": name, "error": str(exc)})

    summary = summarize(results)
    report = {
        "manifest": str(manifest_path),
        "n_entries": len(results),
        "n_ok": summary["n_scored"],
        "n_skip": summary["n_skip"],
        "n_fail": summary["n_fail"],
        "summary": summary,
        "results": results,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scoring-only eval (Q6). Not compile-gate."
    )
    parser.add_argument("--manifest", help="YAML manifest with entries[]")
    parser.add_argument("--fixture", help="Single ghidra JSON fixture")
    parser.add_argument("--name", default="fixture", help="Name for --fixture run")
    parser.add_argument(
        "--out",
        default="output/eval_report.json",
        help="Output report path",
    )
    args = parser.parse_args(argv)

    out = Path(args.out)
    if args.manifest:
        report = run_manifest(Path(args.manifest), out)
    elif args.fixture:
        result = eval_entry(args.name, ghidra_json=Path(args.fixture))
        report = {"n_entries": 1, "n_ok": 1, "results": [result]}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        parser.error("Provide --manifest or --fixture")
        return 2

    print(
        f"OK: scoring {report.get('n_ok')}/{report.get('n_entries')} "
        f"skip={report.get('n_skip', 0)} fail={report.get('n_fail', 0)} -> {out}"
    )
    summary = report.get("summary") or {}
    if summary.get("mean_recall_at_k_names_filtered") is not None:
        print(
            f"  mean filtered recall@k="
            f"{summary['mean_recall_at_k_names_filtered']} "
            f"(raw names={summary.get('mean_recall_at_k_names')})"
        )
    for r in report.get("results") or []:
        if r.get("skipped"):
            print(f"  SKIP {r['name']}: {r.get('reason')}")
        elif r.get("error"):
            print(f"  FAIL {r['name']}: {r['error']}")
        else:
            m = r.get("metrics") or {}
            tri = (r.get("triage") or {}).get("profile", "-")
            print(
                f"  OK   {r['name']}: funcs={m.get('functions')} "
                f"cand={m.get('candidates')} profile={tri} "
                f"recall@k={m.get('recall_at_k')}"
                + (
                    f" names={m.get('recall_at_k_names')}"
                    f" filtered={m.get('recall_at_k_names_filtered')}"
                    if m.get("recall_at_k_names") is not None
                    else ""
                )
            )
    return 0 if int(report.get("n_fail") or 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
