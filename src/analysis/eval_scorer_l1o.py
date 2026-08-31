from __future__ import annotations

"""Leave-one-binary-out scoring eval. Same 22 FEATURE_KEYS. Not compile-gate.

  py -m src.analysis.eval_scorer_l1o --manifest eval/manifest.yaml

Trains logreg / RF / DecisionTree(max_depth=4) on every binary except one,
then measures filtered recall@15 on the held-out dump. Heuristic has no
fit — it is the WEIGHTS scorer on that dump. Does not read gcc diagnostics
and does not write corpus recipes.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

from src.analysis.eval_harness import (
    ROOT,
    _load_ghidra,
    _mean,
    _name_matches,
    _resolve_path,
    _score_dump,
    load_address_labels,
)
from src.analysis.features import FEATURE_KEYS
from src.analysis.scorer import apply_runtime_noise_penalty, select_llm_targets

MODEL_ORDER = ("heuristic", "logreg", "rf", "dtree")

_GCC_SUBSTRINGS = ("gcc", "error", "diagnostic", "fingerprint")


def assert_scoring_features() -> None:
    """Q6 L1O uses the live 22 keys. gcc text is not a feature."""
    if len(FEATURE_KEYS) != 22:
        raise RuntimeError(f"FEATURE_KEYS length {len(FEATURE_KEYS)}, expected 22")
    lowered = [k.lower() for k in FEATURE_KEYS]
    bad = [k for k in lowered if any(s in k for s in _GCC_SUBSTRINGS)]
    if bad:
        raise RuntimeError(f"gcc-like keys in FEATURE_KEYS: {bad}")


@dataclass
class BinaryPack:
    name: str
    user_names: List[str]
    scored: List[Dict[str, Any]]
    X: np.ndarray
    y: np.ndarray
    addr_positives: List[str] = field(default_factory=list)
    y_source: str = "names"
    family: str = ""


def _row(ft: Dict[str, Any]) -> List[float]:
    return [float(ft.get(k, 0) or 0) for k in FEATURE_KEYS]


def _label_row(name: str, user_names: Sequence[str]) -> int:
    return int(any(_name_matches(name, want) for want in user_names))


def load_binary(
    name: str,
    ghidra_json: Path,
    user_names: Sequence[str],
    labels: Optional[Dict[str, int]] = None,
    family: str = "",
) -> BinaryPack:
    ghidra = _load_ghidra(ghidra_json)
    scored = _score_dump(ghidra)
    addr_pos = [a for a, v in (labels or {}).items() if int(v) == 1]
    if addr_pos:
        y = np.asarray(
            [int((labels or {}).get(s.get("address"), 0)) for s in scored],
            dtype=np.int32,
        )
        y_source = "addresses"
    else:
        y = np.asarray(
            [_label_row(s.get("name") or "", user_names) for s in scored],
            dtype=np.int32,
        )
        y_source = "names"
    X = np.asarray([_row(s) for s in scored], dtype=np.float64)
    return BinaryPack(
        name=name,
        user_names=list(user_names),
        scored=scored,
        X=X,
        y=y,
        addr_positives=addr_pos,
        y_source=y_source,
        family=str(family or ""),
    )


def load_manifest_packs(manifest_path: Path) -> Tuple[List[BinaryPack], List[Dict[str, Any]]]:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    packs: List[BinaryPack] = []
    skipped: List[Dict[str, Any]] = []
    for e in data.get("entries") or []:
        name = str(e.get("name") or f"entry_{len(packs)}")
        ghidra_json = Path(e["ghidra_json"]) if e.get("ghidra_json") else None
        gj = _resolve_path(ghidra_json, manifest_path)
        if gj is None or not gj.exists():
            skipped.append({
                "name": name,
                "skipped": True,
                "reason": f"missing ghidra_json: {ghidra_json}",
            })
            continue
        user_names = list(e.get("user_names") or [])
        labels_path = Path(e["labels"]) if e.get("labels") else None
        labels = load_address_labels(_resolve_path(labels_path, manifest_path))
        if not user_names and not labels:
            skipped.append({
                "name": name,
                "skipped": True,
                "reason": "no user_names or labels",
            })
            continue
        packs.append(load_binary(
            name,
            gj,
            user_names,
            labels=labels or None,
            family=str(e.get("family") or ""),
        ))
    return packs, skipped


def _recall(
    scored: List[Dict[str, Any]],
    user_names: Sequence[str],
    top_k: int,
    addr_positives: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    ranked = sorted(scored, key=lambda s: float(s.get("score") or 0), reverse=True)
    raw_top = ranked[:top_k]
    n = len(user_names)
    raw_hits = sum(
        1 for want in user_names
        if any(_name_matches(t.get("name") or "", want) for t in raw_top)
    )
    filtered, n_noise = select_llm_targets(ranked, top_k)
    f_hits = sum(
        1 for want in user_names
        if any(_name_matches(t.get("name") or "", want) for t in filtered)
    )
    out: Dict[str, Any] = {
        "recall_at_k_names": round(raw_hits / n, 3) if n else None,
        "recall_at_k_names_filtered": round(f_hits / n, 3) if n else None,
        "hits_filtered": f_hits,
        "n_labels": n,
        "runtime_filtered": n_noise,
        "top_filtered": [
            {"address": t.get("address"), "name": t.get("name"), "score": t.get("score")}
            for t in filtered
        ],
    }
    pos = [a for a in (addr_positives or []) if a]
    if pos:
        pset = set(pos)
        raw_a = sum(1 for t in raw_top if t.get("address") in pset)
        filt_a = sum(1 for t in filtered if t.get("address") in pset)
        naddr = len(pset)
        out["n_addr_labels"] = naddr
        out["recall_at_k_addr"] = round(raw_a / naddr, 3)
        out["recall_at_k_addr_filtered"] = round(filt_a / naddr, 3)
        out["addr_hits"] = [
            {"address": t.get("address"), "name": t.get("name"),
             "score": t.get("score"), "n_literals": t.get("n_literals"),
             "size": t.get("size")}
            for t in filtered if t.get("address") in pset
        ]
        fset = {t.get("address") for t in filtered}
        out["addr_misses"] = [
            {"address": s.get("address"), "name": s.get("name"),
             "score": s.get("score"), "n_literals": s.get("n_literals"),
             "n_iostream": s.get("n_iostream"), "size": s.get("size"),
             "is_named": s.get("is_named"), "is_fun_name": s.get("is_fun_name")}
            for s in scored
            if s.get("address") in pset and s.get("address") not in fset
        ]
    return out


def _with_scores(pack: BinaryPack, scores: np.ndarray) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s, sc in zip(pack.scored, scores):
        row = dict(s)
        row["score"] = apply_runtime_noise_penalty(s.get("name") or "", float(sc))
        out.append(row)
    return out


def _fit(model: str, X: np.ndarray, y: np.ndarray) -> Tuple[Optional[StandardScaler], Any]:
    if model == "logreg":
        scaler = StandardScaler()
        clf = LogisticRegression(class_weight="balanced", max_iter=3000)
        clf.fit(scaler.fit_transform(X), y)
        return scaler, clf
    if model == "rf":
        clf = RandomForestClassifier(
            n_estimators=300,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
        )
        clf.fit(X, y)
        return None, clf
    if model == "dtree":
        clf = DecisionTreeClassifier(
            max_depth=4,
            class_weight="balanced",
            random_state=42,
        )
        clf.fit(X, y)
        return None, clf
    raise ValueError(model)


def _predict(scaler: Optional[StandardScaler], clf: Any, X: np.ndarray) -> np.ndarray:
    Xt = scaler.transform(X) if scaler is not None else X
    if hasattr(clf, "predict_proba"):
        return np.asarray(clf.predict_proba(Xt)[:, 1], dtype=np.float64)
    return np.asarray(clf.decision_function(Xt), dtype=np.float64)


def _stack(packs: Sequence[BinaryPack]) -> Tuple[np.ndarray, np.ndarray]:
    return (
        np.vstack([p.X for p in packs]),
        np.concatenate([p.y for p in packs]),
    )


def eval_held_out(
    held: BinaryPack,
    train: Sequence[BinaryPack],
    *,
    top_k: int,
) -> Dict[str, Any]:
    per_model: Dict[str, Any] = {}
    per_model["heuristic"] = _recall(
        held.scored, held.user_names, top_k, held.addr_positives,
    )

    if not train:
        for name in ("logreg", "rf", "dtree"):
            per_model[name] = {"error": "no train binaries"}
        return {
            "name": held.name,
            "n_test": int(len(held.y)),
            "n_test_pos": int(held.y.sum()),
            "n_train": 0,
            "n_train_pos": 0,
            "y_source": held.y_source,
            "family": held.family,
            "n_addr_labels": len(held.addr_positives),
            "models": per_model,
        }

    Xtr, ytr = _stack(train)
    n_pos = int(ytr.sum())
    n_neg = int(len(ytr) - n_pos)
    if n_pos == 0 or n_neg == 0:
        for name in ("logreg", "rf", "dtree"):
            per_model[name] = {"error": "train set has one class"}
    else:
        for name in ("logreg", "rf", "dtree"):
            scaler, clf = _fit(name, Xtr, ytr)
            pred = _predict(scaler, clf, held.X)
            rec = _recall(
                _with_scores(held, pred),
                held.user_names,
                top_k,
                held.addr_positives,
            )
            if name == "dtree":
                rec["tree_rules"] = export_text(
                    clf, feature_names=list(FEATURE_KEYS), max_depth=4,
                )
            if name == "rf":
                rec["importances"] = [
                    {"key": k, "value": round(float(v), 4)}
                    for k, v in sorted(
                        zip(FEATURE_KEYS, clf.feature_importances_),
                        key=lambda t: -t[1],
                    )[:8]
                ]
            per_model[name] = rec

    return {
        "name": held.name,
        "n_test": int(len(held.y)),
        "n_test_pos": int(held.y.sum()),
        "n_train": int(len(ytr)),
        "n_train_pos": n_pos,
        "user_names": list(held.user_names),
        "y_source": held.y_source,
        "family": held.family,
        "n_addr_labels": len(held.addr_positives),
        "models": per_model,
    }


def _train_packs(held: BinaryPack, packs: Sequence[BinaryPack]) -> List[BinaryPack]:
    """Leave-one-out, and also drop a named/stripped twin of the held-out dump."""
    out: List[BinaryPack] = []
    for p in packs:
        if p.name == held.name:
            continue
        if held.family and p.family and p.family == held.family:
            continue
        out.append(p)
    return out


def run_l1o(
    packs: Sequence[BinaryPack],
    *,
    top_k: int = 15,
    skipped: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    assert_scoring_features()
    folds = [
        eval_held_out(
            held,
            _train_packs(held, packs),
            top_k=top_k,
        )
        for held in packs
    ]

    named_folds = [f for f in folds if f.get("y_source") != "addresses"]
    addr_folds = [f for f in folds if f.get("y_source") == "addresses"]

    means: Dict[str, Optional[float]] = {}
    means_raw: Dict[str, Optional[float]] = {}
    means_addr: Dict[str, Optional[float]] = {}
    means_named: Dict[str, Optional[float]] = {}
    for model in MODEL_ORDER:
        means[model] = _mean([
            ((f.get("models") or {}).get(model) or {}).get("recall_at_k_names_filtered")
            for f in folds
        ])
        means_raw[model] = _mean([
            ((f.get("models") or {}).get(model) or {}).get("recall_at_k_names")
            for f in folds
        ])
        means_addr[model] = _mean([
            ((f.get("models") or {}).get(model) or {}).get("recall_at_k_addr_filtered")
            for f in addr_folds
        ])
        means_named[model] = _mean([
            ((f.get("models") or {}).get(model) or {}).get("recall_at_k_names_filtered")
            for f in named_folds
        ])

    table: List[Dict[str, Any]] = []
    for f in folds:
        row = {
            "name": f["name"],
            "n_test": f["n_test"],
            "n_test_pos": f["n_test_pos"],
            "y_source": f.get("y_source"),
            "family": f.get("family") or "",
            "n_addr_labels": f.get("n_addr_labels") or 0,
            "n_train": f.get("n_train"),
        }
        for model in MODEL_ORDER:
            rec = (f.get("models") or {}).get(model) or {}
            row[model] = rec.get("recall_at_k_names_filtered")
            row[f"{model}_raw"] = rec.get("recall_at_k_names")
            row[f"{model}_addr"] = rec.get("recall_at_k_addr_filtered")
        table.append(row)

    return {
        "track": "scoring_l1o",
        "not_compile_gate": True,
        "top_k": top_k,
        "feature_keys": list(FEATURE_KEYS),
        "n_feature_keys": len(FEATURE_KEYS),
        "models": list(MODEL_ORDER),
        "n_binaries": len(packs),
        "n_named_binaries": len(named_folds),
        "n_addr_binaries": len(addr_folds),
        "n_skip": len(skipped or []),
        "skipped": skipped or [],
        "mean_filtered_recall": means,
        "mean_raw_recall": means_raw,
        "mean_named_filtered_recall": means_named,
        "mean_addr_filtered_recall": means_addr,
        "table": table,
        "folds": folds,
    }


def run_manifest(manifest_path: Path, out_path: Path, top_k: int = 15) -> Dict[str, Any]:
    packs, skipped = load_manifest_packs(manifest_path)
    report = run_l1o(packs, top_k=top_k, skipped=skipped)
    report["manifest"] = str(manifest_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return report


def _print_report(report: Dict[str, Any], out: Path) -> None:
    named_means = report.get("mean_named_filtered_recall") or {}
    addr_means = report.get("mean_addr_filtered_recall") or {}
    print(
        f"OK: scoring L1O binaries={report.get('n_binaries')} "
        f"named={report.get('n_named_binaries')} "
        f"addr={report.get('n_addr_binaries')} "
        f"skip={report.get('n_skip', 0)} keys={report.get('n_feature_keys')} "
        f"-> {out}"
    )
    print(
        "  named-dump filtered recall@"
        f"{report.get('top_k')}: "
        + "  ".join(f"{m}={named_means.get(m)}" for m in MODEL_ORDER)
    )
    print(
        "  FUN_* addr filtered recall@"
        f"{report.get('top_k')}: "
        + "  ".join(f"{m}={addr_means.get(m)}" for m in MODEL_ORDER)
    )
    mixed = report.get("mean_filtered_recall") or {}
    print(
        "  mixed name-recall (FUN_* folds are 0): "
        + "  ".join(f"{m}={mixed.get(m)}" for m in MODEL_ORDER)
    )
    header = (
        f"{'binary':<16} {'src':<10} {'n':>5} {'pos':>4}  "
        + "  ".join(f"{m:>9}" for m in MODEL_ORDER)
        + "  heur_addr"
    )
    print(header)
    for row in report.get("table") or []:
        cells = "  ".join(
            f"{(row.get(m) if row.get(m) is not None else '-'):>9}"
            for m in MODEL_ORDER
        )
        addr = row.get("heuristic_addr")
        addr_s = f"{addr:>9}" if addr is not None else f"{'-':>9}"
        print(
            f"{row.get('name', ''):<16} {str(row.get('y_source') or ''):<10} "
            f"{row.get('n_test', 0):>5} {row.get('n_test_pos', 0):>4}  "
            f"{cells}  {addr_s}"
        )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Leave-one-binary-out scoring eval. Not compile-gate."
    )
    parser.add_argument(
        "--manifest",
        default=str(ROOT / "eval" / "manifest.yaml"),
        help="YAML manifest with entries[] (default: eval/manifest.yaml)",
    )
    parser.add_argument(
        "--out",
        default="output/scorer_l1o.json",
        help="Output report path",
    )
    parser.add_argument("--top-k", type=int, default=15)
    args = parser.parse_args(argv)

    report = run_manifest(Path(args.manifest), Path(args.out), top_k=int(args.top_k))
    _print_report(report, Path(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
