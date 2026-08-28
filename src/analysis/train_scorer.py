from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

from src.analysis.features import FEATURE_KEYS, derive_features


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("features")
    ap.add_argument("labels")
    ap.add_argument("out")
    a = ap.parse_args()

    feats = json.loads(Path(a.features).read_text(encoding="utf-8"))
    labels = json.loads(Path(a.labels).read_text(encoding="utf-8"))

    X, y, addrs = [], [], []
    for e in feats:
        d = derive_features(dict(e["features"]))
        X.append([float(d[k]) for k in FEATURE_KEYS])
        y.append(int(labels.get(e["address"].strip(), 0)))
        addrs.append(e["address"].strip())
    X = np.asarray(X)
    y = np.asarray(y)
    print(f"dataset: {len(y)} rows, positives: {int(y.sum())}")

    models = {
        "logreg": lambda: (StandardScaler(),
                           LogisticRegression(class_weight="balanced", max_iter=3000)),
        "rf": lambda: (None, RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2,
            class_weight="balanced", random_state=42)),
    }
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    results = {}
    for name, factory in models.items():
        scaler, clf = factory()
        Xt = scaler.fit_transform(X) if scaler is not None else X
        clf.fit(Xt, y)
        score = (clf.decision_function(Xt) if hasattr(clf, "decision_function")
                 else clf.predict_proba(Xt)[:, 1])
        order = np.argsort(-score)
        p12 = sum(y[i] for i in order[:12]) / 12
        aucs, aps = [], []
        for tr, te in skf.split(X, y):
            s2, c2 = factory()
            Xtr = s2.fit_transform(X[tr]) if s2 is not None else X[tr]
            c2.fit(Xtr, y[tr])
            Xte = s2.transform(X[te]) if s2 is not None else X[te]
            pr = (c2.decision_function(Xte) if hasattr(c2, "decision_function")
                  else c2.predict_proba(Xte)[:, 1])
            aucs.append(roc_auc_score(y[te], pr))
            aps.append(average_precision_score(y[te], pr))
        results[name] = (p12, np.mean(aucs))
        print(f"{name:7s} in-sample p@12={p12:.2f}  "
              f"cv_auc={np.mean(aucs):.3f}+/-{np.std(aucs):.3f}  cv_ap={np.mean(aps):.3f}")
        if name == "rf":
            imp = sorted(zip(FEATURE_KEYS, clf.feature_importances_),
                         key=lambda t: -t[1])[:8]
            print("   rf importances:", ", ".join(f"{k}={v:.2f}" for k, v in imp))

    best = max(results, key=lambda k: (results[k][1], results[k][0]))
    print("chosen:", best)
    scaler, clf = models[best]()
    Xt = scaler.fit_transform(X) if scaler is not None else X
    clf.fit(Xt, y)
    score = (clf.decision_function(Xt) if hasattr(clf, "decision_function")
             else clf.predict_proba(Xt)[:, 1])
    order = np.argsort(-score)
    print(f"final p@12 = {sum(y[i] for i in order[:12]) / 12:.2f}")
    for i in order[:15]:
        print(f"{score[i]:8.3f} label={y[i]} {addrs[i]}")

    meta_p = Path(a.out)
    joblib.dump(
        {"model": clf, "scaler": scaler,
         "feature_keys": list(FEATURE_KEYS), "model_type": best},
        meta_p.with_name("ml_model.joblib"),
    )
    meta_p.write_text(json.dumps({
        "model_file": "ml_model.joblib",
        "model_type": best,
        "feature_keys": list(FEATURE_KEYS),
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()