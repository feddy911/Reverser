from __future__ import annotations
import argparse, json
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

FEATURE_KEYS = (
    "size", "n_local_callees", "n_ext_calls", "n_gmp", "n_stdio",
    "n_fileio", "n_iostream", "n_literals", "n_crt", "crt_ratio",
    "thunk_ratio", "is_fun_name", "is_thunk_name", "is_named", "n_callers",
    "is_crt_name", "is_stl_name", "is_lib_name",
    "hot_callers", "hot_callees",
)

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("features"); ap.add_argument("labels"); ap.add_argument("out")
    a = ap.parse_args()
    feats = json.loads(Path(a.features).read_text(encoding="utf-8"))
    labels = json.loads(Path(a.labels).read_text(encoding="utf-8"))
    X, y, addrs = [], [], []
    for e in feats:
        addr = e["address"].strip()
        X.append([float(e["features"][k]) for k in FEATURE_KEYS])
        y.append(int(labels.get(addr, 0))); addrs.append(addr)
    X = np.asarray(X); y = np.asarray(y)
    sc = StandardScaler().fit(X)
    clf = LogisticRegression(class_weight="balanced", max_iter=2000).fit(sc.transform(X), y)
    score = clf.decision_function(sc.transform(X))
    order = np.argsort(-score)
    p12 = sum(y[i] for i in order[:12]) / 12
    print(f"precision@12 = {p12:.2f}; positives total = {int(y.sum())}")
    for i in order[:15]:
        print(f"{score[i]:8.3f} label={y[i]} {addrs[i]}")
    Path(a.out).write_text(json.dumps({
        "feature_keys": list(FEATURE_KEYS),
        "mean": sc.mean_.tolist(), "scale": sc.scale_.tolist(),
        "coef": clf.coef_[0].tolist(), "intercept": float(clf.intercept_[0]),
    }, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()