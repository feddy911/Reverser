from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.analysis.features import (
    FeatureIndex, derive_features, extract_features,
)
from src.analysis.platform import is_runtime_noise

logger = logging.getLogger("revllm.scorer")

WEIGHTS: Dict[str, float] = {
    "name_underscore": -150.0, "name_thunk": -100.0, "name_stl": -200.0,
    "name_lib": -150.0, "lib_matched": -150.0, "domain": 30.0,
    "stdio": 15.0, "iostream": 10.0, "size_large": 25.0,
    "size_medium": 15.0, "size_tiny": -20.0, "local_calls": 15.0,
    "crt_only": -20.0, "called_by_seed": 25.0,
}


class GhidraFunctionScorer:
    """Скоринг: эвристика или ML-бандл (joblib)."""

    def __init__(self, strings, functions, seed_score: int = 60,
                 ml_bundle: Optional[Dict[str, Any]] = None, thunks=None):
        self.index = FeatureIndex(strings, functions, thunks)
        self.seed_score = seed_score
        self.ml_bundle = ml_bundle

    def _score(self, ft: Dict[str, Any]) -> Tuple[float, List[str]]:
        w = WEIGHTS
        s = 0.0
        reasons: List[str] = []
        name = ft.get("name", "") or ""

        if is_runtime_noise(name) or name.startswith("_"):
            s += w["name_underscore"]
            reasons.append("CRT/runtime (name)")
        elif name.startswith("thunk_") or name.startswith("thunk "):
            s += w["name_thunk"]; reasons.append("thunk")
        elif "std::" in name:
            s += w["name_stl"]; reasons.append("STL (name)")
        elif name and not name.startswith("FUN_"):
            # Demangled user-like symbol — not a library penalty.
            reasons.append("named symbol")
        if ft.get("lib_matched", 0):
            s += w["lib_matched"]; reasons.append("library (signature match)")

        n_domain = int(ft.get("n_domain", 0) or 0)
        if n_domain:
            s += w["domain"]; reasons.append(f"calls domain DLLs x{n_domain}")
        if ft.get("n_stdio", 0):
            s += w["stdio"]; reasons.append(f"calls stdio x{ft['n_stdio']}")
        if ft.get("n_iostream", 0):
            s += w["iostream"]; reasons.append("uses cout/cerr/operator<<")
        if ft.get("n_literals", 0):
            s += min(40, 15 * ft["n_literals"])
            reasons.append(f"references {ft['n_literals']} strings")

        size = ft.get("size", 0)
        if size >= 500:
            s += w["size_large"]; reasons.append("large function")
        elif size >= 200:
            s += w["size_medium"]; reasons.append("medium function")
        elif size < 40:
            s += w["size_tiny"]; reasons.append("tiny function")
        if ft.get("n_local_callees", 0) >= 2:
            s += w["local_calls"]
            reasons.append(f"calls {ft['n_local_callees']} local funcs")
        if ft.get("n_crt", 0):
            s += w["crt_only"]; reasons.append("CRT imports")
        return s, reasons

    def _ml_score(self, ft: Dict[str, Any]) -> float:
        b = self.ml_bundle
        d = derive_features(dict(ft))
        x = [[float(d.get(k, 0.0)) for k in b["feature_keys"]]]
        if b.get("scaler") is not None:
            x = b["scaler"].transform(x)
        m = b["model"]
        if hasattr(m, "decision_function"):
            return float(m.decision_function(x)[0])
        return float(m.predict_proba(x)[0][1])

    def score_all(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        use_ml = self.ml_bundle is not None
        feats_all = {
            f.get("address"): extract_features(self.index, f)
            for f in self.index.all_functions
        }

        def hot(ft: Optional[Dict[str, Any]]) -> int:
            if not ft:
                return 0
            return int(
                ft.get("n_domain", 0) > 0
                or ft.get("n_literals", 0) > 0
                or ft.get("n_iostream", 0) > 0
                or ft.get("n_stdio", 0) > 0
            )

        for ft in feats_all.values():
            addr = ft["address"]
            ft["hot_callers"] = sum(
                1 for p in self.index.callers.get(addr, []) if hot(feats_all.get(p)))
            ft["hot_callees"] = sum(
                1 for c in self.index.resolved_callees.get(addr, []) if hot(feats_all.get(c)))
            derive_features(ft)

        scored: List[Dict[str, Any]] = []
        for f in functions:
            ft = feats_all.get(f.get("address")) or derive_features(extract_features(self.index, f))
            base, reasons = self._score(ft)
            if use_ml:
                base = self._ml_score(ft)
            out = dict(f)
            out.update(ft)
            out["score"] = base
            out["reasons"] = reasons
            scored.append(out)

        if not use_ml:
            first = {s["address"]: s["score"] for s in scored}
            for s in scored:
                if s["score"] >= self.seed_score:
                    continue
                hotc = [p for p in self.index.callers.get(s["address"], [])
                        if first.get(p, 0) >= self.seed_score]
                if hotc:
                    s["score"] += WEIGHTS["called_by_seed"]
                    s["reasons"].append(f"called by user code ({len(hotc)})")

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored


def select_llm_targets(
    scored: List[Dict[str, Any]],
    top_n: int,
) -> Tuple[List[Dict[str, Any]], int]:
    """Top-N для LLM без CRT/STL/MinGW internals.

    Returns (targets, n_filtered). If everything is noise, falls back to raw top-N.
    """
    kept: List[Dict[str, Any]] = []
    n_filtered = 0
    for s in scored:
        if is_runtime_noise(s.get("name") or ""):
            n_filtered += 1
            continue
        kept.append(s)
        if len(kept) >= top_n:
            break
    if kept:
        return kept, n_filtered
    return list(scored[:top_n]), n_filtered