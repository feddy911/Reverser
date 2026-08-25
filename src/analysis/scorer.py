from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.analysis.features import FeatureIndex, extract_features

logger = logging.getLogger("revllm.scorer")

WEIGHTS: Dict[str, float] = {
    "name_underscore": -150.0,
    "name_thunk": -100.0,
    "name_stl": -200.0,
    "name_lib": -150.0,
    "gmp": 30.0,
    "stdio": 15.0,
    "iostream": 10.0,
    "size_large": 25.0,
    "size_medium": 15.0,
    "size_tiny": -20.0,
    "local_calls": 15.0,
    "crt_only": -20.0,
    "called_by_seed": 25.0,
}


class GhidraFunctionScorer:
    """Скоринг функций: эвристика или ML (логрег поверх признаков)."""

    def __init__(
            self,
            strings,
            functions,
            seed_score: int = 60,
            ml_weights: Optional[Dict[str, Any]] = None,
            thunks=None,
    ):
        self.index = FeatureIndex(strings, functions, thunks)
        self.seed_score = seed_score
        self.ml_weights = ml_weights

    # ---- эвристика -----------------------------------------------------
    def _score(self, ft: Dict[str, Any]) -> Tuple[float, List[str]]:
        w = WEIGHTS
        s = 0.0
        reasons: List[str] = []
        name = ft.get("name", "") or ""

        if name.startswith("_"):
            s += w["name_underscore"]; reasons.append("CRT/runtime (name)")
        elif name.startswith("thunk_") or name.startswith("thunk "):
            s += w["name_thunk"]; reasons.append("thunk")
        elif "std::" in name:
            s += w["name_stl"]; reasons.append("STL (name)")
        elif name and not name.startswith("FUN_"):
            s += w["name_lib"]; reasons.append("known library (signature)")

        if ft["n_gmp"]:
            s += w["gmp"]; reasons.append(f"calls GMP x{ft['n_gmp']}")
        if ft["n_stdio"]:
            s += w["stdio"]; reasons.append(f"calls stdio x{ft['n_stdio']}")
        if ft["n_iostream"]:
            s += w["iostream"]; reasons.append("uses cout/cerr/operator<<")
        if ft["n_literals"]:
            s += min(40, 15 * ft["n_literals"])
            reasons.append(f"references {ft['n_literals']} strings")

        size = ft["size"]
        if size >= 500:
            s += w["size_large"]; reasons.append("large function")
        elif size >= 200:
            s += w["size_medium"]; reasons.append("medium function")
        elif size < 40:
            s += w["size_tiny"]; reasons.append("tiny function")

        if ft["n_local_callees"] >= 2:
            s += w["local_calls"]
            reasons.append(f"calls {ft['n_local_callees']} local funcs")

        if ft["n_crt"]:
            s += w["crt_only"]; reasons.append("CRT imports")
        return s, reasons

    # ---- ML --------------------------------------------------------------
    def _ml_score(self, ft: Dict[str, Any]) -> float:
        w = self.ml_weights
        acc = float(w["intercept"])
        for k, m, sc, c in zip(w["feature_keys"], w["mean"], w["scale"], w["coef"]):
            acc += c * ((float(ft.get(k, 0.0)) - m) / sc)
        return acc

    # ---- public API ------------------------------------------------------
    def score_all(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        use_ml = self.ml_weights is not None

        # проход 1: признаки всех функций (нужны для графовых агрегатов)
        feats_all: Dict[str, Dict[str, Any]] = {
            f.get("address"): extract_features(self.index, f)
            for f in self.index.all_functions
        }

        def hot(ft: Optional[Dict[str, Any]]) -> int:
            if not ft:
                return 0
            return int(ft["n_gmp"] > 0 or ft["n_literals"] > 0 or
                       ft["n_iostream"] > 0 or ft["n_stdio"] > 0)

        # проход 2: графовые признаки
        for addr, ft in feats_all.items():
            ft["hot_callers"] = sum(
                1 for p in self.index.callers.get(addr, []) if hot(feats_all.get(p)))
            ft["hot_callees"] = sum(
                1 for c in self.index.resolved_callees.get(addr, []) if hot(feats_all.get(c)))

        scored: List[Dict[str, Any]] = []
        for f in functions:
            ft = feats_all.get(f.get("address")) or extract_features(self.index, f)
            base, reasons = self._score(ft)
            if use_ml:
                base = self._ml_score(ft)
            out = dict(f)
            out.update(ft)
            out["score"] = base
            out["reasons"] = reasons
            scored.append(out)

        if not use_ml:  # каскад только в эвристике (теперь видит сквозь thunk'и)
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