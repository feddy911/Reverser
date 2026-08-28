from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RunMetrics:
    """Метрики одного прогона пайплайна."""

    stages_sec: Dict[str, float] = field(default_factory=dict)
    llm_attempted: int = 0
    llm_ok: int = 0
    llm_fail: int = 0
    llm_fallback: int = 0
    llm_cache_hit: int = 0
    polish_attempted: int = 0
    polish_ok: int = 0
    polish_fail: int = 0
    polish_skipped: int = 0
    polish_rolled_back: int = 0
    fidelity_scores: List[float] = field(default_factory=list)
    functions_total: int = 0
    candidates: int = 0
    llm_top: int = 0
    domain_pack: str = "none"
    triage_profile: str = ""
    scoring_mode: str = "heuristic"

    def mark_stage(self, name: str, started_at: float) -> None:
        self.stages_sec[name] = round(time.perf_counter() - started_at, 3)

    def record_fidelity(self, report: List[Dict[str, Any]]) -> None:
        self.fidelity_scores = [
            float(r.get("fidelity", 0.0)) for r in (report or []) if "fidelity" in r
        ]

    def to_dict(self) -> Dict[str, Any]:
        scores = self.fidelity_scores
        fid_summary: Dict[str, Any] = {"count": len(scores)}
        if scores:
            fid_summary.update(
                {
                    "mean": round(sum(scores) / len(scores), 3),
                    "min": round(min(scores), 3),
                    "max": round(max(scores), 3),
                }
            )
        llm_total = max(1, self.llm_attempted)
        return {
            "domain_pack": self.domain_pack,
            "triage_profile": self.triage_profile,
            "scoring_mode": self.scoring_mode,
            "functions_total": self.functions_total,
            "candidates": self.candidates,
            "llm_top": self.llm_top,
            "stages_sec": dict(self.stages_sec),
            "llm": {
                "attempted": self.llm_attempted,
                "ok": self.llm_ok,
                "fail": self.llm_fail,
                "fallback": self.llm_fallback,
                "cache_hit": self.llm_cache_hit,
                "fail_rate": round(self.llm_fail / llm_total, 3),
            },
            "polish": {
                "attempted": self.polish_attempted,
                "ok": self.polish_ok,
                "fail": self.polish_fail,
                "skipped_high_fid": self.polish_skipped,
                "rolled_back": self.polish_rolled_back,
            },
            "fidelity": fid_summary,
        }

    def summary_lines(self) -> List[str]:
        d = self.to_dict()
        lines = ["=== RUN METRICS ==="]
        for stage, sec in d["stages_sec"].items():
            lines.append(f"  stage {stage}: {sec:.3f}s")
        llm = d["llm"]
        lines.append(
            f"  llm: ok={llm['ok']} fail={llm['fail']} "
            f"fallback={llm['fallback']} cache_hit={llm.get('cache_hit', 0)} "
            f"fail_rate={llm['fail_rate']:.1%}"
        )
        pol = d["polish"]
        if pol["attempted"] or pol["skipped_high_fid"]:
            lines.append(
                f"  polish: ok={pol['ok']} fail={pol['fail']} "
                f"skip={pol['skipped_high_fid']} rollback={pol['rolled_back']}"
            )
        fid = d["fidelity"]
        if fid["count"]:
            lines.append(
                f"  fidelity: n={fid['count']} mean={fid['mean']:.3f} "
                f"min={fid['min']:.3f} max={fid['max']:.3f}"
            )
        lines.append(
            f"  domain_pack={d['domain_pack']} profile={d.get('triage_profile') or '-'} "
            f"scoring={d['scoring_mode']}"
        )
        return lines
