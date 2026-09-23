from __future__ import annotations

"""SQLite warehouse for live pipeline runs. Not the dialect catalog.

Recipes and skip-forever stay in git (eval/corpus YAML, compiler.py).
This store indexes output/logs so scorecards are not copied by hand.

  py -m src.analysis.run_store ingest
  py -m src.analysis.run_store scorecard
"""

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "output" / "runs.sqlite"
DEFAULT_LOGS = ROOT / "output" / "logs"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY,
  run_dir TEXT NOT NULL UNIQUE,
  sample TEXT NOT NULL,
  binary_md5 TEXT,
  prompt_ver TEXT,
  profile TEXT,
  started_at TEXT,
  critic_accept INTEGER,
  identity_ok INTEGER,
  fidelity_ok INTEGER,
  compile_ok INTEGER,
  tu_gcc INTEGER,
  fid_mean REAL,
  per_fn_ok INTEGER,
  per_fn_n INTEGER,
  llm_cache_hit INTEGER,
  n_unknown INTEGER,
  skip_forever TEXT,
  known_ids TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_sample_started ON runs(sample, started_at);
CREATE TABLE IF NOT EXISTS gcc_errors (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  kind TEXT NOT NULL,
  reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_gcc_run ON gcc_errors(run_id);
"""

_RUN_DIR_TS = re.compile(r"run_(\d{8}_\d{6})")


def connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _sample_name(run_dir: Path, binary_info: Any) -> str:
    if isinstance(binary_info, dict):
        raw = str(binary_info.get("path") or "")
        if raw:
            return Path(raw).stem
    return run_dir.name


def _started_at(run_dir: Path) -> str:
    m = _RUN_DIR_TS.search(run_dir.name)
    return m.group(1) if m else run_dir.name


_LEFTOVER_CASE_MARKERS = (
    "ostream-addr-insert",
    "ostream-overlay-insert",
    "dead-array-home",
    "concat-shift",
    "concat71-low",
    "extra-star-stack-array",
    "extra-star-formal",
    "gs-cookie-slot",
    "glued-placement-new",
    "glued-ctrl-brace",
    "init-list-priv-field",
    "overlay-ptr-qword",
)


def _classify_errors(
    errors: Sequence[Dict[str, str]],
    *,
    tu_text: str = "",
    call_sites: object | None = None,
    iat_facts: object | None = None,
    dat_facts: object | None = None,
) -> Dict[str, Any]:
    from src.agents.compiler import match_errors
    from src.analysis.feedback_facts import ACTION_LEFTOVER, plan_one
    from src.analysis.ghidra_cpp import (
        leftover_concat71_low_byte,
        leftover_extra_star_formal,
        leftover_extra_star_stack_array,
        leftover_glued_ctrl_brace,
        leftover_glued_placement_new,
        leftover_init_list_priv_field,
        leftover_gs_cookie_slot,
        leftover_overlay_ptr_qword,
        leftover_ostream_addr_insert,
        leftover_ostream_overlay_insert,
    )

    decision = match_errors(list(errors or []))
    rows: List[Dict[str, str]] = []
    for tok in leftover_ostream_addr_insert(tu_text):
        rows.append({
            "message": tok,
            "kind": "leftover",
            "reason": "ostream_addr",
        })
        break
    for name in leftover_ostream_overlay_insert(tu_text):
        rows.append({
            "message": name,
            "kind": "leftover",
            "reason": "ostream_overlay",
        })
        break
    for name in leftover_concat71_low_byte(tu_text):
        rows.append({
            "message": name,
            "kind": "leftover",
            "reason": "concat71_low",
        })
        break
    for name in leftover_extra_star_stack_array(tu_text):
        rows.append({
            "message": name,
            "kind": "leftover",
            "reason": "extra_star",
        })
        break
    for name in leftover_extra_star_formal(tu_text):
        rows.append({
            "message": name,
            "kind": "leftover",
            "reason": "extra_star_formal",
        })
        break
    for name in leftover_gs_cookie_slot(tu_text):
        rows.append({
            "message": name,
            "kind": "leftover",
            "reason": "gs_cookie",
        })
        break
    for tok in leftover_glued_placement_new(tu_text):
        rows.append({
            "message": tok,
            "kind": "leftover",
            "reason": "glued_new",
        })
        break
    for tok in leftover_glued_ctrl_brace(tu_text):
        rows.append({
            "message": tok,
            "kind": "leftover",
            "reason": "glued_brace",
        })
        break
    for name in leftover_init_list_priv_field(tu_text):
        rows.append({
            "message": name,
            "kind": "leftover",
            "reason": "init_list_field",
        })
        break
    for name in leftover_overlay_ptr_qword(tu_text):
        rows.append({
            "message": name,
            "kind": "leftover",
            "reason": "overlay_ptr",
        })
        break
    for hit in decision.skip_forever:
        fb = plan_one(
            hit.reason,
            hit.message,
            tu_text,
            call_sites=call_sites,
            iat_facts=iat_facts,
            dat_facts=dat_facts,
        )
        if fb.get("action") == ACTION_LEFTOVER:
            rows.append({
                "message": hit.message,
                "kind": "leftover",
                "reason": str(fb.get("kind") or hit.reason),
            })
        else:
            rows.append({
                "message": hit.message,
                "kind": "skip_forever",
                "reason": hit.reason,
            })
    for hit in decision.known:
        joined = ",".join(hit.case_ids)
        kind = "leftover" if any(m in joined for m in _LEFTOVER_CASE_MARKERS) else "known"
        reason = "ostream_addr" if "ostream-addr-insert" in joined else joined
        if kind == "leftover" and "ostream-overlay-insert" in joined:
            reason = "ostream_overlay"
        if kind == "leftover" and "dead-array" in joined:
            reason = "dead_array"
        if kind == "leftover" and "concat-shift" in joined:
            reason = "concat_shift"
        if kind == "leftover" and "concat71-low" in joined:
            reason = "concat71_low"
        if kind == "leftover" and "extra-star-stack-array" in joined:
            reason = "extra_star"
        if kind == "leftover" and "extra-star-formal" in joined:
            reason = "extra_star_formal"
        if kind == "leftover" and "gs-cookie-slot" in joined:
            reason = "gs_cookie"
        if kind == "leftover" and "glued-placement-new" in joined:
            reason = "glued_new"
        if kind == "leftover" and "glued-ctrl-brace" in joined:
            reason = "glued_brace"
        if kind == "leftover" and "init-list-priv-field" in joined:
            reason = "init_list_field"
        if kind == "leftover" and "overlay-ptr-qword" in joined:
            reason = "overlay_ptr"
        rows.append({
            "message": hit.message,
            "kind": kind,
            "reason": reason,
        })
    for msg in decision.unknown:
        rows.append({"message": msg, "kind": "unknown", "reason": ""})
    leftover_n = sum(1 for r in rows if r["kind"] == "leftover")
    skip_forever: List[str] = []
    for r in rows:
        if r["kind"] == "skip_forever" and r["reason"] and r["reason"] not in skip_forever:
            skip_forever.append(r["reason"])
    return {
        "rows": rows,
        "n_unknown": len(decision.unknown),
        "n_leftover": leftover_n,
        "skip_forever": skip_forever,
        "known_ids": decision.known_ids,
    }


def build_analysis_stack(
    errors: Sequence[Dict[str, str]],
    *,
    tu_text: str = "",
    disasm_facts: Sequence[Any] | None = None,
    restored: Sequence[Dict[str, Any]] | None = None,
    call_sites: object | None = None,
    iat_facts: object | None = None,
    dat_facts: object | None = None,
) -> Dict[str, Any]:
    """Classified gcc / leftover bag for planning. Not a recipe catalog."""
    classified = _classify_errors(
        errors,
        tu_text=tu_text,
        call_sites=call_sites,
        iat_facts=iat_facts,
        dat_facts=dat_facts,
    )
    rows: List[Dict[str, str]] = list(classified["rows"])
    if restored:
        from src.analysis.ghidra_cpp import leftover_facts_disagree

        for rec in restored:
            names = leftover_facts_disagree(
                rec.get("cpp_code") or tu_text,
                rec.get("fn_facts"),
            )
            if names:
                rows.append({
                    "message": names[0],
                    "kind": "leftover",
                    "reason": "facts_disagree",
                })
                break
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    leftover_n = sum(1 for r in rows if r["kind"] == "leftover")
    out: Dict[str, Any] = {
        "n": len(rows),
        "counts": counts,
        "n_unknown": classified["n_unknown"],
        "n_leftover": leftover_n,
        "skip_forever": classified["skip_forever"],
        "known_ids": classified["known_ids"],
        "items": rows,
    }
    if disasm_facts is not None:
        items: List[Dict[str, Any]] = []
        keep = (
            "addr",
            "size",
            "callees",
            "stack_alloc",
            "lea_arg_slots",
            "qword_store_slots",
            "source",
            "has_byte_facts",
        )
        for raw in disasm_facts:
            if hasattr(raw, "to_dict"):
                payload = raw.to_dict()
            elif isinstance(raw, dict):
                payload = {k: raw[k] for k in keep if k in raw}
            else:
                continue
            dumped = json.dumps(payload)
            if "****" in dumped or "ghidra_code" in dumped or "cpp_code" in dumped:
                continue
            items.append(payload)
        out["disasm_facts"] = {
            "opt_in": True,
            "n": len(items),
            "n_byte": sum(1 for i in items if i.get("has_byte_facts")),
            "items": items,
        }
    return out


def write_analysis_stack(run_dir: Path, stack: Dict[str, Any]) -> Path:
    path = Path(run_dir) / "analysis_stack.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(stack, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def record_run(
    run_dir: Path,
    *,
    db_path: Optional[Path] = None,
    prompt_ver: str = "",
) -> int:
    """Upsert one output/logs/run_* directory. Returns runs.id."""
    run_dir = Path(run_dir)
    metrics = _load_json(run_dir / "metrics.json") or {}
    critic = _load_json(run_dir / "critic.json") or {}
    compile_rep = _load_json(run_dir / "compile.json") or {}
    binary_info = _load_json(run_dir / "binary_info.json") or {}
    tu_text = ""
    tu_path = run_dir / "restored_final.cpp"
    if tu_path.exists():
        tu_text = tu_path.read_text(encoding="utf-8", errors="replace")
    classified = _classify_errors(compile_rep.get("errors") or [], tu_text=tu_text)
    restored = _load_json(run_dir / "restored.json") or []
    fact_rows = [
        r.get("fn_facts")
        for r in restored
        if isinstance(r, dict) and isinstance(r.get("fn_facts"), dict)
    ]
    stack_kw: Dict[str, Any] = {}
    if fact_rows:
        stack_kw["disasm_facts"] = fact_rows
        stack_kw["restored"] = restored
    write_analysis_stack(run_dir, build_analysis_stack(
        compile_rep.get("errors") or [], tu_text=tu_text, **stack_kw
    ))
    compile_m = metrics.get("compile") or {}
    llm = metrics.get("llm") or {}
    fid = metrics.get("fidelity") or {}
    if not prompt_ver:
        prompt_ver = "p4"
    sample = _sample_name(run_dir, binary_info)
    per_fn_ok = int(compile_m.get("fn_ok") or 0)
    per_fn_fail = int(compile_m.get("fn_fail") or 0)
    row = {
        "run_dir": str(run_dir.resolve()),
        "sample": sample,
        "binary_md5": str(binary_info.get("md5") or ""),
        "prompt_ver": prompt_ver,
        "profile": str(metrics.get("triage_profile") or ""),
        "started_at": _started_at(run_dir),
        "critic_accept": 1 if critic.get("accept") else 0,
        "identity_ok": 1 if critic.get("identity_ok") else 0,
        "fidelity_ok": 1 if critic.get("fidelity_ok") else 0,
        "compile_ok": 1 if (
            critic.get("compile_ok")
            if "compile_ok" in critic
            else compile_m.get("ok")
        ) else 0,
        "tu_gcc": int(compile_m.get("n_errors") or compile_rep.get("n_errors") or 0),
        "fid_mean": float(fid.get("mean") or 0.0),
        "per_fn_ok": per_fn_ok,
        "per_fn_n": per_fn_ok + per_fn_fail,
        "llm_cache_hit": int(llm.get("cache_hit") or 0),
        "n_unknown": int(classified["n_unknown"]),
        "skip_forever": json.dumps(classified["skip_forever"], ensure_ascii=False),
        "known_ids": json.dumps(classified["known_ids"], ensure_ascii=False),
    }
    conn = connect(db_path)
    try:
        conn.execute("DELETE FROM gcc_errors WHERE run_id IN (SELECT id FROM runs WHERE run_dir = ?)", (row["run_dir"],))
        conn.execute("DELETE FROM runs WHERE run_dir = ?", (row["run_dir"],))
        cur = conn.execute(
            """
            INSERT INTO runs (
              run_dir, sample, binary_md5, prompt_ver, profile, started_at,
              critic_accept, identity_ok, fidelity_ok, compile_ok, tu_gcc,
              fid_mean, per_fn_ok, per_fn_n, llm_cache_hit, n_unknown,
              skip_forever, known_ids
            ) VALUES (
              :run_dir, :sample, :binary_md5, :prompt_ver, :profile, :started_at,
              :critic_accept, :identity_ok, :fidelity_ok, :compile_ok, :tu_gcc,
              :fid_mean, :per_fn_ok, :per_fn_n, :llm_cache_hit, :n_unknown,
              :skip_forever, :known_ids
            )
            """,
            row,
        )
        run_id = int(cur.lastrowid)
        conn.executemany(
            "INSERT INTO gcc_errors (run_id, message, kind, reason) VALUES (?, ?, ?, ?)",
            [
                (run_id, e["message"], e["kind"], e["reason"])
                for e in classified["rows"]
            ],
        )
        conn.commit()
        return run_id
    finally:
        conn.close()


def ingest_logs(
    logs_dir: Optional[Path] = None,
    *,
    db_path: Optional[Path] = None,
) -> int:
    root = Path(logs_dir) if logs_dir else DEFAULT_LOGS
    if not root.exists():
        return 0
    n = 0
    for run_dir in sorted(p for p in root.iterdir() if p.is_dir() and p.name.startswith("run_")):
        if not (run_dir / "metrics.json").exists():
            continue
        record_run(run_dir, db_path=db_path)
        n += 1
    return n


def latest_scorecard(*, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT r.* FROM runs r
            INNER JOIN (
              SELECT sample, MAX(started_at) AS started_at
              FROM runs GROUP BY sample
            ) t ON r.sample = t.sample AND r.started_at = t.started_at
            ORDER BY r.tu_gcc ASC, r.sample ASC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def format_scorecard(rows: Sequence[Dict[str, Any]]) -> str:
    lines = [
        f"{'sample':<14} {'critic':<8} {'fid':>5} {'fn':>5} {'gcc':>5} {'unk':>4}  skip-forever",
        "-" * 88,
    ]
    for r in rows:
        critic = "ACCEPT" if r.get("critic_accept") else "REJECT"
        fn = f"{r.get('per_fn_ok') or 0}/{r.get('per_fn_n') or 0}"
        skips = ""
        raw = r.get("skip_forever") or "[]"
        try:
            skips = ", ".join(json.loads(raw)[:3])
        except json.JSONDecodeError:
            skips = str(raw)[:40]
        lines.append(
            f"{str(r.get('sample') or ''):<14} {critic:<8} "
            f"{float(r.get('fid_mean') or 0):5.3f} {fn:>5} "
            f"{int(r.get('tu_gcc') or 0):5d} {int(r.get('n_unknown') or 0):4d}  {skips}"
        )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="SQLite warehouse of live restore runs (not the dialect corpus)"
    )
    parser.add_argument("--db", default=str(DEFAULT_DB))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_ing = sub.add_parser("ingest", help="Index output/logs/run_*")
    p_ing.add_argument("--logs", default=str(DEFAULT_LOGS))
    sub.add_parser("scorecard", help="Latest run per sample")
    args = parser.parse_args(argv)
    db = Path(args.db)
    if args.cmd == "ingest":
        n = ingest_logs(Path(args.logs), db_path=db)
        print(f"OK: ingested {n} runs -> {db}")
        return 0
    rows = latest_scorecard(db_path=db)
    print(format_scorecard(rows))
    print(f"({len(rows)} samples, db={db})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
