from __future__ import annotations

"""Offline dialect lab: unknown gcc → catalog mini. Not restore.

  py -m src.analysis.dialect_loop --from-report output/apply_inimini_report.json
  py -m src.analysis.dialect_loop --message "invalid cast from type '__const_iterator'..."

Does not patch ghidra_cpp.py. Does not copy YAML into eval/corpus.
Live restore still only writes corpus_proposals and stops.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.agents.compiler import _safe_search, match_errors, skip_forever_reason
from src.analysis.corpus import load_corpus
from src.analysis.eval_heldout import FROZEN_TOKENS
from src.analysis.gen_corpus import MINI_PROGRAMS

ROOT = Path(__file__).resolve().parents[2]

# LLM restore debris: not a Ghidra dialect class. Do not emit a catalog mini.
_RESTORE_DEBRIS = (
    r"missing terminating ['\"] character",
    r"'else' without a previous 'if'",
    r"break statement not within loop or switch",
    r"expected unqualified-id before '(?:void|return)'",
    r"expected unqualified-id before '\{' token",
    r"expected unqualified-id before string constant",
    r"expected declaration before '\}' token",
    r"expected unqualified-id before ',' token",
    r"expected unqualified-id before '>' token",
    r"invalid declarator before ',' token",
    r"invalid declarator before '>' token",
    r"stray '`' in program",
)

# Honest Q3 minis: gcc text → generator id + Ghidra token to require in a dump.
CATALOG: Sequence[tuple[str, str, str]] = (
    (r"const_std::|'conststd' was not declared", "map_str_size", "const_std::"),
    (
        r"_Node_iterator|_Node_const_iterator|__detail::operator(==|!=)",
        "umap_str_walk",
        "_M_cur",
    ),
    (
        r"expected constructor, destructor, or type conversion before ';'|"
        r"cannot convert 'std::unordered_map.*\*' to 'int\*'",
        "umap_collect",
        "* collect(",
    ),
    (
        r"'pointer'.*is not a pointer-to-object type",
        "umap_show_val",
        "->second",
    ),
    (
        r"invalid cast from type '__const_iterator'.*basic_string",
        "string_ret_ws",
        "_M_current",
    ),
    (
        r"base operand of '->' has non-pointer type 'const_reference'|"
        r"no match for 'operator=' \(operand types are 'const_reference'",
        "vec_field_n",
        "const_reference",
    ),
    (
        r"'_Rb_tree_const_iterator' was not declared|"
        r"'_Rb_tree_const_iterator'.*is not a template",
        "map_walk_n",
        "_Rb_tree_const_iterator",
    ),
    (
        r"'__normal_iterator' was not declared|"
        r"'__normal_iterator'.*is not a template",
        "vec_sum_n",
        "__normal_iterator",
    ),
    (
        r"no match for 'operator=' \(operand types are 'const_iterator'",
        "vec_sum_n",
        "const_iterator",
    ),
    (
        r"'_bool_' was not declared",
        "vec_sort_n",
        "_bool_",
    ),
    (
        r"'sort' is not a member of 'std'",
        "vec_sort_n",
        "sort<",
    ),
    (
        r"::vector\(.*value_type_conflict",
        "vec_fill_n",
        "value_type_conflict",
    ),
    (
        r"'time_point' was not declared",
        "chrono_now",
        "time_point",
    ),
)


_RE_PATH = re.compile(r"(?:[A-Za-z]:)?(?:[\\/][^\s:'\"]+)+")
_RE_AKA = re.compile(r"\s*\{aka\s+'[^']*'\}")
_REFUSE_MINI = (
    "heldout", "pointcloud", "echofilter", "mycollatz", "xorcipher",
    "inimini", "parse_ini", "taskboard", "netpath", "fibtimer",
)


def normalize_message(msg: str) -> str:
    """Drop paths and aka-clauses so the same class clusters across TUs."""
    t = msg or ""
    t = _RE_PATH.sub(" ", t)
    t = _RE_AKA.sub("", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _mini_by_id(mini_id: str):
    for prog in MINI_PROGRAMS:
        if prog.id == mini_id:
            return prog
    return None


def _refuse_mini(mini_id: str, source: str) -> Optional[str]:
    blob = f"{mini_id} {source}"
    low = blob.lower()
    for tok in _REFUSE_MINI:
        if tok in low:
            return f"refusing mini {mini_id!r} ({tok})"
    for tok in FROZEN_TOKENS:
        if tok in blob:
            return f"refusing frozen token {tok!r} in mini {mini_id!r}"
    return None


def _skip_forever_reason(msg: str) -> Optional[str]:
    return skip_forever_reason(msg)


def _restore_debris_reason(msg: str) -> Optional[str]:
    text = msg or ""
    for pat in _RESTORE_DEBRIS:
        if _safe_search(pat, text):
            return "restore TU debris (not Ghidra dialect)"
    return None


def _catalog_hit(msg: str) -> Optional[tuple[str, str]]:
    for pat, mini_id, token in CATALOG:
        if _safe_search(pat, msg):
            return mini_id, token
    return None


def plan_messages(
    messages: Sequence[str],
    *,
    budget: int = 1,
    corpus_cases=None,
) -> Dict[str, Any]:
    """Classify gcc lines: known / skip-forever / catalog mini / unmatched."""
    cases = corpus_cases if corpus_cases is not None else load_corpus()
    errors = [{"message": m} for m in messages if (m or "").strip()]
    decision = match_errors(errors, cases)

    known_set = {h.message for h in decision.known}
    clusters: List[Dict[str, Any]] = []
    seen_mini: Dict[str, int] = {}
    seen_skip: Dict[str, int] = {}
    seen_known: Dict[tuple, int] = {}
    n_no_catalog = 0

    for msg in messages:
        text = (msg or "").strip()
        if not text:
            continue
        forever = _skip_forever_reason(text)
        if forever:
            idx = seen_skip.get(forever)
            if idx is None:
                seen_skip[forever] = len(clusters)
                clusters.append({
                    "action": "skip_forever",
                    "reason": forever,
                    "messages": [text],
                    "mini_id": "",
                    "token": "",
                })
            else:
                clusters[idx]["messages"].append(text)
            continue
        debris = _restore_debris_reason(text)
        if debris:
            idx = seen_skip.get(debris)
            if idx is None:
                seen_skip[debris] = len(clusters)
                clusters.append({
                    "action": "skip_restore_debris",
                    "reason": debris,
                    "messages": [text],
                    "mini_id": "",
                    "token": "",
                })
            else:
                clusters[idx]["messages"].append(text)
            continue
        if text in known_set:
            ids = tuple(
                cid
                for h in decision.known
                if h.message == text
                for cid in h.case_ids
            )
            idx = seen_known.get(ids)
            if idx is None:
                seen_known[ids] = len(clusters)
                clusters.append({
                    "action": "skip_known",
                    "reason": "fingerprint already in corpus",
                    "known_ids": list(ids),
                    "messages": [text],
                    "mini_id": "",
                    "token": "",
                })
            else:
                clusters[idx]["messages"].append(text)
            continue
        hit = _catalog_hit(text)
        if hit:
            mini_id, token = hit
            idx = seen_mini.get(mini_id)
            if idx is None:
                seen_mini[mini_id] = len(clusters)
                clusters.append({
                    "action": "propose_mini",
                    "reason": "catalog match; dump must contain token before any recipe",
                    "mini_id": mini_id,
                    "token": token,
                    "messages": [text],
                    "known_ids": [],
                })
            else:
                clusters[idx]["messages"].append(text)
            continue
        n_no_catalog += 1
        clusters.append({
            "action": "no_catalog",
            "reason": "unknown and no catalog mini; do not regex the user TU",
            "mini_id": "",
            "token": "",
            "messages": [text],
            "known_ids": [],
        })

    proposed = [c for c in clusters if c.get("action") == "propose_mini"]
    cap = max(0, int(budget))
    for i, c in enumerate(proposed):
        c["in_budget"] = i < cap

    return {
        "n_messages": len([m for m in messages if (m or "").strip()]),
        "n_unknown": len(decision.unknown),
        "n_known": len(decision.known),
        "n_no_catalog": n_no_catalog,
        "budget": cap,
        "clusters": clusters,
        "emit": [
            c["mini_id"]
            for c in proposed
            if c.get("in_budget")
        ],
        "note": (
            "dialect_loop is a lab. It does not patch ghidra_cpp.py "
            "and does not accept YAML into eval/corpus."
        ),
    }


def plan_from_report(path: Path, *, budget: int = 1) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("compile_fix") is not None or data.get("assembled_ok") is not None:
        return {
            "report": str(path),
            "refused": "restore/compile TU is not a dialect_loop source; use apply-only or a mini",
            "n_messages": 0,
            "n_unknown": 0,
            "n_known": 0,
            "n_no_catalog": 0,
            "budget": max(0, int(budget)),
            "clusters": [],
            "emit": [],
            "note": (
                "dialect_loop is a lab. It does not patch ghidra_cpp.py "
                "and does not accept YAML into eval/corpus."
            ),
        }
    msgs = list(data.get("unknown_messages") or [])
    rec = plan_messages(msgs, budget=budget)
    rec["report"] = str(path)
    rec["report_name"] = data.get("name")
    rec["report_n_unknown"] = data.get("n_unknown")
    rec["report_known_ids"] = data.get("known_ids") or []
    if not msgs and rec["report_known_ids"]:
        rec["clusters"].append({
            "action": "skip_known",
            "reason": "report has no unknown; leftover gcc already classified",
            "known_ids": list(rec["report_known_ids"]),
            "messages": [],
            "mini_id": "",
            "token": "",
            "in_budget": False,
        })
    return rec


def dump_contains_token(ghidra: Dict[str, Any], token: str) -> bool:
    """True if any function body in a Ghidra dump contains ``token``."""
    needle = (token or "").strip()
    if not needle:
        return False
    for fn in ghidra.get("functions") or []:
        code = str(fn.get("ghidra_code") or fn.get("code") or "")
        if needle in code:
            return True
    return False


def verify_dumps(plan: Dict[str, Any], dumps_dir: Path) -> List[Dict[str, Any]]:
    """Require catalog token in an existing dump before any recipe."""
    checks: List[Dict[str, Any]] = []
    for c in plan.get("clusters") or []:
        if c.get("action") != "propose_mini" or not c.get("in_budget"):
            continue
        mini_id = str(c.get("mini_id") or "")
        token = str(c.get("token") or "")
        dump = dumps_dir / f"{mini_id}.json"
        rec: Dict[str, Any] = {
            "mini_id": mini_id,
            "token": token,
            "dump": str(dump),
            "token_ok": None,
        }
        if not dump.exists():
            rec["error"] = "dump missing; run --ghidra or gen_corpus --ghidra --ids"
            checks.append(rec)
            continue
        try:
            data = json.loads(dump.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            rec["error"] = str(exc)
            checks.append(rec)
            continue
        rec["token_ok"] = dump_contains_token(data, token)
        if not rec["token_ok"]:
            rec["error"] = "hypothesized token not in dump; do not regex the user TU"
        checks.append(rec)
    plan["dump_checks"] = checks
    return checks


def emit_minis(mini_ids: Sequence[str], out_dir: Path) -> List[Dict[str, Any]]:
    """Write catalog sources. Never into eval/corpus."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Dict[str, Any]] = []
    for mid in mini_ids:
        prog = _mini_by_id(mid)
        rec: Dict[str, Any] = {"id": mid, "ok": False}
        if prog is None:
            rec["error"] = f"unknown mini id {mid!r}"
            written.append(rec)
            continue
        hit = _refuse_mini(prog.id, prog.source)
        if hit:
            rec["error"] = hit
            written.append(rec)
            continue
        path = out_dir / f"{prog.id}.cpp"
        path.write_text(prog.source, encoding="utf-8")
        rec["ok"] = True
        rec["path"] = str(path)
        written.append(rec)
    return written


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Unknown gcc → catalog mini (lab, not restore)"
    )
    parser.add_argument("--from-report", help="eval_heldout_entry JSON")
    parser.add_argument(
        "--message",
        action="append",
        dest="messages",
        help="Raw gcc diagnostic (repeatable)",
    )
    parser.add_argument("--budget", type=int, default=1, help="Max minis to emit")
    parser.add_argument(
        "--emit",
        action="store_true",
        help="Write in-budget mini .cpp under --out-dir (not eval/corpus)",
    )
    parser.add_argument("--out-dir", default="output/dialect_loop")
    parser.add_argument("--out", default="", help="JSON plan path")
    parser.add_argument(
        "--dumps-dir",
        default="output/corpus_gen/ghidra_dumps",
        help="Existing Ghidra JSON dumps for token checks",
    )
    parser.add_argument(
        "--ghidra",
        action="store_true",
        help="Decompile in-budget minis, then check catalog tokens",
    )
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--force-ghidra", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.from_report:
        plan = plan_from_report(Path(args.from_report), budget=args.budget)
    elif args.messages:
        plan = plan_messages(args.messages, budget=args.budget)
    else:
        parser.error("Provide --from-report or --message")
        return 2

    if args.emit or args.ghidra:
        plan["emitted"] = emit_minis(plan.get("emit") or [], Path(args.out_dir))

    dumps_dir = Path(args.dumps_dir)
    if args.ghidra:
        from src.analysis.gen_corpus import emit_programs, run_ghidra_on_programs
        from src.config import load_config

        wanted = [_mini_by_id(i) for i in (plan.get("emit") or [])]
        wanted = [p for p in wanted if p is not None]
        cfg = load_config(args.config)
        if not cfg.ghidra_path:
            plan["ghidra_error"] = "ghidra_path missing in config"
        elif wanted:
            src_dir = Path(args.out_dir)
            emit_programs(src_dir, programs=wanted)
            dumps_dir.mkdir(parents=True, exist_ok=True)
            plan["ghidra"] = run_ghidra_on_programs(
                src_dir,
                ghidra_path=Path(cfg.ghidra_path),
                draft_dir=Path(args.out_dir) / "drafts",
                timeout_sec=cfg.ghidra_timeout,
                programs=wanted,
                dump_dir=dumps_dir,
                force=args.force_ghidra,
            )

    if args.emit or args.ghidra or Path(args.dumps_dir).exists():
        verify_dumps(plan, dumps_dir)

    text = json.dumps(plan, indent=2, ensure_ascii=False)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
