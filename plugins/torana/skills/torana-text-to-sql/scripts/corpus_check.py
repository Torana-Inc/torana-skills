#!/usr/bin/env python3
"""Run the reachability gate across the corpus — the skill's calibration harness.

`question_reachable_sql.csv` is a test set with an answer key attached: each row
carries the mechanical pass's verdict (clean / degraded / structural / ...). This
replays the gate against it and reports AGREEMENT, so a change to the gate that
starts condemning clean SQL (or waving through blocked SQL) is visible.

⛔ Runs no SQL and reads no tenant data. Schema only.
"""
from __future__ import annotations

import argparse
import collections
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reachability_gate import check_sql, fetch_reachable  # noqa: E402

csv.field_size_limit(10_000_000)


def bucket(err: str) -> str:
    if not err:
        return "clean"
    if err.startswith("DEGRADED"):
        return "degraded"
    if "STRUCTURAL" in err:
        return "structural"
    if err.startswith("UNPARSEABLE"):
        return "unparseable"
    if "every projected" in err:
        return "nothing_left"
    return "case_blocked"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--scope", default="platform")
    ap.add_argument("--column", default="original_sql",
                    help="which SQL column to gate (original_sql | reachable_sql)")
    ap.add_argument("--only", help="comma-separated bucket filter")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    reach = fetch_reachable(args.scope)
    rows = list(csv.DictReader(open(args.csv)))
    only = set(args.only.split(",")) if args.only else None

    tally = collections.Counter()
    blockers = collections.Counter()
    for r in rows:
        b = bucket(r["error"])
        if only and b not in only:
            continue
        sql = r[args.column]
        if not sql.strip():
            tally[(b, "empty")] += 1
            continue
        res = check_sql(sql, reach)
        if not res["parsed"]:
            verdict = "parse_error"
        elif res["unreachable"]:
            verdict = ("structural" if any(u["structural"] for u in res["unreachable"])
                       else "projection_only")
        elif res["unknown_table"]:
            verdict = "unknown_table"
        else:
            verdict = "reachable"
        tally[(b, verdict)] += 1
        for u in res["unreachable"]:
            blockers[f"{u['table']}.{u['column']}"] += 1
        if args.verbose and b == "clean" and verdict != "reachable":
            print(f"  ⚠️ {r['query_id']} key=clean gate={verdict}: "
                  f"{[f'{u['table']}.{u['column']}' for u in res['unreachable']][:4]}"
                  f" unknown={res['unknown_table'][:3]}")

    print(f"scope={args.scope}  column={args.column}  rows={sum(tally.values())}\n")
    print(f"{'answer key':<14} {'gate verdict':<18} {'n':>4}")
    print("-" * 40)
    for (b, v), n in sorted(tally.items()):
        print(f"{b:<14} {v:<18} {n:>4}")

    if blockers:
        print(f"\ntop blocking columns ({len(blockers)} distinct):")
        for c, n in blockers.most_common(15):
            print(f"  {n:>3}  {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
