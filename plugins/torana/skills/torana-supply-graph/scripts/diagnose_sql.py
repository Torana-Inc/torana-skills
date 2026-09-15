#!/usr/bin/env python3
"""Whole-file mode — parse a SQL file, run the backward walk per column, aggregate.

  python scripts/diagnose_sql.py widget.sql
  python scripts/diagnose_sql.py --format json widget.sql
  echo "SELECT ..." | python scripts/diagnose_sql.py -

Aggregation is § 3.4.2: worst-wins by the § 3.4.1 `rank`, at most 3 columns, load-bearing
first. ⛔ That rank is CARRIED ON EACH VERDICT from the server-side resolver — it is not a
skill-local ordering, because P9 and the CLI inherit the same table.

`load_bearing` comes from sqlglot's PARSE TREE (§ 3.6.1), never from a guess: a reference
is load-bearing when any ancestor is a filter (WHERE/JOIN/HAVING/QUALIFY), sets the grain
(GROUP BY / PARTITION BY), or computes a value acted upon (CASE/FILTER/Func).

⚠️ Transformer-backed tables (reachable_exploitable_risk, account_hygiene_summary, ...) are
NOT sink tables, so no writer record exists for them. That is UNRESOLVED and it is EXPECTED
until the transformer hop (P8) ships. Reported, never worked around.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # self-relative: allowed

from render import aggregate, internal_note, message_for  # noqa: E402
from supply_graph import (  # noqa: E402
    SupplyGraphError,
    build_supply_graph,
    die,
    resolved_context,
)

try:
    import sqlglot
    from sqlglot import exp
    _SQLGLOT_ERROR = None
except ImportError as _exc:  # pragma: no cover
    sqlglot = None
    exp = None
    _SQLGLOT_ERROR = _exc

# ⛔ § 3.6.1 — POSITIVE membership test, deliberately. Never "everything except ORDER BY":
# an exclusion list breaks silently the day a new node type appears.
# ⚠️ exp.Window and exp.Qualify were MISSING from an earlier draft of this list; a bare
# `ORDER BY t.x` reaches Select without matching, so it returns False naturally.


def _load_bearing_ancestors():
    return (
        exp.Where, exp.Join, exp.Having, exp.Qualify,   # filters
        exp.Group, exp.Window,                          # grain
        exp.Case, exp.Filter, exp.Func,                 # computes a value acted upon
    )


def _clause_of(node) -> str:
    """Nearest enclosing clause, for display only — the load-bearing decision is the
    ancestor-set membership test, never this label."""
    cur = node.parent
    while cur is not None:
        for kind, name in (
            (exp.Where, "WHERE"), (exp.Join, "JOIN"), (exp.Having, "HAVING"),
            (exp.Qualify, "QUALIFY"), (exp.Group, "GROUP BY"), (exp.Order, "ORDER BY"),
            (exp.Window, "WINDOW"), (exp.Select, "SELECT"),
        ):
            if isinstance(cur, kind):
                return name
        cur = cur.parent
    return "?"


def extract_columns(sql: str) -> list[tuple[str, str, bool, str]]:
    """-> [(table, column, load_bearing, clause)] with table resolved from aliases."""
    if sqlglot is None:
        # ⛔ FAIL CLOSED, and name the cause. Guessing load-bearing from a regex would be
        # a verdict computed from a partial view — the thing skills/CLAUDE.md calls
        # strictly worse than failing, because nobody investigates a confident result.
        die(f"sqlglot is unavailable ({_SQLGLOT_ERROR}), and load-bearing classification "
            f"is computed from its parse tree (§ 3.6) — never guessed.\n"
            f"       interpreter: {sys.executable}\n"
            f"  Fix: source $TORANA_ROOT/.venv/bin/activate   (or: pip install sqlglot)\n"
            f"  Or:  use diagnose_column.py with explicit table.column names — it needs "
            f"no parser.")
    try:
        statements = sqlglot.parse(sql, read="postgres")
    except Exception as exc:  # noqa: BLE001
        die(f"could not parse the SQL: {exc}")
        return []

    found: dict[tuple[str, str], tuple[bool, str]] = {}
    lb_ancestors = _load_bearing_ancestors()

    for stmt in statements:
        if stmt is None:
            continue
        # alias -> real table name
        alias_map: dict[str, str] = {}
        for table in stmt.find_all(exp.Table):
            real = table.name
            if table.alias:
                alias_map[table.alias] = real
            alias_map.setdefault(real, real)

        single = None
        tables = {t.name for t in stmt.find_all(exp.Table)}
        if len(tables) == 1:
            single = next(iter(tables))

        for col in stmt.find_all(exp.Column):
            name = col.name
            qualifier = col.table
            table = alias_map.get(qualifier, qualifier) if qualifier else single
            if not table or not name or name == "*":
                continue
            # walk ancestors outward; stop at the first match
            load_bearing = False
            cur = col.parent
            while cur is not None:
                if isinstance(cur, lb_ancestors):
                    load_bearing = True
                    break
                cur = cur.parent
            key = (table, name)
            clause = _clause_of(col)
            if key in found:
                prev_lb, prev_clause = found[key]
                found[key] = (prev_lb or load_bearing, prev_clause)
            else:
                found[key] = (load_bearing, clause)

    return [(t, c, lb, cl) for (t, c), (lb, cl) in sorted(found.items())]


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose every column in a SQL file.")
    ap.add_argument("file", help="path to a .sql file, or - for stdin")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--tenant-profile", default="T1")
    ap.add_argument("--sa-profile", default="SA")
    ap.add_argument("--allow-degraded", action="store_true")
    args = ap.parse_args()

    sql = sys.stdin.read() if args.file == "-" else open(args.file).read()
    refs = extract_columns(sql)
    if not refs:
        die("no column references found in that SQL")

    try:
        graph, inputs = build_supply_graph(
            args.tenant_profile, args.sa_profile, args.allow_degraded
        )
    except SupplyGraphError as exc:
        die(str(exc))
        return 2

    verdicts = graph.diagnose([(t, c) for t, c, _, _ in refs])
    for v, (_, _, lb, clause) in zip(verdicts, refs):
        v.load_bearing = lb
        v.clause = clause

    summary = aggregate(verdicts)
    context = resolved_context(inputs)

    if args.format == "json":
        json.dump(
            {"schema_version": 1,
             "resolved_context": context,
             "query_verdict": summary,
             "columns": [{**v.to_dict(), "customer_message": message_for(v)}
                         for v in verdicts]},
            sys.stdout, indent=2,
        )
        sys.stdout.write("\n")
        return 0

    print(f"{len(verdicts)} column reference(s) in {args.file}\n")
    order = sorted(verdicts,
                   key=lambda v: (v.rank if v.rank is not None else 99,
                                  not v.load_bearing, v.table, v.column))
    for v in order:
        flag = "load-bearing" if v.load_bearing else "display"
        print(f"  {v.verdict:<17} {v.table}.{v.column}  [{v.clause}, {flag}]")
        note = internal_note(v)
        if note and v.verdict != "SUPPLIED":
            print(f"      {note}")

    print(f"\n{'=' * 62}")
    print(f"QUERY VERDICT : {summary['verdict']}")
    if summary.get("neutral_empty_state"):
        print("                ⚠️  not customer-facing — render the neutral empty state")
        print("                and emit internal telemetry. Never an incident message.")
    elif summary["verdict"] == "SUPPLIED":
        print("                ⛔ every column is supplied. A 0-row result here means the")
        print("                FILTERS MATCHED NOTHING — that is not a supply problem.")
        print("                Render nothing, or a neutral 'No matching records.'")
    else:
        print(f"driven by     : {summary['columns']}")
        print(f"say to user   : {summary['message']}")
    print(f"\nresolved against {context['reachable_column_count']} reachable columns "
          f"· tenant profile {context['tenant_profile']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
