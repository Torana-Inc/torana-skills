#!/usr/bin/env python3
"""Backward walk — "why is this column empty for this tenant?"

  python scripts/diagnose_column.py vulnerabilities.cve_id assets.vm_scan_enabled
  python scripts/diagnose_column.py --format json vulnerabilities.is_confirmed

⛔ Two calls, TWO DIFFERENT PROFILES (§ 3.10.1):
     reachable-columns -> --tenant-profile (default T1)
     category-map      -> --sa-profile     (default SA, super-admin ONLY)

⛔ --json emits ONLY JSON on stdout; diagnostics go to stderr (skills/CLAUDE.md).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # self-relative: allowed

from render import internal_note, message_for  # noqa: E402
from supply_graph import (  # noqa: E402
    SupplyGraphError,
    build_supply_graph,
    die,
    resolved_context,
)


def parse_column(token: str) -> tuple[str, str]:
    if token.count(".") != 1:
        die(f"expected <table>.<column>, got {token!r}")
    table, column = token.split(".")
    if not table or not column:
        die(f"expected <table>.<column>, got {token!r}")
    return table, column


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose why a column is empty.")
    ap.add_argument("columns", nargs="+", metavar="TABLE.COLUMN")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--tenant-profile", default="T1")
    ap.add_argument("--sa-profile", default="SA")
    ap.add_argument(
        "--allow-degraded",
        action="store_true",
        help="proceed without the super-admin category half; category-dependent "
             "verdicts collapse to UNRESOLVED rather than guessing a vendor",
    )
    args = ap.parse_args()

    targets = [parse_column(c) for c in args.columns]
    try:
        graph, inputs = build_supply_graph(
            args.tenant_profile, args.sa_profile, args.allow_degraded
        )
    except SupplyGraphError as exc:
        die(str(exc))
        return 2

    verdicts = graph.diagnose(targets)
    context = resolved_context(inputs)

    if args.format == "json":
        json.dump(
            {
                "schema_version": 1,
                "resolved_context": context,
                "columns": [
                    {**v.to_dict(),
                     "customer_message": message_for(v),
                     "internal_note": internal_note(v)}
                    for v in verdicts
                ],
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    if inputs.degraded:
        print("⚠️  DEGRADED: the super-admin category half is unavailable.", file=sys.stderr)
        print("    CATEGORY_MISSING and PEER_GAP cannot be resolved and are reported as",
              file=sys.stderr)
        print("    UNRESOLVED. No vendor name is inferred.\n", file=sys.stderr)

    for v in verdicts:
        print(f"{v.table}.{v.column}")
        print(f"  verdict     : {v.verdict}"
              f"{'' if v.rank is None else f'  (rank {v.rank})'}")
        msg = message_for(v)
        if msg:
            print(f"  say to user : {msg}")
        elif v.verdict == "SUPPLIED":
            print("  say to user : (nothing — a 0-row result here is not a supply problem)")
        else:
            print("  say to user : (neutral empty state — not customer-facing)")
        note = internal_note(v)
        if note:
            print(f"  internal    : {note}")
        print()

    print(f"resolved against {context['reachable_column_count']} reachable columns"
          f" · tenant profile {context['tenant_profile']}"
          f" · connected: {', '.join(context['connected_integrations'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
