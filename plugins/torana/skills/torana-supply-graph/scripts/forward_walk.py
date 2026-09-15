#!/usr/bin/env python3
"""Forward walk — "what breaks if this integration disconnects?" (§ 3.2.2)

  python scripts/forward_walk.py gcp
  python scripts/forward_walk.py --format json tenable
  python scripts/forward_walk.py --all          # rank every known integration

⛔ READ THE SOLE-WRITER NUMBER, NOT THE TOTAL. `cve_id` has seven writers; losing one
changes nothing. Reporting "Tenable writes 115 columns" overstates its blast radius by
more than 2x — sole-written is what actually goes dark.

The same walk answers the buyer's question from the other side: for an integration that is
NOT connected, `would_light` is how many currently-dark columns connecting it would
populate (§ 3.14.2 Q7/Q8).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # self-relative: allowed

from supply_graph import (  # noqa: E402
    SupplyGraphError,
    build_supply_graph,
    die,
    resolved_context,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Forward walk / blast radius.")
    ap.add_argument("integration", nargs="?", help="e.g. gcp, tenable, github")
    ap.add_argument("--all", action="store_true", help="rank every known integration")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--tenant-profile", default="T1")
    ap.add_argument("--sa-profile", default="SA")
    ap.add_argument("--allow-degraded", action="store_true")
    args = ap.parse_args()

    if not args.integration and not args.all:
        die("give an integration name, or --all")

    try:
        # The forward walk needs no category data, so degrade freely here: it costs
        # nothing and lets a tenant-only operator run it.
        graph, inputs = build_supply_graph(
            args.tenant_profile, args.sa_profile, allow_degraded=True
        )
    except SupplyGraphError as exc:
        die(str(exc))
        return 2

    names = sorted(graph.known_integrations()) if args.all else [args.integration]
    reports = [graph.forward(n) for n in names]

    if not args.all and reports[0].writes == []:
        print(f"WARNING: {args.integration!r} writes no column in the reachable set. "
              f"Check the name against: {', '.join(sorted(graph.known_integrations()))}",
              file=sys.stderr)

    if args.format == "json":
        json.dump(
            {"schema_version": 1,
             "resolved_context": resolved_context(inputs),
             "integrations": [r.to_dict() for r in reports]},
            sys.stdout, indent=2,
        )
        sys.stdout.write("\n")
        return 0

    reports.sort(key=lambda r: (-len(r.sole_writes), r.integration))
    print(f"{'integration':<16}{'conn':<7}{'writes':>7}{'SOLE':>7}{'would-light':>13}")
    print("-" * 50)
    for r in reports:
        conn = "yes" if r.connected else "no"
        light = "" if r.connected else str(len(r.would_light))
        print(f"{r.integration:<16}{conn:<7}{len(r.writes):>7}"
              f"{len(r.sole_writes):>7}{light:>13}")
    print()
    print("⛔ SOLE = columns this integration is the ONLY writer of. That is the blast")
    print("   radius; the writes total overstates it.")
    print("   would-light = dark columns that connecting this integration would populate.")

    if not args.all:
        r = reports[0]
        if r.connected:
            print(f"\nIf {r.integration} disconnects, {len(r.sole_writes)} column(s) go dark:")
            for t, c in sorted(r.sole_writes)[:20]:
                print(f"  {t}.{c}")
            if len(r.sole_writes) > 20:
                print(f"  ... and {len(r.sole_writes) - 20} more")
        elif r.would_light:
            print(f"\nConnecting {r.integration} would light up {len(r.would_light)} "
                  f"currently-dark column(s), e.g.:")
            for t, c in sorted(r.would_light)[:20]:
                print(f"  {t}.{c}")
            if len(r.would_light) > 20:
                print(f"  ... and {len(r.would_light) - 20} more")
        else:
            print(f"\n⚠️  Connecting {r.integration} would light up NOTHING new — every "
                  f"column it writes already has a connected source. An honest 'no'.")

    ctx = resolved_context(inputs)
    print(f"\nresolved against {ctx['reachable_column_count']} reachable columns "
          f"· tenant profile {ctx['tenant_profile']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
