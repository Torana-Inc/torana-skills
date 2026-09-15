#!/usr/bin/env python3
"""Acceptance test — SUPPLY_GRAPH_SPEC.md § 3.13 / § 3.14, measured on T1.

  python scripts/acceptance.py

⛔ § 3.13 IS the acceptance test: "Nothing below is illustrative. Each row was produced by
running the traversal against the live platform. If the skill does not reproduce them, the
skill is wrong."

Two classes of check, and the distinction matters:

  VERDICT checks   — must reproduce EXACTLY. A wrong verdict is a wrong customer message.
  SHAPE checks     — the SOLE-writer / dark-column counts of § 3.13.3 / § 3.14.2. These are
                     measurements of a moving platform (§ 3.10.1 records the reachable
                     count moving 384->389->395->397 within ONE day), so a drifted total is
                     reported, not failed. ⛔ The sole-writer numbers ARE asserted, because
                     § 3.13.3's own rule is "read the SOLE column, not the total".

⚠️ SOURCE_DISABLED and SYNC_FAILING have NO T1 instance. That is the correct answer today
(every connected integration has all data sources enabled and reports last_sync_status
success), not a bug to chase. This script asserts their ABSENCE so the day one appears is
visible rather than silent.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # self-relative: allowed

from supply_graph import SupplyGraphError, build_supply_graph  # noqa: E402

# § 3.13.1 — one column, seven different answers.
BACKWARD = [
    ("vulnerabilities", "cve_id", "SUPPLIED"),
    ("vulnerabilities", "cvss4_base_score", "PEER_GAP"),
    ("vulnerabilities", "epss_score", "PEER_GAP"),
    ("findings", "confidence", "CATEGORY_MISSING"),
    ("assets", "asset_owner_email", "DOCUMENT_ONLY"),
    ("vulnerabilities", "is_confirmed", "NEEDS_CALLER"),
    ("vulnerabilities", "torana_issue_id", "NEEDS_CALLER"),
    ("assets", "vm_scan_enabled", "UNREACHABLE"),
]

# § 3.13.3 — sole-writer blast radius (asserted) and total writes (drift-reported).
FORWARD_SOLE = {"gcp": 12, "tenable": 48, "snyk": 12, "jira": 15, "qualys": 0}
FORWARD_WRITES = {"gcp": 64, "tenable": 105, "snyk": 47, "jira": 69, "github": 75,
                  "qualys": 28}

# § 3.14.2 — what connecting one more tool is worth (dark columns it would light).
BUYER_DARK = {"tenable": 62, "snyk": 19, "aikido": 13, "qualys": 4, "splunk": 0,
              "semgrep": 3}


def main() -> int:
    try:
        graph, inputs = build_supply_graph()
    except SupplyGraphError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    failures: list[str] = []
    drift: list[str] = []

    print(f"resolved against {inputs.reach.get('count')} reachable columns · "
          f"connected: {', '.join(sorted(graph.connected_integrations()))}\n")

    # ---- § 3.13.1 backward -------------------------------------------------
    print("§ 3.13.1  backward — eight columns, seven verdicts")
    verdicts = graph.diagnose([(t, c) for t, c, _ in BACKWARD])
    for (table, column, want), got in zip(BACKWARD, verdicts):
        ok = got.verdict == want
        print(f"  {'PASS' if ok else 'FAIL'}  {table}.{column:<22} "
              f"want={want:<17} got={got.verdict}")
        if not ok:
            failures.append(f"{table}.{column}: want {want}, got {got.verdict}")

    # ---- verdicts with no T1 instance --------------------------------------
    print("\n§ 3.13.1  the two verdicts that correctly have NO T1 instance")
    everything = graph.diagnose(graph.all_columns())
    seen = {v.verdict for v in everything}
    for absent in ("SOURCE_DISABLED", "SYNC_FAILING"):
        if absent in seen:
            n = sum(1 for v in everything if v.verdict == absent)
            print(f"  NOTE  {absent} now has {n} instance(s) — the platform state CHANGED.")
            print("        Not a failure: verify the instance is real, then update § 3.13.")
            drift.append(f"{absent} appeared ({n})")
        else:
            print(f"  PASS  {absent:<17} no T1 instance — correct answer today")

    # ---- § 3.13.3 forward --------------------------------------------------
    print("\n§ 3.13.3  forward — SOLE-writer blast radius (asserted)")
    for name, want_sole in FORWARD_SOLE.items():
        report = graph.forward(name)
        got = len(report.sole_writes)
        ok = got == want_sole
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<10} sole={got:<4} (spec {want_sole})")
        if not ok:
            failures.append(f"forward {name}: sole {got} != {want_sole}")

    print("\n§ 3.13.3  forward — TOTAL writes (drift-reported, not asserted)")
    for name, want_total in FORWARD_WRITES.items():
        got = len(graph.forward(name).writes)
        mark = "same" if got == want_total else f"DRIFT {want_total}->{got}"
        print(f"        {name:<10} writes={got:<5} {mark}")
        if got != want_total:
            drift.append(f"{name} writes {want_total}->{got}")

    # ---- § 3.14.2 buyer ----------------------------------------------------
    print("\n§ 3.14.2  buyer — dark columns connecting a tool would light up")
    for name, want in BUYER_DARK.items():
        got = len(graph.forward(name).would_light)
        ok = got == want
        # splunk 0 / qualys 0-sole are the load-bearing 'honest no' cases; assert those.
        strict = want == 0
        status = "PASS" if ok else ("FAIL" if strict else "DRIFT")
        print(f"  {status:<5} {name:<10} would_light={got:<4} (spec {want})")
        if not ok:
            (failures if strict else drift).append(
                f"buyer {name}: would_light {got} != {want}")

    # ---- result ------------------------------------------------------------
    print(f"\n{'=' * 64}")
    if drift:
        print(f"DRIFT ({len(drift)}) — measurements of a moving platform, not failures:")
        for d in drift:
            print(f"  · {d}")
    if failures:
        print(f"\nFAILED ({len(failures)}):")
        for f in failures:
            print(f"  · {f}")
        return 1
    print("\nALL VERDICT CHECKS PASS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
