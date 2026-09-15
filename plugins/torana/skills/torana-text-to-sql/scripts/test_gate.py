#!/usr/bin/env python3
"""Regression cases for the reachability gate.

Every case here is a bug that was actually made and caught while building this
skill, or a trap the packet named. They pull in opposite directions — the alias
handling that fixes `ORDER BY critical_open` is the same code that, done
carelessly, made `SELECT cve_id` verify zero columns. Keep them together so a
fix for one cannot silently reintroduce the other.

Hermetic: uses a FIXED reachable map, never the network. The fixture is a
deliberately tiny hand-written map, NOT a captured schema dump — this file must
never become the embedded schema listing the skill exists to avoid.

    python test_gate.py
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reachability_gate  # noqa: E402
from reachability_gate import check_sql  # noqa: E402

# These cases drive `check_sql` directly with the fixture map below, so they never go through
# `main()` — which is what normally establishes ground truth from the API.
#
# ⛔ The system columns are a FIXTURE here, not a local import. `load_ground_truth_offline()`
# used to supply them by reading `pantheon-shared` out of a checkout — the exact outward reach
# `skills/CLAUDE.md` forbids, and the reason it forbids it: off-repo, that import degraded
# rather than failed, and the gate then condemned `is_deleted` with a confident verdict.
#
# ⚠️ A fixture is honest HERE because these cases test the PARSER, not ground truth: they ask
# "does the gate see this column reference", with the reachable set supplied. Ground truth
# comes from the API in `main()`, and `check-corpus`/`check` exercise that path for real.
reachability_gate.SYSTEM_COLUMNS = {
    "created_at", "created_by", "is_deleted", "namespace_id", "tenant_id",
    "updated_at", "updated_by",
}
reachability_gate.SYSTEM_PROVENANCE = "test fixture (parser cases only)"
SYSTEM_PROVENANCE = reachability_gate.SYSTEM_PROVENANCE  # noqa: E402

# Minimal fixture: a few reachable + a few known-unreachable columns.
REACH = {
    "vulnerabilities": {"cve_id", "severity", "torana_entity_id",
                        "scan_last_detected_date", "vulnerability_status"},
    "assets": {"asset_team", "torana_entity_id", "asset_name"},
    "issues": {"torana_issue_id", "issue_key", "status"},
}

# `min_checked` guards against a case passing VACUOUSLY — clean because the gate
# skipped everything rather than because the columns are reachable. It is 0 only
# where the SQL genuinely references no datalake column (COUNT(*), a function
# table), which is a real and correct shape.
CASES = [
    # (name, sql, expect_clean, must_flag, min_checked)
    ("system fields are always available",
     "SELECT cve_id FROM vulnerabilities WHERE is_deleted IS NOT TRUE "
     "AND tenant_id = 'x'", True, [], 1),

    ("bare projection is still checked (not self-aliased)",
     "SELECT exploitability_status FROM vulnerabilities",
     False, ["exploitability_status"], 0),

    ("explicit alias in ORDER BY is not a column",
     "SELECT COUNT(*) AS open_findings FROM vulnerabilities "
     "ORDER BY open_findings DESC", True, [], 0),

    ("alias must NOT mask an unreachable column of the same name",
     "SELECT v.exploitability_status AS exploitability_status "
     "FROM vulnerabilities v WHERE v.exploitability_status = 'x'",
     False, ["exploitability_status"], 0),

    ("unreachable in WHERE is STRUCTURAL",
     "SELECT a.asset_team FROM assets a WHERE a.vm_scan_enabled IS TRUE",
     False, ["vm_scan_enabled"], 1),

    ("unreachable inside CASE in SELECT is caught",
     "SELECT CASE WHEN v.is_weaponized THEN 1 ELSE 0 END AS w "
     "FROM vulnerabilities v", False, ["is_weaponized"], 0),

    ("derived table alias is not a datalake table",
     "SELECT a.asset_team, v.open_findings FROM assets a "
     "LEFT JOIN (SELECT torana_entity_id, COUNT(*) AS open_findings "
     "FROM vulnerabilities GROUP BY 1) v "
     "ON v.torana_entity_id = a.torana_entity_id", True, [], 2),

    ("CTE name is not a datalake table",
     "WITH x AS (SELECT cve_id FROM vulnerabilities) SELECT cve_id FROM x",
     True, [], 1),

    ("function table (GENERATE_SERIES) is not a datalake table",
     "SELECT DATE_TRUNC('month', gs)::date AS period "
     "FROM GENERATE_SERIES(NOW() - INTERVAL '3 months', NOW(), "
     "INTERVAL '1 month') gs", True, [], 0),

    ("join predicate on unreachable column is STRUCTURAL",
     "SELECT i.issue_key FROM issues i JOIN vulnerabilities v "
     "ON v.torana_issue_id = i.torana_issue_id",
     False, ["torana_issue_id"], 1),
]


def main() -> int:
    # ⭐ No checkout guard any more: ground truth for these parser cases is the fixture set
    # at the top of this file, so the suite runs identically on a machine with no
    # `pantheon-*` source — which is the environment the skill is built for.
    failed = 0
    for name, sql, expect_clean, must_flag, min_checked in CASES:
        res = check_sql(sql, REACH)
        if not res["parsed"]:
            print(f"❌ {name}\n     parse error: {res['error']}")
            failed += 1
            continue
        flagged = {u["column"].lower() for u in res["unreachable"]}
        ok = True
        detail = []
        if expect_clean:
            if res["unreachable"] or res["unknown_table"]:
                ok = False
                detail.append(f"expected clean, got unreachable={sorted(flagged)} "
                              f"unknown={res['unknown_table']}")
        if res["checked"] < min_checked:
            ok = False
            detail.append(f'verified {res["checked"]} columns, expected '
                          f'>= {min_checked} — vacuously clean')
        for m in must_flag:
            if m.lower() not in flagged:
                ok = False
                detail.append(f"expected to flag {m}, flagged {sorted(flagged)}")
        print(("✅ " if ok else "❌ ") + name +
              ("" if ok else "\n     " + "; ".join(detail)))
        if not ok:
            failed += 1
    print(f"\n{len(CASES) - failed}/{len(CASES)} passed")
    return 1 if failed else 0


def check_evidence_shape_matches_platform() -> int:
    """⛔ The evidence shape is DUPLICATED with the harness on purpose — pin it.

    `skills/CLAUDE.md` forbids a skill importing platform code, so
    `scripts/authoring_evidence.py` is a deliberate copy of
    `pantheon-agent-builder/src/utils/authoring_evidence.py`. § 3.2.1 wants both paths
    emitting the SAME keys. Those two rules only coexist if the drift is DETECTED.

    ⚠️ SKIPS (never fails) when the platform checkout is absent — that is the whole point of
    bundling. On a developer machine, where both exist, a divergence is a failure.
    """
    import authoring_evidence as skill_ev

    plat = None
    for parent in Path(__file__).resolve().parents:
        cand = parent / "pantheon-agent-builder" / "src" / "utils" / "authoring_evidence.py"
        if cand.is_file():
            import importlib.util
            spec = importlib.util.spec_from_file_location("_plat_ev", cand)
            plat = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plat)
            break
    if plat is None:
        print("⏭️  evidence-shape parity: SKIPPED (no platform checkout — expected off-repo)")
        return 0

    if tuple(skill_ev.EVIDENCE_KEYS) != tuple(plat.EVIDENCE_KEYS):
        print(f"❌ evidence-shape parity: keys DRIFTED\n"
              f"     skill   : {skill_ev.EVIDENCE_KEYS}\n"
              f"     platform: {plat.EVIDENCE_KEYS}")
        return 1

    # The per-layer keys must match too — a record whose `joins` lacks `probed` on one path
    # would make the § 3.13.7c roll-up unanswerable from that path.
    a, b = skill_ev.new_evidence("q"), plat.new_evidence("q")
    for fn in ("record_corpus", "record_catalog", "record_schema", "record_joins",
               "record_shape"):
        kw = {"record_corpus": {"resolved": True},
              "record_catalog": {"verdict": "probed"},
              "record_schema": {"scope": "platform", "columns_checked": 1},
              "record_joins": {"source": "query-hints", "probed": False},
              "record_shape": {"result_rows": 1}}[fn]
        getattr(skill_ev, fn)(a, **kw)
        getattr(plat, fn)(b, **kw)
    for layer in skill_ev.EVIDENCE_KEYS:
        if layer == "question":
            continue
        if set(a[layer]) != set(b[layer]):
            print(f"❌ evidence-shape parity: `{layer}` keys DRIFTED\n"
                  f"     skill   : {sorted(a[layer])}\n"
                  f"     platform: {sorted(b[layer])}")
            return 1
    print("✅ evidence-shape parity: skill and platform agree")
    return 0


def check_fanout_constants_match_platform() -> int:
    """⛔ The fan-out rule is DUPLICATED with the platform — pin the numbers.

    Threshold, floor and probe cap decide whether the same SQL is flagged on both paths. A
    silent drift means the harness warns and the skill does not (or the reverse), which is
    exactly the § 3.2.1 asymmetry this work exists to close. SKIPS off-repo by design.
    """
    plat = None
    for parent in Path(__file__).resolve().parents:
        cand = (parent / "pantheon-agent-builder" / "src" / "tools" / "sql_validator_mint.py")
        if cand.is_file():
            plat = cand.read_text()
            break
    if plat is None:
        print("⏭️  fan-out constants: SKIPPED (no platform checkout — expected off-repo)")
        return 0

    import re
    want = {
        "_FANOUT_RATIO_THRESHOLD": reachability_gate._FANOUT_RATIO_THRESHOLD,
        "_FANOUT_MIN_SOURCE_ROWS": reachability_gate._FANOUT_MIN_SOURCE_ROWS,
        "_FANOUT_PROBE_CAP": reachability_gate._FANOUT_PROBE_CAP,
    }
    bad = []
    for name, mine in want.items():
        m = re.search(rf"^{name}\s*=\s*([0-9_.]+)", plat, re.M)
        if not m:
            bad.append(f"{name}: not found in the platform copy")
            continue
        theirs = float(m.group(1).replace("_", ""))
        if float(mine) != theirs:
            bad.append(f"{name}: skill={mine} platform={theirs}")
    if bad:
        print("❌ fan-out constants DRIFTED from the platform:\n     " + "\n     ".join(bad))
        return 1
    print("✅ fan-out constants: skill and platform agree")
    return 0


def check_evidence_record_contract() -> int:
    """⛔ Pin the evidence record's CONTRACT, not just its key names (§ 3.13.5).

    Three properties decide whether the record is worth anything, and each has a failure mode
    that is silent rather than loud.
    """
    import authoring_evidence as EV
    bad = []

    # 1. A failed corpus resolve must STILL be recorded, as demand. § 3.6.1: a miss is an
    #    entry in the owed-a-corpus-entry queue, not a failure — dropping it loses the only
    #    signal telling curators what to add.
    ev = EV.record_corpus(EV.new_evidence("q"), resolved=False, recorded_as_demand=True)
    if not ev["corpus"]["recorded"] or not ev["corpus"]["recorded_as_demand"]:
        bad.append("an UNRESOLVED corpus question is not recorded as demand")

    # 2. `joins.probed` must be able to say TRUE. A field that can only report the happy path
    #    cannot report the regression it exists to catch.
    probed = EV.record_joins(EV.new_evidence("q"), source="data-probe", probed=True)
    if probed["joins"]["probed"] is not True:
        bad.append("joins.probed cannot represent a probe having happened")

    # 3. Every layer present on every path — a partial record reads as "checked" for the
    #    layers it silently omits.
    full = EV.new_evidence("q")
    EV.record_corpus(full, resolved=True)
    EV.record_catalog(full, verdict="probed")
    EV.record_schema(full, scope="platform", columns_checked=1)
    EV.record_joins(full, source="query-hints", probed=False)
    EV.record_shape(full, result_rows=1)
    missing = EV.unrecorded_layers(full)
    if missing:
        bad.append(f"a fully-recorded record still reports unrecorded layers: {missing}")

    if bad:
        print("❌ evidence-record contract:\n     " + "\n     ".join(bad))
        return 1
    print("✅ evidence-record contract: demand recorded, probed representable, all layers present")
    return 0


def check_fanout_declines_on_cte_rooted_sql() -> int:
    """⛔ A CTE name is not a fan-out denominator — decline, never guess.

    Measured 2026-08-20 on corpus query `Q-001b`: the outer query reads `FROM attributed`,
    a CTE. `SELECT count(*) FROM attributed` is not runnable, so the probe failed and the
    check reported the useless "declined — the result could not be counted".

    ⚠️ This matters at scale, not just for one query: **10 of the 32 live corpus queries
    (31%) are CTE-rooted**, so this path is the majority experience for complex SQL.
    """
    cte_sql = ("WITH t AS (SELECT torana_vulnerability_id AS id FROM vulnerabilities) "
               "SELECT count(*) FROM t")
    plain_sql = "SELECT cve_id FROM vulnerabilities v JOIN entity_edges e ON e.from_key = v.cve_id"
    bad = []
    if reachability_gate._driving_table(cte_sql) is not None:
        bad.append("a CTE name was returned as the denominator — the probe will fail on it")
    if reachability_gate._driving_table(plain_sql) != "vulnerabilities":
        bad.append("a plain FROM table is no longer resolved — fan-out is now blind")
    if bad:
        print("❌ fan-out CTE handling:\n     " + "\n     ".join(bad))
        return 1
    print("✅ fan-out CTE handling: declines on CTE-rooted, resolves a plain FROM")
    return 0


def check_fanout_strips_comments_not_keywords() -> int:
    """⛔ The binder renders vocabulary keys INSIDE `--` comments. Strip lines, not keywords.

    Measured 2026-08-20 on Q-011: a comment documenting `-> {{actionable_status_set}}` was
    rendered to `-> SELECT unnest(ARRAY['Open'])`, and a `find("SELECT")` then sliced from
    THAT text — sending a mangled fragment and reporting "declined — could not be counted".
    ⚠️ The failure looks like a broken CHECK when the query is fine.
    """
    src = inspect.getsource(reachability_gate._cmd_fanout)
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    bad = []
    if 'clean.upper().find(' in code:
        bad.append("still slices on a keyword — a rendered comment will mangle the SQL")
    if 'startswith("--")' not in code:
        bad.append("no longer drops comment lines")
    if bad:
        print("❌ fan-out comment handling:\n     " + "\n     ".join(bad))
        return 1
    print("✅ fan-out comment handling: drops comment LINES, never keyword-slices")
    return 0


if __name__ == "__main__":
    rc = main()
    rc |= check_fanout_strips_comments_not_keywords()
    rc |= check_fanout_declines_on_cte_rooted_sql()
    rc |= check_evidence_record_contract()
    rc |= check_fanout_constants_match_platform()
    rc |= check_evidence_shape_matches_platform()
    raise SystemExit(rc)
