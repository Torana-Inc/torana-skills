"""pytest suite for the SQL reachability gate.

Collected by pytest (the older `test_gate.py` is a standalone script with a
`main()`, so nothing ever ran it in CI — that is how the FILTER bug survived).

    cd $TORANA_ROOT/pantheon-cli/skills/torana-text-to-sql/scripts
    DISABLE_CLEANUP=true python -m pytest test_reachability_gate.py -v

⚠️ NO NETWORK. Every test passes a fixed `reachable` dict, so the suite never
calls `torana` and never depends on a live platform. A gate whose tests need the
platform up is a gate nobody runs.

The clause-classification block is the ADVERSARIAL one. Its job is to catch the
recurring bug shape: a construct that EMBEDS a node looking like a top-level
clause (`FILTER` embeds Where; `OVER (...)` embeds Order), which flips
`structural` and therefore flips the verdict between "degrade" and "refuse".
"""
from __future__ import annotations

import json
import sys

import pytest

import reachability_gate
from reachability_gate import (
    BIND_ENTRY,
    _verdict_of,
    check_policy_literals,
    check_sql,
    render_sql,
)

# These tests drive `check_sql` directly with the fixture maps below, so they
# never go through `main()` — the entry point that normally establishes ground
# truth from the platform API. Seed the module globals from an explicit FIXTURE
# payload here.
#
# ⛔ This used to call `load_ground_truth_offline()`, which re-derived the list
# from a local checkout. § 3.13.5 deleted that function to make the API the sole
# authority — but this call site was left behind, so the ENTIRE suite failed at
# COLLECTION with AttributeError and all 90+ tests silently stopped running.
# A green "0 collected" is not a pass. Seeding from a fixture keeps these tests
# hermetic and removes the checkout dependency for good.
_FIXTURE_PAYLOAD = {
    "system_columns": ["is_deleted", "tenant_id", "namespace_id", "created_at",
                       "updated_at", "created_by", "updated_by"],
    "policy_derived": [
        {"column": "vulnerability_due_date", "decoration": "sla_due_date",
         "kind": "DERIVE"},
        {"column": "vulnerability_sla_breach_date", "decoration": "sla_breach",
         "kind": "DERIVE"},
    ],
}
reachability_gate.SYSTEM_COLUMNS, reachability_gate.SYSTEM_PROVENANCE = (
    reachability_gate.load_system_columns("test", _FIXTURE_PAYLOAD))
reachability_gate.POLICY_DERIVED_COLUMNS, reachability_gate.POLICY_DERIVED_PROVENANCE = (
    reachability_gate.load_policy_derived_columns("test", _FIXTURE_PAYLOAD))

# One table, three reachable columns. Anything named `bogus_*` is unreachable.
REACH = {
    "vulnerabilities": {"cve_id", "severity", "vulnerability_status"},
    "assets": {"torana_entity_id", "asset_name"},
}


def _clauses(sql):
    r = check_sql(sql, REACH)
    assert r["parsed"], r["error"]
    return [u["clause"] for u in r["unreachable"]]


# ── Clause classification — the adversarial block ───────────────────────────
@pytest.mark.parametrize("sql,expected", [
    # Projection scope. Dropping the column narrows the answer; it is safe.
    ("SELECT CASE WHEN bogus_col THEN 1 ELSE 0 END FROM vulnerabilities", "SELECT"),
    ("SELECT DISTINCT ON (bogus_col) cve_id FROM vulnerabilities", "SELECT"),
    ("SELECT (SELECT max(bogus_col) FROM vulnerabilities) FROM vulnerabilities", "SELECT"),
    # FILTER embeds a Where but constrains ONE aggregate — projection scope.
    # Regression guard for the bug fixed 2026-08-06.
    ("SELECT COUNT(*) FILTER (WHERE bogus_col IS NULL) FROM vulnerabilities", "SELECT"),
    # A window spec embeds an Order but orders rows WITHIN the frame, not the
    # result set. Both found by this session's adversarial pass.
    ("SELECT cve_id, RANK() OVER (ORDER BY bogus_col) r FROM vulnerabilities", "SELECT"),
    ("SELECT cve_id, ROW_NUMBER() OVER (PARTITION BY bogus_col) rn FROM vulnerabilities",
     "SELECT"),
    # Row scope. Dropping the column returns a DIFFERENT ROW SET, silently.
    ("SELECT cve_id FROM vulnerabilities WHERE CASE WHEN bogus_col THEN 1 ELSE 0 END = 1",
     "WHERE"),
    ("SELECT cve_id FROM vulnerabilities v WHERE EXISTS "
     "(SELECT 1 FROM vulnerabilities x WHERE x.bogus_col = 1)", "WHERE"),
    ("SELECT v.cve_id FROM vulnerabilities v, LATERAL "
     "(SELECT 1 WHERE v.bogus_col = 1) s", "WHERE"),
    ("SELECT cve_id FROM vulnerabilities UNION SELECT cve_id FROM vulnerabilities "
     "WHERE bogus_col = 1", "WHERE"),
    ("SELECT count(*) FROM vulnerabilities GROUP BY CASE WHEN bogus_col THEN 1 ELSE 0 END",
     "GROUP BY"),
    ("SELECT severity FROM vulnerabilities GROUP BY severity HAVING sum(bogus_col) > 1",
     "HAVING"),
    # A FILTER nested in HAVING must resolve past Filter to HAVING, not to SELECT.
    ("SELECT cve_id FROM vulnerabilities GROUP BY cve_id "
     "HAVING COUNT(*) FILTER (WHERE bogus_col IS NULL) > 0", "HAVING"),
    ("SELECT a.cve_id FROM vulnerabilities a JOIN vulnerabilities b "
     "ON a.bogus_col = b.cve_id", "JOIN"),
    ("SELECT cve_id FROM vulnerabilities QUALIFY "
     "ROW_NUMBER() OVER (ORDER BY bogus_col) = 1", "QUALIFY"),
    # A REAL statement-level ORDER BY must still be ORDER BY — the guard against
    # "fixing" the window bug by swallowing every Order node.
    ("SELECT cve_id FROM vulnerabilities ORDER BY bogus_col", "ORDER BY"),
    ("SELECT cve_id, RANK() OVER (PARTITION BY severity) r FROM vulnerabilities "
     "ORDER BY bogus_col", "ORDER BY"),
])
def test_clause_classification(sql, expected):
    assert _clauses(sql) == [expected]


@pytest.mark.parametrize("sql,structural", [
    ("SELECT bogus_col FROM vulnerabilities", False),
    ("SELECT COUNT(*) FILTER (WHERE bogus_col IS NULL) FROM vulnerabilities", False),
    ("SELECT cve_id, RANK() OVER (ORDER BY bogus_col) r FROM vulnerabilities", False),
    ("SELECT cve_id FROM vulnerabilities WHERE bogus_col = 1", True),
    ("SELECT cve_id FROM vulnerabilities QUALIFY "
     "ROW_NUMBER() OVER (ORDER BY bogus_col) = 1", True),
])
def test_structural_flag(sql, structural):
    r = check_sql(sql, REACH)
    assert r["unreachable"][0]["structural"] is structural


# ── Semantic risk — the confident-wrong-value cases ─────────────────────────
@pytest.mark.parametrize("sql", [
    "SELECT COALESCE(bogus_col, 0) FROM vulnerabilities",
    "SELECT IFNULL(bogus_col, 0) FROM vulnerabilities",
    "SELECT CASE WHEN bogus_col THEN 1 ELSE 0 END FROM vulnerabilities",
    "SELECT cve_id FROM vulnerabilities WHERE COALESCE(bogus_col, 0) = 0",
])
def test_masking_is_flagged(sql):
    """An unreachable column behind a default returns WRONG data, not missing data."""
    r = check_sql(sql, REACH)
    assert r["masked_risks"], f"masking not detected: {sql}"
    assert r["unreachable"][0]["masked_by"]


@pytest.mark.parametrize("sql", [
    # No ELSE → fallthrough is NULL, which reads as missing, not as a fact.
    "SELECT CASE WHEN bogus_col THEN 1 END FROM vulnerabilities",
    # An ordinary reference whose absence is visible in the result.
    "SELECT bogus_col FROM vulnerabilities",
    "SELECT cve_id FROM vulnerabilities WHERE bogus_col = 1",
])
def test_not_masking(sql):
    r = check_sql(sql, REACH)
    assert not r["masked_risks"], f"false masking positive: {sql}"


def test_masked_outranks_blocked():
    """MASKED must win the verdict: it is the more dangerous outcome."""
    r = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE COALESCE(bogus_col, 0) = 0", REACH)
    assert _verdict_of(r) == "MASKED"


# ── Core behaviour + regression guards ──────────────────────────────────────
def test_clean_sql_is_clean():
    r = check_sql("SELECT cve_id, severity FROM vulnerabilities", REACH)
    assert r["clean"] and r["checked"] == 2
    assert _verdict_of(r) == "CLEAN"


def test_system_columns_are_always_available():
    """`is_deleted` appears in nearly every corpus WHERE clause and is NOT in the
    reachable list. Condemning it was the trap that failed 80 of 93 questions."""
    r = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE is_deleted = false", REACH)
    assert r["clean"], r["unreachable"]


def test_projection_alias_does_not_alias_itself():
    """A bare `SELECT cve_id` must still be CHECKED. Using alias_or_name here made
    every projected column alias itself and skip its own check — the gate then
    verified 0 columns and reported clean on unreachable SQL."""
    r = check_sql(
        "SELECT bogus_col FROM vulnerabilities WHERE is_deleted = false", REACH)
    assert not r["clean"]


def test_explicit_alias_is_not_a_column():
    r = check_sql(
        "SELECT COUNT(*) AS open_count FROM vulnerabilities ORDER BY open_count", REACH)
    assert r["clean"], r["unreachable"]


def test_cte_columns_are_not_datalake_columns():
    r = check_sql(
        "WITH x AS (SELECT cve_id AS c FROM vulnerabilities) SELECT x.c FROM x", REACH)
    assert r["clean"], r["unreachable"]


def test_derived_table_alias():
    r = check_sql(
        "SELECT v.n FROM vulnerabilities a LEFT JOIN "
        "(SELECT COUNT(*) AS n FROM vulnerabilities) v ON true", REACH)
    assert r["clean"], r["unreachable"]


def test_unqualified_column_attributed_to_single_table():
    """Silently skipping unqualified columns would wave through the single most
    ordinary shape a text-to-SQL tool emits."""
    r = check_sql("SELECT bogus_col FROM vulnerabilities", REACH)
    assert [u["table"] for u in r["unreachable"]] == ["vulnerabilities"]


def test_unknown_table_reported_separately():
    r = check_sql("SELECT x FROM not_a_table", REACH)
    assert r["unknown_table"] and _verdict_of(r) == "UNKNOWN_TABLE"


def test_parse_failure_is_reported_not_raised():
    r = check_sql("SELECT FROM WHERE ***", REACH)
    assert not r["parsed"] or _verdict_of(r) in ("PARSE_FAILED", "CLEAN")


def test_verdict_ordering():
    assert _verdict_of(check_sql("SELECT cve_id FROM vulnerabilities", REACH)) == "CLEAN"
    assert _verdict_of(
        check_sql("SELECT bogus_col FROM vulnerabilities", REACH)) == "PARTIAL"
    assert _verdict_of(
        check_sql("SELECT cve_id FROM vulnerabilities WHERE bogus_col=1", REACH)) == "BLOCKED"


# ── Addendum 2 / Task A: render-then-parse ──────────────────────────────────
def test_dbt_source_is_resolved_to_bare_table():
    """dbt refs are a SEPARATE template family from vocabulary — bind_entry does
    not touch them, and sqlglot fails on the surviving braces."""
    r = check_sql(
        "SELECT cve_id FROM {{ source('torana', 'vulnerabilities') }}", REACH)
    assert r["parsed"] and r["clean"], r


def test_dbt_ref_is_resolved():
    r = render_sql("SELECT a FROM {{ ref('some_model') }}")
    assert "{{" not in r["rendered"] and "some_model" in r["rendered"]


def test_tenant_id_is_bound_separately():
    r = render_sql("SELECT 1 FROM vulnerabilities WHERE tenant_id = '{{ tenant_id }}'")
    assert "{{" not in r["rendered"]


@pytest.mark.skipif(BIND_ENTRY is None, reason="binder not importable")
def test_vocabulary_placeholder_binds_from_conservative_defaults():
    """No tenant, no live platform — the platform's own declared fallbacks."""
    r = render_sql(
        "SELECT cve_id FROM vulnerabilities "
        "WHERE severity = ANY({{severity_floor.at_or_above}})")
    assert r["bound"] and not r["unresolved"]
    # ⚠️ A set renders as a set-returning subquery, NOT a bare `ARRAY[…]`
    # (SUPPLY_GRAPH_SPEC § 3.12 G-d). A bare array is valid only after
    # `= ANY`/`<> ALL` and cannot run after `IN`, so asserting merely on
    # "ARRAY[" in the output would still pass against the defect.
    assert "SELECT unnest(ARRAY[" in r["rendered"], r["rendered"]
    assert "severity_floor" in r["used_keys"]


def test_unresolved_placeholder_is_not_a_parse_error():
    """Different cause, different fix — an unknown key is an authoring defect,
    a parse error is a SQL defect. Conflating them misdirects the reader."""
    r = check_sql("SELECT a FROM t WHERE x = {{not_a_real_key}}", REACH)
    assert r["unresolved_placeholders"]
    assert r["error"] is None
    assert _verdict_of(r) == "UNRESOLVED_PLACEHOLDER"


def test_vocab_prefix_is_reported_not_supported():
    """`{{vocab:…}}` belongs to torana-vm artifact SQL. Reaching this gate with
    one would otherwise survive to EXPLAIN and fail there."""
    r = check_sql("SELECT a FROM t WHERE s = {{vocab:severity_floor}}", REACH)
    assert _verdict_of(r) == "UNRESOLVED_PLACEHOLDER"


def test_untemplated_sql_is_untouched():
    sql = "SELECT cve_id FROM vulnerabilities"
    assert render_sql(sql)["rendered"] == sql


def test_findings_map_back_to_source_template():
    """A finding reported at a RENDERED line cannot be found in the file the
    author wrote."""
    r = check_sql(
        "SELECT bogus_col\nFROM {{ source('torana', 'vulnerabilities') }}", REACH)
    u = r["unreachable"][0]
    assert u["source_line"] == 1 and "bogus_col" in u["source_text"]


def test_substituted_finding_admits_it_has_no_source_line():
    """When a column only exists post-substitution there is no honest source
    coordinate — say so rather than report a rendered one as if it were source."""
    from reachability_gate import _locate_in_source
    f = {"column": "not_in_template"}
    _locate_in_source(f, "SELECT {{severity_floor}} FROM t")
    assert f["source_line"] is None and "substitution" in f["source_note"]


# ── Addendum 2 / Task B: hardcoded policy ───────────────────────────────────
@pytest.mark.parametrize("sql,key", [
    ("SELECT 1 FROM vulnerabilities WHERE severity IN ('Critical','High')",
     "severity_floor"),
    ("SELECT 1 FROM vulnerabilities WHERE epss_score > 0.7",
     "epss_escalate_threshold"),
    ("SELECT 1 FROM vulnerabilities WHERE vulnerability_status = 'Open'",
     "actionable_status_set"),
])
def test_hardcoded_policy_is_flagged(sql, key):
    keys = [f["suggested_key"] for f in check_policy_literals(sql)["findings"]]
    assert key in keys


def test_templated_policy_is_not_flagged():
    """The whole point: using the vocabulary must silence the check."""
    sql = ("SELECT 1 FROM vulnerabilities "
           "WHERE severity = ANY({{severity_floor.at_or_above}})")
    assert not check_policy_literals(sql)["findings"]


def test_waiver_requires_a_reason():
    """A bare marker is itself reported — 'someone waived this and did not say
    why' is the state the check exists to prevent."""
    base = "SELECT 1 FROM vulnerabilities WHERE severity = 'Critical'"
    assert len(check_policy_literals(base)["findings"]) == 1
    with_reason = base + "  -- policy-literal-ok: definitional to this KPI"
    r = check_policy_literals(with_reason)
    assert not r["findings"] and len(r["waived"]) == 1
    bare = base + "  -- policy-literal-ok"
    r2 = check_policy_literals(bare)
    assert r2["findings"] and r2["bare_waivers"]


def test_trailing_waiver_reason_stops_at_end_of_its_own_line():
    """⛔ REGRESSION. The reason must be bounded by the LINE it is written on.

    The context used to be built by JOINING the literal's line with the line
    ABOVE it into one string, then splitting on the marker. For a TRAILING
    waiver the marker is last, so the "reason" ran off the end of its own line
    and swallowed the previous line's SQL:

        'pinned by regression fixture FROM vulnerabilities v'
                                      ^^^^^^^^^^^^^^^^^^^^^^ leaked SQL

    The waiver was still APPLIED — only the recorded reason was polluted, so
    this failed silently and a reviewer auditing waivers read garbage. Found by
    hand-validating corpus SQL (Torana_Corpus_Regeneration.md § 6.3 defect #4).
    """
    sql = ("SELECT v.cve_id, v.severity\n"
           "FROM vulnerabilities v\n"
           "WHERE v.severity = 'Critical'  -- policy-literal-ok: pinned by fixture")
    r = check_policy_literals(sql)
    assert not r["findings"], r["findings"]
    assert len(r["waived"]) == 1
    assert r["waived"][0]["waiver_reason"] == "pinned by fixture"


def test_adjacent_leading_waiver_reason_is_not_polluted():
    """The line-above shape must also yield a clean reason — same root cause."""
    sql = ("SELECT v.cve_id, v.severity\n"
           "FROM vulnerabilities v\n"
           "-- policy-literal-ok: pinned by fixture\n"
           "WHERE v.severity = 'Critical'")
    r = check_policy_literals(sql)
    assert not r["findings"], r["findings"]
    assert r["waived"][0]["waiver_reason"] == "pinned by fixture"


# ── Addendum 2 / A: stale policy — reachable, populated, and still wrong ────
#
# The deny-list is DERIVED from `DECORATIONS` (kind=DERIVE + scope="tenant"),
# so these tests assert BEHAVIOUR, not a hardcoded pair of column names.
_REACH_SLA = {
    "vulnerabilities": {
        "cve_id", "severity", "vulnerability_status",
        "vulnerability_due_date", "vulnerability_sla_breach_date",
        "scan_first_detected_date",
    },
}


def test_denylist_is_derived_from_the_registry_not_hardcoded():
    """The predicate is structural: DERIVE outputs on a tenant-scoped spec.

    If this fails with an empty dict, the import broke and EVERY stale-policy
    check below is silently passing for the wrong reason.
    """
    # Read through the module, not a from-import: the fixture seeding above
    # rebinds these, and a from-import captures the pre-seed value.
    assert reachability_gate.POLICY_DERIVED_PROVENANCE not in ("NOT LOADED", "")
    assert "vulnerability_due_date" in reachability_gate.POLICY_DERIVED_COLUMNS
    assert "platform API" in reachability_gate.POLICY_DERIVED_PROVENANCE


def test_denylist_read_in_a_deciding_clause_is_flagged():
    sql = ("SELECT cve_id FROM vulnerabilities "
           "WHERE vulnerability_due_date < NOW()")
    r = check_sql(sql, _REACH_SLA)
    assert len(r["stale_policy"]) == 1
    f = r["stale_policy"][0]
    assert f["column"] == "vulnerability_due_date"
    assert f["suggested_key"] == "sla_window_by_severity"
    assert not r["clean"]
    assert _verdict_of(r) == "STALE_POLICY"


def test_denylist_echoed_in_select_is_NOT_flagged():
    """A projection echoes 'what the platform currently thinks'. It decides
    nothing, and flagging it would cry wolf on ordinary reporting queries."""
    sql = "SELECT cve_id, vulnerability_due_date FROM vulnerabilities"
    r = check_sql(sql, _REACH_SLA)
    assert r["stale_policy"] == []
    assert _verdict_of(r) == "CLEAN"


def test_denylist_inside_case_in_where_is_flagged():
    """`_clause_of` attributes a CASE to its enclosing clause — the reason this
    needs no second AST walk."""
    sql = ("SELECT cve_id FROM vulnerabilities WHERE CASE WHEN "
           "vulnerability_sla_breach_date < NOW() THEN 1 ELSE 0 END = 1")
    r = check_sql(sql, _REACH_SLA)
    assert [f["column"] for f in r["stale_policy"]] == [
        "vulnerability_sla_breach_date"]


def test_denylist_inside_aggregate_filter_is_flagged():
    """COUNT(*) FILTER (WHERE due_date < NOW()) computes an SLA-BREACH NUMBER
    from stale policy. `_clause_of` reattributes FILTER to SELECT (right for
    reachability), so this needs its own detection. 6 corpus rows use it."""
    sql = ("SELECT COUNT(*) FILTER (WHERE vulnerability_due_date < NOW()) "
           "AS breached FROM vulnerabilities")
    r = check_sql(sql, _REACH_SLA)
    assert len(r["stale_policy"]) == 1
    assert "aggregate FILTER" in r["stale_policy"][0]["clause"]


def test_stale_policy_waiver_needs_a_reason():
    base = ("SELECT cve_id FROM vulnerabilities "
            "WHERE vulnerability_due_date < NOW()")
    r = check_sql(base + "  -- policy-literal-ok: showing the materialised date",
                  _REACH_SLA)
    assert r["stale_policy"] == [] and len(r["stale_policy_waived"]) == 1
    assert r["stale_policy_waived"][0]["waiver_reason"].startswith("showing")
    bare = check_sql(base + "  -- policy-literal-ok", _REACH_SLA)
    assert bare["stale_policy"], "a bare marker must NOT waive"


def test_computing_the_deadline_from_the_key_is_clean():
    """The prescribed replacement must actually pass the rule it teaches."""
    sql = ("SELECT cve_id FROM vulnerabilities WHERE scan_first_detected_date "
           "+ ({{sla_window_by_severity[severity]}})::int * INTERVAL '1 day' "
           "< NOW()")
    r = check_sql(sql, _REACH_SLA, render=True)
    assert r["parsed"], r.get("error")
    assert r["stale_policy"] == [] and r["clean"]


def test_masked_outranks_stale_policy():
    """Both are confidently wrong; MASKED is wrong about the WORLD (a value
    that was never measured), so it is triaged first."""
    r = {"parsed": True, "unreachable": [], "unknown_table": [],
         "masked_risks": [{"column": "x"}],
         "stale_policy": [{"column": "vulnerability_due_date"}]}
    assert _verdict_of(r) == "MASKED"


def test_stale_policy_outranks_blocked():
    """A blocked query fails visibly; this one runs and returns plausible rows."""
    r = {"parsed": True, "unknown_table": [], "masked_risks": [],
         "unreachable": [{"column": "b", "structural": True}],
         "stale_policy": [{"column": "vulnerability_due_date"}]}
    assert _verdict_of(r) == "STALE_POLICY"


# ── Portability: fail-closed + source disagreement ──────────────────────────
#
# ⚠️ These cover the defect that motivated the portability work. Measured on a
# machine with no `pantheon-*` checkout, the gate did NOT crash: it warned on
# stderr and then printed a confident `❌ UNREACHABLE vulnerabilities.is_deleted
# [WHERE — STRUCTURAL]` to stdout with exit 1. `is_deleted` is in nearly every
# real WHERE clause, so it condemned almost every valid query — and anything
# scripted around it saw only the wrong answer.

def test_missing_system_columns_refuses_instead_of_answering():
    """An API payload with no system columns ⇒ REFUSE. Never a verdict from a
    partial view. (§ 3.13.5 removed the local fallback, so an empty payload is
    now the ONLY way this can happen — and it must still fail closed.)"""
    with pytest.raises(reachability_gate.GroundTruthUnavailable) as exc:
        reachability_gate.load_system_columns("SA", {})
    # The cause must be NAMED — "something went wrong" is not actionable.
    assert "is_deleted" in str(exc.value)


def test_missing_policy_derived_refuses_instead_of_answering():
    """Without the deny-list a stale-policy read is waved through as ordinary."""
    with pytest.raises(reachability_gate.GroundTruthUnavailable):
        reachability_gate.load_policy_derived_columns("SA", {})


def test_empty_reachable_map_refuses(monkeypatch):
    """An empty map is a BROKEN FETCH, not 'nothing is reachable'. Answering
    from it would call every column in every query a build defect."""
    class _Proc:
        returncode = 0
        stdout = '{"columns": []}'
        stderr = ""
    monkeypatch.setattr(reachability_gate.subprocess, "run",
                        lambda *a, **k: _Proc())
    with pytest.raises(reachability_gate.GroundTruthUnavailable):
        reachability_gate.fetch_reachable("platform", "SA")


def test_local_ground_truth_fallback_stays_DELETED():
    """⛔ § 3.13.5 deleted the local-checkout fallback to make the platform API the
    SOLE authority for system + policy-derived columns.

    Two tests used to monkeypatch `_system_columns_from_local` to prove the API
    won a disagreement and that provenance was reported. Both described a
    mechanism that no longer exists — and because the deletion ALSO left a stale
    `load_ground_truth_offline()` call at import, the whole suite failed at
    COLLECTION and every test here silently stopped running.

    This test replaces them: it pins the deletion so a well-meaning "restore the
    offline fallback" cannot reintroduce a second authority unnoticed. If you are
    deliberately bringing it back, delete this test in the same change.
    """
    for gone in ("_system_columns_from_local", "_load_policy_derived_columns",
                 "load_ground_truth_offline"):
        assert not hasattr(reachability_gate, gone), (
            f"{gone} is back — the API is no longer the sole authority. "
            f"See § 3.13.5 before restoring it.")


def test_provenance_names_the_platform_api():
    """Provenance must still SAY where ground truth came from — the reason the
    old disagreement test existed. It is now always the API."""
    cols, prov = reachability_gate.load_system_columns(
        "SA", {"system_columns": ["is_deleted"]})
    assert cols == {"is_deleted"}
    assert "platform API" in prov


# ── Waiver scope (regressions for two bugs found regenerating the corpus) ─────

def test_single_line_sql_honours_a_header_waiver():
    """Corpus SQL is routinely ONE long line, so 'the line above' never matched.

    The literal sat on line 13 while every waiver sat in the leading comment
    block — the check failed OPEN, reporting a documented deliberate literal as
    an unwaived finding. The reason must also stop at the next comment marker,
    or the whole header becomes the "reason".
    """
    sql = ("-- policy-literal-ok: severity here names its own counter.\n"
           "-- (more header prose that must NOT become the reason)\n"
           "SELECT COUNT(*) FILTER (WHERE v.severity = 'Critical') AS critical_count "
           "FROM vulnerabilities v")
    r = check_policy_literals(sql)
    assert not r["findings"], r["findings"]
    assert len(r["waived"]) == 1
    assert r["waived"][0]["waiver_reason"] == "severity here names its own counter."


def test_template_guard_is_PER_LITERAL_not_per_line():
    """⛔ REGRESSION. One `{{…}}` anywhere on a line used to switch the whole
    policy-literal rule off for that line.

    Since corpus SQL is stored as single lines, that was a per-QUERY switch: 8 of
    32 live queries carried literals the checker never reported, including two
    the executing session then found BY HAND and recorded as HELPED.

    ⭐ The proof it was a bug and not a policy: the SAME SQL reformatted across
    lines reported the literal. A correctness rule must never depend on where the
    author pressed Enter.
    """
    one_line = ("SELECT cve_id, ({{sla_window_by_severity[v.severity]}})::int AS w "
                "FROM vulnerabilities v "
                "WHERE v.vulnerability_status IN ('Fixed','Mitigated')")
    multi_line = ("SELECT cve_id,\n"
                  "  ({{sla_window_by_severity[v.severity]}})::int AS w\n"
                  "FROM vulnerabilities v\n"
                  "WHERE v.vulnerability_status IN ('Fixed','Mitigated')")
    one = [c["literal"] for c in reachability_gate._policy_candidates(one_line)]
    many = [c["literal"] for c in reachability_gate._policy_candidates(multi_line)]
    assert "'Fixed'" in one, one
    # ⭐ Formatting must not change the verdict.
    assert one == many


def test_a_literal_that_IS_bound_stays_silent():
    """The guard's real intent, preserved: an already-templated comparison is not
    re-flagged. It just must not silence its NEIGHBOURS."""
    bound = ("SELECT cve_id FROM vulnerabilities v "
             "WHERE v.vulnerability_status IN ({{actionable_status_set}})")
    assert reachability_gate._policy_candidates(bound) == []


def test_header_waiver_does_NOT_blanket_waive_multi_line_sql():
    """One marker at the top must not excuse every literal in a long query."""
    sql = ("-- policy-literal-ok: only the adjacent one is excused\n"
           "SELECT 1 FROM vulnerabilities\n"
           "WHERE severity IN ('Critical','High')\n"
           "  AND vulnerability_status = 'Open'")
    r = check_policy_literals(sql)
    assert len(r["findings"]) >= 2, r
    assert not r["waived"]


def test_check_sql_reports_policy_literals_like_the_corpus_runner():
    """`check --file` used to omit the tenant-neutrality half entirely.

    check_policy_literals ran ONLY in check-corpus, so the two commands
    disagreed about the same text and the single-file path — the one the
    skill's workflow tells you to run — was the permissive one.
    """
    reach = {"vulnerabilities": {"severity", "vulnerability_status"}}
    res = check_sql("SELECT 1 FROM vulnerabilities WHERE severity IN ('Critical','High')",
                    reach)
    assert "policy_literals" in res
    assert any(p["suggested_key"] == "severity_floor" for p in res["policy_literals"])


# ── Declared-writer dependencies — the SECOND AXIS ──────────────────────────
#
# ⛔ THE INVARIANT THESE TESTS EXIST TO PROTECT: this axis must NEVER change
# `clean`. A `declared` column IS reachable and the question IS answerable.
# Folding the dependency into the verdict would destroy the property that made
# the underlying fix work at all — registering a column made Q-047 pass with no
# edit to this gate. If a future change makes a dependency flip `clean`, these
# fail, and that is the point.

_DECL_REACH = {"vulnerabilities": {"cve_id", "is_confirmed", "exploitability_status"}}

#: Two declared columns on the SAME table, differing ONLY in whether a caller
#: exists — so a test can prove the gate distinguishes them rather than flagging
#: every declared column identically.
_DECL_DEPS = {
    ("vulnerabilities", "is_confirmed"): {
        "table": "vulnerabilities", "column": "is_confirmed",
        "has_caller": False, "caller_undeclared": False,
        "callers": [{"name": "triage workflow (NOT BUILT)", "status": "none",
                     "exists": False}],
        "writers": ["ingest.py::_update_vulnerability_impl"],
        "why": "reachable, and NO caller exists",
    },
    ("vulnerabilities", "exploitability_status"): {
        "table": "vulnerabilities", "column": "exploitability_status",
        "has_caller": True, "caller_undeclared": False,
        "callers": [{"name": "torana-pentest", "status": "wired", "exists": True}],
        "writers": ["ingest.py::_update_vulnerability_impl"],
        "why": "reachable, filled only when an external actor calls the writer",
    },
}


@pytest.fixture
def declared_deps(monkeypatch):
    """Install the fixture dependency map. NO NETWORK, like every other test."""
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES", _DECL_DEPS)
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES_PROVENANCE",
                        "fixture")


def test_declared_dependency_does_NOT_change_clean(declared_deps):
    """⛔ The load-bearing invariant. A no-caller column is still CLEAN.

    Q-047's real shape: every column reachable, verdict ✅, and it returns zero
    rows forever because nothing writes `is_confirmed`. The gate must say BOTH
    things — answerable, and dependent — never trade one for the other.
    """
    res = check_sql("SELECT cve_id FROM vulnerabilities WHERE is_confirmed IS TRUE",
                    _DECL_REACH)
    assert res["clean"] is True, "a declared dependency must NEVER flip the verdict"
    assert not res["unreachable"]
    assert _verdict_of(res) == "CLEAN", "the corpus verdict must stay CLEAN too"
    assert [d["column"] for d in res["declared_dependencies_without_caller"]] == \
        ["is_confirmed"]


def test_declared_dependency_distinguishes_wired_from_unbuilt(declared_deps):
    """A wired caller is reported but NOT marked dead — else the gate cries wolf.

    `exploitability_status` is genuinely written by torana-pentest. Reporting it
    as having no caller would be a false finding on a working path, and a checker
    that cries wolf gets waived by reflex.
    """
    res = check_sql(
        "SELECT cve_id, exploitability_status, is_confirmed FROM vulnerabilities",
        _DECL_REACH)
    assert res["clean"] is True
    reported = {d["column"] for d in res["declared_dependencies"]}
    assert reported == {"exploitability_status", "is_confirmed"}
    dead = {d["column"] for d in res["declared_dependencies_without_caller"]}
    assert dead == {"is_confirmed"}, "only the caller-less column is dead"


def test_declared_dependency_reported_in_a_projection_too(declared_deps):
    """Position is NOT the test here — unlike the stale-policy check.

    A projection of a column nothing writes returns an empty COLUMN, and an
    aggregate over it returns a confident zero. Both mislead, so a SELECT-only
    reference is reported rather than waived.
    """
    res = check_sql("SELECT is_confirmed FROM vulnerabilities", _DECL_REACH)
    assert res["clean"] is True
    assert len(res["declared_dependencies_without_caller"]) == 1


def test_no_declared_dependencies_when_map_is_empty():
    """Absent dependency data must not fabricate findings, and must not refuse.

    Unlike system columns and policy-derived columns, this input cannot make a
    verdict WRONG (nothing consults it for `clean`), so an old platform that does
    not serve the key loses one advisory rather than the whole check.
    """
    res = check_sql("SELECT is_confirmed FROM vulnerabilities", _DECL_REACH)
    assert res["clean"] is True
    assert res["declared_dependencies"] == []
    assert res["declared_dependencies_without_caller"] == []


def test_unreachable_column_is_still_unreachable_with_deps_loaded(declared_deps):
    """The new axis must not accidentally swallow a real unreachable finding."""
    res = check_sql("SELECT bogus_col FROM vulnerabilities WHERE is_confirmed IS TRUE",
                    _DECL_REACH)
    assert res["clean"] is False
    assert [u["column"] for u in res["unreachable"]] == ["bogus_col"]
    # ...and the dependency is still reported alongside the failure.
    assert [d["column"] for d in res["declared_dependencies_without_caller"]] == \
        ["is_confirmed"]


def test_load_declared_dependencies_distinguishes_missing_from_empty():
    """"nothing depends on a caller" and "the platform did not answer" differ.

    Collapsing them would let a stale platform silently report a clean second
    axis — the same shape as a partial view answering confidently.
    """
    got, prov = reachability_gate.load_declared_dependencies(
        {"declared_dependencies": []})
    assert got == {} and not prov.startswith("unavailable")

    got, prov = reachability_gate.load_declared_dependencies({})
    assert got == {} and prov.startswith("unavailable")

    got, prov = reachability_gate.load_declared_dependencies(None)
    assert got == {} and prov.startswith("unavailable")


def test_declared_dependency_keys_are_lowercased(declared_deps):
    """A quoted/upper-case reference must still match the map."""
    res = check_sql('SELECT "IS_CONFIRMED" FROM vulnerabilities', _DECL_REACH)
    assert len(res["declared_dependencies_without_caller"]) == 1


# ── Supply provenance (`sql_provenance`) — writers for EVERY column ──────────
#
# ⛔ THE INVARIANT THIS BLOCK PROTECTS, and it is the SAME one as the section
# above: provenance is a SECOND AXIS and must NEVER change `clean`. A column
# gaining a writer record — or losing one — cannot flip a verdict. If a future
# change makes it, these fail, and that is the point.
#
# The gap being closed: the gate resolved writers for every column and kept them
# only for `declared` ones. Measured on corpus Q-026 — 25 column references
# checked, 6 carrying provenance, 19 (every mapping-written column, i.e. almost
# all real data) carrying none.

#: Mirrors the live API shape (verified against `reachable-columns --explain`):
#: many writers per column, MIXED kinds, `integration` present only on mappings.
_WRITERS = {
    # 7 mapping writers — the real `cve_id` shape. Self-filling.
    ("vulnerabilities", "cve_id"): [
        {"kind": "mapping", "source": "mappings/gcp/container_analysis.yaml",
         "integration": "gcp", "detail": "op:derive"},
        {"kind": "mapping", "source": "mappings/snyk/vulnerabilities.yaml",
         "integration": "snyk", "detail": "op:derive"},
    ],
    # declared ONLY — the strict `caller_only` case.
    ("vulnerabilities", "is_confirmed"): [
        {"kind": "declared",
         "source": "ingest.py::_update_vulnerability_impl",
         "detail": "PATCH /ingest/vulnerabilities",
         "expected_caller": {"name": "torana vulnerability triage",
                             "status": "manual", "exists": True},
         "bridge_id": "BRIDGE-TRIAGE-001"},
    ],
    # ⚠️ BOTH a mapping AND a declared writer. The seam deliberately allows this
    # — it IS the triage design — and it is the case the ANY/ALL reduction
    # exists to get right: self-filling, NOT caller_only.
    ("vulnerabilities", "severity"): [
        {"kind": "mapping", "source": "mappings/snyk/vulnerabilities.yaml",
         "integration": "snyk", "detail": "op:derive"},
        {"kind": "declared", "source": "ingest.py::_update_vulnerability_impl",
         "detail": "analyst override"},
    ],
    ("vulnerabilities", "vulnerability_status"): [
        {"kind": "operator", "source": "torana_mesh/etl/operators/status.py"},
    ],
}


@pytest.fixture
def column_writers(monkeypatch):
    """Install the fixture writer map. NO NETWORK, like every other test."""
    monkeypatch.setattr(reachability_gate, "WRITERS_BY_COLUMN", _WRITERS)
    monkeypatch.setattr(reachability_gate, "WRITERS_PROVENANCE", "fixture")


def test_provenance_does_NOT_change_clean(column_writers):
    """⛔ C3, restated for the supply axis. This is the load-bearing invariant.

    A `declared` column IS reachable and its question IS answerable. Folding
    caller status into the verdict would mean registering a writer could make a
    passing query newly FAIL — destroying the property that made the write seam
    work (register a column -> the question passes, with no edit to this gate).
    """
    res = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE is_confirmed IS TRUE",
        _DECL_REACH)
    assert res["clean"] is True, "supply provenance must NEVER flip the verdict"
    assert _verdict_of(res) == "CLEAN"
    # ...and it is still REPORTED. Answerable AND dependent, never one traded
    # for the other.
    cols = {c["column"] for c in res["sql_provenance"]["columns"]}
    assert cols == {"cve_id", "is_confirmed"}


def test_provenance_covers_every_checked_column_not_just_declared(column_writers):
    """The G1 gap itself: mapping-written columns carried NO provenance.

    `cve_id` is written by mappings only, so it never appeared in
    `declared_dependencies` — the key that used to be the ONLY provenance
    carrier. It must now carry writers, integrations and kinds.
    """
    res = check_sql("SELECT cve_id, is_confirmed FROM vulnerabilities", _DECL_REACH)
    by = {c["column"]: c for c in res["sql_provenance"]["columns"]}
    assert by["cve_id"]["writer_kinds"] == ["mapping"]
    assert by["cve_id"]["integrations"] == ["gcp", "snyk"]
    assert len(by["cve_id"]["writers"]) == 2
    # The declared column keeps everything it already had.
    assert by["is_confirmed"]["bridge_ids"] == ["BRIDGE-TRIAGE-001"]


def test_self_filling_is_ANY_and_caller_only_is_ALL(column_writers):
    """⛔ The reduction rule, and its asymmetry is the whole point.

        self_filling = ANY writer kind is self-filling
        caller_only  = ALL writers are `declared`

    `severity` carries BOTH a mapping and a declared writer. Calling it
    caller-dependent would tell a user "this fills only when <caller> runs" —
    false, because a sync also fills it, and precisely the kind of false that
    sends someone to configure something that was never the problem.
    """
    res = check_sql(
        "SELECT cve_id, severity, is_confirmed, vulnerability_status "
        "FROM vulnerabilities", _DECL_REACH)
    by = {c["column"]: c for c in res["sql_provenance"]["columns"]}

    assert by["severity"]["self_filling"] is True
    assert by["severity"]["caller_only"] is False, \
        "a mixed-writer column is NOT caller-only"
    assert by["is_confirmed"]["caller_only"] is True
    assert by["is_confirmed"]["self_filling"] is False
    assert by["cve_id"]["self_filling"] is True
    # A non-mapping self-filling kind must count too — the set is positive
    # membership, not "anything that is not a mapping".
    assert by["vulnerability_status"]["self_filling"] is True


def test_summary_counts_partition_the_columns(column_writers):
    """⚠️ `self_filling + caller_dependent == columns` (§ 3.3.1).

    `caller_dependent` is the STRICT `caller_only`, not "has >=1 declared
    writer". The loose reading double-counts `severity` and breaks the identity.
    """
    res = check_sql(
        "SELECT cve_id, severity, is_confirmed, vulnerability_status "
        "FROM vulnerabilities", _DECL_REACH)
    s = res["sql_provenance"]["summary"]
    assert s["columns"] == 4
    assert s["self_filling"] == 3
    assert s["caller_dependent"] == 1
    assert s["self_filling"] + s["caller_dependent"] == s["columns"]


def test_a_column_read_twice_is_ONE_supply_record(column_writers):
    """A re-read in another clause is the SAME supply fact.

    Counting it twice would break the partition above, and § 3.3.1 defines
    `columns` as DISTINCT (table, column) references. The per-QUERY reduction
    is also what P2's load-bearing rule requires (§ 3.6.2: reduce with OR).
    """
    res = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL "
        "ORDER BY cve_id", _DECL_REACH)
    cols = res["sql_provenance"]["columns"]
    assert len(cols) == 1
    assert res["sql_provenance"]["summary"]["columns"] == 1


def test_no_writer_fails_CLOSED_and_is_not_called_self_filling(column_writers):
    """⛔ § 3.5. An empty writer list is NOT evidence of self-filling.

    A checked column resolving to no writer is a bug in the map or a column
    outside the sink tables. Emitting `writers: []` as though it meant
    "self-filling" would launder a gap into a clean answer. Measured today the
    list is empty (0 of 397), so a non-empty one is real signal.
    """
    reach = {"vulnerabilities": {"cve_id", "ghost_col"}}
    res = check_sql("SELECT cve_id, ghost_col FROM vulnerabilities", reach)
    unres = res["sql_provenance"]["unresolved_writers"]
    assert [u["column"] for u in unres] == ["ghost_col"]

    ghost = {c["column"]: c for c in res["sql_provenance"]["columns"]}["ghost_col"]
    assert ghost["writers"] == []
    assert ghost["self_filling"] is False, "no writer must NEVER read as self-filling"
    assert ghost["caller_only"] is False, "and it is not caller-dependent either"
    # ...and it stays out of BOTH buckets, which is why it is reported separately.
    s = res["sql_provenance"]["summary"]
    assert s["self_filling"] + s["caller_dependent"] == s["columns"] - 1
    # ⛔ The verdict is untouched: a provenance gap is not a SQL defect.
    assert res["clean"] is True


def test_schema_version_is_present_and_one(column_writers):
    """Three sibling keys share the word "provenance"; the block says what it is."""
    res = check_sql("SELECT cve_id FROM vulnerabilities", _DECL_REACH)
    assert res["sql_provenance"]["schema_version"] == 1


def test_provenance_block_present_even_when_nothing_parsed(column_writers):
    """Present-but-empty, like the declared-dependency keys.

    Nothing parsed, so no column resolved and no supply claim can be made —
    `columns: 0` is honest, where an absent block looks like a tool that forgot.
    """
    res = check_sql("SELECT FROM WHERE ((", _DECL_REACH)
    assert res["parsed"] is False
    assert res["sql_provenance"]["summary"]["columns"] == 0
    assert res["sql_provenance"]["schema_version"] == 1


def test_unreachable_column_still_gets_a_supply_record(column_writers):
    """An unreachable column's provenance is the input to `load_bearing_unreachable`.

    Recording it only for reachable columns would leave P2 unable to compute the
    § 1.3 number — a query computing an answer from a column nothing writes.
    """
    reach = {"vulnerabilities": {"cve_id"}}
    res = check_sql("SELECT cve_id, bogus_col FROM vulnerabilities", reach)
    assert [u["column"] for u in res["unreachable"]] == ["bogus_col"]
    got = {c["column"] for c in res["sql_provenance"]["columns"]}
    assert got == {"cve_id", "bogus_col"}
    assert res["sql_provenance"]["summary"]["unreachable_with_provenance"] == 1


def test_missing_writers_degrades_and_does_not_fabricate(column_writers, monkeypatch):
    """No writer map at all: report nothing rather than 397 fake crises.

    Like the declared-dependency map and unlike system/policy columns, this
    input cannot make a verdict WRONG, so an older platform loses provenance
    rather than the whole check.
    """
    monkeypatch.setattr(reachability_gate, "WRITERS_BY_COLUMN", {})
    res = check_sql("SELECT cve_id FROM vulnerabilities", _DECL_REACH)
    assert res["clean"] is True
    assert res["sql_provenance"]["reachable_column_count"] == 0


def test_load_column_writers_distinguishes_missing_from_served():
    """⚠️ "no writers served" and "served, every column has one" are different.

    Without `--explain` the API omits `writers` entirely. Treating that as "397
    columns with no writer" would report a catastrophic supply failure that is
    not real — the same shape as a partial view answering confidently.
    """
    # Served WITH writers.
    got, prov = reachability_gate.load_column_writers({"columns": [
        {"table": "vulnerabilities", "column": "cve_id",
         "writers": [{"kind": "mapping", "source": "m.yaml"}]}]})
    assert got == {("vulnerabilities", "cve_id"): [{"kind": "mapping",
                                                    "source": "m.yaml"}]}
    assert not prov.startswith("unavailable")

    # Served, but NO `writers` key on any row — i.e. `--explain` was not honoured.
    got, prov = reachability_gate.load_column_writers({"columns": [
        {"table": "vulnerabilities", "column": "cve_id", "reachable": True}]})
    assert got == {} and prov.startswith("unavailable")

    # Not served at all.
    got, prov = reachability_gate.load_column_writers({})
    assert got == {} and prov.startswith("unavailable")
    got, prov = reachability_gate.load_column_writers(None)
    assert got == {} and prov.startswith("unavailable")


def test_writer_keys_are_lowercased(column_writers):
    """A quoted/upper-case reference must still resolve its writers."""
    res = check_sql('SELECT "CVE_ID" FROM vulnerabilities', _DECL_REACH)
    assert res["sql_provenance"]["columns"][0]["writer_kinds"] == ["mapping"]


def test_no_caller_counts_only_status_none(monkeypatch):
    """⛔ `no_caller` is the number that says "answers with silence, forever".

    A caller with `status: manual` EXISTS — it just needs running. A caller with
    `status: none` does not exist and never will until someone builds one. The
    measured failure this whole axis exists for: `count(is_confirmed)` = 0 of
    6,179 rows with no caller anywhere, a dashboard rendering an empty panel,
    and a reader concluding "there are no lingering mitigations" when the truth
    is "nobody has recorded one". Opposite conclusions.
    """
    monkeypatch.setattr(reachability_gate, "WRITERS_BY_COLUMN", {
        ("vulnerabilities", "is_confirmed"): [
            {"kind": "declared", "source": "ingest.py::x",
             "expected_caller": {"name": "triage (NOT BUILT)", "status": "none",
                                 "exists": False}}],
        ("vulnerabilities", "exploitability_status"): [
            {"kind": "declared", "source": "ingest.py::y",
             "expected_caller": {"name": "torana-pentest", "status": "wired",
                                 "exists": True}}],
    })
    monkeypatch.setattr(reachability_gate, "WRITERS_PROVENANCE", "fixture")
    res = check_sql(
        "SELECT is_confirmed, exploitability_status FROM vulnerabilities",
        {"vulnerabilities": {"is_confirmed", "exploitability_status"}})
    s = res["sql_provenance"]["summary"]
    assert s["caller_dependent"] == 2, "both are declared-only"
    assert s["no_caller"] == 1, "only the status=none column answers with silence"
    # ⛔ And neither touches the verdict.
    assert res["clean"] is True


# ─────────────────────────────────────────────────────────────────────────────
# P2 / G2 — load-bearing, computed from the PARSE TREE (spec § 3.6.1).
#
# ⛔ The whole point of this block: `clause` says SELECT for BOTH a bare
# projection and a column inside a CASE in the select list. Treating those alike
# is what produced the § 1.3 error — a query that computes an answer from a
# column nothing writes, noticed only as a harmless-looking display field.
# ─────────────────────────────────────────────────────────────────────────────

#: The six cases § 3.6.1 states as the rule's verified behaviour. Re-measured
#: against the sqlglot in this venv before the rule was written.
_LOAD_BEARING_CASES = [
    ("SELECT v.cve_id FROM vulnerabilities v", "cve_id", False,
     "bare projection — dropping it removes a display field only"),
    ("SELECT v.severity FROM vulnerabilities v ORDER BY v.cve_id", "cve_id", False,
     "bare ORDER BY is presentation order only"),
    ("SELECT v.severity FROM vulnerabilities v WHERE v.cve_id = 'x'", "cve_id", True,
     "WHERE filters"),
    ("SELECT v.severity FROM vulnerabilities v "
     "ORDER BY (CASE WHEN v.cve_id = 'c' THEN 1 ELSE 2 END)", "cve_id", True,
     "⛔ CASE wins over ORDER BY — the RULE decides, not the clause"),
    ("SELECT count(*) OVER (PARTITION BY v.cve_id) FROM vulnerabilities v",
     "cve_id", True, "PARTITION BY defines the grain"),
    ("SELECT v.severity FROM vulnerabilities v "
     "QUALIFY row_number() OVER (PARTITION BY v.cve_id) = 1", "cve_id", True,
     "QUALIFY filters"),
]


@pytest.mark.parametrize("sql,column,expected,why", _LOAD_BEARING_CASES)
def test_load_bearing_rule_six_cases(column_writers, sql, column, expected, why):
    """§ 3.6.1's six verified cases, driven through the real `check_sql`."""
    res = check_sql(sql, REACH)
    recs = [c for c in res["sql_provenance"]["columns"] if c["column"] == column]
    assert recs, f"no provenance record for {column}"
    assert recs[0]["load_bearing"] is expected, why


def test_no_order_by_exclusion_is_needed(column_writers):
    """⚠️ A bare ORDER BY returns False NATURALLY, from the positive rule.

    § 3.6.1 is explicit that adding an ORDER BY exclusion would be a bug: the
    walk reaches `Select` without touching a load-bearing ancestor. This asserts
    the mechanism, not just the outcome — if someone "fixes" the rule by adding
    an exclusion list, the CASE-in-ORDER-BY case above breaks and this one
    keeps passing, which is how you tell them apart.
    """
    import sqlglot
    from sqlglot import exp
    tree = sqlglot.parse_one("SELECT a FROM t ORDER BY t.x", dialect="postgres")
    col = next(c for c in tree.find_all(exp.Column) if c.name == "x")
    assert reachability_gate._is_load_bearing(col) is False


def test_load_bearing_is_per_query_not_per_reference(column_writers):
    """⛔ Reduce with OR — the § 3.6.2 rule, and the one most easily lost.

    ⚠️ THE ORDERING TRAP THIS GUARDS. `check_sql` dedups references by
    (table, column, CLAUSE), and BOTH references below are clause=SELECT — a
    CASE in the select list is attributed to SELECT by design. The bare
    projection parses FIRST. So if the reduction ran after the dedup, the
    `false` would be kept and the `true` discarded, reporting precisely the
    reassuring half. Measured on Q-058, Q-006 and Q-088, where the bare
    projection is first every time.
    """
    res = check_sql(
        "SELECT v.cve_id, CASE WHEN v.cve_id LIKE 'CVE-2024%' THEN 1 ELSE 0 END "
        "AS recent FROM vulnerabilities v", REACH)
    recs = [c for c in res["sql_provenance"]["columns"] if c["column"] == "cve_id"]
    assert len(recs) == 1, "one supply fact per (table, column), not per reference"
    assert recs[0]["load_bearing"] is True, "ANY reference load-bearing ⇒ the query is"


def test_load_bearing_crosses_the_subquery_boundary(column_writers):
    """⚠️ The walk continues to the ROOT — it does not stop at the inner SELECT.

    A column inside a subquery in a WHERE clause IS load-bearing for the outer
    query. Stopping at the boundary would report it as a harmless projection.
    """
    res = check_sql(
        "SELECT a.asset_name FROM assets a WHERE a.torana_entity_id IN "
        "(SELECT v.cve_id FROM vulnerabilities v)", REACH)
    recs = [c for c in res["sql_provenance"]["columns"] if c["column"] == "cve_id"]
    assert recs and recs[0]["load_bearing"] is True


def test_load_bearing_unreachable_is_the_hazard_number(column_writers):
    """⛔ § 3.3.1 — BOTH unreachable AND load-bearing.

    Non-zero means the query computes an answer from a column nothing writes.
    ⚠️ An unreachable column in a bare projection must NOT count: it returns an
    empty display field, which is visible. The hazard is the one that silently
    changes which rows come back.
    """
    # Unreachable AND filtering → counted.
    res = check_sql(
        "SELECT v.cve_id FROM vulnerabilities v WHERE v.bogus_flag = true", REACH)
    assert res["sql_provenance"]["summary"]["load_bearing_unreachable"] == 1

    # Unreachable but merely PROJECTED → not counted.
    res = check_sql("SELECT v.bogus_flag FROM vulnerabilities v", REACH)
    assert res["sql_provenance"]["summary"]["load_bearing_unreachable"] == 0

    # Reachable and load-bearing → not counted (it is not a hazard).
    res = check_sql(
        "SELECT v.severity FROM vulnerabilities v WHERE v.cve_id = 'x'", REACH)
    assert res["sql_provenance"]["summary"]["load_bearing_unreachable"] == 0


def test_load_bearing_does_NOT_change_clean(column_writers):
    """⛔ C3 — provenance is a SECOND AXIS. It never feeds the verdict."""
    lb = check_sql(
        "SELECT v.severity FROM vulnerabilities v WHERE v.cve_id = 'x'", REACH)
    plain = check_sql("SELECT v.cve_id FROM vulnerabilities v", REACH)
    assert lb["sql_provenance"]["columns"][0]["load_bearing"] is True
    assert plain["sql_provenance"]["columns"][0]["load_bearing"] is False
    assert lb["clean"] is True and plain["clean"] is True


# ─────────────────────────────────────────────────────────────────────────────
# P3 / G3 — execution evidence (spec § 3.7).
#
# ⛔ EVIDENCE, NEVER THE VERDICT. The three states are distinct and must stay so:
#   ok:false               → a real defect; the SQL does not run (§ 1.1's miss)
#   ok:true, row_count:0   → NOT a defect; a caller may not have run yet
#   attempted:false        → the author skipped it; allowed and visible
# ⚠️ NO NETWORK — `execute_sql` is stubbed, like every other test here.
# ─────────────────────────────────────────────────────────────────────────────


def test_strip_leading_comments_or_41_queries_look_broken():
    """⛔ The platform's read-only guard reads the FIRST TOKEN.

    ⚠️ MEASURED, and it is why this helper exists: nearly every regenerated
    corpus row opens with a `-- REGENERATED …` header, and the guard answers
    `HTTP 400 Only SELECT queries are allowed`. Without the strip, 41 of 49
    corpus queries are reported as broken when every one of them runs — the
    § 1.1 error inverted, with this phase's own evidence as the casualty.
    """
    s = reachability_gate._strip_leading_comments
    assert s("-- header\nSELECT 1").startswith("SELECT")
    assert s("-- a\n-- b\n\n  SELECT 1").startswith("SELECT")
    assert s("/* block */ SELECT 1").startswith("SELECT")
    assert s("/* a */\n-- b\nWITH x AS (SELECT 1) SELECT * FROM x").startswith("WITH")
    # ⛔ Comments INSIDE the query are the author's and are left untouched.
    assert "-- inline" in s("SELECT 1 -- inline\nFROM t")
    # Degenerate input must not raise.
    assert s("-- only a comment") == ""
    assert s("/* unterminated") == ""


def test_execution_ok_is_from_the_PAYLOAD_not_the_exit_code(monkeypatch):
    """⛔ MEASURED: `torana datalake query` prints an HTTP 500 and EXITS 0.

    Trusting the exit code reports a broken query as `ok: true` — the single
    failure this phase exists to catch, reported as a success.
    """
    class _Proc:
        returncode = 0                      # ← the trap: success exit code…
        stdout = ""
        stderr = 'ERROR: API error (HTTP 500) Query failed: column "sev" does not exist'

    monkeypatch.setattr(reachability_gate.subprocess, "run",
                        lambda *a, **k: _Proc())
    res = reachability_gate.execute_sql("SELECT sev FROM t", "T1")
    assert res["ok"] is False, "a 500 on stderr with exit 0 is still a failure"
    assert "does not exist" in res["error"]
    assert res["profile"] == "T1"


def test_execution_row_count_uses_server_total_not_the_cap(monkeypatch):
    """⚠️ `total_rows` is counted BEFORE the cap, so it is the true number.

    ⛔ And when the result was truncated, the cap is reported alongside — never
    silently, or a reader takes 100 for the answer.
    """
    import json as _json

    class _Proc:
        returncode = 0
        stderr = ""
        stdout = _json.dumps({"error": None, "data": [{"n": 1}] * 100,
                              "total_rows": 82354, "limited": True, "limit": 100})

    monkeypatch.setattr(reachability_gate.subprocess, "run",
                        lambda *a, **k: _Proc())
    res = reachability_gate.execute_sql("SELECT 1 FROM t", "T1")
    assert res["ok"] is True
    assert res["row_count"] == 82354, "the true count, not the truncated page"
    assert res["rows_returned"] == 100 and res["row_cap"] == 100


def test_execution_row_count_gte_when_no_total_is_served(monkeypatch):
    """⛔ At the cap with no total, the count is UNKNOWN — say only what was proven."""
    import json as _json

    class _Proc:
        returncode = 0
        stderr = ""
        stdout = _json.dumps({"error": None, "data": [{"n": 1}] * 100})

    monkeypatch.setattr(reachability_gate.subprocess, "run",
                        lambda *a, **k: _Proc())
    res = reachability_gate.execute_sql("SELECT 1 FROM t", "T1")
    assert res.get("row_count") is None, "must NOT assert a number it did not measure"
    assert res["row_count_gte"] == 100


def test_zero_rows_is_NOT_a_failure(monkeypatch):
    """⛔ § 3.7 — the distinction the whole phase turns on.

    A query can be correct and return nothing because a caller has not run yet.
    Q-050 does exactly this on live data (ok:true, row_count:0,
    caller_dependent:4). Collapsing it into `ok:false` would call a correct
    query broken and send the reader to fix SQL that has nothing wrong with it.
    """
    import json as _json

    class _Proc:
        returncode = 0
        stderr = ""
        stdout = _json.dumps({"error": None, "data": [], "total_rows": 0,
                              "limited": False})

    monkeypatch.setattr(reachability_gate.subprocess, "run",
                        lambda *a, **k: _Proc())
    res = reachability_gate.execute_sql("SELECT 1 FROM t WHERE false", "T1")
    assert res["ok"] is True and res["row_count"] == 0


def test_execution_never_changes_clean(column_writers, monkeypatch):
    """⛔ C3 — execution is a THIRD axis. A failing run must not fail the gate.

    Reachability asks "can this column ever hold data"; execution asks "does
    this text run today". Folding one into the other destroys the property that
    makes the gate useful: a query blocked by a live outage is not an authoring
    defect, and a query that runs is not thereby reachable.
    """
    monkeypatch.setattr(reachability_gate, "execute_sql",
                        lambda sql, profile: {"attempted": True, "ok": False,
                                              "error": "boom", "profile": profile})
    res = check_sql("SELECT v.cve_id FROM vulnerabilities v", REACH)
    assert res["clean"] is True
    reachability_gate._attach_execution(res, "T1")
    assert res["sql_provenance"]["execution"]["ok"] is False
    assert res["clean"] is True, "⛔ execution must never move the verdict"


def test_attach_execution_records_not_attempted_when_nothing_parsed(column_writers):
    """⚠️ "the author skipped it" and "it does not run" are DIFFERENT facts.

    A parse failure has no SQL to run, so recording `ok:false` there would
    invent a runtime defect on top of a parse defect and double-count it.
    """
    res = check_sql("SELECT FROM WHERE ((", REACH)
    assert res["parsed"] is False
    reachability_gate._attach_execution(res, "T1")
    ex = res["sql_provenance"]["execution"]
    assert ex["attempted"] is False and "nothing parsed" in ex["skipped_because"]
    assert "ok" not in ex, "must not claim a run happened"


# ─────────────────────────────────────────────────────────────────────────────
# P4 — the two mandatory user-facing reports (spec § 3.8).
#
# ⛔ SKILL.md tells the model WHAT to say. These tests lock the DATA that
# licenses it, because prose cannot enforce itself: the "fills only when <caller>
# runs" sentence may be emitted ONLY for `caller_only` columns, and the field
# that gates it has to keep meaning what it means.
# ─────────────────────────────────────────────────────────────────────────────


def test_mixed_writer_column_must_NOT_license_the_caller_report(column_writers,
                                                                monkeypatch):
    """⛔ THE FALSE-REPORT HAZARD, and it is not a corner case.

    ⚠️ MEASURED on T1 2026-08-06: **34 columns** carry BOTH a `declared` and a
    self-filling writer (`assets.asset_name`, `assets.criticality_level`, …).
    The seam allows this deliberately — that IS the triage design.

    Saying "column X fills only when <caller> runs" about such a column is
    simply false: a sync also fills it. It is the kind of false that sends a
    customer to configure something that was never the problem.

    ⛔ So the gate is `caller_only` (ALL writers declared), NEVER `has ≥1
    declared writer` and NEVER `not self_filling`.
    """
    monkeypatch.setattr(reachability_gate, "WRITERS_BY_COLUMN", {
        # Mixed — a sync fills it too. MUST NOT be reported as caller-dependent.
        ("assets", "asset_name"): [
            {"kind": "mapping", "source": "mappings/gcp/assets.yaml",
             "integration": "gcp"},
            {"kind": "declared", "source": "ingest.py::patch",
             "expected_caller": {"name": "torana assets update", "status": "manual"}},
        ],
        # Declared-only — the ONLY shape the sentence may be said about.
        ("vulnerabilities", "is_confirmed"): [
            {"kind": "declared", "source": "ingest.py::triage",
             "expected_caller": {"name": "torana vulnerability triage",
                                 "status": "manual"}},
        ],
    })
    monkeypatch.setattr(reachability_gate, "WRITERS_PROVENANCE", "fixture")
    res = check_sql(
        "SELECT a.asset_name FROM assets a",
        {"assets": {"asset_name"}})
    rec = res["sql_provenance"]["columns"][0]
    assert rec["caller_only"] is False, "a sync also fills it"
    assert rec["self_filling"] is True
    assert res["sql_provenance"]["summary"]["caller_dependent"] == 0, (
        "⛔ non-zero here would license a FALSE 'fills only when X runs' report")

    res = check_sql(
        "SELECT v.is_confirmed FROM vulnerabilities v",
        {"vulnerabilities": {"is_confirmed"}})
    assert res["sql_provenance"]["columns"][0]["caller_only"] is True
    assert res["sql_provenance"]["summary"]["caller_dependent"] == 1, (
        "declared-only IS the case the report exists for")


def test_the_two_report_gates_are_readable_from_the_block_alone(column_writers,
                                                               monkeypatch):
    """§ 3.8's two reports must be answerable WITHOUT re-deriving anything.

    A skill that has to recompute a field to know whether it may speak will
    eventually recompute it differently. Both gates are single field reads.
    """
    monkeypatch.setattr(reachability_gate, "execute_sql",
                        lambda sql, profile: {"attempted": True, "ok": False,
                                              "error": "syntax error",
                                              "profile": profile})
    res = check_sql("SELECT v.cve_id FROM vulnerabilities v", REACH)
    reachability_gate._attach_execution(res, "T1")
    sp = res["sql_provenance"]

    # Report 1 gate — one integer.
    assert isinstance(sp["summary"]["caller_dependent"], int)
    # Report 2 gate — one boolean, and `ok:false` means NOT deliverable
    # regardless of the verdict.
    assert sp["execution"]["ok"] is False
    assert res["clean"] is True, "⛔ …and the verdict still says CLEAN — which is"
    # ⛔ …exactly why § 3.8 requires the skill to report execution SEPARATELY.
    # A CLEAN query that does not run is still broken (§ 1.1).


# ── S6 — the value axis, wired into this gate ───────────────────────────────
#
# ⛔ These test the WIRING, not the classifier. The routing rule itself lives in
# `pantheon_shared.datalake.shape_routing` and is tested in
# `pantheon-shared/tests/datalake/test_shape_routing.py` — deliberately ONE test
# suite for one classifier, because the platform text-to-SQL agent runs the same
# code. Duplicating the rule's tests here would let the two copies disagree,
# which is the exact drift the shared module exists to prevent.

_SHAPES_FIXTURE = {
    "vulnerabilities.is_false_positive": {
        "known": True, "shape": "constant", "distinct": 1,
        "values": [{"value": False, "rows": 6275, "percent": 100.0}],
        "rows_with_a_value": 6275, "source": "exact",
    },
    "vulnerabilities.severity": {
        "known": True, "shape": "enum", "distinct": 4,
        "values": [{"value": "Critical", "rows": 288, "percent": 4.6}],
        "rows_with_a_value": 6051, "source": "exact",
    },
}


def test_shape_report_routes_and_warns(monkeypatch):
    """The gate must route by usage and surface a CONSTANT deciding column."""
    monkeypatch.setattr(reachability_gate, "_fetch_shapes",
                        lambda cols, depth, profile: _SHAPES_FIXTURE)
    rep = reachability_gate.shape_report(
        "SELECT severity, COUNT(*) FROM vulnerabilities "
        "WHERE is_false_positive = true GROUP BY severity", "T1")
    assert rep["available"] is True
    # ONE call, at the deepest depth any column needs.
    assert rep["depth_requested"] == "values"
    assert rep["routing"]["values"] == ["vulnerabilities.is_false_positive"]
    assert rep["routing"]["shape"] == ["vulnerabilities.severity"]
    assert len(rep["warnings"]) == 1
    # ⛔ S6 § 4 rule 3 — the warning NAMES the value.
    assert "False" in rep["warnings"][0]["message"]


def test_shape_report_emits_generated_against(monkeypatch):
    """⭐ ARTIFACT_INTENT_SPEC.md § 4.1 — the shape signature, written at
    generation time because it is unrecoverable afterwards without regenerating
    everything once."""
    monkeypatch.setattr(reachability_gate, "_fetch_shapes",
                        lambda cols, depth, profile: _SHAPES_FIXTURE)
    rep = reachability_gate.shape_report(
        "SELECT cve_id FROM vulnerabilities WHERE severity = 'Critical'", "T1")
    assert rep["generated_against"]["vulnerabilities.is_false_positive"] == "CONSTANT(False)"
    assert rep["generated_against"]["vulnerabilities.severity"] == "ENUM(4)"


def test_shape_report_never_reports_a_parse_failure_as_nothing_to_check():
    """⛔ An empty report reads as 'all clear'. Say the SQL could not be parsed."""
    rep = reachability_gate.shape_report("not sql (((", "T1")
    assert rep.get("parse_error")
    assert "could not parse" in reachability_gate._fmt_shape(rep)


def test_shape_never_changes_the_reachability_verdict(monkeypatch, tmp_path, capsys):
    """⛔ A shape is a property of a DATASET AT A MOMENT, so letting it gate would
    make an authoring verdict depend on today's data — one tenant's rows failing
    another tenant's SQL. Reachability gates; shape informs.

    ⚠️ This drives `main()` END-TO-END, not `shape_report()` in isolation.
    Measured: the isolated version of this test PASSED against a mutation that
    set `result["clean"] = False` on a shape warning inside the `--shapes`
    dispatch — it never executed the line where the coupling would be
    introduced, so it asserted the invariant without protecting it. The EXIT
    CODE is the contract a CI gate consumes, so the exit code is what is tested.
    """
    monkeypatch.setattr(reachability_gate, "_fetch_shapes",
                        lambda cols, depth, profile: _SHAPES_FIXTURE)
    monkeypatch.setattr(reachability_gate, "establish_ground_truth",
                        lambda scope, profile: REACH)
    monkeypatch.setattr(reachability_gate, "_provenance_lines", lambda: [])

    # ⚠️ The SQL must be reachability-CLEAN so the two axes are separable — a
    # query that is ALSO unreachable proves nothing about whether shape moved
    # the verdict. `vulnerability_status` is in REACH; the shapes fixture below
    # makes it CONSTANT, so the shape pass warns and the reachability pass does
    # not. (First draft used `is_false_positive`, which is absent from REACH —
    # `clean` was already False for an unrelated reason and the test failed at
    # baseline.)
    monkeypatch.setitem(
        _SHAPES_FIXTURE, "vulnerabilities.vulnerability_status",
        {"known": True, "shape": "constant", "distinct": 1,
         "values": [{"value": "Open", "rows": 6274, "percent": 100.0}],
         "rows_with_a_value": 6274, "source": "exact"},
    )
    sql_file = tmp_path / "q.sql"
    sql_file.write_text(
        "SELECT v.cve_id FROM vulnerabilities v "
        "WHERE v.vulnerability_status = 'Resolved'")

    monkeypatch.setattr(
        sys, "argv",
        ["reachability_gate.py", "check", "--file", str(sql_file),
         "--shapes", "--profile", "T1", "--json"],
    )
    rc = reachability_gate.main()
    payload = json.loads(capsys.readouterr().out)

    assert payload["shape"]["warnings"], "fixture should produce a warning"
    assert payload["clean"] is True, "shape must not alter the verdict"
    assert rc == 0, "⛔ shape findings must NOT change the exit code"


def test_shape_report_degrades_with_a_named_cause_never_silently(monkeypatch):
    """A checker that keeps answering from a partial view is worse than one that
    refuses — the rule this gate already applies to system columns."""
    monkeypatch.setattr(reachability_gate, "_load_shape_routing",
                        lambda: (None, ""))
    rep = reachability_gate.shape_report("SELECT 1 FROM vulnerabilities", "T1")
    assert rep["available"] is False
    assert "why" in rep and rep["why"]
    assert "unavailable" in reachability_gate._fmt_shape(rep)


# ── S23: `CLEAN` must say what an EMPTY RESULT means ─────────────────────────
#
# The defect this block guards: `CLEAN` meant only "every column is REACHABLE".
# It did not distinguish a query that fills itself from one that waits on a
# human, so a dashboard rendering `0` was read as "there are none" when the
# truth was "nobody has recorded one" — opposite conclusions, same verdict.
#
# ⚠️ The reduction is derived from the caller's `status`, NOT from `has_caller`.
# That is the whole point. Measured 2026-08-10: after the bridges were built,
# every declared column in the corpus had a caller, so `has_caller` was True for
# all 47 caller-dependent CLEAN rows and separated nothing. A test written
# against `has_caller` would pass while the reader learned nothing.

#: Three columns that differ ONLY in caller status, so a test can prove the gate
#: separates them rather than flagging every declared column identically.
_FILL_REACH = {"vulnerabilities": {"cve_id", "is_confirmed",
                                   "exploitability_status", "severity"}}

_FILL_DEPS = {
    ("vulnerabilities", "is_confirmed"): {
        "table": "vulnerabilities", "column": "is_confirmed",
        "has_caller": True, "caller_undeclared": False,
        "callers": [{"name": "torana vulnerability triage", "status": "manual",
                     "exists": True}],
        "writers": ["ingest.py::_update_vulnerability_impl"], "why": "",
    },
    ("vulnerabilities", "exploitability_status"): {
        "table": "vulnerabilities", "column": "exploitability_status",
        "has_caller": True, "caller_undeclared": False,
        "callers": [{"name": "torana-pentest", "status": "wired", "exists": True}],
        "writers": ["ingest.py::_update_vulnerability_impl"], "why": "",
    },
    ("vulnerabilities", "severity"): {
        "table": "vulnerabilities", "column": "severity",
        "has_caller": False, "caller_undeclared": False,
        "callers": [{"name": "triage workflow (NOT BUILT)", "status": "none",
                     "exists": False}],
        "writers": ["ingest.py::_update_vulnerability_impl"], "why": "",
    },
}


@pytest.fixture
def fill_deps(monkeypatch):
    """Install the fill-mode fixture map. NO NETWORK, like every other test."""
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES", _FILL_DEPS)
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES_PROVENANCE",
                        "fixture")


def test_fill_mode_separates_the_three_states(fill_deps):
    """⭐ The row's headline: three CLEAN queries, three different meanings of `0`.

    All three are ✅ CLEAN and all three are CORRECT SQL. What differs is what an
    empty result licenses a reader to conclude.
    """
    self_filling = check_sql("SELECT cve_id FROM vulnerabilities", _FILL_REACH)
    wired = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE exploitability_status = 'x'",
        _FILL_REACH)
    manual = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE is_confirmed IS TRUE",
        _FILL_REACH)

    assert self_filling["fill_mode"] == "self_filling"
    assert wired["fill_mode"] == "wired"
    assert manual["fill_mode"] == "manual"

    # ⛔ ...and every one of them is still CLEAN. The axis is orthogonal to the
    # verdict; if this ever fails, the axis has been folded into the ladder.
    for res in (self_filling, wired, manual):
        assert res["clean"] is True
        assert _verdict_of(res) == "CLEAN"


def test_fill_mode_is_derived_from_status_NOT_from_has_caller(fill_deps):
    """⛔ The regression that motivated the whole row.

    All three fixture columns carry a caller record; `is_confirmed` and
    `exploitability_status` both have `has_caller: True`. A reduction keyed on
    `has_caller` reports them IDENTICALLY — which is exactly what the gate did,
    and why 47 caller-dependent CLEAN rows looked the same as each other.
    """
    manual = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE is_confirmed IS TRUE",
        _FILL_REACH)
    wired = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE exploitability_status = 'x'",
        _FILL_REACH)

    # Identical on the OLD signal...
    assert manual["declared_dependencies"][0]["has_caller"] is True
    assert wired["declared_dependencies"][0]["has_caller"] is True
    assert manual["declared_dependencies_without_caller"] == []
    assert wired["declared_dependencies_without_caller"] == []
    # ...and DIFFERENT on the new one. This inequality is the fix.
    assert manual["fill_mode"] != wired["fill_mode"]


def test_fill_mode_takes_the_WORST_across_columns(fill_deps):
    """⚠️ Across columns the quantifier is conjunctive — weakest link wins.

    A query joining a self-filling column and a `manual` column returns nothing
    until a human acts. Reporting it by its healthiest column would hide the
    exact dependency this exists to surface.
    """
    res = check_sql(
        "SELECT cve_id, exploitability_status FROM vulnerabilities "
        "WHERE is_confirmed IS TRUE", _FILL_REACH)
    assert {d["column"] for d in res["declared_dependencies"]} == {
        "is_confirmed", "exploitability_status"}
    assert res["fill_mode"] == "manual", (
        "a wired sibling must NOT upgrade a row that also reads a manual column")

    # `none` outranks `manual` — the loudest state wins.
    res2 = check_sql(
        "SELECT cve_id, severity FROM vulnerabilities WHERE is_confirmed IS TRUE",
        _FILL_REACH)
    assert res2["fill_mode"] == "none"


def test_fill_mode_takes_the_BEST_within_one_column(monkeypatch):
    """⚠️ Within a column the quantifier is OPPOSITE — alternatives, best wins.

    The seam is explicit: two writers may declare the same column and "if ONE of
    them is wired the column can fill, so it is not dead"
    (`write_seam.columns_without_caller`). Taking the worst here would cry wolf
    on a column a robot already fills, and a checker that cries wolf gets waived.
    """
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES", {
        ("vulnerabilities", "is_confirmed"): {
            "table": "vulnerabilities", "column": "is_confirmed",
            "has_caller": True, "caller_undeclared": False,
            "callers": [
                {"name": "triage workflow (NOT BUILT)", "status": "none",
                 "exists": False},
                {"name": "torana-pentest", "status": "wired", "exists": True},
            ],
            "writers": [], "why": "",
        }})
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES_PROVENANCE",
                        "fixture")
    res = check_sql("SELECT cve_id FROM vulnerabilities WHERE is_confirmed IS TRUE",
                    _FILL_REACH)
    assert res["fill_mode"] == "wired", (
        "a wired caller on the SAME column must win — the column really can fill")


def test_fill_mode_fails_CLOSED_on_an_unknown_or_missing_status(monkeypatch):
    """⛔ An unrecognised status ranks as `none`, the loudest state.

    `status` is a closed vocabulary in the seam. If a NINTH value ever appears,
    the optimistic default ("probably fine") would silently launder it into a
    clean answer — the same reasoning that makes SELF_FILLING_WRITER_KINDS a
    positive membership set rather than "everything except declared".
    """
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES", {
        ("vulnerabilities", "is_confirmed"): {
            "table": "vulnerabilities", "column": "is_confirmed",
            "has_caller": True, "caller_undeclared": False,
            "callers": [{"name": "some future thing", "status": "probably-fine"}],
            "writers": [], "why": "",
        },
        ("vulnerabilities", "severity"): {
            "table": "vulnerabilities", "column": "severity",
            "has_caller": True, "caller_undeclared": False,
            "callers": [],          # a record with NO caller entries at all
            "writers": [], "why": "",
        }})
    monkeypatch.setattr(reachability_gate, "DECLARED_DEPENDENCIES_PROVENANCE",
                        "fixture")
    unknown = check_sql(
        "SELECT cve_id FROM vulnerabilities WHERE is_confirmed IS TRUE",
        _FILL_REACH)
    empty = check_sql("SELECT cve_id, severity FROM vulnerabilities", _FILL_REACH)
    assert unknown["fill_mode"] == "none", "an unknown status must not read as fillable"
    assert empty["fill_mode"] == "none", "absent evidence is not evidence of a caller"


def test_unparsed_sql_is_unknown_NEVER_self_filling():
    """⛔ C1: never assert a fill claim about SQL the gate did not read.

    `_fill_mode([])` is `self_filling` because "reads no declared column" is a
    real finding. But a row that did not PARSE examined no column at all, so
    reusing that label would state "an empty result is a real answer" about SQL
    nobody checked — a fabricated answer.
    """
    res = check_sql("SELECT FROM WHERE ((", _FILL_REACH)
    assert res["parsed"] is False
    assert res["fill_mode"] == "unknown"
    assert "did not parse" in res["empty_result_means"]


def test_fill_mode_never_changes_the_verdict_or_the_exit_code(fill_deps, tmp_path,
                                                              monkeypatch, capsys):
    """⛔ §3.1/§3.2 as an executable contract: this is an AXIS, not a rung.

    A caller-dependent question is legitimate and its SQL is correct, so it must
    stay CLEAN and must keep exit 0. If a `none` row ever flips the exit code,
    every corpus run fails until callers exist — and the property that made the
    write seam work (register a column, the question passes, no gate edit) dies
    with it.
    """
    monkeypatch.setattr(reachability_gate, "establish_ground_truth",
                        lambda scope, profile: _FILL_REACH)
    monkeypatch.setattr(reachability_gate, "_provenance_lines", lambda: [])
    sql_file = tmp_path / "q.sql"
    # `severity` has status=none — the loudest possible second-axis state.
    sql_file.write_text("SELECT cve_id, severity FROM vulnerabilities")

    monkeypatch.setattr(sys, "argv",
                        ["reachability_gate.py", "check", "--file", str(sql_file),
                         "--profile", "T1", "--json"])
    rc = reachability_gate.main()
    payload = json.loads(capsys.readouterr().out)

    assert payload["fill_mode"] == "none"
    assert payload["clean"] is True, "⛔ the second axis must NOT alter the verdict"
    assert rc == 0, "⛔ a caller-dependent row must NOT change the exit code"


def test_human_output_states_what_an_empty_result_means(fill_deps):
    """The reader-facing half. A boolean nobody interprets is not a fix.

    The failure mode is a person reading a panel, so the consequence must be
    spelled out in the words they need — not left as `has_caller: false` for
    them to translate.
    """
    res = check_sql("SELECT cve_id FROM vulnerabilities WHERE is_confirmed IS TRUE",
                    _FILL_REACH)
    txt = reachability_gate._fmt(res, _FILL_REACH)
    assert "if this returns NOTHING" in txt
    assert "NOBODY HAS RECORDED ONE" in txt
    # ...and it must NOT be phrased as a defect: the SQL is correct.
    assert "answerable and correct" in txt
