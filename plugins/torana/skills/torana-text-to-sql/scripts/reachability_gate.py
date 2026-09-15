#!/usr/bin/env python3
"""Reachability gate for text-to-SQL — the authority on what is answerable.

Two jobs, and ONLY these two:

  fetch   — pull the REACHABLE schema from the live platform. Never embed one.
  check   — parse a SQL string and report every column reference that is NOT
            reachable, wherever it appears (SELECT, WHERE, JOIN, GROUP BY, CTE,
            inside a CASE, ...).

⚠️ Why `check` re-parses instead of trusting the author
------------------------------------------------------
The mechanical corpus pass leaked unreachable columns twice by PREDICTING that a
rewrite was clean. A column can be both a plain projection and a reference inside
a CASE in the same SELECT; deleting the projection leaves the CASE behind. So the
only trustworthy check is to re-parse the FINAL text and re-ask the schema.

⚠️ Two traps this module encodes, both measured (see SKILL.md § Ground truth)
----------------------------------------------------------------------------
1. `--scope platform`, never tenant. Measured on `vulnerabilities`:
   platform=99 reachable, tenant=7. Tenant scope hides columns that are fine the
   moment a customer connects an integration — a deployment fact, not an
   authoring one. Authoring against tenant scope would condemn 92 good columns.

2. System fields are NOT in the reachability classification and are ALWAYS
   available. They are not even in the declared-schema response. A naive
   "absent from the list ⇒ unreachable" check condemns `is_deleted`, which
   appears in nearly every corpus WHERE clause. The list is IMPORTED from
   pantheon-shared, never retyped here — if the platform adds a system field
   this picks it up with no edit.

⛔ This module does not run SQL and holds no opinion about rows. The schema
   decides; execution is a smoke test owned by the caller.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:
    import sqlglot
    from sqlglot import exp
except ImportError:  # pragma: no cover
    print("ERROR: sqlglot is required. Use $TORANA_ROOT/.venv.", file=sys.stderr)
    raise SystemExit(2)


# ── Ground truth: API FIRST, local import only as an offline fallback ────────
#
# ⛔ THE RULE THIS FILE NOW OBEYS (skills/CLAUDE.md): a skill runs against the
# API via the `torana` CLI. It must never REQUIRE a `pantheon-*` checkout to
# produce a correct answer.
#
# ⚠️ And when ground truth cannot be established, it REFUSES. It does not warn
# and keep answering. Measured, on a machine with no checkout: this gate used to
# print a confident `❌ UNREACHABLE vulnerabilities.is_deleted [WHERE —
# STRUCTURAL]` on STDOUT with exit 1, while the only warning went to STDERR.
# `is_deleted` is in nearly every real WHERE clause, so it condemned almost
# every correct query — and anything scripted around it saw only the wrong
# answer. A checker degraded to a partial view keeps answering, and its answers
# look authoritative. That is strictly worse than crashing, because nobody
# investigates a confident result.
class GroundTruthUnavailable(RuntimeError):
    """Raised when a ground-truth input cannot be established. NEVER caught to
    produce a verdict — only to print a named cause and exit non-zero."""


def _torana_json(args: Sequence[str], profile: str) -> object:
    """Run a `torana` command and parse its JSON. Returns None on any failure.

    Deliberately quiet: the CALLER decides whether a failure is fatal, because
    only the caller knows whether a local fallback exists.
    """
    env = {**os.environ, "TORANA_PROFILE": profile}
    try:
        proc = subprocess.run(["torana", *args], capture_output=True,
                              text=True, env=env, timeout=120)
    except Exception:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except Exception:
        return None


def _local_pantheon_shared() -> List[Path]:
    """Candidate `pantheon-shared/src` dirs, if a checkout happens to be here."""
    cands: List[Path] = []
    root = os.environ.get("TORANA_ROOT")
    if root:
        cands.append(Path(root) / "pantheon-shared" / "src")
    for parent in Path(__file__).resolve().parents:
        cand = parent / "pantheon-shared" / "src"
        if cand.is_dir():
            cands.append(cand)
    return [c for c in cands if c.is_dir()]


def load_system_columns(profile: str, payload: object = None) -> Tuple[Set[str], str]:
    """The 7 always-available system fields, from the PLATFORM API. No local fallback.

    ⛔ THE LOCAL IMPORT WAS DELETED (Torana_Datalake_Fixes.md § 3.13.5). It read
    `SYSTEM_WRITTEN_COLUMNS` out of a checkout, which made a SECOND authority for a fact the
    API already serves in the same `reachable-columns` payload this function is handed. Two
    authorities for one fact is precisely the defect § 3.13.2a removed from the value domains,
    and the same drift was already measured here: the old code had to print a DISAGREEMENT
    warning because it expected the two to diverge.

    ⭐ The API is also the only correct source: it is what the SQL will actually run against.
    A checkout can be newer OR older than the deployed platform, and a verdict computed from
    a stale constant is a verdict about a system that no longer exists.

    ⚠️ Fails CLOSED. Without these, `is_deleted` and 6 siblings are misreported as
    unreachable, condemning nearly every valid query — a refusal is honest; a confident wrong
    verdict is not.
    """
    api_cols: Set[str] = set()
    if isinstance(payload, dict):
        api_cols = {str(c).lower() for c in (payload.get("system_columns") or [])}
    if api_cols:
        return api_cols, "platform API (torana datalake reachable-columns)"
    raise GroundTruthUnavailable(
        "cannot resolve system columns — the API returned no `system_columns`.\n"
        "       Refusing to check: without them `is_deleted` and 6 siblings are\n"
        "       misreported as unreachable, condemning nearly every valid query.\n"
        "       Fix connectivity (torana auth me)."
    )


# ── Policy-derived columns: DERIVED from the registry, never retyped ─────────
def load_policy_derived_columns(
    profile: str, payload: object = None
) -> Tuple[Dict[str, str], str]:
    """Policy-derived columns. API first, local second, else REFUSE.

    Same precedence and same disagreement rule as `load_system_columns`. The
    server applies the identical STRUCTURAL predicate (`kind=DERIVE` on a
    `scope="tenant"` decoration), so a third such column is covered the day it is
    registered — on both paths, with no edit here.

    ⛔ Fails closed. Without this list, a read of `vulnerability_due_date` in a
    WHERE clause is waved through as ordinary and reachable — and it silently
    applies whatever policy was in force when the decoration last ran instead of
    the tenant's current policy. A stale-policy answer is REAL, POPULATED and
    still wrong, which is exactly the class of defect this gate exists to catch.
    """
    api_map: Dict[str, str] = {}
    if isinstance(payload, dict):
        for row in (payload.get("policy_derived") or []):
            col = str(row.get("column", "")).lower()
            if col:
                api_map[col] = row.get("why") or (
                    f"written by the '{row.get('decoration')}' decoration "
                    f"(kind={row.get('kind')}) — it IS the tenant's policy already "
                    f"materialised"
                )

    # ⛔ THE LOCAL IMPORT WAS DELETED (§ 3.13.5). It re-derived this list from a checkout's
    # `DECORATIONS`, which made a second authority for a fact the API serves in the SAME
    # payload. The server applies the identical structural predicate (`kind=DERIVE` on a
    # `scope="tenant"` decoration), so the local copy could only ever agree or be stale — and
    # the old code printed a DISAGREEMENT warning because it expected the latter.
    if api_map:
        return api_map, "platform API (torana datalake reachable-columns)"
    raise GroundTruthUnavailable(
        "cannot resolve policy-derived columns — the API returned no `policy_derived`.\n"
        "       Refusing to check: without them a stale-policy read in a WHERE\n"
        "       clause is waved through as ordinary — a real, populated, WRONG\n"
        "       answer that nothing else in this gate detects."
    )


# ── Declared-writer dependencies: a SECOND AXIS, never a verdict change ──────
def load_declared_dependencies(payload: object = None) -> Tuple[Dict[Tuple[str, str], dict], str]:
    """Columns that fill ONLY when an external actor calls an API.

    ⚠️ NOT A VERDICT INPUT. A `declared` column IS reachable and a question that
    touches it IS answerable — this changes nothing about `clean`, and folding it
    in would break the exact property that made the underlying fix work: a column
    became answerable the moment it was registered, with no edit to this gate.

    What it adds is the second question a reader needs. Seven of the eight writer
    mechanisms fill themselves (a mapping fills when an integration syncs, an
    operator when ETL runs); `declared` fills only when someone acts. So:

        answerable-and-self-filling      vs   answerable-but-depends-on-a-caller

    Measured, and the reason this exists: registering six human-triage columns
    moved the reachable count 389 -> 395 and flipped two corpus questions from
    refused to CLEAN, with `count(is_confirmed)` = 0 of 6,179 rows and NO caller in
    existence. Q-047 now passes the gate and returns zero rows; a dashboard renders
    an empty panel and a reader concludes "there are no lingering mitigations" when
    the truth is "nobody has recorded one". Opposite conclusions.

    ⚠️ API-ONLY, and deliberately DEGRADES rather than refusing. Unlike system
    columns and policy-derived columns, an absent answer here cannot produce a
    WRONG verdict — it can only omit an advisory note, because `clean` does not
    consult it. Refusing the whole check over a missing advisory would be strictly
    worse than reporting one less thing. Returns ({} , "unavailable") in that case,
    and every consumer says so rather than implying "no dependencies".

    Returns ({(table, column): row}, provenance).
    """
    if not isinstance(payload, dict):
        return {}, "unavailable"
    rows = payload.get("declared_dependencies")
    if rows is None:
        # An older platform that does not serve the key. Distinguished from an
        # empty list, which is a real answer ("nothing depends on a caller").
        return {}, "unavailable (platform does not serve declared_dependencies)"
    out: Dict[Tuple[str, str], dict] = {}
    for row in rows or []:
        t = str(row.get("table", "")).lower()
        c = str(row.get("column", "")).lower()
        if t and c:
            out[(t, c)] = row
    return out, "platform API (torana datalake reachable-columns)"


#: What an EMPTY result means, worst-first. The ORDER IS THE SEMANTICS: a row is
#: labelled by the WEAKEST fill guarantee any column it reads carries, because a
#: single unfillable column empties the whole result regardless of how well the
#: others fill.
#:
#: ⚠️ Derived from the caller's `status`, NOT from `has_caller`. That distinction
#: is the entire content of this row. `has_caller` is `ExpectedCaller.exists()`,
#: which the seam documents as answering "can this fill AT ALL?" — and which
#: explicitly refuses the question asked here: *"Will it fill unattended?" is a
#: different question — ask `status`* (write_seam.py, `exists()`). Measured
#: 2026-08-10: every declared column in the corpus now has a caller, so
#: `has_caller` is TRUE for all 47 caller-dependent CLEAN rows and separates
#: nothing. The bridges being built is what silently blinded the old reduction.
FILL_MODES: Tuple[str, ...] = ("none", "manual", "wired", "self_filling")

#: The reader-facing consequence of each mode. Carried in the payload rather than
#: left for each consumer to re-derive: three consumers already print this
#: distinction and prose retyped three times drifts three ways.
FILL_MODE_MEANING: Dict[str, str] = {
    "self_filling": "a real answer — the pipeline fills this unattended, so empty means "
                    "there is genuinely nothing",
    "wired": "an automated caller exists — empty means 'not exercised yet'",
    "manual": "⚠️ fills ONLY when a person acts — empty means 'NOBODY HAS RECORDED ONE', "
              "NOT 'this does not happen'",
    "none": "⛔ no caller exists — permanently empty until someone builds one",
}


def _fill_mode(declared_deps: List[dict]) -> str:
    """Reduce a row's declared dependencies to what an EMPTY RESULT would mean.

    ⛔ NOT A VERDICT INPUT, and never becomes one — see the C3 note on
    `declared_dependencies`. This is the SECOND AXIS finally saying something a
    reader can act on. The verdict answers *"is the SQL right?"*; this answers
    *"if it returns nothing, is that an answer or a silence?"* Those are
    orthogonal, which is why this is a sibling field and not a ladder rung: a
    `CLEAN_PENDING_CALLER` verdict would rank a legitimate, correct question as
    worse-than-clean, and would mean registering a caller could change a verdict.

    ⚠️ THE TWO QUANTIFIERS ARE OPPOSITE, and getting either backwards is a real
    bug that this docstring exists to prevent:

      - WITHIN one column, callers are ALTERNATIVES -> take the BEST. Two writers
        may declare the same column and "if ONE of them is wired the column can
        fill, so it is not dead" (`write_seam.columns_without_caller`). Taking
        the worst here would cry wolf on a column a robot already fills, and a
        checker that cries wolf gets waived.
      - ACROSS columns, dependencies are CONJUNCTIVE -> take the WORST. A query
        joining nine self-filling columns and one `manual` column returns nothing
        until a human acts, so the row is `manual`. Taking the best across
        columns would report the row by its healthiest column and hide exactly
        the dependency this exists to surface.

    ⚠️ A dependency whose callers list is EMPTY reduces to `none`, not to
    `self_filling`. Absent evidence is not evidence of self-filling — the same
    fail-closed rule the writer-resolution code applies at :949.
    """
    if not declared_deps:
        return "self_filling"
    worst = len(FILL_MODES) - 1
    for d in declared_deps:
        statuses = [str((c or {}).get("status", "")).strip().lower()
                    for c in (d.get("callers") or [])]
        # ⛔ FAIL CLOSED on the STATUS VALUE. No caller record, or a status this
        # gate does not know, ranks as `none` — the loudest state. A NEW status
        # appearing in the seam's closed vocabulary must be classified
        # deliberately here; guessing "probably fine" is the optimistic
        # direction and therefore the wrong one to default to. Note this is
        # fail-closed per CALLER, and the max() below still lets a sibling
        # `wired` caller win — which is correct, not a leak: the column really
        # can fill.
        ranks = [FILL_MODES.index(s) if s in FILL_MODES else 0 for s in statuses]
        best_for_column = max(ranks) if ranks else 0
        worst = min(worst, best_for_column)
    return FILL_MODES[worst]


# ── Writers for EVERY column: the supply record, also a SECOND AXIS ─────────
#: Writer kinds that fill THEMSELVES. Seven of the eight mechanisms need no
#: actor: a `mapping` fills when an integration syncs, an `operator` when ETL
#: runs, a `system` field on any insert. Only `declared` waits for someone to
#: call the endpoint — which is the entire reason this distinction exists.
#: ⚠️ A POSITIVE membership set, deliberately, mirroring LOAD_BEARING_ANCESTORS:
#: "everything except declared" would silently classify a NEW ninth mechanism as
#: self-filling on the day it appears, which is the optimistic direction and
#: therefore the wrong one to guess in.
SELF_FILLING_WRITER_KINDS: Set[str] = {
    "mapping", "operator", "ingestor", "extractor", "system", "decoration",
}


def load_column_writers(payload: object = None) -> Tuple[Dict[Tuple[str, str], List[dict]], str]:
    """Every column's writer records, keyed by (table, column).

    ⚠️ PLUMBING, NOT A NEW SOURCE OF TRUTH. The API already returns this for
    every column and the gate already makes the call; it simply threw the
    `writers` array away for everything except `declared` columns. Measured on
    Q-026: 25 column references checked, 6 carrying provenance, 19 — every
    mapping-written column, i.e. almost all real data — carrying none.

    ⛔ NOT A VERDICT INPUT, for the same reason `load_declared_dependencies` is
    not (C3). A column's writer list says WHAT FILLS IT, never whether the
    question is answerable. Folding it into `clean` would mean registering a
    writer could make a passing query newly fail — destroying the property that
    made the write seam work.

    ⚠️ DEGRADES rather than refusing, like the declared-dependency map and
    unlike system/policy-derived columns: it cannot make a verdict wrong, so an
    older platform that does not serve `writers` loses provenance rather than
    the whole check. The provenance string is what distinguishes "served, and
    every column has a writer" from "not served at all" — an empty map means
    very different things in those two worlds, and a consumer must be able to
    tell them apart before reading `unresolved_writers` as signal.

    Returns ({(table, column): [writer, ...]}, provenance).
    """
    if not isinstance(payload, dict):
        return {}, "unavailable"
    rows = payload.get("columns")
    if rows is None:
        return {}, "unavailable (platform does not serve columns)"
    out: Dict[Tuple[str, str], List[dict]] = {}
    served = False
    for row in rows or []:
        t = str(row.get("table", "")).lower()
        c = str(row.get("column", "")).lower()
        if not (t and c):
            continue
        # ⚠️ `writers` ABSENT and `writers: []` are different facts, and only the
        # first is a platform-capability answer. An absent key across the whole
        # response means `--explain` was not honoured; an empty list on one row
        # is a real (and today unmeasured — 0 of 397) finding about that column.
        if "writers" in row:
            served = True
        out[(t, c)] = list(row.get("writers") or [])
    if not served:
        # Every row lacked the key: the platform served columns but no writer
        # provenance. Say so rather than reporting 397 columns with no writer,
        # which would read as a catastrophic supply failure that is not real.
        return {}, "unavailable (platform served no per-column writers; needs --explain)"
    return out, "platform API (torana datalake reachable-columns --explain)"


#: Populated by `main()` once ground truth is established. Module-level so the
#: checking functions read them without threading state through every call.
#: ⚠️ EMPTY IS NEVER A VALID STATE HERE — `main()` refuses before it gets this
#: far, precisely so an empty set can never be mistaken for "nothing applies".
SYSTEM_COLUMNS: Set[str] = set()
SYSTEM_PROVENANCE: str = "NOT LOADED"
POLICY_DERIVED_COLUMNS: Dict[str, str] = {}
POLICY_DERIVED_PROVENANCE: str = "NOT LOADED"
#: ⚠️ Empty IS a valid state here, unlike the two above — it means either "nothing
#: depends on a caller" or "the platform did not serve the key". The provenance
#: string is what distinguishes them, so consumers must read both.
DECLARED_DEPENDENCIES: Dict[Tuple[str, str], dict] = {}
DECLARED_DEPENDENCIES_PROVENANCE: str = "NOT LOADED"
#: ⚠️ Same caveat as above: empty is valid and AMBIGUOUS on its own. Read the
#: provenance string with it — "unavailable (…)" means the platform did not
#: serve writers, which is NOT the same as "no column has a writer".
WRITERS_BY_COLUMN: Dict[Tuple[str, str], List[dict]] = {}
WRITERS_PROVENANCE: str = "NOT LOADED"


#: The vocabulary key that should replace a policy-derived column read, plus the
#: anchor form. Keyed by column so a newly-registered column can be added here
#: without touching the detector; an unmapped column still reports, with generic
#: guidance, so a new column is never silently un-checked.
_POLICY_DERIVED_REPLACEMENT: Dict[str, Tuple[str, str]] = {
    "vulnerability_due_date": (
        "sla_window_by_severity",
        "{row}.scan_first_detected_date "
        "+ ({{sla_window_by_severity[{row}.severity]}})::int * INTERVAL '1 day'",
    ),
    "vulnerability_sla_breach_date": (
        "sla_window_by_severity",
        "{row}.scan_first_detected_date "
        "+ ({{sla_window_by_severity[{row}.severity]}})::int * INTERVAL '1 day'",
    ),
}

# Bare identifiers that are never table columns.
_SQL_PSEUDO = {"true", "false", "null", "now", "current_date", "current_timestamp"}


# ── Fetch ────────────────────────────────────────────────────────────────────
def require_profile() -> str:
    """Return `TORANA_PROFILE`, or exit non-zero. NEVER defaults one.

    ⚠️ An unlabelled profile is how a TENANT-scope answer gets read as a
    PLATFORM-scope one. The two answer different questions — "can this customer
    write it" vs "can any shipped integration write it" — and silently
    defaulting either the profile or the scope produces an answer that is
    confidently mislabelled rather than obviously missing. Fail loudly instead.
    """
    profile = os.environ.get("TORANA_PROFILE", "").strip()
    if not profile:
        print(
            "ERROR: TORANA_PROFILE is not set.\n"
            "  This tool refuses to default a profile: an unlabelled profile is how a\n"
            "  tenant-scope answer gets read as a platform-scope one.\n"
            "  Set it explicitly, e.g.:  TORANA_PROFILE=SA <command>",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return profile


def fetch_reachable(scope: str = "platform", profile: str = "") -> Dict[str, Set[str]]:
    """Fetch the reachable (table -> columns) map from the live platform.

    ⚠️ FETCHED, never embedded. `text_to_sql.py` drifted precisely because it
    froze a schema listing into a prompt (it claims 197 asset fields; the live
    table has 145).

    `profile` defaults to whatever `TORANA_PROFILE` says — never to a
    hard-coded identity. Platform scope has been measured as profile-
    independent (SA with 0 integrations and T1 with 6 return byte-identical
    384-column sets), but the label still has to be explicit so the answer
    carries its provenance.

    ⚠️ `--explain` is REQUIRED, not decorative. Without it the API omits the
    per-column `writers` array entirely — the response carries only
    `{table, column, reachable}` — and `WRITERS_BY_COLUMN` below is built from
    nothing, so every checked column lands in `unresolved_writers` and the
    provenance block reports a fabricated crisis. Verified: the two responses
    are otherwise BYTE-IDENTICAL (same 397 columns, same `declared_dependencies`,
    `system_columns`, `policy_derived`, `tables`, `summary`), so the flag is
    purely additive and cannot change any existing verdict.
    """
    profile = profile or require_profile()
    cmd = [
        "torana", "datalake", "reachable-columns",
        "--scope", scope, "--explain", "--format", "json",
    ]
    env = {**os.environ, "TORANA_PROFILE": profile}
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise RuntimeError(
            f"`torana datalake reachable-columns` failed (exit {proc.returncode}).\n"
            f"{proc.stderr.strip()}\n"
            "Bootstrap the CLI via `torana-skill` first."
        )
    payload = json.loads(proc.stdout)
    _LAST_REACHABLE_PAYLOAD.clear()
    _LAST_REACHABLE_PAYLOAD.update(payload if isinstance(payload, dict) else {})
    out: Dict[str, Set[str]] = {}
    for row in payload.get("columns", []):
        if row.get("reachable", True):
            out.setdefault(row["table"], set()).add(row["column"])
    if not out:
        # ⛔ An empty reachable map is NOT "nothing is reachable" — it is a
        # broken fetch. Answering from it would render every column in every
        # query a build defect: the most convincing possible way to be wrong.
        raise GroundTruthUnavailable(
            "the reachable-columns response contained no reachable columns.\n"
            "       Refusing to check: an empty map would condemn every column in\n"
            "       every query as unreachable."
        )
    return out


def submit_catalog_decision(
    *,
    question: str,
    verdict: str,
    entry_id: str = "",
    axis: str = "",
    gap_category: str = "",
    question_id: str = "",
    profile: str = "",
) -> Dict[str, object]:
    """⭐ Send the catalog verdict TO THE PLATFORM, and return what it recorded.

    ⛔ **Why this exists.** Before it, `--catalog-verdict` was recorded into a local JSON
    blob and printed to stdout — and NOTHING ELSE. Measured 2026-08-26: running
    `evidence --catalog-verdict reuse` left the platform's decision count unchanged at 225.
    The skill's verdict never reached the system that ranks catalog demand, so the reuse
    counter read 0 no matter how often a caller actually reused an entry, and every miss
    the skill observed was invisible to curation.

    ⚠️ **VOCABULARY BRIDGE — the two sides genuinely use different words.**
    The skill says ``reuse | miss``; the platform stores ``reused | authored_new``. Same two
    facts, different names, so the mapping is stated here rather than left to coincide:

        skill 'reuse'  -> platform decision 'reused'      (via `catalog search`, a HIT)
        skill 'miss'   -> platform decision 'authored_new' (via `catalog record-miss`)
        skill 'probed' -> not submitted — the caller looked but did not author, so there
                          is no decision to record and inventing one fabricates demand.

    ⚠️ **The two verdicts take DIFFERENT commands, and that asymmetry is real.**
    `record-miss` records only misses; there is no `record-reuse`. A reuse is recorded by
    re-running `catalog search --record-miss`, whose server side writes `decision='reused'`
    when the lookup HITS (routes/vm_catalog.py). So a reuse is submitted by asking the
    catalog the same question again and letting the server observe its own hit.

    ⛔ **A reuse therefore depends on the SERVER also finding a hit.** If the server's recall
    threshold disagrees with the caller's judgement, nothing is recorded — and this function
    REPORTS that rather than claiming success, because a silently-unrecorded reuse is exactly
    the failure this wire exists to end. See `server_agreed` in the return value.

    ⛔ Best-effort by contract, mirroring the platform's own rule: a telemetry failure must
    never fail the authoring path that produced it. Never raises.
    """
    if verdict not in ("reuse", "miss"):
        return {"submitted": False, "reason": f"verdict '{verdict}' is not recordable"}

    profile = profile or require_profile()
    env = {**os.environ, "TORANA_PROFILE": profile}

    if verdict == "miss":
        # ⚠️ Both flags are REQUIRED by the CLI. A miss with no named axis is precisely the
        # "no entry matched" non-answer the catalog contract rejects, so we refuse to
        # fabricate one — the caller must supply it.
        if not axis:
            return {"submitted": False,
                    "reason": "a miss needs --catalog-axis (name the axis, never a bare 'no')"}
        cmd = ["torana", "vm", "transformers", "catalog", "record-miss", question,
               "--gap-category", gap_category or "genuinely_novel",
               "--rationale", axis]
        if question_id:
            cmd += ["--question-id", question_id]
        if entry_id:
            cmd += ["--near-miss", entry_id]
    else:
        # A reuse: re-ask, and let the server record its own hit as decision='reused'.
        cmd = ["torana", "vm", "transformers", "catalog", "search", question,
               "--record-miss"]
        if axis:
            cmd += ["--rationale", axis]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    except Exception as e:  # noqa: BLE001 — telemetry must never break the caller
        return {"submitted": False, "reason": f"transport error: {e}"}
    if proc.returncode != 0:
        return {"submitted": False,
                "reason": f"exit {proc.returncode}: {proc.stderr.strip()[:200]}"}

    out = (proc.stdout or "")
    result: Dict[str, object] = {"submitted": True, "skill_verdict": verdict}
    if verdict == "reuse":
        # ⛔ Do not assume the server agreed. If its lookup cleared nothing, it did NOT
        # record a reuse, and the caller must be told rather than left believing it landed.
        #
        # ⚠️ Anchored on the CLI's two EXACT section headers, not on loose keywords. An
        # earlier version tested `"miss" not in out`, which reported a FALSE disagreement
        # on a reuse that had in fact been recorded — the word appears in unrelated entry
        # prose. A detector that cries wolf on a working path is worse than none, because
        # it trains the reader to ignore it.
        HIT = "CLEARED THE THRESHOLD:"
        NO_HIT = "none cleared the threshold"
        if NO_HIT in out:
            result["server_agreed"] = False
            result["reason"] = (
                "the caller judged REUSE but the server's lookup cleared nothing, so a "
                "reuse was NOT recorded. This is a real disagreement — report it rather "
                "than assuming the reuse landed."
            )
        elif HIT in out:
            result["server_agreed"] = True
        else:
            # ⛔ Neither marker present: the output shape changed. Report UNKNOWN rather
            # than guessing — a confident wrong answer here is the failure mode this whole
            # function exists to remove.
            result["server_agreed"] = None
            result["reason"] = (
                "could not determine whether the server recorded the reuse: neither "
                "expected marker was present in the CLI output. Verify manually."
            )
    return result


#: The most recent raw `reachable-columns` payload. `system_columns` and
#: `policy_derived` ride along on it, so establishing all three ground truths
#: costs ONE round-trip rather than three.
_LAST_REACHABLE_PAYLOAD: Dict[str, object] = {}


# ── Template rendering: bind vocabulary, then resolve dbt refs ──────────────
#
# ⚠️ Templated SQL is the NORM, not the exception. Corpus SQL is authored
# tenant-neutrally — per-tenant policy is expressed as vocabulary placeholders so
# one SQL serves every tenant and is specialised at deployment by substitution.
# A gate that reports PARSE_FAILED on a placeholder therefore checks NOTHING
# exactly when it matters most.
#
# TWO TEMPLATE FAMILIES, TWO OWNERS — this is the thing to understand:
#
#   vocabulary   {{severity_floor}}, {{key.at_or_above}}, {{#toggle k}}…
#                owned by vm_catalog/binder.py :: bind_entry
#   dbt          {{ source('torana','assets') }}, {{ ref('…') }}
#                owned by dbt — bind_entry does NOT touch these
#
# Binding alone leaves dbt refs behind and sqlglot still fails with "Expected
# table name but got L_BRACE". BOTH must be resolved for the round-trip to parse.
# Verified across all 87 shipped catalog entries: 87/87 bind from conservative
# defaults with NO tenant and NO live platform; the only survivors are dbt refs.
#
# ⚠️ `{{vocab:key}}` is NOT a valid form here — that prefix belongs to artifact
# SQL in `torana-vm`. Reaching this gate with one is an ERROR to report, not a
# form to support: it would survive to EXPLAIN and fail there.

_RE_DBT_SOURCE = re.compile(
    r"\{\{\s*source\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)\s*\}\}")
_RE_DBT_REF = re.compile(r"\{\{\s*ref\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\}\}")
_RE_TENANT_ID = re.compile(r"\{\{\s*tenant_id\s*\}\}")
_RE_ANY_PLACEHOLDER = re.compile(r"\{\{.*?\}\}", re.DOTALL)

_SYNTHETIC_TENANT = "00000000-0000-0000-0000-000000000000"


def _render_via_api(sql: str, profile: str) -> dict | None:
    """Render templated SQL through the PLATFORM's binder. None if unavailable.

    ⚠️ THE PREFERRED PATH, and the reason gap 3 is not vendored into this skill.
    `torana vm transformers catalog render` calls the same `bind_entry` that
    materialize calls, so what this gate checks is what the platform would
    actually build. A second binder living in the skill would be a second
    definition of truth: it would drift, and a drifted binder produces SQL that
    binds one way here and another in production — invisible until deployment.
    """
    payload = _torana_json(
        ["vm", "transformers", "catalog", "render", "--sql", sql, "--format", "json"],
        profile,
    )
    if not isinstance(payload, dict) or "rendered_sql" not in payload:
        return None
    return payload


def _load_binder():
    """Import `bind_entry` + the vocabulary snapshot from pantheon-data-transformers.

    OFFLINE FALLBACK ONLY — `_render_via_api` is the preferred path. Returns
    (bind_entry, snapshot_module, provenance). Never fabricates a fallback
    binder: a silently-wrong render is worse than an honest refusal.
    """
    root = os.environ.get("TORANA_ROOT")
    cands = []
    if root:
        cands.append(Path(root) / "pantheon-data-transformers")
    here = Path(__file__).resolve()
    for parent in here.parents:
        c = parent / "pantheon-data-transformers"
        if c.is_dir():
            cands.append(c)
    for c in cands:
        if not c.is_dir():
            continue
        sys.path.insert(0, str(c))
        try:
            from pantheon_transformers.vm_catalog.binder import (  # noqa: E402
                bind_entry as _be,
            )
            from pantheon_transformers.vm_catalog import (  # noqa: E402
                _vocabulary_snapshot as _snap,
            )
            # ⚠️ The binder logs "used conservative defaults for [...]" on every
            # bind, through pantheon_shared's STRUCTLOG logger, which writes to
            # STDOUT. That corrupts `--json`: the payload is preceded by log
            # lines and json.load() fails with "Extra data: line 1 column 5".
            #
            # It is structlog, NOT stdlib logging — `logging.getLogger(name)
            # .setLevel(...)` looks right and silences nothing. Drop the events
            # at structlog's own filter level instead.
            #
            # Nothing is lost: `defaulted_keys` is in the result payload, which
            # is the parseable place for it.
            try:
                import structlog  # noqa: E402
                import logging  # noqa: E402
                structlog.configure(
                    wrapper_class=structlog.make_filtering_bound_logger(
                        logging.WARNING
                    ),
                )
            except Exception:
                pass  # never let log hygiene break the import
            return _be, _snap, f"imported from {c}"
        except Exception:
            continue
    return None, None, "UNAVAILABLE"


BIND_ENTRY, VOCAB_SNAPSHOT, BINDER_PROVENANCE = _load_binder()

#: Set by `main()`. When set, `render_sql` binds through the platform API rather
#: than a local import — the portable path.
_RENDER_PROFILE: str = ""
BINDER_SOURCE: str = "none"


def set_render_profile(profile: str) -> None:
    global _RENDER_PROFILE
    _RENDER_PROFILE = profile or ""


def probe_binder(profile: str) -> str:
    """Establish HOW templates will be bound, or REFUSE. Returns the provenance.

    ⛔ Fails closed. With no binder, every templated query becomes
    `UNRESOLVED_PLACEHOLDER` — and templated SQL is the NORM here, not the
    exception: per-tenant policy is authored as placeholders so one SQL serves
    every tenant. A gate that reports "cannot check" on the normal case checks
    nothing exactly when it matters most. Measured on the 8 regenerated cases: 6
    of 8 failed this way on a machine with no checkout.
    """
    global BINDER_SOURCE
    probe = _render_via_api("SELECT 1", profile)
    if probe is not None:
        set_render_profile(profile)
        BINDER_SOURCE = "platform API (torana vm transformers catalog render)"
        return BINDER_SOURCE
    if BIND_ENTRY is not None and VOCAB_SNAPSHOT is not None:
        BINDER_SOURCE = f"local import — {BINDER_PROVENANCE}"
        return BINDER_SOURCE
    raise GroundTruthUnavailable(
        "cannot resolve a template binder (API render unavailable, and no local "
        "pantheon-data-transformers).\n"
        "       Refusing to check: templated SQL is the NORM, so without a binder\n"
        "       every real query is reported UNRESOLVED_PLACEHOLDER and nothing is\n"
        "       actually verified.\n"
        "       Fix connectivity (torana auth me) or set TORANA_ROOT."
    )


class _AdHocEntry:
    """Minimal duck-typed CatalogEntry so raw corpus SQL can use the real binder.

    `bind_entry` needs only `sql_template` + `vocabulary_keys`. Declaring EVERY
    known key (rather than guessing which the SQL uses) is deliberate: an
    undeclared key is left unbound and would then be misreported as an unresolved
    placeholder — a false finding produced by the checker itself.
    """

    #: Attributes `bind_entry` reads: `id`, `sql_template`, `vocabulary_keys`
    #: (verified by grepping `entry.` in binder.py — a missing one surfaces as an
    #: AttributeError swallowed into `bind_error`, i.e. a silently unbound row).
    def __init__(self, sql: str, keys):
        self.id = "adhoc:reachability_gate"
        self.sql_template = sql
        self.vocabulary_keys = list(keys)
        self.key = "adhoc"


def render_sql(sql: str, *, tenant_id: str = _SYNTHETIC_TENANT) -> dict:
    """Render templated SQL to parseable SQL. Returns a dict, never raises.

        {rendered, bound, defaulted_keys, used_keys, unresolved, bind_error}

    `unresolved` is any `{{…}}` still standing after both families are resolved.
    It is reported SEPARATELY from a parse error because the cause and the fix
    are different: an unknown key / a `vocab:` prefix / a malformed block is an
    authoring defect, whereas a parse error is a SQL defect.
    """
    out = {"rendered": sql, "bound": False, "defaulted_keys": [],
           "used_keys": [], "unresolved": [], "bind_error": None}
    if not _RE_ANY_PLACEHOLDER.search(sql or ""):
        return out                      # untemplated — nothing to do

    text = sql
    # 1. Vocabulary family — via the platform's OWN binder and its conservative
    #    defaults. We are not choosing values; we are using declared fallbacks.
    #
    # ⚠️ API FIRST. Both branches call the SAME `bind_entry`; the API branch just
    # calls it where it lives instead of needing a checkout. Preferring the API
    # also means the bind matches the platform this SQL will run against.
    api_res = _render_via_api(sql, _RENDER_PROFILE) if _RENDER_PROFILE else None
    if api_res is not None:
        text = api_res.get("rendered_sql", sql)
        out["bound"] = True
        out["used_keys"] = sorted(api_res.get("used_keys") or [])
        out["defaulted_keys"] = sorted(
            set(api_res.get("defaulted_keys") or []) & set(out["used_keys"]))
    elif BIND_ENTRY is not None and VOCAB_SNAPSHOT is not None:
        keys = list(VOCAB_SNAPSHOT.VOCABULARY_KEYS)
        out["used_keys"] = sorted(
            k for k in keys
            if re.search(r"\{\{#?\w*\s*" + re.escape(k) + r"[\s.\[}]", text)
        )
        try:
            res = BIND_ENTRY(_AdHocEntry(text, keys), vocabulary={},
                             tenant_id=tenant_id)
            text = res.sql
            out["bound"] = True
            # Only report defaults for keys this SQL actually uses — the ad-hoc
            # entry declares all 48, so the raw list would be meaningless noise.
            out["defaulted_keys"] = sorted(
                set(getattr(res, "defaulted_keys", []) or []) & set(out["used_keys"]))
        except ValueError as exc:
            # NOT_APPLICABLE_KEYS and friends: a finding, never a crash. One bad
            # entry must not abort a 93-row corpus run.
            out["bind_error"] = str(exc)
        except Exception as exc:                     # noqa: BLE001
            out["bind_error"] = f"{type(exc).__name__}: {exc}"

    # 2. dbt family — a different owner. `source('torana','assets')` is just the
    #    bare table name to a reachability check; `ref('m')` is a model name,
    #    which is NOT a datalake table and resolves to a non-sink relation.
    text = _RE_DBT_SOURCE.sub(lambda m: m.group(1), text)
    text = _RE_DBT_REF.sub(lambda m: m.group(1), text)
    # 3. Routing value — bound separately, never from vocabulary.
    text = _RE_TENANT_ID.sub(f"'{tenant_id}'", text)

    out["rendered"] = text
    out["unresolved"] = sorted(set(_RE_ANY_PLACEHOLDER.findall(text)))
    return out


# ── Check ────────────────────────────────────────────────────────────────────
def _alias_map(tree: exp.Expression) -> Dict[str, str]:
    """alias -> real table name, including CTE names mapped to themselves."""
    aliases: Dict[str, str] = {}
    for tbl in tree.find_all(exp.Table):
        # A function-table (`GENERATE_SERIES(...) gs`) is not a datalake table;
        # mapping its alias to a "table name" would send its columns to lookup.
        if not isinstance(tbl.this, exp.Identifier):
            continue
        name = tbl.name
        if not name:
            continue
        aliases[name.lower()] = name.lower()
        alias = tbl.alias
        if alias:
            aliases[alias.lower()] = name.lower()
    return aliases


def _cte_names(tree: exp.Expression) -> Set[str]:
    """Names that are NOT datalake tables and whose columns must not be checked.

    Three sources, all seen in the real corpus:
      - CTEs (`WITH x AS (...)`)
      - derived tables — an aliased subquery (`LEFT JOIN (SELECT ...) v`).
        Q-025 is a KNOWN-CLEAN row that joins a subquery aliased `v`; without
        this the gate reports `v.open_findings` as an unknown table.
      - function tables — `GENERATE_SERIES(...) gs` (Q-094, also known-clean).
    """
    names = set()
    for cte in tree.find_all(exp.CTE):
        if cte.alias:
            names.add(cte.alias.lower())
    for sub in tree.find_all(exp.Subquery):
        if sub.alias:
            names.add(sub.alias.lower())
    # A table whose `this` is not a plain Identifier is a function-table
    # (GENERATE_SERIES(...), UNNEST(...), ...). Structural test, not a type
    # allow-list: sqlglot models these under many classes
    # (ExplodingGenerateSeries, Anonymous, ...) and a name-based check rots.
    for tbl in tree.find_all(exp.Table):
        if isinstance(tbl.this, exp.Identifier):
            continue
        if tbl.alias:
            names.add(tbl.alias.lower())
        # The alias may not hang off the Table node; collect any bare
        # identifiers the function introduces so they are not checked.
        for ident in tbl.find_all(exp.Identifier):
            names.add(ident.name.lower())
    return names


def _writer_label(w: dict) -> str:
    """One writer, rendered as the string a reader can act on.

    `source` alone is ambiguous across the eight mechanisms (a mapping's source
    is a YAML path, a declared writer's is a `module.py::function`), so the
    `detail` is appended when it is short enough to be a label rather than a
    paragraph. ⚠️ RESOLVED, never composed from reasoning (C1): every part comes
    off the API record.
    """
    src = str(w.get("source") or "").strip()
    detail = str(w.get("detail") or "").strip()
    if src and detail and len(detail) <= 80:
        return f"{src} [{detail}]"
    return src or detail or str(w.get("kind") or "?")


#: ⛔ THE LOAD-BEARING RULE (spec § 3.6.1). A column reference is load-bearing
#: when removing it would change WHICH ROWS are returned or how they are
#: classified. Walk the reference's ancestors outward; it is load-bearing if any
#: ancestor is a member of this set.
#:
#: ⛔ POSITIVE MEMBERSHIP TEST, deliberately — never "everything except ORDER BY".
#: An exclusion list breaks silently the day sqlglot grows a node type; a
#: membership test cannot. A bare `ORDER BY t.x` reaches `Select` without
#: touching any member and returns False naturally, so no ORDER BY exclusion is
#: needed and adding one would be a bug.
#:
#: ⚠️ `exp.Func` subsumes several members in practice (`exp.If` — what a CASE
#: arm parses to — is a Func, so it matches before `exp.Case` is reached). The
#: redundancy is kept because the SET is the specification: dropping `Case`
#: because `Func` happens to catch today's parse shape would make the rule
#: depend on sqlglot's class hierarchy staying put.
LOAD_BEARING_ANCESTORS = (
    exp.Where, exp.Join, exp.Having, exp.Qualify,   # filters
    exp.Group, exp.Window,                          # grain (GROUP BY / PARTITION BY)
    exp.Case, exp.Filter, exp.Func,                 # computes a value acted upon
)


def _is_load_bearing(node: exp.Expression) -> bool:
    """§ 3.6.1 — is THIS reference load-bearing? Computed from the parse tree.

    ⚠️ Deliberately NOT derived from `_clause_of`. The two answer different
    questions and disagree on a real case: a column inside a CASE in the ORDER
    BY reports clause `ORDER BY` (correct — that IS where it sits) but is
    load-bearing `True`, because the CASE computes a value the reader acts on.
    § 3.6.2 is explicit that `clause` says SELECT for both a bare projection and
    a CASE in the select list, and treating those alike is what produced the
    § 1.3 error. So the rule reads the tree itself.

    ⚠️ SUBQUERIES: the walk does NOT stop at the enclosing SELECT, it continues
    to the root. A column inside a subquery in a WHERE clause IS load-bearing
    for the outer query; stopping at the boundary would report it as a harmless
    projection.
    """
    cur = node.parent
    while cur is not None:
        if isinstance(cur, LOAD_BEARING_ANCESTORS):
            return True
        cur = cur.parent
    return False


def _column_provenance(table: str, column: str, clause: str) -> dict:
    """The supply record for ONE checked column reference. Resolve only (C1).

    ⛔ This NEVER feeds `clean`. See the C3 note at the `declared_dependencies`
    key — provenance is a second axis, and a column becoming better-documented
    must not be able to fail a query that passes today.
    """
    writers = WRITERS_BY_COLUMN.get((table, column)) or []
    kinds = sorted({str(w.get("kind") or "") for w in writers if w.get("kind")})
    integrations = sorted({str(w.get("integration") or "")
                           for w in writers if w.get("integration")})

    # ⛔ THE REDUCTION RULE (spec § 3.3), and the two halves are NOT symmetrical:
    #   self_filling = ANY writer kind fills itself
    #   caller_only  = ALL writers are `declared`   ← the strict case
    # A column may carry both a mapping and a declared writer (`cve_id` has 7
    # writers) — the seam deliberately allows this, because that IS the triage
    # design. Such a column is self-filling and must NOT be described to a user
    # as "fills only when <caller> runs": a sync also fills it, and that
    # sentence would send them to configure something that was never broken.
    self_filling = any(w.get("kind") in SELF_FILLING_WRITER_KINDS for w in writers)
    caller_only = bool(writers) and all(w.get("kind") == "declared" for w in writers)

    # ⚠️ The caller/bridge half is READ OFF THE WRITER RECORDS FIRST — they carry
    # `expected_caller` and `bridge_id` directly, so the record is self-contained
    # and needs no second lookup. Verified on live data: for every declared
    # column, the writers' `bridge_id`s and `declared_dependencies.bridge_ids`
    # AGREE, so preferring one cannot change the answer — it only removes a
    # dependency on a second map being loaded.
    #
    # The declared-dependency map is the FALLBACK, which matters because it is
    # the richer reduction (it resolves `has_caller` across all of a column's
    # writers) and because a platform may serve it without `--explain`.
    dep = DECLARED_DEPENDENCIES.get((table, column)) or {}
    callers = [w["expected_caller"] for w in writers
               if isinstance(w.get("expected_caller"), dict)]
    bridges = sorted({str(w["bridge_id"]) for w in writers if w.get("bridge_id")})
    return {
        "table": table,
        "column": column,
        "clause": clause,
        # ⚠️ Seeded False and OR-reduced across every reference by the caller
        # (§ 3.6.2): the answer is per-QUERY, not per-reference. Verified on the
        # corpus — `vm_scan_enabled` (Q-058), `sprint` (Q-006) and
        # `remediation_priority` (Q-088) each appear BOTH as a bare projection
        # and inside a CASE. Classifying per reference yields [false, true] for
        # one column and invites a reader to act on the `false`, which is
        # precisely the § 1.3 error — the bare projection was the one noticed.
        "load_bearing": False,
        "writer_kinds": kinds,
        "integrations": integrations,
        "writers": [_writer_label(w) for w in writers],
        "self_filling": self_filling,
        "caller_only": caller_only,
        "callers": callers or dep.get("callers") or [],
        "bridge_ids": bridges or dep.get("bridge_ids") or [],
    }


#: Bumped on any BREAKING field change to `sql_provenance`. It exists because
#: THREE sibling keys share the word "provenance" and mean different things
#: (`provenance` = where the SCRIPT got its inputs;
#: `declared_dependencies_provenance` = where the declared-writer list came from;
#: `sql_provenance` = this per-column supply record). A consumer reading the
#: wrong one gets a confidently wrong answer, so the block says what it is.
SQL_PROVENANCE_SCHEMA_VERSION = 1


def _build_sql_provenance(
    provenance_cols: Dict[Tuple[str, str], dict],
    unreachable: List[dict],
) -> dict:
    """Assemble the `sql_provenance` block from the per-column records.

    ⛔ ADDITIVE ONLY (C4). This block is read by consumers; it is never read by
    `clean`. Nothing in here may change a verdict — see C3.

    ⚠️ `load_bearing` is now COMPUTED (P2, § 3.6.1) from the parse tree and
    OR-reduced per query. `execution` remains deliberately ABSENT, not stubbed:
    it belongs to P3, and a consumer can tell "not attempted" from "attempted
    and failed" only if the key is missing rather than falsified. Emitting a
    field before the rule that computes it exists would be a fabricated answer —
    the exact C1 violation this design forbids.
    """
    cols = [provenance_cols[k] for k in sorted(provenance_cols)]

    # ⛔ FAIL CLOSED (§ 3.5). A checked column that resolves to NO writer is
    # either a bug in the map or a column outside the sink tables — it is NOT
    # evidence of self-filling, and emitting a bare `writers: []` as though it
    # meant one would launder a gap into a clean answer. Measured today this
    # list is empty (0 of 397), so a non-empty one is real signal.
    unresolved = [
        {"table": c["table"], "column": c["column"], "clause": c["clause"]}
        for c in cols if not c["writers"]
    ]

    unreachable_keys = {(u.get("table", ""), str(u.get("column", "")).lower())
                        for u in unreachable}

    # ⚠️ THE PARTITION (§ 3.3.1): self_filling + caller_dependent == columns.
    # `caller_dependent` is `caller_only` (ALL writers declared), NOT "has at
    # least one declared writer" — the loose reading double-counts every column
    # carrying both a mapping and a declared writer and breaks the identity.
    # ⚠️ A column with NO writers is in neither bucket, which is exactly why
    # `unresolved_writers` is reported separately rather than absorbed into one.
    n_self = sum(1 for c in cols if c["self_filling"])
    n_caller = sum(1 for c in cols if c["caller_only"])
    no_caller = sum(
        1 for c in cols
        if c["caller_only"] and not any(
            (cl or {}).get("status") != "none" for cl in c["callers"])
    )

    return {
        "schema_version": SQL_PROVENANCE_SCHEMA_VERSION,
        "resolved_at": _utc_now(),
        "reachable_column_count": len(WRITERS_BY_COLUMN),
        "writers_provenance": WRITERS_PROVENANCE,
        "columns": cols,
        "unresolved_writers": unresolved,
        "summary": {
            "columns": len(cols),
            "self_filling": n_self,
            "caller_dependent": n_caller,
            "no_caller": no_caller,
            "unresolved_writers": len(unresolved),
            # Retained alongside the finished number below: it is the
            # denominator that says how many unreachable columns were seen at
            # all, which is what makes `load_bearing_unreachable` readable as a
            # proportion rather than a bare count.
            "unreachable_with_provenance": sum(
                1 for c in cols
                if (c["table"], c["column"]) in unreachable_keys),
            # ⛔ § 3.3.1: columns that are BOTH unreachable AND load-bearing —
            # "arguably the block's most important number". Non-zero means the
            # query COMPUTES AN ANSWER from a column nothing writes: not a
            # missing display field, but a filter or a CASE arm that silently
            # changes which rows come back. That is the § 1.3 hazard stated as a
            # number, and it is the pair that a clause label alone cannot see.
            "load_bearing_unreachable": sum(
                1 for c in cols
                if c["load_bearing"]
                and (c["table"], c["column"]) in unreachable_keys),
        },
    }


#: ⛔ § 3.7 row cap. A corpus query without a LIMIT would otherwise pull an
#: arbitrary result set only to learn `row_count`. At the cap we record
#: `row_count_gte` instead of `row_count`, because the exact number is unknown
#: and reporting the cap as though it were the count would be a fabrication.
EXECUTION_ROW_CAP = 100


def _strip_leading_comments(sql: str) -> str:
    """Drop leading `--` / block comments so the read-only guard sees SELECT|WITH.

    ⛔ NOT COSMETIC — without it this phase reports 41 of 49 corpus queries as
    broken when every one of them runs. MEASURED 2026-08-06.

    The platform's read-only guard decides "is this a SELECT?" by looking at the
    statement's FIRST TOKEN, so a leading comment makes it refuse:

        $ torana datalake query-execute --sql-query "-- a comment
                                                     SELECT 1"
        ERROR: HTTP 400  Only SELECT queries are allowed for security reasons

    ⚠️ Nearly every regenerated corpus row opens with a `-- REGENERATED …`
    provenance header, so the naive call attributes a GUARD LIMITATION to the
    SQL. That is the § 1.1 error running backwards — reporting a working query
    as broken — and it would have made this phase's own evidence worthless:
    42 failures of which 41 were the harness, not the queries.

    ⛔ Strips only what precedes the first statement token. Comments INSIDE the
    query are left untouched: they are the author's, they are harmless to the
    guard, and rewriting a user's SQL beyond the minimum needed to run it would
    mean the evidence no longer describes the text they wrote.
    """
    out = sql.lstrip()
    while True:
        if out.startswith("--"):
            nl = out.find("\n")
            if nl == -1:
                return ""
            out = out[nl + 1:].lstrip()
            continue
        if out.startswith("/*"):
            end = out.find("*/")
            if end == -1:
                return ""
            out = out[end + 2:].lstrip()
            continue
        return out


def execute_sql(sql: str, profile: str) -> dict:
    """§ 3.7 — run the RENDERED SQL and record what happened. Evidence, not verdict.

    ⛔ THE DISTINCTION THIS FUNCTION EXISTS TO PRESERVE:

        ok: false                → a REAL defect. The SQL does not run. This is
                                   what § 1.1 missed: a CLEAN verdict is not an
                                   executable query.
        ok: true, row_count: 0   → ⚠️ NOT a defect on its own. A query can be
                                   perfectly correct and return nothing because
                                   a caller has not run yet (Q-050 does exactly
                                   this). Cross-reference `summary.caller_dependent`.
        attempted: false         → the author skipped it. Allowed, and visible.

    ⚠️ `ok` IS DERIVED FROM THE PAYLOAD, NEVER THE EXIT CODE. Measured
    2026-08-06: `torana datalake query` prints `ERROR: API error (HTTP 500) /
    Query failed: column "sev" does not exist` on stderr and still **exits 0**.
    Trusting the exit code would report a broken query as `ok: true` — the
    single failure this phase exists to catch, reported as a success.

    ⚠️ `profile` is recorded because row counts are only meaningful with respect
    to ONE tenant's data and vocabulary binding: templated SQL cannot execute
    unbound, so the profile's tenant is what bound the policy literals.
    """
    sql = _strip_leading_comments(sql)
    env = {**os.environ, "TORANA_PROFILE": profile}
    # ⚠️ `query-execute`, NOT `query`. Measured 2026-08-06: `torana datalake
    # query` IGNORES --limit and says so on stdout ("has no server-side limit;
    # ... Ignoring --limit"), which would defeat the § 3.7 row cap entirely and
    # pull an arbitrary result set. `query-execute` enforces the cap
    # server-side AND returns `total_rows`, so `row_count` below is the TRUE
    # count rather than a capped guess.
    args = ["torana", "datalake", "query-execute", "--sql-query", sql,
            "--limit", str(EXECUTION_ROW_CAP), "--format", "json"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              env=env, timeout=180)
    except Exception as e:  # timeout, missing binary, ...
        return {"attempted": True, "ok": False, "error": f"{type(e).__name__}: {e}",
                "profile": profile}

    out = (proc.stdout or "").strip()
    try:
        payload = json.loads(out) if out else None
    except Exception:
        payload = None

    # A parseable payload carrying a `data` list and no `error` is the ONLY
    # evidence of success. ⚠️ `error` is checked explicitly because the endpoint
    # carries a null `error` key on success — an absent-vs-null distinction that
    # a truthiness test on `data` alone would miss.
    if isinstance(payload, dict) and isinstance(payload.get("data"), list) \
            and not payload.get("error"):
        res = {"attempted": True, "ok": True, "error": None, "profile": profile}
        total = payload.get("total_rows")
        if isinstance(total, int):
            # The server counted the FULL result set before applying the cap, so
            # this is the real number even when `data` was truncated.
            res["row_count"] = total
            if payload.get("limited"):
                res["rows_returned"] = len(payload["data"])
                res["row_cap"] = EXECUTION_ROW_CAP
        elif len(payload["data"]) >= EXECUTION_ROW_CAP:
            # ⛔ No total served and we hit the cap: the true count is UNKNOWN.
            # Reporting `row_count: 100` would assert a number we did not
            # measure, so say only what was proven.
            res["row_count_gte"] = EXECUTION_ROW_CAP
        else:
            res["row_count"] = len(payload["data"])
        return res

    err = (payload or {}).get("error") if isinstance(payload, dict) else None
    err = err or (proc.stderr or "").strip() or out or "no output"
    return {"attempted": True, "ok": False,
            "error": " ".join(str(err).split())[:400], "profile": profile}


def _attach_execution(result: dict, profile: str) -> dict:
    """Run the check's RENDERED SQL and attach the evidence, in place.

    ⛔ Runs the RENDERED text, never the template. Templated SQL cannot execute
    unbound — that is precisely why `execution.profile` is recorded (§ 3.7): the
    row count is only meaningful against the tenant whose vocabulary bound the
    policy literals.

    ⛔ NEVER CHANGES THE VERDICT. `clean` is not read here and not written here.
    Execution is a second axis exactly like provenance (C3): a query that runs
    is not thereby reachable, and a query that returns nothing is not thereby
    broken.

    When nothing parsed there is no SQL to run, so `attempted: false` is
    recorded rather than a fabricated failure — "the author skipped it" and
    "it does not run" are different facts and must stay distinguishable.
    """
    sp = result.get("sql_provenance")
    if not isinstance(sp, dict):
        return result
    sql = result.get("rendered") or result.get("template")
    if not result.get("parsed") or not sql:
        sp["execution"] = {
            "attempted": False,
            "skipped_because": "nothing parsed — there is no SQL to run",
        }
        return result
    sp["execution"] = execute_sql(sql, profile)
    return result


def _utc_now() -> str:
    """UTC timestamp for the provenance block. Isolated so tests can freeze it."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_value_domains(sql: str, template: str = "") -> List[dict]:
    """⭐ Are the literals in this SQL values the column can actually HOLD?

    ⛔ **The failure this catches is invisible to every other check.** A column can be
    reachable, populated, and correctly named, and the SQL still returns the wrong rows
    because a literal was GUESSED. Measured 2026-08-26: `severity` is a CLOSED domain of
    (Critical, High, Medium, Low, Info, Unknown) — a filter naming the five "obvious" bands
    silently drops every `Unknown` row, and T2 holds 9,426 of them. Reachability passes,
    shape passes, fan-out passes, EXPLAIN passes, and the answer is quietly wrong.

    ⭐ The domains now ride on the `reachable-columns` payload the gate ALREADY fetches
    (pantheon-datalake `reachability.py`), so this costs no extra round-trip.

    Two findings, and they are different:
      * `not_in_domain` — the literal is not a value the column holds. On a CLOSED domain
        that is a defect; the predicate matches nothing.
      * `exhaustive_in_on_open_domain` — an `IN (...)` enumerating an OPEN domain. More
        spellings can appear, so the list is wrong by construction the moment one does.

    ⚠️ WARNING, never a refusal — same contract as `shape`. A domain is a declaration, and
    a tenant may legitimately hold a value nobody described yet. Reachability gates; this
    informs.
    """
    # ⛔ A BOUND POLICY SET IS NOT A GUESSED LITERAL. When the author wrote
    # `severity = ANY({{severity_floor.at_or_above}})`, the binder renders the tenant's
    # actual bands — and those legitimately omit the ones below the floor. Flagging that
    # would fire on every correctly-templated query and train the reader to ignore the
    # check, which is exactly the failure this whole file argues against elsewhere.
    #
    # So: if the ORIGINAL template had a placeholder on this column, the omission was a
    # policy decision, not a guess. Only unbound literals are judged.
    bound_cols: Set[str] = set()
    if template:
        for m in re.finditer(r"(\w+)\s*(?:=\s*ANY\s*\(|\s+IN\s*\()?\s*\{\{", template, re.I):
            bound_cols.add(m.group(1).lower())

    payload = dict(_LAST_REACHABLE_PAYLOAD)
    domains: Dict[str, dict] = {}
    for row in (payload.get("columns") or []):
        if isinstance(row, dict) and row.get("value_domain"):
            key = f"{str(row.get('table','')).lower()}.{str(row.get('column','')).lower()}"
            domains[key] = row["value_domain"]
    if not domains:
        return []

    # ⚠️ Restrict to the tables this SQL actually READS. The same column name lives on
    # several sink tables (`severity` is on vulnerabilities AND findings), and reporting the
    # wrong one is worse than reporting none: the reader checks a table the query never
    # touches, finds the warning inapplicable, and learns to ignore the check.
    low = sql.lower()
    tables_in_sql = {
        t for t in {k.split(".", 1)[0] for k in domains}
        if re.search(rf"\b{re.escape(t)}\b", low)
    }

    findings: List[dict] = []
    seen: Set[str] = set()
    for key, dom in domains.items():
        tbl, col = key.split(".", 1)
        if tables_in_sql and tbl not in tables_in_sql:
            continue
        if col in bound_cols:
            continue  # bound policy, not a guess — see bound_cols above
        values = [str(v) for v in (dom.get("values") or [])]
        if not values:
            continue
        # Only look where the column is actually COMPARED to a literal. A bare projection
        # decides nothing, and warning on it would train the reader to ignore the warning.
        for m in re.finditer(
            rf"\b{re.escape(col)}\s*(=|<>|!=|\s+in\s*\()\s*([^)\n]{{0,400}})",
            low,
        ):
            frag = m.group(2)
            lits = re.findall(r"'([^']*)'", frag)
            if not lits:
                continue
            known = {v.lower() for v in values}
            unknown = [x for x in lits if x.lower() not in known]
            sig = f"{key}|{sorted(lits)}"
            if sig in seen:
                continue
            seen.add(sig)
            if unknown:
                findings.append({
                    "column": key, "kind": "not_in_domain",
                    "literals": unknown, "declared": values,
                    "closed": bool(dom.get("closed")),
                })
            elif len(lits) > 1:
                # An IN list that OMITS declared values. Two different problems:
                #   closed domain -> the omitted rows are silently dropped. This is the
                #     `severity IN (...5 bands...)` bug that loses every `Unknown` row —
                #     9,426 of them on T2, with no error anywhere.
                #   open domain   -> worse in a different way: more spellings can appear,
                #     so the list is wrong by construction the moment one does.
                missing = [v for v in values if v.lower() not in {x.lower() for x in lits}]
                if missing:
                    findings.append({
                        "column": key,
                        "kind": ("omits_closed_domain_values"
                                 if dom.get("closed") else "exhaustive_in_on_open_domain"),
                        "literals": lits, "declared": values, "omitted": missing,
                        "closed": bool(dom.get("closed")),
                    })
    return findings


def check_sql(
    sql: str,
    reachable: Dict[str, Set[str]],
    dialect: str = "postgres",
    render: bool = True,
) -> dict:
    """Parse `sql` and report unreachable column references.

    Reports each offending column with the CLAUSE it appears in, because that is
    what decides whether the query can be degraded or must be refused: a column
    in the SELECT list can be dropped (the answer narrows); a column in
    WHERE/JOIN/GROUP BY cannot (dropping it silently returns a DIFFERENT ROW SET).

    `render=True` binds vocabulary + resolves dbt refs first, so templated SQL is
    CHECKED rather than refused. Findings are mapped back to the ORIGINAL
    template text (see `_locate_in_source`) — a finding reported at a rendered
    line number cannot be found in the file the author actually wrote.
    """
    source_sql = sql
    rendered_info = None
    if render:
        rendered_info = render_sql(sql)
        sql = rendered_info["rendered"]
        # An unresolved placeholder is its OWN failure class. Reporting it as a
        # parse error would send the reader looking for a SQL bug when the real
        # cause is an unknown key, a `vocab:` prefix, or a malformed block.
        if rendered_info["unresolved"]:
            return {
                "parsed": False, "error": None,
                "unresolved_placeholders": rendered_info["unresolved"],
                "bind_error": rendered_info["bind_error"],
                "rendered": sql, "template": source_sql,
                "unreachable": [], "unknown_table": [], "masked_risks": [],
                # Nothing was parsed, so no column was verified and no dependency
                # can be claimed either way. Present-but-empty keeps the result
                # shape stable for consumers that read them unconditionally.
                "declared_dependencies": [],
                "declared_dependencies_without_caller": [],
                # ⛔ "unknown", NOT "self_filling". `_fill_mode([])` returns
                # self_filling because "this query reads no declared column" is a
                # real finding — but here nothing was PARSED, so no column was
                # examined at all. Reusing the self-filling label would assert
                # "an empty result is a real answer" about SQL the gate never
                # read, which is the C1 fabricated-answer violation.
                "fill_mode": "unknown",
                "empty_result_means":
                    "unknown — the SQL did not parse, so no column was examined",
                "declared_dependencies_provenance": DECLARED_DEPENDENCIES_PROVENANCE,
                # Same reasoning as the two keys above: nothing parsed, so no
                # column was resolved and no supply claim can be made either
                # way. Present-but-empty keeps the shape stable for consumers
                # that read it unconditionally — and `columns: 0` is honest,
                # where an absent block would look like a tool that forgot.
                "sql_provenance": _build_sql_provenance({}, []),
                "checked": 0, "clean": False,
            }

    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
    except Exception as e:
        return {"parsed": False, "error": f"{type(e).__name__}: {e}",
                "unresolved_placeholders": [],
                "bind_error": (rendered_info or {}).get("bind_error"),
                "rendered": sql, "template": source_sql,
                "unreachable": [], "unknown_table": [], "masked_risks": [],
                "sql_provenance": _build_sql_provenance({}, []),
                # Same reasoning as the unresolved-placeholder path above: the
                # SQL did not parse, so no column was examined and no fill claim
                # is warranted. "unknown" says that; "self_filling" would lie.
                "fill_mode": "unknown",
                "empty_result_means":
                    "unknown — the SQL did not parse, so no column was examined",
                "checked": 0}

    aliases = _alias_map(tree)
    ctes = _cte_names(tree)
    # Projection aliases are NOT datalake columns. Two sources, both real:
    #   - a CTE's output names, referenced by a later SELECT
    #   - THIS select's own aliases, referenced by ORDER BY / HAVING
    #     (`ORDER BY critical_open` — caught on corpus Q-001, which is a
    #     KNOWN-CLEAN row; without this the gate cries wolf on valid SQL)
    # ⚠️ Only EXPLICIT aliases (`COUNT(*) AS open_findings`) count. A bare
    # `SELECT cve_id` has alias_or_name == 'cve_id', so using alias_or_name
    # here makes every projected column alias ITSELF and skip its own check —
    # the gate then verifies 0 columns and reports ✅ on unreachable SQL.
    # Caught by the `SELECT cve_id ... WHERE is_deleted` regression case.
    cte_outputs: Set[str] = set()
    for sel in tree.find_all(exp.Select):
        for proj in sel.expressions:
            if isinstance(proj, exp.Alias) and proj.alias:
                cte_outputs.add(proj.alias.lower())

    unreachable: List[dict] = []
    unknown_table: List[dict] = []
    stale_policy: List[dict] = []
    declared_deps: List[dict] = []
    # ⚠️ Keyed by (table, column) — NOT by (table, column, clause). The same
    # column read in two clauses is ONE supply fact, and the § 3.3.1 `columns`
    # count is defined as DISTINCT (table, column) references, so counting a
    # re-read twice would break the `self_filling + caller_dependent = columns`
    # partition. First clause seen wins the `clause` label.
    provenance_cols: Dict[Tuple[str, str], dict] = {}
    checked = 0
    seen: Set[Tuple[str, str, str]] = set()

    for col in tree.find_all(exp.Column):
        cname = col.name
        if not cname or cname == "*":
            continue
        low = cname.lower()
        if low in _SQL_PSEUDO:
            continue
        # ✅ System fields are ALWAYS available — the trap that condemned 80/93.
        if low in SYSTEM_COLUMNS:
            continue

        qualifier = (col.table or "").lower()
        table = aliases.get(qualifier, qualifier)

        if table and (table in ctes):
            continue
        # An unqualified name matching a CTE/derived/function-table alias is a
        # reference to that relation, not a datalake column — `GENERATE_SERIES
        # (...) gs` then `DATE_TRUNC('month', gs)` is the real corpus case.
        if not table and (low in cte_outputs or low in ctes):
            continue

        clause = _clause_of(col)
        # ⛔ COMPUTED BEFORE THE `seen` DEDUP, and that ordering is load-bearing
        # in itself. `seen` is keyed by (table, column, CLAUSE) — but the two
        # references that matter here share a clause: `_clause_of` maps a CASE in
        # the select list to SELECT, so a bare projection and a CASE over the
        # same column are BOTH clause=SELECT and the second is deduped away.
        #
        # ⚠️ MEASURED on the three corpus fixtures that motivate the per-query
        # reduction — Q-058 `vm_scan_enabled`, Q-006 `sprint`, Q-088
        # `remediation_priority`. In every one the bare projection is parsed
        # FIRST and the CASE reference second, so deduping first would keep the
        # `false` and discard the `true`, reporting exactly the reassuring
        # half of the answer. Reducing before the skip is what makes the
        # § 3.6.2 "reduce with OR" rule actually reachable.
        lb_here = _is_load_bearing(col)
        if lb_here and (table, low) in provenance_cols:
            provenance_cols[(table, low)]["load_bearing"] = True

        key = (table, low, clause)
        if key in seen:
            continue
        seen.add(key)

        if not table:
            # Unqualified. If exactly ONE real datalake table is in scope,
            # attribution is unambiguous — check it there. Silently skipping
            # unqualified columns would wave through `SELECT
            # exploitability_status FROM vulnerabilities`, the single most
            # ordinary shape a text-to-SQL tool emits.
            real = [t for t in set(aliases.values()) if t in reachable]
            if len(real) == 1:
                table = real[0]
            else:
                hits = [t for t, cs in reachable.items() if low in cs]
                if hits:
                    checked += 1
                    continue
                unknown_table.append({"column": cname, "clause": clause})
                continue

        if table not in reachable:
            unknown_table.append({"table": table, "column": cname, "clause": clause})
            continue

        checked += 1
        # ⚠️ Recorded for EVERY checked reference, reachable or not. An
        # UNREACHABLE column's supply record is not redundant — it is the input
        # to `load_bearing_unreachable` (§ 3.3.1), the number that says the query
        # computes an answer from a column nothing writes.
        if (table, low) not in provenance_cols:
            provenance_cols[(table, low)] = _column_provenance(table, low, clause)
        # The reference that CREATES the record carries its own verdict in; later
        # references OR into it above. Both paths are needed — the first
        # reference reaches here having skipped the merge above (no record
        # existed yet), and a column referenced exactly once has no later one.
        if lb_here:
            provenance_cols[(table, low)]["load_bearing"] = True

        if low not in reachable[table]:
            item = {
                "table": table, "column": cname, "clause": clause,
                "structural": clause not in ("SELECT", "ORDER BY"),
            }
            masked = _masking_context(col)
            if masked:
                item["masked_by"] = masked
            unreachable.append(item)
        else:
            # ⚠️ Reachable — and it may still never hold data. Recorded on EVERY
            # position (SELECT included), unlike the stale-policy check below where
            # position is the whole test. Here it is not: a projection of a column
            # nothing writes returns an empty COLUMN, and an aggregate over it
            # returns a confident zero. Both mislead, so neither is waived.
            dep = DECLARED_DEPENDENCIES.get((table, low))
            if dep is not None and not any(
                    d["table"] == table and d["column"] == cname.lower()
                    for d in declared_deps):
                declared_deps.append({
                    "table": table,
                    "column": cname.lower(),
                    "clause": clause,
                    "has_caller": bool(dep.get("has_caller")),
                    "caller_undeclared": bool(dep.get("caller_undeclared")),
                    "callers": dep.get("callers") or [],
                    # WHERE the callable contract lives. `callers` names WHO
                    # should call and whether they exist; it cannot say HOW to
                    # become one — method, path, a working payload, and (for a
                    # join key) the timing constraint. Carried through so a
                    # corpus row derived from this payload is ACTIONABLE, not
                    # merely alarming. Absent on older platforms -> [].
                    "bridge_ids": dep.get("bridge_ids") or [],
                    "writers": dep.get("writers") or [],
                    "why": dep.get("why") or "",
                })

            if low in POLICY_DERIVED_COLUMNS:
                # Reachable AND populated — and still wrong when it DECIDES something.
                # See _policy_derived_reads for why position is the whole test.
                f = _policy_derived_finding(table, cname, low, clause,
                                            _in_aggregate_filter(col))
                if f is not None:
                    stale_policy.append(f)

    # ⚠️ Map every finding back to the ORIGINAL template text. A user reading a
    # finding at a RENDERED position cannot find it in the file they wrote.
    if render and source_sql != sql:
        for u in unreachable + unknown_table + stale_policy:
            _locate_in_source(u, source_sql)

    # A stale-policy finding must be locatable in the SOURCE even when the SQL
    # was never templated (the branch above only runs for templated input),
    # because the waiver is positional. Locate any that still lack a line.
    for f in stale_policy:
        if f.get("source_line") is None:
            _locate_in_source(f, source_sql)

    # A deliberate read is declared with the SAME marker the policy-literal
    # check uses — one waiver mechanism, one grep, reason required.
    stale_policy, stale_policy_waived = _split_waived(stale_policy, source_sql)

    masked_risks = [u for u in unreachable if u.get("masked_by")]
    out = {
        "parsed": True,
        "error": None,
        "unresolved_placeholders": [],
        "bind_error": (rendered_info or {}).get("bind_error"),
        "unreachable": unreachable,
        "unknown_table": unknown_table,
        "masked_risks": masked_risks,
        "stale_policy": stale_policy,
        "stale_policy_waived": stale_policy_waived,
        # ⛔ DELIBERATELY ABSENT FROM `clean` BELOW. A declared column IS reachable
        # and the question IS answerable; this is a SEPARATE AXIS
        # (answerable-and-self-filling vs answerable-but-depends-on-a-caller).
        # Folding it into `clean` would mean a column becoming reachable could make
        # a query newly UNCLEAN — destroying the property that made the original fix
        # work at all (register a column -> the question passes, no gate edit).
        "declared_dependencies": declared_deps,
        "declared_dependencies_without_caller": [
            d for d in declared_deps if not d["has_caller"]
        ],
        # ⛔ The axis stated as something a reader can ACT on, and the reason this
        # block is not just `has_caller`. See `_fill_mode`. Sibling of the
        # verdict, never an input to it.
        "fill_mode": _fill_mode(declared_deps),
        "empty_result_means": FILL_MODE_MEANING[_fill_mode(declared_deps)],
        "declared_dependencies_provenance": DECLARED_DEPENDENCIES_PROVENANCE,
        "checked": checked,
        "clean": not unreachable and not stale_policy,
    }
    # ⚠️ The tenant-neutrality half runs HERE, not only in the corpus runner.
    # It used to live solely in `check-corpus`, so `check --file` reported a
    # hardcoded-policy row as clean while `check-corpus` flagged it — the two
    # commands disagreed about the same text, and the single-file path (the one
    # the skill's own workflow step 5 tells you to run) was the permissive one.
    # A waiver that `check --file` appeared to accept was in fact never tested.
    out["sql_provenance"] = _build_sql_provenance(
        provenance_cols, unreachable)
    # ⭐ Value-domain check — run on the RENDERED text, so a bound policy set is checked
    # as the literals it actually becomes, not as a placeholder.
    out["value_domain_findings"] = check_value_domains(sql, source_sql)
    _pol = check_policy_literals(source_sql)
    out["policy_literals"] = _pol["findings"]
    out["policy_waived"] = _pol["waived"]
    out["policy_bare_waivers"] = _pol["bare_waivers"]
    if rendered_info is not None:
        out["template"] = source_sql
        out["rendered"] = sql
        out["was_templated"] = source_sql != sql
        out["vocab_keys_used"] = rendered_info["used_keys"]
        out["defaulted_keys"] = rendered_info["defaulted_keys"]
    return out


def _locate_in_source(finding: dict, source_sql: str) -> None:
    """Attach the finding's position in the ORIGINAL template, in place.

    Sets `source_line` when the column name appears verbatim in the template.
    When it does NOT — the reference was produced by substituting a vocabulary
    placeholder — there is no honest source coordinate, so we say so and name the
    placeholder instead. ⚠️ Deliberately never reports a RENDERED coordinate as
    if it were a source one; a confidently wrong line number is worse than none.
    """
    col = finding.get("column") or ""
    if not col:
        return
    for i, line in enumerate(source_sql.splitlines(), start=1):
        if re.search(r"\b" + re.escape(col) + r"\b", line):
            finding["source_line"] = i
            finding["source_text"] = line.strip()[:160]
            return
    holes = _RE_ANY_PLACEHOLDER.findall(source_sql)
    finding["source_line"] = None
    finding["source_note"] = (
        "not present verbatim in the template — introduced by substitution; "
        + (f"placeholders in this SQL: {', '.join(sorted(set(holes))[:5])}"
           if holes else "no placeholders found")
    )


# ── Semantic risk: unreachable columns that get SUBSTITUTED, not dropped ─────
#
# ⚠️ The dangerous case is NOT the loud one. An unreachable column inside
# `COALESCE(col, 0)` or `CASE WHEN col ... ELSE 'none' END` does not produce a
# missing value — it produces a CONFIDENT WRONG ONE. The column is NULL for
# every row (nothing writes it), the default wins every time, and the query
# returns `0` / `'none'` for 100% of rows while looking completely healthy.
# Nobody reads that as "no data"; they read it as the answer.
#
# This is strictly worse than an ordinary unreachable reference, which at least
# fails visibly or returns an obviously empty column. Reported separately so the
# caller can refuse rather than degrade.
_MASKING_FUNCS = {
    "coalesce": "COALESCE(<unreachable>, default) — the default wins on EVERY row",
    "ifnull": "IFNULL(<unreachable>, default) — the default wins on EVERY row",
    "nvl": "NVL(<unreachable>, default) — the default wins on EVERY row",
    "case": "CASE ... ELSE <default> — every row falls through to the ELSE branch",
    "if": "IF(<unreachable>, a, b) — every row takes the false branch",
    "nullif": "NULLIF(<unreachable>, x) — always NULL",
}


def _masking_context(node: exp.Expression) -> str:
    """If this column sits inside a null-substituting construct, name it.

    Walks up to the nearest masking function. Returns '' when the reference is
    an ordinary one whose absence would be visible in the result.
    """
    cur = node.parent
    while cur is not None:
        if isinstance(cur, exp.Case):
            # Only a CASE with an ELSE silently substitutes; without one the
            # fallthrough is NULL, which reads as missing rather than as a fact.
            return _MASKING_FUNCS["case"] if cur.args.get("default") is not None else ""
        if isinstance(cur, exp.Coalesce):
            return _MASKING_FUNCS["coalesce"]
        # ⚠️ sqlglot models each `WHEN ... THEN ...` arm of a CASE as an
        # `exp.If` NESTED INSIDE the Case. So an `exp.If` check placed before
        # the Case check fires on every CASE — including one with no ELSE,
        # whose fallthrough is NULL and therefore reads as missing rather than
        # as a fact. Only treat an If as masking when it is a genuine standalone
        # IF(cond, a, b), i.e. not an arm of an enclosing Case.
        if isinstance(cur, exp.If) and not isinstance(cur.parent, exp.Case):
            return _MASKING_FUNCS["if"]
        if isinstance(cur, exp.Nullif):
            return _MASKING_FUNCS["nullif"]
        name = (cur.name or "").lower() if isinstance(cur, exp.Anonymous) else ""
        if name in _MASKING_FUNCS:
            return _MASKING_FUNCS[name]
        # Stop at a clause boundary — beyond it we are no longer inside the
        # expression that would do the substituting.
        for typ, _label in _CLAUSE_NODES:
            if isinstance(cur, typ):
                return ""
        cur = cur.parent
    return ""


_CLAUSE_NODES: Sequence[Tuple[type, str]] = (
    (exp.Join, "JOIN"),
    (exp.Where, "WHERE"),
    (exp.Group, "GROUP BY"),
    (exp.Having, "HAVING"),
    (exp.Order, "ORDER BY"),
    (exp.Qualify, "QUALIFY"),
)


def _enclosing_window(node: exp.Expression):
    """The `exp.Window` this node sits inside, if any — else None.

    Stops at the first real clause boundary so a window in the SELECT list does
    not capture a column belonging to the statement's own ORDER BY.
    """
    cur = node.parent
    while cur is not None:
        if isinstance(cur, exp.Window):
            return cur
        if isinstance(cur, (exp.Select, exp.Join, exp.Group, exp.Having)):
            return None
        cur = cur.parent
    return None


def _within_window(node: exp.Expression) -> bool:
    return _enclosing_window(node) is not None


#: Clauses in which a policy-derived column DECIDES the answer. A read here
#: silently applies whatever policy was in force when the decoration last ran,
#: instead of the tenant's CURRENT policy bound at bind time.
#:
#: ⚠️ POSITION IS THE WHOLE TEST, and the two positions are genuinely different:
#:   - WHERE / JOIN / HAVING / QUALIFY / GROUP BY, or a CASE inside one of them:
#:     the column selects or classifies rows. THE DEFECT. `_clause_of` already
#:     attributes a CASE to its enclosing clause, which is exactly what makes
#:     this work without a second AST walk.
#:   - SELECT / ORDER BY: the column is echoed as "what the platform currently
#:     thinks the deadline is". LEGITIMATE — a reader may well want to see the
#:     materialised value, and it decides nothing.
#: Reporting the SELECT echo would flag EM-034-shaped reporting queries that are
#: doing nothing wrong, and a checker that cries wolf gets waived by reflex.
_POLICY_DECIDING_CLAUSES = frozenset({
    "WHERE", "JOIN", "ON", "HAVING", "QUALIFY", "GROUP BY",
})


def _in_aggregate_filter(node: exp.Expression) -> bool:
    """True when the column sits inside `COUNT(*) FILTER (WHERE …)`.

    ⚠️ THE ONE PLACE `_clause_of` IS RIGHT FOR REACHABILITY AND WRONG HERE.
    A FILTER's WHERE constrains ONE aggregate rather than the returned rows, so
    `_clause_of` deliberately reattributes it to the enclosing clause (SELECT) —
    correct for reachability, where dropping a projection only narrows.

    But `COUNT(*) FILTER (WHERE vulnerability_due_date < NOW()) AS breached` is a
    DECISION: the resulting number is an SLA-breach count computed from a stale
    policy. It is not an echo of the column, it is a verdict derived from it.
    Measured on the corpus: 6 rows use this shape (9 of the 12 findings), and
    reporting only the plain WHERE positions would miss every one of them.
    """
    cur = node
    while cur is not None:
        if type(cur).__name__ == "Filter":
            return True
        if isinstance(cur, (exp.Select, exp.Where)) and \
                type(cur.parent).__name__ != "Filter":
            return False
        cur = cur.parent
    return False


def _policy_derived_finding(table: str, cname: str, low: str, clause: str,
                            in_agg_filter: bool = False) -> dict | None:
    """A read of a policy-derived column in a DECIDING position. None if benign.

    This is a THIRD defect kind, alongside unreachable and masked:

        unreachable   the column is written by nothing        -> empty/wrong
        masked        an unreachable column behind a default  -> confident wrong
        stale-policy  a REACHABLE, POPULATED column that is   -> confidently
                      yesterday's policy                         out-of-date

    It is not BLOCKED (the column is reachable and populated) and not MASKED
    (nothing substitutes a confident literal — the value is real, just stale).
    It needs its own name, because the remedy is different: bind the vocabulary
    key and compute from the row's own anchor.
    """
    if clause.upper() not in _POLICY_DECIDING_CLAUSES and not in_agg_filter:
        return None
    if in_agg_filter:
        clause = f"{clause} (aggregate FILTER)"
    key, form = _POLICY_DERIVED_REPLACEMENT.get(low, (None, None))
    row = table.split(".")[-1][:1] or "v"
    return {
        "table": table,
        "column": cname,
        "clause": clause,
        "why": POLICY_DERIVED_COLUMNS[low],
        "suggested_key": key,
        "suggested_form": (form.replace("{row}", row) if form else
                           "compute from the tenant's vocabulary key and the "
                           "row's own anchor column"),
    }


def _split_waived(findings: List[dict], source_sql: str) -> Tuple[List[dict], List[dict]]:
    """Partition findings into (live, waived) using the ONE waiver marker.

    Same semantics as `check_policy_literals`: the marker must carry a reason on
    the finding's line or the line above it. A BARE marker does not waive —
    "someone waived this and did not say why" is precisely the state the check
    exists to surface.

    Findings without a resolved line number cannot be waived positionally, so
    they stay live rather than being waived by a marker elsewhere in the file.
    """
    if not findings:
        return findings, []
    lines = source_sql.splitlines()
    live, waived = [], []
    for f in findings:
        ln = f.get("source_line") or f.get("line")
        # The finding's own line and the one above it, kept SEPARATE. Joining
        # them (as the older policy-literal path does) makes the reason bleed
        # into the next line's text when the marker is on the upper line.
        ctx_lines: List[str] = []
        if isinstance(ln, int) and 1 <= ln <= len(lines):
            i = ln - 1
            ctx_lines = [lines[i]] + ([lines[i - 1]] if i - 1 >= 0 else [])
        reason = ""
        found = False
        for cl in ctx_lines:
            if _OVERRIDE_MARKER in cl:
                found = True
                reason = cl.split(_OVERRIDE_MARKER, 1)[1].lstrip(": ").strip()
                if reason:
                    break
        if found:
            if reason:
                f["waiver_reason"] = reason
                waived.append(f)
                continue
            f["waiver_reason"] = None
        live.append(f)
    return live, waived


def _clause_of(node: exp.Expression) -> str:
    """Walk up to the nearest clause. A CASE in the SELECT list is SELECT —
    but a CASE inside WHERE is WHERE, which is what makes it structural.

    ⚠️ THE RECURRING BUG SHAPE — read this before adding a clause node.
    Several sqlglot constructs EMBED a node that looks like a top-level clause
    but is scoped to ONE expression. A naive upward walk hits the embedded node
    first and reports the wrong clause, which flips `structural` and therefore
    flips the whole verdict between "degrade the query" and "refuse it". Three
    instances found so far, all the same shape:

        construct                      embeds        real scope
        ─────────────────────────────  ────────────  ──────────────────────
        COUNT(x) FILTER (WHERE ...)    exp.Where     the enclosing clause
        ... OVER (PARTITION BY/ORDER   exp.Order     the enclosing clause
            BY ...)                    (in Window)
        QUALIFY rn() OVER (ORDER BY)   exp.Order     QUALIFY

    `FILTER` was fixed 2026-08-06; the two `Window` cases were found by this
    session's adversarial pass (`SELECT ... RANK() OVER (ORDER BY col)` was
    reported as ORDER BY, and a QUALIFY'd window as ORDER BY rather than
    QUALIFY). The rule that covers all three: when the walk reaches a
    SCOPE-BREAKING node, discard everything below it and continue from its
    parent. Adding a new clause to `_CLAUSE_NODES` without asking "can any
    construct embed this?" is how the next one gets introduced.

    Measured on the corpus, the FILTER instance alone misclassified 5 of the 51
    UNANSWERABLE rows (EM-011, EM-024, EM-061, EM-074, EM-092), each really a
    PARTIAL, and inflated the blocker list on 11 more.
    """
    cur = node
    while cur is not None:
        # ── Scope-breaking nodes, checked BEFORE the clause table ────────────
        # A FILTER's WHERE constrains ONE aggregate, never the returned rows.
        # Checked first because sqlglot nests it as `Where < Filter`; testing
        # exp.Where first would return "WHERE" and never reach the Filter.
        if type(cur).__name__ == "Filter":
            return _clause_of(cur.parent) if cur.parent is not None else "SELECT"
        if isinstance(cur, exp.Where) and type(cur.parent).__name__ == "Filter":
            return _clause_of(cur.parent.parent) if cur.parent.parent is not None else "SELECT"
        # A window spec's PARTITION BY / ORDER BY orders rows WITHIN the window
        # frame. It does not order — or filter — the result set, so the column
        # belongs to whatever clause the window sits in (SELECT, QUALIFY, ...).
        # Without this, `RANK() OVER (ORDER BY col)` in a projection reports
        # ORDER BY, and a QUALIFY'd window reports ORDER BY instead of QUALIFY —
        # which silently downgrades a genuinely STRUCTURAL reference.
        #
        # ⚠️ The `Order` inside a Window is hit by the walk BEFORE the Window
        # itself (`Column < Ordered < Order < Window`), so testing the clause
        # table first would return "ORDER BY" and never reach this branch. The
        # scope-breaker check must therefore look UPWARD from the clause node,
        # not merely appear earlier in the loop body.
        if isinstance(cur, (exp.Order, exp.Where)) and _within_window(cur):
            win = _enclosing_window(cur)
            return _clause_of(win.parent) if win is not None and win.parent is not None else "SELECT"
        if isinstance(cur, exp.Window):
            return _clause_of(cur.parent) if cur.parent is not None else "SELECT"
        for typ, label in _CLAUSE_NODES:
            if isinstance(cur, typ):
                return label
        cur = cur.parent
    return "SELECT"


# ── Task B: hardcoded policy that should be a vocabulary reference ──────────
#
# ⚠️ THE DEFECT NOTHING ELSE CATCHES. A SQL that hardcodes `severity = 'Critical'`
# instead of `{{severity_floor.at_or_above}}` passes reachability, parsing AND
# masking — and is still wrong, because it cannot be specialised per tenant. It
# fails only at DEPLOYMENT, when the policy layer has nothing to bind. Every
# other check in this file asks "will this SQL run?"; this one asks "will this
# SQL still be correct for the NEXT tenant?".
#
# ⚠️ FALSE POSITIVES ARE EXPECTED AND ACCEPTABLE — but must be OVERRIDABLE.
# `CATALOG_ENTRY_AUTHORING.md` records the real three-way distinction a tool
# cannot make:
#     tenant policy  -> bind it            ("Critical means 7 days HERE")
#     definitional   -> keep it            ("12-month trend" — the window IS the
#                                            question)
#     reporting window -> expose it        (emit days_ago, let the caller narrow)
# So this SURFACES candidates and lets the author declare intent. Over-templating
# is its own failure: a query where everything is a variable answers nothing
# specific and forces every caller to supply 20 values.

#: (key, form, matcher, confidence, why). Grounded in CONSERVATIVE_DEFAULTS'
#: actual value domains — not invented thresholds.
_SEVERITY_WORDS = ("Critical", "High", "Medium", "Low", "Info")
_ENV_WORDS = ("production", "prod", "staging", "development", "dev", "test")


def _literal_is_bound(line: str, match) -> bool:
    r"""True when THIS literal is itself inside, or immediately adjacent to, a
    `{{…}}` binding — the only case the template guard was ever meant to skip.

    ⛔ The guard used to be per-LINE: `not re.search(r"\{\{", line)`. One bound
    key anywhere on a line switched the whole rule off for that line — and since
    the corpus stores SQL as single lines, that is a per-QUERY switch. Measured:
    8 of 32 live queries carried policy literals the checker never reported, and
    the SAME SQL reformatted across lines reported them again. ⚠️ A correctness
    rule must never depend on where the author pressed Enter.

    "Adjacent" is deliberately narrow: the literal must sit inside a `{{…}}`
    span, or within `_BOUND_WINDOW` characters of one on the same line, so an
    already-templated comparison is not re-flagged.
    """
    lo, hi = match.span()
    for t in re.finditer(r"\{\{.*?\}\}", line, re.S):
        tlo, thi = t.span()
        if tlo <= lo and hi <= thi:          # literal is INSIDE the template
            return True
        if abs(lo - thi) <= _BOUND_WINDOW or abs(tlo - hi) <= _BOUND_WINDOW:
            return True
    return False


def _policy_candidates(sql: str) -> List[dict]:
    """Find literals in POLICY POSITIONS that should be vocabulary references."""
    out: List[dict] = []

    def add(literal, key, form, confidence, why, line):
        out.append({"literal": literal, "suggested_key": key,
                    "suggested_form": form, "confidence": confidence,
                    "why": why, "line": line})

    for i, raw in enumerate(sql.splitlines(), start=1):
        line = raw.strip()
        ll = line.lower()
        if not line or ll.startswith("--"):
            continue

        # 1. Severity compared/filtered against a literal → severity_floor.
        #    Comparison or set-membership on a severity column is the single most
        #    common hardcoded policy in the corpus.
        if re.search(r"\bseverity\b", ll):
            hits = []
            for w in _SEVERITY_WORDS:
                mm = re.search(r"['\"]" + w + r"['\"]", line, re.I)
                # ⛔ Per-LITERAL, not per-line. See _literal_is_bound().
                if mm and not _literal_is_bound(line, mm):
                    hits.append(w)
            if hits and re.search(r"(=|<>|!=|\bin\b|\bany\b|>=|<=|>|<)", ll):
                add(", ".join(f"'{h}'" for h in hits), "severity_floor",
                    "{{severity_floor.at_or_above}}", "high",
                    "severity threshold is tenant policy, not a fixed fact", i)

        # 2. SLA / age day-counts → sla_window_by_severity (key-map form).
        for m in re.finditer(
                r"\b(?:interval\s*'|)(\d{1,4})\s*(?:days?)['\"]?", ll):
            n = int(m.group(1))
            if n in (7, 14, 30, 60, 90, 180) and re.search(
                    r"sla|due|breach|overdue|age|stale|remediat", ll):
                add(f"{n} days", "sla_window_by_severity",
                    "{{sla_window_by_severity[t.severity]}}", "medium",
                    "remediation window is per-tenant policy; may instead be "
                    "definitional (a fixed reporting window) — declare intent", i)
                break

        # 3. Status sets → actionable_status_set.
        # ⚠️ NOT `\bstatus\b`: `_` is a word character, so `\b` never matches
        # before the `status` in `vulnerability_status` — which is the actual
        # column name in every corpus row. The anchored form silently detected
        # nothing on real SQL and only passed on a synthetic bare `status`.
        # Caught by test_hardcoded_policy_is_flagged.
        if re.search(r"status\b", ll):
            _sv = re.search(r"['\"](open|resolved|fixed|closed|suppressed)['\"]",
                            ll)
            # ⛔ Per-LITERAL, not per-line. See _literal_is_bound().
            if _sv and _literal_is_bound(line, _sv):
                _sv = None
            if _sv and re.search(r"(=|\bin\b|<>|!=)", ll):
                # ⛔ REPORT THE TOKEN THAT ACTUALLY MATCHED, not the first quoted
                # string on the line. This used to `add(re.search(r"['\"](\w+)['\"]",
                # line))` — the FIRST quoted token anywhere on the line — which is a
                # different string from the one the rule matched whenever the SQL is
                # a single line (every corpus row is). Measured on Q-026: the rule
                # correctly matched 'Open' inside `vulnerability_status IN (...)`,
                # then reported `'no_owner'` — a CASE output LABEL that is not policy
                # at all. An author told to bind 'no_owner' to a vocabulary key would
                # be replacing a display string and leaving the real policy literal
                # in place, so a true finding read as a false positive and the actual
                # defect survived. Slice the original line at the match offsets so
                # the reported token preserves the source's casing.
                _tok = line[_sv.start():_sv.end()]
                add(_tok,
                    "actionable_status_set", "{{actionable_status_set}}",
                    "medium", "which statuses count as actionable is tenant policy", i)

        # 4. EPSS thresholds → epss_escalate_threshold / epss_monitor_threshold.
        m = re.search(r"epss\w*\s*(?:>=|>|<=|<)\s*(0?\.\d+)", ll)
        if m and "{{" not in line:
            v = float(m.group(1))
            key = ("epss_escalate_threshold" if v >= 0.3
                   else "epss_monitor_threshold")
            add(m.group(1), key, "{{" + key + "}}", "high",
                "EPSS cut-off is tenant risk appetite", i)

        # 5. Environment names → production_criticality_floor scope.
        if re.search(r"environment|env\b", ll) and "{{" not in line:
            hits = [w for w in _ENV_WORDS
                    if re.search(r"['\"]" + w + r"['\"]", line, re.I)]
            if hits and re.search(r"(=|\bin\b|<>|!=)", ll):
                add(", ".join(f"'{h}'" for h in hits),
                    "production_criticality_floor",
                    "{{production_criticality_floor}}", "low",
                    "environment scoping MAY be definitional to the question — "
                    "low confidence, confirm intent", i)

        # 6. Scan coverage percentage → scan_coverage_target_pct.
        m = re.search(r"(?:coverage|pct|percent)\w*\s*(?:>=|>|<=|<)\s*(\d{2,3})",
                      ll)
        if m and "{{" not in line:
            add(m.group(1), "scan_coverage_target_pct",
                "{{scan_coverage_target_pct}}", "medium",
                "coverage target is a tenant goal, not a fact", i)

    return out


#: An author declares intent with a comment on (or just above) the line. Explicit
#: and greppable BY DESIGN — never a silent suppression. One command lists every
#: waiver in the corpus:  grep -rn 'policy-literal-ok' <corpus>
_OVERRIDE_MARKER = "policy-literal-ok"
# How close a literal must sit to a `{{…}}` to count as already bound.
_BOUND_WINDOW = 24


def check_policy_literals(sql: str) -> dict:
    """Task B. Returns {findings, waived, overrides_seen}.

    ⚠️ SCOPE. A waiver applies to its line, the line above it, or — when the
    statement is a SINGLE LINE — any leading comment block. Corpus SQL is
    routinely stored as one long line (93 rows; most are one line), so the
    original "line above" rule could never match: the literal was at line 13
    and every waiver sat in the header, twelve lines up. That silently failed
    OPEN, reporting a documented, deliberate literal as an unwaived finding.

    ⚠️ The leading-comment fallback is deliberately NOT a whole-file scan. A
    marker anywhere in a multi-line query still has to sit next to the literal
    it excuses, or one waiver at the top would excuse every literal below it —
    which is the silent blanket suppression this mechanism exists to prevent.

    A finding is WAIVED when its line — or the line above it — carries
    `-- policy-literal-ok: <reason>`. The reason is required: a bare marker is
    itself reported, because "someone waived this and did not say why" is exactly
    the state this check exists to prevent.
    """
    lines = sql.splitlines()
    # Leading comment block, used ONLY when the statement itself is one line.
    header = []
    for ln in lines:
        st = ln.strip()
        if not st or st.startswith("--"):
            header.append(ln)
        else:
            break
    body_lines = len(lines) - len(header)
    header_ctx = " ".join(header) if body_lines <= 1 else ""

    findings, waived, bare = [], [], []
    for f in _policy_candidates(sql):
        i = f["line"] - 1
        # ⛔ Search each candidate line SEPARATELY, never a joined string. Joining
        # them let a reason run past its own end-of-line and swallow the next
        # line's SQL: a TRAILING waiver recorded "…pinned by fixture FROM
        # vulnerabilities v". A reason is bounded by the line it is written on.
        for cand in (lines[i] if 0 <= i < len(lines) else "",
                     lines[i - 1] if i - 1 >= 0 else "",
                     header_ctx):
            if cand and _OVERRIDE_MARKER in cand:
                reason = cand.split(_OVERRIDE_MARKER, 1)[1].lstrip(": ").strip()
                break
        else:
            findings.append(f)
            continue
        # Stop at the next comment marker: a single-line header block can still
        # hold several comments, and the raw split would make the "reason" the
        # whole header.
        reason = re.split(r"\s+--\s", reason)[0].strip()
        if reason:
            f["waiver_reason"] = reason
            waived.append(f)
        else:
            f["waiver_reason"] = None
            bare.append(f)
            findings.append(f)
    return {"findings": findings, "waived": waived, "bare_waivers": bare}


# ── CLI ──────────────────────────────────────────────────────────────────────
def _fmt(result: dict, reachable: Dict[str, Set[str]]) -> str:
    lines = []
    if not result["parsed"]:
        return f"❌ PARSE FAILED — {result['error']}"
    if result["clean"] and not result["unknown_table"]:
        lines.append(f"✅ REACHABLE — {result['checked']} column reference(s) verified")
    for u in result["unreachable"]:
        kind = "STRUCTURAL" if u["structural"] else "projection"
        lines.append(
            f"❌ UNREACHABLE  {u['table']}.{u['column']}  [{u['clause']} — {kind}]"
        )
    for u in result["unknown_table"]:
        t = u.get("table", "?")
        lines.append(f"⚠️  UNKNOWN     {t}.{u['column']}  [{u['clause']}] "
                     f"— table not in the reachable map")
    masked = result.get("masked_risks") or []
    if masked:
        lines.append("")
        lines.append("🔥 SEMANTIC RISK — these do not return NO data, they return WRONG data:")
        for u in masked:
            lines.append(f"   {u['table']}.{u['column']}  [{u['clause']}]")
            lines.append(f"      {u['masked_by']}")
        lines.append(
            "   The column is NULL for every row, so the default is substituted on 100%\n"
            "   of rows and the query returns a confident, plausible, WRONG value.\n"
            "   → This is MORE dangerous than an ordinary unreachable reference, which at\n"
            "     least looks empty. Refuse rather than degrade."
        )
    stale = result.get("stale_policy") or []
    if stale:
        lines.append("")
        lines.append("🕰️  STALE POLICY — reachable, populated, and still WRONG:")
        for u in stale:
            lines.append(f"   {u['table']}.{u['column']}  [{u['clause']}]")
            lines.append(f"      {u['why']}")
            lines.append(f"      → use  {u['suggested_form']}")
        lines.append(
            "   The vocabulary key is applied at BIND time and always wins; this column\n"
            "   carries whatever policy was in force when the decoration last ran.\n"
            "   → Compute the deadline from the key + the row's own anchor, or waive with\n"
            "     `-- policy-literal-ok: <reason>` if the stale value is genuinely wanted."
        )
    # ⚠️ Printed even when the verdict is ✅, and that is the point: these rows are
    # CLEAN and may still return nothing. Kept visually distinct from the failure
    # findings above so nobody reads it as a verdict.
    deps = result.get("declared_dependencies") or []
    dead = result.get("declared_dependencies_without_caller") or []
    if deps:
        mode = result.get("fill_mode") or _fill_mode(deps)
        lines.append("")
        lines.append("📡 DEPENDS ON A CALLER — reachable, but nothing fills it on a sync:")
        for d in deps:
            who = ", ".join(
                f"{c.get('name')} [{c.get('status')}]" for c in (d.get("callers") or [])
            ) or ("no caller declared" if d.get("caller_undeclared") else "unknown")
            # ⚠️ Marked by the WEAKEST caller status on the column, not by
            # `has_caller`. Every column below has a caller once the bridges are
            # built, so a has_caller mark goes uniformly blank and the reader
            # sees no difference between "a robot fills this" and "a human must".
            # Per column, the BEST caller wins (they are alternatives) — same
            # quantifier as `_fill_mode`, which see. Reusing it keeps the two
            # from drifting apart.
            _cm = _fill_mode([d])
            mark = {"none": "⛔", "manual": "⚠️"}.get(_cm, "  ")
            lines.append(f"   {mark} {d['table']}.{d['column']}  [{d['clause']}]  → {who}")
        # ⭐ The line this whole row exists to print: what an EMPTY RESULT means.
        # Stated per row, in the reader's terms, next to the columns that cause
        # it — never left as a boolean for a reader to interpret.
        lines.append(f"   → if this returns NOTHING: {FILL_MODE_MEANING[mode]}")
        if dead:
            lines.append(
                "   ⛔ The marked column(s) have NO caller: the query is answerable and\n"
                "      will return NOTHING until one is built. An empty result here means\n"
                "      'nobody recorded this', NOT 'this does not happen' — do not let a\n"
                "      reader draw the opposite conclusion from an empty panel."
            )
        elif mode == "manual":
            lines.append(
                "   ⚠️ Every caller here is MANUAL — a human must run it. The query is\n"
                "      answerable and correct, and returns NOTHING until somebody does.\n"
                "      'No rows' is NOT evidence that nothing happened. Unaffected verdict."
            )
        else:
            lines.append(
                "   A caller exists, so an empty result means 'not exercised yet',\n"
                "      not 'unanswerable'. This does NOT affect the verdict above."
            )
    waived_stale = result.get("stale_policy_waived") or []
    if waived_stale:
        lines.append("")
        for u in waived_stale:
            lines.append(f"✓ waived stale-policy read {u['table']}.{u['column']} "
                         f"[{u['clause']}] — {u.get('waiver_reason')}")
    if result["unreachable"]:
        struct = [u for u in result["unreachable"] if u["structural"]]
        lines.append("")
        if struct:
            lines.append(
                "⛔ At least one unreachable column is STRUCTURAL "
                "(WHERE/JOIN/GROUP BY/HAVING).\n"
                "   Deleting it does not narrow the answer — it returns a "
                "DIFFERENT ROW SET, silently.\n"
                "   → Outcome 3 (cannot answer) unless a SEMANTIC substitute exists."
            )
        else:
            lines.append(
                "🟡 Unreachable columns are projections only. The query can run "
                "with them dropped —\n   state explicitly what the result no "
                "longer answers (outcome 2)."
            )
    # ⭐ Value domains — a guessed literal is the one failure that passes every other
    # check and still returns the wrong rows.
    vdf = result.get("value_domain_findings") or []
    if vdf:
        lines.append("")
        lines.append("🔤 VALUE DOMAIN — a literal this column may never hold:")
        for f in vdf:
            if f["kind"] == "not_in_domain":
                shut = "CLOSED" if f.get("closed") else "open"
                lines.append(
                    f"   ⛔ {f['column']} compared to {f['literals']} — not in the {shut} "
                    f"domain {f['declared']}."
                )
                lines.append(
                    "      On a CLOSED domain that predicate matches NOTHING, forever."
                )
            elif f["kind"] == "omits_closed_domain_values":
                lines.append(
                    f"   ⛔ {f['column']} IN {f['literals']} OMITS {f['omitted']} from a "
                    f"CLOSED domain — those rows are dropped SILENTLY."
                )
                lines.append(
                    "      This is the classic 'exhaustive-looking' filter bug. If the "
                    "omission is deliberate, bind it as policy instead."
                )
            else:
                lines.append(
                    f"   ⚠️ {f['column']} enumerates an OPEN domain and omits "
                    f"{f['omitted']} — more spellings can appear, so this IN list is "
                    f"wrong the moment one does."
                )
        lines.append("   ⚠️ Advisory: a tenant may hold a value nobody described yet.")

    # Tenant-neutrality. Reported here so `check --file` and `check-corpus`
    # agree; previously only the corpus runner said anything about literals.
    pol = result.get("policy_literals") or []
    bare = result.get("policy_bare_waivers") or []
    if pol:
        lines.append("")
        lines.append("🏷️  HARDCODED POLICY — correct here, wrong at the next tenant:")
        for p in pol:
            note = " ⚠️ waiver has NO REASON" if p in bare else ""
            lines.append(f"   {p['literal']}  → {p['suggested_form']}  "
                         f"({p['confidence']}){note}")
        lines.append("   Apply the three-way test: tenant policy → bind; definitional → keep;")
        lines.append("   reporting window → expose. Keep a literal with "
                     "`-- policy-literal-ok: <reason>`.")
    waived_pol = result.get("policy_waived") or []
    if waived_pol:
        lines.append("")
        for p in waived_pol:
            lines.append(f"✓ waived policy literal {p['literal']} — {p.get('waiver_reason')}")
    return "\n".join(lines)


def _resolve_scope(args) -> str:
    """Return the scope to use, refusing an unflagged `--scope tenant`.

    ⚠️ The default is ALWAYS platform and can never silently become tenant.
    Authoring is a platform question ("could any shipped integration write
    this?"); tenant scope answers a DEPLOYMENT question and, used for
    authoring, condemns columns that are fine the moment a customer connects
    an integration. Measured on `vulnerabilities`: platform=99 reachable,
    tenant=7 — authoring against tenant would have thrown away 92 good columns.
    Tenant is therefore available only behind an explicit opt-in flag.
    """
    scope = getattr(args, "scope", "platform")
    if scope == "tenant" and not getattr(args, "i_know_this_is_a_deployment_question", False):
        print(
            "ERROR: --scope tenant answers a DEPLOYMENT question, not an authoring one.\n"
            "  Tenant scope reports only what THIS customer's connected integrations can\n"
            "  write, so using it to author SQL condemns columns that are fine the moment\n"
            "  an integration is connected (measured: vulnerabilities platform=99, tenant=7).\n"
            "  If you really want the deployment answer, pass:\n"
            "      --i-know-this-is-a-deployment-question",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return scope


# ── S6 — shape routing (the value axis, consumed at authoring time) ─────────
#
# ⛔ THE ROUTING RULE IS NOT IMPLEMENTED HERE. It lives in
# `pantheon_shared.datalake.shape_routing`, imported below, because the PLATFORM
# text-to-SQL agent runs the same rule. Two harnesses, one classifier — a local
# copy is exactly the drift that makes a Claude skill and a platform agent
# produce different SQL for the same question (S6 § 5b, SCHEMA_CONVERGENCE § 3).
#
# ⚠️ This is the ONE place this skill imports `pantheon_shared`, and it obeys the
# same discipline as `load_system_columns`: the DATA comes over the `torana` CLI
# (so no checkout is needed for the values), and only the pure CLASSIFIER is
# imported, with a named refusal when it is unavailable. It never silently
# degrades to a partial answer.


def _load_shape_routing():
    """Import the shared classifier. Returns the module, or None with a cause."""
    try:
        from pantheon_shared.datalake import shape_routing  # noqa: F401
        return shape_routing, ""
    except ImportError:
        pass
    for cand in _local_pantheon_shared():
        sys.path.insert(0, str(cand))
        try:
            from pantheon_shared.datalake import shape_routing  # noqa: F811
            return shape_routing, f"local import ({cand})"
        except Exception:
            continue
    return None, ""


def _load_progression_check():
    """Import the shared progression checker. Returns the module, or None with a cause.

    Mirrors `_load_shape_routing` exactly — same one-rule-two-consumers reason: the platform
    harness runs this identical check, so classifying locally would let a skill-authored and
    a harness-authored funnel get different verdicts.
    """
    try:
        from pantheon_shared.datalake import progression_check  # noqa: F401
        return progression_check, ""
    except ImportError:
        pass
    for cand in _local_pantheon_shared():
        sys.path.insert(0, str(cand))
        try:
            from pantheon_shared.datalake import progression_check  # noqa: F811
            return progression_check, f"local import ({cand})"
        except Exception:
            continue
    return None, ""


def progression_report(rows, intent_text: str, force: bool = False) -> dict:
    """⭐ Does a query CLAIMING a funnel actually narrow? (Fix 2)

    ⛔ THE ONE DEFECT EVERY OTHER GATE PASSES. Measured 2026-08-26 on a real blueprint step:
    reachability, shape, fan-out and EXPLAIN all reported clean, and the result was

        Open findings 95,976 -> Distinct CVEs 537 -> Distinct fixes 607 -> Fixable 254

    Stage 3 GREW. The "reduction" narrative was false, and the same defect reproduced on a
    second tenant (492 -> 554), proving it was the SQL and not one tenant's data. No
    column-level check can see it: every column is reachable, every literal is in domain,
    nothing fans out. The error lives in the RELATIONSHIP BETWEEN ROWS.

    ⚠️ Needs the query's OWN RESULT — whether stage 3 exceeds stage 2 is a fact about the
    data returned, not about the SQL text. Run it first (workflow step 7).
    """
    mod, _ = _load_progression_check()
    if mod is None:
        return {
            "available": False,
            "why": "pantheon_shared.datalake.progression_check is not importable — "
                   "progression check skipped (reachability verdict is unaffected)",
        }
    rep = mod.check_progression(rows, intent_text, force=force)
    return {
        "available": True,
        "checked": rep.checked,
        "why_skipped": rep.why_skipped,
        "monotonic": rep.monotonic,
        "stages": rep.stages,
        "warnings": rep.warnings(),
    }


def _fetch_shapes(columns: Sequence[str], depth: str, profile: str) -> Dict[str, dict]:
    """Fetch the value axis for `columns` at `depth` over the `torana` CLI.

    ⛔ ONE call at the deepest depth any column needs. The `values ⊃ shape ⊃
    fill` implication is resolved SERVER-SIDE (SCHEMA_CONVERGENCE.md § 2.2), so
    asking per column would be N calls for a payload the server returns whole —
    and a local resolution is the drift the one-resolver rule prevents.
    """
    if not columns:
        return {}
    mod, _ = _load_shape_routing()
    if mod is None:
        return {}
    flag = {"values": "--values", "shape": "--shape", "fill": "--fill"}[depth]
    payload = _torana_json(
        ["datalake", "supply", "column", *columns, flag, "--format", "json"],
        profile,
    )
    if not isinstance(payload, dict):
        return {}
    return mod.shapes_from_diagnosis(payload)


def shape_report(sql: str, profile: str) -> dict:
    """Route every column by usage, fetch that depth, and report CONSTANT risks.

    ⛔ Shape NEVER changes the reachability verdict. A shape is a property of a
    DATASET AT A MOMENT (S6 § 6) — `vulnerability_status` is CONSTANT on one copy
    of the dogfood data and ENUM on T1, ONE ROW apart. Letting it block would
    make an authoring verdict depend on today's data, which is the tenant-decides-
    a-platform-question failure this whole discipline removes. It is a SECOND
    AXIS, reported alongside.
    """
    mod, _ = _load_shape_routing()
    if mod is None:
        return {
            "available": False,
            "why": "pantheon_shared.datalake.shape_routing is not importable — "
                   "shape routing skipped (reachability verdict is unaffected)",
        }

    # ⛔ BIND FIRST — templated SQL is the NORM here, not the exception, and `{{…}}` is not
    # SQL. Routing the raw template fails to TOKENIZE and reported
    # `⚠ could not parse the SQL — TokenError`, which reads as "your SQL is broken" when the
    # SQL is fine and the gate simply had not rendered it.
    #
    # ⭐ Reuses `render_sql` — the SAME binder `check` uses. A second render path here could
    # bind differently from the one that produced the reachability verdict, and two gates
    # disagreeing about the same text is the failure `check_sql`'s own docstring warns about.
    #
    # ⚠️ Best-effort, never fatal: shape INFORMS, it does not gate. If binding fails we route
    # the original text and let the parse error surface as it did before, rather than losing
    # the whole second axis to a binder problem.
    try:
        _rendered = render_sql(sql)
        if _rendered and not _rendered.get("unresolved"):
            sql = _rendered["rendered"]
    except Exception:  # noqa: BLE001 — a binder failure must not cost the shape axis
        pass

    route = mod.route_sql(sql)
    if route.parse_error:
        # ⛔ Never report a parse failure as "nothing to check".
        return {"available": True, "parse_error": route.parse_error, "routing": {}}
    if not route.usages:
        return {"available": True, "routing": {}, "warnings": [],
                "note": "no column reference could be resolved to a table"}

    depth = route.deepest_depth()
    shapes = _fetch_shapes(sorted(route.usages), depth, profile)
    warnings = mod.constant_warnings(route, shapes) if shapes else []
    return {
        "available": True,
        "depth_requested": depth,
        "routing": {
            "values": route.values_columns,
            "shape": route.shape_columns,
            "fill": route.fill_columns,
        },
        # ⭐ ARTIFACT_INTENT_SPEC.md § 4.1 — the shape signature the generator
        # saw, written at generation time because it is recoverable later only by
        # regenerating everything once (§ 5).
        "generated_against": mod.shape_signature(shapes),
        "warnings": [
            {"column": w.column, "value": w.value, "clauses": w.clauses,
             "message": w.render()}
            for w in warnings
        ],
    }


def _fmt_shape(rep: dict) -> str:
    """Render the value-axis report. ⛔ Every warning NAMES THE VALUE (S6 § 4.3)."""
    if not rep.get("available"):
        return f"⚠ shape routing unavailable — {rep.get('why', 'unknown cause')}"
    if rep.get("parse_error"):
        # ⛔ Say the SQL could not be parsed. Never print an empty report, which
        # reads as "nothing to check".
        return f"⚠ could not parse the SQL — {rep['parse_error']}"
    lines: List[str] = []
    routing = rep.get("routing") or {}
    lines.append(f"# value axis — one call at depth `{rep.get('depth_requested')}` "
                 f"(the server resolves values ⊃ shape ⊃ fill)")
    for depth, why in (("values", "predicated against a literal"),
                       ("shape", "counted / grouped / ordered"),
                       ("fill", "existence only")):
        cols = routing.get(depth) or []
        if cols:
            lines.append(f"  --{depth:<7s} {why}")
            for c in cols:
                lines.append(f"      {c}")
    warns = rep.get("warnings") or []
    if warns:
        lines.append("")
        lines.append(f"⚠ {len(warns)} CONSTANT column(s) used in a DECIDING clause:")
        for w in warns:
            lines.append(f"  ❌ {w['message']}")
    else:
        lines.append("")
        lines.append("✅ no CONSTANT column is used in a deciding clause")
    sig = rep.get("generated_against") or {}
    if sig:
        lines.append("")
        lines.append("generated_against (the shape signature this SQL was written against):")
        lines.append("  " + json.dumps(sig, indent=2).replace("\n", "\n  "))
    return "\n".join(lines)


def _add_scope_args(p) -> None:
    p.add_argument("--scope", default="platform", choices=["platform", "tenant"],
                   help="ALWAYS platform for authoring. tenant needs the opt-in flag below.")
    p.add_argument("--i-know-this-is-a-deployment-question", action="store_true",
                   help="Required to use --scope tenant. Says you want the DEPLOYMENT "
                        "answer (what this customer can write today), not the authoring one.")
    p.add_argument("--profile", default="",
                   help="Overrides TORANA_PROFILE. Never defaulted — one of the two must be set.")


def establish_ground_truth(scope: str, profile: str) -> Dict[str, Set[str]]:
    """Resolve EVERY ground-truth input, or raise `GroundTruthUnavailable`.

    ⛔ THE LOAD-BEARING FUNCTION. Called before any verdict is computed, so a
    verdict is never produced from a partial view. The four inputs are the
    reachable set, the system columns, the policy-derived deny-list and the
    binder; each refuses independently, with a named cause.

    Ordered so ONE `reachable-columns` round-trip supplies three of the four:
    `system_columns` and `policy_derived` ride along on that payload.
    """
    global SYSTEM_COLUMNS, SYSTEM_PROVENANCE
    global POLICY_DERIVED_COLUMNS, POLICY_DERIVED_PROVENANCE
    global DECLARED_DEPENDENCIES, DECLARED_DEPENDENCIES_PROVENANCE
    global WRITERS_BY_COLUMN, WRITERS_PROVENANCE

    reach = fetch_reachable(scope, profile)
    payload = dict(_LAST_REACHABLE_PAYLOAD)

    SYSTEM_COLUMNS, SYSTEM_PROVENANCE = load_system_columns(profile, payload)
    POLICY_DERIVED_COLUMNS, POLICY_DERIVED_PROVENANCE = load_policy_derived_columns(
        profile, payload)
    # ⚠️ Rides on the SAME payload — no extra round-trip — and deliberately does NOT
    # refuse when absent. It cannot make a verdict wrong (nothing consults it for
    # `clean`), so an old platform loses one advisory rather than the whole check.
    DECLARED_DEPENDENCIES, DECLARED_DEPENDENCIES_PROVENANCE = (
        load_declared_dependencies(payload))
    # ⚠️ Rides on the SAME payload too — still ONE round-trip for four inputs —
    # and degrades for the same reason: nothing consults it for `clean`, so an
    # older platform loses provenance rather than the whole check.
    WRITERS_BY_COLUMN, WRITERS_PROVENANCE = load_column_writers(payload)
    probe_binder(profile)
    return reach


def _provenance_lines() -> List[str]:
    """Where every ground truth came from. A verdict whose provenance is unknown
    cannot be audited, so this is printed on EVERY run, not only on failure."""
    return [
        f"# system fields ({SYSTEM_PROVENANCE}): {', '.join(sorted(SYSTEM_COLUMNS))}",
        f"# policy-derived ({POLICY_DERIVED_PROVENANCE}): "
        f"{', '.join(sorted(POLICY_DERIVED_COLUMNS)) or '—'}",
        # ⚠️ Reports the COUNT and the provenance, never a bare number: empty is
        # ambiguous here ("nothing depends on a caller" vs "the platform did not
        # serve the key"), and only the provenance string tells them apart.
        f"# declared-writer deps ({DECLARED_DEPENDENCIES_PROVENANCE}): "
        f"{len(DECLARED_DEPENDENCIES)} column(s), "
        f"{sum(1 for d in DECLARED_DEPENDENCIES.values() if not d.get('has_caller'))} "
        f"with NO caller",
        # ⚠️ Count AND provenance, for the same reason as the line above: an
        # empty writer map means "the platform did not serve writers", never
        # "no column has one" — and only the provenance string says which.
        f"# column writers ({WRITERS_PROVENANCE}): "
        f"{len(WRITERS_BY_COLUMN)} column(s), "
        f"{sum(1 for w in WRITERS_BY_COLUMN.values() if not w)} with NO writer",
        f"# binder: {BINDER_SOURCE}",
    ]


#: ⛔ THE SAME CONSTANTS THE PLATFORM USES (`sql_validator_mint.py:73-81`). Duplicated, not
#: imported — `skills/CLAUDE.md` forbids reaching into a `pantheon-*` checkout. Three numbers
#: and a ratio; `test_gate.py` pins them against the platform's copy when one is present.
_FANOUT_RATIO_THRESHOLD = 3.0
_FANOUT_MIN_SOURCE_ROWS = 100
_FANOUT_PROBE_CAP = 50_000


def _driving_table(sql: str) -> Optional[str]:
    """The table in the FROM clause — the relation the query ITERATES.

    ⭐ THIS IS THE FAN-OUT DENOMINATOR, and it is the whole design. Measured across four real
    shapes, neither `min` nor `max` over all source tables separates a bug from a healthy
    query: the wrong-edge_type BUG is 3.21x over `vulnerabilities` but 0.14x over
    `entity_edges`, while a legitimately edge-driven query is 23.26x over `vulnerabilities`.
    Only the table the query actually iterates gives the right answer.

    Returns None for a CTE-rooted or unparseable query — the caller then declines to judge
    rather than guessing a denominator.
    """
    try:
        import sqlglot
        from sqlglot import exp
        tree = sqlglot.parse_one(sql, read="postgres")
        if tree is None:
            return None
        frm = tree.find(exp.From)
        if frm is None:
            return None
        tbl = frm.find(exp.Table)
        if tbl is None:
            return None

        # ⛔ A CTE NAME IS NOT A DENOMINATOR. Measured 2026-08-20 on Q-001b: the outer query
        # reads `FROM attributed`, a CTE — and `SELECT count(*) FROM attributed` is not a
        # runnable statement, so the probe failed and the check reported the useless
        # "declined — the result could not be counted".
        #
        # ⚠️ The docstring already PROMISED this behaviour ("Returns None for a CTE-rooted
        # query") and the code did not implement it. Declining EXPLICITLY, by name, is the
        # honest answer: the fan-out ratio needs a PHYSICAL row count to divide by, and a CTE
        # has none until it is materialised.
        cte_names = {
            (c.alias_or_name or "").lower()
            for c in tree.find_all(exp.CTE)
        }
        if tbl.name.lower() in cte_names:
            return None
        return tbl.name
    except Exception:  # noqa: BLE001 — advisory only
        return None


def _fanout_warning(result_rows: int, driving_table: str, source_rows: int) -> Optional[str]:
    """Warn when a result is a large multiple of the table it iterates.

    ⛔ WHY. Measured 2026-08-18: a builder authored SQL joining `entity_edges` on
    `edge_type = 'contains'` (image→package) where the intent needed `'deployed_as'`
    (image→service). Every token was legitimate — real columns, a real edge type, correct
    casing, passed EXPLAIN. It reported **19,450** KEV exposures where there are **24**.

    ⭐ No gate can catch that by inspecting the SQL. But the SHAPE of the result gives it away:
    a relation over a 6,063-row table returning 19,450 rows has fanned out on a join, whatever
    the reason. That catches the CLASS, not the instance.

    ⚠️ WARNING, NEVER A REFUSAL. Some relations legitimately multiply — one finding across N
    deployed services is a documented grain — so refusing would block correct work.
    """
    if result_rows <= 0 or source_rows <= 0:
        return None
    ratio = result_rows / source_rows
    if ratio < _FANOUT_RATIO_THRESHOLD:
        return None
    return (f"FAN-OUT: {result_rows:,} result rows vs {source_rows:,} in `{driving_table}` "
            f"({ratio:.2f}x, threshold {_FANOUT_RATIO_THRESHOLD}). A join is multiplying rows. "
            f"If that is intended (one finding across N services), say so; if not, check the "
            f"join keys and any `edge_type` filter.")


def _cmd_fanout(args) -> int:
    """Probe the authored SQL's shape against the table it iterates (§ 3.5.2)."""
    sql = args.sql or (Path(args.file).read_text() if args.file else "")
    if not sql.strip():
        print("ERROR: pass --sql or --file", file=sys.stderr)
        return 2
    table = _driving_table(sql)
    if not table:
        # ⚠️ Name WHY. "declined" alone reads like a broken check; a reader needs to know the
        # query shape is out of scope, not that the gate failed.
        print("# fan-out: DECLINED — the query is CTE-rooted (or unparseable), so there is no "
              "physical table to divide by. This is a scope limit, not a defect: judge such a "
              "query by comparing its row count to the previous version instead.",
              file=sys.stderr)
        return 0

    prof = getattr(args, "profile", "") or ""
    # ⚠️ BIND FIRST. Templated SQL is not SQL — `{{key}}` reaches Postgres as a syntax error,
    # so a fan-out probe on the raw text would always "decline" and silently never run. This
    # is the same bound text step 7 runs, with conservative defaults applied.
    clean = (render_sql(sql) or {}).get("rendered") or sql
    # ⛔ DROP WHOLE COMMENT LINES — do NOT search for the first "SELECT"/"WITH".
    #
    # Measured 2026-08-20 on corpus query Q-011: the binder RENDERS vocabulary keys wherever
    # they appear, INCLUDING inside `--` comments that document which keys the query binds. A
    # comment reading `-> {{actionable_status_set}}` became `-> SELECT unnest(ARRAY['Open'])`,
    # the keyword search then sliced from THAT text, and the probe sent a mangled fragment —
    # reported to the user as the useless "declined — the result could not be counted".
    #
    # ⚠️ The failure is silent and looks like the CHECK is broken, when the query is fine.
    clean = "\n".join(
        ln for ln in clean.splitlines() if not ln.strip().startswith("--")
    ).strip().rstrip(";")
    n_result, err = _count_via_cli(
        f"SELECT count(*) AS n FROM (SELECT 1 AS _f FROM ({clean}) _fanout "
        f"LIMIT {_FANOUT_PROBE_CAP}) _c", prof)
    if n_result is None:
        # ⭐ A TIMEOUT IS EVIDENCE OF FAN-OUT, NOT AN ABSENCE OF IT. Measured 2026-08-20: the
        # wrong-`edge_type` counterfactual fanned out so hard that even the CAPPED count hit
        # the statement timeout. Reporting "could not be counted" there would be technically
        # true and actively misleading — the very query most likely to be broken is the one
        # that cannot be measured.
        if err and "timeout" in err.lower():
            print(f"⚠️  FAN-OUT (suspected): the capped count over `{table}` TIMED OUT. A "
                  f"query whose first {_FANOUT_PROBE_CAP:,} rows cannot be counted is almost "
                  f"certainly multiplying rows on a join. Check the join keys and any "
                  f"`edge_type` filter before trusting this SQL.")
            return 0
        print("# fan-out: declined — the result could not be counted.", file=sys.stderr)
        return 0
    if n_result < _FANOUT_MIN_SOURCE_ROWS:
        # ⚠️ A small result cannot be a meaningful fan-out. Skipping the source count here is
        # not laziness — it avoids a scary ratio computed off a handful of rows.
        print(f"✅ fan-out: {n_result} rows — below the {_FANOUT_MIN_SOURCE_ROWS}-row floor, "
              f"not judged.")
        return 0
    n_source, _ = _count_via_cli(f"SELECT count(*) AS n FROM {table}", prof)
    if n_source is None:
        print(f"# fan-out: declined — `{table}` could not be counted.", file=sys.stderr)
        return 0

    warning = _fanout_warning(n_result, table, n_source)
    if warning:
        print(f"⚠️  {warning}")
    else:
        print(f"✅ fan-out: {n_result:,} rows vs {n_source:,} in `{table}` "
              f"({n_result / n_source:.2f}x) — below threshold.")
    return 0


def _count_via_cli(sql: str, profile: str) -> Tuple[Optional[int], str]:
    """Run a COUNT through the CLI. Returns `(count, error_text)`.

    ⛔ Returns `None` on any failure — a count that cannot be taken is not, by itself,
    evidence of a defect, and this check may never block. ⚠️ But the ERROR TEXT is returned
    alongside, because one failure mode IS evidence: a statement timeout on a capped count
    means the query is fanning out too hard to measure (§ 3.5.2).
    """
    import subprocess
    env = dict(os.environ)
    if profile:
        env["TORANA_PROFILE"] = profile
    try:
        out = subprocess.run(
            ["torana", "datalake", "query", "--sql", sql, "--format", "json"],
            capture_output=True, text=True, timeout=180, env=env)
        try:
            rows = json.loads(out.stdout).get("results") or []
        except Exception:  # noqa: BLE001 — non-JSON means the CLI printed an error
            return None, (out.stdout or "") + (out.stderr or "")
        if rows:
            return int(rows[0].get("n", 0)), ""
        return None, (out.stdout or "") + (out.stderr or "")
    except Exception as exc:  # noqa: BLE001 — advisory only, never fatal
        return None, str(exc)


def _cmd_evidence(args) -> int:
    """Emit the AUTHORING EVIDENCE RECORD as JSON (§ 3.13.5, § 3.13.5a).

    ⛔ CODE-GENERATED, NEVER MODEL-AUTHORED. § 3.13.5's crux: *"a model writing '✅ corpus
    checked' is a CLAIM, not evidence."* So the deliverable is this script emitting JSON that
    SKILL.md pastes — never prose telling the model what to report. Fields the caller cannot
    substantiate are simply left unrecorded; there is no free-text field to narrate into.

    ⚠️ THE SHAPE IS SHARED WITH THE HARNESS, BUT BUNDLED — not imported. § 3.2.1 wants both
    paths emitting the same keys; `skills/CLAUDE.md` forbids a skill importing platform code,
    because a skill's most valuable use is on a laptop with the CLI and no checkout. Those two
    rules meet at a DELIBERATE duplicate (`scripts/authoring_evidence.py`), pinned against the
    platform's copy by `test_gate.py` so the drift fails a test rather than passing silently.

    ⚠️ `joins.probed` is `False` because after Phases 2-3 edge direction is served by
    `query-hints` on BOTH paths. It is reported, not assumed: a `true` here is the § 3.13.7c
    regression signal.
    """
    # ⛔ BUNDLED WITH THE SKILL, never imported from a `pantheon-*` checkout.
    # `skills/CLAUDE.md` forbids reaching outward into the platform source, and cites THIS
    # script's old `SYSTEM_WRITTEN_COLUMNS` import as the measured example: on a machine
    # without the repo it did not crash — it warned on stderr, then confidently condemned
    # `is_deleted` on stdout. A self-relative import of the skill's own code is explicitly
    # fine; that is what this is.
    import authoring_evidence as ev_mod  # noqa: E402 — sibling module, self-relative

    # `--file` is what SKILL.md documents (the SQL is already on disk from step 5).
    if not args.sql and getattr(args, "file", ""):
        args.sql = Path(args.file).read_text()

    ev = ev_mod.new_evidence(args.question)

    if args.question_id:
        ev_mod.record_corpus(ev, resolved=True, question_id=args.question_id)
    else:
        # ⛔ An UNRESOLVED question is still recorded, as DEMAND — § 3.6.1 calls a miss "an
        # entry in the owed-an-ETL queue, not a failure". Dropping it loses the only signal
        # telling curators what the corpus is missing.
        ev_mod.record_corpus(ev, resolved=False, recorded_as_demand=True)

    if args.catalog_verdict:
        submission: Dict[str, object] = {}
        if getattr(args, "submit", False):
            # ⭐ The WIRE (§ C2). Without --submit this record dies on stdout and the
            # platform's reuse counter stays at 0 however often the catalog was actually
            # used. Best-effort: a telemetry failure never fails the authoring path.
            submission = submit_catalog_decision(
                question=args.question,
                verdict=args.catalog_verdict,
                entry_id=getattr(args, "catalog_entry_id", "") or "",
                axis=args.catalog_axis or "",
                gap_category=getattr(args, "catalog_gap_category", "") or "",
                question_id=args.question_id or "",
                profile=getattr(args, "profile", "") or "",
            )
        ev_mod.record_catalog(
            ev, verdict=args.catalog_verdict,
            axis=args.catalog_axis or None,
            closest=getattr(args, "catalog_entry_id", "") or None,
            decision_id=(submission.get("decision_id") if submission else None),
        )
        if submission:
            # ⚠️ Surfaced on the record itself. A caller that believes it recorded a reuse
            # while the platform recorded nothing is the exact false-confidence this
            # stream exists to remove.
            ev["catalog"]["submission"] = submission

    if args.sql:
        # ⭐ REUSE `check_sql` — the SAME verdict this script's `check` subcommand emits.
        # Re-deriving "which columns does this SQL touch" here would be a second parser that
        # could disagree with the gate, and an evidence record that disagrees with the gate is
        # worse than none: it reports clean on SQL the gate would refuse.
        # ⛔ `establish_ground_truth`, NOT a bare `fetch_reachable`. The latter omits the
        # SYSTEM_COLUMNS fold, so `is_deleted` comes back UNREACHABLE — measured while writing
        # this, and it is § 2.2.1's defect reproduced a third time. The evidence record would
        # then have reported a clean query as touching an unreachable column.
        reachable = establish_ground_truth(
            getattr(args, "scope", "platform") or "platform",
            getattr(args, "profile", "") or "")
        verdict = check_sql(args.sql, reachable)
        unreachable = [f"{f.get('table')}.{f.get('column')}"
                       for f in (verdict.get("unreachable") or []) if f.get("column")]
        ev_mod.record_schema(
            ev, scope=getattr(args, "scope", "platform") or "platform",
            columns_checked=int((verdict.get("sql_provenance") or {}).get(
                "reachable_column_count") or 0),
            unreachable=unreachable,
            # ⚠️ § 2.2.1 regression guard: `is_deleted` reaching the author is the exact fact
            # whose absence killed two builds, so its USE is recorded rather than assumed.
            system_fields_used=sorted(
                {c for c in SYSTEM_COLUMNS if c in args.sql.lower()}),
        )

    ev_mod.record_joins(ev, source="query-hints", probed=False,
                        edge_type=args.edge_type or None)

    if args.result_rows is not None or args.fanout_warning:
        ev_mod.record_shape(ev, result_rows=args.result_rows,
                            fanout_warning=args.fanout_warning or None)

    missing = ev_mod.unrecorded_layers(ev)
    if missing:
        # ⚠️ Reported, not hidden. A record with four of six layers is not "67% evidence" —
        # it is evidence for four layers and SILENCE for two, and a reader must be told which.
        print(f"# unrecorded layers: {', '.join(missing)}", file=sys.stderr)
    print(json.dumps(ev, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="fetch the reachable schema (never embed one)")
    _add_scope_args(f)
    f.add_argument("--table", action="append", help="restrict to table(s)")

    c = sub.add_parser("check", help="re-verify SQL against the reachable set")
    _add_scope_args(c)
    c.add_argument("--sql", help="SQL text")
    c.add_argument("--file", help="file containing SQL")
    c.add_argument("--json", action="store_true")
    c.add_argument("--execute", action="store_true",
                   help="Run the RENDERED SQL as a smoke test and record the result "
                        "in sql_provenance.execution. ⚠️ EVIDENCE, NOT THE VERDICT: "
                        "ok=false is a real defect, but ok=true with 0 rows is not — "
                        "a caller may simply not have run yet. ⚠️ Opt-in because it "
                        "is a live SELECT against the profile's tenant data.")
    c.add_argument("--shapes", action="store_true",
                   help="S6 — also run the VALUE AXIS: route each column by how "
                        "the SQL uses it (predicate -> --values, GROUP BY -> "
                        "--shape, projection -> --fill), then warn where a "
                        "CONSTANT column is used in a DECIDING clause. ⛔ Never "
                        "changes the reachability verdict — a shape is a property "
                        "of a dataset at a moment, not of the schema. Also emits "
                        "`generated_against`, the shape signature.")

    sh = sub.add_parser("shape",
                        help="S6 — the value axis ALONE: which depth each column "
                             "needs, and which CONSTANT columns this SQL decides on")
    _add_scope_args(sh)
    sh.add_argument("--sql", help="SQL text")
    sh.add_argument("--file", help="file containing SQL")
    sh.add_argument("--json", action="store_true")

    pg = sub.add_parser(
        "progression",
        help="⭐ does a result that CLAIMS a funnel actually NARROW? (the one defect "
             "reachability, shape, fan-out and EXPLAIN all pass)")
    _add_scope_args(pg)
    pg.add_argument("--rows-file", required=True,
                    help="JSON file holding the query's OWN RESULT (a list of stage rows). "
                         "Whether stage 3 exceeds stage 2 is a fact about the DATA, not the "
                         "SQL text — run the query first (workflow step 7).")
    pg.add_argument("--intent", default="",
                    help="the intent/description text. The funnel CLAIM is made in prose, "
                         "so this is what decides whether the check applies.")
    pg.add_argument("--force", action="store_true",
                    help="check even when the intent does not name a funnel")
    pg.add_argument("--json", action="store_true")

    fo = sub.add_parser(
        "fanout", help="§ 3.5.2 — is a join multiplying rows? (advisory, never blocks)")
    _add_scope_args(fo)
    fo.add_argument("--sql", default="", help="SQL text")
    fo.add_argument("--file", default="", help="file containing SQL")

    ev = sub.add_parser(
        "evidence",
        help="emit the AUTHORING EVIDENCE RECORD for one authored question (§ 3.13.5)")
    _add_scope_args(ev)
    ev.add_argument("--question", required=True, help="the question, VERBATIM")
    ev.add_argument("--sql", default="", help="the authored SQL, if any")
    ev.add_argument("--file", default="", help="file containing the SQL")
    ev.add_argument("--question-id", default="", help="corpus question_id, if resolved")
    ev.add_argument("--catalog-verdict", default="", help="reuse | miss | probed")
    ev.add_argument("--catalog-axis", default="", help="named rejection axis on a miss")
    ev.add_argument("--catalog-entry-id", default="",
                    help="the entry REUSED, or the near-miss anchor on a miss")
    ev.add_argument("--catalog-gap-category", default="",
                    help="missing_column | missing_hole | wrong_grain | different_join | "
                         "genuinely_novel | platform_defect | needs_caller (on a miss)")
    ev.add_argument("--submit", action="store_true",
                    help="⭐ SEND the catalog verdict to the platform, not just to stdout. "
                         "Without this the verdict is recorded locally and the platform's "
                         "curation queue never learns the catalog was consulted.")
    ev.add_argument("--edge-type", default="", help="edge_type chosen, if entity_edges is joined")
    ev.add_argument("--result-rows", type=int, default=None)
    ev.add_argument("--fanout-warning", default="")

    b = sub.add_parser("check-corpus",
                       help="check a CSV of SQL in ONE pass (fetches the schema once)")
    _add_scope_args(b)
    b.add_argument("--csv", required=True, help="CSV file containing the SQL")
    b.add_argument("--sql-column", default="sql", help="column holding the SQL (default: sql)")
    b.add_argument("--id-column", default="", help="column to label each row by (default: row number)")
    b.add_argument("--json", action="store_true", help="emit per-row verdicts as JSON")
    b.add_argument("--out", default="", help="write the JSON verdicts to this path as well")
    b.add_argument("--execute", action="store_true",
                   help="Run each row's RENDERED SQL sequentially as a smoke test "
                        "(~1-2 min for the full corpus). ⛔ NEVER commit the result: "
                        "§ 3.11 keeps execution evidence session-local, because row "
                        "counts and a profile name are ONE tenant's data in a "
                        "tenant-neutral corpus.")

    args = ap.parse_args()
    args.profile = args.profile or require_profile()

    scope = _resolve_scope(args)

    if args.cmd == "fanout":
        return _cmd_fanout(args)

    if args.cmd == "evidence":
        return _cmd_evidence(args)

    if args.cmd == "check-corpus":
        return _run_corpus(args, scope)

    if args.cmd == "fetch":
        reach = establish_ground_truth(scope, args.profile)
        if args.table:
            want = {t.lower() for t in args.table}
            reach = {t: c for t, c in reach.items() if t.lower() in want}
        total = sum(len(v) for v in reach.values())
        print(f"# scope={scope}  profile={args.profile}  "
              f"tables={len(reach)}  reachable columns={total}")
        for line in _provenance_lines():
            print(line)
        for t in sorted(reach):
            print(f"\n## {t}  ({len(reach[t])})")
            print("  " + ", ".join(sorted(reach[t])))
        return 0

    if args.cmd == "progression":
        try:
            rows = json.loads(Path(args.rows_file).read_text())
        except Exception as e:  # noqa: BLE001
            print(f"ERROR: could not read --rows-file: {e}", file=sys.stderr)
            return 2
        if isinstance(rows, dict):
            # Accept either a bare list or the CLI's {items:[...]} envelope.
            rows = rows.get("items") or rows.get("results") or rows.get("RESULTS") or []
        rep = progression_report(rows, args.intent, force=args.force)
        if args.json:
            # ⛔ ONLY JSON on stdout (skills/CLAUDE.md) — diagnostics go to stderr.
            print(json.dumps(rep, indent=2))
        else:
            if not rep.get("available"):
                print(f"# {rep.get('why')}", file=sys.stderr)
            elif not rep.get("checked"):
                print(f"# progression: not checked — {rep.get('why_skipped')}", file=sys.stderr)
            elif rep.get("monotonic"):
                stages = " -> ".join(
                    f"{st['label']} {st['count']:,}" for st in rep.get("stages") or [])
                print(f"✅ PROGRESSION MONOTONIC — {stages}")
            else:
                for line in rep.get("warnings") or []:
                    print(line)
        # ⛔ Exit 0 even when flagged. A progression CAN legitimately fan out; this is a
        # second axis that INFORMS, exactly like `shape`. Reachability gates; this does not.
        return 0

    sql = args.sql
    if args.file:
        sql = Path(args.file).read_text()
    if not sql:
        print("ERROR: pass --sql or --file", file=sys.stderr)
        return 2

    if args.cmd == "shape":
        rep = shape_report(sql, args.profile)
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            print(_fmt_shape(rep))
        # ⛔ Exit 0 even with warnings. The value axis INFORMS authoring; it does
        # not gate it. A CONSTANT column is a fact about today's data, and a
        # non-zero exit would let one tenant's data fail another tenant's SQL.
        return 0 if rep.get("available") and not rep.get("parse_error") else 2

    reach = establish_ground_truth(scope, args.profile)
    result = check_sql(sql, reach)
    if getattr(args, "shapes", False):
        result["shape"] = shape_report(sql, args.profile)
    if getattr(args, "execute", False):
        _attach_execution(result, args.profile)
    if args.json:
        # ⛔ `--json` emits ONLY JSON. Provenance goes to stderr — a CI gate
        # consuming stdout must see the payload, never a commentary header.
        # This has broken once already (structlog wrote to stdout and
        # json.load() failed with "Extra data: line 1 column 5").
        for line in _provenance_lines():
            print(line, file=sys.stderr)
        result["provenance"] = {
            "system_columns": SYSTEM_PROVENANCE,
            "policy_derived": POLICY_DERIVED_PROVENANCE,
            "binder": BINDER_SOURCE,
            # ⚠️ Also mirrored inside `sql_provenance.writers_provenance`, so a
            # consumer reading only that block can still tell "served" from
            # "not served" without cross-referencing this one.
            "column_writers": WRITERS_PROVENANCE,
        }
        print(json.dumps(result, indent=2))
    else:
        for line in _provenance_lines():
            print(line, file=sys.stderr)
        print(_fmt(result, reach))
        if "shape" in result:
            print()
            print(_fmt_shape(result["shape"]))
    # ⛔ The exit code is the REACHABILITY verdict only. Shape findings never
    # change it — see shape_report().
    return 0 if (result["parsed"] and result.get("clean")) else 1


# ── Corpus runner ───────────────────────────────────────────────────────────
def _verdict_of(result: dict) -> str:
    """One label per row. Ordered by DANGER, not by tidiness.

    MASKED outranks BLOCKED deliberately: a blocked query fails visibly, while a
    masked one returns a confident wrong number that nobody questions.

    BIND_ERROR and UNRESOLVED_PLACEHOLDER are distinct from PARSE_FAILED because
    the cause and the fix differ: a template that cannot bind is an authoring or
    policy-applicability defect, not a SQL defect.
    """
    if result.get("bind_error"):
        return "BIND_ERROR"
    if result.get("unresolved_placeholders"):
        return "UNRESOLVED_PLACEHOLDER"
    if not result["parsed"]:
        return "PARSE_FAILED"
    if result.get("masked_risks"):
        return "MASKED"
    # STALE_POLICY ranks below MASKED, above BLOCKED.
    #
    # Below MASKED: a masked query invents a value that was never measured; a
    # stale-policy query returns a REAL value computed under an older policy.
    # Both are confidently wrong, but the masked one is wrong about the world.
    #
    # Above BLOCKED: a blocked query fails visibly and nobody acts on it. This
    # one runs, returns plausible rows, and is the harder defect to notice —
    # which is the same argument that puts MASKED above BLOCKED.
    if result.get("stale_policy"):
        return "STALE_POLICY"
    if any(u["structural"] for u in result["unreachable"]):
        return "BLOCKED"
    if result["unreachable"]:
        return "PARTIAL"
    if result["unknown_table"]:
        return "UNKNOWN_TABLE"
    return "CLEAN"


def _run_corpus(args, scope: str) -> int:
    """Check every SQL row in a CSV in ONE pass.

    Fetches the reachable schema ONCE — a per-row fetch would be ~90 subprocess
    round-trips and, worse, could straddle a schema change mid-run and produce a
    report whose rows were judged against different ground truth.
    """
    import csv as _csv

    path = Path(args.csv)
    if not path.is_file():
        print(f"ERROR: no such CSV: {path}", file=sys.stderr)
        return 2

    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(_csv.DictReader(fh))
    if not rows:
        print(f"ERROR: {path} has no data rows", file=sys.stderr)
        return 2
    if args.sql_column not in rows[0]:
        print(f"ERROR: column {args.sql_column!r} not in {path.name}. "
              f"Columns: {sorted(rows[0])}", file=sys.stderr)
        return 2

    # ⚠️ A NON-UNIQUE id column silently loses rows for any consumer that keys
    # results by id — the corpus has 93 rows but only 90 distinct `question_id`
    # values (EM-001/EM-037/EM-058 each carry TWO SQL candidates, which is
    # CORRECT by the corpus doctrine: one question, two answer paths, e.g. a
    # declared-inventory path and an observed-graph path). `query_id` is the
    # unique key (93/93). A prior session keyed by question_id and under-reported
    # a verdict-change count as 6 when it was 8.
    #
    # Warn rather than refuse: the caller may legitimately want to group BY
    # question, and this tool emits a list (positional), so its own output is
    # never lossy.
    if args.id_column:
        seen_ids = [(r.get(args.id_column) or "").strip() for r in rows]
        dupes = sorted({v for v in seen_ids if v and seen_ids.count(v) > 1})
        if dupes:
            print(
                f"WARNING: --id-column {args.id_column!r} is NOT unique across "
                f"{len(rows)} rows ({len(set(seen_ids))} distinct). Duplicated: "
                f"{', '.join(dupes)}.\n"
                f"         Results are emitted POSITIONALLY and are complete, but "
                f"anything that keys them by this id will silently drop rows.\n"
                f"         Use a unique column (e.g. --id-column query_id) if you "
                f"intend to index the output.",
                file=sys.stderr,
            )

    reach = establish_ground_truth(scope, args.profile)

    out: List[dict] = []
    for i, row in enumerate(rows, start=1):
        rid = (row.get(args.id_column) or "").strip() if args.id_column else ""
        sql = (row.get(args.sql_column) or "").strip()
        if not sql:
            out.append({"id": rid or str(i), "verdict": "NO_SQL", "checked": 0,
                        "unreachable": [], "unknown_table": [], "masked_risks": [],
                        # No SQL at all — no column examined, so no fill claim.
                        # "unknown", never "self_filling"; see check_sql.
                        "fill_mode": "unknown",
                        "empty_result_means":
                            "unknown — the row carries no SQL to examine",
                        "sql_provenance": _build_sql_provenance({}, [])})
            continue
        res = check_sql(sql, reach)
        # ⚠️ SEQUENTIALLY, never in parallel across the rows (§ 3.7). Each row is
        # a live SELECT against one tenant; a 93-row pass takes ~1-2 minutes and
        # that is the intended cost. Parallelising it would turn an opt-in smoke
        # test into a load generator against customer data.
        if getattr(args, "execute", False):
            _attach_execution(res, args.profile)
        pol = check_policy_literals(sql)
        out.append({
            "id": rid or str(i),
            "verdict": _verdict_of(res),
            "checked": res.get("checked", 0),
            "error": res.get("error"),
            "bind_error": res.get("bind_error"),
            "unresolved_placeholders": res.get("unresolved_placeholders", []),
            "was_templated": res.get("was_templated", False),
            "vocab_keys_used": res.get("vocab_keys_used", []),
            "unreachable": res.get("unreachable", []),
            "unknown_table": res.get("unknown_table", []),
            "masked_risks": res.get("masked_risks", []),
            "stale_policy": res.get("stale_policy", []),
            "stale_policy_waived": res.get("stale_policy_waived", []),
            # The second axis, per row. Never folded into `verdict`.
            "declared_dependencies": res.get("declared_dependencies", []),
            "declared_dependencies_without_caller":
                res.get("declared_dependencies_without_caller", []),
            # What an empty result from THIS row would mean. Beside the verdict,
            # never inside it.
            "fill_mode": res.get("fill_mode"),
            "empty_result_means": res.get("empty_result_means"),
            # The per-row supply record. Like the axis above, reported ALONGSIDE
            # the verdict and never inside it.
            "sql_provenance": res.get("sql_provenance"),
            "policy_literals": pol["findings"],
            "policy_waived": pol["waived"],
        })

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))

    if args.json:
        # ⛔ stdout carries ONLY the JSON payload.
        for line in _provenance_lines():
            print(line, file=sys.stderr)
        print(json.dumps(out, indent=2))
    else:
        counts: Dict[str, int] = {}
        for r in out:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print(f"# {path.name}  rows={len(out)}  scope={scope}  profile={args.profile}")
        for line in _provenance_lines():
            print(line)
        print()
        for r in out:
            mark = {"CLEAN": "✅", "PARTIAL": "🟡", "BLOCKED": "⛔",
                    "MASKED": "🔥", "STALE_POLICY": "🕰️ ", "UNKNOWN_TABLE": "⚠️ ",
                    "PARSE_FAILED": "❌", "NO_SQL": "·",
                    "BIND_ERROR": "🧩", "UNRESOLVED_PLACEHOLDER": "🧩"}.get(
                        r["verdict"], "?")
            detail = ""
            bad = r["unreachable"] or r["unknown_table"]
            if bad:
                detail = "  " + ", ".join(
                    f"{u.get('table', '?')}.{u['column']}[{u['clause']}]" for u in bad[:4]
                ) + (" …" if len(bad) > 4 else "")
            elif r.get("unresolved_placeholders"):
                detail = "  " + ", ".join(r["unresolved_placeholders"][:3])
            pol = len(r.get("policy_literals") or [])
            if pol:
                detail += f"   [{pol} hardcoded-policy]"
            # Annotated on the row, NEVER folded into the verdict — a CLEAN row that
            # depends on an unbuilt caller stays CLEAN and gains a 📡 marker.
            _dep = len(r.get("declared_dependencies") or [])
            _dead = len(r.get("declared_dependencies_without_caller") or [])
            if _dep:
                # ⚠️ The fill mode is printed on the row itself. Without it every
                # caller-dependent row reads "📡[7 declared]" and a reader cannot
                # tell the wired ones from the ones waiting on a human.
                _fm = r.get("fill_mode") or ""
                _fmark = {"none": " ⛔none", "manual": " ⚠️manual",
                          "wired": " wired"}.get(_fm, "")
                detail += (f"   📡[{_dep} declared" +
                           (f", {_dead} NO-CALLER" if _dead else "") +
                           _fmark + "]")
            print(f"{mark} {r['verdict']:22} {r['id']:14}{detail}")
        print()
        for k in ("CLEAN", "PARTIAL", "BLOCKED", "MASKED", "STALE_POLICY",
                  "UNKNOWN_TABLE",
                  "PARSE_FAILED", "BIND_ERROR", "UNRESOLVED_PLACEHOLDER", "NO_SQL"):
            if counts.get(k):
                print(f"  {k:22} {counts[k]}")
        n_tmpl = sum(1 for r in out if r.get("was_templated"))
        n_pol = sum(len(r.get("policy_literals") or []) for r in out)
        n_rows_pol = sum(1 for r in out if r.get("policy_literals"))
        used = sorted({k for r in out for k in (r.get("vocab_keys_used") or [])})
        print()
        print(f"  templated rows        {n_tmpl}/{len(out)}")
        print(f"  hardcoded-policy      {n_pol} finding(s) across {n_rows_pol} row(s)")
        print(f"  vocabulary keys used  {len(used)}")

        # ⚠️ The summary the whole second axis exists to produce. Reported ALONGSIDE
        # the verdict counts, never inside them: these rows are answerable, and the
        # ones with no caller answer with silence.
        _dep_rows = [r for r in out if r.get("declared_dependencies")]
        _dead_rows = [r for r in out if r.get("declared_dependencies_without_caller")]
        _dep_cols = {(d["table"], d["column"])
                     for r in out for d in (r.get("declared_dependencies") or [])}
        _dead_cols = {(d["table"], d["column"]) for r in out
                      for d in (r.get("declared_dependencies_without_caller") or [])}
        print(f"  declared-writer deps  {len(_dep_rows)} row(s) depend on "
              f"{len(_dep_cols)} declared-writer column(s)")

        # ⭐ WHAT AN EMPTY RESULT MEANS, per row, summarised. This is the point of
        # the row: the verdict counts above say every one of these queries is
        # correct, and they are — but a `0` from a `manual` row and a `0` from a
        # `self_filling` row support OPPOSITE conclusions, and until this block
        # existed the report gave a reader no way to tell them apart.
        _answered = [r for r in out if r["verdict"] == "CLEAN"]
        if _answered:
            _by_mode: Dict[str, List[str]] = {}
            for r in _answered:
                _by_mode.setdefault(r.get("fill_mode") or "unknown", []).append(r["id"])
            print()
            print(f"  ── If a CLEAN row returns NOTHING ({len(_answered)} row(s)) ──")
            for _m in ("self_filling", "wired", "manual", "none", "unknown"):
                _ids = _by_mode.get(_m)
                if not _ids:
                    continue
                _why = FILL_MODE_MEANING.get(
                    _m, "unknown — no column was examined")
                print(f"  {_m:13} {len(_ids):3} row(s)  {_why}")
                if _m in ("manual", "none", "unknown"):
                    print(f"       {', '.join(sorted(_ids))}")
            if _by_mode.get("manual") or _by_mode.get("none"):
                print("     ⚠️ These rows are ANSWERABLE and their SQL is CORRECT. They\n"
                      "        return nothing until a person (or, for `none`, an engineer)\n"
                      "        acts. A dashboard rendering 0 here means 'nobody recorded\n"
                      "        one', NOT 'this does not happen'. The verdict counts above\n"
                      "        are unaffected — this is a SECOND AXIS, not a demotion.")
        if _dead_cols:
            print(f"  ⛔ NO CALLER          {len(_dead_rows)} row(s) depend on "
                  f"{len(_dead_cols)} column(s) NOTHING writes")
            for t, c in sorted(_dead_cols):
                ids = [r["id"] for r in _dead_rows
                       if any(d["table"] == t and d["column"] == c
                              for d in r["declared_dependencies_without_caller"])]
                print(f"       {t}.{c}  ← {', '.join(ids)}")
            print("     These rows are ANSWERABLE and return NOTHING until a caller is\n"
                  "     built. An empty result means 'nobody recorded this', not 'this\n"
                  "     does not happen'. The verdict counts above are unaffected.")
        elif DECLARED_DEPENDENCIES_PROVENANCE.startswith("unavailable"):
            print("  ⚠️  declared-writer dependency data unavailable — "
                  "this run could not check the second axis")

        # ── Supply provenance, per § 3.3. Reported ALONGSIDE the verdict counts
        # for the same reason as the block above: these rows are answerable, and
        # what fills them is a different question from whether they parse.
        _prov_cols = {(c["table"], c["column"])
                      for r in out for c in
                      ((r.get("sql_provenance") or {}).get("columns") or [])}
        _unres = [(u["table"], u["column"]) for r in out for u in
                  ((r.get("sql_provenance") or {}).get("unresolved_writers") or [])]
        if WRITERS_PROVENANCE.startswith("unavailable"):
            print("  ⚠️  column-writer provenance unavailable — "
                  "this run resolved no supply record")
        else:
            print(f"  supply provenance      {len(_prov_cols)} distinct column(s) "
                  f"carry a writer record")
            if _unres:
                # ⛔ Never silent. A checked column with NO writer is a gap in
                # the map or a column outside the sink tables — it is NOT
                # self-filling, and reporting it as an empty list would launder
                # the gap into a clean answer.
                print(f"  ⛔ NO WRITER          {len(set(_unres))} checked column(s) "
                      f"resolve to NO writer")
                for t, c in sorted(set(_unres)):
                    print(f"       {t}.{c}")

        if counts.get("MASKED"):
            print("\n🔥 MASKED rows return a CONFIDENT WRONG VALUE, not an empty one — "
                  "triage these first.")

    # Non-zero when anything needs attention, so CI can gate on it.
    return 0 if all(r["verdict"] in ("CLEAN", "NO_SQL") for r in out) else 1


def _cli() -> int:
    """Run `main`, turning a ground-truth failure into a REFUSAL, not a verdict.

    ⛔ Exit 2 means "did not check", and is deliberately distinct from exit 1
    ("checked, and found a problem"). A caller — human or CI — must be able to
    tell those apart: conflating them is how a broken checker gets read as a
    failing query, or worse, how a green run gets read as a clean one.

    Nothing is printed to stdout on this path. The old behaviour printed a
    confident verdict to stdout and a warning to stderr, so anything scripted
    around it consumed the wrong answer and never saw the caveat.
    """
    try:
        return main()
    except GroundTruthUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        # `fetch_reachable` raises a plain RuntimeError when the CLI call fails.
        # Same class of failure: ground truth is missing, so refuse.
        print(f"ERROR: cannot establish ground truth.\n       {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
