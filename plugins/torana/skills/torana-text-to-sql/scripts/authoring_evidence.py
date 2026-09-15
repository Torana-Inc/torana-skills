"""The AUTHORING EVIDENCE RECORD — the skill's copy of a shared shape.

⛔ **BUNDLED, NOT IMPORTED.** `skills/CLAUDE.md`: *a skill must never import platform code,
read a file from a `pantheon-*` checkout, or require `TORANA_ROOT` to produce a correct
answer* — because a skill's most valuable use is on an operator's laptop that has the CLI and
credentials but no source tree. This file is therefore a DELIBERATE duplicate of
`pantheon-agent-builder/src/utils/authoring_evidence.py`.

⚠️ **The duplication is the lesser evil, and it is pinned.** The shape is six layer names and
a handful of keys — small and stable. `test_gate.py` asserts this copy and the platform's
agree, so a drift fails a test instead of silently producing two incompatible records.

⛔ **WHY THIS LIVES IN THE PLATFORM AND NOT IN EITHER CONSUMER** (Torana_Datalake_Fixes.md
§ 3.13.5a). Phase 5 as written gives the SKILL an evidence block and the harness none, which
re-opens the § 3.2.1 asymmetry the whole spec exists to close — in the opposite direction.
§ 3.2.1 is explicit: the two paths *"converge on the platform, or not at all"*. A capability
authored in a `SKILL.md` is one only the skill can see; authored here, both read one answer
and Phase 6's diff has nothing spurious to explain.

⛔ **CODE-GENERATED, NEVER MODEL-AUTHORED.** § 3.13.5 states the crux: *"a model writing
'✅ corpus checked' is a CLAIM, not evidence."* Every field here is filled by the caller from
something it actually did — a resolve that returned, a probe that ran, a count that came back.
⚠️ There is deliberately no `note` or `summary` field for a model to write into.

⭐ **`joins.probed == false` is the GOAL, not a default.** It is the § 3.13.7c roll-up
criterion and the thing Phases 2–3 made true: edge direction is now obtainable from
`query-hints` on both paths, so nothing needs to read tenant rows to learn a join's shape. A
`true` here is a regression, and the record exists partly to make that visible.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

#: Every key an evidence record carries. ⛔ Pinned as a constant so a consumer that forgets one
#: FAILS a test rather than emitting a quietly-incomplete record — a partial record reads as
#: "this layer was checked" for the layers it omits.
EVIDENCE_KEYS = ("question", "corpus", "catalog", "schema", "joins", "shape")


def new_evidence(question: str) -> Dict[str, Any]:
    """An empty record for one authored artifact.

    ⚠️ Every layer starts EXPLICITLY UNRECORDED rather than absent-or-false. "We did not check"
    and "we checked and found nothing" are different claims, and a reader who cannot tell them
    apart will assume the reassuring one.
    """
    return {
        "question": question,
        "corpus": {"recorded": False},
        "catalog": {"recorded": False},
        "schema": {"recorded": False},
        "joins": {"recorded": False},
        "shape": {"recorded": False},
    }


def record_corpus(ev: Dict[str, Any], *, resolved: bool,
                  question_id: Optional[str] = None,
                  confidence: Optional[float] = None,
                  recorded_as_demand: bool = False) -> Dict[str, Any]:
    """L1 — the corpus resolve.

    ⛔ An UNRESOLVED question must still be recorded, with `recorded_as_demand`. § 3.13.5 calls
    a miss "an entry in the owed-an-ETL queue, not a failure" — dropping it loses the only
    signal that the corpus needs a new entry.
    """
    ev["corpus"] = {
        "recorded": True, "resolved": bool(resolved),
        "question_id": question_id, "confidence": confidence,
        "recorded_as_demand": bool(recorded_as_demand),
    }
    return ev


def record_catalog(ev: Dict[str, Any], *, verdict: str,
                   axis: Optional[str] = None,
                   closest: Optional[str] = None,
                   decision_id: Optional[str] = None) -> Dict[str, Any]:
    """L1 — the catalog probe. A MISS carries a NAMED rejection axis, never a bare 'no'."""
    ev["catalog"] = {
        "recorded": True, "verdict": verdict, "axis": axis,
        "closest": closest, "decision_id": decision_id,
    }
    return ev


def record_schema(ev: Dict[str, Any], *, scope: str, columns_checked: int,
                  unreachable: Optional[List[str]] = None,
                  system_fields_used: Optional[List[str]] = None) -> Dict[str, Any]:
    """L1 — what the author read.

    ⚠️ `system_fields_used` is the § 2.2.1 regression guard: `is_deleted` reaching the author is
    the exact fact whose absence killed two builds, so its presence is recorded rather than
    assumed.
    """
    ev["schema"] = {
        "recorded": True, "scope": scope, "columns_checked": int(columns_checked),
        "unreachable": list(unreachable or []),
        "system_fields_used": list(system_fields_used or []),
    }
    return ev


def record_joins(ev: Dict[str, Any], *, source: str, probed: bool,
                 edge_type: Optional[str] = None,
                 direction: Optional[str] = None,
                 cardinality: Optional[str] = None) -> Dict[str, Any]:
    """L2 — how the join was decided.

    ⛔ `probed=True` means the author read TENANT ROWS to learn a join's shape. After Phases
    2–3 that should never be necessary: `query-hints` carries edge direction and cardinality on
    both paths. Recording it is what makes a regression visible instead of silent.
    """
    ev["joins"] = {
        "recorded": True, "source": source, "probed": bool(probed),
        "edge_type": edge_type, "direction": direction, "cardinality": cardinality,
    }
    return ev


def record_shape(ev: Dict[str, Any], *, result_rows: Optional[int] = None,
                 from_table: Optional[str] = None,
                 fanout_warning: Optional[str] = None) -> Dict[str, Any]:
    """L3 — what the SQL actually returned, and whether it fanned out."""
    ev["shape"] = {
        "recorded": True, "result_rows": result_rows,
        "from_table": from_table, "fanout_warning": fanout_warning,
    }
    return ev


def unrecorded_layers(ev: Dict[str, Any]) -> List[str]:
    """Which layers were never filled in.

    ⭐ The honest completeness check. A record with four of six layers is not 67% evidence —
    it is evidence for four layers and silence for two, and the caller should say which.
    """
    return [k for k in EVIDENCE_KEYS
            if k != "question" and not (ev.get(k) or {}).get("recorded")]


def is_clean(ev: Dict[str, Any]) -> bool:
    """The § 3.13.7c roll-up criterion: nothing unreachable, and no join was probed."""
    schema = ev.get("schema") or {}
    joins = ev.get("joins") or {}
    return (not schema.get("unreachable")) and (joins.get("probed") is False)
