"""Customer-facing phrasing — § 3.4.5 rules and the § 3.4.6 category-vs-vendor choice.

⛔ Kept SEPARATE from supply_graph.py on purpose. The traversal moves server-side at P6;
the phrasing rules are surface concerns that outlive it. Splitting them means the P6 diff
touches one file.

⛔ THE FIVE PHRASING RULES (§ 3.4.5) — non-negotiable, and they are the whole point:

  1. NEVER say "bridge", "declared writer", "write seam", "reachability", or a BRIDGE-* id.
     Those are our internal mechanics. Say what to do.
  2. NEVER blame the customer for a SUPPLIED verdict. If the writer is connected and
     syncing, an empty result is OUR bug. Telling a customer to check their scanner when
     the defect is ours is the trust loss, inverted.
  3. NEVER guess a trigger. Say WHO fills a NEEDS_CALLER column, never WHEN. The
     § 3.2.3 `trigger` field does not exist yet.
  4. Choose category vs vendor by WHAT WE KNOW (§ 3.4.6). A blanket "always categories"
     rule is wrong and evasive.
  5. Distinguish "no data yet" from "cannot ever" — different verdicts, different owners.
"""

from __future__ import annotations

from typing import Any

from supply_graph import Verdict

#: Category slug -> the noun a customer would recognise. Derived from the category's own
#: description where possible; this map only makes the slug read as English.
_CATEGORY_NOUN = {
    "security_scanner": "vulnerability scanner",
    "code_scanner": "source-code scanner",
    "vcs": "version control system",
    "project_management": "ticketing tool",
    "cloud_provider": "cloud provider",
    "identity_provider": "identity provider",
    "artifact_registry": "artifact registry",
    "monitoring": "monitoring platform",
    "communication": "messaging tool",
    "ci_cd": "CI/CD system",
}


def _noun(category: str) -> str:
    return _CATEGORY_NOUN.get(category, category.replace("_", " "))


def _join(items: list[str], conj: str = "or") -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} {conj} {items[-1]}"


def message_for(v: Verdict) -> str | None:
    """The customer-facing message, or None when the verdict must render NOTHING.

    ⛔ Returns None for SUPPLIED (§ 3.4.4: a 0-row result is NOT evidence of a supply
    problem — the filters may simply have matched nothing) and for the two rank-less
    verdicts (§ 3.4.1: neutral empty state, never an incident message).
    """
    ev = v.evidence

    if v.verdict == "UNREACHABLE":
        # ⛔ Rule: this is OUR gap. Say so plainly rather than implying customer action.
        return "Torana does not collect this yet."

    if v.verdict == "NEEDS_CALLER":
        callers = [c.get("name") for c in ev.get("callers") or [] if c.get("name")]
        if not callers:
            # has_caller false → dead on arrival. Still no trigger guess.
            return ("Filled only when something records it, and nothing does so today.")
        # ⛔ Rule 3: WHO, never WHEN. No "this fills after each scan".
        return f"Filled when {_join(callers)} runs. None recorded yet."

    if v.verdict == "DOCUMENT_ONLY":
        # ⚠️ "format" is not a tool a customer can buy — never "connect a []".
        return "Populated by uploading a scan or inventory document."

    if v.verdict == "CATEGORY_MISSING":
        # ⛔ CATEGORY, not vendor: we know nothing relevant is connected, so naming a
        # vendor guesses a stack they may not have and reads as a pitch.
        cats = [_noun(c) for c in ev.get("categories", [])]
        return f"To populate this, connect a {_join(cats)}."

    if v.verdict == "PEER_GAP":
        # ⚠️ BOTH: the category frames it, the example makes it actionable. This is the
        # case a category-only rule would have thrown away, and the most useful of three.
        cats = [_noun(c) for c in ev.get("categories", [])]
        peers = ev.get("peer_examples") or []
        base = f"Your {_join(cats, 'and')} does not report this"
        if peers:
            names = _join([p for p in peers[:3]], "or")
            return f"{base}; tools such as {names} do."
        return f"{base}."

    if v.verdict == "SOURCE_DISABLED":
        # ✅ VENDOR BY NAME: we are reading their own configuration back to them.
        hit = (ev.get("via") or [{}])[0]
        vendor = hit.get("vendor") or hit.get("integration", "the integration")
        return (f"{vendor} is connected, but its "
                f"{hit.get('data_source', 'collector')} collector is off.")

    if v.verdict == "SYNC_FAILING":
        hit = (ev.get("via") or [{}])[0]
        vendor = hit.get("vendor") or hit.get("integration", "the integration")
        return f"Your {vendor} sync is failing."

    # ⛔ SUPPLIED renders NOTHING (§ 3.4.4). UNRESOLVED / LINEAGE_AMBIGUOUS render the
    # neutral empty state — never an incident message — and emit internal telemetry.
    return None


def internal_note(v: Verdict) -> str | None:
    """Engineer-facing detail. ⛔ NEVER shown to a customer — it names our mechanics."""
    ev = v.evidence
    if v.verdict == "SUPPLIED":
        via = ev.get("via") or []
        paths = ", ".join(f"{h['integration']}/{h['data_source']}" for h in via[:3])
        return (f"supplied via {paths} — if this column IS empty, that is OUR bug: "
                f"escalate, do not tell the customer to check their tooling")
    if v.verdict == "NEEDS_CALLER":
        bits = []
        for c in ev.get("callers") or []:
            bits.append(f"{c.get('name')} (status={c.get('status')})")
        if ev.get("bridge_ids"):
            bits.append(f"bridges: {', '.join(ev['bridge_ids'])}")
        if ev.get("has_caller") is False:
            bits.append("⛔ NO CALLER EXISTS — dead on arrival until one is built")
        return "; ".join(bits) or None
    if v.verdict == "UNRESOLVED":
        return ev.get("why")
    if v.verdict == "PEER_GAP":
        return f"writers: {', '.join(ev.get('peer_examples') or [])}"
    return None


def aggregate(verdicts: list[Verdict]) -> dict[str, Any]:
    """§ 3.4.2 — per-query verdict: worst-wins by the § 3.4.1 rank, cap 3 columns,
    load-bearing first.

    ⛔ Never render more than one verdict class: a panel showing three different
    explanations teaches the reader nothing.

    ⚠️ Order by WHO CAN FIX IT and HOW LONG, not by how broken it sounds. UNREACHABLE is
    first because no customer action helps; SYNC_FAILING/SOURCE_DISABLED rank last of the
    non-SUPPLIED verdicts because they are minutes-to-fix and self-evident once named.
    """
    ranked = [v for v in verdicts if v.rank is not None]
    non_customer = [v for v in verdicts if v.rank is None]

    if not ranked:
        # Every verdict is UNRESOLVED / LINEAGE_AMBIGUOUS → neutral empty state.
        return {
            "verdict": "UNRESOLVED",
            "customer_facing": False,
            "message": None,
            "neutral_empty_state": True,
            "columns": [f"{v.table}.{v.column}" for v in non_customer],
            "telemetry": "no traceable verdict for any column",
        }

    worst = min(v.rank for v in ranked)
    group = [v for v in ranked if v.rank == worst]
    # load-bearing first: a filter column being empty explains the panel; a display
    # column does not.
    group.sort(key=lambda v: (not v.load_bearing, v.table, v.column))
    shown = group[:3]
    more = len(group) - len(shown)

    verdict_name = group[0].verdict
    msg = message_for(group[0])
    cols = ", ".join(f"{v.table}.{v.column}" for v in shown)
    if more > 0:
        cols += f" and {more} more"

    return {
        "verdict": verdict_name,
        "customer_facing": group[0].customer_facing,
        "message": msg,
        "columns": cols,
        "column_count": len(group),
        "load_bearing_first": [f"{v.table}.{v.column}" for v in shown if v.load_bearing],
        "unresolved_count": len(non_customer),
        "neutral_empty_state": False,
    }
