"""Supply Graph — a THIN CLIENT over the one server-side resolver.

⛔ THIS MODULE COMPUTES NO VERDICTS. SUPPLY_GRAPH_SPEC.md § 3.4.0 decides the traversal is
implemented ONCE, server-side, in pantheon-datalake:

    GET /api/v1/datalake/supply/diagnosis?columns=t.c,t.c
    GET /api/v1/datalake/supply/forward?integration=<name>

    ┌─ SupplyGraph ─────────────────────────────────────────────────┐
    │  diagnose(columns) -> [Verdict]        ← the ONLY two methods │
    │  forward(integration) -> ForwardReport │   callers may use    │
    └───────────────────────────────────────────────────────────────┘
                                 ▲
                          ApiTraversal — maps a response onto these shapes

⚠️ **HISTORY, because it is the argument for the current shape.** This file was P0: a
validation prototype that knowingly held a SECOND FULL COPY of the § 3.4.1 verdict table
(`LocalTraversal`, `_parse_mapping`, the rank map, the SA category plumbing). It shipped
first because it needed no backend and was the cheapest place to prove the verdicts were
right — an engineer sees a bad verdict in a terminal, a customer sees it in a widget.

⛔ The migration it always specified is now DONE. The two copies never disagreed — P6 was
built from these rules and reproduced 11/11 of the § 3.13.1 verdicts — but **nothing failed
when they diverged**: both kept answering, confidently, and a divergence reaches a customer
as two different answers about the same column. P13 then made the asymmetry real by giving
the server `VERDICT_MEANING` (the internal-name → customer-sentence → owner map § 4.4
requires live in ONE place), which this copy never had.

⚠️ What is left here is the interface — `Verdict`, `ForwardReport`, and the rank map used
ONLY to sort and to decide customer-facing-ness locally. ⛔ Do not re-add a decision tree,
a mapping-path parser, or a category lookup: that is the drift disease § 3.1 exists to
prevent, and it has already been removed once.

Portability (pantheon-cli/skills/CLAUDE.md): no pantheon-* checkout, no platform imports.
Everything arrives over the `torana` CLI.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

# ─────────────────────────────────────────────────────────────────────────────
# The verdict set — ⛔ SERVED, NOT RESTATED.
#
# SUPPLY_GRAPH_SPEC.md § 3.4.1 is the canonical table, and it lives in the resolver. This
# module used to hold a hand-maintained copy of the ranks; that copy is gone.
#
# ⚠️ Every rank and customer_facing flag now arrives ON THE VERDICT, from the server that
# decided it — so adding a verdict stays a one-place edit and this file cannot drift from
# § 3.4.1 no matter what changes there.
#
# `verdict_vocabulary()` below fetches the whole table on demand (§ 3.16.7 step 2's
# `supply verdicts`), for the one caller that needs to reason about verdicts it has not
# been handed.
# ─────────────────────────────────────────────────────────────────────────────


def verdict_vocabulary(tenant_profile: str = "T1") -> dict[str, dict[str, Any]]:
    """The § 3.4.1 table, from the resolver. ⛔ Never a local restatement."""
    payload = _run_cli(
        ["datalake", "supply", "verdicts", "--format", "json"], tenant_profile
    )
    return {v["verdict"]: v for v in (payload.get("items") or [])}


class SupplyGraphError(RuntimeError):
    """Fail closed. Never emit a verdict computed from a partial view."""


# ─────────────────────────────────────────────────────────────────────────────
# Results — the interface contract. P6 must return these same shapes.
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Verdict:
    table: str
    column: str
    verdict: str
    #: Everything the renderer needs. Kept as plain data so an HTTP response can carry it.
    evidence: dict[str, Any] = field(default_factory=dict)
    #: § 3.6 — a filter column being empty explains the panel; a display column does not.
    load_bearing: bool = False
    clause: str | None = None
    #: ⛔ FROM THE SERVER (§ 3.4.1), never re-derived here. 1 = worst; None = deliberately
    #: NOT customer-facing (UNRESOLVED / LINEAGE_AMBIGUOUS mean "we could not trace this",
    #: which is our problem → neutral empty state + telemetry).
    rank: int | None = None
    #: ⚠️ SUPPLIED is RANKED (for § 3.4.2 worst-wins) but never messaged (§ 3.4.4), so this
    #: is not simply `rank is not None` and must not be inferred as such.
    customer_facing: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "column": self.column,
            "verdict": self.verdict,
            "rank": self.rank,
            "customer_facing": self.customer_facing,
            "load_bearing": self.load_bearing,
            "clause": self.clause,
            "evidence": self.evidence,
        }


@dataclass
class ForwardReport:
    integration: str
    connected: bool
    writes: list[tuple[str, str]]
    #: ⛔ THE blast radius. § 3.13.3: reading totals overstates it by >2x.
    sole_writes: list[tuple[str, str]]
    #: Columns dark today that connecting this integration would light up (§ 3.14.2 Q7/Q8).
    would_light: list[tuple[str, str]]

    def to_dict(self) -> dict[str, Any]:
        fmt = lambda ps: [f"{t}.{c}" for t, c in sorted(ps)]  # noqa: E731
        return {
            "integration": self.integration,
            "connected": self.connected,
            "writes_count": len(self.writes),
            "sole_writes_count": len(self.sole_writes),
            "would_light_count": len(self.would_light),
            "writes": fmt(self.writes),
            "sole_writes": fmt(self.sole_writes),
            "would_light": fmt(self.would_light),
        }


class SupplyGraph(Protocol):
    """⛔ The narrow interface. Callers use ONLY these two methods.

    P6 swaps the implementation; every caller keeps working.
    """

    def diagnose(self, columns: Iterable[tuple[str, str]]) -> list[Verdict]: ...

    def forward(self, integration: str) -> ForwardReport: ...


# ─────────────────────────────────────────────────────────────────────────────
# Inputs — two calls, TWO DIFFERENT PROFILES (§ 3.10.1).
#
# ⛔ THE PROFILE TRAP. This stops a fresh session cold:
#   reachable-columns  -> T1 (tenant)      carries WHICH integrations are connected
#   category-map       -> SA (super-admin) a tenant profile is REFUSED outright
# ─────────────────────────────────────────────────────────────────────────────


def _run_cli(args: list[str], profile: str) -> Any:
    if not shutil.which("torana"):
        raise SupplyGraphError(
            "the `torana` CLI is not on PATH. This skill talks to the platform only over "
            "the CLI (skills must not import platform code or read a checkout).\n"
            "  Fix: source $TORANA_ROOT/.venv/bin/activate"
        )
    env = {**os.environ, "TORANA_PROFILE": profile}
    proc = subprocess.run(
        ["torana", *args], capture_output=True, text=True, env=env, timeout=180
    )
    out = proc.stdout.strip()
    if proc.returncode != 0 or not out:
        raise SupplyGraphError(
            f"TORANA_PROFILE={profile} torana {' '.join(args)}\n"
            f"  exit={proc.returncode}\n  {(proc.stderr or out).strip()[:600]}"
        )
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        # The CLI prints a human-readable refusal on stdout with exit 0 when a tenant
        # profile hits an SA-only verb — so a parse failure here is usually THE TRAP.
        raise SupplyGraphError(
            f"TORANA_PROFILE={profile} torana {' '.join(args)} did not return JSON "
            f"({exc}).\n  first line: {out.splitlines()[0][:300] if out else '<empty>'}"
        ) from exc


@dataclass
class Inputs:
    """The CONTEXT a verdict is interpretable against — not the verdict inputs.

    ⚠️ `catmap` / `cats` are vestigial and always None: the skill no longer fetches the
    SUPER-ADMIN category half, because the server resolves it (§ 3.4.0). The fields are
    kept so any external caller constructing an `Inputs` keeps working.
    """

    reach: dict[str, Any]
    catmap: dict[str, Any] | None = None
    cats: dict[str, Any] | None = None
    category_error: str | None = None
    tenant_profile: str = "T1"
    #: ⛔ The SERVER's category state, read off a diagnosis response
    #: (`resolved_context.category_layer`). ⚠️ It must NOT be inferred from whether this
    #: process could reach an SA endpoint — that inference is what made every tenant-profile
    #: run look degraded when the server had resolved both halves perfectly well.
    server_category_layer: str | None = None

    @property
    def degraded(self) -> bool:
        return self.server_category_layer == "unavailable"


def fetch_inputs(
    tenant_profile: str = "T1",
    sa_profile: str = "SA",
    allow_degraded: bool = False,
) -> Inputs:
    """The context stamped onto a diagnosis — NOT the verdict inputs.

    ⛔ **The SA category fetch is GONE.** It existed because the skill computed verdicts
    itself and needed the category map to tell CATEGORY_MISSING from PEER_GAP. ⚠️ That map
    is SUPER-ADMIN-only, so a tenant-profile operator was refused and had to opt into a
    degraded run that lost both verdicts. The server now resolves both halves with a
    tenant-scoped service JWT (§ 3.4.0) — which is a substantive reason for the resolver to
    be server-side, not merely a tidier one.

    ⚠️ `sa_profile` / `allow_degraded` are accepted and ignored so existing callers and
    scripts keep working unchanged.

    What remains is the CONTEXT a verdict is only interpretable against: the column count
    and which integrations are connected. ⛔ Still fails closed — a partial view that keeps
    answering is worse than no answer, because nobody investigates a confident result.
    """
    reach = _run_cli(
        ["datalake", "reachable-columns", "--scope", "platform", "--explain",
         "--format", "json"],
        tenant_profile,
    )
    if "columns" not in reach:
        raise SupplyGraphError(
            "reachable-columns returned no `columns` key — refusing to diagnose from a "
            "partial view. A checker degraded to a partial view keeps answering, and its "
            "answers look authoritative."
        )
    # ⚠️ `degraded` now reports the SERVER's category state, read off the diagnosis
    # response rather than inferred from whether this process could reach an SA endpoint.
    return Inputs(reach, None, None, None, tenant_profile)




# ─────────────────────────────────────────────────────────────────────────────
# ⛔ P6 MIGRATION TARGET — this is the whole diff.
# ─────────────────────────────────────────────────────────────────────────────


#: ⚠️ How many columns to ask for per `diagnosis` call. `acceptance.py` diagnoses ALL 397
#: columns in one go, which as a single query string is ~12KB — past the point where
#: proxies and shells start truncating SILENTLY. Chunking is not an optimisation here; an
#: untruncated request is what stops the walk answering from a partial view.
_DIAGNOSIS_CHUNK = 60


class ApiTraversal:
    """⛔ THE ONE TRAVERSAL — a thin wrapper over the § 3.4.0 server-side resolver.

    Every verdict comes from `GET /api/v1/datalake/supply/{diagnosis,forward}`. This class
    computes nothing: it maps a response onto `Verdict` / `ForwardReport` and returns.

    ⚠️ **This is what closes the § 4.5 "one resolver" bar.** Until now the skill carried a
    full second copy of the § 3.4.1 verdict table (`LocalTraversal`, `_parse_mapping`, the
    rank map, the category plumbing). The two copies did not disagree — P6 was built from
    P0's rules and reproduced 11/11 of its § 3.13.1 verdicts — but ⛔ **nothing failed when
    they diverged**: both kept answering, confidently, and the divergence would reach a
    customer as two different answers about the same column.

    ⛔ P13 turned that risk into a real asymmetry: the server resolver gained
    `VERDICT_MEANING` (the internal-name → customer-sentence → owner mapping § 4.4 requires
    live in exactly ONE place) and the skill's copy never had it. That is what made this
    migration overdue rather than merely outstanding.

    Portability (skills/CLAUDE.md): everything arrives over the `torana` CLI. No platform
    import, no checkout.
    """

    def __init__(self, tenant_profile: str = "T1", inputs: "Inputs | None" = None):
        self.tenant_profile = tenant_profile
        self._columns_cache: list[dict[str, Any]] | None = None
        #: ⚠️ Written back so `resolved_context()` can report the SERVER's category state
        #: rather than this process's ability to reach an SA endpoint.
        self._inputs = inputs

    # -- the two interface methods -------------------------------------------

    def diagnose(self, columns: Iterable[tuple[str, str]]) -> list[Verdict]:
        """§ 3.2.1 backward walk, resolved server-side.

        ⚠️ Returns verdicts in the ORDER ASKED. `acceptance.py` zips its expectations
        against this list positionally, so a reordered result would silently compare the
        wrong verdict to the wrong column.
        """
        refs = list(columns)
        if not refs:
            return []

        out: list[Verdict] = []
        for i in range(0, len(refs), _DIAGNOSIS_CHUNK):
            chunk = refs[i:i + _DIAGNOSIS_CHUNK]
            payload = _run_cli(
                ["datalake", "supply", "column",
                 *[f"{t}.{c}" for t, c in chunk],
                 "--format", "json"],
                self.tenant_profile,
            )
            # ⛔ § 4.6(b) — a degraded category layer must be LOUD, and it is the SERVER
            # that knows. Recorded on the first response so the footer can say so.
            if self._inputs is not None:
                layer = (payload.get("resolved_context") or {}).get("category_layer")
                if layer:
                    self._inputs.server_category_layer = layer

            rows = payload.get("columns")
            if rows is None:
                raise SupplyGraphError(
                    "the supply API returned no `columns` key — refusing to report a "
                    "verdict computed from a partial view."
                )
            if len(rows) != len(chunk):
                # ⛔ Fail closed. A short response silently mis-pairs every verdict after
                # the gap, and a mis-paired verdict is a confident wrong answer.
                raise SupplyGraphError(
                    f"asked for {len(chunk)} columns and got {len(rows)} back — refusing "
                    f"to pair verdicts positionally against a response of the wrong length."
                )
            out.extend(
                Verdict(
                    table=r["table"],
                    column=r["column"],
                    verdict=r["verdict"],
                    evidence=r.get("evidence") or {},
                    # ⛔ Carried, not computed — this is what keeps § 3.4.1 a
                    # one-place edit.
                    rank=r.get("rank"),
                    customer_facing=bool(r.get("customer_facing")),
                )
                for r in rows
            )
        return out

    def forward(self, integration: str) -> ForwardReport:
        """§ 3.2.2 forward walk, resolved server-side.

        ⛔ An UNKNOWN name is an ERROR from the API (P13 step 1), not a confident zero —
        `_run_cli` surfaces it as `SupplyGraphError` naming the valid set. ⚠️ Before P13
        this returned "not connected; 0 columns would light up" for a typo, identical to
        the honest answer for a real tool that adds nothing.
        """
        payload = _run_cli(
            ["datalake", "supply", "integration", integration, "--format", "json"],
            self.tenant_profile,
        )
        return ForwardReport(
            integration=payload["integration"],
            connected=bool(payload.get("connected")),
            writes=_split_refs(payload.get("writes")),
            # ⚠️ `sole_writes` is the P7-era name the server keeps as an alias for
            # `sole_platform_wide`. The tenant-scoped measure (`sole_among_connected`) is
            # the real blast radius and is available on the payload; this dataclass's
            # field keeps its established meaning so existing output does not change
            # meaning silently.
            sole_writes=_split_refs(payload.get("sole_writes")),
            would_light=_split_refs(payload.get("would_light")),
        )

    # -- what the entry points also use --------------------------------------

    def _all(self) -> list[dict[str, Any]]:
        """Every resolvable column, fetched once (§ 3.16.7 step 2)."""
        if self._columns_cache is None:
            payload = _run_cli(
                ["datalake", "supply", "columns", "--format", "json"],
                self.tenant_profile,
            )
            self._columns_cache = payload.get("items") or []
        return self._columns_cache

    def all_columns(self) -> list[tuple[str, str]]:
        return [(c["table"], c["column"]) for c in self._all()]

    def known_integrations(self) -> set[str]:
        payload = _run_cli(
            ["datalake", "supply", "integrations", "--format", "json"],
            self.tenant_profile,
        )
        return {i["integration"] for i in (payload.get("items") or [])}

    def connected_integrations(self) -> dict[str, dict[str, Any]]:
        payload = _run_cli(
            ["datalake", "supply", "integrations", "--connected", "--format", "json"],
            self.tenant_profile,
        )
        return {i["integration"]: i for i in (payload.get("items") or [])}


def _split_refs(refs: Any) -> list[tuple[str, str]]:
    """`["t.c", …]` -> `[(t, c), …]`, the shape `ForwardReport` holds."""
    out: list[tuple[str, str]] = []
    for ref in refs or []:
        table, _, column = str(ref).rpartition(".")
        if table:
            out.append((table, column))
    return out


def build_supply_graph(
    tenant_profile: str = "T1",
    sa_profile: str = "SA",
    allow_degraded: bool = False,
) -> tuple[SupplyGraph, Inputs]:
    """⛔ THE ONLY constructor callers use — now returning `ApiTraversal`.

    ⚠️ `sa_profile` and `allow_degraded` are accepted and IGNORED, deliberately. They
    existed because the skill fetched the SUPER-ADMIN-only category map itself, and a
    tenant profile is refused by that endpoint — so a tenant-only operator lost
    CATEGORY_MISSING and PEER_GAP entirely and had to opt into a degraded run.

    ⛔ The server resolves BOTH halves with a tenant-scoped SERVICE JWT (§ 3.4.0), so a
    caller who could never resolve categories alone now gets them. The parameters are kept
    so every existing invocation and script keeps working; they are no longer meaningful.
    """
    inputs = fetch_inputs(tenant_profile)
    return ApiTraversal(tenant_profile, inputs), inputs


def resolved_context(inputs: Inputs) -> dict[str, Any]:
    """⚠️ The platform column count MOVED 4x WITHIN ONE DAY (384->389->395->397).

    That volatility is exactly why the count is stamped onto every diagnosis: a verdict is
    only interpretable against the column set it was resolved on (§ 3.3, § 3.10.1).
    """
    return {
        "reachable_column_count": inputs.reach.get("count"),
        "tenant_profile": inputs.tenant_profile,
        "connected_integrations": sorted(
            (inputs.reach.get("integrations") or {}).get("enabled", [])
        ),
        "category_layer": "unavailable" if inputs.degraded else "resolved",
        "category_error": inputs.category_error,
    }


def die(message: str, code: int = 2) -> None:
    """Fail closed, on stderr, with a named cause (skills/CLAUDE.md)."""
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)
