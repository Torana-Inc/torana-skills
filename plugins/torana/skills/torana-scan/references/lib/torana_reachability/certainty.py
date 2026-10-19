"""Certainty: when an absence is `known` (REACHABILITY_EXTRACTOR.md § 3.11.5). Read by the ranking (§ 3.13).

`known` only when ALL of K1-K5 hold; else `believed`, with the unmet codes so a card can say what would make it
`known` ("select the shared library"). Only `not_imported` can be `known` in v1 (Bhakta's rule names only "shipped,
imported by nothing"); any other verdict is `believed` with no unmet code (nothing would make it `known`).

| K  | Condition |
|----|-----------|
| K1 | state is `measured` / `measured_at_other_commit` with a non-null `alert_commit`, or the subject is `repository`
|    | and the fact's commit equals the newest scanned commit the caller holds (`commit_matches_scanned`) |
| K2 | `components_complete` |
| K3 | the requirement graph is complete for the ecosystem, and the package has NO ancestor in it (until OI-127's
|    | entry-point view exists, any ancestor -> `believed`: a plugin loaded by entry point imports what no line names) |
| K4 | zero `dynamic_nonliteral` records at runtime paths of the ecosystem, in every component |
| K5 | the ecosystem's `_ABSENCE` entry is None |
| K6 | pypi only: the package's stored `distribution.basis` is measured (`mapping_table`, `wheel_metadata` or
|    | `first_party_pyproject`); `convention` (a guess from the name) or no record is unmet (OI-160, CODE_WALKER.md
|    | § 3.3.6.4). Read from the STORED basis, so a format-1 document is judged by what it holds |
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from .firstparty import normalize
from .grammar import _ABSENCE, BASIS_MEASURED

KNOWN = "known"
BELIEVED = "believed"

#: The family a `dynamic_nonliteral` record of an ecosystem can load (a Python importlib cannot load a Go module).
_DYNAMIC_FAMILY = {"pypi": "pypi", "npm": "npm"}


def ancestors(graph: Iterable[Dict[str, Any]], package: str, ecosystem: str) -> List[str]:
    """Every package that requires `package` in the requirement records (direct parents only), sorted."""
    eco = (ecosystem or "").lower()
    want = _norm(package, eco)
    return sorted({r["package"] for r in graph
                   if r.get("kind") == "requirement" and r["ecosystem"] == eco
                   and want in {_norm(x, eco) for x in r.get("requires") or ()}})


def _norm(name: str, eco: str) -> str:
    return normalize(name) if eco == "pypi" else (name or "")


def certainty(verdict: Optional[str], *, ecosystem: Optional[str], package: Optional[str], subject: str,
              state: str, alert_commit: Optional[str], commit_matches_scanned: bool,
              components_complete: bool, graph_complete: bool, graph: Iterable[Dict[str, Any]],
              dynamic_nonliteral: Iterable[Dict[str, Any]], basis: Optional[str] = None) -> Tuple[str, List[str]]:
    """`(certainty, unmet K-codes)` for one answer. See the module docstring for K1-K6. `basis`: the package's stored
    `distribution.basis` (None = no record, which K6 treats as `convention`)."""
    if verdict != "not_imported":
        return BELIEVED, []
    eco = (ecosystem or "").lower()
    unmet: List[str] = []
    k1 = ((state in ("measured", "measured_at_other_commit") and alert_commit)
          or (subject == "repository" and commit_matches_scanned))
    if not k1:
        unmet.append("K1")
    if not components_complete:
        unmet.append("K2")
    if not graph_complete or ancestors(graph, package or "", eco):
        unmet.append("K3")
    family = _DYNAMIC_FAMILY.get(eco)
    if family and any(r.get("ecosystem") == family and r.get("runtime") for r in dynamic_nonliteral):
        unmet.append("K4")
    if _ABSENCE.get(eco, "unknown ecosystem") is not None:
        unmet.append("K5")
    if eco == "pypi" and basis not in BASIS_MEASURED:
        unmet.append("K6")
    return (KNOWN if not unmet else BELIEVED), unmet
