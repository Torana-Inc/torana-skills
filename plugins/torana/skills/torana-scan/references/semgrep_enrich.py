#!/usr/bin/env python3
"""semgrep_enrich.py — add Semgrep's false-positive signals to its own SARIF.

Semgrep's SARIF carries a rule's confidence only as free text in `tags`
(`LOW CONFIDENCE`), and carries impact, likelihood and subcategory (`vuln` for a confirmed
issue, `audit` for code worth reviewing) not at all. Its JSON output carries all four as
typed rule metadata. The Scan Pack runs Semgrep ONCE and writes both formats
(`--sarif --output <raw> --json-output=<raw>.semgrep.json`); this script copies the four
fields onto each matching SARIF result's `properties.torana`, under the same names.

Everything else stays exactly as Semgrep wrote it. In particular no severity, score or
CVSS field is added: Semgrep publishes none, and an invented `security-severity` would be
stored as a CVSS score (pantheon-tests docs/sarif_severity_cvss_contract_2026-09-15.md).
A field a rule does not declare is left out rather than defaulted — 29 of the 1,074
`--config auto` rules carry no confidence (15 Sep).

Usage (run by scan_pack.py as the semgrep engine's `post_process`):
    python3 semgrep_enrich.py --report semgrep.sarif.raw.json --engine semgrep \
        --output semgrep.sarif [--json semgrep.sarif.raw.json.semgrep.json]

Stdlib only, like the other Scan Pack helpers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Tuple

#: Semgrep rule metadata copied onto each SARIF result, keeping Semgrep's names and values.
SIGNAL_FIELDS = ("confidence", "impact", "likelihood", "subcategory")

#: Where the Scan Pack tells Semgrep to write its JSON copy, relative to the raw SARIF path.
JSON_SUFFIX = ".semgrep.json"


def _json_key(result: Dict[str, Any]) -> Tuple:
    """Location identity of a Semgrep JSON result: rule, path, start and end line/column."""
    start, end = result.get("start") or {}, result.get("end") or {}
    return (result.get("check_id"), result.get("path"),
            start.get("line"), start.get("col"), end.get("line"), end.get("col"))


def _sarif_key(result: Dict[str, Any]) -> Tuple:
    """The same identity read from a Semgrep SARIF result. Semgrep writes the same relative
    path and 1-based line/column into both formats (verified on pantheon-auth, 15 Sep)."""
    phys = ((result.get("locations") or [{}])[0] or {}).get("physicalLocation") or {}
    region = phys.get("region") or {}
    return (result.get("ruleId"), (phys.get("artifactLocation") or {}).get("uri"),
            region.get("startLine"), region.get("startColumn"),
            region.get("endLine"), region.get("endColumn"))


def _signals(result: Dict[str, Any]) -> Dict[str, Any]:
    """The four fields a Semgrep JSON result's rule declares, raw. Absent or empty → omitted."""
    meta = (result.get("extra") or {}).get("metadata") or {}
    return {k: meta[k] for k in SIGNAL_FIELDS if meta.get(k) not in (None, "", [])}


def enrich(sarif: Dict[str, Any], semgrep_json: Dict[str, Any]) -> Tuple[int, int]:
    """Copy the signals onto matching SARIF results in place. Returns (matched, unmatched).

    ⚠️ A queue per location, not a dict: one rule can match the same span twice, and each
    SARIF result must consume exactly one JSON result.
    """
    queues: Dict[Tuple, Deque[Dict[str, Any]]] = defaultdict(deque)
    for result in semgrep_json.get("results") or []:
        queues[_json_key(result)].append(_signals(result))
    matched = unmatched = 0
    for run in sarif.get("runs") or []:
        for result in run.get("results") or []:
            queue = queues.get(_sarif_key(result))
            if not queue:
                unmatched += 1
                continue
            fields = queue.popleft()
            matched += 1
            if fields:
                torana = result.setdefault("properties", {}).setdefault("torana", {})
                for key, value in fields.items():
                    torana.setdefault(key, value)
    return matched, unmatched


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", required=True, help="Semgrep's raw SARIF output.")
    ap.add_argument("--json", default=None,
                    help=f"Semgrep's JSON output (default: <report>{JSON_SUFFIX}).")
    ap.add_argument("--engine", default="semgrep", help="Engine name (accepted for the Scan Pack's post_process call).")
    ap.add_argument("--output", required=True, help="Enriched SARIF to write.")
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as fh:
        sarif = json.load(fh)

    json_path = args.json or (args.report + JSON_SUFFIX)
    semgrep_json: Dict[str, Any] = {}
    if os.path.exists(json_path):
        with open(json_path, encoding="utf-8") as fh:
            semgrep_json = json.load(fh)
    else:
        # ⚠️ Still write the SARIF: failing here would drop every Semgrep finding to save
        # four fields. The warning is the signal that confidence and the rest are missing.
        print(f"WARNING: {args.engine}: no JSON output at {json_path}; confidence, impact, "
              f"likelihood and subcategory were NOT added", file=sys.stderr)

    matched, unmatched = enrich(sarif, semgrep_json) if semgrep_json else (0, 0)
    if semgrep_json and unmatched:
        print(f"WARNING: {args.engine}: {unmatched} SARIF result(s) had no matching JSON "
              f"result; their false-positive signals were NOT added", file=sys.stderr)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    print(f"{args.engine}: signals added to {matched} result(s) -> {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
