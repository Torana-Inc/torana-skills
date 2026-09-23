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
from typing import Any, Deque, Dict, List, Optional, Tuple

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


def _ruleset_prefixes(ruleset: Optional[str]) -> List[str]:
    """Dotted prefixes semgrep prepends to every rule id when rules load from a FILE.

    ⛔ SEMGREP NAMES A RULE AFTER WHERE IT WAS LOADED FROM. Given `--config <path>` it
    derives the id as `<path with / -> .>.<the rule's own id>`; only a REGISTRY config
    (`--config auto`, `p/default`) yields the bare `python.flask.security…` form.

    ⚠️ MEASURED CONSEQUENCE, Classie 2026-09-23. Pinning the ruleset (a fix for the
    unpinned-ruleset and telemetry bugs) switched semgrep from the registry to a local
    file, so every rule id became 222 characters beginning
    `home.<user>..claude.plugins.cache.torana-skills.torana.0.3.1.…`. Three things broke
    at once, none of them loudly:

      * The server's SAST fingerprint hashes the ruleId, so EVERY finding was re-keyed.
        classie-tenant-manager went 34 -> 68 rows at an UNCHANGED commit — the same
        findings under two identities, both Open.
      * The id embeds the plugin VERSION, so the next release would re-key them again.
      * It embeds the operator's HOME DIRECTORY — a machine-local path, and their Linux
        username, in a stored identifier the customer can see. Two operators scanning one
        repo would also produce different ids for the same rule.

    So the id is normalised back to its registry form here. The prefix is the ruleset's
    DIRECTORY, dotted — and nothing else.

    ⛔ DO NOT ALSO STRIP THE FILENAME, ITS STEM, OR A `.yaml.` TOKEN. v2.8.1 did, and it
    corrupted every YAML-language rule id. Semgrep emits `<dotted dir>.<the rule's OWN
    id>`, and a YAML-language rule's own id legitimately BEGINS with `yaml.`:

        …references.scan_pack.rules.  +  yaml.kubernetes.security.run-as-non-root…
        ^ the directory                  ^ the rule's real id, `yaml.` included

    Read as `<dir>.<stem->yaml>.` that looks like a filename token, so v2.8.1 stripped it
    and produced `kubernetes.security.run-as-non-root…` — a DIFFERENT id from the one the
    registry uses and the server already stores. It would have re-keyed 34 rules' worth of
    findings (the GitHub Actions, Kubernetes and docker-compose rules): the very defect
    this function exists to prevent, on a smaller set. Caught before any push.

    ⚠️ The local test that let it through scanned a repo with no YAML-language findings,
    so every id began with `python.`/`dockerfile.`/`generic.` and the bad candidate never
    matched. A fixture must include a rule whose own id starts with `yaml.`.
    """
    if not ruleset:
        return []
    directory = os.path.dirname(os.path.abspath(ruleset))
    return [directory.lstrip(os.sep).replace(os.sep, ".") + "."]


def _normalize_rule_ids(sarif: Dict[str, Any], prefixes: List[str]) -> int:
    """Strip a file-derived prefix from every rule id, in results AND the rule table.

    ⚠️ BOTH, or the document stops resolving: a `result.ruleId` is a reference into
    `tool.driver.rules[].id`, so rewriting one side alone orphans every finding from its
    rule metadata (name, help, tags).
    """
    if not prefixes:
        return 0

    def strip(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        for p in prefixes:
            if value.startswith(p):
                return value[len(p):]
        return value

    changed = 0
    for run in sarif.get("runs") or []:
        for rule in (((run.get("tool") or {}).get("driver") or {}).get("rules") or []):
            new = strip(rule.get("id"))
            if new != rule.get("id"):
                rule["id"] = new
                changed += 1
        for result in run.get("results") or []:
            new = strip(result.get("ruleId"))
            if new != result.get("ruleId"):
                result["ruleId"] = new
                changed += 1
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", required=True, help="Semgrep's raw SARIF output.")
    ap.add_argument("--ruleset", default=None,
                    help="Path to the pinned ruleset, when rules came from a file. Used "
                         "to strip the path-derived prefix semgrep puts on every rule id.")
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

    renamed = _normalize_rule_ids(sarif, _ruleset_prefixes(args.ruleset))
    if renamed:
        print(f"{args.engine}: normalised {renamed} file-derived rule id(s) back to their "
              f"registry form (see _ruleset_prefixes)", file=sys.stderr)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    print(f"{args.engine}: signals added to {matched} result(s) -> {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
