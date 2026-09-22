#!/usr/bin/env python3
"""
build_sarif.py — assemble a multi-run, Torana-profile SARIF 2.1.0 document.

Replaces the proprietary build_envelope.py. The torana-scan skill calls this to
turn its sub-scan outputs into ONE SARIF document with one `run[]` per engine:

  - claude_review : Claude's SAST / IaC / Secret / Container findings
  - osv           : SCA findings from osv_lookup.py
  - <semgrep run> : merged verbatim from `semgrep --sarif`, then enriched

Every run is stamped with `versionControlProvenance` (so the findings are NOT
keyless — they link to the source-neutral repository id server-side), an
`automationDetails.id` (scan id, used for idempotency), and `invocations` (scan
time). Engine-native SARIF (semgrep) is merged as-is and only enriched.

The document is pushed with `torana ingest sarif <doc>`. Governance (criticality,
owner, SLA) travels the SEPARATE asset path (`torana ingest assets`) — this
script optionally mirrors it into `run.properties.torana.target` for context, but
that is not the authoritative governance channel.

This script is intentionally dependency-free (stdlib only) so it runs in the
skill sandbox.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import secrets
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional

SARIF_VERSION = "2.1.0"

_WS_RE = re.compile(r"\s+")

# Native-SARIF engines the Scan Pack merges through `_enrich_run` (S1). The value
# is the Torana `scan_type` to stamp on each result when the native tool does not
# carry a `properties.torana.scan_type` of its own. `None` = mixed/unknown — leave
# whatever the tool emitted (or nothing) untouched.
_NATIVE_ENGINES = {
    "semgrep": "SAST",
    "trivy-config": "IaC",
    "trivy-image": "Container",
    "trivy-fs": None,        # filesystem scan can mix vuln/secret/misconfig
    "trivy": None,
    "gitleaks": "Secret",
    "trufflehog": "Secret",
    "codeql": "SAST",
    "vvah": "SAST",          # Visa harness deep tier (SC2) — agentic SAST, merged via vvah_run.py
}

# Engines whose findings can carry a live secret value — their runs are redacted
# at the write boundary (S2) before the SARIF leaves the host.
_SECRET_ENGINES = {"gitleaks", "trufflehog"}

_REDACTED = "[REDACTED]"


def _norm_snippet(s: Optional[str]) -> str:
    """Whitespace-normalized snippet — collapse runs of whitespace and trim, so
    reindentation / reflow of the same code does not change the finding's
    identity."""
    return _WS_RE.sub(" ", (s or "").strip())


def _occurrences(findings: List[Dict[str, Any]]) -> List[int]:
    """Stable occurrence ordinal for each finding among others that share the
    same (rule_id, file, normalized snippet).

    Ordered by line so the ordinal survives line drift: when an unrelated
    finding earlier in the file is fixed and everything below shifts up, the
    relative order of identical snippets is preserved, so each keeps its ordinal.
    Returns a list parallel to `findings`.
    """
    groups: Dict[tuple, List[tuple]] = defaultdict(list)
    for i, f in enumerate(findings):
        coords = f.get("coordinates") or {}
        file_ = f.get("file") or coords.get("file") or ""
        snippet_ = f.get("code_snippet") or coords.get("code_snippet") or ""
        line_ = f.get("line") if f.get("line") is not None else coords.get("line")
        rid = f.get("rule_id") or "claude.finding"
        groups[(rid, file_, _norm_snippet(snippet_))].append(
            (line_ if isinstance(line_, int) else 0, i)
        )
    occ = [0] * len(findings)
    for items in groups.values():
        for ordinal, (_line, i) in enumerate(sorted(items)):
            occ[i] = ordinal
    return occ

# Title-case severity -> SARIF `level`, for any SARIF consumer. An unrecognised rating
# (e.g. Unknown) falls back to `warning`.
#
# ⛔ NO SCORE COLUMN, and there used to be one (Critical 9.5, High 8.0, Medium 5.5, Low 3.0,
# Info 0.0) written as `security-severity` whenever a finding had no real CVSS score. The
# ingestor read it as a real score: 63 findings Trivy could not rate were stored as Medium
# on Classie's images, and the number was copied into `cvss_base_score` as a CVSS score no
# scanner reported. The platform now takes severity from `scanner_severity` and the real
# CVSS fields (severity/CVSS contract, release 2), so a finding with no real score simply
# carries no `security-severity`.
_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "none",
}


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _gen_scan_id() -> str:
    import base64
    return "01" + base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")[:24]


def _git(repo: str, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def _load_json(path: Optional[str]) -> Any:
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _result_from_finding(f: Dict[str, Any], occurrence: int = 0) -> Dict[str, Any]:
    """Convert one Claude/OSV finding dict into a SARIF result.

    `occurrence` is the stable ordinal among identical SAST snippets in the same
    file (see _occurrences); it disambiguates genuine duplicates without using an
    absolute line number.
    """
    severity = f.get("severity") or "Medium"
    level = _LEVEL.get(severity, "warning")

    # Accept both the new flat shape (file/line/code_snippet) and the legacy
    # osv_lookup shape (coordinates.{file,line,code_snippet}).
    coords = f.get("coordinates") or {}
    file_ = f.get("file") or coords.get("file")
    line_ = f.get("line") if f.get("line") is not None else coords.get("line")
    snippet_ = f.get("code_snippet") or coords.get("code_snippet")

    region: Dict[str, Any] = {}
    if line_ is not None:
        region["startLine"] = line_
    if snippet_:
        region["snippet"] = {"text": snippet_}

    locations = []
    if file_:
        phys: Dict[str, Any] = {"artifactLocation": {"uri": file_}}
        if region:
            phys["region"] = region
        locations.append({"physicalLocation": phys})

    torana: Dict[str, Any] = {"scan_type": f.get("scan_type") or f.get("type") or "SAST"}
    if f.get("cve_id"):
        torana["cve_id"] = f["cve_id"]
    if f.get("package"):
        torana["package"] = f["package"]
    # ⛔ `cvss3_base_score` BELONGS IN THIS LIST and was missing from it. The producer
    # computes the advisory's real score, the Torana ingestor reads
    # `properties.torana.cvss3_base_score` and stores it — but nothing carried it between
    # the two, so every finding reached the platform with only the band constant below
    # and `cvss_base_score` was a rounded stand-in for a number we already had. The
    # CVE-cache enrichment fills empty columns only, so it never corrected the substitute.
    # ⚠️ `vulnerability_status` is passed through RAW (Trivy's 8-value enum:
    # affected / fixed / will_not_fix / fix_deferred / …). The SERVER folds it via
    # normalize_status() — the same gate the native-Trivy mapping uses — so the skill
    # must not pre-translate it into Title Case here. Two normalisers would be two
    # vocabularies, and the one that drifts is the one nobody is looking at.
    # ⭐ `image` is the container finding's attach point — the DIGEST-pinned ref of the
    # image it was found in. The server runs it through image_key(), so the short form a
    # scanner reports meets the same `image:` node the registry/kubernetes syncs write.
    # ⭐ The severity/CVSS contract fields (pantheon-tests
    # docs/sarif_severity_cvss_contract_2026-09-15.md): the scanner's own rating and whose
    # it is, and each CVSS score with the vector and source it came from. All sent RAW —
    # the platform decides severity (the stronger of the rating and the CVSS band), so the
    # skill must not title-case, map or combine them here.
    for k in ("exploit_available", "is_zero_day", "is_fix_available",
              "exploit_code_maturity", "epss_score", "first_seen_at",
              "cvss3_base_score", "vulnerability_status", "image", "advisory_id",
              "scanner_severity", "severity_source",
              "cvss3_vector", "cvss3_source",
              "cvss4_base_score", "cvss4_vector", "cvss4_source",
              "cvss2_base_score", "cvss2_vector", "cvss2_source"):
        if f.get(k) is not None:
            torana[k] = f[k]

    # ⭐ `security-severity` comes ONLY from a real CVSS score: v3, else v4. Never from the
    # rating. SARIF consumers read it as a score, so a band constant here would publish a
    # number nobody computed. A finding with no real score carries no `security-severity`;
    # its rating travels as `torana.scanner_severity`, which the platform uses instead.
    _real = f.get("cvss3_base_score")
    if _real is None:
        _real = f.get("cvss4_base_score")
    props: Dict[str, Any] = {"torana": torana}
    if _real is not None:
        props["security-severity"] = str(_real)

    result: Dict[str, Any] = {
        "ruleId": f.get("rule_id") or "claude.finding",
        "level": level,
        "message": {"text": f.get("title") or f.get("description") or "finding"},
        "properties": props,
        "locations": locations,
    }
    if f.get("cwe"):
        # The ingestor reads CWE from result.taxa[].id first.
        result["taxa"] = [{"id": f["cwe"]}]
    # Deterministic fingerprint so the skill and server agree on identity.
    # Drift-resistant: NO absolute line number is hashed, so re-scanning after an
    # unrelated finding earlier in the file is fixed keeps the same id (the line
    # shift no longer mints a new row + orphans the old one).
    #
    #   SCA  -> tool- and path-neutral key (ecosystem, package, version, CVE):
    #           the same CVE on the same dependency version dedups regardless of
    #           which manifest/scanner found it, and distinct CVEs on one package
    #           stay distinct (CVE is in the key).
    #   SAST -> (rule, file, normalized snippet, occurrence ordinal): line-drift
    #           safe, with the ordinal disambiguating identical snippets.
    pkg = f.get("package") or {}
    scan_type = (f.get("scan_type") or f.get("type") or "").upper()
    if pkg and (scan_type == "SCA" or f.get("cve_id")):
        ident = f.get("cve_id") or (f.get("raw") or {}).get("osv_id") or ""
        raw = "|".join([
            "sca", (pkg.get("manager") or ""), pkg.get("name", "") or "",
            pkg.get("version", "") or "", ident,
        ])
    else:
        raw = "|".join([
            "sast", result["ruleId"], file_ or "",
            _norm_snippet(snippet_), str(occurrence),
        ])
    result["partialFingerprints"] = {"toranaSkill/v1": hashlib.sha256(raw.encode()).hexdigest()[:32]}
    return result


def _rules_from_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rid = f.get("rule_id") or "claude.finding"
        if rid in seen:
            continue
        rule: Dict[str, Any] = {
            "id": rid,
            "shortDescription": {"text": f.get("title") or rid},
        }
        if f.get("description"):
            rule["fullDescription"] = {"text": f["description"]}
        tags = []
        if f.get("cwe"):
            tags.append(f["cwe"])
        scan_type = f.get("scan_type") or f.get("type")
        if scan_type:
            tags.append(scan_type)
        if tags:
            rule["properties"] = {"tags": tags}
        remediation = f.get("remediation") or f.get("remediation_hint")
        if remediation:
            rule["help"] = {"text": remediation}
        seen[rid] = rule
    return list(seen.values())


def _engine_run(
    name: str,
    findings: List[Dict[str, Any]],
    *,
    repo_uri: Optional[str],
    commit: Optional[str],
    scan_id: str,
    scanned_at: str,
    version: str = "skill-1.0",
) -> Dict[str, Any]:
    return _enrich_run(
        {
            "tool": {"driver": {
                "name": name,
                "version": version,
                "rules": _rules_from_findings(findings),
            }},
            "results": [
                _result_from_finding(f, occ)
                for f, occ in zip(findings, _occurrences(findings))
            ],
        },
        repo_uri=repo_uri, commit=commit, scan_id=scan_id, scanned_at=scanned_at,
    )


def _enrich_run(
    run: Dict[str, Any],
    *,
    repo_uri: Optional[str],
    commit: Optional[str],
    scan_id: str,
    scanned_at: str,
) -> Dict[str, Any]:
    """Stamp VCP + automationDetails + invocations so the run links + idempotency
    works. Used for our own runs AND to enrich a merged semgrep run."""
    if repo_uri:
        vcp = {"repositoryUri": repo_uri}
        if commit:
            vcp["revisionId"] = commit
        run.setdefault("versionControlProvenance", [vcp])
    run.setdefault("automationDetails", {"id": scan_id, "correlationGuid": scan_id})
    # ⛔ NOT `setdefault` ON THE LIST. A native-SARIF engine writes its own `invocations`,
    # and Semgrep's carries no time (`[{"executionSuccessful": true,
    # "toolExecutionNotifications": []}]`), so setdefault left the run with no scan time at
    # all. The ingestor reads `endTimeUtc` then `startTimeUtc` and otherwise stores NULL:
    # measured 2026-09-15, all 7 ingested Semgrep findings had scan_first_detected_date and
    # scan_last_detected_date NULL while Trivy's 116 carried them. Silent — the rows land
    # and look complete, but no SAST finding can be aged, trended or SLA'd.
    #
    # ⚠️ Fill only what is MISSING. The tool's own `executionSuccessful: false` is
    # load-bearing (an unserved scan type stamps it, S3), and a time the tool reported is
    # more accurate than ours.
    invocations = run.get("invocations") or [{"executionSuccessful": True}]
    for invocation in invocations:
        invocation.setdefault("endTimeUtc", scanned_at)
    run["invocations"] = invocations
    return run


def _stamp_scan_type(run: Dict[str, Any], scan_type: Optional[str]) -> None:
    """Stamp `properties.torana.scan_type` on every result of a merged native run
    when the tool did not set one itself. Lets Trivy/Gitleaks findings carry the
    Torana profile the ingestor keys on, without each tool knowing about it."""
    if not scan_type:
        return
    for r in run.get("results") or []:
        props = r.setdefault("properties", {})
        torana = props.setdefault("torana", {})
        torana.setdefault("scan_type", scan_type)


def _redact_secret_run(run: Dict[str, Any]) -> None:
    """Mask secret values in a secrets-engine run BEFORE the SARIF is written, so a
    verified credential never propagates into the lake (S2). The line/snippet that
    contains the secret is the leak vector; the rule/message/location stay intact so
    the finding is still actionable ("secret at file:line"), just not the value.

    Conservative: blanks the matched region snippet and any `properties` field whose
    name hints at a raw value. The deterministic fingerprint (a hash, computed by the
    tool) is left as-is so dedup still works.
    """
    for r in run.get("results") or []:
        for loc in r.get("locations") or []:
            region = (loc.get("physicalLocation") or {}).get("region") or {}
            if "snippet" in region:
                region["snippet"] = {"text": _REDACTED}
        props = r.get("properties") or {}
        for key in list(props.keys()):
            if key.lower() in ("secret", "match", "raw", "value", "secret_value"):
                props[key] = _REDACTED


def _stamp_coverage(run: Dict[str, Any], coverage: Optional[Dict[str, Any]]) -> None:
    """Record what the engine actually LOOKED AT on the run, beside its findings.

    ⚠️ Why this exists. A finding count alone is not a result — "294 findings" and
    "294 findings, and 31 files the parser could not read" are different claims, and
    the document only ever carried the first. Engine parse errors did survive (SARIF
    `invocations[].toolExecutionNotifications`, which `_enrich_run` preserves), but
    SCOPE never did: `paths.scanned` lives only in the engine's native JSON, so the
    one number that makes a count interpretable — how many files were examined —
    stopped at the scanner and never reached the ingestor. Working out that 386 files
    went unread took diffing `git ls-files` against a sidecar by hand, after the fact.

    Lands at `run.properties.torana.coverage` so it travels with the run it describes
    (each engine covers a different file set, so this cannot be document-level).
    """
    if not coverage:
        return
    props = run.setdefault("properties", {})
    props.setdefault("torana", {})["coverage"] = coverage


def _stamp_fingerprints(run: Dict[str, Any]) -> None:
    """Give every SCA result in a MERGED native run the same `toranaSkill/v1`
    partialFingerprint our own SCA findings get.

    ⚠️ Why this exists. `_enrich_run` gave a merged run provenance, a scan id and a
    scan_type, but never an identity — only findings built by `_result_from_finding`
    (Claude review + OSV) were fingerprinted. Measured on classie_backend: osv 14/14
    fingerprinted, trivy/semgrep 0. Key is the same as `_result_from_finding`'s SCA
    key — (ecosystem, package, version, CVE), tool- and path-neutral — so the same CVE
    on the same dependency version carries one id whether Trivy or OSV reported it.

    ⛔ SCA ONLY — do NOT extend this to SAST/IaC/secret results. The ingestor
    (pantheon-integration `torana_mesh/etl/ingestors/sarif.py::_fingerprint`) PREFERS a
    usable client `partialFingerprints` value as the row key for every non-SCA result,
    and otherwise synthesizes `sast|asset_key|ruleId|uri|norm_snippet|occurrence` —
    already line-drift safe. Stamping non-SCA results would buy no stability and would
    RE-KEY every existing SAST row, stranding what hangs off `torana_vulnerability_id`
    (compensating controls, pentest verdicts, alert links). For SCA the ingestor
    deliberately ignores client fingerprints, so this stamp is inert server-side and
    only gives the document itself an identity.

    The SCA test mirrors the ingestor's (`package` present and scan_type SCA or a
    cve_id), so exactly the results the server keys itself are stamped.
    An existing `partialFingerprints` map is preserved — we only add our key.
    """
    for r in run.get("results") or []:
        torana = (r.get("properties") or {}).get("torana") or {}
        pkg = torana.get("package") or {}
        ident = torana.get("cve_id") or ""
        if not (pkg and (str(torana.get("scan_type") or "").upper() == "SCA" or ident)):
            continue
        raw = "|".join([
            "sca", (pkg.get("manager") or ""), pkg.get("name", "") or "",
            pkg.get("version", "") or "", ident,
        ])
        fp = hashlib.sha256(raw.encode()).hexdigest()[:32]
        r.setdefault("partialFingerprints", {})["toranaSkill/v1"] = fp


def _merge_native_sarif(
    runs: List[Dict[str, Any]],
    engine: str,
    doc: Dict[str, Any],
    *,
    repo_uri: Optional[str],
    commit: Optional[str],
    scan_id: str,
    scanned_at: str,
    coverage: Optional[Dict[str, Any]] = None,
) -> None:
    """Merge a native-SARIF document from one engine into `runs`, enriching every
    run with provenance/scan-id (so it is not keyless), stamping the engine's
    `scan_type`, and redacting secret values for secret engines. This is the single
    path Trivy / Gitleaks / semgrep / any SARIF-native tool ride (S1)."""
    scan_type = _NATIVE_ENGINES.get(engine)
    is_secret = engine in _SECRET_ENGINES
    for run in (doc.get("runs") or []):
        # Name the driver after the engine so per-engine attribution survives the merge.
        if engine:
            run.setdefault("tool", {}).setdefault("driver", {})["name"] = engine
        _enrich_run(run, repo_uri=repo_uri, commit=commit, scan_id=scan_id, scanned_at=scanned_at)
        _stamp_scan_type(run, scan_type)
        if is_secret:
            _redact_secret_run(run)
        # After redaction — see _stamp_fingerprints' docstring.
        _stamp_fingerprints(run)
        _stamp_coverage(run, coverage)
        runs.append(run)


def _parse_merge_arg(spec: str) -> tuple[str, str]:
    """`engine=path` → (engine, path). A bare `path` → ("", path) (no rename/stamp)."""
    if "=" in spec:
        engine, path = spec.split("=", 1)
        return engine.strip(), path.strip()
    return "", spec.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Assemble a Torana-profile SARIF document.")
    ap.add_argument("--findings", help="JSON list of Claude findings (SAST/IaC/Secret/Container).")
    ap.add_argument("--osv", help="JSON list of OSV/SCA findings (from osv_lookup.py).")
    ap.add_argument("--semgrep-sarif", help="Raw `semgrep --sarif` output to merge + enrich (alias for --merge-sarif semgrep=<path>).")
    ap.add_argument(
        "--coverage", action="append", default=[], metavar="ENGINE=PATH",
        help="Coverage JSON for a merged engine (files scanned, parse failures, timeouts) "
             "-> run.properties.torana.coverage. Repeatable.")
    ap.add_argument(
        "--merge-sarif", action="append", default=[], metavar="ENGINE=PATH",
        help="Merge a native-SARIF document from one engine (repeatable). "
             "ENGINE ∈ {semgrep, trivy-config, trivy-image, gitleaks, ...}; a bare PATH merges verbatim. "
             "Secret engines (gitleaks/trufflehog) are redacted at the write boundary.",
    )
    ap.add_argument("--asset", help="asset-inventory.json — mirrors governance into properties.torana.target.")
    ap.add_argument("--repo", default=".", help="Repo path (for git remote + commit). Default: cwd.")
    ap.add_argument("--repository-uri", help="Explicit repo URI (overrides git remote).")
    ap.add_argument("--commit", help="Explicit commit sha (overrides git HEAD).")
    ap.add_argument("--base", help="Base commit sha for a diff-scan (T3). When set, stamped run-level "
                                   "as run.properties.torana.base_revision so a later ingest can carry "
                                   "the base marker for the fixed/new/unchanged delta.")
    ap.add_argument("--scan-id", help="Scan id (generated if omitted).")
    ap.add_argument("--output", default="./scan.sarif", help="Output path.")
    args = ap.parse_args()

    asset = _load_json(args.asset) or {}
    # Repo-URI precedence (so the scan CONVERGES on the same repositories row as
    # the asset record — design D3):
    #   1. --repository-uri (explicit override)
    #   2. the asset file's asset_ref — AUTHORITATIVE identity. If you pass
    #      --asset, the scan keys to the asset, not the raw git remote. This
    #      matters when the remote owner differs from the canonical one
    #      (e.g. a fork/redirect: remote=gopikris-talos but canonical=Torana-Inc).
    #   3. the git remote (origin)
    # ⛔ STATED vs DERIVED, and the difference is load-bearing for container scans.
    # `--repository-uri` (or an asset's asset_ref) is the caller ASSERTING which repo this
    # came from. The git remote is a GUESS from wherever the scanner happened to run — and
    # `--repo` defaults to ".", so a container scan launched from any checkout would adopt
    # that checkout and its current commit as the source of the image's findings, silently.
    # Once pushed, nginx's CVEs appear as findings in someone's application code: wrong
    # owner, wrong commit, and a repo->image link nobody asserted. An image is not built
    # from the directory you happen to stand in.
    repo_uri_stated = args.repository_uri or (asset.get("asset_ref") if asset else None)
    repo_uri_derived = _git(args.repo, "remote", "get-url", "origin")
    repo_uri = repo_uri_stated or repo_uri_derived
    commit = args.commit or _git(args.repo, "rev-parse", "HEAD")
    scan_id = args.scan_id or _gen_scan_id()
    scanned_at = _now_iso()

    runs: List[Dict[str, Any]] = []

    claude_findings = _load_json(args.findings) or []
    # A Claude-review finding's `severity` IS the engine's own rating (Claude judged it; no
    # score was banded), so it travels as `scanner_severity` with its source named. Without
    # it, once the placeholder scores stop (release 2 of the severity/CVSS contract), the
    # platform would read these findings as unrated.
    for f in claude_findings:
        if f.get("severity") and not f.get("scanner_severity"):
            f["scanner_severity"] = f["severity"]
            f["severity_source"] = "claude_review"
    if claude_findings:
        runs.append(_engine_run(
            "claude_review", claude_findings,
            repo_uri=repo_uri, commit=commit, scan_id=scan_id, scanned_at=scanned_at,
        ))

    osv_findings = _load_json(args.osv) or []
    if osv_findings:
        for f in osv_findings:
            f.setdefault("scan_type", "SCA")
        runs.append(_engine_run(
            "osv", osv_findings,
            repo_uri=repo_uri, commit=commit, scan_id=scan_id, scanned_at=scanned_at,
        ))

    # Native-SARIF engines (Trivy, Gitleaks, semgrep, …) all merge through one path.
    # --semgrep-sarif is kept as a back-compat alias for --merge-sarif semgrep=<path>.
    merge_specs: List[tuple[str, str]] = []
    if args.semgrep_sarif:
        merge_specs.append(("semgrep", args.semgrep_sarif))
    merge_specs.extend(_parse_merge_arg(spec) for spec in args.merge_sarif)
    coverage_by_engine = {eng: (_load_json(p) or None)
                          for eng, p in (_parse_merge_arg(s) for s in args.coverage)}
    for engine, path in merge_specs:
        native_doc = _load_json(path) or {}
        # A CONTAINER run gets a repository only when one was STATED. Its identity is the
        # image digest, which `trivy_to_sarif.py` already puts in `torana.image`; a guessed
        # repo would be a claim the caller never made. Every other engine scans the
        # checkout, so the derived remote is the right answer for them.
        _is_container = _NATIVE_ENGINES.get(engine) == "Container"
        _run_repo = repo_uri_stated if _is_container else repo_uri
        _run_commit = (args.commit if _is_container else commit)
        _merge_native_sarif(
            runs, engine, native_doc,
            repo_uri=_run_repo, commit=_run_commit, scan_id=scan_id, scanned_at=scanned_at,
            coverage=coverage_by_engine.get(engine),
        )

    if not runs:
        print("ERROR: no findings provided (need at least one of --findings/--osv/--semgrep-sarif)",
              file=sys.stderr)
        return 2

    # Mirror governance into each run's torana profile (context only; the asset
    # ingestion path is authoritative for governance).
    target = {}
    if asset:
        target = {"source": "torana-asset-inventory", **(asset.get("governance") or {})}
    for run in runs:
        props = run.setdefault("properties", {})
        torana = props.setdefault("torana", {})
        torana.setdefault("scan_id", scan_id)
        if target:
            torana.setdefault("target", target)
        # T3 diff-scan: stamp the base commit run-level (a property of the SCAN, not any one
        # finding — beside scan_id/target, not per-result). A later `torana ingest sarif` carries
        # this marker so T6 can persist the fixed/new/unchanged delta. The ingestor does NOT read
        # run.properties.torana today (§2.4) — the ~3-line run-level lift is a T6-owned task.
        if args.base:
            torana.setdefault("base_revision", args.base)

    doc = {"version": SARIF_VERSION, "runs": runs}
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)

    n_results = sum(len(r.get("results") or []) for r in runs)
    print(f"wrote {args.output}: {len(runs)} run(s), {n_results} result(s), scan_id={scan_id}")
    # ⚠️ The advice differs by what is IN the document. Telling someone to supply
    # `--asset-ref <host/org/repo>` for a third-party image invites them to invent a
    # repository — which is the very thing this run avoided by not guessing one. For a
    # container-only document the image digest IS the identity.
    _container_only = bool(runs) and all(
        _NATIVE_ENGINES.get((r.get("tool", {}).get("driver", {}) or {}).get("name")) == "Container"
        for r in runs
    )
    # ⚠️ Test what the DOCUMENT got, not what could have been derived. A container-only run
    # deliberately ignores the derived remote, so `repo_uri` is still truthy while every run
    # in the file has no versionControlProvenance — testing it here printed nothing at all.
    if _container_only and not repo_uri_stated:
        print("NOTE: no repository link — correct for a container scan. The image digest is "
              "the identity (properties.torana.image on every result). Pass "
              "--repository-uri only if you are asserting the image was built from that repo.",
              file=sys.stderr)
    elif not repo_uri:
        print("WARNING: no repository URI (no git remote, no --repository-uri, no asset asset_ref) — "
              "the SARIF is KEYLESS; push with `torana ingest sarif <doc> --asset-ref <host/org/repo>`.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
