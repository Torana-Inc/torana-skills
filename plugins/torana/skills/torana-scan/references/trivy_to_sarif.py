#!/usr/bin/env python3
"""Convert a native Trivy JSON report into a Torana-profile SARIF run.

⛔ WHY THIS EXISTS. Trivy can emit SARIF directly, and the Scan Pack used to take it —
but Trivy's own SARIF puts package identity in PROSE (`"Package: busybox Installed
Version: 1.36.1-r20 ... Fixed Version: 1.36.1-r21"`) and has no home at all for fix
status. Measured on one image, ingesting that SARIF landed `cve_id` 0/366 and
`package_name` 0/366, so the findings could not join a `pkg:` node and the fix list had
nothing to point at. The same report through this converter carries every field as a
typed value.

⭐ THE MAPPING IS CODE, NOT AN LLM READING FINDINGS. A container report routinely holds
hundreds of vulnerabilities; asking a model to transcribe each one is slow, costs tokens
per finding, and — worst — is not reproducible, so two scans of an unchanged image can
disagree. Every field below is a deterministic read of a typed Trivy field, the same
contract `osv_lookup.py` follows for OSV.

⚠️ DO NOT "improve" this by parsing Trivy's SARIF message text instead. That string is
human-readable output, not an interface: Trivy may reformat it in any release and the
regex would fail silently, which is the failure mode this file was written to remove.

Usage
-----
    trivy image --quiet --format json -o report.json <image>
    python3 trivy_to_sarif.py --report report.json --engine trivy-image \
        --repository-uri https://github.com/org/repo --output trivy-image.sarif

The output is a complete SARIF document that `build_sarif.py --merge-sarif` folds in
verbatim; its `properties.torana` bag is already populated, and the merge only ever
`setdefault`s, so nothing downstream overwrites it.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

# Self-relative import of a SIBLING skill module — the skill bundling its own code, not a
# reach into a platform checkout. Reusing `_engine_run` guarantees this converter's SARIF
# is byte-shaped like every other run the skill emits, instead of a second assembly that
# drifts.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_sarif import _engine_run, _gen_scan_id, _now_iso  # noqa: E402

#: Trivy severity words -> the datalake vocabulary (Title Case).
#: ⚠️ Trivy's UNKNOWN maps to Unknown, never to a middle band — an unrated finding must
#: stay visibly unrated. Same rule `osv_lookup._severity_from_cvss` follows.
_SEVERITY = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
    "LOW": "Low", "UNKNOWN": "Unknown",
}

#: Trivy result `Type` -> purl ecosystem, so `pkg_key(purl)` mints the SAME `pkg:` node
#: the GAR/Container-Analysis sync and the OSV route already write. ⭐ Agreeing here is
#: what lets an image finding and a repo finding meet on one package node; a private
#: spelling would silently create a parallel node for the same package.
_PURL_TYPE = {
    "alpine": "apk", "debian": "deb", "ubuntu": "deb",
    "redhat": "rpm", "rocky": "rpm", "centos": "rpm", "amazon": "rpm",
    "oracle": "rpm", "photon": "rpm", "suse": "rpm", "opensuse": "rpm",
    "python-pkg": "pypi", "node-pkg": "npm", "gobinary": "golang",
    "jar": "maven", "gemspec": "gem", "conda-pkg": "conda",
    "pipenv": "pypi", "poetry": "pypi", "npm": "npm", "yarn": "npm",
    "pnpm": "npm", "gomod": "golang", "cargo": "cargo", "nuget": "nuget",
    "composer": "composer", "pub": "pub", "bundler": "gem",
}

#: CVSS source precedence. ⛔ NOT "first one found" — Trivy carries several vendors'
#: scores for one CVE (`nvd` and `redhat` regularly differ by more than a band), so an
#: arbitrary pick makes the stored score depend on dict ordering. NVD first because it is
#: the vendor-neutral baseline every other consumer compares against.
_CVSS_SOURCES = ("nvd", "redhat", "ghsa", "bitnami", "amazon", "oracle", "ubuntu")


#: Trivy's key names for each CVSS version inside one `CVSS.<source>` entry.
_CVSS_KEYS = {
    "3": ("V3Score", "V3Vector"),
    "4": ("V40Score", "V40Vector"),
    "2": ("V2Score", "V2Vector"),
}


def _cvss_pick(vuln: Dict[str, Any], version: str) -> Optional[tuple]:
    """(score, vector, source) for one CVSS version, by source precedence. None when absent.

    ⛔ The score, vector and source all come from the SAME `CVSS.<source>` entry. Pairing
    one vendor's score with another vendor's vector would store a vector that does not
    produce the stored score (contract rule 4).
    """
    score_key, vector_key = _CVSS_KEYS[version]
    cvss = vuln.get("CVSS") or {}
    # Listed vendors first, then any unlisted vendor in sorted order, so the choice is
    # reproducible rather than dict-insertion dependent.
    order = [s for s in _CVSS_SOURCES if s in cvss] + sorted(s for s in cvss if s not in _CVSS_SOURCES)
    for src in order:
        entry = cvss.get(src) or {}
        if entry.get(score_key) is not None:
            vector = str(entry.get(vector_key) or "").strip() or None
            return float(entry[score_key]), vector, src
    return None


def _cvss_fields(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """The contract's CVSS fields for one Trivy vulnerability. A version Trivy did not
    report is left out, never sent as null or 0.

    v3 and v4 are selected separately, because one vendor may carry only one of them. v2 is
    sent only when there is neither: an old CVE scored only under v2 (15 findings across the
    pgvector and qdrant images on 15 Sep, e.g. CVE-2010-4756) would otherwise reach the
    platform with no score at all.
    """
    picks = {v: _cvss_pick(vuln, v) for v in ("3", "4")}
    if not picks["3"] and not picks["4"]:
        picks["2"] = _cvss_pick(vuln, "2")
    out: Dict[str, Any] = {}
    for version, pick in picks.items():
        if not pick:
            continue
        score, vector, source = pick
        out[f"cvss{version}_base_score"] = score
        out[f"cvss{version}_source"] = source
        if vector:
            out[f"cvss{version}_vector"] = vector
    return out


def _image_ref(report: Dict[str, Any]) -> Optional[str]:
    """The scanned image's DIGEST-pinned reference, or None.

    ⛔ A TAG IS NOT AN IDENTITY and is deliberately never returned. `ArtifactName` is
    whatever the caller typed — `alpine:3.19`, or `…/pantheon-fe:latest` — and a tag is
    re-pointed at new content whenever someone pushes. Keying on it would attach findings
    to a node that means something different tomorrow, which is worse than not attaching
    them: the graph would assert a link it cannot honour.

    `Metadata.RepoDigests` carries the immutable form. It is usually SHORT
    (`alpine@sha256:…`), which the server's `image_key()` expands to the qualified spelling
    the graph already holds — so this returns it as-is rather than guessing a registry here.
    """
    meta = report.get("Metadata") or {}
    for d in (meta.get("RepoDigests") or []):
        if d and "@sha256:" in d:
            return d
    art = report.get("ArtifactName") or ""
    return art if "@sha256:" in art else None


#: Trivy `Relationship` values -> the platform's dependency_type vocabulary. Trivy only
#: populates this when run with `--list-all-pkgs`; absent means UNKNOWN, never `direct`.
_RELATIONSHIP = {"direct": "direct", "indirect": "transitive", "root": "direct"}


def _dependency_type(vuln: Dict[str, Any]) -> Optional[str]:
    """What the scanner actually said about the package's relationship, or None.

    Returns None whenever Trivy did not report one — which is the normal case, since the
    Scan Pack does not pass `--list-all-pkgs`. Reporting nothing is the honest answer and
    the caller stores NULL; see the comment at the call site for why guessing `direct`
    was worse than saying nothing.
    """
    rel = str(vuln.get("Relationship") or "").strip().lower()
    return _RELATIONSHIP.get(rel)


def convert(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Trivy report -> Torana finding dicts (the shape `build_sarif` consumes)."""
    is_image = (report.get("ArtifactType") or "") == "container_image"
    scan_type = "Container" if is_image else "SCA"
    image_ref = _image_ref(report) if is_image else None
    findings: List[Dict[str, Any]] = []

    for res in report.get("Results") or []:
        raw_type = (res.get("Type") or "").lower()
        manager = _PURL_TYPE.get(raw_type, raw_type or None)
        target = res.get("Target") or report.get("ArtifactName")
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or ""
            fixed = (v.get("FixedVersion") or "").strip() or None
            findings.append({
                # ⭐ ruleId is the advisory id, so the SARIF rule table groups by CVE the
                # way every other engine's does.
                "rule_id": vid or "trivy.finding",
                "title": v.get("Title") or vid or "vulnerability",
                "description": (v.get("Description") or "")[:4000],
                "severity": _SEVERITY.get(str(v.get("Severity") or "").upper(), "Unknown"),
                "scan_type": scan_type,
                # ⚠️ Only a real CVE goes in `cve_id`. Trivy also emits distro placeholders
                # (`TEMP-…`, `DLA-…`) as VulnerabilityID; storing those as a CVE would make
                # them look like published advisories and break any CVE join.
                "cve_id": vid if vid.startswith("CVE-") else None,
                "cwe": (v.get("CweIDs") or [None])[0],
                "file": target,
                "package": {
                    "name": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "fixed_in": fixed,
                    "manager": manager,
                    # ⛔ NOT hardcoded "direct", which is what this was. A Trivy
                    # vulnerability report does not say whether a package is a declared
                    # dependency or a transitive one — that needs `--list-all-pkgs`, which
                    # the Scan Pack does not pass — so every finding was labelled `direct`
                    # on no evidence. MEASURED: `litellm` reaches pantheon-auth only
                    # through the vendored pantheon-shared wheel, and all 15 of its
                    # findings claimed `direct`; an image scan labelled 8 OS packages
                    # `direct` when nobody declared them at all.
                    #
                    # ⚠️ An invented value is worse than an absent one. Empty reads as
                    # "the scanner did not say"; "direct" reads as a fact and sends a fix
                    # to the wrong repository. Left None until Trivy actually reports a
                    # relationship (see `_dependency_type`).
                    "dependency_type": _dependency_type(v),
                },
                # ⭐ Severity/CVSS contract (pantheon-tests
                # docs/sarif_severity_cvss_contract_2026-09-15.md). Trivy's rating and whose
                # rating it is, RAW — the platform decides severity from the rating and the
                # CVSS band, so the Title Case `severity` above only sets the SARIF `level`.
                # Image scans often carry no SeveritySource; it is then left out.
                **({"scanner_severity": v["Severity"]} if v.get("Severity") else {}),
                **({"severity_source": v["SeveritySource"]} if v.get("SeveritySource") else {}),
                # Each CVSS version's score, vector and source, from one Trivy entry.
                **_cvss_fields(v),
                "is_fix_available": fixed is not None,
                # Trivy's own triage state (`fixed` / `affected` / `will_not_fix` /
                # `fix_deferred`). ⚠️ The SARIF profile has no home for this yet, so it is
                # emitted and currently dropped — deliberately, so the producer side is
                # ready the moment the ingestor learns to read it.
                "vulnerability_status": v.get("Status"),
                # Container attach point — omitted entirely for a filesystem scan, and for
                # an image scanned by tag with no digest available.
                "image": image_ref,
                "remediation_hint": (
                    f"Upgrade {v.get('PkgName')} to >={fixed}" if fixed else None
                ),
                "first_seen_at": _now_iso(),
            })
    return findings


def build_document(
    findings: List[Dict[str, Any]],
    *,
    engine: str,
    repository_uri: Optional[str],
    commit: Optional[str],
) -> Dict[str, Any]:
    """Wrap findings in a one-run SARIF document using the skill's own assembly."""
    run = _engine_run(
        engine, findings,
        repo_uri=repository_uri, commit=commit,
        scan_id=_gen_scan_id(), scanned_at=_now_iso(),
    )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", required=True, help="Native Trivy JSON report ('-' for stdin).")
    ap.add_argument("--engine", default="trivy-image", help="Run name (tool.driver.name).")
    ap.add_argument("--repository-uri", default=None)
    ap.add_argument("--commit", default=None)
    ap.add_argument("--output", required=True, help="SARIF document to write.")
    args = ap.parse_args()

    raw = sys.stdin.read() if args.report == "-" else open(args.report, encoding="utf-8").read()
    if not raw.strip():
        # An empty report is a CLEAN scan, not a failure — emit a valid empty run so the
        # merge step and the receipt still see this engine ran.
        report: Dict[str, Any] = {}
    else:
        report = json.loads(raw)

    findings = convert(report)
    doc = build_document(
        findings, engine=args.engine,
        repository_uri=args.repository_uri, commit=args.commit,
    )
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    print(f"{args.engine}: {len(findings)} finding(s) -> {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
