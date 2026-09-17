#!/usr/bin/env python3
"""
osv_lookup.py — bulk-query the OSV (osv.dev) API for vulnerabilities affecting
a set of (package, version, ecosystem) tuples. Used by torana-claude-scan's
SCA sub-scan.

Usage:
    python3 osv_lookup.py < packages.json > findings.json

Input shape (stdin, JSON array):
    [
      {"name": "lodash", "version": "4.17.20", "ecosystem": "npm",
       "manifest": "package.json", "manifest_line": 15,
       "dependency_type": "direct"},
      ...
    ]

Output shape (stdout, JSON array of finding dicts consumed by build_sarif.py):
    [
      {"vendor_id": "<fingerprint>",
       "title": "...", "type": "SCA", "severity": "Medium",
       "cve_id": "CVE-2020-28500",
       "engine": "osv", "engine_version": "...",
       "package": {...}, "coordinates": {...},
       "remediation_hint": "Upgrade to >=4.17.21",
       ...},
      ...
    ]

This script depends on the `requests` library (stdlib only otherwise).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import re
import sys
from typing import Any, Iterable

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

# OSV severity (CVSS v3 vector → high-level bucket) → canonical sink enum.
_SEVERITY_BUCKETS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
]

# CVSS v3 metric weights for pure-Python base score computation.
# Ref: https://www.first.org/cvss/v3.1/specification-document §7.1
_CVSS3_AV    = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS3_AC    = {"L": 0.77, "H": 0.44}
_CVSS3_PR_US = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
_CVSS3_PR_SC = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
_CVSS3_UI    = {"N": 0.85, "R": 0.62}
_CVSS3_CIA   = {"N": 0.00, "L": 0.22, "H": 0.56}


def _cvss3_base_score(vector: str) -> float | None:
    """Compute CVSS v3.x base score from a vector string (no external deps)."""
    try:
        m: dict[str, str] = {}
        for part in vector.split("/")[1:]:
            k, v = part.split(":")
            m[k] = v
        scope_changed = m.get("S") == "C"
        av = _CVSS3_AV[m["AV"]]
        ac = _CVSS3_AC[m["AC"]]
        pr = (_CVSS3_PR_SC if scope_changed else _CVSS3_PR_US)[m["PR"]]
        ui = _CVSS3_UI[m["UI"]]
        c  = _CVSS3_CIA[m["C"]]
        i  = _CVSS3_CIA[m["I"]]
        a  = _CVSS3_CIA[m["A"]]

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0
        raw = min((1.08 * (impact + exploitability) if scope_changed else impact + exploitability), 10.0)
        import math
        return math.ceil(raw * 10) / 10
    except Exception:
        return None


def _exploit_maturity_from_osv(vuln: dict[str, Any]) -> str | None:
    """Infer exploit_code_maturity from OSV data.

    OSV does not carry NVD exploit maturity. We use CISA KEV membership as a
    proxy — KEV-listed CVEs have confirmed active exploitation → 'Functional'.
    """
    db_specific = vuln.get("database_specific") or {}
    if db_specific.get("cisa_kev"):
        return "Functional"
    aliases = vuln.get("aliases") or []
    if any("KEV" in a.upper() for a in aliases):
        return "Functional"
    for ref in vuln.get("references") or []:
        if "cisa.gov" in ref.get("url", "") and "kev" in ref.get("url", "").lower():
            return "Functional"
    return None


logger = logging.getLogger("osv_lookup")


def _fingerprint(parts: Iterable[str]) -> str:
    """Composite fingerprint, first 16 hex chars of sha256.  Same shape as the
    skill's SAST fingerprint so dedupe behaves uniformly."""
    h = hashlib.sha256()
    for p in parts:
        h.update((p or "").encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()[:16]


def _severity_from_cvss(cvss_score: float | None) -> str:
    """Map a CVSS base score to the datalake severity vocabulary.

    ⛔ `None` means UNSCORED, and it must NOT read Medium. A middle band makes an
    advisory nobody scored indistinguishable from one genuinely rated medium, and the
    row carries no trace of the difference. This was not a rounding error: every
    CVSS-v4-only record reached here (see `_highest_cvss`) and every one of them was
    stamped Medium, so the severity column was largely a default wearing a rating's
    clothes — `GHSA-jjhc-v7c2-5hh6` read Medium while Trivy and OSV's own database
    both call it CRITICAL.

    ⚠️ Callers must try `_qualitative_severity()` BEFORE falling back here. Reaching
    this line with `None` means the advisory published neither a v3 vector nor a
    severity word, which is genuinely unknown.
    """
    if cvss_score is None:
        return "Unknown"
    for cutoff, label in _SEVERITY_BUCKETS:
        if cvss_score >= cutoff:
            return label
    return "Low"


def _osv_querybatch(queries: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """One round-trip to /v1/querybatch.  Returns a parallel array of
    `vulns: [{id, modified}, ...]` per input query."""
    resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=20)
    resp.raise_for_status()
    return resp.json().get("results", [])


def _osv_vuln(vuln_id: str) -> dict[str, Any]:
    """Fetch one vuln detail by id."""
    resp = requests.get(OSV_VULN_URL.format(vuln_id=vuln_id), timeout=10)
    resp.raise_for_status()
    return resp.json()


def _highest_cvss(vuln: dict[str, Any]) -> float | None:
    """Highest CVSS **v3** base score from an OSV record, or None when it has none.

    ⛔ CVSS_V4 IS DELIBERATELY NOT PASSED HERE, and it used to be. `_cvss3_base_score`
    reads the v3 metric names (`C`, `I`, `A`); a v4 vector spells them `VC`, `VI`, `VA`,
    so every v4 lookup raised `KeyError`, was swallowed by that function's bare `except`,
    and returned None — with no log line and no DLQ entry. The record then looked
    unscored and got stamped with the old `_severity_from_cvss(None)` default.

    ⚠️ The fix is NOT to add a v4 branch. A v4 base score needs the spec's MacroVector
    lookup table — a large port to carry with no dependencies, and a second scoring
    implementation to keep correct forever. OSV already publishes the qualitative answer
    in `database_specific.severity`, so `_qualitative_severity()` reads that instead.
    """
    best: float | None = None
    for sev in vuln.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            score = _cvss3_base_score(sev.get("score", ""))
            if score is not None:
                best = score if best is None else max(best, score)
    return best


def _record_source(vuln: dict[str, Any]) -> str | None:
    """The advisory database that published this OSV record, from its id prefix
    (`GHSA-…` → `ghsa`, `PYSEC-…` → `pysec`). None when the id has no prefix."""
    vid = str(vuln.get("id") or "")
    return vid.split("-", 1)[0].lower() if "-" in vid else None


def _contract_fields(vuln: dict[str, Any]) -> dict[str, Any]:
    """Severity/CVSS contract fields for one OSV record (pantheon-tests
    docs/sarif_severity_cvss_contract_2026-09-15.md). Anything the record lacks is left out.

    ⛔ `scanner_severity` is the advisory's OWN rating word, sent raw (`MODERATE`, not
    `Medium`). It is deliberately NOT this module's `severity`, which is a band computed
    from the CVSS score whenever one exists (`_severity_from_cvss`). Sending that as the
    scanner's rating would store a number we banded as if an advisory had said it.

    Each vector is the one the record published. The v3 vector is the one behind
    `cvss3_base_score` (the highest v3 score, same tie-break as `_highest_cvss`), so the
    score and the vector always agree. v4 has no computed score here (see `_highest_cvss`),
    so only its vector is sent. A v2 vector is sent only when there is no v3 or v4.
    """
    src = _record_source(vuln)
    out: dict[str, Any] = {}
    word = str((vuln.get("database_specific") or {}).get("severity") or "").strip()
    if word:
        out["scanner_severity"] = word
        if src:
            out["severity_source"] = src
    best3: tuple[float, str] | None = None
    vec4 = vec2 = None
    for sev in vuln.get("severity") or []:
        vector = str(sev.get("score") or "").strip()
        if not vector:
            continue
        if sev.get("type") == "CVSS_V3":
            score = _cvss3_base_score(vector)
            if score is not None and (best3 is None or score > best3[0]):
                best3 = (score, vector)
        elif sev.get("type") == "CVSS_V4" and vec4 is None:
            vec4 = vector
        elif sev.get("type") == "CVSS_V2" and vec2 is None:
            vec2 = vector
    chosen = []
    if best3:
        chosen.append(("3", best3[1]))
    if vec4:
        chosen.append(("4", vec4))
    if not chosen and vec2:
        chosen.append(("2", vec2))
    for version, vector in chosen:
        out[f"cvss{version}_vector"] = vector
        if src:
            out[f"cvss{version}_source"] = src
    return out


#: GitHub advisory severity words -> the datalake vocabulary. GitHub says MODERATE where
#: the platform says Medium; normalising here keeps ONE spelling in the emitted finding.
_GH_SEVERITY_WORDS = {
    "CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium",
    "MEDIUM": "Medium", "LOW": "Low",
}


def _qualitative_severity(vuln: dict[str, Any]) -> str | None:
    """The advisory's own severity word, when it publishes one.

    ⭐ This is the ONLY severity signal for a v4-only record, which `_highest_cvss`
    cannot score. GitHub-sourced OSV records carry `database_specific.severity`
    independently of any CVSS vector, so it answers precisely where the vector fails.
    Returns None for an unrecognised or absent word — the caller then reports Unknown
    rather than inventing a band.
    """
    raw = str((vuln.get("database_specific") or {}).get("severity") or "").strip().upper()
    return _GH_SEVERITY_WORDS.get(raw)


def _primary_cve(vuln: dict[str, Any]) -> str | None:
    """Pick the CVE alias if present, else None.

    ⚠️ Returns None — NOT the OSV id — when no CVE alias exists. That is deliberate and
    the caller depends on it: an advisory with no CVE stays its OWN finding rather than
    merging with other CVE-less advisories on the same package (see `_merge_key`).
    """
    aliases = vuln.get("aliases") or []
    cves = [a for a in aliases if a.startswith("CVE-")]
    return cves[0] if cves else None


def _version_sort_key(v: str):
    """Best-effort comparable key for a version string, newest-comparable-last.

    ⚠️ Deliberately tolerant: OSV spans ecosystems (PyPI, npm, Go, Maven, apk, deb) whose
    version grammars differ, so a strict parser that raises would drop real fixes. Uses
    `packaging` when the string is PEP 440-parseable and falls back to a numeric-aware
    tuple otherwise; anything unparseable sorts last so it is never silently preferred.
    """
    try:
        from packaging.version import Version  # noqa: PLC0415
        return (0, Version(v))
    except Exception:
        pass
    parts: list[Any] = []
    for chunk in re.split(r"[.\-_+~]", str(v)):
        # Split trailing/leading alpha from numeric so `1.2.3rc1` orders under `1.2.3`.
        for token in re.findall(r"\d+|\D+", chunk):
            parts.append((0, int(token)) if token.isdigit() else (1, token))
    return (1, tuple(parts))


def _fixed_in(vuln: dict[str, Any], package_name: str,
              installed: str | None = None) -> str | None:
    """The LOWEST fix version that is actually an upgrade from `installed`.

    ⛔ THIS USED TO BE `min(fixed_versions)` OVER RAW STRINGS, which is wrong twice:

      1. TEXT ORDER IS NOT VERSION ORDER. `min(["1.83.10", "1.83.7"])` returns
         "1.83.10" because "1" sorts before "7" — so the advice named a HIGHER version
         than necessary, and the reverse case names a lower one.
      2. IT RANGED OVER EVERY AFFECTED RANGE, including older release lines. A package
         on 1.83.x with a backport fix on the 0.9.x line yielded `min(...) == "0.9.1"` —
         advice to DOWNGRADE, presented as a fix.

    Both produce a confident, specific, wrong upgrade instruction, which is worse than
    no advice: someone acts on it. Now versions are compared with a real ordering and
    only fixes strictly ABOVE the installed version are eligible.

    ⚠️ With no installed version supplied, every fix stays eligible — the ordering fix
    still applies, and filtering on an unknown baseline would silently drop all of them.
    """
    fixed_versions: list[str] = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name", "").lower() != package_name.lower():
            continue
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev and ev["fixed"]:
                    fixed_versions.append(str(ev["fixed"]))
    if not fixed_versions:
        return None
    candidates = fixed_versions
    if installed:
        base = _version_sort_key(str(installed))
        upgrades = [v for v in fixed_versions if _version_sort_key(v) > base]
        # Keep the unfiltered list when NOTHING sorts above the installed version: that
        # means the comparison could not separate them (mixed grammars), and reporting
        # the lowest known fix beats reporting none.
        candidates = upgrades or fixed_versions
    return min(candidates, key=_version_sort_key)


def _to_issue(
    pkg: dict[str, Any],
    vuln: dict[str, Any],
) -> dict[str, Any]:
    cve_id = _primary_cve(vuln)
    cvss = _highest_cvss(vuln)
    # PRECEDENCE, strongest claim first: a real v3 base score, then the advisory's own
    # severity word (the only signal a v4-only record carries), then Unknown. There is
    # deliberately no default band — see `_severity_from_cvss`.
    severity = (
        _severity_from_cvss(cvss) if cvss is not None
        else (_qualitative_severity(vuln) or "Unknown")
    )
    # The installed version gates the fix choice — a "fix" at or below what is already
    # installed is a downgrade, not a remediation.
    fixed_in = _fixed_in(vuln, pkg["name"], pkg.get("version"))
    title = vuln.get("summary") or f"Vulnerable {pkg['name']} {pkg['version']} ({cve_id or vuln.get('id')})"

    rule_id = f"osv.{pkg['ecosystem'].lower()}.{pkg['name'].lower()}"
    snippet = f'"{pkg["name"]}": "{pkg["version"]}"'
    return {
        "vendor_id": _fingerprint([rule_id, pkg.get("manifest", ""), snippet, vuln.get("id", "")]),
        "title": title,
        "description": vuln.get("details") or "",
        "type": "SCA",
        "severity": severity,
        "cwe": (vuln.get("database_specific") or {}).get("cwe_ids", [None])[0] if (vuln.get("database_specific") or {}).get("cwe_ids") else None,
        "cve_id": cve_id,
        # ⭐ The ADVISORY id (GHSA-…/PYSEC-…), distinct from `rule_id`, which is
        # package-scoped (`osv.pypi.<pkg>`) and therefore identical for every advisory on
        # one package. The server keys a CVE-less SCA finding on this so two DIFFERENT
        # advisories with no CVE stay two findings instead of collapsing into one.
        "advisory_id": vuln.get("id"),
        "rule_id": rule_id,
        "engine": "osv",
        "engine_version": _dt.date.today().strftime("%Y.%m"),
        "coordinates": {
            "file": pkg.get("manifest"),
            "line": pkg.get("manifest_line"),
            "column": None,
            "code_snippet": snippet,
        },
        "package": {
            "name": pkg["name"],
            "version": pkg["version"],
            "fixed_in": fixed_in,
            "manager": pkg["ecosystem"].lower() if pkg.get("ecosystem") else None,
            "dependency_type": pkg.get("dependency_type") or "direct",
        },
        "cvss3_base_score": cvss,
        # ⭐ The advisory's own rating word and each published CVSS vector, with sources
        # (severity/CVSS contract). `severity` above stays: it sets the SARIF `level` and
        # the alias-merge rank.
        **_contract_fields(vuln),
        "exploit_available": None,
        "is_fix_available": fixed_in is not None,
        "is_zero_day": False,
        "exploit_code_maturity": _exploit_maturity_from_osv(vuln),
        "remediation_hint": (
            f"Upgrade {pkg['name']} to >={fixed_in}" if fixed_in else None
        ),
        "remediation_priority": severity,
        "first_seen_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "tags": {},
        "raw": {"osv_id": vuln.get("id"), "cvss": cvss},
    }


#: Severity precedence for alias merging. ⛔ `Unknown` ranks LOWEST so a scored copy always
#: beats an unscored one. Without that, a v4-only PYSEC twin — correctly reported Unknown
#: since `_severity_from_cvss` stopped defaulting to Medium — would be free to overwrite its
#: GHSA sibling's real High whenever it happened to be written second.
_SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Unknown": 1}


def _merge_key(issue: dict[str, Any]) -> tuple:
    """Identity for alias merging: one real-world flaw against one package = one finding.

    ⭐ Keyed on (ecosystem, package, version, CVE) — the SAME natural key the SARIF
    ingestor uses for SCA rows, so the skill and the platform agree on what "one finding"
    means instead of each deduping to a different answer.

    ⚠️ An advisory with NO CVE keeps its own OSV id in the key, so two distinct CVE-less
    advisories on one package stay two findings. Collapsing them on a shared empty string
    would merge unrelated flaws — the failure the bug report files separately as O7.
    """
    p = issue.get("package") or {}
    cve = issue.get("cve_id")
    return (
        p.get("manager"), p.get("name"), p.get("version"),
        cve or "osv:%s" % ((issue.get("raw") or {}).get("osv_id") or ""),
    )


def _merge_rank(issue: dict[str, Any]) -> tuple:
    """Total order deciding which alias copy wins. Every component is deterministic.

    ⚠️ The OSV id is the final tie-break ON PURPOSE. Severity and score alone do not
    order two copies that agree on both, and falling back to arrival order is exactly the
    nondeterminism this merge exists to remove — the scan would still score differently
    run to run, just less often, which is harder to notice rather than better.
    """
    return (
        _SEVERITY_RANK.get(issue.get("severity"), 0),
        issue.get("cvss3_base_score") if issue.get("cvss3_base_score") is not None else -1.0,
        str((issue.get("raw") or {}).get("osv_id") or ""),
    )


def _merge_aliases(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse the advisory aliases for one flaw into a single finding.

    ⛔ WHY THE SKILL DOES THIS RATHER THAN LEAVING IT TO THE INGESTOR. OSV reports one
    flaw under several advisory ids — typically GitHub's `GHSA-…` and PyPI's `PYSEC-…` —
    and emits each as its own record. The datalake upsert runs one statement per row, so
    WHICHEVER COPY IS WRITTEN LAST REPLACES THE OTHER. Nothing chose between them, so the
    stored severity followed the order OSV happened to return records and two consecutive
    scans of unchanged code could disagree.

    ⭐ Highest severity wins, not first-seen: the copies genuinely differ (a GHSA record
    carries a CVSS v3 vector where its PYSEC twin carries only v4), and under-reporting a
    real Critical is the failure that costs something. Every alias id is preserved on the
    surviving finding so nothing is lost by merging.

    ⚠️ `vendor_id` is RECOMPUTED from the merge key, not inherited from the winner. The
    original is a hash over the OSV id, so inheriting it would make the fingerprint depend
    on which copy won — re-introducing run-to-run instability through the back door.
    """
    merged: dict[tuple, dict[str, Any]] = {}
    aliases: dict[tuple, set] = {}
    for issue in issues:
        key = _merge_key(issue)
        osv_id = (issue.get("raw") or {}).get("osv_id")
        aliases.setdefault(key, set()).add(osv_id) if osv_id else None
        keep = merged.get(key)
        if keep is None or _merge_rank(issue) > _merge_rank(keep):
            # Carry the better `fixed_in` across: a copy may be the more severe one and
            # still be the one that omits a fix version.
            if keep is not None and not (issue.get("package") or {}).get("fixed_in"):
                prior = (keep.get("package") or {}).get("fixed_in")
                if prior:
                    issue["package"]["fixed_in"] = prior
                    issue["is_fix_available"] = True
            merged[key] = issue
        elif not (keep.get("package") or {}).get("fixed_in"):
            cand = (issue.get("package") or {}).get("fixed_in")
            if cand:
                keep["package"]["fixed_in"] = cand
                keep["is_fix_available"] = True

    out: list[dict[str, Any]] = []
    for key, issue in merged.items():
        ids = sorted(a for a in aliases.get(key, set()) if a)
        issue["aliases"] = ids
        issue["vendor_id"] = _fingerprint([str(part or "") for part in key])
        out.append(issue)
    return out


def lookup(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Top-level entry. Given a list of packages, return a list of issues."""
    if not packages:
        return []

    queries = [
        {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
        for p in packages
    ]
    results = _osv_querybatch(queries)

    issues: list[dict[str, Any]] = []
    for pkg, hits in zip(packages, results):
        hits_dict: dict[str, Any] = hits
        for hit in hits_dict.get("vulns") or []:
            try:
                vuln = _osv_vuln(hit["id"])
            except requests.HTTPError as exc:
                logger.warning("osv vuln fetch failed for %s: %s", hit.get("id"), exc)
                continue
            issues.append(_to_issue(pkg, vuln))
    return _merge_aliases(issues)


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    packages = json.load(sys.stdin)
    if not isinstance(packages, list):
        logger.error("expected a JSON array on stdin")
        return 2
    issues = lookup(packages)
    json.dump(issues, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
