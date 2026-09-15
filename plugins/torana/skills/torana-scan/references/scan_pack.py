#!/usr/bin/env python3
"""
scan_pack.py — the Torana Scan Pack router + runner (S3/S4).

Turns "Claude plays every engine" into a router over a pinned bundle of real OSS
engines. It:

  1. loads the pinned manifest (scan_pack.json),
  2. detects which scan DOMAINS the repo actually has (IaC files? a container
     image? — secrets/SAST are always on),
  3. for each engine: checks the binary is AVAILABLE (skip-with-message if not —
     never error-spam), runs it to native SARIF,
  4. hands every produced SARIF (plus any Claude/OSV finding files) to
     build_sarif.py, which merges them into ONE Torana-profile document.

Engine SELECTION is automatic (by domain), not a per-run menu — the user's only
choice stays list-only vs push (handled by the skill). An engine is run when its
domain is present AND its binary is installed; otherwise it is skipped with a
clear reason, so a partial toolchain still produces a valid scan.

Stdlib-only so it runs in the skill sandbox (matches build_sarif.py / osv_lookup.py).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Set

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_MANIFEST = os.path.join(_HERE, "scan_pack.json")
_DEFAULT_BUILD_SARIF = os.path.join(_HERE, "build_sarif.py")
_DEFAULT_VVAH_RUN = os.path.join(_HERE, "vvah_run.py")
# Engines provisioned by install_engines.sh land here; preferred over PATH so a
# pinned, checksum-verified bundle wins over whatever happens to be installed.
_LOCAL_BIN = os.path.join(_HERE, "scan_pack", "bin")


# User-facing scan-type names (Title Case, as in scan_pack.json) and the aliases we
# accept on the command line. SCA has no Scan-Pack engine (it runs via OSV in the
# skill), so it is a valid selection here but simply matches no engine.
_SCAN_TYPE_ALIASES = {
    "sast": "sast",
    "sca": "sca",
    "secret": "secret", "secrets": "secret",
    "iac": "iac", "infra": "iac", "infrastructure": "iac",
    "container": "container", "image": "container",
}


def _normalize_scan_types(raw: Optional[str]) -> Optional[List[str]]:
    """Parse a --scan-types value into a normalized lowercase set, or None for 'all'.
    'all' (or empty) → None → no filter. Unknown tokens are ignored with a warning."""
    if not raw:
        return None
    out: List[str] = []
    for tok in raw.split(","):
        t = tok.strip().lower()
        if not t or t == "all":
            return None  # 'all' anywhere means run everything
        norm = _SCAN_TYPE_ALIASES.get(t)
        if norm is None:
            print(f"NOTE: unknown scan-type '{tok.strip()}' ignored "
                  f"(valid: SAST, SCA, Secret, IaC, Container, all)", file=sys.stderr)
            continue
        if norm not in out:
            out.append(norm)
    return out or None


def _resolve_binary(binary: str) -> Optional[str]:
    """Resolve an engine binary: pinned local bin (install_engines.sh) → PATH.
    Returns an absolute path, or None if neither has it (→ graceful skip)."""
    cand = os.path.join(_LOCAL_BIN, binary)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return shutil.which(binary)


def _load_manifest(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ── Diff-scan (T3) — git helpers, changed-file set, per-engine URI post-filter ────────
# Mirrors build_sarif.py:_git (:118-126) — a thin, crash-proof git wrapper. Kept local
# (not imported) so scan_pack stays stdlib-only and self-contained in the sandbox.
def _git(repo: str, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return None
        return out.stdout.strip() or None
    except Exception:
        return None


def _changed_files(repo: str, base: str) -> Optional[List[str]]:
    """Repo-relative paths changed between <base> and HEAD (added/modified/renamed).
    Renames return the new path. Empty list means nothing changed (delta is a no-op).
    Returns None on git failure (invalid base sha) so the caller can abort cleanly.

    Uses the git return code directly — an EMPTY diff (base==HEAD, valid) exits 0 with no
    output and must return [], NOT None. (_git conflates empty output with failure, so we
    can't use it here.)"""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "diff", "--name-only", "--diff-filter=ACMR", f"{base}..HEAD"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return [p for p in proc.stdout.splitlines() if p.strip()]


def _norm_uri(uri: Optional[str]) -> str:
    """Normalize a SARIF artifactLocation.uri to a repo-relative comparison key.
    Strips a leading file:// scheme and any leading './' so the URI compares equal
    to the repo-relative paths git diff emits."""
    if not uri:
        return ""
    s = str(uri)
    if s.startswith("file://"):
        s = s[len("file://"):]
    while s.startswith("./"):
        s = s[2:]
    return s.lstrip("/") if s.startswith("/") else s


def _restrict_sarif_file(out_path: str, restrict_to: Set[str]) -> None:
    """In-place filter a native engine's SARIF file: drop every result whose location
    URI is not in `restrict_to` (path-normalized). Engine-agnostic — engines walk the
    whole tree, so this is how the diff-scan restricts them to the changed set.
    Results with no extractable file URI are kept (can't prove they're out of scope)."""
    try:
        with open(out_path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception:
        return
    norm_keep = {_norm_uri(p) for p in restrict_to}
    changed = False
    for run in doc.get("runs") or []:
        results = run.get("results") or []
        kept = []
        for res in results:
            uri = None
            for loc in res.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                if art.get("uri"):
                    uri = art["uri"]
                    break
            if uri is None or _norm_uri(uri) in norm_keep:
                kept.append(res)
        if len(kept) != len(results):
            run["results"] = kept
            changed = True
    if changed:
        try:
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
        except Exception:
            pass


def _iter_files(repo: str, limit: int = 20000):
    """Yield repo-relative paths, skipping the usual heavy/irrelevant dirs."""
    skip = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".mypy_cache"}
    count = 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            count += 1
            if count > limit:
                return
            yield os.path.relpath(os.path.join(root, f), repo)


#: Dependency manifests and lock files Trivy can read. Presence of ANY of these means the
#: repo has a dependency surface, so the SCA domain applies.
_SCA_MANIFESTS = {
    "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "gemfile", "gemfile.lock", "cargo.toml", "cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "composer.json", "composer.lock", "packages.lock.json", "conan.lock",
    "pubspec.lock", "mix.lock",
}


def _detect_domains(repo: str, image: Optional[str]) -> Dict[str, bool]:
    """Which scan domains apply. SAST + Secret are always on (any repo can leak a
    credential or carry vulnerable code); IaC and SCA are file-driven; Container needs an
    explicit image (the scanner never builds one)."""
    domains = {"sast": True, "secret": True, "iac": False, "sca": False,
               "container": bool(image)}
    iac_suffixes = (".tf", ".tf.json")
    iac_names = {"dockerfile", "chart.yaml", "kustomization.yaml", "cloudformation.yaml"}
    for rel in _iter_files(repo):
        base = os.path.basename(rel).lower()
        low = rel.lower()
        if base in _SCA_MANIFESTS:
            domains["sca"] = True
        if (
            low.endswith(iac_suffixes)
            or base in iac_names
            or base.startswith("dockerfile")
            or "/k8s/" in f"/{low}"
            or "/kubernetes/" in f"/{low}"
            or "/helm/" in f"/{low}"
        ):
            domains["iac"] = True
        # ⚠️ Only stop once BOTH file-driven domains are settled. This used to `break` the
        # moment IaC matched, which was harmless while IaC was the only one — but a repo
        # whose Dockerfile sorts before its requirements.txt would now have its dependency
        # surface go undetected, and SCA would silently not run.
        if domains["iac"] and domains["sca"]:
            break
    return domains


def _unserved_scan_types(
    manifest: Dict[str, Any],
    scan_types: Optional[List[str]],
    statuses: List[Dict[str, Any]],
    findings_arg: Optional[str],
    osv_arg: Optional[str],
) -> List[str]:
    """Selected scan types that NO engine actually ran for.

    Returns the caller-facing type names (`SAST`, `SCA`, …). Empty when every selected
    type was served — including by findings supplied out-of-band, since the caller
    produced those another way and the type is genuinely covered.
    """
    if not scan_types:            # `all`: nothing was specifically asked for
        return []
    selected = {t.strip().lower() for t in scan_types if t and t.strip()}
    if not selected:
        return []

    served = set()
    by_name = {e["name"]: e for e in manifest.get("engines", [])}
    for st in statuses:
        if st.get("status") != "ran":
            continue
        for t in (by_name.get(st.get("engine"), {}).get("scan_types") or []):
            served.add(t.strip().lower())
    # Out-of-band findings cover their own types.
    if _findings_nonempty(osv_arg):
        served.add("sca")
    if _findings_nonempty(findings_arg):
        # A Claude-review findings file can carry any type; it is not introspected here,
        # so treat it as covering every selected type rather than risk a false alarm.
        served |= selected

    canonical = {t.strip().lower(): t for e in manifest.get("engines", [])
                 for t in (e.get("scan_types") or [])}
    return [canonical.get(t, t.upper()) for t in sorted(selected - served)]


def _report_unserved(unserved: List[str]) -> None:
    """Say plainly which selected types were not scanned. stderr, never stdout."""
    names = ", ".join(unserved)
    print(f"ERROR: selected scan type(s) NOT scanned: {names}", file=sys.stderr)
    print("       No engine ran for them, so this run establishes nothing about those "
          "types. An empty result here does NOT mean 'no findings'.", file=sys.stderr)


def _stamp_unserved_in_sarif(output: Optional[str], unserved: List[str]) -> None:
    """Mark the run unsuccessful in the document itself. Best-effort; never raises.

    ⚠️ Writes `invocation.executionSuccessful = false` plus a `toolExecutionNotifications`
    entry on EVERY run in the document. After ingest the SARIF is the only artefact left,
    so a reader who never saw the exit code can still tell the scan was incomplete.
    """
    if not output or not os.path.exists(output):
        return
    try:
        with open(output, encoding="utf-8") as fh:
            doc = json.load(fh)
        note = {
            "level": "error",
            "message": {"text": "Selected scan type(s) not scanned: "
                                + ", ".join(unserved)
                                + ". No engine ran for them; an empty result for these "
                                  "types does not mean no findings."},
            "descriptor": {"id": "scanpack.unserved_scan_type"},
        }
        for run in (doc.get("runs") or []):
            invs = run.setdefault("invocations", [{}])
            for inv in invs:
                inv["executionSuccessful"] = False
                inv.setdefault("toolExecutionNotifications", []).append(note)
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
    except Exception as exc:      # noqa: BLE001 — reporting must not mask the real failure
        print(f"WARNING: could not stamp unserved types into {output}: {exc}",
              file=sys.stderr)


def _binary_version(binary: str) -> Optional[str]:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15)
        return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else None
    except Exception:
        return None


def _run_engine(
    engine: Dict[str, Any], repo: str, image: Optional[str], out_path: str, binary_path: str,
) -> Dict[str, Any]:
    """Run one engine to native SARIF. Returns a status dict; never raises."""
    name = engine["name"]
    # An engine declaring `post_process` emits its NATIVE format (not SARIF); the engine
    # writes to a sidecar and the converter produces the SARIF at `out_path`. Keeps the
    # rest of this function — and every caller — reading one SARIF path either way.
    post = engine.get("post_process")
    engine_out = (out_path + ".raw.json") if post else out_path
    # ⛔ `{repo}` SUBSTITUTES TO "." AND THE ENGINE RUNS WITH cwd=repo. It used to
    # substitute the ABSOLUTE repo path, and every engine echoes its target straight into
    # `artifactLocation.uri` — so findings shipped with `/Users/<someone>/code/<repo>/src/
    # x.py` while also claiming `uriBaseId: %SRCROOT%`. After ingest the `file` column was
    # a path on one laptop: not comparable between scans, not resolvable by the app, and
    # enough to tell source from tests only by luck.
    #
    # ⚠️ Fixing the URIs after the fact was the alternative and is worse — every engine
    # spells locations slightly differently, so the rewrite would need a per-engine rule
    # that silently rots. Running in the repo makes the tools emit relative paths
    # THEMSELVES, which is why `{out}` is forced absolute above.
    cmd = [
        tok.replace("{repo}", ".").replace("{image}", image or "").replace("{out}", engine_out)
        for tok in engine["command"]
    ]
    # Point the command at the resolved binary (local pinned bin, else PATH).
    if cmd and cmd[0] == engine["binary"]:
        cmd[0] = binary_path
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, cwd=repo)
    except FileNotFoundError:
        return {"engine": name, "status": "skipped", "reason": "binary not found at run time"}
    except subprocess.TimeoutExpired:
        return {"engine": name, "status": "failed", "reason": "timeout (1800s)"}
    except Exception as exc:  # noqa: BLE001 — runner must be crash-proof
        return {"engine": name, "status": "failed", "reason": f"{type(exc).__name__}: {exc}"}

    ok_codes = engine.get("ok_exit_codes") or [0]

    # Convert the native report to Torana-profile SARIF before the checks below, so a
    # conversion failure is reported as this engine failing rather than as a silently
    # missing SARIF.
    if post and os.path.exists(engine_out):
        conv = os.path.join(os.path.dirname(os.path.abspath(__file__)), post)
        try:
            cproc = subprocess.run(
                [sys.executable, conv, "--report", engine_out,
                 "--engine", name, "--output", out_path],
                capture_output=True, text=True, timeout=300,
            )
            if cproc.returncode != 0:
                tail = (cproc.stderr or "").strip().splitlines()
                return {"engine": name, "status": "failed",
                        "reason": f"{post} failed: {tail[-1][:160] if tail else 'no stderr'}"}
        except Exception as exc:  # noqa: BLE001 — runner must stay crash-proof
            return {"engine": name, "status": "failed",
                    "reason": f"{post}: {type(exc).__name__}: {exc}"}

    # A tool can exit nonzero *because it found things*; trust the SARIF file, not
    # only the exit code. Success = a parseable SARIF was written.
    sarif_ok = os.path.exists(out_path) and os.path.getsize(out_path) > 0
    n = None
    if sarif_ok:
        try:
            doc = json.load(open(out_path, encoding="utf-8"))
            n = sum(len(r.get("results") or []) for r in (doc.get("runs") or []))
        except Exception:
            sarif_ok = False
    if sarif_ok:
        return {"engine": name, "status": "ran", "results": n, "sarif": out_path}
    reason = f"exit {proc.returncode}, no usable SARIF"
    if proc.returncode not in ok_codes and proc.stderr:
        reason += f": {proc.stderr.strip().splitlines()[-1][:160]}"
    return {"engine": name, "status": "failed", "reason": reason}


def _select_and_run(
    manifest: Dict[str, Any],
    repo: str,
    image: Optional[str],
    out_dir: str,
    only: Optional[List[str]],
    scan_types: Optional[List[str]],
    restrict_to: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """When `restrict_to` is a set of repo-relative paths (diff-scan mode), each engine's
    native SARIF is post-filtered to results in that set (§3.4.4). When None (no --base),
    behavior is unchanged (full-tree) — additive."""
    domains = _detect_domains(repo, image)
    os.makedirs(out_dir, exist_ok=True)
    statuses: List[Dict[str, Any]] = []
    for engine in manifest.get("engines", []):
        name = engine["name"]
        if only and name not in only:
            continue
        # Scan-type gate — the user's per-domain choice (one/more/all). An engine
        # runs only if one of its declared scan_types was selected. SCA is handled
        # outside the Scan Pack (OSV), so selecting only SCA runs no engine here.
        if scan_types is not None:
            eng_types = {t.lower() for t in engine.get("scan_types", [])}
            if not (eng_types & set(scan_types)):
                statuses.append({"engine": name, "status": "skipped",
                                 "reason": "scan-type not selected "
                                           f"({'/'.join(engine.get('scan_types', [])) or '-'})"})
                continue
        # Domain gate.
        if not any(domains.get(d) for d in engine.get("domains", [])):
            statuses.append({"engine": name, "status": "skipped",
                             "reason": f"no {'/'.join(engine.get('domains', []))} target in repo"})
            continue
        # Explicit requirement gate (e.g. container needs --image).
        if "image" in engine.get("requires", []) and not image:
            statuses.append({"engine": name, "status": "skipped", "reason": "needs --image"})
            continue
        # Availability gate — the load-bearing graceful skip. Prefers the pinned
        # local bin (install_engines.sh) over PATH.
        binary_path = _resolve_binary(engine["binary"])
        if not binary_path:
            statuses.append({"engine": name, "status": "skipped",
                             "reason": f"{engine['binary']} not installed (pin {engine.get('version_pin', '?')}; "
                                       f"run install_engines.sh or put it on PATH)"})
            continue
        # Soft version check.
        ver = _binary_version(binary_path)
        pin = engine.get("version_pin")
        if ver and pin and pin not in ver:
            print(f"NOTE: {name} version '{ver}' != pin '{pin}' (proceeding)", file=sys.stderr)
        # ⚠️ ABSOLUTE. Engines now run with the repo as their working directory (see
        # `_run_engine`), so a relative out_dir would write the SARIF *inside the scanned
        # repo* instead of the output dir — and the next engine would then scan it.
        out_path = os.path.abspath(os.path.join(out_dir, f"{name}.sarif"))
        st = _run_engine(engine, repo, image, out_path, binary_path)
        # Diff-scan (§3.4.4): restrict this engine's SARIF to the changed set, then
        # re-count so the printed summary reflects the restricted findings.
        if restrict_to is not None and st.get("status") == "ran" and st.get("sarif"):
            _restrict_sarif_file(st["sarif"], restrict_to)
            try:
                doc = json.load(open(st["sarif"], encoding="utf-8"))
                st["results"] = sum(len(r.get("results") or []) for r in (doc.get("runs") or []))
            except Exception:
                pass
        statuses.append(st)
    return statuses


def _merge_with_build_sarif(
    build_sarif: str,
    ran: List[Dict[str, Any]],
    *,
    findings: Optional[str],
    osv: Optional[str],
    asset: Optional[str],
    repo: str,
    repository_uri: Optional[str],
    commit: Optional[str],
    base: Optional[str],
    output: str,
    engine_name_map: Dict[str, str],
) -> int:
    cmd = [sys.executable, build_sarif, "--repo", repo, "--output", output]
    if findings:
        cmd += ["--findings", findings]
    if osv:
        cmd += ["--osv", osv]
    if asset:
        cmd += ["--asset", asset]
    if repository_uri:
        cmd += ["--repository-uri", repository_uri]
    if commit:
        cmd += ["--commit", commit]
    # Diff-scan (§3.4.5): pass --base so build_sarif stamps run.properties.torana.base_revision.
    if base:
        cmd += ["--base", base]
    for st in ran:
        if st["status"] == "ran":
            # Map the manifest engine name to build_sarif's known native-engine key.
            key = engine_name_map.get(st["engine"], st["engine"])
            cmd += ["--merge-sarif", f"{key}={st['sarif']}"]
    proc = subprocess.run(cmd)
    return proc.returncode


def _scan_base_in_worktree(
    manifest: Dict[str, Any],
    repo: str,
    base: str,
    changed: Set[str],
    only: Optional[List[str]],
    scan_types: Optional[List[str]],
) -> List[Dict[str, Any]]:
    """Scan <base> for the same changed files in a throwaway git worktree so the caller's
    working tree is never checked out / stashed / mutated (§3.4.3, the load-bearing safety
    decision). Only files that exist at <base> are scannable there; new-at-HEAD files are
    simply absent. The base scan runs the same engines restricted to the identical changed
    set (the §3.7 self-BLOCKER fix). Container image scanning is intentionally NOT run for
    the base (an image is a HEAD concept). Returns the engine status list (each 'ran' entry
    carries a 'sarif' path pointing inside the throwaway out-dir — read before cleanup)."""
    tmp = tempfile.mkdtemp(prefix="scanpack-base-")
    out_dir = tempfile.mkdtemp(prefix="scanpack-base-out-")
    added = False
    try:
        # --detach: check out <base> with no branch, isolated from the dev's tree.
        if _git(repo, "worktree", "add", "--detach", tmp, base) is None:
            return [{"engine": "base-worktree", "status": "failed",
                     "reason": f"git worktree add failed for base {base!r}"}]
        added = True
        # Base findings must be read into memory before cleanup removes the out-dir, so we
        # inline the SARIF docs onto each status here.
        statuses = _select_and_run(
            manifest, tmp, image=None, out_dir=out_dir, only=only,
            scan_types=scan_types, restrict_to=changed,
        )
        for st in statuses:
            if st.get("status") == "ran" and st.get("sarif"):
                try:
                    st["_doc"] = json.load(open(st["sarif"], encoding="utf-8"))
                except Exception:
                    st["_doc"] = {"runs": []}
        return statuses
    finally:
        if added:
            _git(repo, "worktree", "remove", "--force", tmp)
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)


def _fps(sarif_doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Map partialFingerprints['toranaSkill/v1'] -> a compact finding summary. The delta is a
    set-op on these fingerprints (§3.4.6) — line-drift-safe, synthesized by build_sarif.py."""
    out: Dict[str, Dict[str, Any]] = {}
    for run in (sarif_doc.get("runs") or []):
        for res in (run.get("results") or []):
            fp = (res.get("partialFingerprints") or {}).get("toranaSkill/v1")
            if fp:
                out[fp] = {
                    "ruleId": res.get("ruleId"),
                    "uri": (((res.get("locations") or [{}])[0].get("physicalLocation") or {})
                            .get("artifactLocation") or {}).get("uri"),
                    "message": ((res.get("message") or {}).get("text")),
                }
    return out


def _scan_delta(base_sarif: Dict[str, Any], head_sarif: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the fixed/new/unchanged delta by set operations on partialFingerprints:
    fixed = base − head, new = head − base, unchanged = base ∩ head (§3.4.6)."""
    b, h = _fps(base_sarif), _fps(head_sarif)
    fixed = [b[k] for k in b.keys() - h.keys()]
    new = [h[k] for k in h.keys() - b.keys()]
    unchanged = [h[k] for k in b.keys() & h.keys()]
    return {
        "base_scanned": True,
        "fixed": fixed,
        "new": new,
        "unchanged": unchanged,
        "counts": {"fixed": len(fixed), "new": len(new), "unchanged": len(unchanged)},
    }


def _finding_file(f: Dict[str, Any]) -> Optional[str]:
    """Extract the file path from a Claude/OSV finding dict (both the flat shape and the
    legacy osv coordinates.{file} shape — matching build_sarif._result_from_finding)."""
    coords = f.get("coordinates") or {}
    return f.get("file") or coords.get("file") or (f.get("package") or {}).get("manifest") \
        or coords.get("manifest")


def _restrict_findings_file(path: Optional[str], restrict_to: Set[str], out_dir: str,
                            label: str) -> Optional[str]:
    """Filter a Claude/OSV findings JSON list to findings whose file is in `restrict_to`
    (diff-scan gating, §3.4.4). Findings with no extractable file are kept (can't prove they
    are out of scope). Writes a filtered copy into out_dir and returns its path; returns the
    original path unchanged if it can't be read/parsed as a list; None stays None."""
    if not path:
        return path
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return path
    if not isinstance(data, list):
        return path
    norm_keep = {_norm_uri(p) for p in restrict_to}
    kept = [f for f in data
            if (_finding_file(f) is None) or (_norm_uri(_finding_file(f)) in norm_keep)]
    os.makedirs(out_dir, exist_ok=True)
    dst = os.path.join(out_dir, f"_diff_{label}.json")
    try:
        with open(dst, "w", encoding="utf-8") as fh:
            json.dump(kept, fh)
    except Exception:
        return path
    return dst


def _emit_diff_delta(
    manifest: Dict[str, Any],
    repo: str,
    args,
    only: Optional[List[str]],
    scan_types: Optional[List[str]],
    changed: Set[str],
    head_ran: List[Dict[str, Any]],
) -> int:
    """Run the base scan in an isolated worktree, build a base SARIF (matching fingerprint
    scheme), compute the fixed/new/unchanged delta vs the HEAD SARIF at args.output, write
    scan-delta.json, and print the summary. Never raises — a delta failure must not sink a
    successful HEAD scan (the HEAD SARIF is already written)."""
    delta_path = args.delta_output or os.path.join(
        os.path.dirname(os.path.abspath(args.output)) or ".", "scan-delta.json")

    # Empty changed set (e.g. --base HEAD) → no-op delta, no base scan needed.
    if not changed:
        delta = {"base_scanned": True, "fixed": [], "new": [], "unchanged": [],
                 "counts": {"fixed": 0, "new": 0, "unchanged": 0}, "note": "no changed files"}
        _write_delta(delta_path, delta)
        print("Diff-scan delta:  Fixed: 0  New: 0  Unchanged: 0  (no changed files)")
        return 0

    # Load the already-written HEAD SARIF (carries partialFingerprints).
    try:
        with open(args.output, encoding="utf-8") as fh:
            head_sarif = json.load(fh)
    except Exception as exc:
        print(f"WARNING: diff-scan could not read HEAD SARIF {args.output}: {exc}; "
              f"skipping delta.", file=sys.stderr)
        return 0

    # Scan the base in a throwaway worktree (working tree never touched), engines restricted
    # to the same changed set. Statuses carry inlined SARIF docs on `_doc` (read before cleanup).
    base_statuses = _scan_base_in_worktree(manifest, repo, args.base, changed, only, scan_types)
    base_ran = [s for s in base_statuses if s.get("status") == "ran" and s.get("_doc")]
    print("Diff-scan base:")
    for s in base_statuses:
        if s.get("status") == "ran":
            print(f"  ✓ {s['engine']:<14} {s.get('results', 0)} finding(s) (base)")
        elif s.get("status") == "skipped":
            print(f"  – {s['engine']:<14} skipped — {s.get('reason', '')} (base)")
        else:
            print(f"  ✗ {s['engine']:<14} FAILED — {s.get('reason', '')} (base)")

    # Build the base SARIF through build_sarif so its partialFingerprints match HEAD's scheme.
    # Base engine SARIFs were written into a throwaway dir already removed — re-materialize the
    # inlined docs to temp files for the merge. Base Claude/OSV findings come from --base-findings
    # / --base-osv (restricted to the changed set), if the caller supplied them.
    tmp_dir = tempfile.mkdtemp(prefix="scanpack-basemerge-")
    try:
        base_merge_inputs: List[Dict[str, str]] = []
        name_map = {e["name"]: e["name"] for e in manifest.get("engines", [])}
        for st in base_ran:
            p = os.path.join(tmp_dir, f"{st['engine']}.sarif")
            try:
                with open(p, "w", encoding="utf-8") as fh:
                    json.dump(st["_doc"], fh)
                base_merge_inputs.append({"engine": name_map.get(st["engine"], st["engine"]),
                                          "sarif": p, "status": "ran"})
            except Exception:
                continue
        base_findings = _restrict_findings_file(args.base_findings, changed, tmp_dir, "base_findings")
        base_osv = _restrict_findings_file(args.base_osv, changed, tmp_dir, "base_osv")
        base_out = os.path.join(tmp_dir, "base.sarif")

        base_sarif = {"version": "2.1.0", "runs": []}
        if base_merge_inputs or base_findings or base_osv:
            rc = _merge_with_build_sarif(
                args.build_sarif, base_merge_inputs,
                findings=base_findings, osv=base_osv, asset=args.asset,
                repo=repo, repository_uri=args.repository_uri, commit=args.base,
                base=None, output=base_out, engine_name_map=name_map,
            )
            if rc == 0:
                try:
                    with open(base_out, encoding="utf-8") as fh:
                        base_sarif = json.load(fh)
                except Exception:
                    pass

        delta = _scan_delta(base_sarif, head_sarif)
        _write_delta(delta_path, delta)
        c = delta["counts"]
        print(f"Diff-scan delta:  Fixed: {c['fixed']}  New: {c['new']}  "
              f"Unchanged: {c['unchanged']}   → {delta_path}")
        return 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _write_delta(path: str, delta: Dict[str, Any]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(delta, fh, indent=2)
    except Exception as exc:
        print(f"WARNING: could not write scan-delta to {path}: {exc}", file=sys.stderr)


def _findings_nonempty(path: Optional[str]) -> bool:
    """True if `path` is a JSON file holding a non-empty list. A filtered findings file may be an
    empty list (truthy path, no content), which build_sarif rejects — this distinguishes them."""
    if not path:
        return False
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return isinstance(data, list) and len(data) > 0
    except Exception:
        # Unreadable/unparseable → let the merge decide (treat as "has input" so nothing is lost).
        return True


def _write_empty_head_sarif(output: str, base: Optional[str]) -> None:
    """Write a minimal valid Torana-profile SARIF with zero findings (diff-scan HEAD had no
    findings in the changed set). Still carries the run-level base_revision marker (§3.4.5)."""
    torana: Dict[str, Any] = {}
    if base:
        torana["base_revision"] = base
    run: Dict[str, Any] = {"tool": {"driver": {"name": "claude_review", "rules": []}},
                           "results": []}
    if torana:
        run["properties"] = {"torana": torana}
    doc = {"version": "2.1.0", "runs": [run]}
    try:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
    except Exception as exc:
        print(f"WARNING: could not write empty HEAD SARIF to {output}: {exc}", file=sys.stderr)


def _run_deep_tier(vvah_run: str, repo: str, scan_types: Optional[List[str]], args) -> Dict[str, Any]:
    """Opt-in deep tier (SC2): shell out to vvah_run.py (VVAH agentic SAST) and return
    its status dict. VVAH is deep *SAST*, so it runs only when SAST is in scope. Never
    raises — a deep-tier failure never sinks the fast-tier scan."""
    if scan_types is not None and "sast" not in scan_types:
        return {"engine": "vvah", "status": "skipped", "reason": "SAST not selected (deep tier is deep SAST)"}
    cmd = [sys.executable, vvah_run, "--repo", repo, "--json"]
    if args.deep_config:
        cmd += ["--config", args.deep_config]
    if args.deep_backend:
        cmd += ["--backend", args.deep_backend]
    if args.deep_application_id:
        cmd += ["--application-id", args.deep_application_id]
    if args.deep_repo_name:
        cmd += ["--repo-name", args.deep_repo_name]
    if args.max_input_tokens is not None:
        cmd += ["--max-input-tokens", str(args.max_input_tokens)]
    if args.deep_estimate_only:
        cmd += ["--estimate-only"]
    if args.deep_allow_nested_cli:
        cmd += ["--allow-nested-cli"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.deep_timeout)
    except subprocess.TimeoutExpired:
        return {"engine": "vvah", "status": "failed", "reason": f"deep-tier timeout ({args.deep_timeout}s)"}
    except Exception as exc:  # noqa: BLE001 — deep tier must never crash the fast tier
        return {"engine": "vvah", "status": "failed", "reason": f"{type(exc).__name__}: {exc}"}
    try:
        return json.loads(proc.stdout)
    except (ValueError, json.JSONDecodeError):
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:]
        return {"engine": "vvah", "status": "failed",
                "reason": "vvah_run.py produced no JSON status" + (f": {tail[0][:160]}" if tail else "")}


def _preflight(manifest: Dict[str, Any], as_json: bool = False) -> int:
    """Report engine availability (local pinned bin → PATH) WITHOUT scanning. The
    deterministic check the skill runs first: its output names exactly which engines
    are missing, so the install offer is driven by a command result, not a guess.
    Always exits 0 (informational) — the caller reads `missing` / the ACTION line."""
    seen: Dict[str, Optional[str]] = {}
    for e in manifest.get("engines", []):
        seen.setdefault(e["binary"], e.get("version_pin"))
    rows: List[Dict[str, Any]] = []
    for binary, pin in seen.items():
        path = _resolve_binary(binary)
        if path:
            via = "local bin" if path.startswith(_LOCAL_BIN) else "PATH"
            rows.append({"binary": binary, "present": True,
                         "version": _binary_version(path) or "?", "via": via, "pin": pin})
        else:
            rows.append({"binary": binary, "present": False, "pin": pin})
    missing = [r["binary"] for r in rows if not r["present"]]

    if as_json:
        print(json.dumps({"all_present": not missing, "missing": missing, "engines": rows}, indent=2))
        return 0

    print("Scan Pack preflight (engine availability):")
    for r in rows:
        if r["present"]:
            print(f"  ✓ {r['binary']:<10} {r['version']}  ({r['via']})")
        else:
            print(f"  ✗ {r['binary']:<10} MISSING (pin {r['pin']})")
    if missing:
        print(f"\nACTION: {len(missing)} engine(s) missing ({', '.join(missing)}) — "
              f"those domains fall back to Claude review. Offer the user: run "
              f"install_engines.sh now (~1 min, checksum-verified) for real-engine "
              f"results, or proceed with the Claude fallback.")
    else:
        print("\nAll engines present — full Scan Pack available; no install needed.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Torana Scan Pack — router over a pinned multi-engine bundle.")
    ap.add_argument("--repo", default=".", help="Repo path to scan. Default: cwd.")
    ap.add_argument("--image", help="Container image ref (registry/repo@sha256:...) for the container engine.")
    ap.add_argument("--scan-types", dest="scan_types",
                    help="Comma-separated scan types to run: SAST,SCA,Secret,IaC,Container "
                         "(or 'all', the default). Picks which security domains scan; there is "
                         "one engine per type. SCA runs via OSV in the skill, not the Scan Pack.")
    ap.add_argument("--engines", help="Comma-separated ENGINE subset (finer than --scan-types; "
                                      "default: all whose domain matches).")
    ap.add_argument("--manifest", default=_DEFAULT_MANIFEST, help="Scan Pack manifest path.")
    ap.add_argument("--out-dir", default="/tmp/scanpack", help="Where per-engine SARIF lands.")
    ap.add_argument("--findings", help="Claude finding-dicts JSON (passed through to build_sarif).")
    ap.add_argument("--osv", help="OSV/SCA finding-dicts JSON (passed through to build_sarif).")
    ap.add_argument("--asset", help="asset-inventory.json (passed through to build_sarif).")
    ap.add_argument("--repository-uri", help="Explicit repo URI (overrides git remote).")
    ap.add_argument("--commit", help="Explicit commit sha.")
    ap.add_argument("--base", default=None,
                    help="Base commit sha. Enables diff-scan: only files/manifests changed "
                         "since <base>..HEAD are scanned (both HEAD and <base>, restricted to the "
                         "identical changed set), and a fixed/new/unchanged delta is written to "
                         "scan-delta.json next to --output. The base scan runs in an isolated git "
                         "worktree — the working tree is never touched.")
    ap.add_argument("--delta-output", dest="delta_output", default=None,
                    help="Where the diff-scan delta JSON is written (default: scan-delta.json next "
                         "to --output).")
    ap.add_argument("--base-findings", dest="base_findings", default=None,
                    help="Diff-scan only: Claude finding-dicts JSON for the BASE commit (if the "
                         "caller re-ran Claude SAST against the base worktree). Restricted to the "
                         "changed set and folded into the base SARIF so Claude findings participate "
                         "in the delta. Omit → base Claude findings are empty (HEAD Claude findings "
                         "in changed files then classify as 'new').")
    ap.add_argument("--base-osv", dest="base_osv", default=None,
                    help="Diff-scan only: OSV/SCA finding-dicts JSON for the BASE commit. Same role "
                         "as --base-findings for the SCA dimension.")
    ap.add_argument("--build-sarif", default=_DEFAULT_BUILD_SARIF, help="Path to build_sarif.py.")
    ap.add_argument("--output", default="./scan.sarif", help="Final merged SARIF path.")
    ap.add_argument("--no-merge", action="store_true", help="Run engines only; skip the build_sarif merge.")
    ap.add_argument("--preflight", action="store_true",
                    help="Report engine availability and exit (no scan). The skill runs this first.")
    ap.add_argument("--json", action="store_true", help="Machine-readable output (only used with --preflight).")
    # ── deep tier (SC2, opt-in) — VVAH agentic SAST via vvah_run.py ────────────────
    ap.add_argument("--deep", action="store_true",
                    help="Also run the VVAH deep tier (agentic SAST) — OFF by default (token-hungry). "
                         "Runs only when SAST is in scope; merged as a 'vvah' SARIF run.")
    ap.add_argument("--vvah-run", dest="vvah_run", default=_DEFAULT_VVAH_RUN, help="Path to vvah_run.py.")
    ap.add_argument("--deep-sarif", dest="deep_sarif",
                    help="Fold in a VVAH SARIF produced OUTSIDE the skill (the 'run in a separate "
                         "terminal' path). Merged as the 'vvah' run; does not launch VVAH here.")
    ap.add_argument("--deep-config", dest="deep_config",
                    help="VVAH config YAML (backend + per-stage max_budget_usd). Omit → cli backend, no key.")
    ap.add_argument("--deep-backend", dest="deep_backend", choices=["cli", "sdk", "openai"],
                    help="VVAH backend (default: cli — Claude Code login, no key).")
    ap.add_argument("--deep-application-id", dest="deep_application_id", help="VVAH application id (Torana asset).")
    ap.add_argument("--deep-repo-name", dest="deep_repo_name", help="VVAH --repo-name (SARIF module tag).")
    ap.add_argument("--max-input-tokens", dest="max_input_tokens", type=int,
                    help="Deep-tier pre-gate: skip if `vvaharness estimate` reports more ~input tokens than this.")
    ap.add_argument("--deep-estimate-only", dest="deep_estimate_only", action="store_true",
                    help="Deep tier: run `vvaharness estimate` only (spends nothing), do not scan.")
    ap.add_argument("--deep-allow-nested-cli", dest="deep_allow_nested_cli", action="store_true",
                    help="Override the deep-tier guard that blocks the cli backend inside Claude Code "
                         "(nested claude → hang). Only if you know your setup handles it.")
    ap.add_argument("--deep-timeout", dest="deep_timeout", type=int, default=3900,
                    help="Deep-tier subprocess timeout in seconds (VVAH is slow).")
    args = ap.parse_args()

    manifest = _load_manifest(args.manifest)
    if args.preflight:
        return _preflight(manifest, as_json=args.json)

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"ERROR: repo path not found: {repo}", file=sys.stderr)
        return 2

    only = [e.strip() for e in args.engines.split(",")] if args.engines else None
    scan_types = _normalize_scan_types(args.scan_types)
    if scan_types is not None:
        print(f"Scan types selected: {', '.join(scan_types)}", file=sys.stderr)

    # ── Diff-scan (T3): compute the changed-file set once, up front ────────────────
    # Both the HEAD scan and the base scan are restricted to this identical set — that is
    # the §3.7 self-BLOCKER fix (findings in unchanged files never enter the delta). An
    # invalid/unknown base sha fails here → abort cleanly, no partial delta.
    changed: Optional[Set[str]] = None
    if args.base:
        _changed_list = _changed_files(repo, args.base)
        if _changed_list is None:
            print(f"ERROR: diff-scan could not compute changed files for base {args.base!r} "
                  f"(invalid sha, or {repo} is not a git repo). Aborting — no partial delta.",
                  file=sys.stderr)
            return 2
        changed = set(_changed_list)
        print(f"Diff-scan: {len(changed)} changed file(s) since {args.base}..HEAD", file=sys.stderr)

    statuses = _select_and_run(manifest, repo, args.image, args.out_dir, only, scan_types,
                               restrict_to=changed)

    # Diff-scan: gate the Claude-SAST review (--findings) and OSV (--osv) inputs to the
    # changed set too (§3.4.4) — they are scan_pack INPUTS, not engine outputs, so the
    # per-engine URI post-filter above does not touch them. Write filtered copies.
    findings_arg = args.findings
    osv_arg = args.osv
    if changed is not None:
        findings_arg = _restrict_findings_file(args.findings, changed, args.out_dir, "findings")
        osv_arg = _restrict_findings_file(args.osv, changed, args.out_dir, "osv")

    # The manifest engine name IS the build_sarif native-engine key (semgrep,
    # trivy-config, trivy-image, gitleaks all already known there) — identity map.
    name_map = {e["name"]: e["name"] for e in manifest.get("engines", [])}

    ran = [s for s in statuses if s["status"] == "ran"]
    print("Scan Pack:")
    for s in statuses:
        if s["status"] == "ran":
            print(f"  ✓ {s['engine']:<14} {s.get('results', 0)} finding(s)")
        elif s["status"] == "skipped":
            print(f"  – {s['engine']:<14} skipped — {s['reason']}")
        else:
            print(f"  ✗ {s['engine']:<14} FAILED — {s['reason']}")

    # ── deep tier (opt-in) — merged as the 'vvah' run when it produces SARIF ───────
    # --deep-sarif: fold in a VVAH SARIF produced OUTSIDE the skill (the "run in a
    # separate terminal" path — no nested claude). Takes precedence over running it.
    if args.deep_sarif:
        if os.path.isfile(args.deep_sarif):
            n = None
            try:
                doc = json.load(open(args.deep_sarif, encoding="utf-8"))
                n = sum(len(r.get("results") or []) for r in (doc.get("runs") or []))
            except Exception:
                pass
            print(f"  ✓ {'vvah (deep)':<14} {n if n is not None else '?'} finding(s) (merged from {args.deep_sarif})")
            ran.append({"engine": "vvah", "status": "ran", "sarif": args.deep_sarif})
        else:
            print(f"  ✗ {'vvah (deep)':<14} FAILED — --deep-sarif not found: {args.deep_sarif}")
    elif args.deep:
        d = _run_deep_tier(args.vvah_run, repo, scan_types, args)
        if d.get("status") == "ran":
            print(f"  ✓ {'vvah (deep)':<14} {d.get('results', 0)} finding(s)")
            ran.append({"engine": "vvah", "status": "ran", "sarif": d["sarif"]})
        elif d.get("status") in ("skipped", "estimated"):
            print(f"  – {'vvah (deep)':<14} {d['status']} — {d.get('reason', '')}")
        else:
            print(f"  ✗ {'vvah (deep)':<14} FAILED — {d.get('reason', '')}")

    # ⛔ A SELECTED SCAN TYPE THAT NOTHING SERVED IS A FAILURE, NOT A CLEAN RUN. This used
    # to print a line to stderr and `return 0` with no output file, so a CI job, a script
    # or a customer reading the exit code saw SUCCESS — and an empty result is
    # indistinguishable from "no vulnerabilities found". That is the worst shape a scanner
    # can fail in: it reports safety it never established.
    #
    # ⚠️ "Unserved" means NO engine covering that type RAN — whether because no engine
    # declares it, its binary is missing, or its target was absent. All three are cases
    # where the caller asked for a scan that did not happen, and all three must be visible.
    # Findings supplied out-of-band (--findings / --osv) DO serve their types, since the
    # caller produced them another way.
    unserved = _unserved_scan_types(manifest, scan_types, statuses,
                                    findings_arg, osv_arg)

    if args.no_merge:
        return 2 if unserved else 0

    # Is there anything real to merge? A filtered findings file can hold an empty list (the path
    # is truthy but there is nothing in it), which build_sarif rejects with exit 2. So gate on the
    # actual content, not just the path being set.
    has_head_input = bool(ran) or _findings_nonempty(findings_arg) or _findings_nonempty(osv_arg)

    if not has_head_input and changed is None:
        print("No engine produced findings and no Claude/OSV findings supplied — nothing to merge.",
              file=sys.stderr)
        if unserved:
            _report_unserved(unserved)
            return 2
        return 0

    rc = 0
    if has_head_input:
        rc = _merge_with_build_sarif(
            args.build_sarif, ran,
            findings=findings_arg, osv=osv_arg, asset=args.asset,
            repo=repo, repository_uri=args.repository_uri, commit=args.commit,
            base=args.base, output=args.output, engine_name_map=name_map,
        )
        if rc != 0:
            return rc
    elif changed is not None:
        # Diff-scan mode with zero HEAD findings in the changed set: still write a valid (empty)
        # HEAD SARIF so a downstream ingest/read has a real document, then emit the delta below
        # (everything in the base becomes 'fixed').
        _write_empty_head_sarif(args.output, args.base)

    # ── Diff-scan (T3): base scan in an isolated worktree + fixed/new/unchanged delta ──
    if changed is not None:
        rc = _emit_diff_delta(manifest, repo, args, only, scan_types, changed, ran)

    # Record the unserved types IN the document as well as on the exit code. The exit code
    # protects whoever watches it; the SARIF protects everyone downstream — after ingest,
    # the receipt is the only artefact left, and "this type was not scanned" must survive
    # in it. `executionSuccessful: false` is SARIF's own way to say the run did not do
    # what it set out to.
    if unserved:
        _stamp_unserved_in_sarif(args.output, unserved)
        _report_unserved(unserved)
        rc = rc or 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
