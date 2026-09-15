#!/usr/bin/env python3
"""
fleet_scan.py — multi-repo / fleet scanning (SC1, S6).

Takes SC0's single-repo Scan Pack and runs it across a SET of repos (e.g. the
whole `pantheon-*` org), producing ONE asset-tagged SARIF per repo plus a
`batch_summary.json` roll-up. This is the "scan the whole fleet" core.

Repo set comes from one of:
  --repos a,b,c        explicit: local paths and/or <owner>/<repo> (cloned)
  --repos @file        same, one entry per line
  --root DIR           every git repo found under DIR
  --github-org ORG     enumerate via `gh repo list ORG` (needs gh + auth)

Each repo runs through `scan_pack.py` (real binary engines — semgrep/Trivy/
Gitleaks where installed). Claude-review SAST is NOT run at fleet scale (it's a
single-repo / deep-tier concern); fleet mode is the automated binary-engine sweep.
With --push, each repo's SARIF is sent via `torana ingest sarif`.

Deliberately OUT of v1 (deferred, see the implementation doc):
  - group-by-service rollup  → needs the asset graph (P4)
  - incremental / auto-nightly scheduling → needs the scheduler (P2)

Stdlib-only so it runs in the skill sandbox.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_SCAN_PACK = os.path.join(_HERE, "scan_pack.py")


def _run(cmd: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _discover_repos(args) -> List[Dict[str, str]]:
    """Resolve the repo set to a list of {ref, kind} where kind ∈ {local, remote}.
    `ref` is a local path (local) or an <owner>/<repo> (remote, to be cloned)."""
    repos: List[Dict[str, str]] = []

    if args.github_org:
        try:
            out = _run([
                "gh", "repo", "list", args.github_org,
                "--limit", str(args.max_repos or 1000),
                "--json", "nameWithOwner", "-q", ".[].nameWithOwner",
            ])
            for line in (out.stdout or "").splitlines():
                line = line.strip()
                if line:
                    repos.append({"ref": line, "kind": "remote"})
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: gh repo list failed: {exc}", file=sys.stderr)

    if args.root:
        for root, dirs, _files in os.walk(args.root):
            if ".git" in dirs:
                repos.append({"ref": os.path.abspath(root), "kind": "local"})
                dirs[:] = [d for d in dirs if d != ".git"]  # don't descend into nested .git

    if args.repos:
        raw = args.repos
        if raw.startswith("@"):
            with open(raw[1:], encoding="utf-8") as fh:
                entries = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        else:
            entries = [e.strip() for e in raw.split(",") if e.strip()]
        for e in entries:
            if os.path.isdir(e):
                repos.append({"ref": os.path.abspath(e), "kind": "local"})
            else:
                repos.append({"ref": e, "kind": "remote"})  # <owner>/<repo>

    # De-dupe, preserve order, honor max-repos.
    seen, uniq = set(), []
    for r in repos:
        if r["ref"] in seen:
            continue
        seen.add(r["ref"])
        uniq.append(r)
    if args.max_repos:
        uniq = uniq[: args.max_repos]
    return uniq


def _ensure_local(repo: Dict[str, str], workdir: str) -> Optional[str]:
    """Return a local path for the repo, cloning a remote one (shallow) if needed."""
    if repo["kind"] == "local":
        return repo["ref"]
    owner_repo = repo["ref"]
    dest = os.path.join(workdir, owner_repo.replace("/", "__"))
    if os.path.isdir(os.path.join(dest, ".git")):
        return dest
    os.makedirs(workdir, exist_ok=True)
    url = owner_repo if owner_repo.startswith(("http://", "https://", "git@")) \
        else f"https://github.com/{owner_repo}.git"
    try:
        proc = _run(["git", "clone", "--depth", "1", url, dest], timeout=600)
        if proc.returncode != 0:
            return None
        return dest
    except Exception:
        return None


def _sarif_stats(path: str) -> Dict[str, Any]:
    """Engines + finding count + repo URI from a produced SARIF doc."""
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"engines": [], "findings": 0, "repo_uri": None}
    engines, n, uri = [], 0, None
    for run in doc.get("runs") or []:
        engines.append((run.get("tool", {}).get("driver", {}) or {}).get("name", "?"))
        n += len(run.get("results") or [])
        if uri is None:
            vcp = (run.get("versionControlProvenance") or [{}])[0]
            uri = vcp.get("repositoryUri")
    return {"engines": engines, "findings": n, "repo_uri": uri}


def _scan_one(repo: Dict[str, str], args) -> Dict[str, Any]:
    """Scan one repo end-to-end. Crash-proof: returns a status dict, never raises."""
    ref = repo["ref"]
    res: Dict[str, Any] = {"ref": ref, "kind": repo["kind"], "status": "failed"}
    path = _ensure_local(repo, args.workdir)
    if not path:
        res["reason"] = "clone/locate failed"
        return res

    safe = ref.replace("/", "__").replace(os.sep, "__")
    sarif_path = os.path.join(args.out_dir, f"{safe}.sarif")
    engine_out = os.path.join(args.out_dir, f"{safe}.engines")
    cmd = [
        sys.executable, args.scan_pack, "--repo", path,
        "--out-dir", engine_out, "--output", sarif_path,
    ]
    if args.engines:
        cmd += ["--engines", args.engines]
    if args.scan_types:
        cmd += ["--scan-types", args.scan_types]
    # Deep tier (opt-in) — fleet-wide flags only; per-repo id/name are left to VVAH's
    # defaults. NOTE: VVAH is token-hungry — --deep across a whole fleet is costly.
    if args.deep:
        cmd += ["--deep"]
        if args.deep_config:
            cmd += ["--deep-config", args.deep_config]
        if args.deep_backend:
            cmd += ["--deep-backend", args.deep_backend]
        if args.max_input_tokens is not None:
            cmd += ["--max-input-tokens", str(args.max_input_tokens)]
    try:
        proc = _run(cmd, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        res["reason"] = f"scan timeout ({args.timeout}s)"
        return res
    except Exception as exc:  # noqa: BLE001
        res["reason"] = f"{type(exc).__name__}: {exc}"
        return res

    if not os.path.exists(sarif_path):
        res["reason"] = f"no SARIF produced (scan_pack rc={proc.returncode})"
        res["scan_pack_tail"] = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        return res

    stats = _sarif_stats(sarif_path)
    res.update({"status": "scanned", "sarif": sarif_path,
                "engines": stats["engines"], "findings": stats["findings"],
                "repo_uri": stats["repo_uri"]})

    if args.push:
        push = [args.torana, "ingest", "sarif", sarif_path, "--format", "json", "--raw"]
        try:
            p = _run(push, timeout=300)
            if p.returncode == 0:
                res["status"] = "pushed"
                try:
                    res["receipt"] = json.loads(p.stdout)
                except Exception:
                    res["receipt"] = (p.stdout or "").strip()[:200]
            else:
                res["push_error"] = (p.stderr or p.stdout or "").strip().splitlines()[-1:]
        except Exception as exc:  # noqa: BLE001
            res["push_error"] = f"{type(exc).__name__}: {exc}"
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="Torana fleet scanner — Scan Pack across many repos (SC1).")
    src = ap.add_argument_group("repo set (use one or more)")
    src.add_argument("--repos", help="Comma list or @file of local paths and/or <owner>/<repo>.")
    src.add_argument("--root", help="Scan every git repo found under this directory.")
    src.add_argument("--github-org", help="Enumerate repos via `gh repo list <org>`.")
    ap.add_argument("--workdir", default="/tmp/fleet-repos", help="Where remote repos are cloned.")
    ap.add_argument("--out-dir", default="./fleet-out", help="Per-repo SARIF + batch_summary.json land here.")
    ap.add_argument("--concurrency", type=int, default=4, help="Repos scanned in parallel.")
    ap.add_argument("--timeout", type=int, default=1800, help="Per-repo scan timeout (seconds).")
    ap.add_argument("--max-repos", type=int, help="Cap the number of repos (cost guard).")
    ap.add_argument("--push", action="store_true", help="Push each repo's SARIF via `torana ingest sarif`.")
    ap.add_argument("--engines", help="Pass-through engine subset to scan_pack.py.")
    ap.add_argument("--scan-types", dest="scan_types",
                    help="Pass-through scan-type subset to scan_pack.py: "
                         "SAST,SCA,Secret,IaC,Container (or 'all', the default).")
    ap.add_argument("--deep", action="store_true",
                    help="Also run the VVAH deep tier per repo (agentic SAST). OFF by default; "
                         "token-hungry — --deep across a whole fleet is expensive.")
    ap.add_argument("--deep-config", dest="deep_config", help="VVAH config YAML (backend + budget caps).")
    ap.add_argument("--deep-backend", dest="deep_backend", choices=["cli", "sdk", "openai"],
                    help="VVAH backend (default cli — Claude Code login, no key).")
    ap.add_argument("--max-input-tokens", dest="max_input_tokens", type=int,
                    help="Per-repo deep-tier pre-gate (skip a repo whose estimate exceeds this).")
    ap.add_argument("--scan-pack", dest="scan_pack", default=_DEFAULT_SCAN_PACK, help="Path to scan_pack.py.")
    ap.add_argument("--torana", default="torana", help="torana CLI (for --push).")
    args = ap.parse_args()

    if not (args.repos or args.root or args.github_org):
        print("ERROR: provide a repo set (--repos / --root / --github-org)", file=sys.stderr)
        return 2

    repos = _discover_repos(args)
    if not repos:
        print("No repos resolved from the given inputs.", file=sys.stderr)
        return 1
    os.makedirs(args.out_dir, exist_ok=True)
    print(f"Fleet scan: {len(repos)} repo(s), concurrency={args.concurrency}, push={args.push}")

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futs = {pool.submit(_scan_one, r, args): r for r in repos}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            results.append(res)
            tag = {"scanned": "✓", "pushed": "⇧", "failed": "✗"}.get(res["status"], "?")
            extra = f"{res.get('findings', 0)} finding(s) {res.get('engines', [])}" \
                if res["status"] in ("scanned", "pushed") else res.get("reason", "")
            print(f"  {tag} {res['ref']:<45} {extra}")

    scanned = [r for r in results if r["status"] in ("scanned", "pushed")]
    summary = {
        "repos_total": len(repos),
        "repos_scanned": len(scanned),
        "repos_failed": len(results) - len(scanned),
        "findings_total": sum(r.get("findings", 0) for r in scanned),
        "pushed": sum(1 for r in results if r["status"] == "pushed"),
        "results": results,
    }
    summary_path = os.path.join(args.out_dir, "batch_summary.json")
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(f"\nbatch_summary: {summary['repos_scanned']}/{summary['repos_total']} scanned, "
          f"{summary['findings_total']} finding(s), {summary['repos_failed']} failed → {summary_path}")
    return 0 if scanned else 1


if __name__ == "__main__":
    sys.exit(main())
