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
        # ⚠️ Say WHICH of the three it was. "clone/locate failed" conflates "not a git
        # repo", "cannot read it" and "clone failed", and the operator cannot tell them
        # apart. MEASURED on demo: both repos reported this, and the real cause was that
        # the scanner user could not traverse /home/<owner> (mode 0750) — a one-line
        # group fix that took far longer to find than it should have.
        reason = "clone/locate failed"
        if repo["kind"] == "local":
            if not os.path.isdir(ref):
                reason = f"path does not exist or is not a directory: {ref}"
            elif not os.access(ref, os.R_OK | os.X_OK):
                reason = (f"permission denied reading {ref} — the scanner user cannot "
                          f"traverse it (check directory modes and group membership)")
            elif not os.path.isdir(os.path.join(ref, ".git")):
                reason = f"not a git repository (no .git): {ref}"
        res["reason"] = reason
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

    # ⛔ CARRY scan_pack's PER-ENGINE FAILURES FORWARD. `engines` above is derived from
    # the SARIF runs, so it lists only the engines that SUCCEEDED — an engine that
    # crashed leaves no run and silently vanishes from the report. scan_pack already
    # prints "✗ <name> FAILED — <reason>" for it, but the branch above consults that
    # output only when NO SARIF was produced at all, so a partial loss was discarded
    # while the repo still reported "scanned".
    # ⚠️ MEASURED on a systemd host: semgrep and trivy-fs both died on a read-only
    # $HOME, and the run printed "6 -> 2 finding(s) ['trivy-config', 'gitleaks']",
    # "0 failed", and exited 0. Half the coverage was gone — no SAST, no dependency
    # findings — and nothing anywhere said so. That is the exact shape this scanner
    # must never have: a missing engine looking like a clean repository.
    # ⚠️ FAILED and skipped are kept APART on purpose. "trivy-image skipped — no
    # container target in repo" is the correct, expected outcome for any repository
    # without a Dockerfile, so counting it as a problem would fire the warning below on
    # nearly every repo — and a warning that always fires is one the operator learns to
    # scroll past, which is how the real one gets missed. Only an engine that was
    # selected and then FAILED reduces coverage unexpectedly.
    _lines = [ln.strip() for ln in
              ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines()]
    res["engine_problems"] = [ln for ln in _lines if "FAILED —" in ln]
    res["engine_skips"] = [ln for ln in _lines if "skipped —" in ln]

    if args.push:
        # ⛔ `--scan-scope full` IS NOT OPTIONAL HERE, and omitting it silently breaks
        # the finding lifecycle. A fleet scan is always whole-tree — this file passes
        # `--base` nowhere — but the server cannot know that, so an ingest with no
        # declared scope is read as `changed` (the fail-safe default), and a `changed`
        # scan RETIRES NOTHING. A nightly fleet scan would then accumulate findings
        # forever and never close one, with every run reporting success.
        # ⚠️ The default is deliberately the safe direction: in a partial scan a
        # finding's absence means NOT EXAMINED, and acting on it would mass-clear an
        # inventory. So the burden is on a full-tree scanner to say so, which is here.
        push = [args.torana, "ingest", "sarif", sarif_path,
                "--scan-scope", "full", "--format", "json", "--raw"]
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
        # ⛔ A REFUSED PUSH IS A FAILED RUN. The status stays "scanned", which the
        # per-repo line renders as ✓ rather than ⇧ — a one-character difference nobody
        # reads. Everything else said success: "2/2 scanned, 132 finding(s), 0 failed".
        # MEASURED on demo: both repos scanned clean and the server refused both
        # documents ("keyless SARIF cannot be linked (D7)") because the scanner could
        # not read the git remote. 236 findings were computed and discarded, and the
        # only trace was a `push_error` key inside batch_summary.json in a mktemp dir
        # the script deletes on exit. Print it, on stderr, under the repo it belongs to.
        if res.get("push_error"):
            res["status"] = "push_failed"
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
            tag = {"scanned": "✓", "pushed": "⇧",
                   "push_failed": "✗", "failed": "✗"}.get(res["status"], "?")
            extra = f"{res.get('findings', 0)} finding(s) {res.get('engines', [])}" \
                if res["status"] in ("scanned", "pushed", "push_failed") else res.get("reason", "")
            print(f"  {tag} {res['ref']:<45} {extra}")
            # ⛔ The rejection, in full, right here. Without this the only signal that a
            # scan was thrown away is ✓ instead of ⇧.
            for line in (res.get("push_error") or []) if isinstance(res.get("push_error"), list) \
                    else ([res["push_error"]] if res.get("push_error") else []):
                print(f"      ⛔ INGEST REFUSED — {str(line).strip()}", file=sys.stderr)
            # ⚠️ Printed under the repo it belongs to, and to stderr so it survives a
            # caller that keeps only stdout. A reduced-coverage run is not a success
            # worth reporting quietly. Benign skips go to stdout at normal volume —
            # visible, because "skipped with a message" is the contract, but not alarming.
            for problem in res.get("engine_problems", []):
                print(f"      ⚠️  {problem}", file=sys.stderr)
            for skipped in res.get("engine_skips", []):
                print(f"      {skipped}")

    scanned = [r for r in results if r["status"] in ("scanned", "pushed")]
    # ⚠️ Counted separately from repos_failed, which counts REPOSITORIES. The old
    # summary said "0 failed" for a run that lost two of four engines, because no
    # repository had failed — technically true and completely misleading.
    degraded = [r for r in results if r.get("engine_problems")]
    refused = [r for r in results if r.get("push_error")]
    summary = {
        "repos_total": len(repos),
        "repos_scanned": len(scanned),
        "repos_failed": len(results) - len(scanned),
        "repos_degraded": len(degraded),
        "repos_push_refused": len(refused),
        "findings_total": sum(r.get("findings", 0) for r in scanned),
        "pushed": sum(1 for r in results if r["status"] == "pushed"),
        "results": results,
    }
    summary_path = os.path.join(args.out_dir, "batch_summary.json")
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(f"\nbatch_summary: {summary['repos_scanned']}/{summary['repos_total']} scanned, "
          f"{summary['findings_total']} finding(s), {summary['repos_failed']} failed"
          + (f", {summary['repos_degraded']} with ENGINE PROBLEMS" if degraded else "")
          + (f", {summary['repos_push_refused']} INGEST REFUSED" if refused else "")
          + f" → {summary_path}")
    if refused:
        # ⛔ Louder than a degraded run, because NOTHING was recorded: the findings were
        # computed, the server rejected the document, and the platform's view of these
        # repositories did not change at all. A scanner whose pushes are refused looks
        # identical, from the platform, to a scanner nobody installed.
        print(f"ERROR: {len(refused)} repository(ies) scanned but the INGEST WAS REFUSED — "
              "those findings reached nothing. The reason is printed under each repo "
              "above. A common cause is the scanner being unable to read a repo's git "
              "remote (git refuses foreign-owned checkouts), which produces a keyless "
              "SARIF the server cannot link; fix with: "
              "git config --global --add safe.directory <repo>", file=sys.stderr)
    if degraded:
        # ⛔ Loud, and on stderr, because this run's zeros do not mean what they look
        # like. The scan still pushed what it found — dropping it would be worse — but
        # the domains whose engine died were NOT examined, and under a full scan an
        # unexamined domain is indistinguishable from a clean one at a glance.
        print(f"WARNING: {len(degraded)} repository(ies) scanned with FEWER ENGINES than "
              "selected. The domains those engines cover were not examined, so their "
              "absence of findings means nothing. Fix the engine or narrow "
              "TORANA_SCAN_TYPES deliberately — do not leave it to chance.",
              file=sys.stderr)
    return 0 if scanned else 1


if __name__ == "__main__":
    sys.exit(main())
