#!/usr/bin/env python3
"""Plan the fix PRs for a checkout's dependency findings, deterministically, with no model.

    findings  →  this script  →  a plan: groups by resolve, each with a class, a target, exact edits, evidence

REMEDIATION_BUILD.md § 2 (phase 2), FIX_PR_DESIGN.md § "One PR per resolve" and § "Classes 2 and 3",
REMEDIATION_ECOSYSTEMS.md § "Declare versus resolve". Read-only: nothing is edited, nothing is run.

THE ONE QUESTION, per package: does the fix change what we DECLARE, or only what we RESOLVE?

  class 2            every declaration in scope already admits the fix: recompile the lock, no manifest touched
  class 3            a declaration in scope blocks it (an exact pin, a range too narrow): edit that line, then
                     recompile. Also the removal sub-case: no fix is published, the package is declared here, and the
                     import scan says `not_imported`
  not_declared_here  no manifest or lock in scope declares or resolves it: the lever is outside these trees (an OS
                     package is a base rebuild, class 1)
  declined           the facts cannot decide, and the reason says which fact is missing. `policy.admits` returning
                     None, a lock that resolves another version than the one scanned, an unreadable manifest, no
                     published fix, or (`edit_needs_human`) a blocking declaration with no mechanical rewrite, such
                     as an upper bound below the fix. ⛔ A decline is never a guess, and never a class

⭐ THE SCOPE IS SEVERAL TREES, NOT ONE. A service image is built from more than its own checkout: A company's services
often install a shared base-image lock (the pip-compile output of a `requirements.in`) and then their own
`pyproject.toml`, and a shared library declares pins every service inherits. A package version can therefore be
resolved by the base-image lock while a service's own lock does not hold the package at all. So
`--with ROOT` adds a tree to the scope; the RESOLVE a group is keyed by is the lock that resolves the INSTALLED
version, and every edit names the repository it lands in. An edit outside `--repo` makes the group a PR set.

⭐ ONE LIBRARY, NO SECOND PARSER. Every manifest, lock, range and import fact comes from the vendored
`torana_reachability` (`lib/`): `manifests.read_manifests` / `declared` / `declarations_complete`,
`locks.read_requirements`, `policy.admits`, and `answer.answer` for the removal sub-case. ⛔ Never edit the copy.

⚠️ CLASS 4 IS NOT DECIDED HERE. Without an API diff (phase 3) the API diff is unknown, so a class-3 bump across a
major version may still be class 4. The plan says the lever; gates and the API diff say whether source must change too.

⚠️ `--json` EMITS ONLY JSON on stdout; every diagnostic goes to stderr.

Usage:
    python3 remediation_plan.py --repo ../service-a --with ../shared-lib \\
        --with ../deploy/base-image --findings findings.json [--json]

    python3 remediation_plan.py --repo . --alert ALERT_ID [--alert ALERT_ID]... [--findings-out F] [--json]

`PATH@REF` (on `--repo` and `--with`): read that tree's manifests and locks at commit REF (`git archive`), not the
working tree, e.g. `--with ../deploy-repo/base-image@origin/main`. Labels and `file:line` evidence still name
PATH; `scope[].commit` is REF's sha and `scope[].ref` is REF. Nothing is fetched: fetch first. A ref containing `@`
(`HEAD@{1}`) is not accepted; pass its sha.

`--findings-out FILE`: also write the findings planned, in the `--findings` shape (for `--alert`, the alert or its
open members), the input `torana remediation-plans propose --findings` takes.

`--findings`: a JSON array of `{ecosystem, package, installed, fixed, alert_id?}`; `fixed` null = no fix published.
The whole queue: `torana alerts reachability-queue --repository KEY --include-measured --as-findings`.

`--alert ID` (repeatable): the alert's findings, read through the `torana` CLI (`alert ID get`, and `alert ID members`
for an Inbox entry, which is planned as its open members). The package comes from the `finding_key`
(`finding:finding_key=<flaw>|<ecosystem>|<package>|<installed>|<place>`, the shape the reachability queue groups on),
the fix from `remediation_target_version`. ⛔ An alert that is not a package finding (a SAST finding, a Dockerfile's
CWE-250, a legacy `vulnerability:` key) is refused with exit 2, never planned. An entry's member that is not one is
left out and named in the output's `not_planned` (`{alert_id, entry_alert_id, why}`); the entry is refused only when
none of its open members can be planned.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ⭐ THE ENGINE IS A VENDORED LIBRARY (see reachability_pass.py): a self-relative path into the skill's own folder.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from torana_reachability import ENGINE_VERSION  # noqa: E402
from torana_reachability import answer as _answer  # noqa: E402
from torana_reachability import locks, manifests, policy  # noqa: E402
from torana_reachability.answer import components_of  # noqa: E402
from torana_reachability.firstparty import normalize  # noqa: E402
from torana_reachability.index import build_imports  # noqa: E402
# ⭐ ONE definition (FIX_KNOWLEDGE_CONVERGENCE § 3.4.2): the rewrite moved into the library, where `must_move` uses
# it too; re-exported here because `remediation_apply` calls `rp.propose_spec`.
from torana_reachability.move_together import propose_spec  # noqa: E402,F401
from torana_reachability import move_together as mt  # noqa: E402

CLASS_LOCK = "2"
CLASS_DECLARATION = "3"
#: The upgrade changes an API this repository calls (FIX_PR_SPEC.md § 3.4.6): reported with its call sites,
#: never fixed. A class-4 group edits no file and runs no resolver.
CLASS_CODE = "4"
NOT_DECLARED_HERE = "not_declared_here"
DECLINED = "declined"

#: The resolver invocation per lock format (FD § "Classes 2 and 3"): ONE per lock and group, every package in it,
#: because a lock cannot be recompiled twice independently. `{src}` / `{lock}` / `{pins}`.
#: ⛔ pip-compile has NO fixed command: a lock is recompiled with the exact argv its header records (`header_argv`).
#: A hand-built `uv pip compile requirements.in -o requirements.lock` drops `--universal --python-version 3.13`
#: and, run on a Mac, re-resolves the shared base lock for darwin.
_RECOMPILE = {
    "uv": ("uv lock", " --upgrade-package {pkg}=={ver}"),
    "poetry": ("poetry update", " {pkg}"),
    "pip-compile": ("{header}", " --upgrade-package {pkg}=={ver}"),
    # ⛔ never `npm install <pkg>@<ver>` for class 2: it rewrites the package.json range, which is class 3's edit.
    # `npm update` does not save package.json; class 3 has edited it already, so a bare install recompiles.
    "npm": ("npm update --package-lock-only", " {pkg}"),
}
_RECOMPILE_NPM_DECLARATION = ("npm install --package-lock-only", "")

#: ⛔ THE REMOVAL SUB-CASE IS OFF until OI-172 (FIX_PR_SPEC.md § 3.4.2): a no-fix package is declined `no_fix`
#: before the import scan runs, so no plan offers a removal. Measured: python-jose at agent-builder would otherwise
#: be proposed for removal on an import scan nobody has reviewed for this use.
REMOVALS_ENABLED = False


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


class LibraryTooOld(RuntimeError):
    """The vendored library lacks a function this script needs. Never worked around with a local parser."""


def header_argv(lock_path: str) -> List[str]:
    """The argv a pip-compile lock's header records (continuation lines included), from the LIBRARY
    (`manifests.pip_compile_argv`, torana-reachability 1.9.1). ⛔ Raises rather than parsing it here: a second
    parser of the header is the defect this replaces."""
    fn = getattr(manifests, "pip_compile_argv", None)
    if fn is None:
        raise LibraryTooOld("recompiling a pip-compile lock needs manifests.pip_compile_argv (torana-reachability "
                            ">= 1.9.1); the vendored library is older. Re-vendor it; never hand-build the command")
    with open(lock_path, encoding="utf-8") as fh:
        argv = fn(fh.read().splitlines())
    if not argv:
        raise LibraryTooOld(f"{lock_path} records no compile command in its header")
    return list(argv)


# ── is the lock current with its manifest? (lock_stale) ──────────────────────────────

#: `npm install --package-lock-only` with no package named: npm's "make the lock satisfy package.json", which
#: changes nothing on a current lock. `remediation_apply._NPM` is this list.
NPM_LOCK_ONLY = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
#: How many moved names a `lock_stale` reason spells out before "and N more".
_STALE_NAMES = 5
_COPY_SKIP = ("node_modules", ".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox")
FRESH, STALE, UNJUDGED, NOT_APPLICABLE = "fresh", "stale", "unjudged", "not_applicable"


def resolved_versions(root: str, lock_file: str) -> Dict[Tuple[str, Tuple[str, ...]], str]:
    """Every resolved copy in one lock: (package, parent chain) -> version."""
    return {(r["package"], tuple(r.get("nested_under") or ())): r["version"]
            for r in manifests.read_manifests(root, files=[lock_file])
            if r["kind"] == "resolution" and r.get("version")}


def relock_command(lock_path: str, fmt: str) -> Optional[List[str]]:
    """The resolver run with NO upgrade: what makes a lock agree with its manifest, and nothing else."""
    if fmt == "uv":
        return ["uv", "lock", "--no-progress"]
    if fmt == "pip-compile":
        return header_argv(lock_path)
    if fmt == "npm":
        return list(NPM_LOCK_ONLY)
    return None


def lock_freshness(root: str, lk: Dict[str, Any], run, scratch: str) -> Dict[str, Any]:
    """Would re-locking with NO upgrade change this lock? `{state, why?, remedy?, moved?, cmd?, timed_out?}`.

    ⛔ WHY IT EXISTS (2026-10-29, a Python service). `uv.lock` was out of date with its own pyproject, so the certifi fix's
    `uv lock --upgrade-package certifi==…` also wrote the 32 packages the lock had never recorded (+1164/−195,
    revision 1→3). Gate 2 listed them as "moved", `probe_summary` stored them as co-movers, and the only thing that
    refused the PR was the platform's lane — AFTER the push (B32), and for a header line, not the staleness. A fix
    must change what the fix changes. A lock that is already wrong is the repository's to correct first.

    ONE computation, two callers: the planner (the plan says so before anyone approves) and the probe/apply (the
    guard, before any write or push). Both pass the resolver boundary as `run(cmd, cwd)` — `remediation_apply._run`
    (credential-free env, own process group, `--resolver-timeout`) — so the suite's resolver doubles govern it too.

    ⛔ RUN ON A SCRATCH COPY of the UNMODIFIED tree, never the working copy: a re-lock writes, and a class-3 edit
    already applied to the copy would read as staleness.
    ⛔ ONLY A RESOLVER THAT ANSWERED CAN SAY `stale`. A failed, missing or timed-out resolver is `unjudged`: the
    check says nothing, and the caller takes its existing path (a timeout declines `resolver_timeout`; anything
    else proceeds to the fix's own resolve, whose verdict stands).
    ⚠️ Decided on RESOLVED VERSIONS (a copy added, removed or at another version), except uv, whose own `--check` is
    the authority. A pip-compile or npm re-lock that only reflows annotations is not called stale: that is a tool
    version difference, not a lock that disagrees with its manifest."""
    fmt, rel = lk["lock_format"], lk["file"]
    if fmt not in ("uv", "pip-compile", "npm"):
        return {"state": NOT_APPLICABLE}
    lock = os.path.join(root, rel)
    try:
        cmd = relock_command(lock, fmt)
    except (LibraryTooOld, OSError) as exc:
        return {"state": UNJUDGED, "why": f"the re-lock command could not be read: {exc}"}
    os.makedirs(scratch, exist_ok=True)
    box = tempfile.mkdtemp(prefix="lock-check-", dir=scratch)
    try:
        copy = os.path.join(box, "tree")
        shutil.copytree(root, copy, symlinks=True, ignore=shutil.ignore_patterns(*_COPY_SKIP))
        return _freshness_in(root, copy, lk, cmd, run)
    finally:
        shutil.rmtree(box, ignore_errors=True)


def _freshness_in(root: str, copy: str, lk: Dict[str, Any], cmd: List[str], run) -> Dict[str, Any]:
    """`lock_freshness` on its scratch copy."""
    fmt, rel = lk["lock_format"], lk["file"]
    cwd = os.path.dirname(os.path.join(copy, rel))
    first = cmd
    if fmt == "uv":
        # ⭐ uv's own answer first: `--check` writes nothing and says whether `uv lock` would change the file.
        first = ["uv", "lock", "--check", "--no-progress"]
        r = run(first, cwd)
        if r.get("timed_out"):
            return {"state": UNJUDGED, "timed_out": True, "cmd": r.get("cmd"),
                    "why": f"`{shlex.join(first)}` ran past the resolver cap: the lock was not judged"}
        if r["rc"] == 0:
            return {"state": FRESH, "cmd": r.get("cmd")}
        if "needs to be updated" not in (r.get("output") or ""):
            return {"state": UNJUDGED, "cmd": r.get("cmd"),
                    "why": f"`{shlex.join(first)}` exited {r['rc']} without judging the lock: "
                           f"{(r.get('output') or '').strip()[-300:]}"}
    r = run(cmd, cwd)
    if r.get("timed_out"):
        return {"state": UNJUDGED, "timed_out": True, "cmd": r.get("cmd"),
                "why": f"`{shlex.join(cmd)}` ran past the resolver cap: the lock was not judged"}
    if r["rc"] != 0:
        return {"state": UNJUDGED, "cmd": r.get("cmd"),
                "why": f"`{shlex.join(cmd)}` exited {r['rc']}, so the lock was not judged: "
                       f"{(r.get('output') or '').strip()[-300:]}"}
    before, after = resolved_versions(root, rel), resolved_versions(copy, rel)
    moved = [{"package": p, "from": before.get((p, c)), "to": after.get((p, c)),
              **({"nested_under": list(c)} if c else {})}
             for p, c in sorted(set(before) | set(after)) if before.get((p, c)) != after.get((p, c))]
    if not moved and fmt != "uv":
        return {"state": FRESH, "cmd": r.get("cmd")}
    names = sorted({m["package"] for m in moved})
    shown = ", ".join(names[:_STALE_NAMES]) + (f" and {len(names) - _STALE_NAMES} more" if len(names) > _STALE_NAMES
                                                else "")
    where = os.path.dirname(rel) or "."
    remedy = (f"the lock is out of date with its manifest: run `{shlex.join(cmd)}` in {lk.get('repo') or ''}"
              f"{'/' + where if where != '.' else ''}, commit it, then re-plan")
    what = (f"re-locking it with no upgrade changes {len(names)} package(s) ({shown})" if names else
            "`uv lock --check` says the lock needs to be updated (no resolved version changes: its recorded "
            "metadata disagrees with the manifest)")
    return {"state": STALE, "cmd": r.get("cmd"), "moved": moved,
            "why": f"{lk.get('repo') or ''}/{rel} is out of date with its manifest: {what}. A fix would ship "
                   f"those changes too",
            "remedy": remedy}


def _resolver_run(cmd: List[str], cwd: str) -> Dict[str, Any]:
    """The planner's resolver boundary IS the applier's (`remediation_apply._run`): the same credential-free env,
    process group and cap. Imported late because remediation_apply imports this module."""
    import remediation_apply
    return remediation_apply._run(cmd, cwd)


def lock_check_pass(rows: List[Dict[str, Any]], roots: List[Root], scratch: str, run=None) -> None:
    """Decline every class-2/3 row whose lock is out of date with its manifest (`lock_stale`), BEFORE anyone
    approves a plan that would ship the staleness. Each lock is checked once. An `unjudged` check changes no
    verdict; the row records it (`lock_check`) so the plan says the lock was not checked rather than implying it
    was."""
    run = run or _resolver_run
    paths = {r.label: r.path for r in roots}
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for i, row in enumerate(rows):
        if row["verdict"] not in (CLASS_LOCK, CLASS_DECLARATION):
            continue
        for lk in row.get("locks") or []:
            key = (lk["repo"], lk["file"])
            if key not in seen:
                seen[key] = (lock_freshness(paths[lk["repo"]], lk, run, scratch) if lk["repo"] in paths
                             else {"state": UNJUDGED, "why": f"{lk['repo']} is not a tree in scope"})
            res = seen[key]
            if res["state"] == STALE:
                rows[i] = {**_declined(row, f"{res['why']}. To fix: {res['remedy']}", [f"{lk['repo']}/{lk['file']}"],
                                       "lock_stale"),
                           "remedy": res["remedy"], "would_move": res["moved"]}
                break
            if res["state"] == UNJUDGED:
                row.setdefault("lock_check", []).append({"lock": f"{lk['repo']}/{lk['file']}", "state": UNJUDGED,
                                                         "why": res.get("why") or ""})


# ── the scope: one record set per tree ───────────────────────────────────────────────

class Root:
    """One tree in scope: its label (the path from `--repo`'s parent, so `deploy/base-image`), its
    manifest records, and its commit when it is a git checkout."""

    def __init__(self, path: str, label: str, primary: bool, commit: Optional[str] = None):
        self.path, self.label, self.primary = path, label, primary
        self.records = manifests.read_manifests(path)
        self.commit = commit or _git_head(path)
        self._requirements: Optional[List[Dict[str, Any]]] = None

    def requirements(self) -> List[Dict[str, Any]]:
        if self._requirements is None:
            self._requirements = locks.read_requirements(self.path)
        return self._requirements

    def has_manifests(self, eco: str) -> bool:
        return any(r["kind"] == "manifest_file" and r["ecosystem"] == eco and r["manifest_kind"] != "lockfile"
                   for r in self.records)


def _git_head(path: str) -> Optional[str]:
    try:
        p = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True, text=True)
    except OSError:
        return None
    return (p.stdout or "").strip() if p.returncode == 0 else None


class BadRef(ValueError):
    """A `PATH@REF` whose ref does not name a commit in PATH's repository."""


def _git(path: str, *args: str) -> Optional[str]:
    try:
        p = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True)
    except OSError:
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def split_ref(arg: str) -> Tuple[str, Optional[str]]:
    """`PATH@REF` → (PATH, REF), or (arg, None) for a plain path. Split on the LAST `@`, and only when the left side
    is a directory: a path that itself contains `@` stays a path."""
    path, sep, ref = arg.rpartition("@")
    if sep and ref and os.path.isdir(path):
        return path, ref
    return arg, None


def materialize(path: str, ref: str, into: str) -> Tuple[str, str]:
    """PATH's tree at REF, extracted under `into`: (the directory standing for PATH, REF's commit sha).

    ⭐ WHY: a fix lane builds its commit from `origin/<base>`, so a plan read from a stale or dirty working tree is
    wrong by the time it is committed. ⚠️ No fetch: `origin/main` is as fresh as the caller's last `git fetch`."""
    sha = _git(path, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    top = _git(path, "rev-parse", "--show-toplevel")
    prefix = _git(path, "rev-parse", "--show-prefix")
    if not sha or top is None or prefix is None:
        raise BadRef(f"{path}@{ref}: unknown ref (not a commit in {path}'s repository; fetch it first?)")
    dest = os.path.join(into, str(len(os.listdir(into))))
    os.makedirs(dest)
    spec = prefix.rstrip("/") or "."
    archive = subprocess.run(["git", "-C", top, "archive", "--format=tar", sha, "--", spec],
                             capture_output=True)
    if archive.returncode != 0:
        raise BadRef(f"{path}@{ref}: git archive failed: {archive.stderr.decode(errors='replace').strip()[:200]}")
    subprocess.run(["tar", "-x", "-C", dest], input=archive.stdout, check=True)
    return os.path.join(dest, prefix.rstrip("/")) if prefix else dest, sha


def _label(path: str, repo: str) -> str:
    return os.path.relpath(path, os.path.dirname(repo))


def _ptr(root: Root, rec: Dict[str, Any]) -> str:
    return f"{root.label}/{rec['file']}:{rec['line']}"


# ── versions, through the policy (never a second comparator) ─────────────────────────

def _eco(raw: str) -> str:
    return (raw or "").strip().lower()


def _pkg(eco: str, name: str) -> str:
    return normalize(name) if eco == "pypi" else name


def same_version(eco: str, a: str, b: str) -> bool:
    return policy.admits(eco, f"=={a}" if eco == "pypi" else a, b) is True


def at_least(eco: str, low: str, v: str) -> bool:
    return policy.admits(eco, f">={low}", v) is True


def highest(eco: str, versions: List[str]) -> Optional[str]:
    best: Optional[str] = None
    for v in versions:
        if best is None or (at_least(eco, best, v) and not same_version(eco, best, v)):
            best = v
    return best


#: How many comment lines above a declaration are read as its stated reason. A cap, because a manifest's
#: file header is not a reason for line 23 and dragging it in would make the brief noise.
_REASON_MAX_LINES = 8


def _stated_reason(root: Root, decl: Dict[str, Any]) -> Optional[List[str]]:
    """The comment block immediately above a declaration, as its author wrote it.

    ⭐ WHY THIS IS WORTH READING. An upper bound is refused because it records a human judgement
    (`propose_spec`), and the first thing a person then needs is WHAT that judgement was. It is
    almost always sitting directly above the line — `starlette<1.0` carries two lines explaining it
    — and going to find it by hand was the first twenty minutes of the 2026-10-24 starlette run.

    ⛔ READ FROM THE ROOT'S OWN BYTES, never the working tree. `Root.path` is the extracted tree when
    the scope entry carries a `ref`, so this quotes the comment at the COMMIT the plan was built
    from. Quoting a working-tree comment beside a committed declaration would be the F38 mistake in
    reverse: two sources, presented as one.

    ⚠️ It does NOT interpret the comment, and deliberately does not hunt for symbol names in it. The
    `starlette<1.0` comment says only "deprecated APIs removed" — the symbol that actually mattered
    (`app.add_event_handler`) is in a different file sixty lines away, and was stale besides. A
    regex over English prose would have found nothing here and something confident-looking
    elsewhere. Whether the reason still HOLDS is the API diff's question, not this one's.
    """
    line = decl.get("line")
    if not isinstance(line, int) or line < 2:
        return None
    try:
        with open(os.path.join(root.path, decl["file"]), encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None                      # unreadable is not an error here: the brief is best-effort
    out: List[str] = []
    i = line - 2                         # 0-based index of the line above the declaration
    while i >= 0 and len(out) < _REASON_MAX_LINES:
        text = lines[i].strip()
        if not text.startswith("#"):
            break
        out.append(text.lstrip("#").strip())
        i -= 1
    return list(reversed(out)) or None


# ── one package, one verdict ─────────────────────────────────────────────────────────

def _aggregate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Findings per (ecosystem, package, installed): one remediation action closes them all, so the target is the
    highest fix any of them needs (a lock recompile must reach it), and a flaw with no fix is carried, not hidden."""
    by: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for f in findings:
        eco = _eco(f.get("ecosystem"))
        key = (eco, _pkg(eco, f.get("package") or ""), str(f.get("installed") or ""))
        a = by.setdefault(key, {"ecosystem": eco, "package": key[1], "installed": key[2] or None,
                                "fixes": [], "no_fix": 0, "alert_ids": [], "_flaws": []})
        if f.get("fixed"):
            a["fixes"].append(str(f["fixed"]))
        else:
            a["no_fix"] += 1
        if f.get("alert_id"):
            a["alert_ids"].append(f["alert_id"])
        a["_flaws"].append((f.get("alert_id"), str(f["fixed"]) if f.get("fixed") else None))
    for a in by.values():
        a["flaws"] = len(a["fixes"]) + a["no_fix"]
        a["target"] = highest(a["ecosystem"], a["fixes"]) if a["fixes"] else None
        a["candidates"] = candidates(a["ecosystem"], a.pop("_flaws"))
        a.pop("fixes")
    return [by[k] for k in sorted(by)]


def candidates(eco: str, flaws: List[Tuple[Optional[str], Optional[str]]]) -> List[Dict[str, Any]]:
    """Every distinct fix version, highest first, with the flaws it clears (a flaw is cleared by any version at or
    above its fix) and the ones it leaves open. Apply tries them in this order (lead's rule, 2026-10-19): the highest
    fix first; if the resolver refuses it, the highest that resolves, which is also the one clearing the most."""
    versions: List[str] = []
    for _, fx in flaws:
        if fx and not any(same_version(eco, fx, v) for v in versions):
            versions.append(fx)
    out = []
    while versions:
        v = highest(eco, versions)
        versions = [x for x in versions if x != v]
        clears = [aid for aid, fx in flaws if fx and at_least(eco, fx, v)]
        out.append({"version": v, "clears": len(clears), "open": len(flaws) - len(clears),
                    "clears_alert_ids": [x for x in clears if x],
                    "open_alert_ids": [aid for aid, fx in flaws if aid and not (fx and at_least(eco, fx, v))]})
    return out


def _resolutions(root: Root, eco: str, pkg: str) -> List[Dict[str, Any]]:
    return [r for r in root.records if r["kind"] == "resolution" and r["ecosystem"] == eco
            and (r["package"] == pkg or r.get("resolved_name") == pkg) and r.get("version")]


def _declined(a: Dict[str, Any], why: str, evidence: List[str], code: str) -> Dict[str, Any]:
    return {**a, "verdict": DECLINED, "decline": code, "why": why, "evidence": evidence}


def classify(a: Dict[str, Any], roots: List[Root], imports_of) -> Dict[str, Any]:
    """The verdict for one aggregated package (see the module docstring for the vocabulary)."""
    eco, pkg, installed, target = a["ecosystem"], a["package"], a["installed"], a["target"]
    if eco not in manifests.DECLARATION_ECOSYSTEMS:
        return {**a, "verdict": NOT_DECLARED_HERE, "why": f"no manifest reader for ecosystem '{eco}': the "
                f"component is outside the application's dependency set (class 1 if it is an OS package)",
                "evidence": []}
    decls = [(r, d) for r in roots for d in manifests.declared(r.records, eco, pkg)]
    # ⭐ A DECLARATION THAT REJECTS THE SCANNED VERSION DID NOT CONSTRAIN THE RESOLVE THAT PRODUCED IT (a resolve
    # satisfies every constraint it was given). So it is another project's manifest or a stale one, and it can
    # neither block the fix nor be its lever. Measured on agent-builder: `scripts/standalone/requirements.txt`
    # pins google-adk==2.7.0 and litellm==1.97.0, the unused top-level requirements.txt caps litellm <1.75.0.
    ignored = [(r, d) for r, d in decls
               if installed and policy.admits(eco, d["version_spec"], installed, d.get("syntax")) is False]
    decls = [x for x in decls if x not in ignored]
    a = {**a, **({"ignored_declarations": [f"{_ptr(r, d)} `{d['version_spec']}` does not admit the scanned "
                                           f"{installed}: not part of this resolve" for r, d in ignored]}
                 if ignored else {})}
    # ⛔ ...EXCEPT OUR OWN BUILD MANIFEST. When `--repo`'s top-level pyproject.toml / package.json rejects the
    # scanned version, the declared set and the resolve disagree (agent-builder: `google-adk>=1.39.1` against the
    # base lock's 1.37.0, a resolver conflict). No lock edit can be planned on a resolve its own manifest refuses.
    conflict = [(r, d) for r, d in ignored if r.primary and "/" not in d["file"]
                and d["manifest_kind"] in ("pyproject", "package.json")]
    # ⛔ A NESTED npm COPY IS NOT A CONFLICT. Our declaration governs the TOP-LEVEL copy; a nested one is
    # constrained by its own parent's requirement, so `semver ^7` beside `a/node_modules/semver 5.7.1` is npm
    # working exactly as designed. Without this guard the scanned nested version looks like a manifest that
    # contradicts its own lock, and a fixable transitive is reported as class 5 blocked (measured 2026-10-20:
    # 6 of nodejs-goof's rows). The real conflict this rule exists for — agent-builder's `google-adk>=1.39.1`
    # against the base lock's 1.37.0 — has no copy at the scanned version at all, nested or otherwise.
    nested_at_scanned = [x for r in roots for x in _resolutions(r, eco, pkg)
                         if installed and same_version(eco, installed, x["version"]) and x.get("nested_under")]
    if conflict and not nested_at_scanned:
        r, d = conflict[0]
        return _declined(a, f"{_ptr(r, d)} `{d['version_spec']}` rejects the scanned {installed}: our declared set "
                         f"and the resolve disagree (a resolver conflict, class 5)",
                         a["ignored_declarations"], "declaration_conflict")
    res = [(r, x) for r in roots for x in _resolutions(r, eco, pkg)]
    incomplete = [r.label for r in roots if r.has_manifests(eco) and not manifests.declarations_complete(r.records, eco)]
    ev_decl = [f"{_ptr(r, d)} declares `{d['version_spec'] or '(any)'}` ({d['group']})" for r, d in decls]
    ev_res = [f"{_ptr(r, x)} resolves {x['version']}" for r, x in res]

    if not decls and not res:
        if incomplete:
            return _declined(a, f"a manifest in {', '.join(incomplete)} is unreadable: absence is not proven", [],
                             "declarations_incomplete")
        return {**a, "verdict": NOT_DECLARED_HERE, "why": "no manifest or lock in scope declares or resolves it",
                "evidence": []}
    at = [(r, x) for r, x in res if installed and same_version(eco, installed, x["version"])]
    if not at:
        why = (f"no lock in scope resolves {pkg} at the scanned {installed}" if res
               else f"{pkg} is declared but no lock in scope resolves it")
        return _declined(a, why + ": this scope did not build the scanned artifact", ev_decl + ev_res, "lock_drift")
    resolve = at[0]
    out = {**a, "resolve": {"repo": resolve[0].label, "file": resolve[1]["file"],
                            "lock_format": resolve[1]["lock_format"],
                            **({"compiled_from": resolve[1]["compiled_from"]} if resolve[1].get("compiled_from") else {})},
           "locks": [{"repo": r.label, "file": x["file"], "line": x["line"], "lock_format": x["lock_format"],
                      **({"compiled_from": x["compiled_from"]} if x.get("compiled_from") else {})} for r, x in at],
           "dev_only": eco == "npm" and all(x.get("dev") for _, x in at),
           "declared_here": any(r.primary for r, _ in decls),
           # ⛔ WHICH COPY, for apply's `overrides` entry. Unscoped, an override rewrites EVERY copy of the
           # package and downgrades the top-level one; the chain is what scopes it. Absent when every copy at
           # the scanned version is top-level, so a pypi row and an ordinary npm row are unchanged.
           # EVERY copy at the scanned version, top-level ones included (`nested_under: []`). This is what
           # gate 1 must judge: the copies this finding is ABOUT. Other copies of the same name are at other
           # versions, which are other findings with their own targets — demanding they all reach THIS target
           # refuses a correct fix (measured on nodejs-goof: async is installed at 0.9.0, 1.5.2, 1.5.2 and the
           # scanned 2.6.3, and only the last is this row).
           "scanned_copies": [{"nested_under": list(x.get("nested_under") or []), "version": x["version"]}
                              for _, x in at],
           **({"nested_copies": [{"nested_under": list(x["nested_under"]), "version": x["version"]}
                                 for _, x in at if x.get("nested_under")]}
              if any(x.get("nested_under") for _, x in at) else {})}
    evidence = [f"{_ptr(r, x)} resolves the scanned {x['version']}" for r, x in at] + ev_decl

    if target is None:
        return _no_fix(out, decls, roots, imports_of, evidence)

    verdicts = [(r, d, policy.admits(eco, d["version_spec"], target, d.get("syntax"))) for r, d in decls]
    blocking = [(r, d) for r, d, v in verdicts if v is False]
    undecidable = [(r, d) for r, d, v in verdicts if v is None]
    if blocking:
        edits = []
        for r, d in blocking:
            new, why = propose_spec(eco, d["version_spec"], d.get("syntax") or "", target)
            edits.append({"repo": r.label, "file": d["file"], "line": d["line"], "action": "bump",
                          "from": d["version_spec"], "to": new, "syntax": d.get("syntax") or "",
                          **({"needs_human": why} if why else {})})
        evidence = evidence + [f"{_ptr(r, d)} `{d['version_spec']}` does not admit {target}" for r, d in blocking]
        # ⛔ AN EDIT NOBODY CAN COMPLETE TAKES THE WHOLE PACKAGE OUT OF THE PLAN. The lock is the unit on both sides
        # (one proposal per lock in `build_proposals`, one open plan per `lock_key` in DF), and DF refuses to approve
        # a plan holding a `needs_human` edit. So kept as class 3, this package made every other fix on its lock
        # unapprovable. Measured on one service 2026-10-20: starlette's `<1.0` held back litellm,
        # snowflake-connector-python and the class-2 group on base-image/requirements.lock. The whole package, not
        # the one edit: an unedited declaration still blocks the resolve. Widening the bound is a source edit and a
        # re-plan, so the edit stays on the row for the person who makes it.
        stuck = [e for e in edits if e.get("needs_human") or e.get("to") is None]
        if stuck:
            # ⭐ THE BRIEF. The decline is correct and must stay a decline, but "a person must change
            # that declaration" is where it used to stop — and everything a person needs next, except
            # one thing, is already in hand. So say it. Measured 2026-10-24/25 on starlette: finding
            # the stated reason, then what we touch, took most of a day by hand, twice, and the second
            # attempt was still incomplete.
            # ⛔ IT RECOMMENDS NOTHING AND CHANGES NO VERDICT. `to` stays null; the edit stays
            # `needs_human`. A brief that read as approval would be worse than silence.
            primary = next((r for r in roots if r.primary), None)
            brief: Dict[str, Any] = {"target": target, "blocking": [
                {"repo": e["repo"], "file": e["file"], "line": e["line"], "spec": e["from"],
                 "why": e.get("needs_human")} for e in stuck]}
            for r, d in blocking:
                said = _stated_reason(r, d)
                if said:
                    brief.setdefault("stated_reason", []).append(
                        {"repo": r.label, "file": d["file"], "line": d["line"], "lines": said})
            if primary is not None:
                v = imports_of(primary, out["ecosystem"], out["package"])
                # ⚠️ `imports_directly`, NOT "we use it". An import scan does not follow inheritance
                # or a wrapper's re-export, so `not_imported` here is "the question went unanswered",
                # never "safe" — the same rule `api_diff_intersection` states for its own verdicts. The
                # library's own `reason_text` is carried verbatim rather than summarised, because it
                # is the sentence that says which of the two it means.
                # ⚠️ `certainty` travels with the verdict and is usually `believed`, not `certain`.
                # Dropping it would promote a static read to a fact. `reason_text` is omitted when the
                # library has nothing to add (a clean `reachable`) rather than carried as a null.
                brief["imports_directly"] = {
                    "repo": primary.label, "verdict": v.get("verdict"), "certainty": v.get("certainty"),
                    **({"reason_text": v["reason_text"]} if v.get("reason_text") else {})}
            # ⛔ NEVER OMIT THIS. Every line above is about declarations and source text; not one of
            # them says the software RUNS. The resolve is unattempted (this script runs no resolver,
            # by contract) and nothing has been built or started.
            brief["not_established"] = [
                "whether lifting the bound resolves at all, and to which version",
                "what else the resolve would move",
                "whether the removed APIs of the new version are reached indirectly",
                "whether the fleet builds and starts against it",
            ]
            return _declined({**out, "edits": edits, "brief": brief},
                             "; ".join(f"{e['repo']}/{e['file']}:{e['line']} {e.get('needs_human') or 'no rewrite'}"
                                       for e in stuck) + ": a person must change that declaration before "
                             f"{pkg} can be planned (the lock's other fixes go ahead without it)",
                             evidence, "edit_needs_human")
        return {**out, "verdict": CLASS_DECLARATION, "edits": edits, "evidence": evidence}
    if undecidable:
        return _declined({**out}, f"the policy cannot decide whether `{undecidable[0][1]['version_spec']}` admits "
                         f"{target}", evidence, "undecidable_spec")
    if not decls and incomplete:
        return _declined(out, f"not declared in scope, but a manifest in {', '.join(incomplete)} is unreadable",
                         evidence, "declarations_incomplete")
    return {**out, "verdict": CLASS_LOCK, "edits": [],
            "evidence": evidence + ([f"every declaration in scope admits {target}"] if decls
                                    else ["declared nowhere in scope: transitive; the resolver proves its parents "
                                          "admit the fix (gate 1)"])}


def _no_fix(out: Dict[str, Any], decls, roots: List[Root], imports_of, evidence: List[str]) -> Dict[str, Any]:
    """No published fix. The one lever left is removal, and only on the import scan's own `not_imported` over a
    declaration in `--repo` (FD § "Class 3": `inconclusive` is not enough)."""
    here = [(r, d) for r, d in decls if r.primary]
    if not here or not REMOVALS_ENABLED:
        return _declined(out, "no fix published (class 5)", evidence, "no_fix")
    primary = next(r for r in roots if r.primary)
    v = imports_of(primary, out["ecosystem"], out["package"])
    if v.get("verdict") != "not_imported":
        return _declined(out, f"no fix published (class 5); removal is not offered: the import scan says "
                         f"`{v.get('verdict') or v.get('state')}`", evidence, "no_fix")
    edits = [{"repo": r.label, "file": d["file"], "line": d["line"], "action": "remove", "from": d["version_spec"]}
             for r, d in decls]
    elsewhere = sorted({r.label for r, _ in decls if not r.primary})
    return {**out, "verdict": CLASS_DECLARATION, "removal": True, "edits": edits,
            **({"blocked_on": f"also declared in {', '.join(elsewhere)}: removing it here alone leaves it "
                              f"installed, and removing it there needs every consumer of that tree to not import it"}
               if elsewhere else {}),
            "evidence": evidence + [f"import scan of {primary.label} at {primary.commit or 'an unversioned copy'}: "
                                    f"not_imported"]}


def falls_out(rows: List[Dict[str, Any]], roots: List[Root]) -> None:
    """A no-fix transitive whose every requirer is being removed leaves the closure with them: say so."""
    removed = {(r["ecosystem"], r["package"]) for r in rows if r.get("removal")}
    if not removed:
        return
    by_label = {r.label: r for r in roots}
    for row in rows:
        if row.get("decline") != "no_fix" or not row.get("resolve"):
            continue
        root = by_label[row["resolve"]["repo"]]
        parents = {q["package"] for q in root.requirements()
                   if q["file"] == row["resolve"]["file"] and row["package"] in q["requires"]}
        if parents and all((row["ecosystem"], p) in removed for p in parents):
            row["falls_out_with"] = sorted(parents)


# ── class 4: the upgrade changes an API this code calls (FIX_PR_SPEC.md § 3.4.6) ─────

API_DIFF_OFF, API_DIFF_READ, API_DIFF_REQUEST = "off", "read", "request"


def _origin_record(roots: List[Root], row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The `resolution` record behind this row's resolve lock — the lock's own account of WHERE the
    package came from (§ 3.4.6 step 1).

    ⚠️ Matched on the resolve lock's own FILE, not merely on the package: one tree can declare the same
    package in several locks (a service lock and a shared base lock), and they can record different
    origins. The record that matters is the one in the lock this fix would edit.

    ⚠️ Versions compared with `same_version`, package under rule N, exactly as `api_diff_for` does — a record
    written `1.4` and a row saying `1.4.0` are the same resolution.
    """
    resolve = row.get("resolve")
    if not resolve:
        return None
    root = next((r for r in roots if r.label == resolve.get("repo")), None)
    if root is None:
        return None
    eco, pkg, installed = row["ecosystem"], row["package"], row.get("installed")
    for rec in root.records:
        if rec.get("kind") != "resolution" or rec.get("ecosystem") != eco:
            continue
        if rec.get("file") != resolve.get("file") or not rec.get("version"):
            continue
        name = rec.get("package") or rec.get("resolved_name") or ""
        if normalize(str(name)) != normalize(str(pkg)):
            continue
        if installed and not same_version(eco, str(rec["version"]), str(installed)):
            continue
        return rec
    return None


def api_diff_question(row: Dict[str, Any], roots: List[Root]) -> Optional[Dict[str, Any]]:
    """Does this row ask the API question, and can an API diff answer it? Pure: reads the row, writes nothing.

    None when the row asks nothing. Otherwise a decision:
      `api_question`  True on a class-2 row that crosses a major (FIX_KNOWLEDGE_CONVERGENCE § 3.6.7 (b)); absent on
                      class 3, which always asks it
      `api_diff`      the block to record when NO API diff can be fetched (`declined` for a non-public origin,
                      `not_requested`/`version_undecidable` for an unparseable move)
      `origin`        the lock's origin record, kept on the row even when not public
      `pair`          the API diff key to read, `{ecosystem, package, from, to, origin_source, origin_url}`, only when
                      an API diff may be fetched

    ⛔ P2 IS ENFORCED HERE, BEFORE ANY CALL, not by the server alone. `locks.is_public` is false for a private
    index AND for a record with no `origin` at all (a lock read by a library older than 1.10.0), so a private
    package's NAME and its internal index URL are never sent anywhere, and never listed in `api_diffs_wanted`.

    ⛔ WHICH ROWS ASK (D6, Bhakta 2026-10-27): a class-3 BUMP, and a class-2 (lock-only) move that crosses a major
    version or a 0.x minor (`policy.crosses_major`), where an API break hides with no declaration to warn anyone.
    Both spend the same per-tenant cold-pair quota. Never the removal variant (`removal: True`): nothing is upgraded,
    so no API diff describes it. A class-2 move whose versions cannot be compared is NOT fetched (the quota is not spent
    on a guess) but still carries `api_question`, so the plan shows and asks it. ⚠️ `api_diff_pass` is deliberately
    broader: once an API diff is IN HAND it intersects any row it matches, since an API diff can only ever RAISE the class.
    """
    if row.get("removal"):
        return None
    out: Dict[str, Any] = {}
    if row.get("verdict") == CLASS_LOCK:
        cross = policy.crosses_major(row["ecosystem"], str(row.get("installed") or ""),
                                     str(row.get("target") or ""))
        if cross is False:
            return None
        # ⭐ Set BEFORE the origin gate: a declined or undecidable row asks the question too.
        out["api_question"] = True
        if cross is None:
            out["api_diff"] = {"state": "not_requested", "reason": "version_undecidable"}
            return out
    elif row.get("verdict") != CLASS_DECLARATION:
        return None
    if not row.get("installed") or not row.get("target"):
        return out or None
    rec = _origin_record(roots, row)
    origin = (rec or {}).get("origin")
    if origin:
        # ⭐ Recorded even when NOT public: a reader deciding this plan needs to see WHY no diff was fetched, and
        # "we never looked" is the one answer that must never be inferred from an absent block.
        out["origin"] = {k: origin.get(k) for k in ("verdict", "source", "url")}
    if not locks.is_public(origin):
        verdict = (origin or {}).get("verdict") if origin else None
        out["api_diff"] = {"state": "declined", "reason": "origin_" + str(verdict or "unknown")}
        return out
    out["pair"] = {"ecosystem": row["ecosystem"], "package": row["package"],
                   "from": str(row["installed"]), "to": str(row["target"]),
                   "origin_source": str(origin.get("source") or ""), "origin_url": str(origin.get("url") or "")}
    return out


def eligible_pairs(rows: List[Dict[str, Any]], roots: List[Root]) -> List[Dict[str, Any]]:
    """Every API diff this plan would read, deduplicated: the planner's `api_diffs_wanted[]` (§ 3.6.7 (f)).

    ⛔ THE SAME FILTER AS `fetch_api_diffs`, by construction (both go through `api_diff_question`), so a pair is listed
    exactly when a laptop run would request it. In the GitHub Action the planner holds no credential: it prints
    this list, `remediate.py` reads each API diff with its own token, and a second run takes them with `--api-diff-file`.
    """
    seen, out = set(), []
    for row in rows:
        pair = (api_diff_question(row, roots) or {}).get("pair")
        if not pair:
            continue
        key = (pair["ecosystem"], normalize(pair["package"]), pair["from"], pair["to"])
        if key not in seen:
            seen.add(key)
            out.append(pair)
    return out


def _mark(row: Dict[str, Any], q: Dict[str, Any], full: bool) -> None:
    """Write a `api_diff_question` decision onto the row. `full=False` (diffs off) records only `api_question`: nobody
    asked, so no `api_diff` is claimed."""
    if q.get("api_question"):
        row["api_question"] = True
    if not full:
        return
    if q.get("origin"):
        row["origin"] = q["origin"]
    if q.get("api_diff"):
        row["api_diff"] = dict(q["api_diff"])


def _apply_view(row: Dict[str, Any], view: Dict[str, Any], diffs: List[Dict[str, Any]]) -> None:
    """One API diff view (`api-diff get --json`: `{state, document?, failure_reason?}`, or a CI record
    `{state: "unavailable", reason}`) onto its row. A ready API diff joins `diffs`; `api_diff_pass` intersects it."""
    state = str(view.get("state") or "")
    # `card`: the view key before the "upgrade card" -> "API diff" rename (2026-10-27), from an older CLI or a
    # views file collected before it. Remove this fallback one release after the rename ships.
    doc = view.get("document") if isinstance(view.get("document"), dict) else view.get("card")
    if state == "ready" and isinstance(doc, dict):
        diffs.append(doc)
    elif state == "pending":
        row["api_diff"] = {"state": "pending"}
    elif state in ("failed", "unavailable"):
        why = view.get("failure_reason") or view.get("reason") or state
        row["api_diff"] = {"state": "unavailable", "reason": str(why)[:200]}
    else:
        # `absent` — only reachable without `--request`, which is exactly "we did not ask for it".
        row["api_diff"] = {"state": "not_requested"}


def fetch_api_diffs(rows: List[Dict[str, Any]], roots: List[Root], mode: str) -> List[Dict[str, Any]]:
    """Steps 1-2 of § 3.4.6: the question and the PUBLIC-ORIGIN gate (`api_diff_question`), then one API diff read per
    eligible row.

    Returns the API diffs that came back `ready`; `api_diff_pass` does the intersection. A row that never reaches an
    intersection gets its `api_diff` set HERE, so the plan records that the question was asked and what the answer
    was — the difference between "this upgrade is safe" and "nobody looked" is the whole point of the block.
    With `off`, only `api_question` is recorded (a fact about the move, not about a fetch).
    """
    diffs: List[Dict[str, Any]] = []
    for row in rows:
        q = api_diff_question(row, roots)
        if q is None:
            continue
        _mark(row, q, full=mode != API_DIFF_OFF)
        if mode == API_DIFF_OFF or not q.get("pair"):
            continue
        p = q["pair"]
        argv = ["remediation-plans", "api-diff", "get",
                "--ecosystem", p["ecosystem"], "--package", p["package"], "--from", p["from"], "--to", p["to"],
                "--origin-source", p["origin_source"], "--origin-url", p["origin_url"]]
        if mode == API_DIFF_REQUEST:
            argv.append("--request")
        try:
            view = _cli_json(argv, dict)
        except RuntimeError as exc:
            # ⚠️ A REFUSAL IS NOT A CRASH. 403 `pair_not_in_queue`, 429, 502 and 503 all arrive here, and
            # each is a true statement about why no diff is available — recorded, so the plan can still
            # be decided by a human who can see that the question was asked.
            row["api_diff"] = {"state": "unavailable", "reason": str(exc)[:200]}
            continue
        _apply_view(row, view, diffs)
    return diffs


def apply_api_diff_file(rows: List[Dict[str, Any]], roots: List[Root], diffs: List[Dict[str, Any]],
                    views: List[Dict[str, Any]]) -> None:
    """A `--api-diff-file` run: the same questions as `fetch_api_diffs`, answered from the file instead of the CLI.

    A pair with a ready API diff (bare, or a ready view) is left to `api_diff_pass`. A non-ready view sets the row's
    `api_diff` exactly as a live read would (`pending`; `failed`/`unavailable` → `unavailable` with the reason). A pair
    the file does not mention is `not_requested`. So a CI plan records "asked, pending", never "nobody asked".
    """
    for row in rows:
        q = api_diff_question(row, roots)
        if q is None:
            continue
        _mark(row, q, full=True)
        p = q.get("pair")
        if not p or api_diff_for(diffs, p["ecosystem"], p["package"], p["from"], p["to"]):
            continue
        view = next((v for v in views if api_diff_for([v], p["ecosystem"], p["package"], p["from"], p["to"])), None)
        _apply_view(row, view or {"state": "absent"}, diffs)


def read_api_diffs(path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """The API diffs for this run, as `(ready diffs, non-ready views)`.

    The file is a JSON array, `{"api_diffs": [...]}`, or one object. Each element is a bare `torana.api_diff.v1`
    (read as ready) OR an API diff VIEW `{key: {ecosystem, package, from, to}, state, document?, failure_reason?|reason?}` —
    what `api-diff get --json` prints plus the pair key, as the GitHub Action collects them (§ 3.6.7 (f)). A ready
    view contributes its API diff.

    ⭐ An API diff is built SERVER-SIDE per `(ecosystem, package, from, to, extractor_version)`, because building one
    means downloading two artifacts and reading them with griffe. This flag is how a CI run, a laptop run and a test
    hand the planner the same API diffs with no credential (§ 3.4.6 specifies it for exactly that)."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    # `cards`: the wrapper key before the rename (2026-10-27); remove one release after it ships.
    wrap = next((k for k in ("api_diffs", "cards") if isinstance(doc, dict) and k in doc), None)
    items = doc[wrap] if wrap else doc
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list) or not all(isinstance(c, dict) for c in items):
        raise ValueError('expected a JSON array of API diffs or API diff views, {"api_diffs": [...]}, or one object')
    diffs: List[Dict[str, Any]] = []
    views: List[Dict[str, Any]] = []
    for item in items:
        if "state" not in item:
            diffs.append(item)
        elif item.get("state") == "ready" and isinstance(item.get("document") or item.get("card"), dict):
            diffs.append(item.get("document") or item["card"])     # `card`: before the rename, as above
        elif isinstance(item.get("key"), dict):
            views.append(item)
        else:
            raise ValueError("an API diff view needs its pair `key` {ecosystem, package, from, to}")
    return diffs, views


def api_diff_for(diffs: List[Dict[str, Any]], eco: str, pkg: str, installed: Optional[str],
             target: Optional[str]) -> Optional[Dict[str, Any]]:
    """The API diff for exactly this move, or None.

    ⛔ BOTH ENDS MUST MATCH. An API diff is the API diff between two specific versions; one built for any other pair
    describes a different upgrade, and reading it here would answer a question nobody asked."""
    if not installed or not target:
        return None
    for c in diffs:
        k = c.get("key") or {}
        if (str(k.get("ecosystem") or "").strip().lower() != eco
                or normalize(str(k.get("package") or "")) != normalize(pkg)
                or not k.get("from") or not k.get("to")):
            continue
        if same_version(eco, str(k["from"]), installed) and same_version(eco, str(k["to"]), target):
            return c
    return None


def api_diff_pass(rows: List[Dict[str, Any]], roots: List[Root], diffs: List[Dict[str, Any]]) -> None:
    """Class 4 in place: for every fixable row that has an API diff, intersect the API diff's changed symbols with the
    primary tree's own call sites (`api_diff_intersection.intersect`).

    ⛔ A CARD CAN ONLY RAISE THE CLASS, NEVER LOWER IT. `intersect` answers one question — "class 4?" — and
    returns "3" for every other outcome, including a class-2 row whose code touches nothing changed. Taking that
    "3" literally would turn every carded lock-only fix into a manifest edit. So only a verdict of 4 moves the
    row; otherwise the `api_diff` block is attached as the record that the question was asked and answered no.

    ⚠️ The primary tree only. A `--with` tree's code is searched by its own run (`usage_for`'s rule), and the
    repository whose code would have to change is the one the findings are about.

    ⭐ ALSO `edit_needs_human`, AND ONLY THAT DECLINE. MEASURED 2026-10-20: starlette 0.52.1 → 1.9.0 against
    a shared library + a base image never reached this pass at all — `requirements.in:23` declares
    `starlette<1.0`, an upper bound is not rewritten mechanically, so the row was declined `edit_needs_human`
    first and the API diff was never read. The decline sends a person to widen a bound; the API diff tells them the
    upgrade is a code change, which is a different decision. Class 4 is the stronger and more specific terminal
    verdict, so it wins, and the declaration edit stays in `blocked_edits` because that bound still has to be
    widened before any version of this fix can land. The property the decline exists for is kept: a class-4 row
    is its own group with no command and no edit, so the lock's other fixes still go ahead without it.
    ⛔ NO OTHER DECLINE. `lock_drift` means this scope did not build the scanned artifact, so an API diff keyed on
    that version is not describing this tree; `declaration_conflict` and `undecidable_spec` are class 5 and the
    API diff cannot speak to either; `no_fix` has no target, so no API diff can match it."""
    if not diffs:
        return
    try:
        import api_diff_intersection as ci                   # ⭐ ships beside this script, in the same scan pack
    except ImportError as exc:                           # never guessed at: class 4 is simply not decided
        log(f"note: class-4 detection is off: {exc}")
        return
    primary = next(r for r in roots if r.primary)
    cache: Dict[str, Any] = {}

    def usage():
        if "usage" not in cache:
            cache["usage"] = ci.usage_for(primary.path, repository=primary.label,
                                          commit=primary.commit or "unknown")
            cache["read"] = ci.reader(primary.path)
        return cache["usage"], cache["read"]

    for row in rows:
        fixable = row["verdict"] in (CLASS_LOCK, CLASS_DECLARATION)
        if not fixable and not (row["verdict"] == DECLINED and row.get("decline") == "edit_needs_human"):
            continue
        doc = api_diff_for(diffs, row["ecosystem"], row["package"], row.get("installed"), row.get("target"))
        if doc is None:
            continue
        recs, read = usage()
        # ⭐ WHICH PACKAGES COULD RE-PROVIDE A REMOVED NAME. Computed from EVERY root's lock, not just the
        # primary's: the lock that governs what a service installs is often a shared one in another
        # repository, and any lock recording the edge states the same fact about the declarer. The caller
        # computes it because `ci.intersect` is pure over its inputs and must not read a lock itself.
        # `recs` is `usage_for`'s (usage records, call graph) pair; the edge search reads the records.
        through = ci.reached_through(row["package"],
                                    [q for r in roots for q in r.requirements()], recs[0])
        res = ci.intersect(doc, recs, read, package=row["package"], ecosystem=row["ecosystem"],
                           through=through)
        row["api_diff"] = res
        if res["verdict"] != CLASS_CODE:
            continue
        named = [h for h in res["touched"] if h.get("by") in ci.NAMED_BY] or res["touched"]
        # ⛔ THE EDIT IS KEPT, NOT MADE. `group()` and apply collect `edits`; a class-4 row must contribute none,
        # or the lock it was classified away from would be recompiled anyway. It stays on the row under another
        # name because it is the useful part of the report: what a person would have to change.
        row["blocked_edits"] = row.get("edits") or []
        row["edits"] = []
        row["verdict"] = CLASS_CODE
        superseded = "" if fixable else f"; {row['why']}"
        if not fixable:
            row["superseded_decline"] = row.pop("decline")
        row["why"] = (f"{row['package']} {row['installed']} → {row['target']} changes "
                      f"{len(res['touched'])} symbol(s) this repository calls ("
                      + ", ".join(f"`{h['symbol']}`" for h in named[:3])
                      + (", …" if len(named) > 3 else "")
                      + "): the upgrade needs a code change, so no lock or manifest is edited" + superseded)
        row["evidence"] = (row.get("evidence") or []) + [
            f"{primary.label}/{h['file']}:{h['line']} uses `{h['symbol']}` ({h['change']} in {row['target']})"
            + ("" if h.get("by") in ci.NAMED_BY else " [the name appears in the file, not in the import]")
            for h in res["touched"]]


# ── W1: everything that must move together (FIX_KNOWLEDGE_CONVERGENCE § 3.4.6, § 3.4.7) ─────────────────

MOVE_OFF, MOVE_CLI = "off", "cli"
#: Alerts whose stored set a laptop run reads through the CLI, per package row (one CLI call each).
MAX_SET_READS = 10
WHY_UNSUPPORTED = "Atlas traces pypi packages only"


def read_move_together(alert_id: str) -> Dict[str, Any]:
    """One alert's stored set, `torana alert <id> fix-scope --json` (DF `GET /alerts/{id}/fix-scope`)."""
    return _cli_json(["alert", alert_id, "fix-scope", "--json"], dict)


def read_subject_alerts(subject: str) -> List[str]:
    """Every alert the platform binds to `subject`, ONE call per run: `torana alerts reachability-queue --repository
    KEY --include-measured --as-findings`, which pages to the end itself. ⭐ The only source for an image-scan
    finding (`image@sha256:…` place, `place` null): its record names no repository, the queue's binding does."""
    rows = _cli_json(["alerts", "reachability-queue", "--repository", subject, "--include-measured",
                      "--as-findings", "--limit", "100"], list)
    return [str(r["alert_id"]) for r in rows if isinstance(r, dict) and r.get("alert_id")]


def read_move_together_file(path: str) -> Dict[str, Dict[str, Any]]:
    """`--fix-scope-file`: a JSON array of the route's responses, as the GitHub Action collects them with its own
    token (the planner holds no credential there). Keyed by `alert_id`; an alert absent from the file has no answer."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, list) or not all(isinstance(x, dict) and x.get("alert_id") for x in doc):
        raise ValueError("expected a JSON array of `alert fix-scope` responses, each with its alert_id")
    return {str(x["alert_id"]): x for x in doc}


def _git_top(path: str) -> Optional[str]:
    try:
        p = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    except OSError:
        return None
    return (p.stdout or "").strip() if p.returncode == 0 else None


def _tree_keys(roots: List[Root], scope: Dict[str, Dict[str, Any]]) -> Dict[str, Tuple[Optional[str], str]]:
    """label → (repository key, the tree's path inside its repository). The same derivation as the proposal's
    `scope_keys` (origin remote; `git_repo_key` is the scan pack's twin of the CLI's `asset_key`)."""
    from reachability_pass import git_repo_key            # ⭐ the scan pack's one remote → key normaliser
    out: Dict[str, Tuple[Optional[str], str]] = {}
    for r in roots:
        path = (scope.get(r.label) or {}).get("path") or r.path
        top = _git_top(path) if os.path.isdir(path) else None
        prefix = os.path.relpath(os.path.realpath(path), os.path.realpath(top)) if top else "."
        out[r.label] = (git_repo_key(path) if os.path.isdir(path) else None, "" if prefix == "." else prefix)
    return out


def _subject_set(subject: "Optional[str] | Iterable[str]") -> set:
    """One subject key or several, lowercased. A row's subjects (F64): the plan's primary and every repository the
    row's own lock or edits land in."""
    if not subject:
        return set()
    return {subject.lower()} if isinstance(subject, str) else {str(x).lower() for x in subject if x}


def _subject_first(aids: List[str], subject: "Optional[str] | Iterable[str]", places: Dict[str, str],
                   mine: Optional[set]) -> List[str]:
    """`aids` reordered subject → unknown → other, each part in its original order. An alert is the subject's when
    its finding names a subject (`places`) or the queue binds it there (`mine`); another repository's when its
    finding names another one; unknown otherwise (an image-scan finding the queue did not list)."""
    subj = _subject_set(subject)
    own, unknown, other = [], [], []
    for a in aids:
        place = places.get(a)
        if place and not place.startswith("repo:"):
            place = None                        # an image place names no repository: unknown, as before
        if (mine is not None and a in mine) or (place and place in subj):
            own.append(a)
        elif place:
            other.append(a)
        else:
            unknown.append(a)
    return own + unknown + other


def _stored_set(row: Dict[str, Any], subject: "Optional[str] | Iterable[str]",
                source: "Optional[Dict[str, Dict[str, Any]]]",
                places: Optional[Dict[str, str]] = None,
                mine: Optional[set] = None, mine_why: str = "") -> Tuple[Optional[Dict[str, Any]], str]:
    """(the NEWEST current stored answer among the row's alerts for the subject repository, or None with why).

    Newest = the highest `fetched_at` (ISO-8601, so it compares as text); answers without one rank below any that
    has one, and ties keep the row's `alert_ids` order (so a route that sends no `fetched_at` gives the first current
    answer in list order). A refusal (403: an alert of another repository, refused by a CI token's binding), a 404,
    or an alert absent from `--fix-scope-file` skips that alert.

    ⚠️ Reading through the CLI costs one call per alert, so a laptop run reads at most `MAX_SET_READS` of them (a
    group can hold hundreds: litellm, 202). The file read by the GitHub Action is free and read whole.

    ⛔ THE SUBJECT'S ALERTS ARE READ FIRST, THEN THE CAP (F62). An entry's row lists every repository's members, and
    an answer is only usable for the subject's own alerts. Capped first, an aiohttp entry (77 alerts, the first 10
    one per OTHER repository) read 10 unusable answers and went to D2 with the subject's 7 never read. `places`
    (alert → the `repo:` its finding names) and `mine` (the alerts the queue binds to the subject, one call per run)
    give the order; `mine` None = the queue was not read, and `mine_why` says why.

    `subject` is one key or a set of them (F64): the answer must be bound to one of them."""
    subj = _subject_set(subject)
    named = ", ".join(sorted(subj)) or "the subject"
    aids = [a for a in row.get("alert_ids") or [] if a]
    if not aids:
        return None, "no alert to read the stored Atlas answer from"
    if source is None:
        aids = _subject_first(aids, subject, places or {}, mine)[:MAX_SET_READS]
    seen: List[str] = []
    best: Optional[Dict[str, Any]] = None
    for aid in aids:
        if source is not None:
            resp = source.get(aid)
        else:
            try:
                resp = read_move_together(aid)
            except RuntimeError:
                seen.append("unreadable")
                continue
        age = (resp or {}).get("fact_age") or "none"
        if age != "current":
            seen.append(age)
            continue
        if subj and resp.get("repository") and str(resp["repository"]).lower() not in subj:
            seen.append("other_repository")
            continue
        if best is None or str(resp.get("fetched_at") or "") > str(best.get("fetched_at") or ""):
            best = resp
    if best is not None:
        return best, ""
    tail = f" ({mine_why})" if source is None and mine_why else ""
    if "pre_w1" in seen:
        return None, "the stored Atlas answer predates the set (it is refreshed in the background)" + tail
    if "unreadable" in seen and set(seen) <= {"unreadable"}:
        return None, "the stored Atlas answer could not be read" + tail
    if seen and set(seen) == {"other_repository"}:
        return None, (f"only other repositories' stored Atlas answers were read ({len(seen)} alert(s)); none of "
                      f"them answers for {named}" + tail)
    return None, "no stored Atlas answer for this package's alerts" + tail


#: Alerts whose stored set a laptop run reads per package row when it combines every claimed repository's answer.
#: An alert whose repository is already answered is not read, so this is a bound on alerts of UNKNOWN repository.
MAX_UNION_READS = 30


def _stored_sets(row: Dict[str, Any], source: "Optional[Dict[str, Dict[str, Any]]]",
                 places: Optional[Dict[str, str]] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """(one stored answer PER REPOSITORY the row's alerts belong to, the gaps, why there is no answer at all).

    ⛔ A PLAN COVERS EVERY REPOSITORY WHOSE FINDINGS IT CLAIMS (F65). A stored answer is bound to ONE repository and
    lists what must move for THAT repository's shipped artifact: service A's names its own pin and its build patches;
    service B's names B's own pin. Picking the single newest answer (`_stored_set`) planned from A's answer while
    claiming B's findings, so B's own exact pin would have shipped the old version again; with B in scope it picked
    B's answer and A's build-patch review vanished. Every repository's newest current answer is used, and the caller
    combines them.

    Gaps (each becomes `move_scope.stale`, so the approver acknowledges unverified scope): a repository whose alerts
    have no current answer, and alerts left unread with their repository unknown. ⚠️ An alert whose repository is
    already answered (`places`) is not read again: one CLI call per repository, not per alert."""
    aids = [a for a in row.get("alert_ids") or [] if a]
    if not aids:
        return [], [], "no alert to read the stored Atlas answer from"
    places = places or {}
    best: Dict[str, Dict[str, Any]] = {}        # repository → newest current answer
    tried: Dict[str, str] = {}                  # repository → why its alerts gave no current answer
    answered: set = set()                       # places (repo: or image) one current answer already covers
    unread: List[str] = []
    reads = 0
    for aid in aids:
        place = places.get(aid)
        if place and (place in answered or place in best):
            continue                            # this place is answered: reading more of its alerts adds nothing
        if source is not None:
            resp = source.get(aid)
        elif reads >= MAX_UNION_READS:
            unread.append(aid)
            continue
        else:
            reads += 1
            try:
                resp = read_move_together(aid)
            except RuntimeError:
                tried.setdefault(place or "?", "unreadable")
                continue
        age = (resp or {}).get("fact_age") or "none"
        repo = str((resp or {}).get("repository") or place or "").lower()
        if age != "current" or not repo:
            tried.setdefault(place or repo or "?", age)
            continue
        if place:
            answered.add(place)
        cur = best.get(repo)
        if cur is None or str(resp.get("fetched_at") or "") > str(cur.get("fetched_at") or ""):
            best[repo] = resp
    gaps: List[Dict[str, Any]] = []
    for repo, age in sorted(tried.items()):
        if repo in best:
            continue
        what = {"pre_w1": "predates the set", "unreadable": "could not be read"}.get(age, "is missing")
        gaps.append({"repository": None if repo == "?" else repo, "file": None, "line": None,
                     "why": f"the stored Atlas answer for "
                            f"{'an alert of unknown repository' if repo == '?' else repo} {what}"})
    if unread:
        left = [a for a in unread if not (places.get(a) and (places[a] in answered or places[a] in best))]
        if left:
            gaps.append({"repository": None, "file": None, "line": None,
                         "why": f"{len(left)} alert(s) were not read (at most {MAX_UNION_READS} per package), "
                                "so their repositories were not checked"})
    if best:
        return [best[k] for k in sorted(best)], gaps, ""
    seen = set(tried.values())
    if "pre_w1" in seen:
        return [], gaps, "the stored Atlas answer predates the set (it is refreshed in the background)"
    if seen and seen <= {"unreadable"}:
        return [], gaps, "the stored Atlas answer could not be read"
    return [], gaps, "no stored Atlas answer for this package's alerts"


def _member_root(m: Dict[str, Any], keys: Dict[str, Tuple[Optional[str], str]]) -> Optional[Tuple[str, str]]:
    """(root label, the member's file relative to that root), or None when no tree in scope holds it."""
    repo = m.get("repository") or m.get("tree")
    file = str(m.get("file") or "")
    for label, (key, prefix) in keys.items():
        if not key or key != repo:
            continue
        rel = os.path.normpath(os.path.relpath(file, prefix)) if prefix else os.path.normpath(file)
        if not rel.startswith(".."):
            return label, rel
    return None


def _row_subjects(row: Dict[str, Any], primary: Optional[str],
                  keys: Dict[str, Tuple[Optional[str], str]]) -> set:
    """⛔ PER ROW, NOT THE PLAN'S PRIMARY ALONE (F64). In a several-lock plan each group lands in its own repository:
    black planned with `--repo agent-builder --with admin` has an admin group whose alert is admin's, and with the
    primary as the only subject its stored answer was skipped as `other_repository` (and the other way round when the
    repos were swapped). The primary stays a subject: an L2 row lands in a FOREIGN lock (aiohttp, base-image) while
    its alerts, and so their answers, belong to the primary."""
    labels = {(row.get("resolve") or {}).get("repo")} | {e.get("repo") for e in row.get("edits") or []} \
        | {e.get("repo") for e in row.get("blocked_edits") or []}
    out = {primary} if primary else set()
    out |= {keys[lb][0] for lb in labels if lb in keys and keys[lb][0]}
    return {k.lower() for k in out}


def _read_mine(subject: Optional[str]) -> Tuple[Optional[set], str]:
    """(the subject's alert ids from the queue, or None) and, when None, why — said in a D2 `why`."""
    if not subject:
        return None, "the subject repository has no key, so its alerts could not be put first"
    try:
        ids = read_subject_alerts(subject)
    except RuntimeError as exc:
        return None, f"the reachability queue could not be read, so the subject's alerts were not put first: {exc}"
    if not ids:
        return None, "the reachability queue listed no alert for the subject, so its alerts were not put first"
    return set(ids), ""


def _lock_member(row: Dict[str, Any], m: Dict[str, Any], label: str, rel: str, root: Root,
                 out: Dict[str, Any]) -> None:
    """A set member on a LOCK line: does this checkout's lock still resolve the version the Atlas saw there, and does
    this plan recompile that lock? Stale only when the lock no longer resolves that version at that place, or when it
    does and the plan leaves the lock alone. A lock already at or past the target is evidence, not a change."""
    pkg, target = row["package"], str(row["target"])
    want = re.sub(r"^\s*===?\s*", "", str(m.get("from") or m.get("version") or "")).strip()
    where = root.commit[:12] if root.commit else "this checkout"
    res = [x for x in _resolutions(root, "pypi", pkg) if x.get("file") == rel]
    stale = {"repository": m.get("repository") or m.get("tree"), "file": rel, "line": m.get("line")}
    if not res:
        out["stale"].append({**stale, "why": f"{rel} no longer resolves {pkg} at {where}"})
        return
    got = str(res[0]["version"])
    line = res[0].get("line")
    if line != m.get("line"):
        row.setdefault("evidence", []).append(
            f"{label}/{rel}: the Atlas snapshot has it at line {m.get('line')}, this checkout at {line}")
    if want and same_version("pypi", got, want):
        if not any(lk.get("repo") == label and lk.get("file") == rel for lk in row.get("locks") or []):
            out["stale"].append({**stale, "line": line,
                                 "why": f"the set says {rel} must move from {want} and this plan does not recompile it"})
        return
    if highest("pypi", [got, target]) == got:
        row.setdefault("evidence", []).append(f"{label}/{rel}:{line} already resolves {got} at {where}")
        return
    out["stale"].append({**stale, "line": line,
                         "why": f"{rel} resolves {got} at {where}, not the {want or '?'} the Atlas saw"})


def _union_sets(sets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Several repositories' must-move sets as one: every member, review and undecidable entry once (same place, same
    action = the same entry). Each set is complete; the union is what the plan must cover for all of them."""
    out: Dict[str, Any] = {"complete": True, "members": [], "review": [], "undecidable": []}
    seen: Dict[str, set] = {k: set() for k in ("members", "review", "undecidable")}
    for s in sets:
        for k in ("members", "review", "undecidable"):
            for e in s.get(k) or []:
                ident = json.dumps({x: e.get(x) for x in ("repository", "tree", "file", "line", "action", "dockerfile",
                                                          "apply_line", "words")}, sort_keys=True, default=str)
                if ident not in seen[k]:
                    seen[k].add(ident)
                    out[k].append(e)
    return out


def move_scope_pass(rows: List[Dict[str, Any]], roots: List[Root], scope: Dict[str, Dict[str, Any]],
                    source: "Optional[Dict[str, Dict[str, Any]]]" = None,
                    places: Optional[Dict[str, str]] = None) -> None:
    """Writes `move_scope` on every package row with a target (§ 3.4.6). The Atlas DISCOVERS, the checkout DECIDES
    the edit (§ 3.4.7): a member in a root is re-read from the checkout; a member outside every root makes the plan
    unapprovable (`out_of_scope`, DF's `member_out_of_scope`); a build patch is `review`.

    ⛔ D2: no usable answer → `source: none` and DF asks the approver to acknowledge `lever_scope_unverified`. A route
    error is NEVER a plan failure (§ 2.7: the fix lane keeps working without the Atlas). A non-pypi row is
    `unsupported`, with no acknowledgement: otherwise every npm plan would need one."""
    keys = _tree_keys(roots, scope)
    primary = next(r for r in roots if r.primary)
    by_label = {r.label: r for r in roots}
    subject = keys[primary.label][0]
    queue: Dict[str, Tuple[Optional[set], str]] = {}   # per repository key, read once and only when a pypi row needs it
    for row in rows:
        if not row.get("target"):
            continue
        if row["ecosystem"] != "pypi":
            row["move_scope"] = {"source": "unsupported", "why": WHY_UNSUPPORTED}
            continue
        subjects = _row_subjects(row, subject, keys)
        mine, mine_why = None, ""
        if source is None:
            for k in sorted(subjects):
                if k not in queue:
                    queue[k] = _read_mine(k)
            got = [queue[k][0] for k in sorted(subjects) if queue[k][0] is not None]
            mine = set().union(*got) if got else None
            mine_why = "" if got else next((queue[k][1] for k in sorted(subjects) if queue[k][1]), "")
        # The subject's alerts first (F62's order), so a capped read never spends itself on other repositories.
        ordered = {**row, "alert_ids": _subject_first([a for a in row.get("alert_ids") or [] if a], subjects,
                                                      places or {}, mine)}
        answers, gaps, why = _stored_sets(ordered, source, places)
        answers = [a for a in answers if isinstance(a.get("pins"), dict)]
        sets, incomplete = [], []
        for resp in answers:
            ms_one = mt.must_move(resp["pins"], str(row["target"]))
            if ms_one.get("complete"):
                sets.append((resp, ms_one))
            else:
                trees = ", ".join(dict.fromkeys(str(g.get("tree") or g.get("repository") or "?")
                                                for g in ms_one.get("not_checked") or []))
                incomplete.append((resp, f"the Atlas could not check {trees or 'every tree'}"))
        if not sets:
            if incomplete:
                why = "; ".join(w for _, w in incomplete)
            elif not why:
                why = "the stored Atlas answer carries no pins"
            if source is None and mine_why and why.startswith(("the stored Atlas answer", "no stored Atlas answer")):
                why += f" ({mine_why})"
            row["move_scope"] = {"source": "none", "why": why}
            continue
        ms = _union_sets([s for _, s in sets])
        as_of: List[Dict[str, Any]] = []
        for resp, _ in sets:
            for a in resp.get("as_of") or []:
                if a not in as_of:
                    as_of.append(a)
        out: Dict[str, Any] = {"source": "atlas", "as_of": as_of, "out_of_scope": [], "review": [], "stale": []}
        out["stale"] += gaps + [{"repository": r.get("repository"), "file": None, "line": None,
                                 "why": f"the Atlas answer for {r.get('repository')} is incomplete ({w})"}
                                for r, w in incomplete]
        mine = {(e.get("repo"), e.get("file")) for e in (row.get("edits") or []) + (row.get("blocked_edits") or [])}
        for m in ms.get("members") or []:
            hit = _member_root(m, keys)
            if hit is None:
                out["out_of_scope"].append({"repository": m.get("repository") or m.get("tree"),
                                            "file": m.get("file"), "line": m.get("line"), "from": m.get("from"),
                                            "to": m.get("to"), "why": m.get("why")})
                # ⚠️ Data only: DF writes the sentence (`out_of_scope_words`). `related` / `integration_id` are
                # omitted: the planner has no cheap read of PI's related repositories (DF prints a placeholder).
                continue
            label, rel = hit
            if m.get("action") == "recompile":
                continue                                # a lock line: the row's resolver command recompiles it
            root = by_label[label]
            if m.get("lock_format"):
                # ⛔ A LOCK LINE IS RE-READ AS A LOCK (F62 (c)). A transitive pinned only by a compiled lock (aiohttp in
                # base-image/requirements.lock) is a `ships` member with no declaration anywhere, so the manifest read
                # below always called it stale: a false `lever_scope_unverified` on every such plan.
                _lock_member(row, m, label, rel, root, out)
                continue
            found = [d for d in manifests.declared(root.records, "pypi", row["package"]) if d["file"] == rel]
            if not found:
                out["stale"].append({"repository": m.get("repository") or m.get("tree"), "file": rel,
                                     "line": m.get("line"),
                                     "why": f"no declaration of {row['package']} in {rel} at "
                                            f"{root.commit[:12] if root.commit else 'this checkout'}"})
                continue
            d = found[0]
            if d.get("line") != m.get("line"):
                row.setdefault("evidence", []).append(
                    f"{label}/{rel}: the Atlas snapshot has it at line {m.get('line')}, this checkout at {d.get('line')}")
            if policy.admits("pypi", d["version_spec"], str(row["target"]), d.get("syntax")) is True:
                row.setdefault("evidence", []).append(
                    f"{label}/{rel}:{d.get('line')} already admits {row['target']} at {(root.commit or '')[:12]}")
            elif (label, rel) not in mine:
                # ⚠️ The set requires this change and the plan does not make it (e.g. a lock input already bumped
                # while the lock is stale, which `classify` ignores as "not part of this resolve"). Never dropped
                # silently: scope is unverified, so a person acknowledges it.
                out["stale"].append({"repository": m.get("repository") or m.get("tree"), "file": rel,
                                     "line": d.get("line"),
                                     "why": f"the set says `{d['version_spec']}` must change and this plan does "
                                            f"not edit it"})
        for r in ms.get("review") or []:
            out["review"].append({k: r.get(k) for k in ("repository", "file", "dockerfile", "apply_line", "words")})
        if ms.get("undecidable") and row["verdict"] in (CLASS_LOCK, CLASS_DECLARATION):
            words = "; ".join(str(u.get("words") or "") for u in ms["undecidable"])
            row.update(_declined(row, words, row.get("evidence") or [], "undecidable_spec"))
            row["edits"] = []                           # as `classify`'s own undecidable decline: nothing is edited
        row["move_scope"] = out


# ── groups: one per resolve and class ────────────────────────────────────────────────

def _commands(rows: List[Dict[str, Any]], paths: Dict[str, str]) -> List[str]:
    """One resolver invocation per lock the group's rows resolve in, naming every package (a removal names none:
    the recompile drops it). ⚠️ An npm transitive is pinned by `npm install <pkg>@<ver>` only through an
    `overrides` entry; the command says so rather than silently promoting it to a declaration."""
    per_lock: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        for lk in row.get("locks") or []:
            c = per_lock.setdefault((lk["repo"], lk["file"]), {"lk": lk, "pins": [], "override": False})
            if not row.get("removal"):
                c["pins"].append((row["package"], row["target"]))
            c["override"] |= (lk["lock_format"] == "npm" and row["verdict"] == CLASS_LOCK
                              and not row.get("declared_here"))
    out = []
    for (repo, _), c in sorted(per_lock.items()):
        lk = c["lk"]
        head, each = _RECOMPILE.get(lk["lock_format"], (None, None))
        if lk["lock_format"] == "npm" and rows[0]["verdict"] == CLASS_DECLARATION:
            head, each = _RECOMPILE_NPM_DECLARATION
        if head is None:
            continue
        if head == "{header}":
            try:
                head = shlex.join(header_argv(os.path.join(paths[repo], lk["file"])))
            except LibraryTooOld as exc:
                log(f"note: {exc}")
                head = f"<the command in {os.path.basename(lk['file'])}'s header>"
        cmd = head
        cmd += "".join(each.format(pkg=p, ver=v) for p, v in c["pins"])
        if c["override"]:
            cmd += "  # transitive: add each to package.json `overrides` first"
        out.append(f"({repo}) {cmd}")
    return out


def group(rows: List[Dict[str, Any]], primary: str, paths: Dict[str, str]) -> List[Dict[str, Any]]:
    """FD § "One PR per resolve": class-2 and class-3 groups keyed by (class, the lock that resolves the scanned
    version, dev-only); a declined, not-declared or class-4 row is its own entry, with its reason. ⚠️ Dev-only npm
    packages are their own group: their approval differs and their lever (an `overrides` block) may not exist yet.

    ⛔ CLASS 4 IS KEYED BY PACKAGE, NOT BY LOCK. Keyed by the lock it would share a group with every other
    package that resolves there, and `_commands` would emit one resolver invocation naming all of them — the
    class-4 package included. Gate 1 would pass, because gate 1 only checks that the asked versions landed, and
    the upgrade this classification exists to refuse would ship inside someone else's PR."""
    groups: Dict[Tuple, Dict[str, Any]] = {}
    members: Dict[Tuple, List[Dict[str, Any]]] = {}
    for row in rows:
        v = row["verdict"]
        if v in (CLASS_LOCK, CLASS_DECLARATION):
            key = (v, row["resolve"]["repo"], row["resolve"]["file"], bool(row.get("dev_only")))
        else:
            key = (v, row.get("decline") or "", row["package"], False)
        g = groups.setdefault(key, {"class": v, "resolve": row.get("resolve")
                                    if v in (CLASS_LOCK, CLASS_DECLARATION, CLASS_CODE) else None,
                                    "dev_only": key[3], "packages": [], "edits": [], "commands": [],
                                    "evidence": []})
        g["packages"].append({k: row.get(k) for k in ("package", "ecosystem", "installed", "target", "flaws",
                                                       "no_fix", "alert_ids", "dev_only", "removal",
                                                       "falls_out_with", "blocked_on") if row.get(k) not in
                              (None, False, [])})
        g["edits"] += [e for e in row.get("edits") or [] if e not in g["edits"]]
        g["evidence"] += (row.get("evidence") or []) + (row.get("ignored_declarations") or [])
        members.setdefault(key, []).append(row)
        if v in (DECLINED, NOT_DECLARED_HERE, CLASS_CODE):
            g["why"] = row["why"]
        if v == CLASS_CODE and row.get("api_diff"):
            g["api_diff"] = row["api_diff"]
            g["blocked_edits"] = row.get("blocked_edits") or []
    for key, g in groups.items():
        if g["class"] in (CLASS_LOCK, CLASS_DECLARATION):
            g["commands"] = _commands(members[key], paths)
        repos = {e["repo"] for e in g["edits"]} | {c.split(")")[0][1:] for c in g["commands"]}
        if g["class"] == CLASS_CODE:
            repos = {primary}                            # it edits nothing; the report belongs to the subject repo
        g["repos"] = sorted(repos)
        g["pr_set"] = bool(repos - {primary})
    order = {CLASS_LOCK: 0, CLASS_DECLARATION: 1, CLASS_CODE: 2, NOT_DECLARED_HERE: 3, DECLINED: 4}
    return [groups[k] for k in sorted(groups, key=lambda k: (order[k[0]], k[1:]))]


# ── an alert as a finding ────────────────────────────────────────────────────────────

class NotAPackageFinding(ValueError):
    """The alert is not about a package version, so there is nothing for the planner to decide."""


def finding_from_alert(alert: Dict[str, Any], alert_id: Optional[str] = None) -> Dict[str, Any]:
    """The planner's finding for one alert record (`torana alert ID get --format json`). The key is split as the
    platform splits it (`reachability_verdict.finding_ecosystem`, the queue's `seg`): five `|` segments after
    `finding_key=`, the ecosystem and package non-empty."""
    aid = alert.get("id") or alert_id
    key = alert.get("finding_key") or ""
    seg = key.split("finding_key=", 1)[1].split("|") if "finding_key=" in key else []
    if len(seg) != 5 or not seg[1].strip() or not seg[2].strip():
        if key.startswith("vulnerability:"):
            raise NotAPackageFinding(f"alert {aid} has a legacy `vulnerability:` key ({key!r}): it names no "
                                     f"ecosystem / installed version the planner can read without guessing")
        if seg[:1] == ["report"]:
            raise NotAPackageFinding(f"alert {aid} is keyed by its scan report ({key!r}): Torana recorded no image "
                                     f"or repository for it, so no lock or manifest can be named")
        raise NotAPackageFinding(f"alert {aid} is not a package finding (finding_key {key!r}): the planner "
                                 f"decides package versions only")
    return {"ecosystem": seg[1].strip().lower(), "package": seg[2].strip(), "installed": seg[3].strip() or None,
            "fixed": alert.get("remediation_target_version") or None, "alert_id": aid}


#: The statuses the reachability queue counts as open (DF `reachability_service._OPEN`): an entry's closed members
#: are not planned again.
_OPEN = ("open", "in_progress", "triaging", "awaiting_input", "pending_remediation")


def repository_of_alert(alert: Dict[str, Any]) -> Optional[str]:
    """The `repo:` key a package finding names as its place, or None. An image-scan finding's place is
    `image@sha256:…`, which names no repository: for those only the reachability queue knows the binding."""
    key = alert.get("finding_key") or ""
    seg = key.split("finding_key=", 1)[1].split("|") if "finding_key=" in key else []
    place = seg[4].strip() if len(seg) == 5 else ""
    return place.lower() if place.startswith("repo:") else None


def place_of_alert(alert: Dict[str, Any]) -> Optional[str]:
    """The place a package finding names, whatever it is (`repo:…`, `image@sha256:…`), or None. Used only to read one
    stored answer per place; a non-`repo:` place says nothing about which repository owns it."""
    key = alert.get("finding_key") or ""
    seg = key.split("finding_key=", 1)[1].split("|") if "finding_key=" in key else []
    place = seg[4].strip() if len(seg) == 5 else ""
    return (place.lower() if place.startswith("repo:") else place) or None


def findings_for_alert(alert: Dict[str, Any], alert_id: str, members_of,
                       not_planned: Optional[List[Dict[str, Any]]] = None,
                       places: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """The findings one alert stands for. ⭐ AN ENTRY IS ITS MEMBERS: an Inbox entry (`entry:<id>:upgrade.package.v1|
    pkg:pypi/pyjwt`) carries the package but no installed version, which lives on each member
    (`finding:finding_key=…|pypi|pyjwt|2.14|…`). So an entry is planned as its open members, and every other alert
    as itself. For example, an entry for one package has one open member, and the plan names that member's installed and fixed versions.

    ⛔ ONE UNPLACEABLE MEMBER NEVER REFUSES THE ENTRY (walkthrough I-6). An entry joins findings from every scanner:
    an image scan's member with no recorded place (`report|…`) sat next to a repo scan's placeable ones, and the whole
    entry was refused, so the fix that was fine never got a plan. Each member that is not a package finding is left
    out and named in `not_planned` (`{alert_id, why}`); the entry is refused only when no open member can be planned.
    An alert asked for directly (not an entry) is still refused: the caller named it.

    `places` (out): alert id → the `repo:` key its finding names, for every finding that names one. Kept beside the
    findings, not in them: `--findings-out` is the `propose --findings` shape and does not change."""
    def note(rec: Dict[str, Any], aid: Optional[str]) -> None:
        # A `repo:` key, or the image the finding was scanned on: alerts on one place share one stored answer.
        place = repository_of_alert(rec) or place_of_alert(rec)
        if places is not None and aid and place:
            places[aid] = place

    if (alert.get("finding_key") or "").startswith("entry:"):
        members = [m for m in members_of(alert_id) if str(m.get("status") or "").lower() in _OPEN]
        if not members:
            raise NotAPackageFinding(f"alert {alert_id} is an entry with no open member: nothing to plan")
        findings: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for m in members:
            try:
                findings.append(finding_from_alert(m))
                note(m, m.get("id"))
            except NotAPackageFinding as exc:
                skipped.append({"alert_id": m.get("id"), "entry_alert_id": alert_id, "why": str(exc)})
        if not findings:
            raise NotAPackageFinding(f"alert {alert_id} is an entry none of whose {len(members)} open member(s) can be "
                                     f"planned: " + "; ".join(s["why"] for s in skipped))
        if not_planned is not None:
            not_planned.extend(skipped)
        return findings
    out = [finding_from_alert(alert, alert_id)]
    note(alert, alert.get("id") or alert_id)
    return out


def _cli_json(args: List[str], want: type) -> Any:
    """`torana <args> --format json`, or raise with the CLI's own words. ⛔ Never plan on a partial record."""
    from reachability_pass import run_cli              # ⭐ the scan pack's CLI caller
    rc, data = run_cli([*args, "--format", "json"])
    if rc != 0 or not isinstance(data, want) or (isinstance(data, dict) and ("_err" in data or "_raw" in data)):
        why = (data.get("_err") or data.get("_raw") or data) if isinstance(data, dict) else data
        raise RuntimeError(f"`torana {' '.join(args)}` failed (rc={rc}): {str(why)[:300]}")
    return data


def read_alert(alert_id: str) -> Dict[str, Any]:
    return _cli_json(["alert", alert_id, "get"], dict)


def read_members(alert_id: str) -> List[Dict[str, Any]]:
    return _cli_json(["alert", alert_id, "members"], list)


# ── the run ──────────────────────────────────────────────────────────────────────────

def plan(repo: str, with_roots: List[str], findings: List[Dict[str, Any]],
         diffs: Optional[List[Dict[str, Any]]] = None,
         api_diff_mode: str = API_DIFF_OFF,
         api_diff_views: Optional[List[Dict[str, Any]]] = None,
         move_together: "Optional[str | Dict[str, Dict[str, Any]]]" = MOVE_OFF,
         places: Optional[Dict[str, str]] = None, lock_check: bool = False) -> Dict[str, Any]:
    """`repo` and each of `with_roots` is a directory, or `PATH@REF` to read PATH's tree at that commit instead of
    the working tree. The label (and so every evidence `file:line`) comes from PATH either way.

    `lock_check`: re-lock each class-2/3 lock with no upgrade and decline its rows `lock_stale` when that changes
    it (`lock_freshness`). ⚠️ The function's default is OFF (a library call runs no resolver); the script's is ON.

    `diffs`/`api_diff_views` given (a `--api-diff-file` run, even an empty one) → the file answers every API diff question
    and `api_diff_mode` must be `off`. ⚠️ The function's default stays `off` (a library call asks nothing); the
    script's default is `request` (`main`).

    `move_together`: `off` (the function's default: no `move_scope`, a pre-W1 plan), `cli` (read each alert's stored
    set through the CLI: the script's default), or the `--fix-scope-file` responses keyed by alert id."""
    with tempfile.TemporaryDirectory(prefix="remediation-plan-") as tmp:
        return _plan(repo, with_roots, findings, tmp, diffs, api_diff_mode, api_diff_views, move_together, places,
                     lock_check)


def _plan(repo_arg: str, with_roots: List[str], findings: List[Dict[str, Any]], tmp: str,
          diffs: Optional[List[Dict[str, Any]]] = None,
          api_diff_mode: str = API_DIFF_OFF,
          api_diff_views: Optional[List[Dict[str, Any]]] = None,
          move_together: "Optional[str | Dict[str, Dict[str, Any]]]" = MOVE_OFF,
          places: Optional[Dict[str, str]] = None, lock_check: bool = False) -> Dict[str, Any]:
    repo = os.path.abspath(split_ref(repo_arg)[0])
    # ⚠️ scope[].path stays the CHECKOUT, never the temp tree: `remediation_proposal.scope_keys` resolves the
    # repository key and prefix from it, and the temp tree is gone when plan() returns. `ref` says the facts came
    # from that commit, and `commit` is its sha.
    scope: Dict[str, Dict[str, Any]] = {}

    def root(arg: str, primary: bool) -> Root:
        path, ref = split_ref(arg)
        path = os.path.abspath(path)
        label = os.path.basename(repo) if primary else _label(path, repo)
        if ref is None:
            r = Root(path, label, primary)
        else:
            tree, sha = materialize(path, ref, tmp)
            r = Root(tree, label, primary, commit=sha)
        scope[label] = {"repo": label, "path": path, "commit": r.commit, **({"ref": ref} if ref else {})}
        return r

    roots = [root(repo_arg, True)] + [root(p, False) for p in with_roots]
    cache: Dict[str, Any] = {}

    def imports_of(root: Root, eco: str, pkg: str) -> Dict[str, Any]:
        if "index" not in cache:
            cache["index"] = build_imports(root.path, commit=root.commit or "unknown", repository=root.label)
        return _answer.answer({"kind": "package", "ecosystem": eco, "package": pkg}, components_of(cache["index"]),
                              repository=root.label, commit=root.commit or "unknown",
                              binding={"state": "measured", "alert_commit": root.commit or "unknown"})

    rows = [classify(a, roots, imports_of) for a in _aggregate(findings)]
    falls_out(rows, roots)
    # ⭐ BEFORE the diffs: the set can decline a row (`undecidable_spec`), and a declined row asks no API question.
    if move_together not in (None, MOVE_OFF):
        move_scope_pass(rows, roots, scope, None if move_together == MOVE_CLI else move_together, places)
    # ⭐ AFTER the set (it can decline a row first) and BEFORE the API diffs: a stale lock declines the row, and a
    # declined row asks no API question.
    if lock_check:
        lock_check_pass(rows, roots, os.path.join(tmp, "lock-check"))
    # ⚠️ AFTER `classify`, BEFORE `api_diff_pass`: the fetch needs each row's verdict and resolve lock to
    # know which rows are eligible and which lock's origin to read, and the intersection needs the API diffs.
    # ⭐ Computed BEFORE any row is marked, by the same filter as the fetch, whatever `--api-diff` says: the GitHub
    # Action runs this planner with `--api-diff off` and reads `api_diffs_wanted` to fetch with its own token (§ 3.6.7 (f)).
    api_diffs_wanted = eligible_pairs(rows, roots)
    # ⭐ A `--api-diff-file` run and a `--api-diff` run cannot both happen (main() refuses it), so the API diffs come from ONE
    # source, never a merge of two.
    if diffs is not None or api_diff_views is not None:
        in_hand = list(diffs or [])
        apply_api_diff_file(rows, roots, in_hand, list(api_diff_views or []))
    else:
        in_hand = fetch_api_diffs(rows, roots, api_diff_mode)
    api_diff_pass(rows, roots, in_hand)
    groups = group(rows, roots[0].label, {r.label: r.path for r in roots})
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"engine": ENGINE_VERSION, "repo": roots[0].label,
            "scope": [scope[r.label] for r in roots],
            "findings": len(findings), "packages": len(rows), "counts": counts, "groups": groups, "rows": rows,
            "api_diffs_wanted": api_diffs_wanted}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", metavar="PATH[@REF]",
                    help="the checkout the findings are about. PATH@REF (e.g. ../service@origin/main) reads "
                         "the tree at that commit instead of the working tree; nothing is fetched")
    ap.add_argument("--with", dest="with_roots", action="append", default=[], metavar="ROOT[@REF]",
                    help="another tree in the scope (repeatable): one whose declarations or lock build this "
                         "service, e.g. shared-lib, deploy/base-image@origin/main")
    ap.add_argument("--findings-out", metavar="FILE",
                    help="also write the findings planned (the `reachability-queue --as-findings` shape, e.g. an "
                         "--alert and its open members) to FILE, for `torana remediation-plans propose --findings`")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings", help="JSON array of {ecosystem, package, installed, fixed, alert_id?}")
    src.add_argument("--alert", dest="alerts", action="append", metavar="ID",
                     help="an alert to plan (repeatable), read through the torana CLI")
    # ⚠️ default=None, resolved below: `request` with no `--api-diff-file`, `off` with one. Only an EXPLICIT `--api-diff`
    # next to `--api-diff-file` is refused (FIX_KNOWLEDGE_CONVERGENCE § 3.6.7 (a)).
    ap.add_argument("--api-diff", choices=[API_DIFF_OFF, API_DIFF_READ, API_DIFF_REQUEST], default=None,
                    help="read API diffs from the platform for every class-3 bump and every class-2 move that "
                         "crosses a major version (or a 0.x minor): `request` (the default) also asks the platform "
                         "to compute a missing pair, which spends the tenant's daily cold-pair quota; `read` uses "
                         "only what is already cached; `off` asks nothing. A package whose changed API this "
                         "repository calls becomes class 4 - reported with its call sites, never fixed. A package "
                         "the lock did not resolve from a PUBLIC registry is never sent.")
    ap.add_argument("--api-diff-file", metavar="FILE",
                    help="API diffs to classify against, instead of asking the platform: a JSON array of "
                         "torana.api_diff.v1 and/or API diff views ({key, state, document?, failure_reason?|reason?}, "
                         "what `api-diff get --json` prints plus the pair key). A package whose changed API "
                         "this repository calls is class 4 — reported with its call sites, never fixed. A pair the "
                         "file does not mention is `not_requested`. This flag is how the GitHub Action (no "
                         "credential in the planner), an offline run and the tests supply them")
    ap.add_argument("--fix-scope-file", metavar="FILE",
                    help="every place that must move together, from the Atlas, read from FILE instead of the CLI: a "
                         "JSON array of `torana alert <id> fix-scope --json` responses (the GitHub Action "
                         "collects them with its own token; the planner holds none). An alert absent from the file "
                         "has no stored answer, so its package is planned on --repo/--with alone and the plan asks "
                         "the approver to acknowledge that other repositories were not checked")
    ap.add_argument("--lock-check", choices=["on", "off"], default="on",
                    help="re-lock each lock with NO upgrade first (`uv lock --check` for uv) and decline its "
                         "packages `lock_stale` when that changes it: a lock already out of date with its manifest "
                         "would ship its staleness inside the fix. Runs the lock's resolver (default: on)")
    ap.add_argument("--json", dest="as_json", action="store_true", help="only JSON on stdout")
    a = ap.parse_args()
    move_together: Any = MOVE_CLI
    if a.fix_scope_file:
        try:
            move_together = read_move_together_file(a.fix_scope_file)
        except (OSError, ValueError) as exc:
            log(f"ERROR: cannot read --fix-scope-file {a.fix_scope_file}: {exc}")
            return 2
    diffs: Optional[List[Dict[str, Any]]] = None
    views: Optional[List[Dict[str, Any]]] = None
    if a.api_diff_file and a.api_diff is not None:
        # REFUSED rather than silently preferring one. A file of API diffs and a live fetch are two different
        # sources of truth for the same question, and a run that quietly used one while the caller believed
        # the other would produce a plan nobody can reproduce.
        log("ERROR: --api-diff-file and --api-diff are mutually exclusive: the file IS the offline source, "
            "so pick one.")
        return 2
    api_diff_mode = a.api_diff or (API_DIFF_OFF if a.api_diff_file else API_DIFF_REQUEST)
    if a.api_diff_file:
        try:
            diffs, views = read_api_diffs(a.api_diff_file)
        except (OSError, ValueError) as exc:
            log(f"ERROR: cannot read --api-diff-file {a.api_diff_file}: {exc}")
            return 2
    not_planned: List[Dict[str, Any]] = []
    places: Dict[str, str] = {}
    if a.alerts:
        try:
            findings = [f for aid in a.alerts
                        for f in findings_for_alert(read_alert(aid), aid, read_members, not_planned, places)]
        except NotAPackageFinding as exc:
            log(f"ERROR: {exc}")
            return 2
        except RuntimeError as exc:
            log(f"ERROR: {exc}")
            return 1
    else:
        try:
            with open(a.findings, encoding="utf-8") as fh:
                findings = json.load(fh)
        except (OSError, ValueError) as exc:
            log(f"ERROR: cannot read --findings {a.findings}: {exc}")
            return 2
        if not isinstance(findings, list):
            log("ERROR: --findings must be a JSON array")
            return 2
    for p in [a.repo, *a.with_roots]:
        if not os.path.isdir(split_ref(p)[0]):
            log(f"ERROR: not a directory: {p}")
            return 2
    if a.findings_out:
        try:
            with open(a.findings_out, "w", encoding="utf-8") as fh:
                json.dump(findings, fh, indent=2)
        except OSError as exc:
            log(f"ERROR: cannot write --findings-out {a.findings_out}: {exc}")
            return 2
    try:
        out = plan(a.repo, a.with_roots, findings, diffs, api_diff_mode, views, move_together, places,
                   lock_check=a.lock_check == "on")
    except BadRef as exc:
        log(f"ERROR: {exc}")
        return 2
    out["not_planned"] = not_planned
    log(f"{out['repo']}: {out['findings']} finding(s) over {out['packages']} package(s) → {out['counts']}")
    for s in not_planned:
        log(f"not planned: member {s['alert_id']} of entry {s['entry_alert_id']}: {s['why']}")
    if a.as_json:
        print(json.dumps(out, indent=2))
        return 0
    for g in out["groups"]:
        pk = ", ".join(f"{p['package']} {p.get('installed')}→{p.get('target') or '—'}" for p in g["packages"])
        where = f"{g['resolve']['repo']}/{g['resolve']['file']}" if g["resolve"] else g.get("why", "")
        print(f"[{g['class']}] {where}{' (dev only)' if g['dev_only'] else ''}"
              f"{'  (PR set: ' + ', '.join(g['repos']) + ')' if g['pr_set'] else ''}")
        print(f"    {pk}")
        if g["class"] == CLASS_CODE:
            print(f"    {g.get('why', '')}")
            for h in (g.get("api_diff") or {}).get("touched") or []:
                print(f"    uses {h['symbol']}  ({h['change']})  {h['file']}:{h['line']}"
                      + ("" if h.get("by") in ("import_name", "attribute")
                         else "   [name in the file, not in the import]"))
            for e in g.get("blocked_edits") or []:
                print(f"    NOT edited {e['repo']}/{e['file']}:{e['line']} `{e.get('from')}` → `{e.get('to')}`")
        for e in g["edits"]:
            print(f"    edit {e['repo']}/{e['file']}:{e['line']} {e['action']} `{e.get('from')}`"
                  f"{(' → `' + e['to'] + '`' if e.get('to') else ' → (a human chooses)') if e['action'] == 'bump' else ''}"
                  f"{'  ⚠ ' + e['needs_human'] if e.get('needs_human') else ''}")
        for c in g["commands"]:
            print(f"    run  {c}")
    for s in not_planned:
        print(f"[not planned] member {s['alert_id']}: {s['why']}")
    print(f"\n{out['counts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
