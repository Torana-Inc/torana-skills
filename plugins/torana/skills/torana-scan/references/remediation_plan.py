#!/usr/bin/env python3
"""Plan the fix PRs for a checkout's dependency findings, deterministically, with no model.

    findings  →  this script  →  a plan: groups by resolve, each with a class, a target, exact edits, evidence

FIX_PR_BUILD_PLAN.md § "Phase 2", FIX_PR_DESIGN.md § "One PR per resolve" and § "Classes 2 and 3",
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
                     published fix. ⛔ A decline is never a guess, and never a class

⭐ THE SCOPE IS SEVERAL TREES, NOT ONE. A service image is built from more than its own checkout: A company's services
often install a shared base-image lock (the pip-compile output of a `requirements.in`) and then their own
`pyproject.toml`, and a shared library declares pins every service inherits. A package version can therefore be
resolved by the base-image lock while a service's own lock does not hold the package at all. So
`--with ROOT` adds a tree to the scope; the RESOLVE a group is keyed by is the lock that resolves the INSTALLED
version, and every edit names the repository it lands in. An edit outside `--repo` makes the group a PR set.

⭐ ONE LIBRARY, NO SECOND PARSER. Every manifest, lock, range and import fact comes from the vendored
`torana_reachability` (`lib/`): `manifests.read_manifests` / `declared` / `declarations_complete`,
`locks.read_requirements`, `policy.admits`, and `answer.answer` for the removal sub-case. ⛔ Never edit the copy.

⚠️ CLASS 4 IS NOT DECIDED HERE. Without an upgrade card (phase 3) the API diff is unknown, so a class-3 bump across a
major version may still be class 4. The plan says the lever; gates and the card say whether source must change too.

⚠️ `--json` EMITS ONLY JSON on stdout; every diagnostic goes to stderr.

Usage:
    python3 remediation_plan.py --repo ../service-a --with ../shared-lib \\
        --with ../deploy/base-image --findings findings.json [--json]

    python3 remediation_plan.py --repo . --alert ALERT_ID [--alert ALERT_ID]... [--json]

`--findings`: a JSON array of `{ecosystem, package, installed, fixed, alert_id?}`; `fixed` null = no fix published.
The whole queue: `torana alerts reachability-queue --repository KEY --include-measured --as-findings`.

`--alert ID` (repeatable): the alert's findings, read through the `torana` CLI (`alert ID get`, and `alert ID members`
for an Inbox entry, which is planned as its open members). The package comes from the `finding_key`
(`finding:finding_key=<flaw>|<ecosystem>|<package>|<installed>|<place>`, the shape the reachability queue groups on),
the fix from `remediation_target_version`. ⛔ An alert that is not a package finding (a SAST finding, a Dockerfile's
CWE-250, a legacy `vulnerability:` key) is refused with exit 2, never planned.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# ⭐ THE ENGINE IS A VENDORED LIBRARY (see reachability_pass.py): a self-relative path into the skill's own folder.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from torana_reachability import ENGINE_VERSION  # noqa: E402
from torana_reachability import answer as _answer  # noqa: E402
from torana_reachability import locks, manifests, policy  # noqa: E402
from torana_reachability.answer import components_of  # noqa: E402
from torana_reachability.firstparty import normalize  # noqa: E402
from torana_reachability.index import build_imports  # noqa: E402

CLASS_LOCK = "2"
CLASS_DECLARATION = "3"
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


# ── the scope: one record set per tree ───────────────────────────────────────────────

class Root:
    """One tree in scope: its label (the path from `--repo`'s parent, so `deploy/base-image`), its
    manifest records, and its commit when it is a git checkout."""

    def __init__(self, path: str, label: str, primary: bool):
        self.path, self.label, self.primary = path, label, primary
        self.records = manifests.read_manifests(path)
        self.commit = _git_head(path)
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


def propose_spec(eco: str, spec: str, syntax: str, target: str) -> Tuple[Optional[str], Optional[str]]:
    """(the declaration rewritten to admit `target`, or None with why). Only the shapes whose rewrite is
    mechanical: an exact pin, a lower bound, npm's `^` / `~` / exact. ⛔ An upper bound that excludes the fix is a
    human's decision (it was written for a reason), so it is not rewritten."""
    s = spec.strip()
    new: Optional[str] = None
    if eco == "pypi" and syntax == "pep508":
        parts = [p.strip() for p in s.split(",") if p.strip()]
        out = []
        for p in parts:
            if p.startswith(("==", ">=", "~=")) and not p.startswith("==="):
                out.append(p[:2] + target)
            elif policy.admits(eco, p, target) is False:
                return None, f"`{p}` excludes {target}: an upper bound or exclusion is not rewritten mechanically"
            else:
                out.append(p)
        new = ",".join(out)
    elif eco == "npm":
        if s[:1] in ("^", "~") and policy.admits(eco, s[1:], s[1:]):
            new = s[0] + target
        elif policy.admits(eco, s, s):
            new = target
    if new is None:
        return None, f"no mechanical rewrite for `{spec}` ({syntax})"
    if policy.admits(eco, new, target, syntax) is not True:
        return None, f"the rewrite `{new}` does not admit {target}"
    return new, None


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
    if conflict:
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
           "declared_here": any(r.primary for r, _ in decls)}
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
        return {**out, "verdict": CLASS_DECLARATION, "edits": edits,
                "evidence": evidence + [f"{_ptr(r, d)} `{d['version_spec']}` does not admit {target}"
                                        for r, d in blocking]}
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
    version, dev-only); a declined or not-declared row is its own entry, with its reason. ⚠️ Dev-only npm packages
    are their own group: their approval differs and their lever (an `overrides` block) may not exist yet."""
    groups: Dict[Tuple, Dict[str, Any]] = {}
    members: Dict[Tuple, List[Dict[str, Any]]] = {}
    for row in rows:
        v = row["verdict"]
        if v in (CLASS_LOCK, CLASS_DECLARATION):
            key = (v, row["resolve"]["repo"], row["resolve"]["file"], bool(row.get("dev_only")))
        else:
            key = (v, row.get("decline") or "", row["package"], False)
        g = groups.setdefault(key, {"class": v, "resolve": row.get("resolve") if v in (CLASS_LOCK, CLASS_DECLARATION)
                                    else None, "dev_only": key[3], "packages": [], "edits": [], "commands": [],
                                    "evidence": []})
        g["packages"].append({k: row.get(k) for k in ("package", "ecosystem", "installed", "target", "flaws",
                                                       "no_fix", "alert_ids", "dev_only", "removal",
                                                       "falls_out_with", "blocked_on") if row.get(k) not in
                              (None, False, [])})
        g["edits"] += [e for e in row.get("edits") or [] if e not in g["edits"]]
        g["evidence"] += (row.get("evidence") or []) + (row.get("ignored_declarations") or [])
        members.setdefault(key, []).append(row)
        if v in (DECLINED, NOT_DECLARED_HERE):
            g["why"] = row["why"]
    for key, g in groups.items():
        if g["class"] in (CLASS_LOCK, CLASS_DECLARATION):
            g["commands"] = _commands(members[key], paths)
        repos = {e["repo"] for e in g["edits"]} | {c.split(")")[0][1:] for c in g["commands"]}
        g["repos"] = sorted(repos)
        g["pr_set"] = bool(repos - {primary})
    order = {CLASS_LOCK: 0, CLASS_DECLARATION: 1, NOT_DECLARED_HERE: 2, DECLINED: 3}
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
        raise NotAPackageFinding(f"alert {aid} is not a package finding (finding_key {key!r}): the planner "
                                 f"decides package versions only")
    return {"ecosystem": seg[1].strip().lower(), "package": seg[2].strip(), "installed": seg[3].strip() or None,
            "fixed": alert.get("remediation_target_version") or None, "alert_id": aid}


#: The statuses the reachability queue counts as open (DF `reachability_service._OPEN`): an entry's closed members
#: are not planned again.
_OPEN = ("open", "in_progress", "triaging", "awaiting_input", "pending_remediation")


def findings_for_alert(alert: Dict[str, Any], alert_id: str, members_of) -> List[Dict[str, Any]]:
    """The findings one alert stands for. ⭐ AN ENTRY IS ITS MEMBERS: an Inbox entry (`entry:<id>:upgrade.package.v1|
    pkg:pypi/pyjwt`) carries the package but no installed version, which lives on each member
    (`finding:finding_key=…|pypi|pyjwt|2.14|…`). So an entry is planned as its open members, and every other alert
    as itself. For example, an entry for one package has one open member, and the plan names that member's installed and fixed versions."""
    if (alert.get("finding_key") or "").startswith("entry:"):
        members = [m for m in members_of(alert_id) if str(m.get("status") or "").lower() in _OPEN]
        if not members:
            raise NotAPackageFinding(f"alert {alert_id} is an entry with no open member: nothing to plan")
        return [finding_from_alert(m) for m in members]
    return [finding_from_alert(alert, alert_id)]


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

def plan(repo: str, with_roots: List[str], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    repo = os.path.abspath(repo)
    roots = [Root(repo, os.path.basename(repo), True)] + [Root(os.path.abspath(p), _label(os.path.abspath(p), repo),
                                                               False) for p in with_roots]
    cache: Dict[str, Any] = {}

    def imports_of(root: Root, eco: str, pkg: str) -> Dict[str, Any]:
        if "index" not in cache:
            cache["index"] = build_imports(root.path, commit=root.commit or "unknown", repository=root.label)
        return _answer.answer({"kind": "package", "ecosystem": eco, "package": pkg}, components_of(cache["index"]),
                              repository=root.label, commit=root.commit or "unknown",
                              binding={"state": "measured", "alert_commit": root.commit or "unknown"})

    rows = [classify(a, roots, imports_of) for a in _aggregate(findings)]
    falls_out(rows, roots)
    groups = group(rows, roots[0].label, {r.label: r.path for r in roots})
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"engine": ENGINE_VERSION, "repo": roots[0].label,
            "scope": [{"repo": r.label, "path": r.path, "commit": r.commit} for r in roots],
            "findings": len(findings), "packages": len(rows), "counts": counts, "groups": groups, "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", help="the checkout the findings are about")
    ap.add_argument("--with", dest="with_roots", action="append", default=[], metavar="ROOT",
                    help="another tree in the scope (repeatable): one whose declarations or lock build this "
                         "service, e.g. shared-lib, deploy/base-image")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings", help="JSON array of {ecosystem, package, installed, fixed, alert_id?}")
    src.add_argument("--alert", dest="alerts", action="append", metavar="ID",
                     help="an alert to plan (repeatable), read through the torana CLI")
    ap.add_argument("--json", dest="as_json", action="store_true", help="only JSON on stdout")
    a = ap.parse_args()
    if a.alerts:
        try:
            findings = [f for aid in a.alerts for f in findings_for_alert(read_alert(aid), aid, read_members)]
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
        if not os.path.isdir(p):
            log(f"ERROR: not a directory: {p}")
            return 2
    out = plan(a.repo, a.with_roots, findings)
    log(f"{out['repo']}: {out['findings']} finding(s) over {out['packages']} package(s) → {out['counts']}")
    if a.as_json:
        print(json.dumps(out, indent=2))
        return 0
    for g in out["groups"]:
        pk = ", ".join(f"{p['package']} {p.get('installed')}→{p.get('target') or '—'}" for p in g["packages"])
        where = f"{g['resolve']['repo']}/{g['resolve']['file']}" if g["resolve"] else g.get("why", "")
        print(f"[{g['class']}] {where}{' (dev only)' if g['dev_only'] else ''}"
              f"{'  (PR set: ' + ', '.join(g['repos']) + ')' if g['pr_set'] else ''}")
        print(f"    {pk}")
        for e in g["edits"]:
            print(f"    edit {e['repo']}/{e['file']}:{e['line']} {e['action']} `{e.get('from')}`"
                  f"{(' → `' + e['to'] + '`' if e.get('to') else ' → (a human chooses)') if e['action'] == 'bump' else ''}"
                  f"{'  ⚠ ' + e['needs_human'] if e.get('needs_human') else ''}")
        for c in g["commands"]:
            print(f"    run  {c}")
    print(f"\n{out['counts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
