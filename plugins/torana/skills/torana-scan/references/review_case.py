#!/usr/bin/env python3
"""EM D-23 S3: the review CASE that carries one plan's applied fix between the remediate Action's jobs.

The remediate Action's reviewed lane (its reusable workflow `.github/workflows/remediate.yml`) is four jobs:

    1 resolve  (Torana token)        gates 1-3 on a scratch copy → WRITES the case        (`write_case`)
    4 gates    (nothing; hosted)     gates 4/5 on the case's trees → gates.json           (`apply --gates-from-case`)
    2 review   (model key; hosted)   vet_case.py reads the case → vet.json                (torana-skills)
    3 open-pr  (Torana token)        CHECKS the case against today's heads, posts the vet, sends the case's files
                                                                                          (`apply --from-case`)

⛔ JOB 3 NEVER RE-RESOLVES. It opens exactly the tree jobs 2 and 4 judged, or nothing. What binds them:
- `bases`: the HEAD of EVERY tree the fix reads, at job 1. Job 3 opens only if each is still the HEAD it checked
  out (a moved base can add a call site the review never saw: em3 r1 M4).
- `digest`: a content digest of the whole fix (`tree_digest`), recomputed by job 3 from its fresh checkout and the
  case's trees. It covers every changed, added and removed file with its mode and bytes, so a repeated lock line
  in another place, a mode change, a rename or an emptied file all change it (a hunk-only hash would not).

⚠️ What it does NOT bind: job 1 itself. Job 1's resolver code runs in the job that writes the case and its digest,
so it can forge both together. That is today's residual (the resolver already runs next to open-pr), bounded by
PI's door (every path against the approved plan's lane) and DF's fingerprint check.

Stdlib only: job 2 and job 4 import it without the CLI.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Tuple

CASE_SCHEMA = "torana.remediation_case.v1"
#: EXACTLY the directories `_fresh_copy` never copies (remediation_apply.py `_SKIP_DIRS`; a test pins the two
#: equal): a digest over any other set would differ between a checkout and its copy for no reason.
SKIP_DIRS = frozenset({"node_modules", ".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "dist",
                       ".angular"})
#: The marker `_fresh_copy` drops into every copy; not part of the fix.
COPY_MARKER = ".torana-remediation-copy"
#: What job 4 hands job 3: the gate results, never anything else from a job that ran third-party code.
GATE_KEYS = ("gate_4_build", "gate_5_tests", "gate_5_coverage")


class CaseError(Exception):
    """The case cannot be used: job 3 opens nothing from it, and says why."""


def _files(root: str) -> Dict[str, Tuple[str, str]]:
    """{relative path: (kind+mode, sha256)} of every file under `root`, skipping `SKIP_DIRS`. A symlink is recorded
    by its target text, never followed."""
    out: Dict[str, Tuple[str, str]] = {}
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not os.path.islink(os.path.join(d, x)))
        for name in files + [x for x in os.listdir(d) if os.path.islink(os.path.join(d, x))
                             and os.path.isdir(os.path.join(d, x))]:
            p = os.path.join(d, name)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if rel == COPY_MARKER:
                continue
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", hashlib.sha256(os.readlink(p).encode()).hexdigest())
            elif stat.S_ISREG(st.st_mode):
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                out[rel] = ("x" if st.st_mode & 0o111 else "f", h.hexdigest())
    return out


def tree_digest(pairs: Dict[str, Tuple[str, str]]) -> str:
    """sha256 over {label: (base root, applied root)}: for each label in order, every path whose kind, mode or bytes
    differ, or that exists on one side only, as `label\\0path\\0before\\0after`. Equal trees → no lines."""
    h = hashlib.sha256(b"torana-case-digest-v1\n")
    for label in sorted(pairs):
        base, applied = pairs[label]
        a, b = _files(base), _files(applied)
        for rel in sorted(set(a) | set(b)):
            if a.get(rel) != b.get(rel):
                before = ":".join(a[rel]) if rel in a else "-"
                after = ":".join(b[rel]) if rel in b else "-"
                h.update(f"{label}\0{rel}\0{before}\0{after}\n".encode())
    return "sha256:" + h.hexdigest()


def git_head(root: str) -> Optional[str]:
    p = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else None


def _copytree(src: str, dst: str) -> None:
    shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(*SKIP_DIRS, COPY_MARKER))


def write_case(case_dir: str, *, rec: Dict[str, Any], subject: str, plan: Dict[str, Any], group_index: int,
               report: Dict[str, Any], copies: Dict[str, str], roots: Dict[str, str],
               api_diffs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Write one plan's case. `copies` = {repo key: applied copy}, `roots` = {repo key: the checkout it came from}.
    Returns `case.json`. ⛔ The base of EVERY root is recorded, not only the copied ones: the review read them all."""
    if os.path.exists(case_dir):
        raise CaseError(f"refusing to write into an existing case dir: {case_dir}")
    os.makedirs(case_dir)
    labels: Dict[str, str] = {}
    for repo, copy in sorted(copies.items()):
        label = os.path.basename(copy.rstrip("/"))
        labels[label] = repo
        _copytree(roots[repo], os.path.join(case_dir, "base", label))
        _copytree(copy, os.path.join(case_dir, "trees", label))
    bases = {}
    for repo, root in sorted(roots.items()):
        head = git_head(root)
        if not head:
            raise CaseError(f"{repo}: no git HEAD at {root}, so its base cannot be bound")
        bases[repo] = head
    diff_src = report.get("diff")
    if diff_src and os.path.isfile(diff_src):
        shutil.copyfile(diff_src, os.path.join(case_dir, "changes.diff"))
    rep = {**report, "diff": "changes.diff"}
    for name, obj in (("plan_group.json", plan), ("report.json", rep), ("api_diffs.json", {"api_diffs": api_diffs or []})):
        with open(os.path.join(case_dir, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=1, default=str)
    case = {"schema": CASE_SCHEMA, "plan_id": rec["id"], "fingerprint": rec.get("effective_fingerprint"),
            "subject": subject, "target": rec.get("target_repository"), "group": int(group_index), "labels": labels,
            "bases": bases, "digest": case_digest(case_dir, labels)}
    with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
        json.dump(case, fh, indent=1)
    return case


def case_digest(case_dir: str, labels: Iterable[str], bases: Optional[Dict[str, str]] = None) -> str:
    """The digest of the case's fix: `base/<label>` (or the given base roots, by label) against `trees/<label>`."""
    bases = bases or {}
    return tree_digest({lb: (bases.get(lb) or os.path.join(case_dir, "base", lb), os.path.join(case_dir, "trees", lb))
                        for lb in labels})


def load_case(case_dir: str, *, plan_id: str, fingerprint: str) -> Dict[str, Any]:
    """`case.json`, checked against the plan job 3 is about to open. Raises CaseError."""
    try:
        with open(os.path.join(case_dir, "case.json"), encoding="utf-8") as fh:
            case = json.load(fh)
    except (OSError, ValueError) as exc:
        raise CaseError(f"no readable case.json in {case_dir}: {exc}")
    if case.get("schema") != CASE_SCHEMA:
        raise CaseError(f"case schema {case.get('schema')!r} is not {CASE_SCHEMA}")
    if case.get("plan_id") != plan_id:
        raise CaseError(f"the case is for plan {case.get('plan_id')}, not {plan_id}")
    if case.get("fingerprint") != fingerprint:
        raise CaseError("the plan changed since the case was built (another fingerprint); the next run builds a new one")
    return case


def check_case(case_dir: str, case: Dict[str, Any], roots: Dict[str, str]) -> None:
    """Job 3's two checks, in order. Raises CaseError naming the first that fails.

    1. Every base the case recorded is the HEAD of the matching fresh checkout now (`roots`, by repo key).
    2. The digest recomputed from those checkouts (as bases) and the case's trees equals the recorded one."""
    for repo, sha in sorted((case.get("bases") or {}).items()):
        root = roots.get(repo)
        now = git_head(root) if root else None
        if now != sha:
            raise CaseError(f"base_moved: {repo} was {sha[:12]} when the fix was reviewed and is "
                            f"{(now or 'not checked out')[:12]} now; the next run reviews it again")
    labels = case.get("labels") or {}
    got = case_digest(case_dir, labels, {lb: roots[repo] for lb, repo in labels.items() if repo in roots})
    if got != case.get("digest"):
        raise CaseError("the case's trees do not match what was reviewed (digest mismatch); nothing was opened")


def load_report(case_dir: str) -> Dict[str, Any]:
    with open(os.path.join(case_dir, "report.json"), encoding="utf-8") as fh:
        rep = json.load(fh)
    rep["diff"] = os.path.join(case_dir, "changes.diff")
    return rep


def gates_for(case_dir: str, gates_path: Optional[str], case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Job 4's gate results for THIS case (same plan and digest), restricted to `GATE_KEYS`, else None."""
    if not gates_path or not os.path.isfile(gates_path):
        return None
    try:
        with open(gates_path, encoding="utf-8") as fh:
            g = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(g, dict) or g.get("plan_id") != case.get("plan_id") or g.get("digest") != case.get("digest"):
        return None
    return {k: g[k] for k in GATE_KEYS if isinstance(g.get(k), dict)}
