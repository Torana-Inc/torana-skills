#!/usr/bin/env python3
"""Apply a fix-PR plan to a scratch copy, run the resolver, and run gates 1-3. No model.

    remediation_plan.py --json  →  this script  →  per group: the edits, the resolver's lock, the gates' verdicts

REMEDIATION_BUILD.md § 2 (phase 2), FIX_PR_DESIGN.md § "What runs before the PR opens" and § "Idempotency".

⛔ DRY RUN UNLESS `--apply`. The dry run prints every edit and every resolver invocation it would make. `--apply` copies
each tree a group touches into `--work`, edits the COPY, runs the resolver there, and runs the gates. It never writes
to the trees the plan was made from.

⛔ THIS SCRIPT HOLDS NO GITHUB TOKEN. Two ways a PR opens:
  * `--open-pr`: the PLATFORM opens it (FIX_PR_SPEC.md § 3.4.3). The applied files go through `torana
    remediation-plan ID open-pr`, and the platform checks plan, paths and content before its GitHub App writes.
  * `--commit --push-pr` (the laptop lane, WP1): the DEVELOPER's own `git push` and `gh pr create`, with the
    credentials already on their machine, after `reserve-pr`; then `record-pr`, where the platform re-reads the
    pushed branch read-only and refuses anything outside the plan. Never `--force`, never a remote branch deleted.
An alert closes when its scanner stops reporting the finding, never by this job.

⛔ A `PATH@REF` PLAN IS PROVEN AT ITS COMMIT: a scope entry with `ref` is read at its recorded `commit` (extracted
under `<work>/base/`), never the working tree (`scope_trees`), so the probe gates the same bytes a fix lane commits.

FOUR MODES (FIX_PR_SPEC.md § 3.4.8):
  --plan FILE            a local planner output (as built): dry run, or `--apply --work DIR`
  --plan-id ID --probe   re-prove a server plan from its stored rows, then `remediation-plans propose
                         --refresh-plan-id ID` (when the platform says it needs a fresh check)
  --plan-id ID --open-pr apply an APPROVED plan under a lease and send the files to the platform
  --plan-id ID --commit [--push-pr] --repo <TARGET checkout>
                         the laptop lane: gate on origin/<base>, commit onto it on `torana/alert-<id>` with a
                         temporary index (the checkout, its branch and its dirty files are never touched); with
                         --push-pr: reserve-pr → git push → gh pr create [--draft] → record-pr --claim-id.
                         Exit 0 committed/already_committed/recorded · 2 refused before any write · 4 busy ·
                         6 GitHub not ready (B22) · 1 not_ready (gates) or error. `why` / `next` are for the developer

THE EDITS, each verified to change exactly the declaring line:
  pyproject.toml     `tomlkit` (vendored as a wheel in `vendor/`, imported from the zip: nothing is installed)
  requirements*.in   a line edit (pip-compile input)
  package.json       a key-order-preserving JSON writer; ⛔ refused if it would reformat any other line

THE RESOLVERS (uv and npm only, classes 2 and 3 only, per BP § Phase 2):
  uv.lock            `uv lock --upgrade-package <pkg>==<target>`
  pip-compile lock   the lock header's OWN command, plus `--upgrade-package <pkg>==<target>`
  package-lock.json  class 3: `npm install --package-lock-only` after the range edit. Class 2 on a direct dependency:
                     npm has no "this exact version, lock only". `npm update` takes the newest in range (0.10.7 for
                     `^0.10.0`, not the 0.10.2 fix), and `npm install <pkg>@<v>` rewrites the range. So the resolver
                     runs twice: once with the exact version in package.json, then again with the original bytes
                     restored, which keeps the locked version because it satisfies the range. Class 2 on a
                     transitive: an `overrides` entry (the one package.json key class 2 may touch), then install.

THE GATES (FD § "What runs before the PR opens"; gates 4 and 5 are phase 4):
  1 Resolve        the lock resolves each package at >= its target (removal: absent). Fail → class 5, with the
                   resolver's own output
  2 Blast radius   every OTHER package whose version moved in the lock. Never a failure: the PR names them
  3 Lane           the changed files are only the ones the class permits. Fail → the classification was wrong
  4 Build, 5 Tests not run yet: the report carries `gate_4_build` / `gate_5_tests` = {status: "not_run"}, never
                   omits them. Test discovery is `test_ladder.py`

⏱ A RESOLVER THAT DOES NOT FINISH within `--resolver-timeout` (default 1800 s) is killed with its process group and
the group is declined `resolver_timeout`: nothing was refused, so it is not class 5.

⭐ A FRESH TOKEN PER WRITE. Every platform call goes through the `torana` CLI, which honours `TORANA_TOKEN_CMD`:
when set, the CLI runs it right before each write (lease, propose, open-pr) and uses the token it prints, so a
900 s CI token taken before a long resolve never reaches a write expired. Unset: the CLI's usual token.

⭐ IDEMPOTENT: every `--apply` starts from a fresh copy, an edit already at its target is a no-op, and the same plan
yields the same lock and the same report.

⚠️ `--json` EMITS ONLY JSON on stdout; resolver output and diagnostics go to stderr.

Usage:
    python3 remediation_plan.py ... --json > plan.json
    python3 remediation_apply.py --plan plan.json [--group N]... [--package NAME]... [--apply --work DIR] [--json]
    python3 remediation_apply.py --plan-id ID --repo SUBJECT [--repo-key K] [--with ROOT[=KEY]]... \\
        --apply --work DIR (--probe | --open-pr) [--holder-run R] [--json]
"""

from __future__ import annotations

import argparse
import difflib
import filecmp
import glob
import json
import os
import re
import shlex
import socket
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "lib"))
# ⭐ VENDORED PURE-PYTHON WHEELS are imported from the zip (`vendor/VENDORED.json`). ⛔ Never pip-install them.
for _whl in sorted(glob.glob(os.path.join(_HERE, "vendor", "*.whl"))):
    sys.path.insert(0, _whl)

import remediation_plan as rp  # noqa: E402
# ⭐ ONE repository-key normaliser in the scan pack: reachability_pass's (an https and an ssh remote → one key).
from reachability_pass import git_repo_key as repo_key_of  # noqa: E402
import tomlkit  # noqa: E402
from torana_reachability import manifests, policy  # noqa: E402
from torana_reachability.firstparty import normalize  # noqa: E402

#: Never copied into the scratch tree, never compared by gate 3.
_SKIP = shutil.ignore_patterns("node_modules", ".git", ".venv", "venv", "__pycache__", ".mypy_cache",
                               ".pytest_cache", "dist", ".angular")
_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "dist",
              ".angular"}
_MARKER = ".torana-remediation-copy"
_TOOL_TAIL = 2000


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


class Refused(Exception):
    """An edit that cannot be made exactly as planned. The group stops; nothing is half-applied."""


# ── the work: which rows, edits and locks one group means ───────────────────────────

def select(plan: Dict[str, Any], groups: List[int], packages: List[str]) -> List[Dict[str, Any]]:
    """The class-2, class-3 and class-4 groups, each narrowed to `packages` when given (a per-alert run).

    ⚠️ A class-4 group is SELECTED but never applied: `run_group` returns its report before any tree is copied.
    It is here so that a package the operator asked about gets an answer — silently dropping it would read as
    "nothing to do" for the one class whose whole point is that something must be done by a person."""
    # ⛔ KEYED BY VERSION TOO. npm installs one package at several versions, so a lock can carry several rows for
    # one name — ansi-regex in nodejs-goof has three (3.0.0 -> 3.0.1, 4.1.0 -> 4.1.1, 5.0.0 -> 5.0.1), each a
    # different copy set with its own target. Keyed by name alone this dict kept ONE of them and the group then
    # looked it up once per entry, so apply fixed 5.0.1, silently dropped the other two findings, and gate 1
    # reported ok. Measured 2026-10-20.
    rows = {(r["ecosystem"], r["package"], r.get("installed")): r for r in plan["rows"]}
    by_name = {(r["ecosystem"], r["package"]): r for r in plan["rows"]}      # a group entry with no `installed`
    want = {p for p in packages}
    out = []
    for i, g in enumerate(plan["groups"]):
        if g["class"] not in ("2", "3", "4") or (groups and i not in groups):
            continue
        members = [rows.get((p["ecosystem"], p["package"], p.get("installed")))
                   or by_name[(p["ecosystem"], p["package"])] for p in g["packages"]
                   if not want or p["package"] in want or normalize(p["package"]) in want]
        if members:
            out.append({"index": i, "class": g["class"], "dev_only": g.get("dev_only", False), "rows": members})
    return out


def _on(lk: Dict[str, Any], row: Dict[str, Any]) -> bool:
    """Does `row` resolve in lock `lk`? By (repo, file): each row's lock entry carries its own line."""
    return any((x["repo"], x["file"]) == (lk["repo"], lk["file"]) for x in row.get("locks") or [])


def _locks(work: Dict[str, Any]) -> List[Dict[str, Any]]:
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in work["rows"]:
        for lk in r.get("locks") or []:
            seen.setdefault((lk["repo"], lk["file"]), lk)
    return [seen[k] for k in sorted(seen)]


def _edits(work: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in work["rows"]:
        for e in r.get("edits") or []:
            if e not in out:
                out.append({**e, "package": r["package"], "ecosystem": r["ecosystem"]})
    return out


def branch_name(work: Dict[str, Any]) -> str:
    """FD § "Idempotency": the branch is the state, and the PR-merge webhook reads the alert id out of it."""
    ids = [a for r in work["rows"] for a in r.get("alert_ids") or []]
    return f"torana/alert-{ids[0]}" if ids else "torana/alert-<alert_id>"


# ── edits ───────────────────────────────────────────────────────────────────────────

def _one_line_changed(before: str, after: str, line: int, removed: bool) -> None:
    """⛔ The writer may change the declaring line and nothing else (FD § "Class 3": a reformatted manifest buries
    the one-line change a reviewer came to see)."""
    a, b = before.splitlines(), after.splitlines()
    ops = [op for op in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes() if op[0] != "equal"]
    want = ("delete", line - 1, line, line - 1, line - 1) if removed else ("replace", line - 1, line, line - 1, line)
    if ops != [want]:
        raise Refused(f"the writer would change more than line {line}: {ops[:3]}")


def _replace_spec(req: str, old: str, new: str) -> str:
    head, sep, marker = req.partition(";")
    at = head.rfind(old)
    if at < 0:
        raise Refused(f"`{old}` is not in `{req}`")
    return head[:at] + new + head[at + len(old):] + sep + marker


def edit_pyproject(text: str, e: Dict[str, Any]) -> str:
    doc = tomlkit.parse(text)
    arrays = []
    project = doc.get("project") or {}
    arrays.append(project.get("dependencies"))
    arrays += list((project.get("optional-dependencies") or {}).values())
    arrays += list((doc.get("dependency-groups") or {}).values())
    arrays.append(((doc.get("tool") or {}).get("uv") or {}).get("dev-dependencies"))
    want = normalize(e["package"])
    for arr in [a for a in arrays if a is not None]:
        for i, item in enumerate(list(arr)):
            parsed = manifests.split_requirement(str(item)) if isinstance(item, str) else None
            if not parsed or parsed[0] != want:
                continue
            if e["action"] == "remove":
                del arr[i]
            elif parsed[1] == e.get("to"):
                return text                                 # already at the target: idempotent
            elif parsed[1] == e["from"]:
                arr[i] = _replace_spec(str(item), e["from"], e["to"])
            else:
                continue
            out = tomlkit.dumps(doc)
            _one_line_changed(text, out, e["line"], e["action"] == "remove")
            return out
    if e["action"] == "remove":
        return text                                         # already removed
    raise Refused(f"{e['file']}:{e['line']} declares no `{e['package']}{e['from']}`")


def edit_requirements(text: str, e: Dict[str, Any]) -> str:
    lines = text.splitlines(True)
    if e["line"] > len(lines):
        raise Refused(f"{e['file']} has no line {e['line']}")
    cur = lines[e["line"] - 1]
    parsed = manifests.split_requirement(cur.split(" #", 1)[0].strip())
    if not parsed or parsed[0] != normalize(e["package"]):
        if e["action"] == "remove":
            return text
        raise Refused(f"{e['file']}:{e['line']} is not a `{e['package']}` requirement: {cur.strip()!r}")
    if e["action"] == "remove":
        return "".join(lines[:e["line"] - 1] + lines[e["line"]:])
    if parsed[1] == e["to"]:
        return text
    if parsed[1] != e["from"]:
        raise Refused(f"{e['file']}:{e['line']} declares `{parsed[1]}`, the plan says `{e['from']}`")
    lines[e["line"] - 1] = _replace_spec(cur, e["from"], e["to"])
    return "".join(lines)


def _json_indent(text: str) -> int:
    for ln in text.splitlines()[1:]:
        if ln.strip():
            return len(ln) - len(ln.lstrip(" ")) or 2
    return 2


def dump_json(data: Any, like: str) -> str:
    """Key order is the insertion order `json.loads` kept; indent and trailing newline follow the original."""
    return json.dumps(data, indent=_json_indent(like), ensure_ascii=False) + ("\n" if like.endswith("\n") else "")


def edit_package_json(text: str, e: Dict[str, Any]) -> str:
    data = json.loads(text)
    if dump_json(data, text) != text:
        raise Refused(f"{e['file']} is not in the writer's own format, so any write would reformat it")
    for section in manifests.NPM_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict) and e["package"] in deps:
            if e["action"] == "remove":
                del deps[e["package"]]
            elif deps[e["package"]] == e["to"]:
                return text
            elif deps[e["package"]] == e["from"]:
                deps[e["package"]] = e["to"]
            else:
                raise Refused(f"{e['file']} declares `{deps[e['package']]}`, the plan says `{e['from']}`")
            out = dump_json(data, text)
            _one_line_changed(text, out, e["line"], e["action"] == "remove")
            return out
    if e["action"] == "remove":
        return text
    raise Refused(f"{e['file']} declares no `{e['package']}`")


def apply_edit(root: str, e: Dict[str, Any]) -> bool:
    """Edit one declaration in the copy at `root`. True when the file changed."""
    link = link_on_path(root, e["file"])
    if link:
        raise Refused(f"{e['file']}: {link} is a symlink; a manifest is never edited through a link")
    path = os.path.join(root, e["file"])
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    name = os.path.basename(e["file"])
    if name == "pyproject.toml":
        out = edit_pyproject(text, e)
    elif name == "package.json":
        out = edit_package_json(text, e)
    elif name.startswith("requirements"):
        out = edit_requirements(text, e)
    else:
        raise Refused(f"no writer for {e['file']}")
    if out != text:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(out)
    return out != text


# ── resolvers ───────────────────────────────────────────────────────────────────────

#: ⛔ Never handed to a resolver. uv, pip-compile and npm can run third-party build code (a setup.py, an npm
#: lifecycle script), so a resolver must not be able to mint a GitHub OIDC token (the two ACTIONS_ID_TOKEN_* values)
#: or use a Torana or GitHub credential this run holds.
RESOLVER_ENV_DENY = ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "TORANA_TOKEN",
                     "TORANA_TOKEN_CMD", "GITHUB_TOKEN")


def resolver_env() -> Dict[str, str]:
    """This process's environment without the credentials a resolver must never see."""
    return {k: v for k, v in os.environ.items() if k not in RESOLVER_ENV_DENY}


#: Wall-clock cap on ONE resolver invocation, in seconds (`--resolver-timeout`). Generous: a cold uv / npm cache on
#: a big lock takes minutes. ⛔ Without it a hung resolver (a registry that never answers) holds the run, and on
#: `--open-pr` the plan's lease, forever.
RESOLVER_TIMEOUT_S = 1800
RC_TIMED_OUT = 124                                      # timeout(1)'s exit code


def _text(b: Any) -> str:
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")


def _run(cmd: List[str], cwd: str) -> Dict[str, Any]:
    log(f"  $ (cd {cwd} && {shlex.join(cmd)})")
    timeout = RESOLVER_TIMEOUT_S
    try:
        # ⭐ ITS OWN PROCESS GROUP, so a timeout kills what the resolver spawned (npm's children, a build backend)
        # rather than only the direct child.
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env=resolver_env(), start_new_session=True)
    except FileNotFoundError:
        return {"cmd": shlex.join(cmd), "rc": 127, "output": f"{cmd[0]}: not found on this runner"}
    try:
        stdout, stderr = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            p.kill()
        stdout, stderr = p.communicate()
        out = (_text(stdout) + _text(stderr)).strip()
        why = f"{cmd[0]} timed out after {timeout} s and was killed: the lock was not proven either way"
        log(f"    {why}")
        return {"cmd": shlex.join(cmd), "rc": RC_TIMED_OUT, "timed_out": True,
                "output": (out[-(_TOOL_TAIL - len(why) - 1):] + "\n" + why).strip()}
    out = (_text(stdout) + _text(stderr)).strip()
    if out:
        log("    " + out[-_TOOL_TAIL:].replace("\n", "\n    "))
    return {"cmd": shlex.join(cmd), "rc": p.returncode, "output": out[-_TOOL_TAIL:]}


def resolver_unavailable(copy: str, lk: Dict[str, Any]) -> Optional[str]:
    """Why this runner cannot run the lock's resolver at all, or None. A uv project that declares a dependency by a
    `file://` path absent here (for example `shared-lib @ file:///app/deps/shared_lib-…whl`, present
    only inside the image) cannot be locked here. That is a decline, not a resolver refusal: nothing about the fix
    was tested."""
    if lk["lock_format"] != "uv" or not lk.get("compiled_from"):
        return None
    for d in manifests.read_manifests(copy, files=[lk["compiled_from"]]):
        spec = (d.get("version_spec") or "").strip()
        if d["kind"] == "declaration" and spec.startswith("@") and "file://" in spec:
            path = spec.split("file://", 1)[1].strip()
            if not os.path.exists(path):
                return (f"{lk['compiled_from']}:{d['line']} references {spec[1:].strip()}, present only in the "
                        f"image, not on this runner")
    return None


def resolve(copy: str, lk: Dict[str, Any], rows: List[Dict[str, Any]], cls: str) -> List[Dict[str, Any]]:
    """Run the resolver for one lock in the copy. Returns every invocation with its rc and output."""
    lock = os.path.join(copy, lk["file"])
    cwd = os.path.dirname(lock)
    pins = [(r["package"], r["target"]) for r in rows if r.get("target") and not r.get("removal")]
    fmt = lk["lock_format"]
    if fmt == "uv":
        return [_run(["uv", "lock", "--no-progress", *[a for p, v in pins for a in ("--upgrade-package",
                                                                                  f"{p}=={v}")]], cwd)]
    if fmt == "pip-compile":
        # ⛔ EXACTLY the argv the header records, plus the pins. `run_group` checked the library has
        # `pip_compile_argv` before anything was copied; `header_argv` raises rather than parse it here.
        return [_run(rp.header_argv(lock) + [a for p, v in pins for a in ("--upgrade-package", f"{p}=={v}")], cwd)]
    if fmt == "npm":
        return _resolve_npm(cwd, rows, cls)
    if fmt == "requirements":
        # ⭐ NOTHING TO RESOLVE: THE EDIT IS THE RESOLUTION. A pinned requirements.txt is both the declaration and
        # the resolved set (torana-reachability 1.12.0), so bumping `PyJWT==2.3.0` to `==2.15.0` has already
        # changed what the file says is installed — there is no second file to recompile and no resolver to run.
        # ⚠️ This is NOT the same as "no resolver wired". Returning that refusal failed gate 1 as class 5 on a
        # correct, complete edit (measured 2026-10-20), which is the absence-reported-as-a-problem shape: no
        # transitive dependency is re-resolved here, and the PR body must say so rather than imply a resolve ran.
        return [{"cmd": None, "rc": 0, "output": "",
                 "note": "no resolver: a pinned requirements file is edited in place, and its transitive "
                         "dependencies are whatever it already pins"}]
    return [{"cmd": None, "rc": 2, "output": f"no resolver wired for {fmt} in phase 2 (uv and npm only)"}]


_NPM = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]


def _scoped_override(overrides: Dict[str, Any], chain: List[str], pkg: str, target: str) -> None:
    """Write `overrides[a][b][pkg] = target` for the parent chain `[a, b]`, merging into whatever is there.

    ⛔ THE CHAIN IS WHY THIS EXISTS. npm's unscoped form `{"semver": "5.7.2"}` rewrites EVERY copy of semver in
    the tree, so fixing `a`'s private 5.7.1 would DOWNGRADE the top-level 7.5.4 — a change nobody asked for, on a
    package whose own finding is already fixed. The scoped form touches only the copy the finding is about.
    ⚠️ An existing STRING at a parent key means "force the parent itself to this version"; npm's syntax keeps that
    as the `"."` key once the entry gains children, so it is preserved rather than overwritten.
    """
    node = overrides
    for parent in chain:
        cur = node.get(parent)
        if isinstance(cur, str):
            cur = {".": cur}
        elif not isinstance(cur, dict):
            cur = {}
        node[parent] = cur
        node = cur
    node[pkg] = target


def _resolve_npm(cwd: str, rows: List[Dict[str, Any]], cls: str) -> List[Dict[str, Any]]:
    pj = os.path.join(cwd, "package.json")
    with open(pj, encoding="utf-8") as fh:
        original = fh.read()
    if cls == "3":
        return [_run(_NPM, cwd)]
    data = json.loads(original)
    # ⛔ A NESTED COPY IS NEVER `direct`, even when the package IS declared. `semver ^7` in `dependencies` governs
    # the TOP-LEVEL copy; rewriting that range to fix `a`'s private 5.7.1 would edit a declaration (class 3's
    # lever, not class 2's) AND downgrade the copy that is already fine. It takes a scoped override instead.
    nested = [r for r in rows if r.get("nested_copies")]
    rest = [r for r in rows if r not in nested]
    direct = [r for r in rest if any(r["package"] in (data.get(s) or {}) for s in manifests.NPM_SECTIONS)]
    transitive = [r for r in rest if r not in direct]
    runs = []
    if transitive or nested:
        data.setdefault("overrides", {})
        for r in transitive:
            data["overrides"][r["package"]] = r["target"]
        for r in nested:
            for copy in r["nested_copies"]:
                _scoped_override(data["overrides"], list(copy["nested_under"]), r["package"], r["target"])
        original = dump_json(data, original)                # the overrides key IS the class-2 edit; it stays
    if direct:
        pinned = json.loads(original)
        for r in direct:
            for s in manifests.NPM_SECTIONS:
                if r["package"] in (pinned.get(s) or {}):
                    pinned[s][r["package"]] = r["target"]
        with open(pj, "w", encoding="utf-8") as fh:
            fh.write(dump_json(pinned, original))
        runs.append(_run(_NPM, cwd))
        if runs[-1]["rc"] != 0:
            with open(pj, "w", encoding="utf-8") as fh:
                fh.write(original)
            return runs
    with open(pj, "w", encoding="utf-8") as fh:
        fh.write(original)                                   # the declared ranges, byte for byte
    runs.append(_run(_NPM, cwd))
    return runs


# ── gates ───────────────────────────────────────────────────────────────────────────

#: One lock's resolved versions, keyed by COPY: `(package, parent chain)`. ⛔ NOT by package name alone — npm
#: installs two versions of one package when two dependents need different majors, and a name-keyed dict silently
#: keeps whichever came last. That dict is what gates 1 and 2 compare, so the loser's fix would be reported as
#: landed when nothing touched it (a FALSE PASS, the one failure that lets a bad PR open). The chain is `()` for a
#: top-level copy, so every non-npm lock keeps exactly the shape it had.
def _resolved(root: str, lock_file: str) -> Dict[Tuple[str, Tuple[str, ...]], str]:
    return {(r["package"], tuple(r.get("nested_under") or ())): r["version"]
            for r in manifests.read_manifests(root, files=[lock_file])
            if r["kind"] == "resolution" and r.get("version")}


def _copies(resolved: Dict[Tuple[str, Tuple[str, ...]], str], pkg: str) -> Dict[Tuple[str, ...], str]:
    """Every copy of `pkg` in one lock: parent chain -> version."""
    return {chain: v for (p, chain), v in resolved.items() if p == pkg}


def _one(copies: Dict[Tuple[str, ...], str]) -> Any:
    """One copy -> its version string (the shape every caller and surface already reads); several -> the sorted
    list. ⚠️ Never a silent pick: two copies that disagree must both reach the reader."""
    vs = sorted(set(copies.values()))
    return (vs[0] if vs else None) if len(vs) < 2 else vs


#: Gates 4 (build) and 5 (tests) until phase 4 wires them: reported, never silently absent.
GATE_NOT_RUN = {"status": "not_run", "why": "gates 4 and 5 are not wired yet (REMEDIATION_BUILD.md § 2, phase 4)"}


def gate_resolve(before: Dict[str, str], after: Dict[str, str], rows: List[Dict[str, Any]],
                 runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    failed = [r for r in runs if r["rc"] != 0]
    if failed:
        return {"ok": False, "why": "the resolver refused (class 5)", "resolver_output": failed[-1]["output"]}
    landed, short = {}, []
    for r in rows:
        eco, pkg = r["ecosystem"], r["package"]
        was, now = _copies(before, pkg), _copies(after, pkg)
        # ⭐ THE QUESTION IS "ARE THE COPIES THIS FINDING IS ABOUT FIXED", and `scanned_copies` is which ones
        # those are. ⛔ NOT "every copy of this name": npm installs one package at several versions, and the
        # others are OTHER findings with their own targets. MEASURED on nodejs-goof: async sits at 0.9.0,
        # 1.5.2, 1.5.2 and the scanned 2.6.3; the override fixed 2.6.3 -> 2.6.4 correctly and judging all four
        # against 2.6.4 refused it — a false refusal, and dragging 0.9.0 to 2.6.4 is a major upgrade nobody
        # asked for. ⛔ NOR per surviving chain: the resolver may HOIST a fixed nested copy to the top, which
        # changes its chain, so a chain that is simply GONE means the vulnerable copy is gone, which is a pass.
        mine = ({tuple(c.get("nested_under") or ()) for c in r["scanned_copies"]}
                if r.get("scanned_copies") else set(was))
        landed[pkg] = {"from": _one(was), "to": _one(now),
                       **({"copies": [{"nested_under": list(c), "version": v} for c, v in sorted(now.items())]}
                          if len(now) > 1 or any(c for c in now) else {})}
        if r.get("removal"):
            if now:
                short.append(f"{pkg} is still resolved at {_one(now)} after its removal")
            continue
        if not now:
            short.append(f"{pkg} resolved at None, below the target {r['target']}")
        for chain in sorted(mine):
            v = now.get(chain)
            if v is None:
                continue                            # hoisted or dropped: the vulnerable copy is gone
            if policy.admits(eco, f">={r['target']}", v) is not True:
                where = f" under {'/'.join(chain)}" if chain else ""
                short.append(f"{pkg} resolved at {v}{where}, below the target {r['target']}")
    return {"ok": not short, "landed": landed, **({"why": "; ".join(short)} if short else {})}


def gate_blast_radius(before: Dict[str, str], after: Dict[str, str], rows: List[Dict[str, Any]],
                      eco: str = "pypi") -> Dict[str, Any]:
    """Every OTHER package whose version moved. Never a failure, but ⛔ a package moving BACKWARDS never passes
    silently (lead's rule, 2026-10-19; measured: litellm 1.88.6 drags openai 3.16.2 → 2.54.0). It is flagged, and
    the group becomes needs_human: a human may accept it, nobody may miss it."""
    # ⛔ ASKED IS A COPY, NOT A NAME. Gate 1 now judges only the copies a row names (`scanned_copies`), so if
    # gate 2 also skipped by name, ANOTHER copy of the asked package moving would be reported by neither.
    # Measured 2026-10-20: the override for ansi-regex 5.0.0 made npm move `nodemon > ansi-regex` 4.1.0 -> 5.0.1,
    # a major jump nobody asked for, and nothing said so.
    asked = {(r["package"], tuple(c.get("nested_under") or ()))
             for r in rows for c in (r.get("scanned_copies") or [{}])}
    asked_names_without_copies = {r["package"] for r in rows if not r.get("scanned_copies")}
    moved = []
    # ⛔ PER COPY, not per name. An unscoped npm `overrides` entry rewrites EVERY copy of a package, so the fix for
    # a nested copy can drag the top-level one backwards; keyed by name that move is invisible, and the downgrade
    # rule above is what must catch it.
    for key in sorted(set(before) | set(after)):
        p, chain = key
        a, b = before.get(key), after.get(key)
        if a == b or (p, chain) in asked or p in asked_names_without_copies:
            continue
        down = bool(a and b and policy.admits(eco, f"<{a}", b) is True)
        moved.append({"package": p, "from": a, "to": b,
                      **({"nested_under": list(chain)} if chain else {}),
                      **({"downgrade": True} if down else {})})
    return {"ok": True, "moved": moved, "downgrades": [m for m in moved if m.get("downgrade")]}


def link_on_path(root: str, rel: str) -> Optional[str]:
    """The first component of `rel` under `root` that is a symlink (as a relative path), or None. Never follows one.

    ⛔ A repository is untrusted: a tracked link can dangle, loop, or point outside the checkout (the vendored
    library's rule, `torana_reachability.paths`). Checking only the last component is not enough: a lock under a
    linked DIRECTORY is read and written through that link just the same. A `..` segment is refused the same way."""
    cur, seen = root, []
    for part in rel.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        seen.append(part)
        if part == "..":
            return "/".join(seen)
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            return "/".join(seen)
    return None


def _entry(path: str) -> Optional[Tuple[str, Any]]:
    """What a tree entry IS, without following it: ('link', target) | ('file', path) | ('dir', None) | None."""
    if os.path.islink(path):
        return ("link", os.readlink(path))
    if os.path.isfile(path):
        return ("file", path)
    if os.path.isdir(path):
        return ("dir", None)
    return None


def changed_files(original: str, copy: str) -> List[str]:
    """Every entry that differs between two trees. ⛔ A link is compared AS a link (its target string), never
    through it: a dangling link identical on both sides is unchanged (a repository can track several, and following
    them fails gate 3 on every `--plan-id` run), a retargeted link is changed, and a link that became a file (or
    the reverse) is changed even when the bytes agree. Directory links are entries too, never descended."""
    out: List[str] = []
    for base, other in ((copy, original), (original, copy)):
        for d, dirs, files in os.walk(base):                    # followlinks=False: a linked dir is not entered
            dirs[:] = [x for x in dirs if x not in _SKIP_DIRS]
            names = list(files) + [x for x in dirs if os.path.islink(os.path.join(d, x))]
            for f in names:
                rel = os.path.relpath(os.path.join(d, f), base)
                if f == _MARKER or rel in out:
                    continue
                mine, theirs = _entry(os.path.join(d, f)), _entry(os.path.join(other, rel))
                if mine is None or theirs is None or mine[0] != theirs[0]:
                    out.append(rel)
                elif mine[0] == "link":
                    if mine[1] != theirs[1]:
                        out.append(rel)
                elif mine[0] == "file" and not filecmp.cmp(mine[1], theirs[1], shallow=False):
                    out.append(rel)
    return sorted(out)


def _only_overrides_moved(original: str, copy: str, rel: str) -> bool:
    if link_on_path(original, rel) or link_on_path(copy, rel):
        return False                                        # a link is never opened: it is simply not the lane
    with open(os.path.join(original, rel), encoding="utf-8") as a, open(os.path.join(copy, rel), encoding="utf-8") as b:
        x, y = json.load(a), json.load(b)
    x.pop("overrides", None)
    y.pop("overrides", None)
    return x == y


def gate_lane(cls: str, changes: Dict[str, List[str]], allowed: Dict[str, set], originals: Dict[str, str],
              copies: Dict[str, str], exact: bool = False) -> Dict[str, Any]:
    """FD gate 3: class 2 → the locks, plus at most package.json's `overrides`; class 3 → the declaring files and
    the locks. ⛔ A hunk outside the lane means the verdict and the edit disagree.

    `exact` (a server plan, `--plan-id`): `allowed` is the plan's server-computed `allowed_files`, which already
    holds the npm class-2 `package.json` beside each lock (FIX_PR_SPEC.md § 3.4.3 check 4, rule P4), so NOTHING
    outside it passes, not even an overrides-only package.json: the platform would refuse that file anyway.

    ⛔ CLASS 4: THE LANE IS EMPTY, whatever `allowed` says. A class-4 PR is a document — the upgrade, and the call
    sites in this repository that it breaks — so no file may change, the lock least of all. `allowed` is seeded
    from the group's locks by its caller (a class-4 row still RESOLVES in a lock; that is how it was found), so
    without this the lane would permit the very recompile the classification refuses."""
    if cls == "4":
        allowed, exact = {}, True
    outside = []
    for repo, files in changes.items():
        for rel in files:
            if rel in allowed.get(repo, set()):
                continue
            if (not exact and cls == "2" and os.path.basename(rel) == "package.json"
                    and _only_overrides_moved(originals[repo], copies[repo], rel)):
                continue
            outside.append(f"{repo}/{rel}")
    return {"ok": not outside, "changed": {k: v for k, v in changes.items() if v},
            **({"outside_lane": outside, "why": "the classification was wrong: re-queue for triage"}
               if outside else {})}


# ── what blocks a partial (FIX_PR_SPEC.md § 3.4.7, § 3.10.14) ──────────────────────

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def blocked_by_locks(plan: Dict[str, Any], row: Dict[str, Any], cache: Optional[Dict[str, Any]] = None,
                     trees: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """A partial package P is blocked by lock L when the resolver's refusal of P's requested target names a
    package Q, and Q is DECLARED in another tree or file in scope (not the lock being recompiled, nor the manifest
    it compiles from: those are this plan's own lever). L = the lock in Q's tree that resolves Q, else the declaring
    file. The server resolves each L to the plan on it, or "not yet planned"."""
    out_text = row.get("refusal_output") or ""
    if not row.get("partial") or not out_text:
        return []
    names = {normalize(t) for t in _NAME.findall(out_text)} - {normalize(row["package"])}
    own = {(lk["repo"], lk["file"]) for lk in row.get("locks") or []}
    own |= {(lk["repo"], lk["compiled_from"]) for lk in row.get("locks") or [] if lk.get("compiled_from")}
    cache = {} if cache is None else cache
    found: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for s in plan.get("scope") or []:
        path = (trees or {}).get(s["repo"], s["path"])          # the tree the edit is proven on (scope_trees)
        if path not in cache:
            cache[path] = manifests.read_manifests(path)
        recs = cache[path]
        for d in recs:
            if (d["kind"] != "declaration" or d.get("ecosystem") != row["ecosystem"]
                    or normalize(d.get("package") or "") not in names or (s["repo"], d["file"]) in own
                    or not (d.get("version_spec") or "").strip()):
                continue
            lock = next((x["file"] for x in recs if x["kind"] == "resolution" and x.get("package") == d["package"]
                         and (s["repo"], x["file"]) not in own), d["file"])
            found.setdefault((s["repo"], lock), {
                "repo": s["repo"], "file": lock,
                "reason": f"`{d['package']}` pinned in `{s['repo']}/{d['file']}` (`{d['version_spec']}`)"})
    return [found[k] for k in sorted(found)]


# ── one group ───────────────────────────────────────────────────────────────────────


def linked_inputs(roots: Dict[str, str], edits: List[Dict[str, Any]], locks: List[Dict[str, Any]]) -> Optional[str]:
    """Why this group cannot run because a file it reads or writes is reached through a symlink, or None.

    ⛔ Everything the group touches: each lock (the resolver REWRITES it in place), the lock's compiled-from input,
    the `package.json` beside an npm lock (rewritten for class 2), and every edited manifest. A link anywhere on
    their path would send the read or the write outside the scratch copy, into the source checkout or beyond. The
    planner cannot name such a file (the library skips links), but a server plan (`--plan-id`) names repo-relative
    paths decided elsewhere, and a tree can change between plan and apply."""
    needed = [(e["repo"], e["file"]) for e in edits]
    for lk in locks:
        needed.append((lk["repo"], lk["file"]))
        if lk.get("compiled_from"):
            needed.append((lk["repo"], lk["compiled_from"]))
        if lk["lock_format"] == "npm":
            needed.append((lk["repo"], os.path.join(os.path.dirname(lk["file"]), "package.json")))
    for repo, rel in needed:
        link = link_on_path(roots[repo], rel)
        if link:
            return (f"symlink_in_tree: {repo}/{link} is a symlink on the path of {rel}; a lock or manifest is never "
                    f"read or written through a link")
    return None


def _fresh_copy(src: str, dst: str) -> None:
    if os.path.exists(dst):
        if not os.path.exists(os.path.join(dst, _MARKER)):
            raise Refused(f"{dst} exists and is not a copy this script made; refusing to replace it")
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=_SKIP, symlinks=True)
    open(os.path.join(dst, _MARKER), "w").close()


def scope_trees(plan: Dict[str, Any], work_dir: Optional[str]) -> Dict[str, str]:
    """repo → the tree an edit is proven ON.

    ⛔ A scope entry with `ref` was planned from that commit (the planner's `PATH@REF`, or the laptop lane's
    `origin/<base>`), and a fix lane commits on that commit. So it is read at its RECORDED `commit` (a sha, which
    cannot move under us the way a ref name can), extracted under `<work>/base/`, never from the working tree:
    otherwise a dirty or behind checkout passes or fails the gates for the wrong reason, and the probe sent to
    `propose` does not match the plan's commit. Without `ref`: the working tree, as before."""
    out: Dict[str, str] = {}
    for s in plan["scope"]:
        if not s.get("ref"):
            out[s["repo"]] = s["path"]
            continue
        if not s.get("commit"):
            raise Refused(f"{s['repo']}: planned at {s['ref']}, but the plan records no commit for it")
        root = os.path.join(work_dir, "base") if work_dir else tempfile.mkdtemp(prefix="remediation-base-")
        into = os.path.join(root, re.sub(r"[^A-Za-z0-9._-]+", "_", s["repo"]) + "@" + s["commit"][:12])
        if os.path.isdir(into):
            shutil.rmtree(into)                          # ours: everything under <work>/base is this script's
        os.makedirs(into)
        try:
            out[s["repo"]], _ = rp.materialize(s["path"], s["commit"], into)
        except rp.BadRef as exc:
            raise Refused(str(exc))
    return out


def run_group(plan: Dict[str, Any], work: Dict[str, Any], apply: bool, work_dir: Optional[str],
              probe: bool = True, allowed_files: Optional[Dict[str, set]] = None) -> Dict[str, Any]:
    """`allowed_files` (a server plan, `--plan-id`) replaces gate 3's derivation: the plan's own allowed set."""
    rows, cls, edits, locks = work["rows"], work["class"], _edits(work), _locks(work)
    cache: Dict[str, Any] = {}
    try:
        scope = scope_trees(plan, work_dir)
    except Refused as exc:
        return {"group": work["index"], "class": cls, "dev_only": work["dev_only"], "packages": [], "edits": edits,
                "locks": [], "branch": branch_name(work), "applied": apply, "status": "refused", "why": str(exc)}
    report: Dict[str, Any] = {
        "group": work["index"], "class": cls, "dev_only": work["dev_only"],
        "packages": [{"package": r["package"], "installed": r["installed"], "target": r.get("target"),
                      **({"removal": True} if r.get("removal") else {}),
                      **({k: r[k] for k in ("partial", "requested_target", "open_alert_ids", "refusal_output")
                          if k in r} if r.get("partial") else {}),
                      **({"blocked_by_locks": b} if (b := blocked_by_locks(plan, r, cache, scope)) else {})}
                     for r in rows],
        "edits": edits, "locks": [{"repo": lk["repo"], "file": lk["file"], "lock_format": lk["lock_format"]}
                                  for lk in locks],
        "branch": branch_name(work), "applied": apply}
    needs_human = [e for e in edits if e.get("needs_human") or (e["action"] == "bump" and not e.get("to"))]
    if needs_human:
        report["status"] = "needs_human"
        report["why"] = "; ".join(f"{e['repo']}/{e['file']}:{e['line']} {e.get('needs_human', '')}"
                                  for e in needs_human)
        return report
    blocked = [r.get("blocked_on") for r in rows if r.get("blocked_on")]
    if blocked:
        report["blocked_on"] = blocked
    if cls == "4":
        # ⛔ BEFORE ANY TREE IS COPIED AND BEFORE ANY RESOLVER RUNS. The rows still carry their locks, so every
        # step below would happily recompile them. Nothing is applied, so `--apply` and a dry run are the same
        # work here and the status says what is true either way.
        report["api_diff"] = [r["api_diff"] for r in rows if r.get("api_diff")]
        report["blocked_edits"] = [e for r in rows for e in r.get("blocked_edits") or []]
        report["gate_1_resolve"], report["gate_2_blast_radius"] = [], []
        # an omitted check reads as a passed one (FD § "The PR body is assembled, not written"), so gates 1 and 2
        # say why they have nothing to judge rather than being left out
        report["gates_not_applicable"] = {
            "gates": ["gate_1_resolve", "gate_2_blast_radius"],
            "why": "class 4 changes no file, so no resolver ran: gates 1 and 2 judge a resolve"}
        report["gate_3_lane"] = gate_lane(cls, {}, {}, scope, {}, exact=True)
        report["gate_4_build"], report["gate_5_tests"] = dict(GATE_NOT_RUN), dict(GATE_NOT_RUN)
        report["status"] = "code_change_required"
        report["why"] = "; ".join(r["why"] for r in rows if r.get("why")) or (
            "the upgrade changes an API this repository calls: a person must change the code")
        return report
    linked = linked_inputs(scope, edits, locks)
    if linked:
        report.update(status="refused", why=linked)
        return report
    if any(lk["lock_format"] == "pip-compile" for lk in locks):
        try:
            for lk in locks:
                if lk["lock_format"] == "pip-compile":
                    rp.header_argv(os.path.join(scope[lk["repo"]], lk["file"]))
        except rp.LibraryTooOld as exc:
            log(f"ERROR: {exc}")                            # ⛔ loudly: never a hand-built compile command
            report.update(status="refused", why=str(exc))
            return report
    if not apply:
        report["status"] = "dry_run"
        return report

    repos = sorted({e["repo"] for e in edits} | {lk["repo"] for lk in locks})
    group_dir = os.path.join(work_dir, f"group-{work['index']}")
    copies = {repo: os.path.join(group_dir, repo) for repo in repos}
    try:
        os.makedirs(group_dir, exist_ok=True)
        for repo in repos:
            _fresh_copy(scope[repo], copies[repo])
        linked = linked_inputs(copies, edits, locks)
        if linked:
            raise Refused(linked)
        before = {(lk["repo"], lk["file"]): _resolved(scope[lk["repo"]], lk["file"]) for lk in locks}
        report["edited"] = [f"{e['repo']}/{e['file']}:{e['line']}" for e in edits if apply_edit(copies[e["repo"]], e)]
    except Refused as exc:
        report.update(status="refused", why=str(exc))
        return report

    runs, gates1, gates2 = [], [], []
    for lk in locks:
        key, name = (lk["repo"], lk["file"]), f"{lk['repo']}/{lk['file']}"
        mine = [r for r in rows if _on(lk, r)]
        unavailable = resolver_unavailable(copies[lk["repo"]], lk)
        if unavailable:
            gates1.append({"lock": name, "ok": False, "declined": "resolver_unavailable", "why": unavailable})
            continue
        rs = resolve(copies[lk["repo"]], lk, mine, cls)
        runs += rs
        timed_out = [r for r in rs if r.get("timed_out")]
        if timed_out:
            # ⛔ A DECLINE, NOT A FAILED GATE 1: a resolver that never finished refused nothing, so the fix is not
            # class 5, and the candidate fallback must not spend another timeout on a lower version.
            gates1.append({"lock": name, "ok": False, "declined": "resolver_timeout",
                           "why": f"{timed_out[0]['cmd']} ran past {RESOLVER_TIMEOUT_S} s and was killed"})
            continue
        after = _resolved(copies[lk["repo"]], lk["file"])
        gates1.append({"lock": name, **gate_resolve(before[key], after, mine, rs)})
        gates2.append({"lock": name, **gate_blast_radius(before[key], after, mine,
                                                         "npm" if lk["lock_format"] == "npm" else "pypi")})
    report["resolver"] = runs
    report["gate_1_resolve"] = gates1
    report["gate_2_blast_radius"] = gates2
    changes = {repo: changed_files(scope[repo], copies[repo]) for repo in repos}
    allowed: Dict[str, set] = {}
    for lk in locks:
        allowed.setdefault(lk["repo"], set()).add(lk["file"])
    if cls == "3":
        for e in edits:
            allowed.setdefault(e["repo"], set()).add(e["file"])
    if allowed_files is not None:
        allowed = allowed_files
    report["gate_3_lane"] = gate_lane(cls, changes, allowed, scope, copies, exact=allowed_files is not None)
    report["diff"] = write_diff(scope, copies, changes, os.path.join(group_dir, "changes.diff"))
    downgrades = [{**d, "lock": g["lock"]} for g in gates2 for d in g["downgrades"]]
    # ⛔ GATES 4 AND 5 ARE NOT RUN YET (phase 4), and the report says so rather than omitting them: an omitted
    # check reads as a passed one (FD § "The PR body is assembled, not written").
    report["gate_4_build"] = dict(GATE_NOT_RUN)
    report["gate_5_tests"] = dict(GATE_NOT_RUN)
    unavailable = [g for g in gates1 if g.get("declined")]
    failed = next((n for n, g in (("1", [x for x in gates1 if not x.get("declined")]),
                                  ("3", [report["gate_3_lane"]])) if not all(x["ok"] for x in g)), None)
    if failed:
        report["status"] = f"failed_gate_{failed}"
    elif unavailable:
        report.update(status="declined", decline=unavailable[0]["declined"],
                      why="; ".join(f"{g['lock']}: {g['why']}" for g in unavailable))
    elif downgrades:
        report.update(status="needs_human", why="a package moves backwards: " + ", ".join(
            f"{d['package']} {d['from']} → {d['to']}" for d in downgrades))
    else:
        report["status"] = "gates_passed"
    if downgrades:                                       # ⛔ first in the report, and first in the PR body
        report = {"downgrades": downgrades, **report}
    if failed == "1" and probe:
        return _fallback(plan, work, report, work_dir, allowed_files)
    return report


def _retarget(row: Dict[str, Any], cand: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """`row` aimed at a lower fix candidate: `partial` with the flaws it leaves open, and each class-3 edit
    rewritten for that version (None when the declaration cannot be rewritten to admit it)."""
    v = cand["version"]
    if v == row["target"]:
        return row
    edits = []
    for e in row.get("edits") or []:
        if e["action"] == "bump":
            new, _ = rp.propose_spec(row["ecosystem"], e["from"], e.get("syntax") or "", v)
            if new is None:
                return None
            e = {**e, "to": new}
        edits.append(e)
    return {**row, "target": v, "edits": edits, "partial": True, "requested_target": row["target"],
            "open_alert_ids": cand.get("open_alert_ids") or []}


def _fallback(plan: Dict[str, Any], work: Dict[str, Any], report: Dict[str, Any],
              work_dir: str, allowed_files: Optional[Dict[str, set]] = None) -> Dict[str, Any]:
    """Gate 1 refused the group. FD § "Failure modes": a resolver conflict makes THAT finding class 5, not the whole
    PR. And (lead's rule, 2026-10-19) a refused full fix is not yet class 5: per package, alone, try its fix
    candidates highest first (the planner's list); the first that resolves is the highest resolvable AND the one
    clearing the most flaws, kept as `partial` with what it leaves open. Only a package no fix version resolves is
    split out as class 5, with the resolver's own output. The survivors are then re-run together.

    Measured on the base lock: cryptography 50.0.0 (the highest fix of its 4 flaws) is unreachable, since pyopenssl
    caps it, and pyopenssl 26.0.0 is capped by snowflake-connector-python==4.2.0."""
    chosen, refused = [], []
    probe_dir = os.path.join(work_dir, f"probe-{work['index']}")
    for r in work["rows"]:
        cands = r.get("candidates") or [{"version": r.get("target"), "open_alert_ids": []}]
        picked, last, first_refusal = None, None, None
        for c in cands if not r.get("removal") else [{"version": None}]:
            rr = r if r.get("removal") else _retarget(r, c)
            if rr is None:
                continue
            if len(work["rows"]) == 1 and rr is r:
                last = report                           # that exact attempt is the one that just failed
            else:
                last = run_group(plan, {**work, "rows": [rr]}, True, probe_dir, probe=False,
                                 allowed_files=allowed_files)
                if last.get("status") in ("gates_passed", "needs_human"):
                    picked = rr
                    break
            if first_refusal is None:                   # P1: the full fix's refusal names what blocks it
                g = next((g for g in last.get("gate_1_resolve") or [] if not g["ok"]), {})
                first_refusal = g.get("resolver_output") or g.get("why")
        if picked is not None:
            chosen.append({**picked, "refusal_output": first_refusal} if picked.get("partial") and first_refusal
                          else picked)
            continue
        g1 = next((g for g in (last or {}).get("gate_1_resolve") or [] if not g["ok"]), {})
        refused.append({"package": r["package"], "target": r.get("target"), "class": "5",
                        "why": "no fix version resolves" if len(cands) > 1 else "the resolver refuses it alone",
                        "tried": [c["version"] for c in cands],
                        "resolver_output": g1.get("resolver_output") or g1.get("why") or (last or {}).get("why")})
    if not chosen:
        return {**report, "split_out": refused}
    out = run_group(plan, {**work, "rows": chosen}, True, work_dir, probe=False, allowed_files=allowed_files)
    return {**out, **({"split_out": refused} if refused else {})}


def _diff_side(root: str, rel: str) -> List[str]:
    """One side of a diff. ⛔ A link (or a path under a linked directory) is shown as its target string and never
    read: the diff is what `open-pr` turns into file contents, so reading through a link could ship a file from
    outside the repository."""
    link = link_on_path(root, rel)
    if link:
        path = os.path.join(root, link)
        return [f"symlink -> {os.readlink(path)}\n"] if os.path.islink(path) else []
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return fh.read().splitlines(True)


def write_diff(originals: Dict[str, str], copies: Dict[str, str], changes: Dict[str, List[str]], out: str) -> str:
    parts = []
    for repo, files in sorted(changes.items()):
        for rel in files:
            x = _diff_side(originals[repo], rel)
            y = _diff_side(copies[repo], rel)
            parts += difflib.unified_diff(x, y, f"a/{repo}/{rel}", f"b/{repo}/{rel}", n=1)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    return out


# ── a server plan (`--plan-id`, FIX_PR_SPEC.md § 3.4.8) ─────────────────────────────

GO_STATES = ("approved", "overridden", "removal_chosen")
EXIT_SCOPE_MISSING = 2
EXIT_NOT_READY = 6
_CODE = re.compile(r"\((?P<a>[a-z_]+), HTTP \d+\)|^\s*error: (?P<b>[a-z_]+)\s*$", re.M)


def torana_bin() -> str:
    """The `torana` CLI: $TORANA, then $TORANA_VENV/bin/torana, then PATH (as reachability_pass.py)."""
    direct = os.environ.get("TORANA")
    if direct and os.path.exists(direct):
        return direct
    venv = os.environ.get("TORANA_VENV") or os.path.join(os.path.expanduser("~"), ".torana-venv")
    cand = os.path.join(venv, "bin", "torana")
    return cand if os.path.exists(cand) else "torana"


def torana(args: List[str]) -> Tuple[int, Any, str]:
    """(rc, parsed stdout or None, stderr). The CLI prints the server's error code as `(code, HTTP n)`.

    ⭐ The CLI inherits this process's environment, so with `TORANA_TOKEN_CMD` set EVERY call, the first GET
    included, takes its token from that command (the action strips TORANA_TOKEN from apply's env); only the
    resolvers get a scrubbed environment (`resolver_env`)."""
    try:
        p = subprocess.run([torana_bin(), *args], capture_output=True, text=True)
    except FileNotFoundError:
        return 127, None, "the torana CLI was not found ($TORANA, $TORANA_VENV/bin/torana, PATH)"
    try:
        parsed = json.loads(p.stdout) if (p.stdout or "").strip() else None
    except ValueError:
        parsed = None
    return p.returncode, parsed, p.stderr or ""


def error_code(stderr: str) -> str:
    m = _CODE.search(stderr or "")
    return (m.group("a") or m.group("b")) if m else ""


def github_not_ready(plan_id: str, target_root: Optional[str]) -> Optional[Dict[str, Any]]:
    """None when GitHub is ready for this plan; else {"why": <the failed checks' words>, "checks": [...]}.

    ⛔ PRE-FLIGHT, BEFORE ANY COMMIT (B22): every GitHub prerequisite is checked up front and each missing one is
    named with who fixes it, so the lane never pushes a branch the platform then refuses to record."""
    args = ["remediation-plan", plan_id, "github-readiness", "--format", "json"]
    if target_root:
        args += ["--repo", target_root]
    rc, out, err = torana(args)
    if rc == 0 and isinstance(out, dict) and out.get("ready") is True:
        return None
    if not isinstance(out, dict):
        return {"why": f"github readiness could not be checked: {err.strip()[-400:]}", "checks": []}
    failed = [c for c in (out.get("checks") or []) if c.get("ok") is not True and c.get("reason_code")]
    return {"why": "; ".join(f"{c['words']} (fix: {c['who_fixes']})" for c in failed) or "not ready",
            "checks": failed}


def _toplevel(path: str) -> str:
    p = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    return (p.stdout or "").strip() if p.returncode == 0 else os.path.abspath(path)


def local_roots(repo: Optional[str], repo_key: Optional[str], with_roots: List[str]) -> Dict[str, str]:
    """key → the repository's top level: `--repo` (key from `--repo-key` or its remote) and each `--with ROOT[=KEY]`.
    A planner `--with` may name a subdirectory (`deploy/base-image`); a server plan's paths are relative to
    the repository, so its top level is the root."""
    out: Dict[str, str] = {}
    for i, spec in enumerate(([repo] if repo else []) + list(with_roots)):
        path, _, key = spec.partition("=") if i or not repo else (spec, "", repo_key or "")
        key = key or repo_key_of(path)
        if key:
            out.setdefault(key, _toplevel(path))
    return out


def plan_input(rec: Dict[str, Any], roots: Dict[str, str], subject: str
               ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, set]]:
    """(planner-shaped plan, the one work item, gate 3's allowed set) from a server plan.

    The input is the union of the plan's `remediation_plan_rows` (every subject's; labels are already keys),
    narrowed to `effective_packages` (a dropped or refused package never comes back from stored rows) and merged
    per (ecosystem, package): the target is the HIGHEST of every subject's row target (each planner set its row to
    the highest fix of its own members, C5, so no CI runner needs another subject's members), an override's target
    replaces it, and locks are the union. Edits are the plan's `effective_edits`; only the plan's `locks` are
    recompiled."""
    target, eco = rec["target_repository"], rec["ecosystem"]
    if target not in roots:
        raise KeyError(target)
    eff = {p["package"]: p for p in rec.get("effective_packages") or rec.get("packages") or []}
    over = rec.get("override_packages") or []
    over = {o["package"]: o.get("target") for o in over} if isinstance(over, list) else dict(over)
    plan_locks = set(rec.get("locks") or [])
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    planner_edits: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for rr in rec.get("remediation_plan_rows") or []:
        for row in rr.get("planner_rows") or []:
            if row.get("package") not in eff:
                continue
            for e in row.get("edits") or []:
                planner_edits.setdefault((e["file"], e["line"]), {**e, "package": row["package"]})
            m = merged.setdefault((row["ecosystem"], row["package"]), {
                **{k: v for k, v in row.items() if k not in ("partial", "requested_target", "open_alert_ids",
                                                             "refusal_output", "edits", "locks")},
                "locks": [], "edits": [], "_targets": []})
            if row.get("target"):
                m["_targets"].append(row["target"])
            for lk in row.get("locks") or []:
                if lk["repo"] == target and lk["file"] in plan_locks and all(
                        (x["repo"], x["file"]) != (lk["repo"], lk["file"]) for x in m["locks"]):
                    m["locks"].append(lk)
    for (e_eco, pkg), m in merged.items():
        m["target"] = over.get(pkg) or rp.highest(e_eco, m.pop("_targets")) or eff[pkg].get("target")
        m.pop("_targets", None)
        if eff[pkg].get("removal"):
            m["removal"] = True
    for e in rec.get("effective_edits") or rec.get("edits") or []:
        src = planner_edits.get((e["file"], e["line"]))
        if src is None:
            raise Refused(f"effective edit {e['file']}:{e['line']} matches no stored planner row edit")
        row = merged.get((eco, src["package"])) or next((m for k, m in merged.items() if k[1] == src["package"]), None)
        if row is None:
            continue
        row["edits"].append({**{k: v for k, v in src.items() if k != "package"}, "repo": target,
                             **{k: e[k] for k in ("action", "from", "to", "needs_human") if k in e}})
    rows = [merged[k] for k in sorted(merged)]
    cls = str(rec.get("remediation_class") or 2)
    scope = [{"repo": subject, "path": roots[subject], "commit": None}] if subject in roots else []
    if target != subject:
        scope.append({"repo": target, "path": roots[target], "commit": None})
    for s in scope:
        s["commit"] = rp._git_head(s["path"])
    group = {"class": cls, "resolve": {"repo": rec["resolve_repository"], "file": rec["resolve_file"],
                                       "lock_format": rec.get("lock_format")},
             "dev_only": bool(rec.get("dev_only")), "packages": [
                 {k: r.get(k) for k in ("package", "ecosystem", "installed", "target", "flaws", "no_fix",
                                        "alert_ids", "removal", "blocked_on") if r.get(k) not in (None, False, [])}
                 for r in rows], "edits": [e for r in rows for e in r["edits"]], "commands": [],
             "evidence": list(rec.get("evidence") or [])}
    plan = {"engine": rec.get("engine_version"), "repo": subject, "scope": scope, "groups": [group], "rows": rows}
    work = {"index": 0, "class": cls, "dev_only": bool(rec.get("dev_only")), "rows": rows}
    return plan, work, {target: set(rec.get("allowed_files") or [])}


def _write(path: str, data: Any) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def propose_refresh(rec: Dict[str, Any], plan: Dict[str, Any], report: Dict[str, Any], subject: str,
                    work_dir: str) -> int:
    """`--probe`: send this probe as a refresh of the plan. The findings are the plan's members of THIS subject
    (the only ones a CI token sees); the server keeps the other subjects' members."""
    findings = [{"ecosystem": rec["ecosystem"], "package": m["package"], "installed": m.get("installed_version")
                 or m.get("installed"), "fixed": m.get("fixed_version") or m.get("fixed"), "alert_id": m["alert_id"]}
                for m in rec.get("members") or [] if isinstance(m, dict)
                and m.get("subject_repository") in (None, subject)]
    paths = {k: _write(os.path.join(work_dir, f"refresh-{k}.json"), v)
             for k, v in (("plan", plan), ("findings", findings), ("probe", {"groups": [report]}))}
    args = ["remediation-plans", "propose", "--plan", paths["plan"], "--findings", paths["findings"],
            "--probe", paths["probe"], "--refresh-plan-id", rec["id"], "--repo-key", subject, "--format", "json"]
    for s in plan["scope"]:
        args += ["--with-key", f"{s['repo']}={s['repo']}"]
    rc, out, err = torana(args)
    log(f"propose --refresh-plan-id {rec['id']}: rc {rc} {err.strip()[-400:]}")
    return rc


def _ready_to_open(rec: Dict[str, Any], report: Dict[str, Any]) -> Optional[str]:
    """None when the probe may become the PR, else why not. needs_human is allowed only for acknowledged
    downgrades; an override target must still admit every visible member's fix (`policy.admits`)."""
    st = report.get("status")
    if st == "needs_human" and not (report.get("downgrades") and "downgrade" in (rec.get("needs_ack") or [])):
        return f"needs_human: {report.get('why')}"
    if st not in ("gates_passed", "needs_human"):
        return f"{st}: {report.get('why') or 'the gates did not pass'}"
    over = rec.get("override_packages") or []
    over = {o["package"]: o.get("target") for o in over} if isinstance(over, list) else dict(over)
    for m in rec.get("members") or []:
        if isinstance(m, dict) and m.get("package") in over and m.get("fixed_version"):
            if policy.admits(rec["ecosystem"], ">=" + m["fixed_version"], over[m["package"]]) is not True:
                return (f"override target {m['package']} {over[m['package']]} is below member {m['alert_id']}'s "
                        f"fix {m['fixed_version']}")
    return None


def run_plan_id(a: argparse.Namespace) -> int:
    rc, rec, err = torana(["remediation-plan", a.plan_id, "get", "--format", "json"])
    if rc != 0 or not isinstance(rec, dict):
        log(f"ERROR: cannot read plan {a.plan_id}: {err.strip()}")
        return rc or 1
    roots = local_roots(a.repo, a.repo_key, a.with_roots)
    subject = a.repo_key or (repo_key_of(a.repo) if a.repo else None) or ""
    if not subject:
        log("ERROR: scope_missing: --plan-id needs --repo (this runner's own checkout) and its key")
        return EXIT_SCOPE_MISSING
    work_dir = os.path.abspath(a.work)
    os.makedirs(work_dir, exist_ok=True)
    try:
        plan, work, allowed = plan_input(rec, roots, subject)
    except KeyError as exc:
        log(f"ERROR: scope_missing: no local root for {exc.args[0]}: pass --with ROOT={exc.args[0]}")
        return EXIT_SCOPE_MISSING
    except Refused as exc:
        log(f"ERROR: {exc}")
        return 1

    def apply_once() -> Dict[str, Any]:
        r = run_group(plan, work, True, work_dir, allowed_files=allowed)
        _write(os.path.join(work_dir, "probe-report.json"), {"groups": [r]})
        return r

    if a.probe:
        report = apply_once()
        print(json.dumps({"plan_id": rec["id"], "mode": "probe", "report": report}, indent=2) if a.as_json
              else f"probe of {rec['id']}: {report['status']}")
        return propose_refresh(rec, plan, report, subject, work_dir)

    if rec.get("state") not in GO_STATES or rec.get("pr_state", "none") not in ("none", "opening_stale"):
        log(f"skip {rec['id']}: state {rec.get('state')}, pr_state {rec.get('pr_state')}")
        return 0
    not_ready = github_not_ready(rec["id"], roots.get(rec["target_repository"]))
    if not_ready:
        for c in not_ready["checks"]:
            log(f"NOT READY: {c['words']} — fixes it: {c['who_fixes']}")
            if c.get("admin_detail"):
                log(f"    For your Torana administrator: {c['admin_detail']}")
        result = {"plan_id": rec["id"], "mode": "open-pr", "status": "not_ready", **not_ready}
        print(json.dumps(result, indent=2) if a.as_json else f"{rec['id']}: not_ready {not_ready['why']}")
        return EXIT_NOT_READY
    holder =a.holder_run or f"local:{socket.gethostname()}:{os.getpid()}"
    rc, lease, err = torana(["remediation-plans", "lease", "acquire", "--plan-id", rec["id"], "--holder-run", holder,
                             "--format", "json"])
    if rc == 4:
        log(f"skip {rec['id']}: {err.strip()}")
        return 0
    if rc != 0 or not isinstance(lease, dict):
        log(f"ERROR: lease: {err.strip()}")
        return rc or 1
    lease_id = lease.get("id") or lease.get("lease_id")
    target = rec["target_repository"]
    result: Dict[str, Any] = {"plan_id": rec["id"], "mode": "open-pr"}
    try:
        for attempt in (1, 2):
            report = apply_once()
            why = _ready_to_open(rec, report)
            if why:
                result.update(status="not_opened", why=why, report=report)
                break
            head = rp._git_head(roots[target]) or ""
            rc, out, err = torana(["remediation-plan", rec["id"], "open-pr", "--diff", report["diff"],
                                   "--root", os.path.join(work_dir, "group-0", target),
                                   "--probe", os.path.join(work_dir, "probe-report.json"), "--base-sha", head,
                                   "--base-branch", a.base_branch, "--format", "json"])
            code = error_code(err)
            if rc == 0:
                result.update(status="opened", pr=out)
            elif code in ("plan_stale", "content_outside_lane"):
                result.update(status="re-probed", why=code, propose_rc=propose_refresh(rec, plan, report, subject,
                                                                                      work_dir))
            elif code == "base_moved" and attempt == 1:
                log("base_moved: re-running once on the current HEAD")
                continue
            elif code == "pr_pending":
                result.update(status="pr_pending", why="the platform is still opening it; the next run records it")
            else:
                result.update(status="error", rc=rc, why=err.strip()[-800:])
            break
    finally:
        if lease_id:
            torana(["remediation-plans", "lease", "release", lease_id, "--holder-run", holder])
    print(json.dumps(result, indent=2) if a.as_json else f"{rec['id']}: {result['status']} {result.get('why', '')}")
    return 0 if result["status"] in ("opened", "re-probed", "pr_pending", "not_opened") else 1


# ── the laptop lane: --plan-id ID --commit [--push-pr] (WP1) ────────────────────────────

_ZERO = "0" * 40
_PR_URL = re.compile(r"https://\S+/pull/(\d+)")


def git(top: str, *args: str, env: Optional[Dict[str, str]] = None, stdin: Optional[str] = None
        ) -> Tuple[int, str, str]:
    """(rc, stdout stripped, stderr stripped). Never raises on a missing git: rc 127."""
    try:
        p = subprocess.run(["git", "-C", top, *args], capture_output=True, text=True, env=env, input=stdin)
    except FileNotFoundError:
        return 127, "", "git is not installed"
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def gh(args: List[str], cwd: str) -> Tuple[int, str, str]:
    """The developer's own `gh`. rc 127 when it is not installed."""
    try:
        p = subprocess.run(["gh", *args], cwd=cwd, capture_output=True, text=True)
    except FileNotFoundError:
        return 127, "", "gh is not installed"
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def build_commit(top: str, base_sha: str, copy_root: str, changed: List[str], message: str,
                 index_file: str) -> str:
    """A commit of exactly `changed` (paths relative to the repository root) as they are in `copy_root`, on
    `base_sha`, WITHOUT touching the developer's working tree, index or current branch: a temporary index,
    `hash-object -w`, `write-tree`, `commit-tree`. ⛔ Bytes as gated: `--no-filters`, so no clean filter or
    line-ending conversion rewrites what gate 3 judged. Raises Refused with git's own words."""
    env = {**os.environ, "GIT_INDEX_FILE": index_file}
    if os.path.exists(index_file):
        os.remove(index_file)
    steps: List[Tuple[str, ...]] = [("read-tree", base_sha)]
    for rel in changed:
        full = os.path.join(copy_root, rel)
        if os.path.islink(full):
            rc, blob, err = git(top, "hash-object", "-w", "--stdin", env=env, stdin=os.readlink(full))
            mode = "120000"
        elif os.path.isfile(full):
            rc, blob, err = git(top, "hash-object", "-w", "--no-filters", "--", full, env=env)
            mode = "100755" if os.access(full, os.X_OK) else "100644"
        else:
            steps.append(("update-index", "--force-remove", "--", rel))
            continue
        if rc != 0:
            raise Refused(f"git hash-object {rel}: {err}")
        steps.append(("update-index", "--add", "--cacheinfo", f"{mode},{blob},{rel}"))
    for st in steps:
        rc, _, err = git(top, *st, env=env)
        if rc != 0:
            raise Refused(f"git {st[0]}: {err}")
    rc, tree, err = git(top, "write-tree", env=env)
    if rc != 0:
        raise Refused(f"git write-tree: {err}")
    rc, sha, err = git(top, "commit-tree", tree, "-p", base_sha, "-F", "-", env=env, stdin=message)
    if rc != 0:
        raise Refused(f"git commit-tree: {err} (is `git config user.name` / `user.email` set?)")
    return sha


def _same_change(top: str, a: str, b: str) -> bool:
    """Two commits carry the same change: the same tree on the same parent."""
    trees = [git(top, "rev-parse", f"{c}^{{tree}}")[1] for c in (a, b)]
    parents = [git(top, "rev-parse", f"{c}^")[1] for c in (a, b)]
    return trees[0] == trees[1] and parents[0] == parents[1]


def _remote_head(top: str, branch: str) -> Optional[str]:
    rc, out, _ = git(top, "ls-remote", "--heads", "origin", f"refs/heads/{branch}")
    return out.split()[0] if rc == 0 and out else None


def _say(result: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2))
        return
    print(f"{result['plan_id']}: {result['status']}" + (f" — {result['why']}" if result.get("why") else ""))
    if result.get("pr"):
        print(f"  PR: {result['pr'].get('url')}")
    if result.get("next"):
        print(f"  next: {result['next']}")


def run_commit(a: argparse.Namespace) -> int:
    """The laptop lane. A developer with the TARGET repository checked out turns an APPROVED plan into a commit on
    `torana/alert-<id>` and, with --push-pr, into a PR opened and recorded under their own credentials.

    ⛔ THE WORKING TREE IS NEVER TOUCHED. The scratch copy is built from `origin/<base>` (fetched), gated there, and
    the gated bytes are committed onto `origin/<base>` with a temporary index: no checkout, no switch, no stash. The
    developer may be mid-work on any branch. ⛔ Never `--force`, never deletes a remote branch: an existing branch with
    different content is a refusal, with what to do. ⛔ Reserve BEFORE pushing (`reserve-pr`): the platform can refuse
    to RECORD a second PR on the same files, but only the reservation stops it from being opened.

    Exit: 0 committed / already_committed / recorded · 4 busy (lease, reservation) · 2 refused before any write ·
    1 not_ready (gates) / error. `why` and `next` are written for the developer."""
    work_dir = os.path.abspath(a.work)
    os.makedirs(work_dir, exist_ok=True)
    result: Dict[str, Any] = {"plan_id": a.plan_id, "mode": "commit", "status": None, "branch": None, "commit": None,
                              "base_sha": None, "draft": False, "pushed": False, "pr": None, "claim_id": None,
                              "why": None, "next": None}

    def done(status: str, code: int, why: Optional[str] = None, nxt: Optional[str] = None, **kw: Any) -> int:
        result.update(status=status, why=why, next=nxt, **kw)
        _say(result, a.as_json)
        return code

    rc, rec, err = torana(["remediation-plan", a.plan_id, "get", "--format", "json"])
    if rc != 0 or not isinstance(rec, dict):
        return done("error", rc or 1, f"cannot read plan {a.plan_id}: {err.strip()[-400:]}",
                    "check `torana auth me` and the plan id")
    target, base = rec["target_repository"], a.base_branch
    if rec.get("state") not in GO_STATES:
        return done("refused", 2, f"the plan is {rec.get('state')}; only an approved plan becomes a PR",
                    "a tenant admin approves it in Torana (or the system does, when plan approval is off)")
    if rec.get("pr_state", "none") not in ("none", "opening_stale"):
        return done("refused", 2, f"the plan already has a PR ({rec.get('pr_state')}) {rec.get('pr_url') or ''}".strip(),
                    "nothing to do: review that PR")
    top = _toplevel(a.repo)
    key = a.repo_key or repo_key_of(a.repo) or ""
    if key != target:
        return done("refused", 2, f"--repo is {key or 'a checkout with no recognisable origin'}, but this plan edits "
                    f"{target}", "pass the TARGET repository's checkout as --repo (and --repo-key if its origin "
                    "remote is not the forge URL)")
    branch = f"torana/alert-{rec['primary_alert_id']}"
    result["branch"] = branch
    # I-33: no ad-hoc `gh auth status` here. The readiness pre-flight below asks it (`gh_cli`), in the one
    # vocabulary with who fixes it; a second check in other words answered first and named no fixer.
    rc, _, err = git(top, "fetch", "--quiet", "origin", base)
    if rc != 0:
        return done("refused", 2, f"cannot fetch origin/{base}: {err[-300:]}",
                    "check the network and your access to origin, or pass --base-branch <the default branch>")
    rc, base_sha, err = git(top, "rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{base}^{{commit}}")
    if rc != 0 or not base_sha:
        return done("refused", 2, f"origin/{base} does not exist", "pass --base-branch <the default branch>")
    result["base_sha"] = base_sha
    # B22 / I-32: before the lease, the commit and any push, and for --commit ALONE too. A commit made while GitHub is
    # not ready is a branch the developer can never push through this lane: "fail midway", one step later.
    not_ready = github_not_ready(rec["id"], top)
    if not_ready:
        for c in not_ready["checks"]:
            log(f"NOT READY: {c['words']} — fixes it: {c['who_fixes']}")
            if c.get("admin_detail"):
                log(f"    For your Torana administrator: {c['admin_detail']}")
        return done("github_not_ready", EXIT_NOT_READY, not_ready["why"],
                    "each check above names who fixes it; rerun when they are done. Nothing was committed",
                    checks=not_ready["checks"])
    log("GitHub ready ✓")

    holder = a.holder_run or f"local:{socket.gethostname()}:{os.getpid()}"
    rc, lease, err = torana(["remediation-plans", "lease", "acquire", "--plan-id", rec["id"], "--holder-run", holder,
                             "--format", "json"])
    if rc == 4:
        return done("busy", 4, f"another run holds this repository's lease: {err.strip()[-300:]}", "rerun later")
    if rc != 0 or not isinstance(lease, dict):
        return done("error", rc or 1, f"lease: {err.strip()[-300:]}", "check `torana auth me` and your permissions")
    lease_id = lease.get("id") or lease.get("lease_id")
    probe_path = os.path.join(work_dir, "probe-report.json")
    try:
        try:
            plan, work, allowed = plan_input(rec, {target: top}, target)
        except Refused as exc:
            return done("error", 1, str(exc))
        for s in plan["scope"]:
            if s["repo"] == target:              # ⛔ gate the bytes we commit on: origin/<base>, not the checkout
                s.update(ref=f"origin/{base}", commit=base_sha)
        report = run_group(plan, work, True, work_dir, allowed_files=allowed)
        _write(probe_path, {"groups": [report]})
        why = _ready_to_open(rec, report)
        if why:
            return done("not_ready", 1, why, "the gates did not pass on origin/" + base + "; nothing was committed. "
                        "See the report in " + probe_path, report_status=report.get("status"))
        rc, text, err = torana(["remediation-plan", rec["id"], "pr-text", "--probe", probe_path, "--format", "json"])
        if rc != 0 or not isinstance(text, dict):
            return done("error", rc or 1, f"pr-text: {err.strip()[-300:]}")
        changed = (report.get("gate_3_lane") or {}).get("changed", {}).get(target) or []
        if not changed:
            return done("not_ready", 1, f"the fix changes nothing on origin/{base}", "nothing to commit")
        commit = build_commit(top, base_sha, os.path.join(work_dir, f"group-{work['index']}", target), changed,
                              text["commit_message"], os.path.join(work_dir, "laptop.index"))
    except Refused as exc:
        return done("error", 1, str(exc))
    finally:
        if lease_id:
            torana(["remediation-plans", "lease", "release", lease_id, "--holder-run", holder])
    result.update(draft=bool(text.get("draft")), draft_reasons=text.get("draft_reasons") or [])

    status = "committed"
    rc, local, _ = git(top, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}")
    remote = _remote_head(top, branch)
    if remote:                                   # its objects, so the comparison below can read its tree
        git(top, "fetch", "--quiet", "origin", f"refs/heads/{branch}")
    for where, sha in (("locally", local if rc == 0 else None), ("on origin", remote)):
        if sha and not _same_change(top, sha, commit):
            return done("refused", 2, f"{branch} already exists {where} with different content",
                        f"look at it (`git log -p origin/{base}..{sha}`); if it is stale, delete it yourself, then "
                        "rerun. This tool never deletes or force-pushes a branch")
    if rc == 0 and local:
        commit, status = local, "already_committed"
    elif remote:
        commit, status = remote, "already_committed"
    rc_ref, _, err = (0, "", "") if status == "already_committed" and rc == 0 else \
        git(top, "update-ref", f"refs/heads/{branch}", commit, _ZERO)
    if rc_ref != 0:
        return done("error", 1, f"cannot create {branch}: {err}")
    result["commit"] = commit
    log(f"{'already committed' if status == 'already_committed' else 'committed'} {branch} @{commit[:12]}")
    look = f"`git switch {branch}` to look at it"
    if not a.push_pr:
        return done(status, 0, None, f"{look}; rerun with --push-pr to push it and open the PR")

    # ── --push-pr: reserve → push → gh pr create → record ──
    rc, res, err = torana(["remediation-plan", rec["id"], "reserve-pr", "--probe", probe_path, "--base-sha", base_sha,
                           "--base-branch", base, "--format", "json"])
    if rc == 4:
        return done("busy", 4, f"the PR slot is taken: {err.strip()[-400:]}",
                    f"wait for that PR to merge or close, then rerun; your commit stays on {branch}")
    if rc != 0 or not isinstance(res, dict):
        return done("error", rc or 1, f"reserve-pr: {err.strip()[-400:]}",
                    "if it says plan_stale, origin moved: rerun (the plan is re-checked on the new base)")
    claim = res["claim_id"]
    result["claim_id"] = claim
    log(f"PR slot reserved (claim {claim})")

    def release(reason: str) -> None:
        torana(["remediation-plan", rec["id"], "release-pr", "--claim-id", claim, "--reason", reason[:500]])

    if remote != commit:
        rc, _, err = git(top, "push", "-u", "origin", f"refs/heads/{branch}:refs/heads/{branch}")
        if rc != 0:
            release(f"git push: {err[-300:]}")
            return done("error", 1, f"git push failed: {err[-400:]}",
                        f"check that you can push to origin; your commit stays on {branch} and no PR was opened")
    result["pushed"] = True
    log(f"pushed {branch} @{commit[:12]}" if remote != commit else f"{branch} @{commit[:12]} was already on origin")
    body_path = _write_text(os.path.join(work_dir, "pr-body.md"), text["body"])
    cmd = ["pr", "create", "--base", base, "--head", branch, "--title", text["title"], "--body-file", body_path]
    if text.get("draft"):
        cmd.append("--draft")
    rc, out, err = gh(cmd, top)
    m = _PR_URL.search(out or "") or _PR_URL.search(err or "")
    if rc != 0 and not m:
        rc2, view, _ = gh(["pr", "view", branch, "--json", "number,url"], top)
        try:
            pr = json.loads(view) if rc2 == 0 else None
        except ValueError:
            pr = None
        if not pr:
            release(f"gh pr create: {err[-300:]}")
            return done("error", 1, f"gh pr create failed: {err[-400:]}",
                        f"{branch} is pushed; open the PR yourself (`gh {shlex.join(cmd)}`), then run "
                        f"`torana remediation-plan {rec['id']} record-pr --probe {probe_path} --base-sha {base_sha} "
                        f"--pr-number <N>`")
        number, url = int(pr["number"]), pr["url"]
    else:
        number, url = int(m.group(1)), m.group(0)
    result["pr"] = {"number": number, "url": url}
    log(f"PR #{number} opened: {url}")
    rc, rec2, err = torana(["remediation-plan", rec["id"], "record-pr", "--probe", probe_path, "--base-sha", base_sha,
                            "--base-branch", base, "--pr-number", str(number), "--claim-id", claim, "--format", "json"])
    if rc != 0:
        return done("error", 1, f"the PR is open but the platform did not record it: {err.strip()[-400:]}",
                    f"read the reason on the plan (`torana remediation-plan {rec['id']} get`); fix the branch and rerun "
                    f"`torana remediation-plan {rec['id']} record-pr --probe {probe_path} --base-sha {base_sha} "
                    f"--pr-number {number}`")
    log(f"recorded PR #{number} on plan {rec['id']}")
    return done("recorded", 0, None, f"review the PR: {url}")


def _write_text(path: str, text: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ── the run ─────────────────────────────────────────────────────────────────────────

def main() -> int:
    global RESOLVER_TIMEOUT_S
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", default="-", help="remediation_plan.py --json output (default: stdin)")
    ap.add_argument("--group", type=int, action="append", default=[], help="group index in the plan (repeatable)")
    ap.add_argument("--package", action="append", default=[], help="narrow the groups to these packages")
    ap.add_argument("--apply", action="store_true", help="edit scratch copies and run the resolver and gates")
    ap.add_argument("--work", default=None, help="where the scratch copies go (required with --apply)")
    ap.add_argument("--json", dest="as_json", action="store_true", help="only JSON on stdout")
    ap.add_argument("--plan-id", default=None, help="a server plan (torana remediation-plans) instead of --plan")
    ap.add_argument("--repo", default=None, help="with --plan-id: this runner's own checkout (the subject)")
    ap.add_argument("--repo-key", default=None, help="with --plan-id: --repo's key (default: its origin remote)")
    ap.add_argument("--with", dest="with_roots", action="append", default=[], metavar="ROOT[=KEY]",
                    help="with --plan-id: another checkout, e.g. the target repository (repeatable)")
    ap.add_argument("--probe", action="store_true", help="with --plan-id --apply: re-prove it and refresh the plan")
    ap.add_argument("--open-pr", dest="open_pr", action="store_true",
                    help="with --plan-id --apply: send an approved plan's files to the platform, under a lease")
    ap.add_argument("--commit", dest="commit", action="store_true",
                    help="with --plan-id --apply: the laptop lane. --repo is the TARGET checkout; gate on origin/<base> "
                         "and commit on a new branch torana/alert-<id>, never touching the working tree")
    ap.add_argument("--push-pr", dest="push_pr", action="store_true",
                    help="with --commit: reserve the PR slot, `git push` with YOUR credentials, `gh pr create`, "
                         "then record the PR")
    ap.add_argument("--holder-run", default=None, help="with --open-pr: this run's id (default local:<host>:<pid>)")
    ap.add_argument("--base-branch", default="main",
                    help="with --open-pr: the PR's base branch, i.e. the target's default branch (main if omitted)")
    ap.add_argument("--resolver-timeout", type=int, default=RESOLVER_TIMEOUT_S, metavar="SECONDS",
                    help=f"wall-clock cap on one resolver run (default {RESOLVER_TIMEOUT_S}); past it the run is "
                         f"killed and the group declined `resolver_timeout`")
    a = ap.parse_args()
    if a.resolver_timeout <= 0:
        log("ERROR: --resolver-timeout must be a positive number of seconds")
        return 2
    RESOLVER_TIMEOUT_S = a.resolver_timeout
    if a.push_pr and not a.commit:
        log("ERROR: --push-pr needs --commit")
        return 2
    if a.plan_id:
        if not (a.apply and a.work) or sum((a.probe, a.open_pr, a.commit)) != 1:
            log("ERROR: --plan-id needs --apply --work DIR and exactly one of --probe / --open-pr / --commit")
            return 2
        if a.commit:
            if not a.repo:
                log("ERROR: --commit needs --repo <the TARGET repository's checkout>")
                return 2
            return run_commit(a)
        return run_plan_id(a)
    try:
        plan = json.load(sys.stdin if a.plan == "-" else open(a.plan, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log(f"ERROR: cannot read the plan: {exc}")
        return 2
    if a.apply and not a.work:
        log("ERROR: --apply needs --work DIR. ⛔ The plan's own trees are never edited.")
        return 2
    works = select(plan, a.group, a.package)
    if not works:
        log("nothing to apply: no class-2 or class-3 group matches")
    reports = [run_group(plan, w, a.apply, os.path.abspath(a.work) if a.work else None) for w in works]
    out = {"repo": plan.get("repo"), "applied": a.apply, "groups": reports}
    if a.as_json:
        print(json.dumps(out, indent=2))
    else:
        for r in reports:
            pk = ", ".join(f"{p['package']} {p['installed']}→{p.get('target') or 'removed'}"
                           + (f" (PARTIAL: {p['requested_target']} does not resolve; {len(p['open_alert_ids'])} "
                              f"flaw(s) stay open)" if p.get("partial") else "") for p in r["packages"])
            print(f"[class {r['class']}{' dev' if r['dev_only'] else ''}] group {r['group']}: {r['status']}  {pk}")
            for d in r.get("downgrades") or []:
                print(f"    ⚠ DOWNGRADE {d['package']} {d['from']} → {d['to']}  ({d['lock']})")
            for e in r["edits"]:
                print(f"    edit {e['repo']}/{e['file']}:{e['line']} {e['action']} `{e.get('from')}`"
                      f"{' → `' + str(e.get('to')) + '`' if e['action'] == 'bump' else ''}")
            for lk in r["locks"]:
                print(f"    lock {lk['repo']}/{lk['file']} ({lk['lock_format']})")
            if r.get("why"):
                print(f"    why: {r['why']}")
            for x in r.get("split_out") or []:
                last = (x.get("resolver_output") or "").strip().splitlines()[-3:]
                print(f"    split out (class 5): {x['package']}→{x['target']}: {x['why']}"
                      + "".join(f"\n        | {ln.strip()}" for ln in last))
            for g in r.get("gate_1_resolve") or []:
                print(f"    gate 1 {g['lock']}: {'ok' if g['ok'] else g.get('declined') or 'FAIL'} "
                      f"{ {k: v['from'] + '→' + str(v['to']) for k, v in (g.get('landed') or {}).items() if v['from']} }")
            for g in r.get("gate_2_blast_radius") or []:
                print(f"    gate 2 {g['lock']}: {len(g['moved'])} other package(s) moved"
                      + "".join(f"\n        {m['package']} {m['from']}→{m['to']}"
                                f"{'  ⚠ DOWNGRADE' if m.get('downgrade') else ''}" for m in g["moved"]))
            for d in r.get("api_diff") or []:
                print(f"    api diff: removed={d['removed']} renamed={d['renamed']} "
                      f"signature_changed={d['signature_changed']} complete={d['complete']}")
                for h in d.get("touched") or []:
                    print(f"        uses {h['symbol']}  ({h['change']})  {h['file']}:{h['line']}"
                          + ("" if h.get("by") in ("import_name", "attribute")
                             else "   [name in the file, not in the import]"))
            for e in r.get("blocked_edits") or []:
                print(f"    NOT edited {e['repo']}/{e['file']}:{e['line']} `{e.get('from')}` → `{e.get('to')}`")
            if r.get("gates_not_applicable"):
                na = r["gates_not_applicable"]
                print(f"    {', '.join(na['gates'])}: not applicable — {na['why']}")
            if r.get("gate_3_lane"):
                g = r["gate_3_lane"]
                print(f"    gate 3: {'ok' if g['ok'] else 'FAIL ' + ', '.join(g['outside_lane'])}  changed "
                      f"{g['changed']}")
                if r.get("diff"):
                    print(f"    diff: {r['diff']}")
            if r.get("gate_4_build"):
                print(f"    gates 4 and 5 (build, tests): {r['gate_4_build']['status']}")
    return 1 if any(r.get("status", "").startswith(("failed", "refused")) for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
