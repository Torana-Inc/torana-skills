#!/usr/bin/env python3
"""Apply a fix-PR plan to a scratch copy, run the resolver, and run gates 1-3. No model.

    remediation_plan.py --json  →  this script  →  per group: the edits, the resolver's lock, the gates' verdicts

REMEDIATION_BUILD.md § 2 (phase 2), FIX_PR_DESIGN.md § "What runs before the PR opens" and § "Idempotency".

⛔ DRY RUN UNLESS `--apply`. The dry run prints every edit and every resolver invocation it would make. `--apply` copies
each tree a group touches into `--work`, edits the COPY, runs the resolver there, and runs the gates. It never writes
to the trees the plan was made from.

⛔ NO GITHUB WRITE CREDENTIAL, EVER. This script never pushes, never runs `gh`, and holds no GitHub token. The
PLATFORM opens the PR (FIX_PR_SPEC.md § 3.4.3): `--plan-id ID --open-pr` sends the applied files through
`torana remediation-plan ID open-pr`, and the platform checks the plan, the paths and the content before its GitHub
App writes anything. An alert closes when its scanner stops reporting the finding, never by this job.

THREE MODES (FIX_PR_SPEC.md § 3.4.8):
  --plan FILE            a local planner output (as built): dry run, or `--apply --work DIR`
  --plan-id ID --probe   re-prove a server plan from its stored rows, then `remediation-plans propose
                         --refresh-plan-id ID` (when the platform says it needs a fresh check)
  --plan-id ID --open-pr apply an APPROVED plan under a lease and send the files to the platform

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
    """The class-2 / class-3 groups to apply, each narrowed to `packages` when given (a per-alert run)."""
    rows = {(r["ecosystem"], r["package"]): r for r in plan["rows"]}
    want = {p for p in packages}
    out = []
    for i, g in enumerate(plan["groups"]):
        if g["class"] not in ("2", "3") or (groups and i not in groups):
            continue
        members = [rows[(p["ecosystem"], p["package"])] for p in g["packages"]
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
    return [{"cmd": None, "rc": 2, "output": f"no resolver wired for {fmt} in phase 2 (uv and npm only)"}]


_NPM = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]


def _resolve_npm(cwd: str, rows: List[Dict[str, Any]], cls: str) -> List[Dict[str, Any]]:
    pj = os.path.join(cwd, "package.json")
    with open(pj, encoding="utf-8") as fh:
        original = fh.read()
    if cls == "3":
        return [_run(_NPM, cwd)]
    data = json.loads(original)
    direct = [r for r in rows if any(r["package"] in (data.get(s) or {}) for s in manifests.NPM_SECTIONS)]
    transitive = [r for r in rows if r not in direct]
    runs = []
    if transitive:
        data.setdefault("overrides", {})
        for r in transitive:
            data["overrides"][r["package"]] = r["target"]
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

def _resolved(root: str, lock_file: str) -> Dict[str, str]:
    return {r["package"]: r["version"] for r in manifests.read_manifests(root, files=[lock_file])
            if r["kind"] == "resolution" and r.get("version")}


#: Gates 4 (build) and 5 (tests) until phase 4 wires them: reported, never silently absent.
GATE_NOT_RUN = {"status": "not_run", "why": "gates 4 and 5 are not wired yet (REMEDIATION_BUILD.md § 2, phase 4)"}


def gate_resolve(before: Dict[str, str], after: Dict[str, str], rows: List[Dict[str, Any]],
                 runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    failed = [r for r in runs if r["rc"] != 0]
    if failed:
        return {"ok": False, "why": "the resolver refused (class 5)", "resolver_output": failed[-1]["output"]}
    landed, short = {}, []
    for r in rows:
        eco, pkg, now = r["ecosystem"], r["package"], after.get(r["package"])
        landed[pkg] = {"from": before.get(pkg), "to": now}
        if r.get("removal"):
            if now is not None:
                short.append(f"{pkg} is still resolved at {now} after its removal")
        elif now is None or policy.admits(eco, f">={r['target']}", now) is not True:
            short.append(f"{pkg} resolved at {now}, below the target {r['target']}")
    return {"ok": not short, "landed": landed, **({"why": "; ".join(short)} if short else {})}


def gate_blast_radius(before: Dict[str, str], after: Dict[str, str], rows: List[Dict[str, Any]],
                      eco: str = "pypi") -> Dict[str, Any]:
    """Every OTHER package whose version moved. Never a failure, but ⛔ a package moving BACKWARDS never passes
    silently (lead's rule, 2026-10-19; measured: litellm 1.88.6 drags openai 3.16.2 → 2.54.0). It is flagged, and
    the group becomes needs_human: a human may accept it, nobody may miss it."""
    asked = {r["package"] for r in rows}
    moved = []
    for p in sorted(set(before) | set(after)):
        a, b = before.get(p), after.get(p)
        if p in asked or a == b:
            continue
        down = bool(a and b and policy.admits(eco, f"<{a}", b) is True)
        moved.append({"package": p, "from": a, "to": b, **({"downgrade": True} if down else {})})
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
    outside it passes, not even an overrides-only package.json: the platform would refuse that file anyway."""
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


def blocked_by_locks(plan: Dict[str, Any], row: Dict[str, Any], cache: Optional[Dict[str, Any]] = None
                     ) -> List[Dict[str, Any]]:
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
        if s["path"] not in cache:
            cache[s["path"]] = manifests.read_manifests(s["path"])
        recs = cache[s["path"]]
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


def run_group(plan: Dict[str, Any], work: Dict[str, Any], apply: bool, work_dir: Optional[str],
              probe: bool = True, allowed_files: Optional[Dict[str, set]] = None) -> Dict[str, Any]:
    """`allowed_files` (a server plan, `--plan-id`) replaces gate 3's derivation: the plan's own allowed set."""
    scope = {s["repo"]: s["path"] for s in plan["scope"]}
    rows, cls, edits, locks = work["rows"], work["class"], _edits(work), _locks(work)
    cache: Dict[str, Any] = {}
    report: Dict[str, Any] = {
        "group": work["index"], "class": cls, "dev_only": work["dev_only"],
        "packages": [{"package": r["package"], "installed": r["installed"], "target": r.get("target"),
                      **({"removal": True} if r.get("removal") else {}),
                      **({k: r[k] for k in ("partial", "requested_target", "open_alert_ids", "refusal_output")
                          if k in r} if r.get("partial") else {}),
                      **({"blocked_by_locks": b} if (b := blocked_by_locks(plan, r, cache)) else {})}
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
    holder = a.holder_run or f"local:{socket.gethostname()}:{os.getpid()}"
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
    if a.plan_id:
        if not (a.apply and a.work) or a.probe == a.open_pr:
            log("ERROR: --plan-id needs --apply --work DIR and exactly one of --probe / --open-pr")
            return 2
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
            if r.get("gate_3_lane"):
                g = r["gate_3_lane"]
                print(f"    gate 3: {'ok' if g['ok'] else 'FAIL ' + ', '.join(g['outside_lane'])}  changed "
                      f"{g['changed']}")
                print(f"    diff: {r['diff']}")
            if r.get("gate_4_build"):
                print(f"    gates 4 and 5 (build, tests): {r['gate_4_build']['status']}")
    return 1 if any(r.get("status", "").startswith(("failed", "refused")) for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
