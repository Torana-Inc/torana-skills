#!/usr/bin/env python3
"""Apply a fix-PR plan to a scratch copy, run the resolver, and run gates 1-5. No model.

    remediation_plan.py --json  →  this script  →  per group: the edits, the resolver's lock, the gates' verdicts

REMEDIATION_BUILD.md § 2 (phase 2), FIX_PR_DESIGN.md § "What runs before the PR opens" and § "Idempotency".

⛔ DRY RUN UNLESS `--apply`. The dry run prints every edit and every resolver invocation it would make. `--apply` copies
each tree a group touches into `--work`, edits the COPY, runs the resolver there, and runs the gates. It never writes
to the trees the plan was made from.

⛔ THIS SCRIPT HOLDS NO GITHUB TOKEN. Two ways a PR opens:
  * `--open-pr`: the PLATFORM opens it (FIX_PR_SPEC.md § 3.4.3). The applied files go through `torana
    remediation-plan ID open-pr`, and the platform checks plan, paths and content before its GitHub App writes.
  * `--commit --push-pr` (the laptop lane, WP1): the DEVELOPER's own `git push` and `gh pr create`, with the
    credentials already on their machine, after `reserve-pr`. ⛔ The platform verifies the PUSHED BRANCH
    (`verify-branch`) BEFORE the PR is opened, so a refusal leaves a branch and no PR (F27); then `record-pr`
    records it. The platform re-reads the
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
                         --push-pr: reserve-pr → git push → verify-branch → gh pr create [--draft] → record-pr.
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

THE GATES (FD § "What runs before the PR opens"):
  1 Resolve        the lock resolves each package at >= its target (removal: absent). Fail → class 5, with the
                   resolver's own output
  2 Blast radius   every OTHER package whose version moved in the lock. Never a failure: the PR names them
  3 Lane           the changed files are only the ones the class permits. Fail → the classification was wrong
  4 Build         the project's OWN install command, discovered by `test_ladder.py`, on the applied copy
  5 Tests         the project's OWN test command, likewise

⛔ GATES 4 AND 5 NEVER ABORT. Gates 1-3 decide whether a PR may open; 4 and 5 decide whether it opens as a DRAFT,
so a non-pass sets `draft` + `draft_why` and leaves `status` alone. Every step is reported — an omitted check reads
as a passed one — with five possible verdicts, and the difference between two of them is the point:
  passed · failed (it ran, the project is broken) · error (it could NOT run: no toolchain, or past
  `--gate-timeout` — the fix is UNJUDGED, not disproven) · not_detected · unsupported
⭐ THEY RUN WHERE THE TREE IS, the only place a toolchain exists: `--apply` runs on the customer's CI runner or a
developer's laptop, never in a service, so nothing is provisioned and there is no per-plane switch.

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
from typing import Any, Dict, List, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "lib"))
# ⭐ VENDORED PURE-PYTHON WHEELS are imported from the zip (`vendor/VENDORED.json`). ⛔ Never pip-install them.
for _whl in sorted(glob.glob(os.path.join(_HERE, "vendor", "*.whl"))):
    sys.path.insert(0, _whl)

import remediation_plan as rp  # noqa: E402
import codemod_run as _cmr                      # the § 3.6.1 block: statuses, state, words
# ⭐ THE LADDER IS DISCOVERY ONLY — it returns the project's OWN install and test commands and runs
# nothing. Gates 4 and 5 below are what run them, so the two halves stay separable and testable.
import test_ladder  # noqa: E402
import assumptions as _assumptions  # noqa: E402  ⭐ D-06 slice 1
import vet_case as _vet  # noqa: E402  ⭐ D-06 slice 1: the AI review
import review_case as _case  # noqa: E402  ⭐ EM D-23 S3: the case between the remediate Action's jobs
# ⭐ ONE repository-key normaliser in the scan pack: reachability_pass's (an https and an ssh remote → one key).
from reachability_pass import git_repo_key as repo_key_of  # noqa: E402
import tomlkit  # noqa: E402
from torana_reachability import locks, manifests, policy  # noqa: E402
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


#: ⛔ GATE 4/5 ENV SCRUB (phase-4 spec P2): the F6 deny list PLUS every variable whose NAME contains TOKEN,
#: SECRET or KEY, case-insensitively. Harder than the resolver's on purpose — a resolver runs a registry
#: client, while these two run the PROJECT'S OWN code (its test suite, its build backend, its conftest), so
#: the blast radius of a leaked credential is every line the repository chooses to execute.
#: ⚠️ A substring test, not a deny list: `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN` and `MY_APP_API_KEY` are not
#: enumerable in advance, which is the whole reason the spec specifies the rule rather than the names.
_GATE_SECRETISH = ("token", "secret", "key")


def gate_env() -> Dict[str, str]:
    return {k: v for k, v in resolver_env().items()
            if not any(w in k.lower() for w in _GATE_SECRETISH)}


def resolver_env() -> Dict[str, str]:
    """This process's environment without the credentials a resolver must never see."""
    return {k: v for k, v in os.environ.items() if k not in RESOLVER_ENV_DENY}


#: Wall-clock cap on ONE resolver invocation, in seconds (`--resolver-timeout`). Generous: a cold uv / npm cache on
#: a big lock takes minutes. ⛔ Without it a hung resolver (a registry that never answers) holds the run, and on
#: `--open-pr` the plan's lease, forever.
RESOLVER_TIMEOUT_S = 1800
RC_TIMED_OUT = 124                                      # timeout(1)'s exit code

#: Wall-clock caps on ONE gate-4/5 command, in seconds — phase-4 spec P2, "FIXED caps now, per-tenant settings
#: later: install ≤ 10 min, tests ≤ 20 min per gate". ⚠️ TWO caps, not one average: an install is a bounded
#: download-and-link and 10 minutes is generous, while a real suite legitimately takes longer, so a single figure
#: either kills good suites or lets a wedged install hold the plan's lease for twice as long as it should.
GATE_INSTALL_TIMEOUT_S = 600
GATE_TEST_TIMEOUT_S = 1200

#: Check each lock is current with its manifest before resolving a fix into it (`lock_stale`). `--lock-check off`.
LOCK_CHECK = True


def _text(b: Any) -> str:
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")


def _tail(out: str, budget: int) -> str:
    return out[-budget:] if budget > 0 else ""


#: Lines that NAME a failing test or error, per runner. ⛔ Runner-specific on purpose: a Karma run also prints
#: `ERROR:` / `WARN:` console lines and stack traces from PASSING specs that log (a large Angular app prints hundreds),
#: so a generic "error" match would fill the excerpt with noise. Karma's progress line (`Executed 9 of 10
#: (1 FAILED)`) is excluded; its TOTAL line is kept.
_FAIL_LINE = re.compile(
    r"^(?:.* FAILED$"                                   # karma: `<browser> <suite> <spec name> FAILED`
    r"|TOTAL: \d+ FAILED.*"                              # karma: the summary
    r"|\s*FAIL\s+\S+.*"                                  # jest: `FAIL src/a.test.js`
    r"|\s*● (?!Console).+"                               # jest: `● suite › test`
    r"|(?:FAILED|ERROR) \S+.*"                           # pytest: the short test summary
    r"|make(?:\[\d+\])?: \*\*\* .*Error \d+.*)$")         # make: which target failed
_EXCLUDE = re.compile(r"Executed \d+ of \d+")
#: A test-file frame under a Karma/Jasmine failure: the line that names WHICH spec file failed.
_SPEC_FRAME = re.compile(r"[\w./-]+\.(?:spec|test)\.[cm]?[jt]sx?:\d+")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def gate_output(out: str, budget: int) -> str:
    """What a gate stores for a reader: the lines NAMING what failed, then the tail, within `budget` chars.

    ⛔ DISPLAY ONLY. The verdict is the exit code (`_gate_step`); nothing here is read back to decide one.
    ⚠️ WHY: a test runner's last 2,000 chars are its progress lines. On a large Angular app (2026-10-29) the stored tail of a
    1,340-spec Karma run held 15 `Executed … (1 FAILED)` lines and not the spec's name, so a reviewer of the plan
    could not see which test failed. The excerpt takes at most half the budget; the tail keeps the rest, so the
    stored size is the same bound as before (DF stores `gates` as given, with no cap of its own)."""
    lines = _ANSI.sub("", out).replace("\r", "\n").splitlines()
    picked: List[str] = []
    for i, ln in enumerate(lines):
        if not _FAIL_LINE.match(ln) or _EXCLUDE.search(ln):
            continue
        picked.append(ln.strip())
        if ln.endswith(" FAILED"):
            # Karma: the assertion (first detail line) and the first frame in a spec file, within the next 12.
            nxt = lines[i + 1:i + 13]
            if nxt and nxt[0].strip():
                picked.append("  " + nxt[0].strip())
            frame = next((m.group(0) for x in nxt if (m := _SPEC_FRAME.search(x))), None)
            if frame:
                picked.append(f"  at {frame}")
    seen, uniq = set(), []
    for ln in picked:
        if ln not in seen:
            seen.add(ln)
            uniq.append(ln)
    if not uniq:
        return _tail(out, budget)
    head = "failures:\n" + "\n".join(uniq)
    head = head[:budget // 2]
    sep = "\n--- last output ---\n"
    return head + sep + _tail(out, budget - len(head) - len(sep))


def _spawn(cmd: List[str], cwd: str, timeout: int, env: Optional[Dict[str, str]] = None,
           shape=_tail) -> Dict[str, Any]:
    """Run one command under a wall-clock cap. ⛔ TWO CALLERS, TWO BOUNDARIES, deliberately separate:
    `_run` is the RESOLVER's, `_gate_cmd` is gates 4/5'. The suite fakes `_run` at 28 sites to control the
    resolver; if gate commands went through the same function, every one of those doubles would silently
    also fake the customer's test suite — and a test asserting "no resolver may run" would fail on a gate
    command instead. `shape(out, budget)` is what is STORED of the output (the resolver keeps the tail; a gate
    keeps `gate_output`)."""
    log(f"  $ (cd {cwd} && {shlex.join(cmd)})")
    try:
        # ⭐ ITS OWN PROCESS GROUP, so a timeout kills what the resolver spawned (npm's children, a build backend)
        # rather than only the direct child.
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env=resolver_env() if env is None else env, start_new_session=True)
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
                "output": (shape(out, _TOOL_TAIL - len(why) - 1) + "\n" + why).strip()}
    out = (_text(stdout) + _text(stderr)).strip()
    if out:
        log("    " + out[-_TOOL_TAIL:].replace("\n", "\n    "))
    return {"cmd": shlex.join(cmd), "rc": p.returncode, "output": shape(out, _TOOL_TAIL)}


def _run(cmd: List[str], cwd: str) -> Dict[str, Any]:
    """The RESOLVER boundary (`--resolver-timeout`). The suite fakes THIS."""
    return _spawn(cmd, cwd, RESOLVER_TIMEOUT_S)


#: Variables a gate ADDS for one ecosystem's steps. ⛔ `CI=true` for npm: many runners (jest, react-scripts, the
#: Angular CLI's prompts, npm itself) read it as "unattended — no watch, no prompt", and a gate on a developer's
#: laptop must behave as on a CI runner. Applied after the scrub and filtered by it, so it can never carry a secret.
GATE_ENV_EXTRA: Dict[str, Dict[str, str]] = {"npm": {"CI": "true"}}


def _gate_cmd(cmd: List[str], cwd: str, timeout: int, eco: str = "") -> Dict[str, Any]:
    """The GATE 4/5 boundary: the project's OWN install or test command, under its own cap and the harder
    `gate_env()` scrub, plus the ecosystem's `GATE_ENV_EXTRA`."""
    env = gate_env()
    env.update({k: v for k, v in GATE_ENV_EXTRA.get(eco, {}).items()
                if not any(w in k.lower() for w in _GATE_SECRETISH)})
    return _spawn(cmd, cwd, timeout, env=env, shape=gate_output)


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


_NPM = list(rp.NPM_LOCK_ONLY)


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


def npm_override_keys(tree: str, lk: Dict[str, Any], rows: List[Dict[str, Any]], cls: str
                      ) -> Dict[str, Dict[str, Any]]:
    """package → `{key, why}` (or `{key: None, needs_human}`) for each row `_resolve_npm` fixes with an UNSCOPED
    `overrides` entry, read from the UNMODIFIED tree. Nested rows keep their chain-scoped entry and are absent.

    ⛔ B54: an unscoped override rewrites every copy, so with brace-expansion at 1.1.15 and 5.0.6 the 1.x fix
    1.1.21 would drag the 5.x copies down (minimatch 5 then breaks). `rp.npm_override_key` decides the key."""
    if lk.get("lock_format") != "npm" or cls == "3":
        return {}
    lock = os.path.join(tree, lk["file"])
    try:
        with open(os.path.join(os.path.dirname(lock), "package.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        return {}
    packages = rp.npm_lock_packages(lock)
    out = {}
    for r in rows:
        if r.get("removal") or not r.get("target") or r.get("nested_copies"):
            continue
        if any(r["package"] in (manifest.get(s) or {}) for s in manifests.NPM_SECTIONS):
            continue                                                   # direct: a declaration, not an override
        out[r["package"]] = rp.npm_override_key("npm", r["package"], r.get("installed"), packages)
    return out


def forced_across_major(row: Dict[str, Any]) -> Optional[str]:
    """The needs_human reason when an npm override forces a version OUTSIDE a parent's declared range AND across a
    major line, else None.

    ⛔ F1's MECHANISM, NOT JUST ITS NUMBERS (B54 follow-up). A major forced past a parent's `^` range breaks a caller
    that lives in node_modules, where no API check looks (minimatch 3 under brace-expansion 5). Measured on a
    counter-case: @hono/node-server 1.19.14 has no fix on 1.x, so the line rule jumps to 2.1.3, outside
    @modelcontextprotocol/sdk `^1.19.9`. A forced move WITHIN the installed line (ws `~8.20.1` → 8.21.0) is stated
    in the evidence and not blocked here; a major jump every parent admits is not blocked either."""
    if row.get("ecosystem") != "npm" or row.get("override_forced") is not True or not row.get("target"):
        return None
    tl = row.get("target_line") or {}
    have, there = rp.version_line("npm", row.get("installed")), rp.version_line("npm", row["target"])
    if not (tl.get("major_jump") or (have and there and have != there)):
        return None
    parents = ((row.get("parents_admit") or {}).get("parents") or [])
    no = list(dict.fromkeys(f"{p.get('name')} `{p.get('declared')}`" for p in parents
                            if isinstance(p, dict) and p.get("admits") is False))
    return (f"{row['package']} {row.get('installed')} → {row['target']} crosses from the {rp.line_words(have)} line "
            f"to {rp.line_words(there)}"
            + (" (no fix on the installed line)" if tl.get("major_jump") else "")
            + f", and the npm override forces it outside {', '.join(no) or 'a parent range'}: a caller written for "
              f"{rp.line_words(have)} inside node_modules can break where no API check looks. A person must decide; "
              f"no PR is planned for it")


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
            # `override_key` (`npm_override_keys`): `pkg@^M` when the lock holds the package on several lines.
            data["overrides"][r.get("override_key") or r["package"]] = r["target"]
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
    return rp.resolved_versions(root, lock_file)


def _copies(resolved: Dict[Tuple[str, Tuple[str, ...]], str], pkg: str) -> Dict[Tuple[str, ...], str]:
    """Every copy of `pkg` in one lock: parent chain -> version."""
    return {chain: v for (p, chain), v in resolved.items() if p == pkg}


def _versions_words(v: Any) -> str:
    """`_one`'s value as words: a version, or several copies' versions joined (never a list's repr)."""
    return ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)


def landed_words(landed: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Gate 1's `landed` for the text report. ⛔ `from`/`to` are LISTS when several copies disagree (`_one`): the
    report used to concatenate them as strings and crashed after `gates_passed` (B54: a frontend
    lock holding brace-expansion at 1.1.15 and four 5.0.6 copies)."""
    return {k: f"{_versions_words(v['from'])}→{_versions_words(v['to'])}"
            for k, v in (landed or {}).items() if v.get("from")}


def _one(copies: Dict[Tuple[str, ...], str]) -> Any:
    """One copy -> its version string (the shape every caller and surface already reads); several -> the sorted
    list. ⚠️ Never a silent pick: two copies that disagree must both reach the reader."""
    vs = sorted(set(copies.values()))
    return (vs[0] if vs else None) if len(vs) < 2 else vs


#: Does this run execute gates 4 and 5? ⛔ The LIBRARY default is off: these gates EXECUTE THE PROJECT'S OWN
#: COMMANDS, so a library call of `run_group` runs none. The SCRIPT resolves it per lane (B57, `resolve_gates_45`):
#: ON wherever a PR is about to open (`--commit`, `--open-pr`), because a fix that merges untested where a suite
#: exists is the failure B57 closes (F1 would have been caught by the frontend's own Karma suite); OFF on `--probe`
#: and a plain `--apply`, which open nothing and would otherwise pay for a full suite on every scheduled run.
#: `--no-gates-45` opts out on any lane, `--gates-45` opts in on any lane.
#: ⚠️ Off still REPORTS — `not_run` with `GATES_45_OFF_WHY` — because an omitted check reads as a passed one.
GATES_45 = False
GATES_45_WHY_NOT_REQUESTED = ("not requested on this invocation (--gates-45): they run the project's own commands, "
                              "and run by default only where a PR is about to open")
GATES_45_WHY_NO_PR = ("not run: no PR opens on this run (--probe), so the project's own commands were not executed; "
                      "--commit and --open-pr run them by default (--gates-45 forces them here)")
GATES_45_WHY_OPTED_OUT = ("skipped by the developer (--no-gates-45): the build and the tests were NOT checked "
                          "on this fix")
#: EM D-23 S3 (em3 d1 M1, Bhakta 2026-11-05): the remediate Action never runs gates 4/5. The job that would run them
#: holds a DEFAULT-BRANCH Actions runtime token, which the upgraded package's code could reach and use to write cache
#: entries the customer's main-branch workflows later restore. The fix PR opens as a draft (D-23 S1), the customer's
#: own CI runs the build and tests on it with a PR-scoped token, and S1's ready rule flips it only when that CI passed.
GATES_45_WHY_PR_CI = ("not run here: the repository's own CI runs the build and tests on the draft PR (EM D-23 S1), "
                      "and the PR becomes ready for review only when that CI passed")
#: Why gates 4 and 5 did not run on this invocation; set with GATES_45 by `main`.
GATES_45_OFF_WHY = GATES_45_WHY_NOT_REQUESTED
#: `--gate-5-off WHY`: run gate 4 (build) but NOT gate 5 (tests), reported `not_run` with WHY. ⚠️ For a bulk dry
#: run over our own repositories (D-06 § 11), whose suites can reach a shared dev database: a test session's cleanup
#: has wiped a dev stack before. Never a default.
GATE_5_OFF_WHY: Optional[str] = None


def resolve_gates_45(choice: str, *, opens_pr: bool, probe: bool) -> Tuple[bool, str]:
    """`--gates-45` (on) / `--no-gates-45` (off) / neither (auto) → (run them?, why not). B57: auto is ON exactly
    when this run is about to open a PR."""
    if choice == "on":
        return True, ""
    if choice == "off":
        return False, GATES_45_WHY_OPTED_OUT
    if choice == "pr_ci":
        return False, GATES_45_WHY_PR_CI
    if opens_pr:
        return True, ""
    return False, (GATES_45_WHY_NO_PR if probe else GATES_45_WHY_NOT_REQUESTED)
#: `auto` runs the codemods on a class-4 group under `--apply`; `off` keeps today's behaviour (the
#: group returns `class_4_skipped` and a person does the work). ⚠️ Default `auto`, unlike GATES_45:
#: the codemods EXECUTE NOTHING of the customer's — libcst and tree-sitter parse bytes — so there is
#: no compute to opt into. Gates 4–5 run the project's own commands, which is why they run only where a PR
#: is about to open, and a developer can still opt out (B57).
CODEMOD = "auto"
#: Per file, per engine. A pathological file must not hang the lane; 120 s is the measured prototype's
#: worst file by two orders of magnitude.
CODEMOD_TIMEOUT = 120
#: Where accepted 4c drafts are read from at probe and re-applied at `--commit` (§ 3.5.5, M5).
CODEMOD_DRAFTS: Optional[str] = None
#: The API diff DOCUMENTS (not the plan's summary) that Gate B's L2 re-runs `intersect` with. Empty
#: means L2 cannot run; the block then reports `partial` and says the closed loop did not run, which
#: is the honest answer and never a pass.
API_DIFF_DOCS: List[Dict[str, Any]] = []

#: Called before each gate 4/5 step to PROVE this run still holds the plan's lease; returns False when it
#: does not. Set by the open-pr flow once the lease is in hand, cleared in its `finally`.
#:
#: ⛔ WHY A HOOK AND NOT A BIGGER TTL. The lease is a mutex on one repository's LOCK FILE, and its TTL is a
#: LIVENESS GUESS ("no progress, presumed dead"). Gates 4 and 5 run the project's own install and suite
#: INSIDE that window, so a slow suite is indistinguishable from a crashed runner and the lease is taken
#: from under us — after which this run would open a PR for a plan another run owns, and two locks resolved
#: from the same base would both merge. `--ttl` only moves the threshold; only a renew gives us the REFUSAL.
GATE_RENEW: Optional[Any] = None


class LeaseLost(Exception):
    """This run no longer holds the plan's lease, so it must open NOTHING."""


def set_gate_renew(fn: Optional[Any]) -> None:
    """Install (or clear) the liveness proof the gates call between steps."""
    global GATE_RENEW
    GATE_RENEW = fn

def gate_not_requested() -> Dict[str, str]:
    """Gates 4 and 5 when this invocation does not run them: `not_run`, with the reason `main` resolved (B57)."""
    return {"status": "not_run", "why": GATES_45_OFF_WHY}

#: Gates 4 and 5 on a class-4 plan. ⛔ NOT a pass. Class 4 applies no edit, so there is no applied tree to
#: build or test, and saying so is the honest answer — an omitted check reads as a passed one.
GATE_NOT_APPLICABLE_4 = {
    "status": "not_run",
    "why": "class 4 changes no file, so nothing was applied: gates 4 and 5 judge an applied tree"}

#: Gate 5's coverage verdict when there is nothing to measure. ⛔ `no-suite`, never `covered`.
#: Every class-2 and class-3 plan lands here: a lock bump rewrites no source line, so no line can be covered.
COVERAGE_NO_SOURCE = {
    "status": "no-suite", "changed_lines": {}, "covered_changed": 0, "uncovered_changed": [],
    "why": "this fix rewrites no source line, so there is nothing for a suite to execute"}

#: ⚠️ The suite was not run at all, so coverage was not measured. Stated, never collapsed into `no-suite`'s
#: "you have no suite" — the reviewer must be able to tell "we did not look" from "there is nothing to see".
def coverage_not_requested() -> Dict[str, Any]:
    return {"status": "no-suite", "changed_lines": {}, "covered_changed": 0, "uncovered_changed": [],
            "why": f"gates 4-5 did not run ({GATES_45_OFF_WHY}), so no suite ran and no coverage of the rewritten "
                   f"lines was measured"}

#: Worst-wins ordering over the per-tree verdicts. ⚠️ `error` outranks a missing suite deliberately: "we could
#: not run your tests" leaves the fix UNJUDGED, which a reviewer must weigh, while "you have none" is a settled
#: fact about the repo. `failed` outranks both.
#: Worst-wins ordering over the per-tree verdicts — this is the ONE word a reviewer reads, so it is ranked by
#: how much it should concern them, and every rank is distinct. ⚠️ TIES ARE A BUG HERE: `pre_existing` and
#: `not_detected` once shared a rank, and a tree with a red `make` suite AND an unconfigured pytest reported
#: whichever `max()` happened to see first — caught by its own test.
#:   failed        the fix broke it                      — drafts
#:   error         could not run, so UNJUDGED             — drafts
#:   not_run       not asked for, or skipped after a failed install
#:   pre_existing  red, but red BEFORE the fix too       — never the fix's fault, never drafts
#:   not_detected / unsupported   nothing here to run
_GATE_RANK = {"passed": 0, "not_detected": 1, "unsupported": 1, "pre_existing": 2,
              "not_run": 3, "error": 4, "failed": 5}


def _gate_step(step: Dict[str, Any], root: str, repo: str, eco: str,
               timeout: int = GATE_TEST_TIMEOUT_S) -> Dict[str, Any]:
    """One ladder step, run on the applied copy, mapped to a gate verdict.

    ⛔ `error` AND `failed` ARE NOT THE SAME CLAIM, and conflating them is the one thing this must not do.
    A missing toolchain (rc 127) or a timeout means the fix was never judged; a non-zero suite means the
    project is broken. A reviewer who reads the first as the second abandons a good fix.
    """
    r = _gate_cmd(list(step["cmd"]), root, timeout, eco)
    out = {"repo": repo, "ecosystem": eco, "cmd": r["cmd"], "rc": r["rc"], "output": r.get("output") or ""}
    if r.get("timed_out"):
        return {**out, "status": "error",
                "why": f"ran past {timeout} s and was killed: the fix is unjudged, not disproven"}
    # ⛔ A PROCESS KILLED BY A SIGNAL DID NOT FINISH, so it judged nothing: never `passed`, never `failed`.
    # (Popen reports death by signal N as rc -N.) Exit codes are the contract only for a run that ended itself.
    if r["rc"] < 0:
        return {**out, "status": "error",
                "why": f"killed by signal {-r['rc']}: unjudged, not disproven"}
    if r["rc"] == 127:
        return {**out, "status": "error",
                "why": f"{step['cmd'][0]} is not on this runner: the fix is unjudged, not disproven"}
    if r["rc"] != 0:
        return {**out, "status": "failed", "why": f"exited {r['rc']}"}
    return {**out, "status": "passed", "why": ""}


class _Baseline:
    """The unmodified trees D4 re-runs a failed step on — COPIES, made lazily, one per repository.

    ⛔ NEVER THE PATH THE CALLER GAVE. Without a planned `ref`, `scope_trees` hands back the developer's own
    working checkout, and the baseline used to run the project's commands IN it: `npm test` there, and after a
    failed install `npm ci` too, writing `node_modules` into the very checkout the runbook promises is never
    touched. Each source is now copied (the same `_fresh_copy` the fix's own copy is made with, so the two start
    from the SAME bytes, dirty tree included) under `<root>/<repo>`, and only the copy is ever run.

    ⛔ INSTALLED BEFORE IT IS TESTED. A copy carries no `node_modules` / `.venv` (`_SKIP`), so a suite run on it
    straight away fails with `ng: command not found` (rc 127) — an `error`, which D4 rightly refuses to call
    `pre_existing`, so a suite red on main was blamed on every fix. The baseline runs the ladder's own install
    first, once per repository; if THAT does not pass, the baseline proves nothing and says so.
    """

    def __init__(self, sources: Dict[str, str], root: Optional[str]):
        self.sources, self.root = sources, root
        self.trees: Dict[str, str] = {}
        self.installed: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def tree(self, repo: str) -> Optional[str]:
        if repo in self.trees:
            return self.trees[repo]
        src = self.sources.get(repo) or ""
        if not os.path.isdir(src):
            return None
        root = self.root or tempfile.mkdtemp(prefix="remediation-baseline-")
        self.root = root
        dst = os.path.join(root, copy_label(repo))
        os.makedirs(root, exist_ok=True)
        _fresh_copy(src, dst)
        self.trees[repo] = dst
        return dst

    def install(self, repo: str, eco: str, step: Optional[Dict[str, Any]], cap: int) -> Dict[str, Any]:
        """The baseline's own install, run once: a gate verdict (`passed` when there is nothing to install)."""
        key = (repo, eco)
        if key not in self.installed:
            if not step or step.get("status") != test_ladder.DETECTED or not step.get("cmd"):
                self.installed[key] = {"status": "passed", "why": "no install step"}
            else:
                self.installed[key] = _gate_step(step, self.trees[repo], repo, eco, cap)
        return self.installed[key]


def _pre_existing(step: Dict[str, Any], baseline: "_Baseline", repo: str, eco: str,
                  cap: int, what: str, install: Optional[Dict[str, Any]] = None
                  ) -> Tuple[Optional[Dict[str, Any]], str]:
    """Phase-4 spec D4: was this step ALREADY failing before the fix?

    Returns `(baseline run, "")` when the same step ALSO failed on the unmodified copy (the caller re-labels the
    gate `pre_existing`), `(None, why)` when the baseline could not judge it (its install did not pass), and
    `(None, "")` when it passed there or there is no unmodified tree. `install` is the ladder's install step,
    run on the copy before a TEST step (`_Baseline`).

    ⛔ WITHOUT THIS, ONE RED SUITE DRAFTS EVERY PR INTO THAT REPOSITORY FOR EVER, each one blaming a fix that
    changed a lock. The blame is the damage: a reviewer who reads two or three such PRs stops reading the gate,
    and the gate stops working for the fixes that genuinely do break something.

    ⚠️ RUN LAZILY — only after the post-fix suite failed (D4: "REC: run this baseline lazily, only on failure"),
    because it spends the customer's CI minutes a second time.

    ⭐ The baseline is a COPY of the tree the fix's copy was made from (`_Baseline`), never that tree itself.

    ⚠️ v1 compares the STEP's verdict, not the failing-test NAMES: per-framework test-name diffing is a
    bigger job, and "it was already red" is the claim that stops the false blame.

    ⭐ APPLIED TO THE INSTALL TOO, not just the suite — D4 names the test case, but the install has the same
    failure mode and P2 makes it likelier: the gate env strips every variable whose name contains TOKEN, SECRET
    or KEY, so a repository that installs from a PRIVATE REGISTRY loses its `NPM_TOKEN` and `npm ci` fails on
    authentication. Without this the gate would report `failed` and a reviewer would read "the fix broke the
    install", for a credential the gate removed on purpose. The baseline fails identically, so it is named
    `pre_existing` instead.
    """
    tree = baseline.tree(repo)
    if tree is None:
        return None, ""
    log(f"  gate {what}: it failed — re-running on an unmodified copy ({tree}) to see if it was already failing")
    if install is not None:
        ins = baseline.install(repo, eco, install, GATE_INSTALL_TIMEOUT_S)
        if ins["status"] != "passed":
            # ⛔ An uninstalled tree proves nothing: never `pre_existing` from it, and never silently.
            return None, (f"the unmodified copy could not be installed ({ins['status']}: "
                          f"{ins.get('why') or 'no reason given'}), so whether it was already failing is unknown")
    base = _gate_step(step, tree, repo, eco, cap)
    return (base, "") if base["status"] == "failed" else (None, "")


def _gate_summary(runs: List[Dict[str, Any]], what: str) -> Dict[str, Any]:
    """The worst verdict across every tree, with the reason that earned it."""
    if not runs:
        return {"status": "not_detected", "why": f"no tree declared a {what} step", "runs": []}
    worst = max(runs, key=lambda r: _GATE_RANK.get(r["status"], 0))
    why = worst["why"] or f"every {what} step passed"
    if worst["status"] != "passed":
        why = f"{worst['repo']} ({worst['ecosystem']}): {why}"
    return {"status": worst["status"], "why": why, "runs": runs}


def review_decision(vet_path: Optional[str], rec: Dict[str, Any], text: Dict[str, Any],
                    overrule: Optional[str] = None) -> Tuple[str, str, Optional[str]]:
    """D-06 slice 1: (final_state, the PR body's review block, the refusal reason or None).

    Code's verdict is the platform's PR text: a draft when it says so, else confirm. The review is `vet.json`
    (spec § 5.1) and counts only when it is about THIS plan at its CURRENT fingerprint. ⛔ Never looser than code:
    no review, an unreadable one or a stale one is `unvetted`, which opens a draft. A refusal stops the PR unless a
    person overrules it, and the overrule is written into the PR.

    ⭐ DF IS THE SOURCE OF TRUTH once it stores the review (slice 2, lead 2026-11-04): code's verdict is pr-text's
    `code_verdict`, NEVER `draft` — DF's `draft` already includes the review, so reading it as code's verdict would
    make every PR a draft. Only an older DF (no `code_verdict`) falls back to `draft`. When pr-text says
    `review_in_body`, DF's own "## Review" block is in the body and no second block is returned."""
    code = text.get("code_verdict") if text.get("code_verdict") in ("confirm", "draft", "refuse") else \
        ("draft" if text.get("draft") else "confirm")
    vet, why = None, "no review was run (--vet)"
    if vet_path:
        try:
            with open(vet_path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError) as exc:
            raw, why = None, f"the review file could not be read ({type(exc).__name__})"
        if raw is not None:
            vet, why = _vet.vet_for_plan(raw, str(rec.get("id")), str(rec.get("effective_fingerprint")))
    final = _vet.final_state(code, vet)
    if final == "refuse" and not overrule:
        return final, "", f"the AI review refused this fix: {(vet or {}).get('reason') or '?'}"
    if final == "refuse":
        final = "draft"
    if text.get("review_in_body"):
        return final, "", None
    return final, _vet.review_block(code, vet, why, overrule), None


def _vet_verdict_of(vet_path: Optional[str]) -> Optional[str]:
    try:
        with open(vet_path or "", encoding="utf-8") as fh:
            return json.load(fh).get("verdict")
    except (OSError, ValueError, AttributeError):
        return None


def _vet_reason_of(vet_path: Optional[str]) -> str:
    try:
        with open(vet_path or "", encoding="utf-8") as fh:
            return str(json.load(fh).get("reason") or "")[:400]
    except (OSError, ValueError, AttributeError):
        return ""


def post_vet(plan_id: str, vet_path: Optional[str]) -> Tuple[str, str]:
    """Store the review on the plan in DF (`torana remediation-plan <id> vet --file`), BEFORE pr-text so the PR text
    carries it. → ("stored" | "stale" | "skipped" | "failed", detail).

    `stale` (exit 1, `vet_stale`): the plan moved since the review; re-review (counts toward the two loops).
    `failed`: an older server or CLI without the route, or a 403. The run CONTINUES: DF then drafts the PR as
    unvetted, which is the safe direction, and the output says so."""
    if not vet_path:
        return "skipped", "no --vet: DF drafts the PR as not reviewed"
    rc, _, err = torana(["remediation-plan", plan_id, "vet", "--file", vet_path, "--format", "json"])
    if rc == 0:
        return "stored", ""
    if rc == 1 and "stale" in (err or "").lower():
        return "stale", (err or "").strip()[-300:]
    return "failed", f"exit {rc}: {(err or '').strip()[-300:]}"


def store_review(rec: Dict[str, Any], vet_path: Optional[str], overrule: Optional[str],
                 result: Dict[str, Any]) -> Optional[Tuple[str, int, str, str]]:
    """Store the AI review (and a person's overrule) on the plan in DF, for EVERY lane that opens a PR (`--push-pr` and
    `--open-pr`, D-06 review M2: one code path, never a copy). Updates `result`; returns None to go on, or the
    `(status, exit, why, next)` to stop with — nothing has been pushed or opened at that point.

    ⛔ A REFUSAL THAT DF DID NOT RECORD IS A STOP (D-06 review M3), never a silent draft: DF's reserve-pr / open-pr
    refuse a refused plan only when DF holds the refusal, so a lost POST would let the platform open what the review
    refused. The same for an overrule that was asked for and not recorded. Any other failed POST continues: DF then
    drafts the PR as not reviewed, which is the safe direction."""
    vet_state, vet_detail = post_vet(rec["id"], vet_path)
    result.update(vet_post=vet_state, **({"vet_post_detail": vet_detail} if vet_detail else {}))
    if vet_state == "stale":
        return ("vet_stale", 1, f"the review is about an older version of this plan: {vet_detail}",
                "re-run vet_case.py on this run's report (it counts toward the two review loops), "
                "then rerun with the new --vet; nothing was pushed")
    verdict = _vet_verdict_of(vet_path) if vet_path else None
    if vet_state == "failed":
        if verdict == "refuse":
            return ("refused_by_review", 2, f"the AI review refused this fix: {_vet_reason_of(vet_path) or '?'} — "
                    f"and the refusal could not be recorded on the plan ({vet_detail})",
                    "nothing was pushed. Fix the cause (an older platform, or `torana auth login` for the "
                    "remediation_plan:vet permission) and rerun; never open a refused fix without its record")
        log(f"WARNING: the review could not be stored on the plan ({vet_detail}); the platform will draft "
            "the PR as not reviewed")
    if overrule and verdict == "refuse":
        if vet_state != "stored":
            return ("refused_by_review", 2, "the overrule needs the refusal recorded first, and it was not",
                    "nothing was pushed; rerun once `vet` succeeds")
        # ⭐ A PERSON's overrule (needs alert:update), recorded in DF with who and why; DF's PR text and Review block
        # then carry it. ⛔ Never called without the flag.
        rc_o, _, err_o = torana(["remediation-plan", rec["id"], "vet-overrule", "--fingerprint",
                                 str(rec.get("effective_fingerprint")), "--reason", overrule[:1000], "--format", "json"])
        if rc_o != 0:
            return ("refused_by_review", 2, f"the overrule was not recorded: {(err_o or '').strip()[-300:]}",
                    "plan_changed: re-review this run's report; nothing_to_overrule: the stored review is not a "
                    "refusal; a permission error: an overrule needs a person who may approve plans (alert:update). "
                    "Nothing was pushed")
        result["vet_overrule"] = "recorded"
    return None


def attach_assumptions(report: Dict[str, Any]) -> Dict[str, Any]:
    """D-06 slice 1 (spec § 5): the two APPLY assumptions, `moved` (gate 2) and `tests` (gates 4-5), as data on the
    group report. The planner's seven ride on the plan's packages; the review step reads both."""
    report["assumptions"] = _assumptions.apply_assumptions(report)
    return report


def gate_build_and_tests(copies: Dict[str, str], pristine: Optional[Dict[str, str]] = None,
                         baseline_root: Optional[str] = None,
                         cov: Optional[Tuple[str, str]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """FD gates 4 (build) and 5 (tests), on the APPLIED copies, with the project's OWN commands.

    `pristine` maps each repository to the tree its applied copy was made FROM (the scope). It is only ever
    COPIED (under `baseline_root`, else a temp dir) for D4's baseline, never run in (`_Baseline`).

    ⭐ IT RUNS WHERE THE TREE IS, which is the only place a toolchain exists. `--apply` only ever runs on the
    customer's CI runner or a developer's laptop — no service invokes this script — so the environment is right
    by construction and nothing is provisioned here. That is also why there is no per-plane switch: there is no
    plane without the tree.

    ⛔ NEITHER GATE ABORTS. Gates 1-3 decide whether a PR may open; these two decide whether it opens as a
    DRAFT (FD § "What runs before the PR opens"). The caller leaves `status` alone and reads `draft`.

    ⚠️ The ladder's reach is its own (v1: uv, npm, a Makefile `test:` target), and it is NOT a superset of the
    ecosystems a plan can be built for. Today they match — `manifests.DECLARATION_ECOSYSTEMS` is pypi + npm — so
    every plan that reaches here is one the ladder can read. Adding an ecosystem to the planner without adding a
    rung would open PRs whose gates 4 and 5 can only ever say `not_detected`.
    """
    build: List[Dict[str, Any]] = []
    tests: List[Dict[str, Any]] = []
    baseline = _Baseline(pristine or {}, baseline_root)
    for repo in sorted(copies):
        root = copies[repo]
        found = test_ladder.discover(root)
        if not found["ecosystems"]:
            absent = {"repo": repo, "ecosystem": "", "status": "not_detected",
                      "why": (f"nothing this ladder reads (v{found['ladder']}: uv, npm, a Makefile `test:` "
                              f"target) declares a project at the root of this tree")}
            build.append(dict(absent))
            tests.append(dict(absent))
            continue
        for e in found["ecosystems"]:
            eco = e["ecosystem"]
            for which, bucket in (("install", build), ("test", tests)):
                step = e[which]
                # ⛔ A SUITE RUN AFTER A FAILED INSTALL IS NOISE, NOT EVIDENCE. It fails for the install's
                # reason and reports a SECOND, derived failure against the fix — which reads to a reviewer as
                # two independent problems. Measured on a uv tree whose lock `uv sync` rejects: gates 4 and 5
                # both said "exited 2" for one cause. Skipped explicitly (never omitted), carrying the cause.
                if which == "test" and GATE_5_OFF_WHY:
                    bucket.append({"repo": repo, "ecosystem": eco, "status": "not_run",
                                   "why": f"switched off for this run (--gate-5-off): {GATE_5_OFF_WHY}"})
                    continue
                if which == "test" and build and build[-1].get("repo") == repo \
                        and build[-1].get("ecosystem") == eco \
                        and build[-1]["status"] in ("failed", "error"):
                    bucket.append({"repo": repo, "ecosystem": eco, "status": "not_run",
                                   "why": f"the install step did not succeed ({build[-1]['status']}), so the "
                                          f"suite was not run: it would fail for the install's reason"})
                    continue
                # ⭐ COVERAGE RIDES ON GATE 5'S OWN RUN (§ 3.4.5), replacing its command rather than adding a
                # second pass. `coverage_request` has already checked that this is the pytest-on-uv step and
                # that pytest-cov is importable in the project's environment, so the swap cannot be the thing
                # that breaks the suite. The artefact path travels on the verdict for gate 5's coverage reader.
                artifact = cov[1] if (cov and which == "test" and repo == cov[0]) else None
                if artifact:
                    step = {**step, "cmd": _cov_cmd(step["cmd"], artifact)}
                if step["status"] == test_ladder.DETECTED and step.get("cmd"):
                    # ⛔ BEFORE the step, never after: the point is to still hold the mutex while the
                    # customer's code runs, and to stop the moment we do not.
                    if GATE_RENEW is not None and not GATE_RENEW():
                        raise LeaseLost("the plan's lease was lost before a gate step")
                    cap = GATE_INSTALL_TIMEOUT_S if which == "install" else GATE_TEST_TIMEOUT_S
                    v = _gate_step(step, root, repo, eco, cap)
                    # D4: a FAILED step is re-run on the unmodified copy before it is blamed on the fix.
                    if v["status"] == "failed":
                        base, unjudged = _pre_existing(step, baseline, repo, eco, cap,
                                                       "4 build" if which == "install" else "5 tests",
                                                       install=e["install"] if which == "test" else None)
                        if unjudged:
                            v = {**v, "why": f"{v['why']}; {unjudged}"}
                        if base is not None:
                            v = {**v, "status": "pre_existing",
                                 "why": (f"exited {v['rc']}, but the SAME command also fails on the unmodified "
                                         f"copy (exited {base['rc']}): it was already failing here, so the "
                                         f"failure is not evidence against this fix"),
                                 "baseline": {k: base[k] for k in ("cmd", "rc", "output")}}
                    # ⛔ RECORDED WHATEVER THE VERDICT. A red suite still wrote which lines it executed, and
                    # "the rewritten line was never run" is true whether or not some other test failed.
                    # ⚠️ `coverage_argv` is the step's ARGV, kept beside the artefact because the verdict's own
                    # `cmd` is `shlex.join(...)` — a STRING for a human to read. Handing that string to
                    # `gate_coverage` as the test step made `tuple(step)[:4]` iterate CHARACTERS, so the v1
                    # pytest check compared ('u','v',' ','r') and answered `no-suite` on the very run that had
                    # just written a good coverage report. Measured end to end on a real uv tree, 2026-10-30.
                    if artifact:
                        v = {**v, "coverage_artifact": artifact, "coverage_argv": list(step["cmd"])}
                    bucket.append(v)
                else:
                    # ⛔ Reported, never dropped: `not_detected` and `unsupported` are ANSWERS a reviewer
                    # needs (test_ladder.py), and a step left out of the report reads as one that passed.
                    bucket.append({"repo": repo, "ecosystem": eco, "status": step["status"],
                                   "why": step["why"]})
    return _gate_summary(build, "install"), _gate_summary(tests, "test")


def _cov_available(root: str, eco: str) -> bool:
    """Is `pytest-cov` importable in the PROJECT'S own environment?

    ⚠️ `uv run --frozen`, not this process. pytest-cov installed beside the CLI proves nothing about the
    interpreter the suite actually uses, and asking the wrong one would swap in a `--cov` flag that then
    fails the whole suite — turning a missing plugin into a FAILED fix.
    """
    r = _gate_cmd(["uv", "run", "--frozen", "python", "-c", "import pytest_cov"],
                  root, GATE_INSTALL_TIMEOUT_S, eco)
    return r["rc"] == 0


def _cov_cmd(cmd: Sequence[str], artifact: str) -> List[str]:
    """Gate 5's own command with coverage switched on, keeping every argument the project chose."""
    return list(cmd) + ["--cov=.", f"--cov-report=json:{artifact}"]


def draft_unproven(report: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Which gates make this PR a DRAFT — gate 4, gate 5 and gate 5's coverage — as `(label, verdict)`.

    ⛔ ONLY A GATE WE ACTUALLY TRIED DRAFTS, and the three statuses that mean "we did not try" are
    deliberately silent: `not_detected` / `unsupported` (this repository has no suite we can run) and
    `not_run` (nobody asked, or the install already failed and is already drafting). Drafting on those
    would draft every PR into such a repository for ever while telling the reviewer nothing new.

    ⛔ COVERAGE DRAFTS ON `uncovered` AND NOTHING ELSE. `no-suite` means we did not MEASURE whether the
    rewritten lines run, which is the same kind of absence — stated, never held against the fix.

    ⚠️ Extracted so the rule has ONE definition. It used to live inline in `run_group`, which meant its
    own test could only re-implement it and then agree with itself.
    """
    out = [(n, g) for n, g in (("4 build", report.get("gate_4_build") or {}),
                               ("5 tests", report.get("gate_5_tests") or {}))
           if g.get("status") in ("failed", "error")]
    cov = report.get("gate_5_coverage") or {}
    if cov.get("status") == "uncovered":
        out.append(("5 coverage", cov))
    return out


def coverage_request(copies: Dict[str, str], subject: str, codemod: Optional[Dict[str, Any]],
                     work_dir: str) -> Optional[Tuple[str, str]]:
    """`(repo, artifact path)` when gate 5 should run WITH coverage, else None.

    ⭐ ONE RUN, NOT TWO (§ 3.4.5). Coverage is read from gate 5's own run with `--cov` switched on, never
    from a second pass: the suite is the customer's and may take many minutes, and running it twice for
    one PR spends their compute to answer a question one run already answers.

    ⚠️ The risk this accepts is that `--cov` changes what is run (the plugin loads, imports move), so a
    suite that is green plain and red under coverage reports as a failed gate 5. D4's baseline re-run is
    what makes that safe: a failed step is re-run with the SAME command on the unmodified copy, so such a
    failure comes back `pre_existing` and is never blamed on the fix.

    ⛔ Asked only for the SUBJECT. The rewritten lines are source in the repository whose code calls the
    moved API — in phase-5 v1 (L1) the subject — while the bump lands in a lock nobody covers.
    """
    if not ((codemod or {}).get("files") or []) or not GATES_45:
        return None
    root = copies.get(subject)
    if not root:
        return None
    step = next((e["test"] for e in test_ladder.discover(root)["ecosystems"]
                 if e["ecosystem"] == "pypi"), None)
    import gate_b as gb
    if not step or step["status"] != test_ladder.DETECTED \
            or tuple(step.get("cmd") or ())[:4] != gb.PYTEST_UV:
        return None
    if not _cov_available(root, "pypi"):
        return None
    return subject, os.path.join(work_dir, "coverage.json")


def gate_coverage_of_codemod(copies: Dict[str, str], subject: str, codemod: Optional[Dict[str, Any]],
                             tests: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Gate 5's coverage verdict: did the suite EXECUTE the lines the codemod rewrote?

    Reads the artefact gate 5's own run wrote (`coverage_request` above asked for it), so nothing is run
    here. The verdict is reported on EVERY class-2 and class-3 report too, where it can only say "nothing
    was rewritten" — an omitted check reads as a passed one.

    ⛔ NOTHING HERE BLOCKS A PR. `uncovered` drafts it and names the lines (§ 3.6.2); every other outcome
    is `no-suite`, which is STATED and never held against the fix — the same asymmetry as a missing suite
    for gates 4-5.
    """
    import gate_b as gb

    files = (codemod or {}).get("files") or []
    if not files:
        return dict(COVERAGE_NO_SOURCE)
    if not GATES_45:
        return coverage_not_requested()
    run = next((r for r in ((tests or {}).get("runs") or [])
                if r.get("repo") == subject and r.get("coverage_artifact")), None)
    root = copies.get(subject) or ""
    if run is None:
        # ⚠️ Gate 5 ran WITHOUT coverage, and which of the two reasons applies is knowable only here:
        # either the ladder found no pytest-on-uv step (so `gate_coverage` says the v1 limit itself), or
        # it did and pytest-cov is missing from the project's own environment. Stated, not guessed.
        step = next((e["test"] for e in test_ladder.discover(root)["ecosystems"]
                     if e["ecosystem"] == "pypi"), None) if root else None
        cmd = (step or {}).get("cmd") if (step or {}).get("status") == test_ladder.DETECTED else None
        return gb.gate_coverage(root, files, cmd, unmeasured=(
            "pytest-cov is not importable in the project's own environment, so gate 5 ran without "
            "coverage and the rewritten lines were not measured" if cmd else None))
    # ⛔ `coverage_argv`, NOT `run["cmd"]` — see the note where it is recorded.
    return gb.gate_coverage(root, files, run.get("coverage_argv"), artifact=run["coverage_artifact"])


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


def _codemod_drift(stored: Dict[str, Any], fresh: Dict[str, Any]) -> Optional[str]:
    """The reason the codemod no longer matches the approved plan, or None.

    ⛔ BOTH HASHES, AND THEY FAIL FOR OPPOSITE REASONS — which is why the message names which:

      `sha256_before` moved  → the BASE changed under us. Somebody edited that file between the
                               proposal and now, so the approved plan describes a tree that no longer
                               exists. The remedy is to RE-PROPOSE: the diff a person read was
                               against different bytes.
      `sha256_after` differs → the base is the same and the codemod produced something ELSE. That is
                               not drift in the repository, it is the codemod being irreproducible,
                               which is a defect to report rather than something to re-propose.

    ⚠️ A file the plan recorded and this run did not produce is also drift: the plan promises that
    file's new bytes, and committing without it would ship a partial fix under a plan that claims a
    whole one.
    """
    want = {f.get("file"): f for f in (stored.get("files") or []) if f.get("file")}
    if not want:
        return None                                   # not a class-4 plan with recorded files
    got = {f.get("file"): f for f in (fresh.get("files") or []) if f.get("file")}
    for path, rec_f in sorted(want.items()):
        now = got.get(path)
        if now is None:
            return (f"{path} is recorded in the plan but this run produced no change for it; the plan "
                    f"promises its new bytes, so committing would ship a partial fix")
        if rec_f.get("sha256_before") != now.get("sha256_before"):
            return (f"{path} differs from the plan ('before' moved: the file changed since the "
                    f"proposal, so re-propose — the diff a person read was against different bytes)")
        if rec_f.get("sha256_after") != now.get("sha256_after"):
            return (f"{path} differs from the plan ('after' differs: the base is unchanged but the "
                    f"codemod produced something else, so it is not reproducible — report it)")
    return None


def _l2_for(plan, work, copies, subject, scope):
    """Gate B's L2 as a callable, or None when it CANNOT run (which is reported, not hidden).

    ⛔ WHY IT MAY BE None, AND WHY THAT IS NOT A FAILURE. L2 re-runs the API-diff check on the applied
    copy, which needs the api-diff DOCUMENT. A stored plan carries only the summary — counts plus the
    touched list — so `intersect` cannot be re-run from it; the document arrives via
    `--api-diff-file` (the planner's `--api-diffs-out`). Without it the block reports `partial` and
    says the closed loop did not run. ⚠️ That is strictly better than the two alternatives: claiming
    `complete` unchecked, or refusing a correct rewrite because an input was missing.

    ⭐ `basis` is what makes a weak pass legible: with no measured module mapping the call graph could
    not place this package's calls, so L2 only really checked import lines, and `l2_closed_loop` words
    it that way instead of reporting a full agreement.
    """
    if not API_DIFF_DOCS or not subject or subject not in copies:
        return None
    rows = work.get("rows") or []
    row = next((r for r in rows if r.get("package")), None)
    if row is None:
        return None
    pkg, eco = row.get("package"), row.get("ecosystem") or "pypi"
    # ⛔ THE PLANNER'S OWN MATCHER, not a second one. A `torana.api_diff.v1` document carries its pair
    # under `key` (`{ecosystem, package, from, to}`) — which is what `read_api_diffs` hands us, whether
    # the file held bare documents or ready views. The hand-rolled matcher here looked for
    # `doc["api_diff"]["package"]` / `doc["package"]`, neither of which exists in that shape, so it
    # matched NOTHING: L2 — the level of Gate B that actually decides — could never run, and every
    # class-4 block was `partial` for ever, quietly, for precisely the reason this function's docstring
    # warns about. ⭐ MEASURED 2026-10-31 (runbook § 1b) on a real class-4 plan.
    # ⚠️ `api_diff_for` also checks BOTH versions, which the old matcher did not: a document for another
    # pair describes a different upgrade, and re-running the check with it would report agreement about
    # a symbol nobody changed.
    doc = rp.api_diff_for(list(API_DIFF_DOCS), eco, pkg, row.get("installed"), row.get("target"))
    if doc is None:
        return None
    entry = next((x for x in scope.values() if x), None)
    commit = next((s0.get("commit") for s0 in (plan.get("scope") or []) if s0.get("repo") == subject), None)

    def _read(rel):
        try:
            with open(os.path.join(copies[subject], rel), encoding="utf-8") as fh:
                return fh.read()
        except (OSError, UnicodeDecodeError):
            return None                              # ⚠️ an unreadable file proves nothing

    def run(sites):
        import gate_b as gb
        return gb.l2_closed_loop(copies[subject], subject, commit, doc, pkg, eco, None,
                                 sites, _read, (row.get("api_diff") or {}).get("basis") or "measured")
    _ = entry
    return run


def _usage_for(copies, subject, cache):
    """The dynamic-use pass's input (B4, § 3.5.2), lazily: `usage_for`'s `(records, call graph)` pair.

    ⛔ THE APPLIED COPY, not the original. The pass asks "does any file still name the old symbol
    dynamically?" about the tree this run would PROPOSE — so a `getattr` the codemod has just made
    stale must be found in the copy, and a file the rewrite touched must be read as it now stands.

    ⚠️ LAZY AND CACHED UNDER ITS OWN KEY. Lazy because `run_codemods` declines before it needs this
    (no engine, a truncated site list) and indexing a tree is not free; under its own key because
    `cache["usage"]` already holds the pair for the ORIGINAL primary tree (`co_mover_api_diffs`), which
    is a different tree and would answer about the code before the rewrite.

    `None` (no copy of the subject) means the pass does not run, which the block STATES.
    """
    root = copies.get(subject)
    if not root:
        return None

    def run():
        import api_diff_intersection as ci                  # ships beside this script, in the scan pack
        key = "codemod_usage:" + root
        if key not in cache:
            cache[key] = ci.usage_for(root)
        return cache[key]
    return run


def gate_lane(cls: str, changes: Dict[str, List[str]], allowed: Dict[str, set], originals: Dict[str, str],
              copies: Dict[str, str], exact: bool = False, codemod_lane: bool = False) -> Dict[str, Any]:
    """FD gate 3: class 2 → the locks, plus at most package.json's `overrides`; class 3 → the declaring files and
    the locks. ⛔ A hunk outside the lane means the verdict and the edit disagree.

    `exact` (a server plan, `--plan-id`): `allowed` is the plan's server-computed `allowed_files`, which already
    holds the npm class-2 `package.json` beside each lock (FIX_PR_SPEC.md § 3.4.3 check 4, rule P4), so NOTHING
    outside it passes, not even an overrides-only package.json: the platform would refuse that file anyway.

    ⛔ CLASS 4: THE LANE IS EMPTY, whatever `allowed` says. A class-4 PR is a document — the upgrade, and the call
    sites in this repository that it breaks — so no file may change, the lock least of all. `allowed` is seeded
    from the group's locks by its caller (a class-4 row still RESOLVES in a lock; that is how it was found), so
    without this the lane would permit the very recompile the classification refuses.

    ⭐ PHASE 5 NARROWS THAT RULE: `codemod_files` says a codemod actually rewrote source in this run,
    and then the bump is no longer a bare recompile — it rides WITH the code change that makes it
    safe, which is the whole point of class 4 being fixable. The empty lane therefore applies to a
    class-4 run WITHOUT a codemod, which is still a document and must change nothing."""
    if cls == "4" and not codemod_lane:
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


def copy_label(repo: str) -> str:
    """The directory name a copy of `repo` gets. ⛔ NEVER THE RAW KEY: the plan-id lanes key repositories by
    `repo:github.com/org/name`, and a `:` in a directory breaks every tool that puts a path inside that tree on
    PATH. npm prepends `<cwd>/node_modules/.bin`, the `:` splits the entry, and gate 5 answered `ng: command not
    found` right after `npm ci` had installed it (first live laptop run, 2026-10-29). The `/` nests directories
    a later reader does not expect. One rule for every copy this script makes."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", repo)


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
        into = os.path.join(root, copy_label(s["repo"]) + "@" + s["commit"][:12])
        if os.path.isdir(into):
            shutil.rmtree(into)                          # ours: everything under <work>/base is this script's
        os.makedirs(into)
        try:
            out[s["repo"]], _ = rp.materialize(s["path"], s["commit"], into)
        except rp.BadRef as exc:
            raise Refused(str(exc))
    return out


# ── W3-14: a co-mover that crosses a major gets an API diff and the call-graph check ────────────────────
# FIX_KNOWLEDGE_CONVERGENCE § 3.4.8 + § 3.6.7 (e), as decided by the lead 2026-10-27.

CO_REQUEST, CO_READ, CO_OFF, CO_CI = "request", "read", "off", "ci"
#: ⛔ THE LEASE MUST OUTLIVE THE GATES. The open-pr flow acquires the plan's lease and THEN applies and gates
#: (`lease acquire` → `run_group`), and the server's default TTL is 600 s (`LEASE_TTL_DEFAULT`, DF
#: `remediation_plan_service.py:52`) — shorter than a suite is allowed to take. An expired lease lets a second
#: runner acquire it and open a DUPLICATE PR for the same plan, which is the one thing the lease exists to stop.
#:
#: ⚠️ THE ARITHMETIC IS LOAD-BEARING. Worst case with gates on is install + test + ONE baseline = 600 + 1200 +
#: 1200 = 3000 s, because the two baselines are MUTUALLY EXCLUSIVE: a failed install skips the suite, so a test
#: baseline can never follow an install baseline. 3000 s fits the server's 3600 s maximum with 600 s of margin.
#: ⛔ Raise GATE_INSTALL_TIMEOUT_S or GATE_TEST_TIMEOUT_S and that margin goes — recompute it here, or the
#: failure is a duplicate PR under load, not an error anyone sees.
#: ⭐ The spec's `renew` before each gate step (§ 3.4.1) is built as of 2026-10-28, so the arithmetic above is
#: now the BACKSTOP and the renew is the mechanism. Both still matter: see `lease_renew_args`.
LEASE_TTL_WITH_GATES = 3600


def lease_acquire_args(plan_id: str, holder: str) -> List[str]:
    args = ["remediation-plans", "lease", "acquire", "--plan-id", plan_id, "--holder-run", holder,
            "--format", "json"]
    return args + (["--ttl", str(LEASE_TTL_WITH_GATES)] if GATES_45 else [])


def lease_renew_args(lease_id: str, holder: str) -> List[str]:
    """⛔ A RENEW MUST CARRY THE SAME TTL AS THE ACQUIRE, or it SHORTENS the lease.

    DF's `renew_lease` defaults `ttl` to `LEASE_TTL_DEFAULT` (600 s), exactly as `acquire_lease` does, so a
    renew sent without `--ttl` does not "extend" anything — it resets the window to 600 s. With gates on, the
    acquire asks for 3600 s and the first renew used to cut it to 600 s, which is BELOW one test step's cap
    (`GATE_TEST_TIMEOUT_S` = 1200 s). The renew meant to prove liveness through a long suite was therefore
    creating the mid-suite expiry it exists to prevent, and leaving the lane worse off than the bare
    `--ttl 3600` acquire: a second runner could take the mutex and open a DUPLICATE PR for the same plan.

    Measured, not reasoned: see `tests/test_remediation_apply_timeout.py::test_a_renew_never_shortens_the_lease`.
    """
    args = ["remediation-plans", "lease", "renew", str(lease_id), "--holder-run", holder, "--format", "json"]
    return args + (["--ttl", str(LEASE_TTL_WITH_GATES)] if GATES_45 else [])


#: Set by `main` from `--co-mover-api-diffs`; a library call of `run_group` asks nothing.
CO_MOVER_API_DIFFS = CO_OFF


def _origin_of(copy_root: str, lock_file: str, eco: str, pkg: str, version: str) -> Optional[Dict[str, Any]]:
    """The AFTER lock's own record of where `pkg` came from (the planner's public-origin gate, on the copy)."""
    for rec in manifests.read_manifests(copy_root, files=[lock_file]):
        if rec.get("kind") != "resolution" or not rec.get("version"):
            continue
        if rp.normalize(str(rec.get("package") or rec.get("resolved_name") or "")) != rp.normalize(pkg):
            continue
        if rp.same_version(eco, str(rec["version"]), version):
            return rec.get("origin")
    return None


def co_mover_api_diffs(gate2: Dict[str, Any], copy_root: str, lock_file: str, eco: str, primary_root: Optional[str],
                   cache: Dict[str, Any], mode: str) -> None:
    """For each co-mover (`gate2["moved"]`) whose move crosses a major version or a 0.x minor, in EITHER direction,
    write `api_diff` on it: the API diff and the call-graph check on the primary tree, as the asked package gets.

    ⛔ Never a crash and never a fetch the lead ruled out: a downgrade pair is `not_requested`/`downgrade_pair` (the
    downgrade acknowledgement covers it); a CI run is `not_requested`/`ci_second_resolve` (an API diff there would need a
    second resolve); an unparseable move is `version_undecidable`; a non-public origin is `declined`; a refused
    read is `unavailable`. `off` writes nothing (nobody asked)."""
    import api_diff_intersection as ci                       # ⭐ ships beside this script, in the same scan pack
    for m in gate2.get("moved") or []:
        a, b = m.get("from"), m.get("to")
        if not a or not b:
            continue                                     # added or removed, not moved: no pair to compare
        cross = policy.crosses_major(eco, str(a), str(b))
        if cross is False or mode == CO_OFF:
            continue
        if m.get("downgrade"):
            m["api_diff"] = {"state": "not_requested", "reason": "downgrade_pair"}
            continue
        if cross is None:
            m["api_diff"] = {"state": "not_requested", "reason": "version_undecidable"}
            continue
        if mode == CO_CI:
            m["api_diff"] = {"state": "not_requested", "reason": "ci_second_resolve"}
            continue
        origin = _origin_of(copy_root, lock_file, eco, m["package"], str(b))
        if not locks.is_public(origin):
            m["api_diff"] = {"state": "declined", "reason": "origin_" + str((origin or {}).get("verdict") or "unknown")}
            continue
        argv = ["remediation-plans", "api-diff", "get", "--ecosystem", eco, "--package", m["package"],
                "--from", str(a), "--to", str(b), "--origin-source", str(origin.get("source") or ""),
                "--origin-url", str(origin.get("url") or "")] + (["--request"] if mode == CO_REQUEST else [])
        try:
            view = rp._cli_json(argv, dict)
        except RuntimeError as exc:                      # ⚠️ a refusal is not a crash (quota, queue, extractor)
            m["api_diff"] = {"state": "unavailable", "reason": str(exc)[:200]}
            continue
        diffs: List[Dict[str, Any]] = []
        holder: Dict[str, Any] = {}
        rp._apply_view(holder, view, diffs)
        if not diffs:
            m["api_diff"] = holder.get("api_diff") or {"state": "not_requested"}
            continue
        if not primary_root:
            m["api_diff"] = {"state": "unavailable", "reason": "no primary tree to check"}
            continue
        if "usage" not in cache:
            cache["usage"] = ci.usage_for(primary_root)
        m["api_diff"] = ci.intersect(diffs[0], cache["usage"], ci.reader(primary_root), package=m["package"],
                                     ecosystem=eco)


def _co_mover_hits(gates2: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{**m, "lock": g["lock"]} for g in gates2 for m in g.get("moved") or []
            if (m.get("api_diff") or {}).get("verdict") == "4"]


def run_group(plan: Dict[str, Any], work: Dict[str, Any], apply: bool, work_dir: Optional[str],
              probe: bool = True, allowed_files: Optional[Dict[str, set]] = None) -> Dict[str, Any]:
    """`allowed_files` (a server plan, `--plan-id`) replaces gate 3's derivation: the plan's own allowed set."""
    rows, cls = work["rows"], work["class"]
    # ⛔ THE SUBSTITUTION HAPPENS BEFORE `_edits(work)` (M1 / D10), and the order is the whole fix.
    # `_edits` reads `row["edits"]` only, which a class-4 row stores EMPTY — the planner moved the bump
    # to `blocked_edits` to record "this needs code before the bump is safe". Phase 5 supplies that
    # code, so the bump is now applied and must ride WITH it: a PR carrying rewritten source and no
    # version bump fixes nothing, because the vulnerable version still resolves.
    # ⚠️ Doing it after `_edits` would leave `edits` empty, so the needs_human guard would judge
    # nothing, `report["edits"]` would list nothing, and `copies` would be keyed off an empty set.
    # ⭐ ONE FACT, ONE NAME. Gate 3's lane needs to know this happened (a class-4 PR now carries the
    # manifest bump as well as the rewrite), and deriving it a second time from `codemod_files` was
    # wrong in both directions: it said yes for a run whose codemod rewrote nothing but still bumped,
    # and the two conditions could drift apart silently.
    bump_substituted = str(cls) == "4" and apply and CODEMOD != "off"
    if bump_substituted:
        rows = [{**r, "edits": list(r.get("edits") or r.get("blocked_edits") or [])} for r in rows]
        work = {**work, "rows": rows}
    edits, locks = _edits(work), _locks(work)
    # ⛔ LOCALITY: phase 5 v1 IS L1 — the subject is the target, so the rewritten files and the bump
    # share one repository, one plan and one lane (M8). A cross-repo class-4 fix is refused BEFORE any
    # copy is made, because the lane guard, the content check and the commit all assume one repo; L2–L4
    # are § 3.12.10. ⚠️ Stated with both sides named, so the reader knows what to do by hand.
    if bump_substituted:
        others = {e["repo"] for e in edits} | {lk["repo"] for lk in locks}
        # ⚠️ `plan["repo"]` is the subject and `plan_input` always sets it, but a caller may build a
        # plan from `scope` alone; `scope[0]` IS the subject by construction (`plan_input` puts it
        # first). Falling back there keeps the gate working instead of raising KeyError on a lean plan.
        subject_repo = plan.get("repo") or ((plan.get("scope") or [{}])[0] or {}).get("repo")
        stray = (others - {subject_repo}) if subject_repo else set()
        if stray:
            return {"group": work["index"], "class": cls, "dev_only": work["dev_only"],
                    "packages": [{"package": r["package"], "installed": r.get("installed"),
                                  "target": r.get("target")} for r in rows],
                    "edits": [], "locks": [], "branch": branch_name(work), "applied": False,
                    "status": "code_change_required",
                    "codemod": _cmr.unavailable(
                        "codemod_cross_repo",
                        f"the code that must change is in {plan['repo']}, the bump in "
                        f"{', '.join(sorted(stray))}")}
    # ⛔ THE EARLY RETURN IS NOW ONLY THE DRY RUN AND `--codemod off`. Before phase 5 every class-4
    # group returned here, which was right while nothing could change code; returning here WITH the
    # codemod available would refuse to fix exactly the rows the codemod exists for.
    if str(cls) == "4" and (not apply or CODEMOD == "off"):
        # ⛔ NEVER APPLIED, AND REPORTED RATHER THAN SKIPPED SILENTLY. A class-4 package's upgrade changes
        # an API this repository calls: a person has to edit code, so there is nothing here to apply and
        # no lock to recompile. ⚠️ `edits` is deliberately EMPTY on the row (the planner moved them to
        # `blocked_edits`), so applying it would recompile the lock this package was classified AWAY from
        # — the one outcome this whole classification exists to prevent.
        # ⭐ A row in the report, not an omission: a finding that vanishes from the output reads as
        # "nothing to do", while `class_4_skipped` reads as "work for a person", which is what it is.
        return {"group": work["index"], "class": cls, "dev_only": work["dev_only"],
                "packages": [{"package": r["package"], "installed": r.get("installed"),
                              "target": r.get("target"),
                              **({"api_diff": r["api_diff"]} if r.get("api_diff") else {})}
                             for r in rows],
                "edits": [], "locks": [], "branch": branch_name(work), "applied": False,
                "status": "class_4_skipped",
                "why": (rows[0].get("why") if rows else None)
                       or "the upgrade changes an API this repository calls; a person must change the code",
                "blocked_edits": [e for r in rows for e in (r.get("blocked_edits") or [])],
                # ⚠️ `not_run` and `complete` must never read alike: "nobody looked" is not "looked,
                # nothing to do".
                "codemod": _cmr.not_run()}
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
        # ⭐ REPORTED, NOT RETURNED (M1). This branch used to STOP here with `code_change_required`,
        # `gates_not_applicable` and `GATE_NOT_APPLICABLE_4` — correct while nothing could change code,
        # and fatal once something could: it returns BEFORE the codemod at the bottom of this function,
        # so the whole phase-5 runner was unreachable in the one lane it exists for.
        # ⛔ MEASURED 2026-10-31 (runbook § 1b): a real class-4 plan (litellm 1.82.6 → 1.95.1, both call
        # sites stamped `4a rename decode → decode_token` in `api_diff.touched`) came back
        # `status: code_change_required`, `codemod: None`, `gate_5_coverage: "class 4 changes no file
        # without a codemod"` — every one of those a true sentence about a run that simply never happened.
        # Nothing said the codemod had been skipped, because from here it looks identical to a class 4
        # that nobody asked to fix.
        # ⚠️ The dry-run and `--codemod off` cases DO still stop, earlier and on purpose (`:1600`), which
        # is why there is no `CODEMOD` test here: by this line the codemod is going to be attempted, the
        # bump has already been substituted onto the rows (D10, above), and gates 1-3 therefore judge a
        # REAL resolve. Only the two reporting keys belong on the report.
        report["api_diff"] = [r["api_diff"] for r in rows if r.get("api_diff")]
        report["blocked_edits"] = [e for r in rows for e in r.get("blocked_edits") or []]
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
    # ⭐ THE OVERRIDE KEY, decided on the unmodified tree and recorded (B54). A key nobody can write safely stops
    # the group here, before anything is copied: a plain key would drag the package's other lines.
    keys = {}
    for lk in locks:
        for pkg, k in npm_override_keys(scope[lk["repo"]], lk, [r for r in rows if _on(lk, r)], cls).items():
            keys[pkg] = k
    if keys:
        report["override_keys"] = keys
    stuck = [f"{p}: {k['needs_human']}" for p, k in keys.items() if not k.get("key")]
    stuck += [w for w in (forced_across_major(r) for r in rows) if w]
    if stuck:
        report.update(status="needs_human", why="; ".join(stuck))
        return report
    rows = [{**r, "override_key": keys[r["package"]]["key"]} if r["package"] in keys else r for r in rows]
    if not apply:
        report["status"] = "dry_run"
        return report

    repos = sorted({e["repo"] for e in edits} | {lk["repo"] for lk in locks})
    group_dir = os.path.join(work_dir, f"group-{work['index']}")
    copies = {repo: os.path.join(group_dir, copy_label(repo)) for repo in repos}
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
        # ⛔ THE LOCK MUST BE CURRENT BEFORE A FIX IS RESOLVED INTO IT (`rp.lock_freshness`, the planner's same
        # computation). Judged on the UNMODIFIED tree (`scope`), in a scratch copy, before any write or push: a stale
        # lock's re-lock would ride inside this fix (a Python service, 2026-10-29: certifi + 32 packages) and only the
        # platform's lane, after the push, would object. ⚠️ `probe_summary` needs no change for this: a declined
        # group is never proposed, so its gate-2 "moved" never becomes stored co-movers.
        if LOCK_CHECK:
            fresh = rp.lock_freshness(scope[lk["repo"]], lk, _run, os.path.join(group_dir, "lock-check"))
            report.setdefault("lock_check", []).append({"lock": name, **{k: fresh[k] for k in
                                                                         ("state", "why", "cmd") if k in fresh}})
            if fresh["state"] == rp.STALE:
                gates1.append({"lock": name, "ok": False, "declined": "lock_stale",
                               "why": f"{fresh['why']}. To fix: {fresh['remedy']}", "remedy": fresh["remedy"],
                               "would_move": fresh["moved"]})
                continue
            if fresh.get("timed_out"):
                # The existing decline for a resolver that never finished: the fix's own resolve would spend the
                # same cap again on the same lock.
                gates1.append({"lock": name, "ok": False, "declined": "resolver_timeout", "why": fresh["why"]})
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
        eco = "npm" if lk["lock_format"] == "npm" else "pypi"
        gates2.append({"lock": name, **gate_blast_radius(before[key], after, mine, eco)})
        co_mover_api_diffs(gates2[-1], copies[lk["repo"]], lk["file"], eco,
                       scope.get(plan.get("repo") or ""), cache, CO_MOVER_API_DIFFS)
    report["resolver"] = runs
    report["gate_1_resolve"] = gates1
    report["gate_2_blast_radius"] = gates2
    # ⭐ THE CODEMOD RUNS HERE: after gate 2 (the bump is applied and its blast radius known) and
    # BEFORE gate 3, because the lane guard must see the rewritten source files as allowed. Running it
    # after gate 3 would have the lane refuse the very files the codemod just wrote.
    codemod_files: List[str] = []
    if cls == "4" and CODEMOD != "off":
        subject = plan.get("repo") or ((plan.get("scope") or [{}])[0] or {}).get("repo")
        report["codemod"] = _cmr.run_codemods(copies.get(subject) or "", rows,
                                              l2=_l2_for(plan, work, copies, subject, scope),
                                              usage=_usage_for(copies, subject, cache))
        codemod_files = [f["file"] for f in report["codemod"].get("files") or []]
        # ⚠️ A REFUSED BLOCK STOPS THE GROUP. `run_codemods` has already restored every touched file,
        # so the copy holds the bump alone — which must not be proposed: a plan claiming a code change
        # it does not carry is worse than no plan (§ 3.4.2).
        if report["codemod"]["state"] in ("refused", "unavailable"):
            report["status"] = "code_change_required"
            report["why"] = report["codemod"]["words"]
            return report
    changes = {repo: changed_files(scope[repo], copies[repo]) for repo in repos}
    allowed: Dict[str, set] = {}
    for lk in locks:
        allowed.setdefault(lk["repo"], set()).add(lk["file"])
    # ⛔ CLASS 4 BELONGS HERE TOO, since phase 5. Its PR carries the manifest bump beside the rewrite —
    # "a PR carrying rewritten source and no version bump fixes nothing, because the vulnerable version
    # still resolves" — so the bump's own file must be IN the lane.
    # ⚠️ MEASURED 2026-10-31 (runbook § 1b) before this line existed: a real class-4 run rewrote both
    # call sites, passed L0 and L1, and then failed gate 3 with `outside_lane:
    # ["gateway/pyproject.toml"]` and `why: "the classification was wrong: re-queue for triage"` — the
    # most misleading message available, since the classification was right and the lane was stale.
    if cls == "3" or (cls == "4" and bump_substituted):
        for e in edits:
            allowed.setdefault(e["repo"], set()).add(e["file"])
    if allowed_files is not None:
        allowed = allowed_files
    elif codemod_files:
        # ⚠️ ONLY when the plan did not supply its own allowed set: for a server plan the plan's
        # `allowed_files` already carries the codemod files (§ 3.6.4) and `exact=True` must stay, or
        # the lane would accept a file the approved plan never listed.
        subject = plan.get("repo") or ((plan.get("scope") or [{}])[0] or {}).get("repo")
        allowed.setdefault(subject, set()).update(codemod_files)
    # ⚠️ `codemod_lane` is "this class-4 run has a lane at all", NOT "it rewrote a file". A run whose
    # every site came back `no_change` (D4's `call_safe`) legitimately produces `files: []` and a
    # bump-only PR (§ 3.4.7); keying on the file list would blank its lane and reject the bump.
    report["gate_3_lane"] = gate_lane(cls, changes, allowed, scope, copies,
                                      exact=allowed_files is not None,
                                      codemod_lane=bool(codemod_files) or bump_substituted)
    report["diff"] = write_diff(scope, copies, changes, os.path.join(group_dir, "changes.diff"))
    downgrades = [{**d, "lock": g["lock"]} for g in gates2 for d in g["downgrades"]]
    co_hits = _co_mover_hits(gates2)
    # ⭐ GATES 4 AND 5, on the applied copies, with the project's own discovered commands. Every step is
    # reported — passed, failed, error, not_detected or unsupported — because an omitted check reads as a
    # passed one (FD § "The PR body is assembled, not written").
    subject_for_cov = plan.get("repo") or ((plan.get("scope") or [{}])[0] or {}).get("repo") or ""
    cov_req = coverage_request(copies, subject_for_cov, report.get("codemod"), group_dir)
    report["gate_4_build"], report["gate_5_tests"] = (
        # The baseline's copies sit BESIDE the group dir, so no repository label can collide with them.
        gate_build_and_tests(copies, scope, f"{group_dir}-baseline", cov=cov_req) if GATES_45
        else (gate_not_requested(), gate_not_requested()))
    # ⭐ COVERAGE OF THE REWRITTEN LINES, which gates 4 and 5 cannot answer: a green suite proves the project
    # still works, never that it went near the lines the codemod rewrote. Reported on EVERY report, including
    # the class-2 and class-3 ones where it can only say "nothing was rewritten" — an omitted check reads as a
    # passed one.
    report["gate_5_coverage"] = gate_coverage_of_codemod(
        copies, subject_for_cov, report.get("codemod"), report["gate_5_tests"])
    attach_assumptions(report)
    unavailable = [g for g in gates1 if g.get("declined")]
    failed = next((n for n, g in (("1", [x for x in gates1 if not x.get("declined")]),
                                  ("3", [report["gate_3_lane"]])) if not all(x["ok"] for x in g)), None)
    if failed:
        report["status"] = f"failed_gate_{failed}"
    elif unavailable:
        report.update(status="declined", decline=unavailable[0]["declined"],
                      why="; ".join(f"{g['lock']}: {g['why']}" for g in unavailable))
    elif downgrades or co_hits:
        whys = (["a package moves backwards: " + ", ".join(f"{d['package']} {d['from']} → {d['to']}"
                                                            for d in downgrades)] if downgrades else [])
        # ⛔ W3-14 (c): a co-mover whose changed API this repository calls is a code change nobody asked for.
        whys += [f"{h['package']} {h['from']} → {h['to']} changes {len((h['api_diff'] or {}).get('touched') or [])} "
                 f"symbol(s) this repository calls" for h in co_hits]
        report.update(status="needs_human", why="; ".join(whys))
    else:
        report["status"] = "gates_passed"
    if downgrades:                                       # ⛔ first in the report, and first in the PR body
        report = {"downgrades": downgrades, **report}
    # ⛔ GATES 4 AND 5 NEVER ABORT, and `status` is deliberately untouched here. Gates 1-3 decide whether a
    # PR may open at all; these two decide whether it opens as a DRAFT with the output (FD § "What runs
    # before the PR opens"). A build we could not RUN is not a build that failed, so the reason travels with
    # the flag rather than being collapsed into a status word.
    # ⛔ ONLY A GATE WE ACTUALLY TRIED DRAFTS THE PR — `failed` (it ran, the project is broken) or `error` (it
    # could not run, so the fix is unjudged). ABSENCE IS STATED, NOT DRAFTED: `not_detected` / `unsupported`
    # means this repo has no suite we can run, and drafting on that would draft every PR into such a repo for
    # ever while telling the reviewer nothing new (FD: no suite → "the job says so in the body"). `not_run`
    # likewise — a gate nobody asked for, or a suite skipped because its own install already failed and is
    # already drafting, is not a second finding. Caught by its own test: the common path had `draft` set.
    _mark_unproven(report)
    if failed == "1" and probe:
        return _fallback(plan, work, report, work_dir, allowed_files)
    return report


def _mark_unproven(report: Dict[str, Any]) -> None:
    """A gate 4/5 we tried and that failed or errored drafts the PR, with the output (see `run_group`)."""
    unproven = draft_unproven(report)
    if unproven:
        report["draft"] = True
        report["draft_why"] = "; ".join(f"gate {n}: {g['status']} — {g['why']}" for n, g in unproven)


# ── probing a refused bound (the brief's resolve half) ───────────────────────────────────────────

def select_declined(plan: Dict[str, Any], groups: List[int], packages: List[str]) -> List[Dict[str, Any]]:
    """The rows the planner refused with `edit_needs_human` — the ONLY rows a bound probe applies to.

    ⛔ Deliberately not folded into `select`. That function feeds `run_group`, which must refuse an edit
    nobody can complete, and it does so before any tree is copied. A probe wants the opposite: fill the
    value in on purpose, in a scratch copy, to find out what it would cost.
    """
    want = {p for p in packages}
    out = []
    for r in plan.get("rows") or []:
        if r.get("verdict") != rp.DECLINED or r.get("decline") != "edit_needs_human":
            continue
        if want and r["package"] not in want and normalize(r["package"]) not in want:
            continue
        if any(e.get("needs_human") or e.get("to") is None for e in r.get("edits") or []):
            out.append(r)
    return out


def _compiled_lock(row: Dict[str, Any], edit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The lock that is COMPILED FROM the manifest this edit changes, or None.

    ⛔ THE PAIRING IS THE WHOLE CORRECTNESS OF THE PROBE, and the row's own lock is usually the wrong
    answer.
    #| Measured on a real two-repository case: one row of a package resolved in a service's own
    #| `uv.lock`, while the declaration blocking it lived in a SHARED base image's `requirements.in`.
    #| The service's lock is compiled from its own manifest and never reads the shared one, so
    #| recompiling it after editing that file would measure a file the edit cannot affect and report
    #| the result as if it meant something. Only the sibling row whose lock IS the shared lock could
    #| be probed, and the other is refused.
    """
    for lk in row.get("locks") or []:
        if lk.get("repo") == edit.get("repo") and lk.get("compiled_from") == edit.get("file"):
            return lk
    return None


def _probe_resolve(copy: str, lk: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
    """Recompile one lock, upgrading `pkg` with NO version pinned.

    ⛔ NOT `resolve()`, and the difference is the point. That function pins `--upgrade-package pkg==target`
    because a plan has a target to land on. A probe must answer a different question — *what happens if a
    person lifts this bound and recompiles* — and the answer is usually NOT the target: measured on
    starlette, lifting `<1.0` for a fix published at 1.3.1 lands on **1.10.0**. Pinning `==1.3.1` would
    have reported 1.3.1 and hidden the seven minor versions nobody asked for.

    ⚠️ The existing lock stays the preference set (pip-compile's own `-o` argv, uv's own lock), so only
    `pkg` and whatever it drags move. A naked recompile re-resolves every floor to latest — measured the
    same day: 288 pins moved, `certifi` among them.
    """
    lock = os.path.join(copy, lk["file"])
    cwd = os.path.dirname(lock)
    fmt = lk["lock_format"]
    if fmt == "uv":
        return [_run(["uv", "lock", "--no-progress", "--upgrade-package", pkg], cwd)]
    if fmt == "pip-compile":
        return [_run(rp.header_argv(lock) + ["--upgrade-package", pkg], cwd)]
    return [{"cmd": None, "rc": 2, "output": f"no bound probe for {fmt}: uv and pip-compile only"}]


def probe_bound(plan: Dict[str, Any], row: Dict[str, Any], work_dir: str) -> Dict[str, Any]:
    """Measure what lifting a refused bound would cost. ⛔ A MEASUREMENT, NEVER A PROPOSAL.

    The planner refuses an upper bound because picking its new value is a human judgement
    (`propose_spec`), and that refusal is unchanged by this. But refusing to CHOOSE a value is not a
    reason to refuse to MEASURE with one: this writes a provisional spec into a scratch copy, recompiles,
    reports what moved, and recommends nothing. The provisional value is named in the output so no reader
    can mistake it for an answer.
    """
    out: Dict[str, Any] = {"package": row["package"], "installed": row.get("installed"),
                           "target": row.get("target"), "measurement_only": True}
    target = row.get("target")
    stuck = [e for e in row.get("edits") or [] if e.get("needs_human") or e.get("to") is None]
    if not target or not stuck:
        return {**out, "status": "refused", "why": "no blocking edit with a target to probe"}
    pairs = [(e, _compiled_lock(row, e)) for e in stuck]
    unpaired = [e for e, lk in pairs if lk is None]
    if unpaired:
        # ⛔ REFUSE, never fall back to the row's own lock. See `_compiled_lock`.
        e = unpaired[0]
        return {**out, "status": "not_probeable",
                "why": f"no lock in this plan is compiled from {e['repo']}/{e['file']}, so recompiling "
                       f"anything here would measure a file this edit cannot affect"}
    if any(e.get("syntax") not in (None, "", "pep508") for e, _ in pairs):
        return {**out, "status": "not_probeable", "why": "bound probing is pep508 only for now"}
    try:
        scope = scope_trees(plan, work_dir)
    except Refused as exc:
        return {**out, "status": "refused", "why": str(exc)}
    copies = {repo: os.path.join(work_dir, "probe", copy_label(repo)) for repo in scope}
    for repo, src in scope.items():
        _fresh_copy(src, copies[repo])
    provisional, runs, moved, landed = [], [], [], {}
    for e, lk in pairs:
        # ⭐ The probe value: "at least the published fix". It is the edit a person would most likely make,
        # and naming it in the report is what keeps this a measurement rather than a recommendation.
        spec = f">={target}"
        provisional.append({"repo": e["repo"], "file": e["file"], "line": e["line"],
                            "from": e.get("from"), "probed_with": spec,
                            "lock": f"{lk['repo']}/{lk['file']}"})
        before = _resolved(scope[lk["repo"]], lk["file"])
        try:
            # ⚠️ `package` / `ecosystem` live on the ROW, not the edit — `_edits()` is what normally
            # merges them in, and the writers need them to prove they changed the right line.
            apply_edit(copies[e["repo"]], {**e, "to": spec, "needs_human": None,
                                           "package": row["package"], "ecosystem": row["ecosystem"]})
        except Refused as exc:
            return {**out, "status": "refused", "why": f"the provisional edit was refused: {exc}"}
        rs = _probe_resolve(copies[lk["repo"]], lk, row["package"])
        runs += rs
        if any(r.get("rc") for r in rs):
            return {**out, "status": "does_not_resolve", "provisional": provisional, "resolver": runs,
                    "why": "the resolver refused the lifted bound; no combination satisfies it"}
        after = _resolved(copies[lk["repo"]], lk["file"])
        for key, v in sorted(after.items()):
            was = before.get(key)
            if was is None or was == v:
                continue
            entry = {"package": key[0], "from": was, "to": v, "lock": f"{lk['repo']}/{lk['file']}"}
            (landed.setdefault(key[0], entry) if key[0] == row["package"] else moved.append(entry))
    return {**out, "status": "resolves", "provisional": provisional, "landed": landed,
            "also_moved": moved, "resolver": runs,
            # ⛔ NEVER OMITTED. A resolve is not a build and not a test run.
            "not_established": ["whether the fleet builds and starts against this",
                                "whether the new version's removed APIs are reached indirectly",
                                "whether the bound's stated reason still holds"]}


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
    """The `torana` CLI, by the scan pack's ONE lookup (`reachability_pass.torana_cli`)."""
    from reachability_pass import torana_cli
    return torana_cli()


def torana(args: List[str]) -> Tuple[int, Any, str]:
    """(rc, parsed stdout or None, stderr). The CLI prints the server's error code as `(code, HTTP n)`.

    ⭐ The CLI inherits this process's environment, so with `TORANA_TOKEN_CMD` set EVERY call, the first GET
    included, takes its token from that command (the action strips TORANA_TOKEN from apply's env); only the
    resolvers get a scrubbed environment (`resolver_env`)."""
    try:
        p = subprocess.run([torana_bin(), *args], capture_output=True, text=True)
    except FileNotFoundError:
        return 127, None, "the torana CLI was not found ($TORANA, $TORANA_VENV/bin/torana, ~/.torana-venv, PATH)"
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
            # ⛔ `blocked_edits` IS INDEXED HERE TOO, and without it a stored CLASS-4 plan cannot be
            # applied at all (M1 (a)). A class-4 row carries `edits: []` and its bump in
            # `blocked_edits` — that is how the planner records "this needs code before the bump is
            # safe". The plan's `effective_edits` still names that bump, so looking it up in `edits`
            # alone found nothing and the next loop raised
            # `Refused: effective edit uv.lock:12 matches no stored planner row edit`.
            # MEASURED 2026-10-30 before the fix: exactly that refusal, on a minimal stored row.
            # ⚠️ Phase 5 is what makes this reachable: before it, class 4 never got past the planner,
            # so the dead path was invisible. Now the codemod supplies the code change and the bump
            # MUST ride with it — a PR with the source edit and no version bump fixes nothing.
            for e in (row.get("edits") or []) + (row.get("blocked_edits") or []):
                planner_edits.setdefault((e["file"], e["line"]), {**e, "package": row["package"]})
            # ⛔ `blocked_edits` IS STRIPPED from the merged row (M1 (b)). It is the planner's record of
            # a bump it would not apply; once the codemod has run, the bump IS applied and `edits`
            # carries it. Leaving the key behind would make the applier read the row as still blocked
            # and skip the very group it just fixed — two sources of truth for one decision.
            m = merged.setdefault((row["ecosystem"], row["package"]), {
                **{k: v for k, v in row.items() if k not in ("partial", "requested_target", "open_alert_ids",
                                                             "refusal_output", "edits", "blocked_edits",
                                                             "locks")},
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


# ── EM D-23 S3: the remediate Action's review lane (review_case.py has the case itself) ─────────────────────────

def run_review_case(a: argparse.Namespace, rec: Dict[str, Any], plan: Dict[str, Any], work: Dict[str, Any],
                    roots: Dict[str, str], subject: str, apply_once) -> int:
    """`--review-case DIR` (job 1): gates 1-3 on a scratch copy, then write the case for jobs 2 and 3. ⛔ NO TORANA
    WRITE: the plan was read with `get`, and nothing here leases, proposes or opens. A group that did not pass gates
    1-3 writes no case (job 3 would refuse it anyway); the JSON says why."""
    report = apply_once()
    out: Dict[str, Any] = {"plan_id": rec["id"], "mode": "review-case", "status": report.get("status")}
    why = _ready_to_open(rec, report)
    if why:
        out.update(case=None, why=why)
    else:
        group_dir = os.path.join(os.path.abspath(a.work), f"group-{work['index']}")
        copies = {r: os.path.join(group_dir, copy_label(r)) for r in roots
                  if os.path.isdir(os.path.join(group_dir, copy_label(r)))}
        try:
            case = _case.write_case(os.path.join(os.path.abspath(a.review_case), rec["id"]), rec=rec, subject=subject,
                                 plan=plan, group_index=int(work["index"]), report=report, copies=copies,
                                 roots=roots, api_diffs=API_DIFF_DOCS)
        except _case.CaseError as exc:
            out.update(case=None, why=str(exc))
        else:
            out.update(case=os.path.join(os.path.abspath(a.review_case), rec["id"]), digest=case["digest"],
                       bases=case["bases"])
    print(json.dumps(out, indent=2) if a.as_json else f"{rec['id']}: review case {out.get('case') or out.get('why')}")
    return 0


def run_gates_from_case(a: argparse.Namespace) -> int:
    """`--gates-from-case DIR`: gates 4/5 on each case's applied trees against its base trees, written as `gates.json`
    beside `case.json`. It only reads the case and runs the project's own commands, exactly as `--open-pr --gates-45`
    would have. ⚠️ Since EM D-23 S3 d2 the remediate Action no longer calls it (no gates job: the PR's own CI runs
    them, `GATES_45_WHY_PR_CI`); it stays for a laptop that wants gates 4/5 on a case it holds."""
    root = os.path.abspath(a.gates_from_case)
    cases = [root] if os.path.isfile(os.path.join(root, "case.json")) else \
        [os.path.join(root, d) for d in sorted(os.listdir(root)) if os.path.isfile(os.path.join(root, d, "case.json"))]
    out = []
    for cd in cases:
        with open(os.path.join(cd, "case.json"), encoding="utf-8") as fh:
            case = json.load(fh)
        labels = case.get("labels") or {}
        # The case carries no symlink (review_case.write_case); the safe in-tree ones come back for the build.
        skipped_links = _case.restore_links(cd, case)
        if skipped_links:
            log(f"{case['plan_id']}: {len(skipped_links)} recorded symlink(s) not recreated (absolute or leaving "
                f"the tree): gates 4/5 run without them")
        copies = {repo: os.path.join(cd, "trees", lb) for lb, repo in labels.items()}
        scope = {repo: os.path.join(cd, "base", lb) for lb, repo in labels.items()}
        with open(os.path.join(cd, "report.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        work_dir = os.path.join(os.path.abspath(a.work or os.path.join(cd, "..", ".gates-work")), case["plan_id"])
        os.makedirs(work_dir, exist_ok=True)
        gates = run_gates_45_on(report, copies, scope, os.path.join(work_dir, "group"), case.get("subject") or "")
        doc = {"plan_id": case["plan_id"], "digest": case["digest"], **gates}
        _write(os.path.join(cd, "gates.json"), doc)
        out.append({"plan_id": case["plan_id"], **{k: (v or {}).get("status") for k, v in gates.items()}})
    print(json.dumps({"mode": "gates-from-case", "cases": out}, indent=2) if a.as_json else
          "\n".join(f"{o['plan_id']}: gate 4 {o.get('gate_4_build')}, gate 5 {o.get('gate_5_tests')}" for o in out))
    return 0


def run_gates_45_on(report: Dict[str, Any], copies: Dict[str, str], scope: Dict[str, str], group_dir: str,
                    subject: str) -> Dict[str, Any]:
    """Gates 4/5 and the rewritten-lines coverage on applied `copies` against `scope`, as `run_group` runs them."""
    cov_req = coverage_request(copies, subject, report.get("codemod"), group_dir)
    g4, g5 = gate_build_and_tests(copies, scope, f"{group_dir}-baseline", cov=cov_req)
    return {"gate_4_build": g4, "gate_5_tests": g5,
            "gate_5_coverage": gate_coverage_of_codemod(copies, subject, report.get("codemod"), g5)}


def merge_gates(report: Dict[str, Any], gates: Optional[Dict[str, Any]], why_missing: str) -> Dict[str, Any]:
    """Job 3: the case's report with a gates file's results when one is given, the assumptions and the draft flag
    recomputed from them.
    No (matching) gates file → gates 4/5 `not_run` with `why_missing`, never a pass."""
    rep = dict(report)
    if gates:
        rep.update({k: gates[k] for k in _case.GATE_KEYS if k in gates})
    else:
        rep["gate_4_build"] = rep["gate_5_tests"] = {"status": "not_run", "why": why_missing}
    rep.pop("draft", None)
    rep.pop("draft_why", None)
    attach_assumptions(rep)
    _mark_unproven(rep)
    return rep


def open_from_case(a: argparse.Namespace, rec: Dict[str, Any], plan: Dict[str, Any], subject: str,
                   roots: Dict[str, str], work_dir: str, result: Dict[str, Any], renew) -> None:
    """`--open-pr --from-case DIR` (job 3), under the lease the caller holds. In order: the case is this plan's at
    this fingerprint; every base is still the HEAD of today's checkout and the trees are the reviewed ones (else
    NOT OPENED, no vet posted); job 4's gates merged; `_ready_to_open`; the vet posted; the files sent from the case.
    ⛔ `base_moved` from the platform is not retried here: a retry would mean resolving next to the token."""
    case_dir = os.path.join(os.path.abspath(a.from_case), rec["id"]) \
        if not os.path.isfile(os.path.join(a.from_case, "case.json")) else os.path.abspath(a.from_case)
    try:
        case = _case.load_case(case_dir, plan_id=rec["id"], fingerprint=str(rec.get("effective_fingerprint")))
        _case.check_case(case_dir, case, roots)
    except _case.CaseError as exc:
        result.update(status="not_opened", why=str(exc))
        return
    report = merge_gates(_case.load_report(case_dir), _case.gates_for(case_dir, getattr(a, "gates_file", None), case),
                         GATES_45_WHY_PR_CI)
    _write(os.path.join(work_dir, "probe-report.json"), {"groups": [report]})
    why = _ready_to_open(rec, report)
    if why:
        result.update(status="not_opened", why=why, report=report)
        return
    stop = store_review(rec, getattr(a, "vet", None), getattr(a, "overrule_refusal", None), result)
    if stop:
        status, _rc, why, nxt = stop
        result.update(status=status, why=why, next=nxt)
        return
    if not renew():
        result.update(status="not_opened", why="the lease was lost before the PR was opened")
        return
    target = rec["target_repository"]
    label = next((lb for lb, repo in (case.get("labels") or {}).items() if repo == target), copy_label(target))
    rc_o, out, err = torana(["remediation-plan", rec["id"], "open-pr", "--diff", report["diff"],
                             "--root", os.path.join(case_dir, "trees", label),
                             "--probe", os.path.join(work_dir, "probe-report.json"),
                             "--base-sha", case["bases"][target], "--base-branch", a.base_branch, "--format", "json"])
    code = error_code(err)
    if rc_o == 0:
        result.update(status="opened", pr=out)
    elif code in ("plan_stale", "content_outside_lane"):
        result.update(status="re-probed", why=code,
                      propose_rc=propose_refresh(rec, plan, report, subject, work_dir))
    elif code == "base_moved":
        result.update(status="not_opened", why="base_moved: the target moved while the PR was being opened; the next "
                                                "run reviews it again")
    elif code == "pr_pending":
        result.update(status="pr_pending", why="the platform is still opening it; the next run records it")
    elif code == "vet_refused":
        result.update(status="refused_by_review", why=err.strip()[-400:],
                      next="nothing was opened. Read the review on the plan; re-plan, or a person who may approve "
                           "plans overrules it with --overrule-refusal")
    else:
        result.update(status="error", rc=rc_o, why=err.strip()[-800:])


def run_plan_id(a: argparse.Namespace) -> int:
    rc, rec, err = torana(["remediation-plan", a.plan_id, "get", "--format", "json"])
    if rc != 0 or not isinstance(rec, dict):
        log(f"ERROR: cannot read plan {a.plan_id}: {err.strip()}")
        return rc or 1
    # ⛔ A CLASS-4 PLAN IS NOT APPLICABLE, and the refusal is explicit rather than a no-op. Its whole
    # content is "a person must change code": it carries no edits and no command, so letting the run
    # proceed would produce an empty success — a branch with nothing on it, and a reader concluding the
    # fix had landed. Exit 2 with a named reason instead.
    if str(rec.get("remediation_class") or "") == "4" or rec.get("class4_package"):
        log(f"ERROR: class_4_not_applicable: plan {a.plan_id} is class 4"
            + (f" ({rec.get('class4_package')})" if rec.get("class4_package") else "")
            + ": the upgrade changes an API the repository calls, so it is fixed by a person editing code, "
              "not by this script. Nothing was applied.")
        return 2
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
    if getattr(a, "review_case", None):
        return run_review_case(a, rec, plan, work, roots, subject, apply_once)
    # ⛔ The PLATFORM half only (no local root): in the --open-pr lane Torana's App pushes, so a local `gh` login proves
    # nothing, and a CI container has none (EM D-23 S3 L1, F-L1-3). The laptop push lanes (run_commit,
    # run_follow_up) still check this machine can push.
    not_ready = github_not_ready(rec["id"], None)
    if not_ready:
        for c in not_ready["checks"]:
            log(f"NOT READY: {c['words']} — fixes it: {c['who_fixes']}")
            if c.get("admin_detail"):
                log(f"    For your Torana administrator: {c['admin_detail']}")
        result = {"plan_id": rec["id"], "mode": "open-pr", "status": "not_ready", **not_ready}
        print(json.dumps(result, indent=2) if a.as_json else f"{rec['id']}: not_ready {not_ready['why']}")
        return EXIT_NOT_READY
    holder =a.holder_run or f"local:{socket.gethostname()}:{os.getpid()}"
    rc, lease, err = torana(lease_acquire_args(rec["id"], holder))
    if rc == 4:
        log(f"skip {rec['id']}: {err.strip()}")
        return 0
    if rc != 0 or not isinstance(lease, dict):
        log(f"ERROR: lease: {err.strip()}")
        return rc or 1

    def _renew_open_pr() -> bool:
        """⚠️ ONLY rc 0 is a yes: a transport failure is not a licence to keep the customer's code running
        inside a mutex we may have lost."""
        _lid = (lease or {}).get("id") or (lease or {}).get("lease_id")
        if not _lid:
            return True                                  # no lease to prove; the caller never took one
        rc_r, _, _ = torana(lease_renew_args(_lid, holder))
        return rc_r == 0

    set_gate_renew(_renew_open_pr)
    lease_id = lease.get("id") or lease.get("lease_id")
    target = rec["target_repository"]
    result: Dict[str, Any] = {"plan_id": rec["id"], "mode": "open-pr"}
    try:
        if getattr(a, "from_case", None):
            # EM D-23 S3: the remediate Action's job 3 opens the tree jobs 2 and 4 judged, or nothing. No resolve and
            # no gate runs here, so no third-party code runs next to this job's Torana token.
            open_from_case(a, rec, plan, subject, roots, work_dir, result, _renew_open_pr)
            stop = True
        else:
            # ⭐ D-06 review M2: the SAME review step as --push-pr, before the platform opens anything. DF then drafts
            # the App's PR from it (and refuses a refused plan with 409 vet_refused).
            stop = store_review(rec, getattr(a, "vet", None), getattr(a, "overrule_refusal", None), result)
        if stop and stop is not True:
            status, _rc, why, nxt = stop
            result.update(status=status, why=why, next=nxt)
        for attempt in (1, 2) if not stop else ():
            try:
                report = apply_once()
            except LeaseLost as exc:
                # ⛔ OPEN NOTHING. Another run holds this repository's lease now, so proceeding would open a
                # second PR against a lock resolved from the same base — the lost update the lease prevents.
                # `not_opened` is the existing word for "we stopped on purpose", and exit 0 for the lane.
                result.update(status="not_opened", why=f"the lease was lost while the gates ran: {exc}")
                break
            why = _ready_to_open(rec, report)
            if why:
                result.update(status="not_opened", why=why, report=report)
                break
            head = rp._git_head(roots[target]) or ""
            # ⛔ PROVE WE STILL HOLD THE MUTEX IMMEDIATELY BEFORE THE OUTWARD-FACING CALL (B52). The last
            # renew ran BEFORE the final gate step, and that step may have taken its full 1200 s cap, so the
            # lease can be gone by now and another run can own this repository's lock file. Opening a PR then
            # is exactly the duplicate the lease exists to stop, and `open-pr` is irreversible.
            # ⚠️ ONLY THIS LANE. The laptop lane (`run_commit`) RELEASES the lease before `reserve-pr` on
            # purpose — from there the PR slot is held by the claim, not the lease — so a renew there would be
            # asking to extend a lease we have already given up.
            if not _renew_open_pr():
                result.update(status="not_opened", report=report,
                              why="the lease was lost after the gates ran, before the PR was opened")
                break
            rc, out, err = torana(["remediation-plan", rec["id"], "open-pr", "--diff", report["diff"],
                                   "--root", os.path.join(work_dir, "group-0", copy_label(target)),
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
            elif code == "vet_refused":
                result.update(status="refused_by_review", why=err.strip()[-400:],
                              next="nothing was opened. Read the review on the plan; re-plan, or a person who may "
                                   "approve plans overrules it with --overrule-refusal")
            else:
                result.update(status="error", rc=rc, why=err.strip()[-800:])
            break
    finally:
        # ⛔ DISARM BEFORE RELEASING. A hook left installed would renew a lease this run no longer holds on
        # the next library call of `run_group` — asking the server to extend somebody else's mutex.
        set_gate_renew(None)
        if lease_id:
            torana(["remediation-plans", "lease", "release", lease_id, "--holder-run", holder])
    print(json.dumps(result, indent=2) if a.as_json else f"{rec['id']}: {result['status']} {result.get('why', '')}")
    return 0 if result["status"] in ("opened", "re-probed", "pr_pending", "not_opened") else \
        2 if result["status"] == "refused_by_review" else 1


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
                 index_file: str, parent: Optional[str] = None) -> str:
    """A commit of exactly `changed` (paths relative to the repository root) as they are in `copy_root`, on
    `base_sha`, WITHOUT touching the developer's working tree, index or current branch: a temporary index,
    `hash-object -w`, `write-tree`, `commit-tree`. ⛔ Bytes as gated: `--no-filters`, so no clean filter or
    line-ending conversion rewrites what gate 3 judged. Raises Refused with git's own words.

    ⭐ D-22 `parent`: the TREE is still `base_sha` + the gated files, but the commit's parent is the open PR's head.
    So the PR's diff against its base is exactly the plan's lane, and the branch moves by a plain fast-forward."""
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
    rc, sha, err = git(top, "commit-tree", tree, "-p", parent or base_sha, "-F", "-", env=env, stdin=message)
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
    rc, lease, err = torana(lease_acquire_args(rec["id"], holder))
    if rc == 4:
        return done("busy", 4, f"another run holds this repository's lease: {err.strip()[-300:]}", "rerun later")
    if rc != 0 or not isinstance(lease, dict):
        return done("error", rc or 1, f"lease: {err.strip()[-300:]}", "check `torana auth me` and your permissions")
    lease_id = lease.get("id") or lease.get("lease_id")
    probe_path = os.path.join(work_dir, "probe-report.json")

    def _renew() -> bool:
        """Still ours? ⚠️ ONLY rc 0 is a yes — a transport failure is not a licence to keep going with
        the customer's code running inside a mutex we may have lost."""
        rc_r, _, _ = torana(lease_renew_args(lease_id, holder))
        return rc_r == 0

    set_gate_renew(_renew if lease_id else None)
    try:
        try:
            plan, work, allowed = plan_input(rec, {target: top}, target)
        except Refused as exc:
            return done("error", 1, str(exc))
        for s in plan["scope"]:
            if s["repo"] == target:              # ⛔ gate the bytes we commit on: origin/<base>, not the checkout
                s.update(ref=f"origin/{base}", commit=base_sha)
        # ⛔ A 4c HUNK CANNOT BE REPRODUCED FROM THE PLAN (M5). A model wrote it, so re-running the
        # codemod would produce something else — possibly correct, but not the thing a person
        # approved. The plan records the file's hashes, not its content, so without the drafts
        # directory there is nothing to re-apply and the commit must refuse rather than silently
        # commit a plan minus its model-authored half.
        stored_cm = (rec.get("codemod") or {})
        if any(f.get("model_authored") for f in (stored_cm.get("files") or [])) and not CODEMOD_DRAFTS:
            return done("refused", 2,
                        "codemod_drift: the 4c drafts are not available (--codemod-drafts); "
                        "re-run the triage flow's draft step",
                        "pass --codemod-drafts DIR with the accepted drafts from the probe run")
        try:
            report = run_group(plan, work, True, work_dir, allowed_files=allowed)
        except LeaseLost as exc:
            # ⛔ NOTHING IS OPENED. Another run owns this plan now; pushing a branch or opening a PR here
            # is exactly the duplicate the lease exists to prevent.
            return done("busy", 4, f"the lease was lost while the gates ran: {exc}",
                        "rerun later; another run holds this repository's lease")
        _write(probe_path, {"groups": [report]})
        drift = _codemod_drift(stored_cm, report.get("codemod") or {})
        if drift:
            # ⛔ NOTHING IS COMMITTED. The two halves of this check fail for opposite reasons and the
            # message says which, because the remedies are opposite too.
            return done("refused", 2, f"codemod_drift: {drift}")
        why = _ready_to_open(rec, report)
        if why:
            return done("not_ready", 1, why, "the gates did not pass on origin/" + base + "; nothing was committed. "
                        "See the report in " + probe_path, report_status=report.get("status"))
        # ⭐ D-06 slice 2: the review goes to DF FIRST, so pr-text (and reserve-pr's vet_refused) read it.
        if a.push_pr:
            stop = store_review(rec, getattr(a, "vet", None), getattr(a, "overrule_refusal", None), result)
            if stop:
                return done(*stop)
        rc, text, err = torana(["remediation-plan", rec["id"], "pr-text", "--probe", probe_path, "--format", "json"])
        if rc != 0 or not isinstance(text, dict):
            return done("error", rc or 1, f"pr-text: {err.strip()[-300:]}")
        changed = (report.get("gate_3_lane") or {}).get("changed", {}).get(target) or []
        if not changed:
            return done("not_ready", 1, f"the fix changes nothing on origin/{base}", "nothing to commit")
        commit = build_commit(top, base_sha, os.path.join(work_dir, f"group-{work['index']}", copy_label(target)), changed,
                              text["commit_message"], os.path.join(work_dir, "laptop.index"))
    except Refused as exc:
        return done("error", 1, str(exc))
    finally:
        # ⛔ DISARM BEFORE RELEASING. A hook left installed would renew a lease this run no longer holds on
        # the next library call of `run_group` — asking the server to extend somebody else's mutex.
        set_gate_renew(None)
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

    # ── D-06: the AI review gates the PR (spec § 5, slice 1). BEFORE the reservation, so a refusal reserves,
    # pushes and opens nothing. Stricter of code and review; no review (or a stale one) = draft.
    final, block, refused = review_decision(getattr(a, "vet", None), rec, text,
                                            getattr(a, "overrule_refusal", None))
    result.update(review_final_state=final)
    if refused:
        return done("refused_by_review", 2, refused,
                    f"nothing was pushed; your commit stays on {branch}. Read the review, fix the plan or re-plan its "
                    "alternative, or overrule with --overrule-refusal \"<why>\" (recorded in the PR)")
    text = dict(text, body=(text.get("body") or "") + block, draft=bool(text.get("draft")) or final != "confirm")
    result.update(draft=text["draft"])

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
    # ⛔ D-06 review m3: DF re-reads the review AFTER the claim; a draft review that landed after pr-text still drafts.
    if res.get("draft") and not text.get("draft"):
        text = dict(text, draft=True)
        result.update(draft=True, draft_reasons=sorted(set(result.get("draft_reasons") or []) |
                                                       set(res.get("draft_reasons") or [])))
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

    # ── VERIFY THE PUSHED BRANCH BEFORE OPENING THE PR (F27 / B32) ─────────────────────────
    #
    # ⛔ THE ORDER IS THE FIX. This same check used to run only at `record-pr`, AFTER `gh pr create`
    # — so a refusal left a real open pull request on the repository that the platform had declined
    # to record. 3 of the first 8 fix PRs ended that way (#327, #329, #330), and every one of them
    # was THIS applier producing a diff the platform's own guard then refused (F26, F30, F31). The
    # irreversible, outward-facing action came before the check that gates it.
    #
    # ⛔ AND IT CANNOT MOVE EARLIER THAN THIS. The platform's verify route takes its changed-file
    # list from GitHub and never from the caller — that inversion is its whole security content —
    # so before the push there is nothing to read, and this script may not import `check_lane`
    # either (a skill calls the API, it never imports platform code). Pushed-then-verified is as
    # early as the check can honestly run.
    #
    # ⚠️ NO `release()` HERE, deliberately. On a refusal the platform has ALREADY released the claim
    # and written the reason onto the plan; calling release again would report a second failure for
    # a claim that is gone. On a timeout or an unreachable platform it KEEPS the claim on purpose,
    # so that a retry can reuse the same reservation — releasing it would hand the slot to a second
    # runner racing the same push.
    rc, _verified, err = torana(["remediation-plan", rec["id"], "verify-branch", "--probe", probe_path,
                                 "--base-sha", base_sha, "--base-branch", base, "--claim-id", claim,
                                 "--format", "json"])
    if rc != 0:
        return done("refused", 2,
                    f"the platform refused the pushed branch: {err.strip()[-400:]}",
                    f"NO PR was opened, so there is nothing to close. {branch} is pushed at "
                    f"{commit[:12]}; read the reason on the plan "
                    f"(`torana remediation-plan {rec['id']} get`), fix the branch and rerun")
    log("branch verified against the plan; opening the PR")

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


# ── EM D-22: a follow-up commit on an open fix PR (D05B § 3.8, decision D3) ─────────────────────────

#: Where a follow-up commit waits while the platform verifies it. ⛔ OUTSIDE refs/heads and refs/tags: a push there
#: runs no workflow and makes no check suite (probed 2026-11-05), so a customer's `on: push` CI
#: never sees a commit that may yet be refused. The run deletes exactly this ref, sha-matched, on every path.
FOLLOW_UP_REF = "refs/torana/follow-up/{alert}/{sha7}"


def _primary_remediation(rec: Dict[str, Any]) -> Optional[str]:
    """The remediation row slice A's CI read is stored on: the primary alert's row for the plan's PR."""
    for r in rec.get("remediations") or []:
        if r.get("alert_id") == rec.get("primary_alert_id") and r.get("pr_number") == rec.get("pr_number"):
            return str(r["id"])
    return None


def caused_by_fix(ci: Dict[str, Any]) -> bool:
    """Does the stored CI read attribute at least one failed check to the fix itself (D-05B)?"""
    return any(((c.get("attribution") or {}).get("verdict") == "caused_by_fix") for c in ci.get("checks") or [])


def _delete_side_ref(top: str, ref: str, sha: str) -> Optional[bool]:
    """Delete `ref` on origin ONLY when it still points at `sha` (this run's commit). True deleted, False left
    (someone else's, or the delete failed), None absent."""
    rc, out, _ = git(top, "ls-remote", "origin", ref)
    if rc != 0:
        return False
    if not out:
        return None
    if out.split()[0] != sha:
        return False
    rc, _, _ = git(top, "push", "origin", "--delete", ref)
    return rc == 0


def run_follow_up(a: argparse.Namespace) -> int:
    """EM D-22. A follow-up commit on the OPEN fix PR `torana/alert-<id>`, carrying ONLY what the plan, as approved
    now, allows (D3: after an `override`, its new version; a class-4 codemod the plan accepted).

    ⛔ THE WORKING TREE IS NEVER TOUCHED, as in `run_commit`. The plan is gated on the PR's OWN base (where its head
    meets `origin/<base>`), the tree is that base plus the gated files, and the commit's parent is the PR's head
    `H`, so the PR's diff against its base is exactly the plan's lane.
    `--check` stops after building the commit (no ref, no push). `--push` (the developer's yes) pushes it to
    `refs/torana/follow-up/…` (no workflow), asks the platform to verify it over GitHub's own diff, and only on a pass
    fast-forwards the PR's branch. ⛔ Never `--force`: a rejected fast-forward is reported, never retried. The side
    ref is deleted (sha-matched) whatever happens. A free-form source edit is NOT this mode's: Claude shows that diff
    and the developer commits it under their own name.

    Exit: 0 built / pushed / nothing_to_add · 4 busy (lease) · 2 refused before any write · 1 not_ready / error."""
    work_dir = os.path.abspath(a.work)
    os.makedirs(work_dir, exist_ok=True)
    result: Dict[str, Any] = {"plan_id": a.plan_id, "mode": "follow_up", "status": None, "branch": None,
                              "parent": None, "commit": None, "base_sha": None, "side_ref": None,
                              "side_ref_deleted": None, "verified": False, "pushed": False, "why": None,
                              "next": None}

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
        return done("refused", 2, f"the plan is {rec.get('state')}; a follow-up carries only an approved plan",
                    "a tenant admin approves it (or overrides it to the corrected version) in Torana")
    if rec.get("pr_state") != "open":
        return done("refused", 2, f"the plan has no open fix PR ({rec.get('pr_state')})",
                    "a follow-up goes onto an open fix PR; open one with --commit --push-pr")
    top = _toplevel(a.repo)
    key = a.repo_key or repo_key_of(a.repo) or ""
    if key != target:
        return done("refused", 2, f"--repo is {key or 'a checkout with no recognisable origin'}, but this plan edits "
                    f"{target}", "pass the TARGET repository's checkout as --repo")
    branch = f"torana/alert-{rec['primary_alert_id']}"
    result["branch"] = branch
    rc, _, err = git(top, "fetch", "--quiet", "origin", base, f"+refs/heads/{branch}:refs/remotes/origin/{branch}")
    if rc != 0:
        return done("refused", 2, f"no origin/{branch} (or origin/{base}): {err[-300:]}",
                    "the fix PR's branch must exist on origin")
    _, head, _ = git(top, "rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{branch}^{{commit}}")
    if not head:
        return done("refused", 2, f"origin/{branch} does not exist", "a follow-up goes onto the fix PR's branch")
    result["parent"] = head
    rem_id = _primary_remediation(rec)
    rc, ci, err = torana(["remediation", rem_id, "ci", "get", "--format", "json"]) if rem_id else (1, None, "")
    ci_head = (ci or {}).get("head_sha") if isinstance(ci, dict) else None
    if ci_head != head:
        return done("refused", 2, f"pr_moved: the PR is at {head[:12]} but Torana last read CI on "
                    f"{(ci_head or 'nothing')[:12]}; the analysis is about another head",
                    f"ask again (`torana remediation {rem_id} refresh`), then rerun" if rem_id else
                    "ask Torana to read the PR's CI first")
    if not caused_by_fix(ci) and not a.anyway:
        return done("refused", 2, "not_caused_by_fix: no failed check on this head is attributed to the fix",
                    "a follow-up is for a check the fix broke; pass --anyway only if you know it is")
    rc, base_sha, err = git(top, "merge-base", head, f"refs/remotes/origin/{base}")
    if rc != 0 or not base_sha:
        return done("refused", 2, f"base_moved_under_pr: {branch} shares no history with origin/{base}",
                    f"merge {base} into the PR (or re-open it), then ask again")
    result["base_sha"] = base_sha
    not_ready = github_not_ready(rec["id"], top)
    if not_ready:
        for c in not_ready["checks"]:
            log(f"NOT READY: {c['words']} — fixes it: {c['who_fixes']}")
        return done("github_not_ready", EXIT_NOT_READY, not_ready["why"],
                    "each check above names who fixes it; rerun when they are done. Nothing was committed",
                    checks=not_ready["checks"])

    holder = a.holder_run or f"local:{socket.gethostname()}:{os.getpid()}"
    rc, lease, err = torana(lease_acquire_args(rec["id"], holder))
    if rc == 4:
        return done("busy", 4, f"another run holds this repository's lease: {err.strip()[-300:]}", "rerun later")
    if rc != 0 or not isinstance(lease, dict):
        return done("error", rc or 1, f"lease: {err.strip()[-300:]}", "check `torana auth me` and your permissions")
    lease_id = lease.get("id") or lease.get("lease_id")
    probe_path = os.path.join(work_dir, "probe-report.json")

    def _renew() -> bool:
        rc_r, _, _ = torana(lease_renew_args(lease_id, holder))
        return rc_r == 0

    set_gate_renew(_renew if lease_id else None)
    try:
        try:
            plan, work, allowed = plan_input(rec, {target: top}, target)
        except Refused as exc:
            return done("error", 1, str(exc))
        for s in plan["scope"]:
            if s["repo"] == target:              # ⛔ the PR's OWN base, never origin/<base>'s tip (issue 2)
                s.update(ref=base_sha, commit=base_sha)
        stored_cm = (rec.get("codemod") or {})
        if any(f.get("model_authored") for f in (stored_cm.get("files") or [])) and not CODEMOD_DRAFTS:
            return done("refused", 2, "codemod_drift: the 4c drafts are not available (--codemod-drafts)",
                        "pass --codemod-drafts DIR with the accepted drafts from the probe run")
        try:
            report = run_group(plan, work, True, work_dir, allowed_files=allowed)
        except LeaseLost as exc:
            return done("busy", 4, f"the lease was lost while the gates ran: {exc}", "rerun later")
        _write(probe_path, {"groups": [report]})
        drift = _codemod_drift(stored_cm, report.get("codemod") or {})
        if drift:
            return done("refused", 2, f"codemod_drift: {drift}")
        why = _ready_to_open(rec, report)
        if why:
            return done("not_ready", 1, why, "the gates did not pass on the PR's base; nothing was committed. "
                        "See the report in " + probe_path, report_status=report.get("status"))
        rc, text, err = torana(["remediation-plan", rec["id"], "pr-text", "--probe", probe_path, "--format", "json"])
        if rc != 0 or not isinstance(text, dict):
            return done("error", rc or 1, f"pr-text: {err.strip()[-300:]}")
        changed = (report.get("gate_3_lane") or {}).get("changed", {}).get(target) or []
        if not changed:
            return done("nothing_to_add", 0, "the plan changes nothing on the PR's base",
                        "nothing to commit")
        message = "Follow-up: " + str(text["commit_message"])
        commit = build_commit(top, base_sha, os.path.join(work_dir, f"group-{work['index']}", copy_label(target)),
                              changed, message, os.path.join(work_dir, "follow-up.index"), parent=head)
    except Refused as exc:
        return done("error", 1, str(exc))
    finally:
        set_gate_renew(None)
        if lease_id:
            torana(["remediation-plans", "lease", "release", lease_id, "--holder-run", holder])
    result["commit"] = commit
    trees = [git(top, "rev-parse", f"{c}^{{tree}}")[1] for c in (commit, head)]
    if trees[0] == trees[1]:
        return done("nothing_to_add", 0, "the approved plan is already on the branch",
                    f"a corrected fix needs an override first: `torana remediation-plan {rec['id']} override …`")
    log(f"follow-up built @{commit[:12]} on {head[:12]} (base {base_sha[:12]})")
    if not a.push:
        return done("built", 0, None, f"look at it (`git show {commit}`); rerun with --push to verify and push it. "
                    "Nothing was pushed")

    # ── --push: side ref → verify → fast-forward → delete the side ref ──
    side = FOLLOW_UP_REF.format(alert=rec["primary_alert_id"], sha7=commit[:7])
    result["side_ref"] = side
    rc, _, err = git(top, "push", "origin", f"{commit}:{side}")
    if rc != 0:
        return done("error", 1, f"cannot push the follow-up to {side}: {err[-300:]}",
                    "check that you can push to origin; nothing reached the PR")
    # ⚠️ The outcome is decided first and REPORTED after the side ref is gone, so the report never says
    # `side_ref_deleted: null` about a ref this run did delete.
    try:
        outcome = _verify_and_fast_forward(top, rec, probe_path, base_sha, base, commit, head, branch, result)
    finally:
        result["side_ref_deleted"] = _delete_side_ref(top, side, commit)
    return done(*outcome)


def _verify_and_fast_forward(top: str, rec: Dict[str, Any], probe_path: str, base_sha: str, base: str, commit: str,
                             head: str, branch: str, result: Dict[str, Any]) -> Tuple[str, int, Optional[str], str]:
    """`--push`'s two steps after the side ref: the platform's verify, then the plain fast-forward."""
    rc, ver, err = torana(["remediation-plan", rec["id"], "verify-follow-up", "--probe", probe_path,
                           "--base-sha", base_sha, "--base-branch", base, "--follow-up-sha", commit,
                           "--parent", head, "--format", "json"])
    if rc != 0:
        return ("refused", 2, f"the platform refused the follow-up: {err.strip()[-400:]}",
                f"the PR did not move. Read the reason on the plan (`torana remediation-plan {rec['id']} get`)")
    result["verified"] = True
    log(f"follow-up verified against the plan: {', '.join((ver or {}).get('verified_paths') or [])}")
    rc, _, err = git(top, "push", "origin", f"{commit}:refs/heads/{branch}")
    if rc != 0:
        return ("not_fast_forward", 1, f"the PR's branch moved; the push was rejected: {err[-300:]}",
                "nothing was forced. Ask again: the follow-up is rebuilt on the PR's new head")
    result["pushed"] = True
    log(f"pushed {branch} @{commit[:12]} (fast-forward from {head[:12]})")
    return ("pushed", 0, None, "the PR's CI runs on the new head; ask Claude about it when it finishes")


def _write_text(path: str, text: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ── the run ─────────────────────────────────────────────────────────────────────────

def main() -> int:
    global RESOLVER_TIMEOUT_S, GATE_INSTALL_TIMEOUT_S, GATE_TEST_TIMEOUT_S, GATES_45, CO_MOVER_API_DIFFS, LOCK_CHECK
    global GATES_45_OFF_WHY, GATE_5_OFF_WHY
    global CODEMOD, CODEMOD_TIMEOUT, CODEMOD_DRAFTS, API_DIFF_DOCS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", default="-", help="remediation_plan.py --json output (default: stdin)")
    ap.add_argument("--group", type=int, action="append", default=[], help="group index in the plan (repeatable)")
    ap.add_argument("--package", action="append", default=[], help="narrow the groups to these packages")
    ap.add_argument("--apply", action="store_true", help="edit scratch copies and run the resolver and gates")
    ap.add_argument("--work", default=None, help="where the scratch copies go (required with --apply)")
    ap.add_argument("--json", dest="as_json", action="store_true", help="only JSON on stdout")
    ap.add_argument("--co-mover-api-diffs", choices=[CO_REQUEST, CO_READ, CO_OFF, CO_CI], default=CO_REQUEST,
                    help="a package the resolve moved along with the fix (gate 2) that crosses a major version gets "
                         "an API diff and the call-graph check, as the asked package does: `request` (the "
                         "default) asks the platform to compute a missing API diff (the tenant's daily quota), `read` "
                         "takes only cached ones, `off` asks nothing, `ci` records `not_requested` "
                         "(`ci_second_resolve`: the GitHub Action, where an API diff would need a second resolve). A "
                         "co-mover whose changed API this repository calls makes the group needs_human")
    ap.add_argument("--plan-id", default=None, help="a server plan (torana remediation-plans) instead of --plan")
    ap.add_argument("--repo", default=None, help="with --plan-id: this runner's own checkout (the subject)")
    ap.add_argument("--repo-key", default=None, help="with --plan-id: --repo's key (default: its origin remote)")
    ap.add_argument("--with", dest="with_roots", action="append", default=[], metavar="ROOT[=KEY]",
                    help="with --plan-id: another checkout, e.g. the target repository (repeatable)")
    ap.add_argument("--probe", action="store_true", help="with --plan-id --apply: re-prove it and refresh the plan")
    ap.add_argument("--probe-bound", dest="probe_bound", action="store_true",
                    help="with --plan --apply --work DIR: for each row the planner refused "
                         "`edit_needs_human`, MEASURE what lifting the bound would cost — recompile a "
                         "scratch copy with `>=<target>` and report what moves. Changes no verdict, "
                         "proposes no value, writes nothing outside --work")
    ap.add_argument("--open-pr", dest="open_pr", action="store_true",
                    help="with --plan-id --apply: send an approved plan's files to the platform, under a lease")
    ap.add_argument("--commit", dest="commit", action="store_true",
                    help="with --plan-id --apply: the laptop lane. --repo is the TARGET checkout; gate on origin/<base> "
                         "and commit on a new branch torana/alert-<id>, never touching the working tree")
    ap.add_argument("--push-pr", dest="push_pr", action="store_true",
                    help="with --commit: reserve the PR slot, `git push` with YOUR credentials, `gh pr create`, "
                         "then record the PR")
    ap.add_argument("--follow-up", dest="follow_up", action="store_true",
                    help="with --plan-id --apply --repo: EM D-22, a follow-up commit on the plan's OPEN fix PR, "
                         "parent = the PR's head, carrying only the plan as approved now. With --check or --push")
    ap.add_argument("--check", action="store_true",
                    help="with --follow-up: gate and build the commit; push nothing")
    ap.add_argument("--push", action="store_true",
                    help="with --follow-up (the developer's yes): verify it on the platform, then fast-forward the "
                         "PR's branch. Never forced")
    ap.add_argument("--anyway", action="store_true",
                    help="with --follow-up: build it even though no failed check is attributed to the fix")
    ap.add_argument("--holder-run", default=None, help="with --open-pr: this run's id (default local:<host>:<pid>)")
    ap.add_argument("--base-branch", default="main",
                    help="with --open-pr: the PR's base branch, i.e. the target's default branch (main if omitted)")
    ap.add_argument("--resolver-timeout", type=int, default=RESOLVER_TIMEOUT_S, metavar="SECONDS",
                    help=f"wall-clock cap on one resolver run (default {RESOLVER_TIMEOUT_S}); past it the run is "
                         f"killed and the group declined `resolver_timeout`")
    ap.add_argument("--gate-install-timeout", type=int, default=GATE_INSTALL_TIMEOUT_S, metavar="SECONDS",
                    help=f"wall-clock cap on gate 4's install (default {GATE_INSTALL_TIMEOUT_S}); past it "
                         f"the command is killed and the gate reports `error`, never `failed`")
    ap.add_argument("--gate-test-timeout", type=int, default=GATE_TEST_TIMEOUT_S, metavar="SECONDS",
                    help=f"wall-clock cap on gate 5's suite (default {GATE_TEST_TIMEOUT_S}); past it the "
                         f"command is killed and the gate reports `error`, never `failed`")
    ap.add_argument("--api-diff-file", dest="api_diff_file", default=None, metavar="FILE",
                    help="the API diff DOCUMENTS this run may use, as the planner's --api-diffs-out "
                         "writes them. ⛔ Gate B's L2 needs the document, not the plan's summary: a "
                         "stored plan carries only counts and the touched list, and `intersect` cannot "
                         "be re-run from those. Without this file L2 does not run and the codemod "
                         "block says so (state `partial`), rather than reporting complete unchecked")
    ap.add_argument("--codemod", choices=("auto", "off"), default="auto",
                    help="auto (default): on a class-4 group under --apply, run the 4a/4b codemods and "
                         "Gate B. off: keep the pre-phase-5 behaviour — the group is reported "
                         "class_4_skipped and a person changes the code")
    ap.add_argument("--codemod-drafts", dest="codemod_drafts", default=None, metavar="DIR",
                    help="accept 4c drafts from DIR at probe and re-apply them at --commit. Without it "
                         "a plan carrying model-authored files is refused at --commit (codemod_drift), "
                         "because the hunk cannot be reproduced from the plan alone")
    ap.add_argument("--codemod-timeout", dest="codemod_timeout", type=int, default=120, metavar="SECONDS",
                    help="per file, per engine (default 120)")
    g45 = ap.add_mutually_exclusive_group()
    g45.add_argument("--gates-45", dest="gates_45", action="store_const", const="on", default="auto",
                     help="run gates 4 (build) and 5 (tests) on any lane: the project's OWN commands, discovered "
                          "by test_ladder.py, on the applied copy. Without either flag they run exactly where a PR "
                          "is about to open (--commit, --open-pr) and report `not_run` with the reason elsewhere")
    g45.add_argument("--no-gates-45", dest="gates_45", action="store_const", const="off",
                     help="do not run gates 4-5, even where a PR is about to open; the report and the PR say the "
                          "developer skipped them")
    g45.add_argument("--gates-45-in-pr-ci", dest="gates_45", action="store_const", const="pr_ci",
                     help="(EM D-23 S3, the remediate Action) do not run gates 4-5 here; the report and the PR say the "
                          "repository's own CI runs them on the draft PR")
    ap.add_argument("--gate-5-off", dest="gate_5_off", default=None, metavar="WHY",
                    help="run gate 4 (build) but not gate 5 (tests); gate 5 reports not_run with WHY. For bulk dry "
                         "runs whose suites must not reach a shared database")
    ap.add_argument("--review-case", dest="review_case", default=None, metavar="DIR",
                    help="with --plan-id --apply --work (EM D-23 S3, the remediate Action's job 1): gates 1-3 on a "
                         "scratch copy, then write the plan's review case under DIR for the review and open-pr jobs. "
                         "Writes nothing to Torana; never runs gates 4/5 (the PR's own CI does)")
    ap.add_argument("--gates-from-case", dest="gates_from_case", default=None, metavar="DIR",
                    help="run gates 4/5 on each case under DIR and write gates.json beside it. Reads no plan and talks "
                         "to nobody. Not used by the remediate Action since EM D-23 S3 d2 (the PR's own CI runs them)")
    ap.add_argument("--from-case", dest="from_case", default=None, metavar="DIR",
                    help="with --plan-id --open-pr (EM D-23 S3, job 3): open the case's tree, never re-resolving. "
                         "Not opened if any base moved or the trees are not the reviewed ones")
    ap.add_argument("--gates-file", dest="gates_file", default=None, metavar="GATES.json",
                    help="with --from-case: a gates.json from --gates-from-case for that case (ignored unless plan "
                         "and digest match). Without it, gates 4/5 read not_run: the PR's own CI runs them")
    ap.add_argument("--vet", default=None, metavar="VET.json",
                    help="with --commit --push-pr or --open-pr: the AI review of this plan (vet_case.py, spec § 5.1), "
                         "stored on the plan first. The PR is the stricter of code and review; without it, or with a "
                         "stale one, the PR opens as a draft; a refusal opens nothing")
    ap.add_argument("--overrule-refusal", dest="overrule_refusal", default=None, metavar="WHY",
                    help="with --vet: a PERSON who may approve plans (alert:update) overrules a refusal; the fix "
                         "opens as a draft, WHY recorded on the plan and in the PR")
    ap.add_argument("--lock-check", choices=["on", "off"], default="on",
                    help="before resolving a fix into a lock, re-lock the UNMODIFIED tree with no upgrade (`uv lock "
                         "--check` for uv) and decline the group `lock_stale` when that changes the lock: the fix "
                         "would ship the lock's staleness. A resolver that fails or times out here never reads as "
                         "stale (default: on)")
    a = ap.parse_args()
    LOCK_CHECK = a.lock_check == "on"
    CO_MOVER_API_DIFFS = a.co_mover_api_diffs
    if a.resolver_timeout <= 0:
        log("ERROR: --resolver-timeout must be a positive number of seconds")
        return 2
    RESOLVER_TIMEOUT_S = a.resolver_timeout
    GATE_INSTALL_TIMEOUT_S = a.gate_install_timeout
    GATE_TEST_TIMEOUT_S = a.gate_test_timeout
    GATES_45, GATES_45_OFF_WHY = resolve_gates_45(a.gates_45, opens_pr=bool(a.commit or a.open_pr or a.follow_up),
                                                  probe=bool(a.probe))
    GATES_45_OFF_WHY = GATES_45_OFF_WHY or GATES_45_WHY_NOT_REQUESTED
    # EM D-23 S3: the remediate Action's review lane. Job 1 (`--review-case`) and job 3 (`--from-case`) NEVER run
    # gates 4/5 (the project's own install and suite import the upgraded package, next to a main-scoped runtime
    # token): the PR's own CI runs them (em3 d1 M1). `--gates-from-case` (a laptop) always runs them.
    if a.review_case or a.from_case:
        GATES_45, GATES_45_OFF_WHY = False, GATES_45_WHY_PR_CI
    elif a.gates_from_case:
        GATES_45, GATES_45_OFF_WHY = True, ""
    GATE_5_OFF_WHY = a.gate_5_off
    CODEMOD, CODEMOD_TIMEOUT, CODEMOD_DRAFTS = a.codemod, a.codemod_timeout, a.codemod_drafts
    if a.api_diff_file:
        try:
            API_DIFF_DOCS = rp.read_api_diffs(a.api_diff_file)[0]
        except Exception as exc:                 # noqa: BLE001 — stated, never silently empty
            print(f"WARNING: --api-diff-file unreadable ({type(exc).__name__}): L2 will not run",
                  file=sys.stderr)
            API_DIFF_DOCS = []
    if a.push_pr and not a.commit:
        log("ERROR: --push-pr needs --commit")
        return 2
    if a.follow_up:
        if not (a.plan_id and a.apply and a.work and a.repo) or a.check == a.push \
                or a.probe or a.open_pr or a.commit:
            log("ERROR: --follow-up needs --plan-id --apply --work DIR --repo <target checkout> and exactly one of "
                "--check / --push")
            return 2
        return run_follow_up(a)
    if a.gates_from_case:
        if a.plan_id or a.from_case or a.review_case:
            log("ERROR: --gates-from-case DIR stands alone: it reads the case, nothing else")
            return 2
        return run_gates_from_case(a)
    if a.from_case and not a.open_pr:
        log("ERROR: --from-case DIR goes with --plan-id --open-pr")
        return 2
    if a.plan_id:
        if not (a.apply and a.work) or sum((a.probe, a.open_pr, a.commit, bool(a.review_case))) != 1:
            log("ERROR: --plan-id needs --apply --work DIR and exactly one of --probe / --open-pr / --commit / "
                "--review-case")
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
    if a.probe_bound:
        if not (a.apply and a.work):
            log("ERROR: --probe-bound needs --apply --work DIR. ⛔ Nothing outside --work is ever written.")
            return 2
        rows = select_declined(plan, a.group, a.package)
        if not rows:
            log("no row was refused `edit_needs_human`: there is no bound to probe")
        probes = [probe_bound(plan, r, os.path.abspath(a.work)) for r in rows]
        out = {"repo": plan.get("repo"), "probe_bound": probes}
        if a.as_json:
            print(json.dumps(out, indent=2))
        else:
            for pr in probes:
                print(f"[{pr['package']} {pr.get('installed')} → at least {pr.get('target')}] {pr['status']}"
                      + (f"  {pr['why']}" if pr.get("why") else ""))
                for v in (pr.get("provisional") or []):
                    print(f"    probe  {v['repo']}/{v['file']}:{v['line']}  `{v['from']}` → `{v['probed_with']}`"
                          f"   recompiling {v['lock']}")
                for k, v in (pr.get("landed") or {}).items():
                    print(f"    LANDS  {k} {v['from']} → {v['to']}"
                          + ("   ⚠ above the published fix" if v["to"] != pr.get("target") else ""))
                for v in (pr.get("also_moved") or []):
                    print(f"    also   {v['package']} {v['from']} → {v['to']}")
                for n in (pr.get("not_established") or []):
                    print(f"    ⛔ not established: {n}")
        return 0
    works = select(plan, a.group, a.package)
    if not works:
        log("nothing to apply: no class-2, class-3 or class-4 group matches")
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
                      f"{landed_words(g.get('landed'))}")
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
