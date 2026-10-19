#!/usr/bin/env python3
"""The fix-PR lane, unattended: queue → planner → probe → propose; then re-probe stale plans; then, with
`open-pr: true`, apply every approved plan of this repository through the platform.

Spec: pantheon-cli `docs/FIX_PR_SPEC.md` § 3.4.9 (this action), § 3.4.10 (the plan's read token), § 3.4.11 (the
propose-run read token), § 3.4.8 (apply's `--plan-id` modes), § 3.7 (what a CI token may reach).

⛔ NO GITHUB WRITE CREDENTIAL, EVER. Every checkout is read-only and keeps no credential: the subject by the
workflow's `GITHUB_TOKEN` (`contents: read`, done by action.yml), every other repository by a one-repository,
`contents: read` token the PLATFORM mints, which this script masks, uses for one clone and revokes at once. The
PR is opened by the platform's App (`torana remediation-plan ID open-pr`, run by `remediation_apply.py`), after
it checks every path and every changed line against what a human approved.

⛔ A FRESH CI TOKEN BEFORE EVERY WRITE. The CI token lives 900 s (`internal_tokens.py:96`) and a resolve can
outlast it, so this script re-runs the OIDC exchange before each CLI call, and hands `remediation_apply.py`
`TORANA_TOKEN_CMD` so it does the same before each of ITS writes (lease, open-pr, the refresh propose).

⛔ APPLY OWNS THE LEASE (§ 3.4.8 item 3). This script passes `--holder-run <run id>:<attempt>` and never leases.

⛔ NEVER ON A PULL REQUEST. A PR's code is not what ships, and a `pull_request_target` run would hand an
untrusted head the job's OIDC identity. Refused before anything runs.

Environment (set by action.yml): TORANA_BASE_URL, TORANA_OIDC_AUDIENCE, TORANA_SCAN_REF (the scan pack's
`references/`), REMEDIATE_REPO_KEY (optional), REMEDIATE_WITH (newline list `owner/repo[:subdir]`),
REMEDIATE_OPEN_PR (`true|false`), REMEDIATE_SUBJECT (the subject checkout), REMEDIATE_OUT (scratch), plus the
runner's GITHUB_* variables. Stdlib only.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_token  # noqa: E402

GO_STATES = ("approved", "overridden", "removal_chosen")
LIVE_STATES = ("proposed",) + GO_STATES          # non-terminal: a stale one of these is re-probed
OPENABLE_PR_STATES = ("none", "opening_stale")
PAGE = 100                                       # the routes' limit cap (§ 3.4.3, § 3.8.4)
EXIT_LEASE_HELD = 4                              # torana CLI: lease held (§ 3.4.7)
_WITH_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?::(.+))?$")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def mask(secret: str) -> None:
    # ⛔ On stdout: the runner reads workflow commands there. Printed BEFORE the secret is used anywhere.
    print(f"::add-mask::{secret}", flush=True)


def repo_key(owner: str, repo: str) -> str:
    # Lowercased because the finding keys are (`torana-inc`, not `Torana-Inc`); github.com because the
    # platform opens PRs on github.com only (§ 3.4.4 pre-flight, `unsupported_forge`).
    return f"repo:github.com/{owner.lower()}/{repo.lower()}"


@dataclass
class WithTree:
    owner: str
    repo: str
    subdir: str
    key: str


@dataclass
class Run:
    env: Dict[str, str]
    subject_dir: str
    subject_key: str
    out: str
    holder_run: str
    trees: List[WithTree]
    open_pr: bool
    ref: str
    roots: Dict[str, str] = field(default_factory=dict)      # repo key → local checkout (repo root, not subdir)
    errors: List[str] = field(default_factory=list)
    summary: List[str] = field(default_factory=list)

    def fail(self, msg: str) -> None:
        print(f"::error::{msg}", flush=True)
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        print(f"::warning::{msg}", flush=True)


def parse_with(raw: str) -> List[WithTree]:
    trees = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _WITH_RE.match(line)
        sub = (m.group(3) or "").strip("/") if m else ""
        if not m or any(seg in ("", ".", "..") for seg in sub.split("/") if sub):
            raise ValueError(f"`with` wants owner/repo[:subdir], got {line!r}")
        trees.append(WithTree(m.group(1), m.group(2), sub, repo_key(m.group(1), m.group(2))))
    return trees


# ── the CLI, always with a fresh token ────────────────────────────────────────────────

def fresh_token(run: Run) -> None:
    token = ci_token.mint(run.env)
    mask(token)
    run.env["TORANA_TOKEN"] = token


def torana(run: Run, args: List[str], stdin: Optional[str] = None, fresh: bool = True) -> Tuple[int, Any, str]:
    """`torana … --format json` with a fresh CI token. Returns (rc, parsed stdout or None, stderr)."""
    if fresh:
        fresh_token(run)
    p = subprocess.run(["torana", *args, "--format", "json"], env=run.env, input=stdin, capture_output=True,
                       text=True)
    try:
        data = json.loads(p.stdout) if p.stdout.strip() else None
    except ValueError:
        data = None
    return p.returncode, data, p.stderr


def script(run: Run, name: str, args: List[str], stdout_path: Optional[str] = None,
           fresh: bool = False) -> int:
    """A scan-pack script. Its stdout (JSON with `--json`) goes to `stdout_path`; its stderr streams."""
    if fresh:
        fresh_token(run)
    cmd = [sys.executable, os.path.join(run.ref, name), *args]
    log(f"$ {name} {' '.join(shlex.quote(a) for a in args)}")
    if stdout_path:
        with open(stdout_path, "w", encoding="utf-8") as fh:
            return subprocess.run(cmd, env=run.env, stdout=fh).returncode
    return subprocess.run(cmd, env=run.env).returncode


def list_plans(run: Run, state: str) -> List[Dict[str, Any]]:
    """Every plan of THIS subject in `state` (a CI token must name its own repository, § 3.4.3), offset-paged."""
    items: List[Dict[str, Any]] = []
    offset = 0
    while True:
        rc, data, err = torana(run, ["remediation-plans", "list", "--subject-repository", run.subject_key,
                                     "--state", state, "--limit", str(PAGE), "--offset", str(offset)])
        if rc != 0:
            run.fail(f"listing {state} plans: {err.strip()[-400:]}")
            return items
        page = (data or {}).get("items") if isinstance(data, dict) else (data or [])
        items += page or []
        total = data.get("total") if isinstance(data, dict) else None
        offset += len(page or [])
        if not page or len(page) < PAGE or (total is not None and offset >= total):
            return items


# ── read-only checkouts with a platform-minted token ──────────────────────────────────

def clone(run: Run, owner: str, repo: str, dest: str, token: str) -> None:
    """A shallow, read-only clone. ⛔ The token goes through GIT_CONFIG_* (never argv, never .git/config), as an
    http.extraheader — the shape `actions/checkout` uses with `persist-credentials: false`."""
    server = run.env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {**run.env, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "1",
           "GIT_CONFIG_KEY_0": f"http.{server}/.extraheader", "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"}
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    p = subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--no-tags", f"{server}/{owner}/{repo}.git",
                        dest], env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"git clone {owner}/{repo} failed: {p.stderr.strip()[-400:]}")


def checkout_with_token(run: Run, mint_args: List[str], revoke_args: List[str], owner: str, repo: str,
                        dest: str) -> Tuple[bool, str]:
    """Mint → mask → clone → revoke (always, once minted). Returns (ok, error code or message)."""
    rc, data, err = torana(run, [*mint_args, "--holder-run", run.holder_run])
    if rc != 0 or not isinstance(data, dict) or not data.get("token"):
        code = next((c for c in ("not_related", "token_not_needed") if c in err), "")
        return False, code or err.strip()[-400:] or f"mint exit {rc}"
    token, mint_id = data["token"], data.get("mint_id")
    mask(token)
    try:
        clone(run, owner, repo, dest, token)
        return True, ""
    except RuntimeError as exc:
        return False, str(exc)
    finally:
        # ⛔ Revoked as soon as the checkout is done: GitHub fixes the lifetime at one hour (§ 3.4.10), so
        # revocation is the minutes-scale bound. The token travels on stdin, never argv.
        rrc, _, rerr = torana(run, [*revoke_args, "--holder-run", run.holder_run, "--revoke",
                                    "--mint-id", str(mint_id)], stdin=token)
        if rrc != 0:
            run.fail(f"could not revoke the read token for {owner}/{repo} (mint {mint_id}): {rerr.strip()[-300:]}")
        else:
            log(f"revoked the read token for {owner}/{repo} (mint {mint_id})")


def checkout_with_trees(run: Run) -> None:
    """Before the first probe: every `with` repository (§ 3.4.11). Same repository → no token; another → a
    propose-run token, only for a repository a tenant admin declared related."""
    for t in run.trees:
        if t.key == run.subject_key:
            run.roots.setdefault(t.key, run.subject_dir)
            continue
        if t.key in run.roots:
            continue
        dest = os.path.join(run.out, "src", t.repo)
        ok, why = checkout_with_token(run, ["remediation-plans", "target-token", "--subject", run.subject_key,
                                            "--target", t.key],
                                      ["remediation-plans", "target-token", "--subject", run.subject_key,
                                       "--target", t.key], t.owner, t.repo, dest)
        if ok:
            run.roots[t.key] = dest
        elif why == "not_related":
            run.warn(f"{t.owner}/{t.repo} is not declared related to {run.subject_key}, so it is left out of the "
                     f"plan (its locks answer not_declared_here). A tenant admin declares it with: torana "
                     f"integration <IID> related-repos add --subject {run.subject_key} --target {t.key} "
                     f"--description '<why>'")
        else:
            run.fail(f"checkout of {t.owner}/{t.repo}: {why}")


def scope_args(run: Run, flag_for_with: str) -> List[str]:
    """`--with` roots for the planner (the `with` subdir: what it reads) or for apply (`ROOT=KEY`, the
    REPOSITORY root once per key: a stored plan's rows carry repo-relative paths, § 3.4.7 propose step 2)."""
    out: List[str] = []
    if flag_for_with == "plan":
        for t in run.trees:
            root = run.roots.get(t.key)
            if root and not (t.key == run.subject_key and not t.subdir):
                out += ["--with", os.path.join(root, t.subdir) if t.subdir else root]
        return out
    for key, root in run.roots.items():
        if key != run.subject_key:
            out += ["--with", f"{root}={key}"]
    return out


def with_keys(run: Run) -> List[str]:
    """`propose --with-key LABEL=KEY`: the planner labels a root by its path relative to `--repo`'s parent
    (`remediation_plan.py` `_label`), which is why every checkout sits beside the subject."""
    parent = os.path.dirname(run.subject_dir)
    out: List[str] = []
    for t in run.trees:
        root = run.roots.get(t.key)
        if not root or (t.key == run.subject_key and not t.subdir):
            continue
        out += ["--with-key", f"{os.path.relpath(os.path.join(root, t.subdir) if t.subdir else root, parent)}"
                              f"={t.key}"]
    return out


# ── the three stages ──────────────────────────────────────────────────────────────────

def propose_stage(run: Run) -> None:
    findings = os.path.join(run.out, "findings.json")
    rc, data, err = torana(run, ["alerts", "reachability-queue", "--repository", run.subject_key,
                                 "--include-measured", "--as-findings"])
    if rc != 0 or not isinstance(data, list):
        run.fail(f"reading the reachability queue: {err.strip()[-400:] or 'not a JSON list'}")
        return
    with open(findings, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    if not data:
        run.summary.append("Queue: nothing to plan.")
        return
    checkout_with_trees(run)
    plan = os.path.join(run.out, "plan.json")
    if script(run, "remediation_plan.py", ["--repo", run.subject_dir, *scope_args(run, "plan"),
                                           "--findings", findings, "--json"], plan) != 0:
        run.fail("remediation_plan.py failed")
        return
    probe = os.path.join(run.out, "probe.json")
    # Exit 1 = some group failed its gates; propose sends only gates_passed / needs_human groups (§ 3.4.7).
    rc = script(run, "remediation_apply.py", ["--plan", plan, "--apply", "--work", os.path.join(run.out, "work"),
                                              "--json"], probe)
    if rc not in (0, 1):
        run.fail(f"remediation_apply.py (probe) exited {rc}")
        return
    rc, data, err = torana(run, ["remediation-plans", "propose", "--plan", plan, "--findings", findings,
                                 "--probe", probe, "--repo-key", run.subject_key, *with_keys(run)])
    if rc != 0:
        run.fail(f"propose exited {rc}: {err.strip()[-600:]}")
        return
    run.summary.append(f"Proposed from {len(data) if isinstance(data, list) else 'the'} finding(s) in the queue: "
                       f"{json.dumps(data)[:600] if data is not None else 'ok'}")


def apply_plan_id(run: Run, plan_id: str, mode: str) -> Tuple[int, Any]:
    work = os.path.join(run.out, f"{mode}-{plan_id}")
    args = ["--plan-id", plan_id, "--repo", run.subject_dir, "--repo-key", run.subject_key,
            *scope_args(run, "apply"), "--apply", "--work", work, f"--{mode}", "--json"]
    if mode == "open-pr":
        args += ["--holder-run", run.holder_run]
    report = os.path.join(run.out, f"{mode}-{plan_id}.json")
    rc = script(run, "remediation_apply.py", args, report, fresh=True)
    try:
        with open(report, encoding="utf-8") as fh:
            return rc, json.load(fh)
    except (OSError, ValueError):
        return rc, None


def reprobe_stage(run: Run) -> None:
    """A stale plan of this subject is re-probed (§ 3.4.9) from the trees this run can read."""
    for state in LIVE_STATES:
        for p in list_plans(run, state):
            if not p.get("probe_stale"):
                continue
            target = p.get("target_repository")
            if target and target not in run.roots:
                run.warn(f"plan {p['id']} is stale but {target} is not checked out here (add it to `with`, "
                         f"declared related): not re-probed")
                continue
            rc, rep = apply_plan_id(run, p["id"], "probe")
            if rc == 2:
                run.warn(f"plan {p['id']}: scope_missing, a tree its rows name is not checked out: not re-probed")
            elif rc != 0:
                run.fail(f"re-probe of plan {p['id']} exited {rc}")
            else:
                run.summary.append(f"Re-probed plan {p['id']} ({state}).")


def open_pr_stage(run: Run) -> None:
    """Each go-state plan of this subject → a fresh target token and clone (base = the target's current HEAD)
    → apply `--open-pr`, which leases, sends the files and releases."""
    for state in GO_STATES:
        for p in list_plans(run, state):
            pid, target = p["id"], p.get("target_repository") or ""
            if p.get("pr_state", "none") not in OPENABLE_PR_STATES:
                continue
            saved = dict(run.roots)
            if target != run.subject_key:
                owner, _, repo = target.removeprefix("repo:github.com/").partition("/")
                dest = os.path.join(run.out, "pr", pid, repo)
                ok, why = checkout_with_token(run, ["remediation-plan", pid, "target-token"],
                                              ["remediation-plan", pid, "target-token"], owner, repo, dest)
                if not ok:
                    run.fail(f"plan {pid}: checkout of {target}: {why}")
                    continue
                run.roots[target] = dest
            try:
                rc, res = apply_plan_id(run, pid, "open-pr")
            finally:
                run.roots = saved
            status = (res or {}).get("status")
            if rc != 0:
                run.fail(f"plan {pid}: apply --open-pr exited {rc} ({status}: {(res or {}).get('why')})")
            else:
                pr = (res or {}).get("pr") or {}
                run.summary.append(f"Plan {pid}: {status}"
                                   f"{' ' + str(pr.get('pr_url')) if isinstance(pr, dict) and pr.get('pr_url') else ''}"
                                   f"{' (' + str(res.get('why')) + ')' if res and res.get('why') else ''}")


# ── the run ───────────────────────────────────────────────────────────────────────────

def build_run(env: Dict[str, str]) -> Run:
    gh_repo = env.get("GITHUB_REPOSITORY", "")
    key = (env.get("REMEDIATE_REPO_KEY") or "").strip()
    if not key:
        owner, _, repo = gh_repo.partition("/")
        if not repo:
            raise ValueError("no repo-key input and no GITHUB_REPOSITORY")
        key = repo_key(owner, repo)
    out = os.path.abspath(env.get("REMEDIATE_OUT") or os.path.join(env.get("RUNNER_TEMP", "/tmp"),
                                                                   "torana-remediate"))
    os.makedirs(out, exist_ok=True)
    run = Run(env=env, subject_dir=os.path.abspath(env["REMEDIATE_SUBJECT"]), subject_key=key, out=out,
              holder_run=f"{env.get('GITHUB_RUN_ID', 'local')}:{env.get('GITHUB_RUN_ATTEMPT', '1')}",
              trees=parse_with(env.get("REMEDIATE_WITH", "")),
              open_pr=(env.get("REMEDIATE_OPEN_PR", "false").strip().lower() == "true"),
              ref=env["TORANA_SCAN_REF"])
    run.roots[key] = run.subject_dir
    # apply runs this before each of its own writes (lease, open-pr, refresh propose).
    here = os.path.dirname(os.path.abspath(__file__))
    run.env["TORANA_TOKEN_CMD"] = f"{shlex.quote(sys.executable)} {shlex.quote(os.path.join(here, 'ci_token.py'))}"
    return run


def write_outputs(run: Run) -> None:
    lines = ["## Torana remediation", "", *[f"- {s}" for s in run.summary or ["Nothing to do."]],
             *[f"- ❌ {e}" for e in run.errors]]
    if run.env.get("GITHUB_STEP_SUMMARY"):
        with open(run.env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    if run.env.get("GITHUB_OUTPUT"):
        with open(run.env["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"out-dir={run.out}\n")
    log("\n".join(lines))


def main() -> int:
    env = dict(os.environ)
    event = env.get("GITHUB_EVENT_NAME", "")
    if event.startswith("pull_request"):
        print(f"::error::actions/remediate never runs on `{event}`: a PR's code is not what ships, and the job's "
              f"OIDC identity must not be handed to an untrusted head. Use push to the default branch, schedule or "
              f"workflow_dispatch.", flush=True)
        return 1
    ref = env.get("TORANA_SCAN_REF", "")
    missing = [n for n in ("remediation_plan.py", "remediation_apply.py") if not os.path.isfile(os.path.join(ref, n))]
    if missing:
        print(f"::error::the scan pack at {ref or '(TORANA_SCAN_REF unset)'} has no {', '.join(missing)}: this "
              f"torana-skills release predates the fix-PR lane (the generated plugins/ tree must be rebuilt)",
              flush=True)
        return 1
    try:
        run = build_run(env)
    except (ValueError, KeyError) as exc:
        print(f"::error::{exc}", flush=True)
        return 1
    log(f"Torana remediation for {run.subject_key} (holder {run.holder_run}, open-pr {run.open_pr})")
    try:
        propose_stage(run)
        reprobe_stage(run)
        if run.open_pr:
            open_pr_stage(run)
    except ci_token.TokenError as exc:
        run.fail(f"Torana refused the token exchange: {exc}")
    write_outputs(run)
    return 1 if run.errors else 0


if __name__ == "__main__":
    sys.exit(main())
