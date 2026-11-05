#!/usr/bin/env python3
"""The fix-PR lane, unattended: queue → planner → probe → propose; then re-probe stale plans; then, with
`open-pr: true`, apply every approved plan of this repository through the platform.

Spec: pantheon-cli `docs/remediation/FIX_PR_SPEC.md` § 3.4.9 (this action), § 3.4.10 (the plan's read token), § 3.4.11 (the
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
import vet_guard  # noqa: E402  ⭐ EM D-23 S3: the review lane's deterministic guards

GO_STATES = ("approved", "overridden", "removal_chosen")
LIVE_STATES = ("proposed",) + GO_STATES          # non-terminal: a stale one of these is re-probed
OPENABLE_PR_STATES = ("none", "opening_stale")
PAGE = 100                                       # the routes' limit cap (§ 3.4.3, § 3.8.4)
EXIT_LEASE_HELD = 4                              # torana CLI: lease held (§ 3.4.7)
_WITH_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?::(.+))?$")
_KEY_RE = re.compile(r"^repo:github\.com/([a-z0-9_.-]+)/([a-z0-9_.-]+)$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# ⛔ Never handed to a scan-pack script: resolvers run third-party build code. apply gets TORANA_TOKEN_CMD instead.
_SECRET_ENV = ("TORANA_TOKEN",)
_OIDC_ENV = ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "TORANA_TOKEN_CMD")
#: The stored sets read per package (the planner's `MAX_SET_READS`): one CLI call, one fresh CI token, each.
MAX_SET_READS = 10
#: What a scan pack and a CLI must offer for this script (FIX_KNOWLEDGE_CONVERGENCE § 3.6.11 startup guard).
PLANNER_FLAGS = ("--fix-scope-file", "--api-diff-file")


def safe(text: Any) -> str:
    """Escape a value for a workflow-command line (GitHub's own data escaping): no embedded newline can start a
    new `::command::` line. Applied to everything a CLI, git, the API or a plan field puts in a message."""
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def log(msg: str) -> None:
    print(safe(msg), file=sys.stderr, flush=True)


class NoCommands:
    """`::stop-commands::` around output we stream but do not control (the scan-pack scripts, the summary)."""

    def __enter__(self):
        self.tag = base64.b16encode(os.urandom(12)).decode().lower()
        print(f"::stop-commands::{self.tag}", flush=True)

    def __exit__(self, *exc):
        print(f"::{self.tag}::", flush=True)


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

    tried: set = field(default_factory=set)                  # `with` keys already attempted this run

    def fail(self, msg: str) -> None:
        print(f"::error::{safe(msg)}", flush=True)
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        print(f"::warning::{safe(msg)}", flush=True)

    def notice(self, msg: str) -> None:
        print(f"::notice::{safe(msg)}", flush=True)


def parse_with(raw: str) -> List[WithTree]:
    trees = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _WITH_RE.match(line)
        sub = (m.group(3) or "").strip("/") if m else ""
        if not m or m.group(1) in (".", "..") or m.group(2) in (".", "..") \
                or any(seg in ("", ".", "..") for seg in sub.split("/") if sub):
            raise ValueError(f"`with` wants owner/repo[:subdir], got {line!r}")
        trees.append(WithTree(m.group(1), m.group(2), sub, repo_key(m.group(1), m.group(2))))
    return trees


# ── the CLI, always with a fresh token ────────────────────────────────────────────────

def fresh_token(run: Run) -> None:
    token = ci_token.mint(run.env)
    mask(token)
    run.env["TORANA_TOKEN"] = token


def torana(run: Run, args: List[str], stdin: Optional[str] = None,
           token: Optional[str] = None) -> Tuple[int, Any, str]:
    """`torana … --format json` with a fresh CI token (or the one given). Returns (rc, parsed stdout, stderr)."""
    if token is None:
        fresh_token(run)
    env = {**run.env, "TORANA_TOKEN": token} if token is not None else run.env
    p = subprocess.run(["torana", *args, "--format", "json"], env=env, input=stdin, capture_output=True,
                       text=True)
    try:
        data = json.loads(p.stdout) if p.stdout.strip() else None
    except ValueError:
        data = None
    return p.returncode, data, p.stderr


def script(run: Run, name: str, args: List[str], stdout_path: str, platform: bool = False) -> int:
    """A scan-pack script. Its stdout (JSON with `--json`) goes to `stdout_path`; its stderr streams, with workflow
    commands off. ⛔ Its env never holds a CI token. Only a `platform` call (apply `--plan-id`, which writes) gets
    TORANA_TOKEN_CMD and the runner's OIDC request variables it needs; the planner and the local probe get none."""
    drop = _SECRET_ENV + (() if platform else _OIDC_ENV)
    env = {k: v for k, v in run.env.items() if k not in drop}
    cmd = [sys.executable, os.path.join(run.ref, name), *args]
    log(f"$ {name} {' '.join(shlex.quote(a) for a in args)}")
    with open(stdout_path, "w", encoding="utf-8") as fh, NoCommands():
        return subprocess.run(cmd, env=env, stdout=fh).returncode


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
        if not isinstance(data, (dict, list)):
            run.fail(f"listing {state} plans: not JSON")
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
    if not inside(run.out, dest):
        raise RuntimeError(f"refusing a checkout outside the scratch dir: {dest}")
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    p = subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--no-tags", f"{server}/{owner}/{repo}.git",
                        dest], env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"git clone {owner}/{repo} failed: {p.stderr.strip()[-400:]}")


def inside(root: str, path: str) -> bool:
    root, path = os.path.realpath(root), os.path.realpath(path)
    return path != root and os.path.commonpath([root, path]) == root


def revoke(run: Run, revoke_args: List[str], token: str, mint_id: Optional[str], ci: Optional[str],
           what: str) -> None:
    """⛔ Revoked as soon as the checkout is done: GitHub fixes the lifetime at one hour (§ 3.4.10), so revocation
    is the minutes-scale bound. The read token travels on stdin, never argv. The CI token for this call was minted
    BEFORE the clone, so a token-exchange failure now cannot skip the revoke; it is retried once with a fresh one."""
    if not mint_id:
        run.warn(f"the read token for {what} came back without a mint_id, so its revoke cannot be recorded and is "
                 f"skipped; it expires on GitHub's one-hour clock")
        return
    args = [*revoke_args, "--holder-run", run.holder_run, "--revoke", "--mint-id", str(mint_id)]
    rc, rerr = 1, ""
    for ci_for_call in ([ci] if ci else []) + [None]:      # the pre-minted CI token, then one fresh retry
        try:
            rc, _, rerr = torana(run, args, stdin=token, token=ci_for_call)
        except ci_token.TokenError as exc:
            rc, rerr = 1, str(exc)
        if rc == 0:
            break
    if rc != 0:
        run.fail(f"could not revoke the read token for {what} (mint {mint_id}): {rerr.strip()[-300:]}")
    else:
        log(f"revoked the read token for {what} (mint {mint_id})")


def checkout_with_token(run: Run, mint_args: List[str], revoke_args: List[str], owner: str, repo: str,
                        dest: str) -> Tuple[bool, str]:
    """Mint → mask → clone → revoke (always, once minted). Returns (ok, error code or message)."""
    rc, data, err = torana(run, [*mint_args, "--holder-run", run.holder_run])
    if rc != 0 or not isinstance(data, dict) or not data.get("token"):
        code = next((c for c in ("not_related", "token_not_needed") if c in err), "")
        return False, code or err.strip()[-400:] or f"mint exit {rc}"
    token, mint_id = str(data["token"]), data.get("mint_id")
    mask(token)
    ci: Optional[str] = None
    try:
        ci = ci_token.mint(run.env)
        mask(ci)
        clone(run, owner, repo, dest, token)
        return True, ""
    except (RuntimeError, ci_token.TokenError) as exc:
        return False, str(exc)
    finally:
        revoke(run, revoke_args, token, mint_id, ci, f"{owner}/{repo}")


def checkout_with_trees(run: Run) -> None:
    """Every `with` repository (§ 3.4.11), once per run, on first need (the first probe, a stale plan's re-probe,
    or an approved plan's apply). Same repository → no token; another → a propose-run token, only for a
    repository a tenant admin declared related."""
    for t in run.trees:
        if t.key == run.subject_key:
            run.roots.setdefault(t.key, run.subject_dir)
            continue
        if t.key in run.roots or t.key in run.tried:
            continue
        run.tried.add(t.key)
        dest = os.path.join(run.out, "src", t.repo.lower())
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


# ── what the planner cannot read itself (it holds no credential) ──────────────────────

def stale_copy(run: Run) -> Optional[str]:
    """Why this plugin copy is too old for this script, or None. ⛔ Checked BEFORE any write: an old planner rejects
    `--fix-scope-file` (argparse exit 2) and an old CLI has no `alert fix-scope` and calls the API diffs'
    pre-Atlas paths, which answer 410 (§ 3.6.11). Neither `--help` needs a token."""
    env = {k: v for k, v in run.env.items() if k not in _SECRET_ENV + _OIDC_ENV}
    try:
        plan_help = subprocess.run([sys.executable, os.path.join(run.ref, "remediation_plan.py"), "--help"],
                                   env=env, capture_output=True, text=True).stdout
        cli_help = subprocess.run(["torana", "alert", "--help"], env=env, capture_output=True, text=True).stdout
    except OSError as exc:
        return f"cannot run the planner or the torana CLI: {exc}"
    lacking = [f for f in PLANNER_FLAGS if f not in plan_help]
    if lacking:
        return f"its remediation_plan.py has no {', '.join(lacking)}"
    if "fix-scope" not in cli_help:
        return "its torana CLI has no `alert <id> fix-scope`"
    return None


def collect_move_together(run: Run, findings: List[Dict[str, Any]], path: str) -> None:
    """Every stored "must move together" set the planner will look for, read with this script's token
    (§ 3.4.6), written for `--fix-scope-file`. pypi only (the Atlas traces pypi); at most `MAX_SET_READS`
    alerts per package, the planner's own laptop cap. ⚠️ A non-zero exit leaves that alert out (→ D2 for it),
    never a failed run."""
    per: Dict[Tuple[str, str], List[str]] = {}
    for f in findings:
        aid = f.get("alert_id")
        if aid and str(f.get("ecosystem") or "").lower() == "pypi":
            ids = per.setdefault((str(f.get("package")), str(f.get("installed"))), [])
            if aid not in ids and len(ids) < MAX_SET_READS:
                ids.append(aid)
    out = []
    for ids in per.values():
        for aid in ids:
            rc, data, err = torana(run, ["alert", aid, "fix-scope", "--json"])
            if rc == 0 and isinstance(data, dict):
                out.append(data)
            else:
                log(f"no stored set for alert {aid} (exit {rc}): {err.strip()[-200:]}")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh)


def collect_api_diffs(run: Run, wanted: List[Dict[str, Any]], path: str) -> None:
    """Each API diff the planner listed (`api_diffs_wanted`), read with this script's token and `--request` (§ 3.6.7 (f)).
    The quota, eligibility and public-origin checks are the server's. A non-zero exit is recorded as
    `{state: unavailable, reason}` for that pair, never a failed run."""
    views = []
    for w in wanted:
        key = {k: w.get(k) for k in ("ecosystem", "package", "from", "to")}
        rc, data, err = torana(run, ["remediation-plans", "api-diff", "get", "--ecosystem", str(w["ecosystem"]),
                                     "--package", str(w["package"]), "--from", str(w["from"]), "--to", str(w["to"]),
                                     "--origin-source", str(w.get("origin_source") or ""),
                                     "--origin-url", str(w.get("origin_url") or ""), "--request"])
        if rc == 0 and isinstance(data, dict) and data.get("state"):
            views.append({**data, "key": key})
        else:
            views.append({"key": key, "state": "unavailable", "reason": (err.strip() or f"exit {rc}")[-200:]})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(views, fh)


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
    moves = os.path.join(run.out, "fix-scope.json")
    collect_move_together(run, data, moves)
    base = ["--repo", run.subject_dir, *scope_args(run, "plan"), "--findings", findings,
            "--fix-scope-file", moves, "--json"]
    # ⛔ The planner holds no credential (script() strips it), so it never fetches an API diff itself: run 1 asks
    # nothing and lists `api_diffs_wanted`; this script reads them with its own token; run 2 takes them from the file.
    if script(run, "remediation_plan.py", [*base, "--api-diff", "off"], plan) != 0:
        run.fail("remediation_plan.py failed")
        return
    try:
        with open(plan, encoding="utf-8") as fh:
            wanted = json.load(fh).get("api_diffs_wanted") or []
    except (OSError, ValueError, AttributeError):
        wanted = []
    if wanted:
        diffs = os.path.join(run.out, "api_diffs.json")
        collect_api_diffs(run, wanted, diffs)
        if script(run, "remediation_plan.py", [*base, "--api-diff-file", diffs], plan) != 0:
            run.fail("remediation_plan.py (with the diffs) failed")
            return
    probe = os.path.join(run.out, "probe.json")
    # Exit 1 = some group failed its gates; propose sends only gates_passed / needs_human groups (§ 3.4.7).
    # `--co-mover-api-diffs ci`: a co-mover's API diff would need a second resolve here, so it is recorded as not asked.
    rc = script(run, "remediation_apply.py", ["--plan", plan, "--apply", "--work", os.path.join(run.out, "work"),
                                              "--co-mover-api-diffs", "ci", "--json"], probe)
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


def apply_plan_id(run: Run, plan_id: str, mode: str, base_branch: str = "",
                  extra: Optional[List[str]] = None) -> Tuple[int, Any]:
    work = os.path.join(run.out, f"{mode}-{plan_id}")
    # `review-case` names its own flag with its directory in `extra` (EM D-23 S3 job 1).
    args = ["--plan-id", plan_id, "--repo", run.subject_dir, "--repo-key", run.subject_key,
            *scope_args(run, "apply"), "--apply", "--work", work, *([] if mode == "review-case" else [f"--{mode}"]),
            "--co-mover-api-diffs", "ci", "--json", *(extra or [])]
    if mode == "open-pr" and extra:
        # EM D-23 S3 job 3 (`--from-case`): no gate runs here, so neither --gates-45 nor a gate lease TTL.
        args += ["--holder-run", run.holder_run, "--base-branch", base_branch or "main"]
    elif mode == "open-pr":
        # ⭐ GATES 4 AND 5 ARE ASKED FOR HERE AND NOWHERE ELSE. They run the project's OWN install and test
        # commands (discovered by test_ladder.py) on the applied copy, which is why they are opt-in — and
        # `--open-pr` is the one invocation FD requires them for, since a PR is about to open. ⛔ Deliberately
        # NOT on `--probe`: a probe only refreshes a plan, and it runs for every stale plan on every scheduled
        # run, so paying for a full suite there would charge the customer's CI for a verdict nobody reads.
        args += ["--holder-run", run.holder_run, "--base-branch", base_branch or "main", "--gates-45"]
    report = os.path.join(run.out, f"{mode}-{plan_id}.json")
    rc = script(run, "remediation_apply.py", args, report, platform=True)
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
            if not valid_plan(run, p):
                continue
            checkout_with_trees(run)        # lazily: an empty queue still re-probes a cross-repo plan
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
            if p.get("pr_state", "none") not in OPENABLE_PR_STATES or not valid_plan(run, p):
                continue
            pid, target = p["id"], p["target_repository"]
            checkout_with_trees(run)        # the plan's rows may name other `with` trees
            saved = dict(run.roots)
            base_branch = default_branch(run.subject_dir) if target == run.subject_key else ""
            if target != run.subject_key:
                owner, repo = _KEY_RE.match(target).groups()
                dest = os.path.join(run.out, "pr", pid.lower(), repo)
                ok, why = checkout_with_token(run, ["remediation-plan", pid, "target-token"],
                                              ["remediation-plan", pid, "target-token"], owner, repo, dest)
                if not ok:
                    run.fail(f"plan {pid}: checkout of {target}: {why}")
                    continue
                run.roots[target] = dest
                base_branch = default_branch(dest)
            try:
                rc, res = apply_plan_id(run, pid, "open-pr", base_branch)
            finally:
                run.roots = saved
            status = (res or {}).get("status")
            if rc == EXIT_LEASE_HELD:
                # § 3.4.8 item 3: another run holds this target's lease. Not a failure: that run opens it.
                run.notice(f"plan {pid}: skipped, the lease on {target} is held by another run")
                run.summary.append(f"Plan {pid}: skipped (lease held by another run).")
            elif rc != 0:
                run.fail(f"plan {pid}: apply --open-pr exited {rc} ({status}: {(res or {}).get('why')})")
            else:
                pr = (res or {}).get("pr") or {}
                run.summary.append(f"Plan {pid}: {status}"
                                   f"{' ' + str(pr.get('pr_url')) if isinstance(pr, dict) and pr.get('pr_url') else ''}"
                                   f"{' (' + str(res.get('why')) + ')' if res and res.get('why') else ''}")


# ── EM D-23 S3: the four-job review lane (`mode`; .github/workflows/remediate.yml) ─────────────────────────────
#
#   1 resolve  (Torana token)   propose + re-probe as today, then a review CASE per openable approved plan
#   4 gates    (nothing)        gates 4/5 on each case (the project's own install and tests)
#   2 review   (the model key)  vet_case.py on each case, guarded
#   3 open-pr  (Torana token)   each case: checked against today's heads, its vet posted, its files sent
#
# ⛔ Jobs 1 and 3 never run gates 4/5; job 3 never resolves. Only the case, the gate results and the vets cross
# between jobs, as artifacts that live one day.

CASES_DIR, GATES_DIR, VETS_DIR = "cases", "gates", "vets"
#: `mode` input: "" = the legacy single job (unchanged); the four jobs of the reusable workflow otherwise.
MODES = ("", "resolve", "gates", "review", "open-pr")


def downloaded(run: Run, env_name: str, name: str) -> Optional[str]:
    """The `<name>.tar.gz` an earlier job uploaded: `env_name` is the file itself or the directory
    `actions/download-artifact` filled (exactly one such file inside, else GuardError). None when unset."""
    path = run.env.get(env_name, "")
    if not path:
        return None
    if os.path.isfile(path):
        return path
    hits = [os.path.join(d, f) for d, _, fs in os.walk(path) for f in fs if f == f"{name}.tar.gz"]
    if len(hits) != 1:
        raise vet_guard.GuardError(f"{env_name}: expected one {name}.tar.gz under the download, found {len(hits)}")
    return hits[0]


def openable_plans(run: Run) -> List[Dict[str, Any]]:
    """This subject's approved plans that have no PR yet, in a stable order."""
    out = []
    for state in GO_STATES:
        for p in list_plans(run, state):
            if p.get("pr_state", "none") in OPENABLE_PR_STATES and valid_plan(run, p):
                out.append(p)
    return sorted(out, key=lambda p: str(p.get("id")))


def public_cross_repo(run: Run, p: Dict[str, Any]) -> bool:
    """em3 r1 M2a / r2 M1': a public subject repository's artifacts are public, so a fix in ANOTHER repository
    (often private, e.g. the deploy repo) is never packed into one, and the Action does not open it."""
    return run.env.get("REMEDIATE_PUBLIC", "").lower() == "true" and p.get("target_repository") != run.subject_key


def case_stage(run: Run) -> None:
    """Job 1: a review case per openable plan (at most `review-max-plans`), deny-scanned, packed for upload."""
    cases = os.path.join(run.out, CASES_DIR)
    os.makedirs(cases, exist_ok=True)
    cap = int(run.env.get("REMEDIATE_REVIEW_MAX") or 5)
    plans = openable_plans(run)
    for p in plans[cap:]:
        run.summary.append(f"Plan {p['id']}: not prepared this run (review-max-plans {cap}); the next run takes it.")
    for p in plans[:cap]:
        pid, target = p["id"], p["target_repository"]
        if public_cross_repo(run, p):
            run.summary.append(f"Plan {pid}: fixes {target}, and this repository is public, so its tree is never "
                               f"packed into this run's artifacts. Open it from the laptop lane.")
            continue
        checkout_with_trees(run)
        saved = dict(run.roots)
        if target != run.subject_key and target not in run.roots:
            owner, repo = _KEY_RE.match(target).groups()
            dest = os.path.join(run.out, "pr", pid.lower(), repo)
            ok, why = checkout_with_token(run, ["remediation-plan", pid, "target-token"],
                                          ["remediation-plan", pid, "target-token"], owner, repo, dest)
            if not ok:
                run.fail(f"plan {pid}: checkout of {target}: {why}")
                continue
            run.roots[target] = dest
        try:
            rc, res = apply_plan_id(run, pid, "review-case", extra=["--review-case", cases, "--no-gates-45"])
        finally:
            run.roots = saved
        cd = os.path.join(cases, pid)
        if rc != 0 or not (res or {}).get("case"):
            run.summary.append(f"Plan {pid}: no review case ({(res or {}).get('why') or f'exit {rc}'}).")
            shutil.rmtree(cd, ignore_errors=True)
            continue
        bad = vet_guard.deny_scan(cd)
        if bad:
            run.summary.append(f"Plan {pid}: no review case: {bad}. Open it from the laptop lane.")
            shutil.rmtree(cd, ignore_errors=True)
            continue
        run.summary.append(f"Plan {pid}: review case prepared ({res.get('digest')}).")
    vet_guard.pack(cases, os.path.join(run.out, "cases.tar.gz"))


def gates_stage(run: Run) -> None:
    """Job 4 (no Torana token, no key, a GitHub-hosted runner): gates 4/5 on every case; only `gates.json` leaves."""
    cases = os.path.join(run.out, CASES_DIR)
    vet_guard.safe_extract(downloaded(run, "REMEDIATE_CASES_TAR", "cases"), cases)
    gates = os.path.join(run.out, GATES_DIR)
    os.makedirs(gates, exist_ok=True)
    if any(os.path.isfile(os.path.join(cases, d, "case.json")) for d in os.listdir(cases)):
        rc = script(run, "remediation_apply.py", ["--gates-from-case", cases, "--work",
                                                  os.path.join(run.out, "gates-work"), "--json"],
                    os.path.join(run.out, "gates.json"))
        if rc != 0:
            run.fail(f"gates 4/5 exited {rc}")
    for d in sorted(os.listdir(cases)):
        g = os.path.join(cases, d, "gates.json")
        if os.path.isfile(g):
            os.makedirs(os.path.join(gates, d))
            shutil.copyfile(g, os.path.join(gates, d, "gates.json"))
            run.summary.append(f"Plan {d}: gates 4/5 ran.")
    vet_guard.pack(gates, os.path.join(run.out, "gates.tar.gz"))


def review_stage(run: Run) -> None:
    """Job 2 (the customer's model key; nothing else): a vet per case. ⛔ Refuses to start where an OIDC request
    variable exists or on a runner that is not GitHub-hosted (em3 r1 M5/M5b): a persistent runner keeps other jobs'
    workspaces and its own credentials on a disk the reviewer's Read can reach."""
    if run.env.get("ACTIONS_ID_TOKEN_REQUEST_URL") or run.env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        raise vet_guard.GuardError("the review job can request an OIDC token (id-token: write); it must not")
    if run.env.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise vet_guard.GuardError(f"the review job runs only on a GitHub-hosted runner, not "
                                   f"{run.env.get('RUNNER_ENVIRONMENT') or 'an unknown one'}")
    if not run.env.get("ANTHROPIC_API_KEY"):
        raise vet_guard.GuardError("no ANTHROPIC_API_KEY: pass the secret to the reusable workflow")
    cases = os.path.join(run.out, CASES_DIR)
    dropped: List[str] = []
    plans = vet_guard.safe_extract(downloaded(run, "REMEDIATE_CASES_TAR", "cases"), cases, review=True,
                                   dropped=dropped)
    if dropped:
        log(f"left out of the review copy (Claude/MCP configuration): {len(dropped)} file(s)")
    gates = os.path.join(run.out, GATES_DIR)
    gates_tar = downloaded(run, "REMEDIATE_GATES_TAR", "gates")
    if gates_tar:
        vet_guard.safe_extract(gates_tar, gates)
    vets = os.path.join(run.out, VETS_DIR)
    os.makedirs(vets, exist_ok=True)
    secrets = vet_guard.secret_values(run.env)
    # L0 (2026-11-05): a hosted runner's own credential files are readable by the job user, so the reviewer's Read can
    # reach them. Their values join the exact-value filter BEFORE the reviewer starts; only a count is ever logged.
    runner_vals = vet_guard.runner_file_values(run.env)
    secrets = sorted(set(secrets) | set(runner_vals), key=len, reverse=True)
    log(f"the filter also holds {len(runner_vals)} value(s) from this runner's own credential files")
    public = run.env.get("REMEDIATE_PUBLIC", "").lower() == "true"
    for pid in plans:
        cd = os.path.join(cases, pid)
        case = vet_guard.load_json(os.path.join(cd, "case.json"))
        report = vet_guard.load_json(os.path.join(cd, "report.json"))
        g = os.path.join(gates, pid, "gates.json")
        if os.path.isfile(g):
            gd = vet_guard.load_json(g)
            if gd.get("plan_id") == pid and gd.get("digest") == case.get("digest"):
                report.update({k: gd[k] for k in ("gate_4_build", "gate_5_tests", "gate_5_coverage") if k in gd})
        rep_path = os.path.join(run.out, f"review-report-{pid}.json")
        with open(rep_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh)
        out = os.path.join(vets, f"{pid}.json")
        trees = [a for lb in sorted(case.get("labels") or {}) for a in ("--tree", f"{lb}={os.path.join(cd, 'trees', lb)}")]
        rc = script(run, "vet_case.py", ["--plan", os.path.join(cd, "plan_group.json"), "--group",
                                         str(case.get("group", 0)), "--report", rep_path, "--plan-id", pid,
                                         "--fingerprint", str(case["fingerprint"]), *trees,
                                         "--api-diff-file", os.path.join(cd, "api_diffs.json"),
                                         "--case", os.path.join(run.out, "review-cwd", pid), "--out", out,
                                         "--clean-env", "--quiet"],
                    os.path.join(run.out, f"review-{pid}.log"))
        if rc != 0 or not os.path.isfile(out):
            run.summary.append(f"Plan {pid}: the review did not run (exit {rc}); it opens as a draft.")
            continue
        vet, what = vet_guard.guard_vet(vet_guard.load_json(out), secrets, public=public)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(vet, fh)
        run.summary.append(f"Plan {pid}: reviewed: {vet.get('verdict')}"
                           + ("" if what == "ok" else f" ({what.split(':')[0]})"))
    vet_guard.pack(vets, os.path.join(run.out, "vets.tar.gz"))


def open_from_cases_stage(run: Run) -> None:
    """Job 3: each openable plan WITH a case → `apply --open-pr --from-case`, with this case's gates and its vet when
    the vet passes every check. No case → not opened by the Action (em3 r2 M1')."""
    cases, gates, vets = (os.path.join(run.out, d) for d in (CASES_DIR, GATES_DIR, VETS_DIR))
    vet_guard.safe_extract(downloaded(run, "REMEDIATE_CASES_TAR", "cases"), cases)
    for env_name, name, dest in (("REMEDIATE_GATES_TAR", "gates", gates), ("REMEDIATE_VETS_TAR", "vets", vets)):
        tar = downloaded(run, env_name, name)
        if tar:
            vet_guard.safe_extract(tar, dest)
    secrets = vet_guard.secret_values(run.env)
    for p in openable_plans(run):
        pid, target = p["id"], p["target_repository"]
        cd = os.path.join(cases, pid)
        if public_cross_repo(run, p):
            run.summary.append(f"Plan {pid}: fixes {target} from a public repository: not opened by the Action. "
                               f"Open it from the laptop lane.")
            continue
        if not os.path.isfile(os.path.join(cd, "case.json")):
            run.summary.append(f"Plan {pid}: no review case from this run, so not opened (the next run prepares it).")
            continue
        case = vet_guard.load_json(os.path.join(cd, "case.json"))
        extra = ["--from-case", cases]
        g = os.path.join(gates, pid, "gates.json")
        if os.path.isfile(g):
            extra += ["--gates-file", g]
        vet_path = checked_vet(run, pid, case, cd, os.path.join(vets, f"{pid}.json"), secrets)
        if vet_path:
            extra += ["--vet", vet_path]
        checkout_with_trees(run)
        saved = dict(run.roots)
        base_branch = default_branch(run.subject_dir) if target == run.subject_key else ""
        if target != run.subject_key:
            owner, repo = _KEY_RE.match(target).groups()
            dest = os.path.join(run.out, "pr", pid.lower(), repo)
            ok, why = checkout_with_token(run, ["remediation-plan", pid, "target-token"],
                                          ["remediation-plan", pid, "target-token"], owner, repo, dest)
            if not ok:
                run.fail(f"plan {pid}: checkout of {target}: {why}")
                continue
            run.roots[target] = dest
            base_branch = default_branch(dest)
        try:
            rc, res = apply_plan_id(run, pid, "open-pr", base_branch, extra=extra)
        finally:
            run.roots = saved
        status = (res or {}).get("status")
        if rc == EXIT_LEASE_HELD:
            run.summary.append(f"Plan {pid}: skipped (lease held by another run).")
        elif rc != 0:
            run.fail(f"plan {pid}: apply --open-pr --from-case exited {rc} ({status}: {(res or {}).get('why')})")
        else:
            pr = (res or {}).get("pr") or {}
            run.summary.append(f"Plan {pid}: {status}"
                               f"{' ' + str(pr.get('pr_url')) if isinstance(pr, dict) and pr.get('pr_url') else ''}"
                               f"{' (' + str(res.get('why')) + ')' if res and res.get('why') else ''}"
                               f"{'' if vet_path else ' (no review: opens as a draft)'}")


def checked_vet(run: Run, pid: str, case: Dict[str, Any], case_dir: str, path: str,
                secrets: List[str]) -> Optional[str]:
    """The vet job 3 may post, written beside it, or None. In order: it exists and is the § 5.1 shape (the scan
    pack's own `validate_vet`); it names THIS case's plan and fingerprint; the filter passes (patterns and this job's
    own secret values); its evidence is trimmed to files and lines in the case's trees."""
    if not os.path.isfile(path):
        return None
    sys.path.insert(0, run.ref)
    try:
        import vet_case  # noqa: E402  (the scan pack's own, so both sides validate alike)
        vet = vet_case.validate_vet(vet_guard.load_json(path))
    except Exception as exc:  # noqa: BLE001: any refusal means "no review", never a failed run
        run.summary.append(f"Plan {pid}: the review was not a valid vet ({type(exc).__name__}); opens as a draft.")
        return None
    finally:
        sys.path.remove(run.ref)
    if vet.get("plan_id") != pid or vet.get("fingerprint") != case.get("fingerprint"):
        run.summary.append(f"Plan {pid}: the review names another plan or version; opens as a draft.")
        return None
    vet, what = vet_guard.guard_vet(vet, secrets)
    vet = vet_guard.trim_evidence(vet, case_dir, case.get("labels") or {})
    out = os.path.join(run.out, f"vet-post-{pid}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(vet, fh)
    if what != "ok":
        run.summary.append(f"Plan {pid}: the review's text was withheld ({what.split(':')[0]}).")
    return out


def valid_plan(run: Run, p: Any) -> bool:
    """A plan's id becomes a path and an argv word, its target a clone URL and a path: both are checked first."""
    pid = p.get("id") if isinstance(p, dict) else None
    target = p.get("target_repository") if isinstance(p, dict) else None
    if not isinstance(pid, str) or not _UUID_RE.match(pid):
        run.fail(f"a plan with an invalid id was listed ({pid!r}): skipped")
        return False
    if not isinstance(target, str) or not _KEY_RE.match(target) or \
            any(x in (".", "..") for x in _KEY_RE.match(target).groups()):
        run.fail(f"plan {pid}: invalid target_repository {target!r}: skipped")
        return False
    return True


def default_branch(checkout: str) -> str:
    """The branch a fresh clone checked out = the remote's default branch (the PR's base)."""
    p = subprocess.run(["git", "-C", checkout, "symbolic-ref", "--short", "HEAD"], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


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
    def one_line(x: str) -> str:            # no entry can start a line of its own (a `::command::`)
        return " ⏎ ".join(str(x).splitlines())

    lines = ["## Torana remediation", "", *[f"- {one_line(s)}" for s in run.summary or ["Nothing to do."]],
             *[f"- ❌ {one_line(e)}" for e in run.errors]]
    if run.env.get("GITHUB_STEP_SUMMARY"):
        with open(run.env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    if run.env.get("GITHUB_OUTPUT"):
        with open(run.env["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"out-dir={run.out}\n")
            for name in ("cases", "gates", "vets"):           # EM D-23 S3: what the next job downloads
                tar = os.path.join(run.out, f"{name}.tar.gz")
                if os.path.isfile(tar):
                    fh.write(f"{name}-tar={tar}\n")
    with NoCommands():
        print("\n".join(lines), file=sys.stderr, flush=True)


def main() -> int:
    env = dict(os.environ)
    event = env.get("GITHUB_EVENT_NAME", "")
    if event.startswith("pull_request"):
        print(f"::error::actions/remediate never runs on `{event}`: a PR's code is not what ships, and the job's "
              f"OIDC identity must not be handed to an untrusted head. Use push to the default branch, schedule or "
              f"workflow_dispatch.", flush=True)
        return 1
    mode = env.get("REMEDIATE_MODE", "").strip()
    if mode not in MODES:
        print(f"::error::unknown mode {safe(mode)!r}: one of {', '.join(m or '(none)' for m in MODES)}", flush=True)
        return 1
    ref = env.get("TORANA_SCAN_REF", "")
    if mode in ("gates", "review"):
        # EM D-23 S3: these two jobs hold no Torana token and never call Torana, so no CLI check and no plan read.
        need = ("remediation_apply.py", "review_case.py") if mode == "gates" else ("vet_case.py", "assumptions.py")
        missing = [n for n in need if not os.path.isfile(os.path.join(ref, n))]
        if missing:
            print(f"::error::the scan pack at {safe(ref)} has no {', '.join(missing)}: rebuild the plugin tree",
                  flush=True)
            return 1
        try:
            run = build_run(env)
            (gates_stage if mode == "gates" else review_stage)(run)
        except (vet_guard.GuardError, ValueError, KeyError, OSError) as exc:
            print(f"::error::{safe(str(exc))}", flush=True)
            return 1
        write_outputs(run)
        return 1 if run.errors else 0
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
    why = stale_copy(run)
    if why:
        print(f"::error::the torana-skills plugin copy at {safe(ref)} is too old for this action: {safe(why)}. "
              f"Use a torana-skills release that ships the fix-knowledge planner and CLI together (the plugin's "
              f"torana-scan references and torana_cli wheel are rebuilt in the same release). Nothing was written.",
              flush=True)
        return 1
    if run.open_pr:
        default, ref = env.get("REMEDIATE_DEFAULT_BRANCH", ""), env.get("GITHUB_REF", "")
        if not default or ref != f"refs/heads/{default}":
            # ⛔ A PR's base is the repository's default branch; a dispatch on another branch would probe and
            # apply against code that is not what ships.
            print(f"::error::open-pr runs only on the default branch ({safe(default) or 'unknown'}); this run is on "
                  f"{safe(ref) or 'an unknown ref'}. Run it from the default branch, or set open-pr: false.",
                  flush=True)
            return 1
    log(f"Torana remediation for {run.subject_key} (holder {run.holder_run}, open-pr {run.open_pr})")
    try:
        if mode == "open-pr":
            # EM D-23 S3 job 3: open from the cases jobs 2 and 4 judged; never propose, re-probe or resolve here.
            open_from_cases_stage(run)
        else:
            propose_stage(run)
            reprobe_stage(run)
            if run.open_pr and mode == "resolve":
                case_stage(run)
            elif run.open_pr:
                # ⚠️ The legacy single-job lane (no `mode`): it resolves AND runs gates 4/5 (the project's own install
                # and tests, importing the upgraded package) in the job that holds the Torana token. Since EM D-23 S3
                # that token may record an AI review, so such code could post one for this repository's plans (the
                # M1 residual in full). The reusable workflow (.github/workflows/remediate.yml) is the safe shape.
                open_pr_stage(run)
    except ci_token.TokenError as exc:
        run.fail(f"Torana refused the token exchange: {exc}")
    except vet_guard.GuardError as exc:
        run.fail(f"the review lane refused its input: {exc}")
    write_outputs(run)
    return 1 if run.errors else 0


if __name__ == "__main__":
    sys.exit(main())
