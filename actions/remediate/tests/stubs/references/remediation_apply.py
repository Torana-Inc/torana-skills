#!/usr/bin/env python3
"""Stub apply: the argv contract of remediation_apply.py (FIX_PR_SPEC.md § 3.4.8) and its CLI calls, with the
lead's TORANA_TOKEN_CMD rule — a fresh token from that command before EACH write (lease acquire, open-pr, lease
release, refresh propose). The resolver and gates are not modelled."""

import argparse
import json
import os
import shlex
import subprocess
import sys

ap = argparse.ArgumentParser()
ap.add_argument("--plan")
ap.add_argument("--plan-id")
ap.add_argument("--repo")
ap.add_argument("--repo-key")
ap.add_argument("--with", dest="with_roots", action="append", default=[])
ap.add_argument("--apply", action="store_true")
ap.add_argument("--work")
ap.add_argument("--probe", action="store_true")
ap.add_argument("--open-pr", action="store_true")
ap.add_argument("--holder-run")
ap.add_argument("--base-branch")
ap.add_argument("--co-mover-api-diffs", choices=("request", "read", "off", "ci"))
# Gates 4/5 (phase-4 spec P3): asked for on --open-pr only. The stub only has to ACCEPT it — the real
# gates are tested in pantheon-cli (tests/test_remediation_apply_timeout.py).
ap.add_argument("--gates-45", dest="gates_45", action="store_true")
ap.add_argument("--json", action="store_true")
a = ap.parse_args()
if a.co_mover_api_diffs:                       # recorded beside the log (the call-sequence line is unchanged)
    with open(os.environ["STUB_LOG"] + ".co-mover-api-diffs", "w") as fh:
        fh.write(a.co_mover_api_diffs)


def log(line):
    with open(os.environ["STUB_LOG"], "a") as fh:
        fh.write(line + "\n")


def write(args):
    """One CLI write, with a token fresh from TORANA_TOKEN_CMD."""
    cmd = os.environ["TORANA_TOKEN_CMD"]
    env = dict(os.environ, TORANA_TOKEN=subprocess.run(shlex.split(cmd), capture_output=True, text=True,
                                                      check=True).stdout)
    p = subprocess.run(["torana", *args, "--format", "json"], env=env, capture_output=True, text=True)
    return p.returncode, (json.loads(p.stdout) if p.stdout.strip() else None)


assert "TORANA_TOKEN" not in os.environ, "TEST FAILURE: a CI token reached apply's env"
if a.plan:
    for k in ("TORANA_TOKEN_CMD", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        assert k not in os.environ, f"TEST FAILURE: {k} reached the local probe"
withs = dict(w.rsplit("=", 1) for w in a.with_roots) if a.plan_id else {}
log("script remediation_apply.py " + (f"--plan {os.path.basename(a.plan)}" if a.plan else f"--plan-id {a.plan_id}")
    + "".join(f" --with <{os.path.basename(r)}>={k}" for r, k in withs.items())
    + (" --probe" if a.probe else "") + (" --open-pr" if a.open_pr else "")
    + (f" --holder-run {a.holder_run}" if a.holder_run else "")
    + (f" --base-branch {a.base_branch}" if a.base_branch else "")
    # ⭐ RENDERED so the call-sequence test proves phase-4 spec P3: gates 4/5 are asked for at --open-pr
    # and NOWHERE else. Accepting the flag without recording it would let the probe start running the
    # customer's suite on every scheduled run and no test would notice.
    + (" --gates-45" if a.gates_45 else ""))
if a.plan:
    print(json.dumps({"repo": "stub", "applied": True, "groups": [{"status": "gates_passed"}]}))
    sys.exit(0)
if a.probe:
    write(["remediation-plans", "propose", "--plan", "p.json", "--findings", "f.json", "--probe", "r.json",
           "--refresh-plan-id", a.plan_id, "--repo-key", a.repo_key])
    print(json.dumps({"plan_id": a.plan_id, "mode": "probe", "report": {"status": "gates_passed"}}))
    sys.exit(0)
assert a.holder_run, "open-pr without --holder-run"
for root in withs:
    # the target checkout must be a real git tree: apply takes --base-sha from its HEAD
    head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True)
    assert head.returncode == 0, root
    cfg = open(os.path.join(root, ".git", "config")).read()
    assert "extraheader" not in cfg and "ghs_" not in cfg, "a credential persisted in .git/config"
rc, lease = write(["remediation-plans", "lease", "acquire", "--plan-id", a.plan_id, "--holder-run", a.holder_run])
if rc == 4:                       # § 3.4.8 item 3: another run holds the lease
    print(json.dumps({"plan_id": a.plan_id, "mode": "open-pr", "status": "lease_held"}))
    sys.exit(4)
rc, pr = write(["remediation-plan", a.plan_id, "open-pr", "--diff", "changes.diff", "--root", "copy",
                "--probe", "probe-report.json", "--base-sha", "HEAD"])
write(["remediation-plans", "lease", "release", lease["id"], "--holder-run", a.holder_run])
print(json.dumps({"plan_id": a.plan_id, "mode": "open-pr", "status": "opened", "pr": pr}))
