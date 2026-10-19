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
ap.add_argument("--json", action="store_true")
a = ap.parse_args()


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


withs = dict(w.rsplit("=", 1) for w in a.with_roots) if a.plan_id else {}
log("script remediation_apply.py " + (f"--plan {os.path.basename(a.plan)}" if a.plan else f"--plan-id {a.plan_id}")
    + "".join(f" --with <{os.path.basename(r)}>={k}" for r, k in withs.items())
    + (" --probe" if a.probe else "") + (" --open-pr" if a.open_pr else "")
    + (f" --holder-run {a.holder_run}" if a.holder_run else ""))
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
rc, pr = write(["remediation-plan", a.plan_id, "open-pr", "--diff", "changes.diff", "--root", "copy",
                "--probe", "probe-report.json", "--base-sha", "HEAD"])
write(["remediation-plans", "lease", "release", lease["id"], "--holder-run", a.holder_run])
print(json.dumps({"plan_id": a.plan_id, "mode": "open-pr", "status": "opened", "pr": pr}))
