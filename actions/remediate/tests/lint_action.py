#!/usr/bin/env python3
"""Lint a composite action: structure, then shellcheck on every `run:` block, then actionlint on a caller workflow.

    python3 actions/remediate/tests/lint_action.py [actions/<name>/action.yml …]

Needs PyYAML, `shellcheck` and `actionlint` on PATH (`pip install pyyaml shellcheck-py actionlint-py`).
actionlint does not read a composite action's own steps, so each `run:` block is extracted, its `${{ … }}`
expressions replaced by a variable (`${GHA_EXPR}`, so no constant-test false positive), and shellchecked as bash; actionlint then checks the quickstart
workflow below, which validates the inputs a caller passes against action.yml.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
EXPR = re.compile(r"\$\{\{.*?\}\}")

CALLER = """\
name: torana-remediate
on:
  schedule: [{ cron: '41 5 * * 1-5' }]
  workflow_dispatch:
jobs:
  remediate:
    permissions: { id-token: write, contents: read }
    runs-on: ubuntu-latest
    steps:
      - uses: ./actions/remediate
        with:
          torana-url: https://app.example.com
          with: |
            acme/deploy:base-image
          open-pr: true
"""


def check(path: str) -> list:
    errs = []
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if doc.get("runs", {}).get("using") != "composite":
        errs.append(f"{path}: runs.using must be composite")
    for name, spec in (doc.get("inputs") or {}).items():
        if "description" not in spec:
            errs.append(f"{path}: input {name} has no description")
    for i, step in enumerate(doc["runs"].get("steps") or []):
        if "run" in step:
            if step.get("shell") != "bash":
                errs.append(f"{path}: step {i} ({step.get('name')}) needs shell: bash")
            body = EXPR.sub("${GHA_EXPR}", step["run"])
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tf:
                tf.write("#!/usr/bin/env bash\n" + body)
            p = subprocess.run(["shellcheck", "-s", "bash", tf.name], capture_output=True, text=True)
            os.unlink(tf.name)
            if p.returncode != 0:
                errs.append(f"{path}: step {i} ({step.get('name')}):\n{p.stdout}")
    return errs


WORKFLOW = os.path.join(REPO, ".github", "workflows", "remediate.yml")
ACTION_USE = re.compile(r"^Torana-Inc/torana-skills/actions/remediate@(\S+)$")
#: EM D-23 S3: who may hold what. resolve/open-pr talk to Torana; review holds no Torana identity. ⛔ No gates job
#: (S3 d2, em3 d1 M1): no job runs the project's own build or tests.
TORANA_JOBS, BARE_JOBS = ("resolve", "open-pr"), ("review",)
#: The review's runs-on, exactly (delta d2 § 2): GitHub-hosted, or the isolated pool's labels; never torana-runs-on.
REVIEW_RUNS_ON = ("${{ inputs.untrusted-runner == 'isolated' && fromJSON(inputs.untrusted-runner-labels) "
                  "|| 'ubuntu-latest' }}")
#: Each model credential: the secret, and the review step's input it must appear as, ONCE.
CREDENTIAL_SECRETS = (("ANTHROPIC_API_KEY", "anthropic-api-key"), ("CLAUDE_CODE_OAUTH_TOKEN", "claude-oauth-token"))


def check_workflow(path: str = WORKFLOW) -> list:
    """The reviewed lane's shape, pinned (S3 plan § 1; em3 r1 M5/M5b, r2 m2; delta d2):
    - the workflow grants nothing by default, and only resolve/open-pr hold `id-token: write`;
    - exactly three jobs: no gates job (no job runs the project's own build or tests);
    - review has `permissions: {}`, no container, and runs on exactly `REVIEW_RUNS_ON` (GitHub-hosted or the isolated
      pool's labels), never the caller's torana-runs-on;
    - `untrusted-runner` is a required input;
    - each model credential appears in the review job only, once, as the action step's input;
    - every use of the Action names THE SAME ref, never `./` (which would resolve in the caller's repository);
    - every upload keeps its artifact one day, and every download is by artifact id;
    - open-pr runs whatever review's result is (its `if:` names no review result)."""
    errs = []
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    doc = yaml.safe_load(text)
    jobs = doc.get("jobs") or {}
    if doc.get("permissions") != {}:
        errs.append(f"{path}: top-level permissions must be {{}}")
    refs = set()
    for name, job in jobs.items():
        perms = job.get("permissions")
        if name in TORANA_JOBS and perms != {"id-token": "write", "contents": "read"}:
            errs.append(f"{path}: job {name} must have exactly id-token: write, contents: read")
        if name in TORANA_JOBS and job.get("container") != "${{ inputs.torana-container }}":
            errs.append(f"{path}: job {name} must take its container from inputs.torana-container (empty = none)")
        if name in BARE_JOBS:
            if "container" in job:
                errs.append(f"{path}: job {name} must not run in a caller-chosen container")
            if perms != {}:
                errs.append(f"{path}: job {name} must have permissions: {{}}")
            if job.get("runs-on") != REVIEW_RUNS_ON:
                errs.append(f"{path}: job {name} must run on exactly {REVIEW_RUNS_ON}")
        if name not in (*TORANA_JOBS, *BARE_JOBS):
            errs.append(f"{path}: unexpected job {name}")
        for i, step in enumerate(job.get("steps") or []):
            uses = str(step.get("uses") or "")
            if uses.startswith("./"):
                errs.append(f"{path}: {name} step {i}: `uses: ./…` resolves in the CALLER's repository")
            m = ACTION_USE.match(uses)
            if m:
                refs.add(m.group(1))
                for _, inp in CREDENTIAL_SECRETS:
                    if (step.get("with") or {}).get(inp) and name != "review":
                        errs.append(f"{path}: {name} step {i} passes a model credential ({inp})")
            if uses.startswith("actions/upload-artifact@") and (step.get("with") or {}).get("retention-days") != 1:
                errs.append(f"{path}: {name} step {i}: an upload must keep its artifact 1 day")
            if uses.startswith("actions/download-artifact@") and "artifact-ids" not in (step.get("with") or {}):
                errs.append(f"{path}: {name} step {i}: download by artifact id, never by name")
            for secret, _ in CREDENTIAL_SECRETS:
                if secret in str(step.get("env") or ""):
                    errs.append(f"{path}: {name} step {i}: {secret} travels as the review step's input only")
    if len(refs) != 1:
        errs.append(f"{path}: every use of actions/remediate must name the same ref, found {sorted(refs)}")
    for secret, inp in CREDENTIAL_SECRETS:
        lines = [ln for ln in text.splitlines() if f"secrets.{secret}" in ln and not ln.lstrip().startswith("#")]
        if len(lines) != 1 or f"{inp}:" not in lines[0]:
            errs.append(f"{path}: secrets.{secret} must appear exactly once, as the review step's {inp} input")
    if sorted(jobs) != sorted((*TORANA_JOBS, *BARE_JOBS)):
        errs.append(f"{path}: the jobs must be exactly {sorted((*TORANA_JOBS, *BARE_JOBS))}, found {sorted(jobs)}")
    trig = (doc.get("on") or doc.get(True) or {}).get("workflow_call") or {}
    ur = (trig.get("inputs") or {}).get("untrusted-runner") or {}
    if ur.get("required") is not True or "default" in ur:
        errs.append(f"{path}: input untrusted-runner must be required, with no default")
    if "review" in str((jobs.get("open-pr") or {}).get("if", "")).replace("inputs.review", ""):
        errs.append(f"{path}: open-pr's if: must not depend on the review job's result")
    p = subprocess.run(["actionlint", path], cwd=REPO, capture_output=True, text=True)
    if p.returncode != 0:
        errs.append(f"actionlint {path}:\n{p.stdout}{p.stderr}")
    return errs


def main() -> int:
    paths = sys.argv[1:] or [os.path.join(REPO, "actions", "remediate", "action.yml")]
    errs = [e for p in paths for e in check(p)]
    if os.path.isfile(WORKFLOW):
        errs += check_workflow()
    if any(p.endswith(os.path.join("remediate", "action.yml")) for p in paths):
        wf_dir = os.path.join(REPO, ".github", "workflows")
        made = not os.path.isdir(wf_dir)
        os.makedirs(wf_dir, exist_ok=True)
        wf = os.path.join(wf_dir, "_lint_remediate_caller.yml")
        with open(wf, "w", encoding="utf-8") as fh:
            fh.write(CALLER)
        try:
            p = subprocess.run(["actionlint", wf], cwd=REPO, capture_output=True, text=True)
            if p.returncode != 0:
                errs.append(f"actionlint:\n{p.stdout}{p.stderr}")
        finally:
            os.unlink(wf)
            if made:
                os.removedirs(wf_dir)
    for e in errs:
        print(e)
    print(f"{len(paths)} action(s): {'FAIL' if errs else 'ok'}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
