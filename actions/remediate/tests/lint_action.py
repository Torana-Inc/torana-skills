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
#: EM D-23 S3: who may hold what. resolve/open-pr talk to Torana; gates/review hold no Torana identity.
TORANA_JOBS, BARE_JOBS = ("resolve", "open-pr"), ("gates", "review")


def check_workflow(path: str = WORKFLOW) -> list:
    """The reviewed lane's shape, pinned (S3 plan § 1; em3 r1 M5/M5b, r2 m2):
    - the workflow grants nothing by default, and only resolve/open-pr hold `id-token: write`;
    - gates/review have `permissions: {}` and run on `ubuntu-latest` (GitHub-hosted, ephemeral), never the caller's
      runner input;
    - the model key appears in the review job only, and there only on the action step's `anthropic-api-key`;
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
        if name in BARE_JOBS:
            if perms != {}:
                errs.append(f"{path}: job {name} must have permissions: {{}}")
            if job.get("runs-on") != "ubuntu-latest":
                errs.append(f"{path}: job {name} must run on ubuntu-latest (GitHub-hosted)")
        if name not in (*TORANA_JOBS, *BARE_JOBS):
            errs.append(f"{path}: unexpected job {name}")
        for i, step in enumerate(job.get("steps") or []):
            uses = str(step.get("uses") or "")
            if uses.startswith("./"):
                errs.append(f"{path}: {name} step {i}: `uses: ./…` resolves in the CALLER's repository")
            m = ACTION_USE.match(uses)
            if m:
                refs.add(m.group(1))
                key = (step.get("with") or {}).get("anthropic-api-key")
                if key and name != "review":
                    errs.append(f"{path}: {name} step {i} passes the model key")
            if uses.startswith("actions/upload-artifact@") and (step.get("with") or {}).get("retention-days") != 1:
                errs.append(f"{path}: {name} step {i}: an upload must keep its artifact 1 day")
            if uses.startswith("actions/download-artifact@") and "artifact-ids" not in (step.get("with") or {}):
                errs.append(f"{path}: {name} step {i}: download by artifact id, never by name")
            if "ANTHROPIC_API_KEY" in str(step.get("env") or ""):
                errs.append(f"{path}: {name} step {i}: the key travels as the review step's input only")
    if len(refs) != 1:
        errs.append(f"{path}: every use of actions/remediate must name the same ref, found {sorted(refs)}")
    key_lines = [ln for ln in text.splitlines() if "secrets.ANTHROPIC_API_KEY" in ln and not ln.lstrip().startswith("#")]
    if len(key_lines) != 1 or "anthropic-api-key:" not in key_lines[0]:
        errs.append(f"{path}: secrets.ANTHROPIC_API_KEY must appear exactly once, as the review step's input")
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
