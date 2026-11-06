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
from typing import Any, Optional

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
#: EM D-23 S2 lane B.
JUDGE_WORKFLOW = os.path.join(REPO, ".github", "workflows", "judge.yml")
ACTION_USE = re.compile(r"^Torana-Inc/torana-skills/actions/remediate@(\S+)$")
#: EM D-23 S3: who may hold what. resolve/open-pr talk to Torana; review holds no Torana identity. ⛔ No gates job
#: (S3 d2, em3 d1 M1): no job runs the project's own build or tests.
TORANA_JOBS, BARE_JOBS = ("resolve", "open-pr"), ("review",)
#: Per workflow: each Torana job's exact permissions, and the one bare job (no permissions, holds the credential).
SHAPES = {
    WORKFLOW: ({"resolve": {"id-token": "write", "contents": "read"},
                "open-pr": {"id-token": "write", "contents": "read"}}, "review"),
    JUDGE_WORKFLOW: ({"collect": {"id-token": "write", "actions": "read"}, "post": {"id-token": "write"}}, "judge"),
}
#: action.yml `mode` values (remediate.py `MODES`), and the steps that alone may carry a model credential.
MODES = ("", "resolve", "review", "open-pr", "judge-collect", "judge", "judge-post")
CREDENTIAL_STEPS = ("Review (the model credential reaches this step only)",
                    "Judge (the model credential reaches this step only)")
CREDENTIAL_INPUTS = ("inputs.anthropic-api-key", "inputs.claude-oauth-token")
#: The review's runs-on, exactly (delta d2 § 2): GitHub-hosted, or the isolated pool's labels; never torana-runs-on.
REVIEW_RUNS_ON = ("${{ inputs.untrusted-runner == 'isolated' && fromJSON(inputs.untrusted-runner-labels) "
                  "|| 'ubuntu-latest' }}")
#: Each model credential: the secret, and the review step's input it must appear as, ONCE.
CREDENTIAL_SECRETS = (("ANTHROPIC_API_KEY", "anthropic-api-key"), ("CLAUDE_CODE_OAUTH_TOKEN", "claude-oauth-token"))


def check_workflow(path: str = WORKFLOW, refs: Optional[set] = None) -> list:
    """A reusable workflow's shape, pinned (S3 plan § 1; em3 r1 M5/M5b, r2 m2; delta d2; EM D-23 S2 § 3.5.4):
    - the workflow grants nothing by default, and each Torana job holds exactly its `SHAPES` permissions;
    - exactly those jobs plus the one bare job: no gates job (no job runs the project's own build or tests);
    - the bare job has `permissions: {}`, no container, and runs on exactly `REVIEW_RUNS_ON` (GitHub-hosted or the
      isolated pool's labels), never the caller's torana-runs-on;
    - `untrusted-runner` is a required input;
    - each model credential appears in the bare job only, once, as the action step's input;
    - every use of the Action names THE SAME ref (across both workflows: `refs`), never `./`;
    - every upload keeps its artifact one day, and every download is by artifact id;
    - remediate.yml: open-pr runs whatever review's result is (its `if:` names no review result)."""
    errs = []
    torana_jobs, bare = SHAPES[path]
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    doc = yaml.safe_load(text)
    jobs = doc.get("jobs") or {}
    if doc.get("permissions") != {}:
        errs.append(f"{path}: top-level permissions must be {{}}")
    refs = set() if refs is None else refs
    for name, job in jobs.items():
        perms = job.get("permissions")
        if name in torana_jobs and perms != torana_jobs[name]:
            errs.append(f"{path}: job {name} must have exactly {torana_jobs[name]}")
        if name in torana_jobs and job.get("container") != "${{ inputs.torana-container }}":
            errs.append(f"{path}: job {name} must take its container from inputs.torana-container (empty = none)")
        if name == bare:
            if "container" in job:
                errs.append(f"{path}: job {name} must not run in a caller-chosen container")
            if perms != {}:
                errs.append(f"{path}: job {name} must have permissions: {{}}")
            if job.get("runs-on") != REVIEW_RUNS_ON:
                errs.append(f"{path}: job {name} must run on exactly {REVIEW_RUNS_ON}")
        if name not in (*torana_jobs, bare):
            errs.append(f"{path}: unexpected job {name}")
        for i, step in enumerate(job.get("steps") or []):
            uses = str(step.get("uses") or "")
            if uses.startswith("./"):
                errs.append(f"{path}: {name} step {i}: `uses: ./…` resolves in the CALLER's repository")
            m = ACTION_USE.match(uses)
            if m:
                refs.add(m.group(1))
                for _, inp in CREDENTIAL_SECRETS:
                    if (step.get("with") or {}).get(inp) and name != bare:
                        errs.append(f"{path}: {name} step {i} passes a model credential ({inp})")
            if uses.startswith("actions/upload-artifact@") and (step.get("with") or {}).get("retention-days") != 1:
                errs.append(f"{path}: {name} step {i}: an upload must keep its artifact 1 day")
            if uses.startswith("actions/download-artifact@") and "artifact-ids" not in (step.get("with") or {}):
                errs.append(f"{path}: {name} step {i}: download by artifact id, never by name")
            for secret, _ in CREDENTIAL_SECRETS:
                if secret in str(step.get("env") or ""):
                    errs.append(f"{path}: {name} step {i}: {secret} travels as the {bare} step's input only")
    if len(refs) != 1:
        errs.append(f"{path}: every use of actions/remediate must name the same ref, found {sorted(refs)}")
    for secret, inp in CREDENTIAL_SECRETS:
        lines = [ln for ln in text.splitlines() if f"secrets.{secret}" in ln and not ln.lstrip().startswith("#")]
        if len(lines) != 1 or f"{inp}:" not in lines[0]:
            errs.append(f"{path}: secrets.{secret} must appear exactly once, as the {bare} step's {inp} input")
    if sorted(jobs) != sorted((*torana_jobs, bare)):
        errs.append(f"{path}: the jobs must be exactly {sorted((*torana_jobs, bare))}, found {sorted(jobs)}")
    trig = (doc.get("on") or doc.get(True) or {}).get("workflow_call") or {}
    ur = (trig.get("inputs") or {}).get("untrusted-runner") or {}
    if ur.get("required") is not True or "default" in ur:
        errs.append(f"{path}: input untrusted-runner must be required, with no default")
    if path == WORKFLOW and "review" in str((jobs.get("open-pr") or {}).get("if", "")).replace("inputs.review", ""):
        errs.append(f"{path}: open-pr's if: must not depend on the review job's result")
    p = subprocess.run(["actionlint", path], cwd=REPO, capture_output=True, text=True)
    if p.returncode != 0:
        errs.append(f"actionlint {path}:\n{p.stdout}{p.stderr}")
    return errs


_IF_TOKEN = re.compile(r"inputs\.mode|'[^']*'|==|!=|&&|\|\||[()]|\s+")


def step_runs(cond: Any, mode: str) -> bool:
    """Does an action.yml step with `if: cond` run in `mode`? Only `inputs.mode` comparisons joined by && / || are
    allowed; anything else is a lint error (the matrix must be decidable here)."""
    if cond is None:
        return True
    expr = str(cond).strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2]
    out, pos = [], 0
    for m in _IF_TOKEN.finditer(expr):
        if m.start() != pos:
            raise ValueError(f"cannot evaluate if: {cond!r}")
        tok, pos = m.group(0), m.end()
        out.append({"inputs.mode": repr(mode), "&&": " and ", "||": " or "}.get(tok, tok))
    if pos != len(expr):
        raise ValueError(f"cannot evaluate if: {cond!r}")
    return bool(eval("".join(out), {"__builtins__": {}}, {}))  # noqa: S307 (tokens checked above)


def check_modes(path: str) -> list:
    """EM D-23 S2 § 3.5.4 lint rules (2) and (3) on action.yml, evaluated for EVERY mode:
    (2) a step that runs in `judge` must not install the CLI (`torana_cli`), set a `TORANA_*` or `GITHUB_TOKEN` env, or
        use actions/checkout (the job holding the model credential has nothing else);
    (3) only the Review and Judge steps may carry the credential inputs, and each runs in one model mode only."""
    errs = []
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    for i, step in enumerate(doc["runs"].get("steps") or []):
        name = step.get("name") or f"step {i}"
        try:
            runs_in = [m for m in MODES if step_runs(step.get("if"), m)]
        except ValueError as e:
            errs.append(f"{path}: {name}: {e}")
            continue
        env = step.get("env") or {}
        body = f"{step.get('run') or ''}\n{step.get('uses') or ''}"
        if "judge" in runs_in:
            if "torana_cli" in body:
                errs.append(f"{path}: {name} runs in mode judge and installs the torana CLI")
            if any(k.startswith("TORANA_") or k == "GITHUB_TOKEN" for k in env):
                errs.append(f"{path}: {name} runs in mode judge and sets a TORANA_* or GITHUB_TOKEN env")
            if str(step.get("uses") or "").startswith("actions/checkout@"):
                errs.append(f"{path}: {name} runs in mode judge and checks out the repository")
        carries = any(c in str(v) for v in env.values() for c in CREDENTIAL_INPUTS) or \
            any(c in str(step.get("with") or "") for c in CREDENTIAL_INPUTS)
        if carries and name not in CREDENTIAL_STEPS:
            errs.append(f"{path}: {name} carries a model credential; only the Review and Judge steps may")
        if carries and (len(runs_in) != 1 or runs_in[0] not in ("review", "judge")):
            errs.append(f"{path}: {name} carries a model credential but runs in {runs_in}")
    return errs


def main() -> int:
    paths = sys.argv[1:] or [os.path.join(REPO, "actions", "remediate", "action.yml")]
    errs = [e for p in paths for e in check(p)]
    refs: set = set()
    for wf in (WORKFLOW, JUDGE_WORKFLOW):
        if os.path.isfile(wf):
            errs += check_workflow(wf, refs)
    if len(refs) > 1:
        errs.append(f"the workflows' uses of actions/remediate name different refs: {sorted(refs)}")
    errs += [e for p in paths if p.endswith(os.path.join("remediate", "action.yml")) for e in check_modes(p)]
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
