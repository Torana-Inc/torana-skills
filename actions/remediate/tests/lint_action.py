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


def main() -> int:
    paths = sys.argv[1:] or [os.path.join(REPO, "actions", "remediate", "action.yml")]
    errs = [e for p in paths for e in check(p)]
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
