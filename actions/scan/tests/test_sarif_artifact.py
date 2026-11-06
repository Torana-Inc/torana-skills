"""actions/scan, EM S-07b § 3.0-3.1: the SARIF artifact Torana's GitHub App pulls, and the run key on the push.

⛔ These run the code FROM action.yml (the blocks between `# ARTIFACT-DECIDE-BEGIN/END` and `# META-BEGIN/END`),
never a copy, so the tests and the Action cannot drift. Stdlib only:

    python3 -m unittest discover -s actions/scan/tests -v
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ACTION_YML = os.path.join(os.path.dirname(HERE), "action.yml")
TEXT = open(ACTION_YML, encoding="utf-8").read()
HEAD = "AbCdEf" + "0" * 34
GUID = "0f9e8d7c-6b5a-4321-9876-543210fedcba"


def block(begin: str, end: str) -> str:
    a = TEXT.rindex("\n", 0, TEXT.index(begin)) + 1
    return textwrap.dedent(TEXT[a:TEXT.index(end)])


def step(name: str) -> str:
    """The text of one step, from its `- name:` line to the next step."""
    i = TEXT.index(f"- name: {name}")
    j = TEXT.find("\n    - name:", i + 1)
    return TEXT[i:j if j > 0 else len(TEXT)]


def decide(want: str, private: str, days: str = "3"):
    with tempfile.NamedTemporaryFile("w+", delete=False) as out:
        path = out.name
    try:
        script = "set -euo pipefail\n" + block("# ARTIFACT-DECIDE-BEGIN", "# ARTIFACT-DECIDE-END")
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           env=dict(os.environ, WANT=want, PRIVATE=private, DAYS=days, GITHUB_OUTPUT=path))
        outputs = dict(line.split("=", 1) for line in open(path).read().split() if "=" in line)
        return r.returncode, r.stdout + r.stderr, outputs.get("upload")
    finally:
        os.unlink(path)


class DecideTheArtifact(unittest.TestCase):
    def test_auto_uploads_only_on_a_private_repository(self):
        self.assertEqual(decide("auto", "true")[2], "true")
        rc, log, up = decide("auto", "false")
        self.assertEqual((rc, up), (0, "false"))
        self.assertIn("not published as an artifact", log)

    def test_unknown_visibility_is_treated_as_public(self):
        """Fail closed: an event without `repository.private` never publishes the findings."""
        self.assertEqual(decide("auto", "")[2], "false")

    def test_the_input_forces_it_either_way(self):
        self.assertEqual(decide("true", "false")[2], "true")
        self.assertEqual(decide("false", "true")[2], "false")

    def test_a_bad_value_fails_the_step(self):
        for want, days, why in (("yes", "3", "auto|true|false"), ("auto", "x", "whole number"),
                                ("auto", "0", "1-90"), ("auto", "91", "1-90"), ("auto", "", "whole number")):
            rc, log, up = decide(want, "true", days)
            self.assertEqual(rc, 1, f"{want}/{days}: {log}")
            self.assertIn(why, log)
            self.assertIsNone(up)


def run_meta(tmp, scope, doc):
    script = os.path.join(tmp, "meta.py")
    open(script, "w").write(block("# META-BEGIN", "# META-END"))
    sp, mp = os.path.join(tmp, "torana.sarif"), os.path.join(tmp, "torana-scan-meta.json")
    for p in (sp, mp):
        if os.path.exists(p):
            os.remove(p)
    if doc is not None:
        json.dump(doc, open(sp, "w"))
    r = subprocess.run([sys.executable, "-I", script], capture_output=True, text=True,
                       env=dict(os.environ, SARIF=sp, META=mp, SCOPE=scope, HEAD_SHA=HEAD, RUN_ID="7", RUN_ATTEMPT="2",
                                EVENT="push"))
    return r.returncode, r.stdout + r.stderr, (json.load(open(mp)) if os.path.exists(mp) else None)


def sarif(with_ad=True):
    run = {"tool": {"driver": {"name": "t"}}, "results": []}
    if with_ad:
        run["automationDetails"] = {"id": GUID, "correlationGuid": GUID}
    return {"version": "2.1.0", "runs": [run]}


class TheScanMetaFile(unittest.TestCase):
    def test_it_vouches_for_the_scope_the_scan_declared(self):
        with tempfile.TemporaryDirectory() as tmp:
            for scope in ("full", "changed"):
                rc, log, meta = run_meta(tmp, scope, sarif())
                self.assertEqual(rc, 0, log)
                self.assertEqual(meta, {"schema": "torana.scan_meta.v1", "scan_id": GUID, "scan_scope": scope,
                                        "head_sha": HEAD.lower(), "run_id": 7, "run_attempt": 2, "event": "push"})

    def test_nothing_to_vouch_for_writes_nothing_and_never_fails_the_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, scope, doc in (("no scope", "", sarif()), ("unknown scope", "all", sarif()),
                                     ("no SARIF", "full", None), ("no automationDetails", "full", sarif(False))):
                rc, log, meta = run_meta(tmp, scope, doc)
                self.assertEqual((rc, meta), (0, None), name)
                self.assertIn("no scan-meta file", log, name)

    def test_it_is_the_same_writer_as_pantheon_deploys_ci_scan(self):
        """Two writers, one format: when pantheon-deploy sits beside this repo, its META block must be this one."""
        other = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(HERE))), "..", "pantheon-deploy",
                             ".github", "workflows", "ci-scan.yml")
        if not os.path.isfile(other):
            self.skipTest(f"no pantheon-deploy checkout beside this repo ({os.path.normpath(other)})")
        t = open(other, encoding="utf-8").read()
        a = t.rindex("\n", 0, t.index("# META-BEGIN")) + 1
        self.assertEqual(textwrap.dedent(t[a:t.index("# META-END")]), block("# META-BEGIN", "# META-END"))


class TheUploadAndThePush(unittest.TestCase):
    def test_the_upload_is_pinned_named_and_never_carries_the_delta(self):
        up = step("Save the SARIF artifact (for Torana's CI scan pull)")
        self.assertIn("uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", up)
        self.assertIn("name: torana-scan-sarif", up)
        self.assertIn("steps.meta.outputs.dir }}/torana.sarif", up)
        self.assertIn("steps.meta.outputs.dir }}/torana-scan-meta.json", up)
        self.assertNotIn("scan-delta", up)
        self.assertIn("retention-days: ${{ inputs.sarif-artifact-retention-days }}", up)
        self.assertIn("if: ${{ always() && steps.artifact.outputs.upload == 'true' }}", up)

    def test_no_runner_temp_expression_in_the_new_steps(self):
        """In a container job `${{ runner.temp }}` is the HOST path: the new steps use $RUNNER_TEMP only."""
        for name in ("Scan meta (for Torana's CI scan pull)", "Save the SARIF artifact (for Torana's CI scan pull)"):
            self.assertNotIn("${{ runner.temp", step(name), name)

    def test_the_artifact_is_saved_before_the_push(self):
        """The pull exists for the run whose push failed, so the artifact cannot wait for the push."""
        self.assertLess(TEXT.index("- name: Save the SARIF artifact"), TEXT.index("- name: Report to Torana"))

    def test_the_push_sends_the_run_key(self):
        push = step("Report to Torana")
        self.assertRegex(push, re.escape('--run-id "${{ github.run_id }}" --run-attempt "${{ github.run_attempt }}"'))

    def test_the_inputs_and_their_defaults(self):
        for name, default in (("upload-sarif-artifact", '"auto"'), ("sarif-artifact-retention-days", '"3"')):
            i = TEXT.index(f"  {name}:")
            self.assertIn(f"default: {default}", TEXT[i:TEXT.index("\n  ", TEXT.index("default:", i))])


if __name__ == "__main__":
    unittest.main()
