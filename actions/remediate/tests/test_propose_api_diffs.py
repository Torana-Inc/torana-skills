"""actions/remediate: the planner stays credential-free, so this script reads the stored "must move together" sets
and the API diffs itself (FIX_KNOWLEDGE_CONVERGENCE § 3.4.6, § 3.6.7 (f), § 3.6.11).

⛔ WHAT THIS GUARDS. A planner fetching for itself in CI would fail unauthenticated: every row would read
`api_diff unavailable`, no CI plan would reach class 4, and every plan would fall to `lever_scope_unverified`. And a
plugin copy older than this script must stop BEFORE any write, not fail half-way.

    python3 -m unittest discover -s actions/remediate/tests -p 'test_propose_api_diffs.py' -v
"""

from __future__ import annotations

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from test_remediate import DryRun, _read, _write  # noqa: E402

PAIR = {"ecosystem": "pypi", "package": "starlette", "from": "0.52.1", "to": "1.10.0",
        "origin_source": "registry", "origin_url": "https://pypi.org/simple"}
SET = {"alert_id": "a1", "repository": "repo:github.com/acme/api", "package": "pyjwt", "as_of": [], "pins": {},
       "move_together": None, "fact_age": "current", "fetched_at": "2026-10-27T10:00:00+00:00"}


class ProposeApiDiffs(DryRun):

    def _planner_runs(self, calls):
        return [c for c in calls if c.startswith("script remediation_plan.py")]

    def _stub_file(self, name):
        return json.loads(_read(self.log + f".{name}.json"))

    def test_no_api_diff_wanted_means_one_planner_run_with_api_diffs_off(self):
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        runs = self._planner_runs(calls)
        self.assertEqual(len(runs), 1, runs)
        self.assertIn("--api-diff off", runs[0])
        self.assertFalse([c for c in calls if "remediation-plans api-diff" in c])

    def test_wanted_api_diffs_are_read_with_request_then_planned_from_the_file(self):
        self.scenario["api_diffs_wanted"] = [PAIR, {**PAIR, "package": "litellm"}]
        self.scenario["api_diffs"] = {"starlette": {"state": "pending"}}       # litellm → 429, a refusal
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        runs = self._planner_runs(calls)
        self.assertEqual(len(runs), 2, runs)
        self.assertIn("--api-diff off", runs[0])
        self.assertIn("--api-diff-file api_diffs.json", runs[1])
        self.assertNotIn("--api-diff off", runs[1])
        reads = [c for c in calls if c.startswith("torana remediation-plans api-diff get")]
        self.assertEqual(len(reads), 2)
        self.assertTrue(all("--request" in c and "--origin-url https://pypi.org/simple" in c for c in reads))
        views = {v["key"]["package"]: v for v in self._stub_file("api_diffs")}
        self.assertEqual(views["starlette"]["state"], "pending",
                         "a pending API diff is recorded as asked, not as nobody asked")
        self.assertEqual(views["starlette"]["key"], {k: PAIR[k] for k in ("ecosystem", "package", "from", "to")})
        self.assertEqual(views["litellm"]["state"], "unavailable")
        self.assertIn("quota_exhausted", views["litellm"]["reason"], "a refusal is recorded, never a failed run")

    def test_the_fix_scope_file_reaches_both_planner_runs(self):
        self.scenario["move_together"] = {"a1": SET}
        self.scenario["api_diffs_wanted"] = [PAIR]
        self.scenario["api_diffs"] = {"starlette": {"state": "pending"}}
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        runs = self._planner_runs(calls)
        self.assertTrue(all("--fix-scope-file fix-scope.json" in r for r in runs), runs)
        self.assertEqual(self._stub_file("fix-scope"), [SET])

    def test_an_unreadable_set_is_left_out_not_a_failure(self):
        p, calls = self.run_action()                   # the stub answers 404 for a1
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self._stub_file("fix-scope"), [])

    def test_only_pypi_alerts_are_read_and_at_most_ten_per_package(self):
        self.scenario["queue"] = (
            [{"ecosystem": "pypi", "package": "pyjwt", "installed": "2.14.0", "fixed": "2.15.0",
              "alert_id": f"p{i}"} for i in range(12)]
            + [{"ecosystem": "npm", "package": "lodash", "installed": "4.17.20", "fixed": "4.17.21",
                "alert_id": "n1"}])
        _, calls = self.run_action()
        reads = [c for c in calls if " fix-scope" in c and c.startswith("torana alert")]
        self.assertEqual(len(reads), 10, reads)
        self.assertFalse([c for c in reads if "alert n1 " in c])

    def test_the_probe_records_co_mover_api_diffs_as_not_asked(self):
        """W3-14 (d): a co-mover's API diff would need a second resolve in CI, so the probe records it as not asked."""
        p, _ = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(_read(self.log + ".co-mover-api-diffs"), "ci")

    # ── § 3.6.11 the startup guard ──────────────────────────────────────────────────

    def test_an_old_planner_stops_the_run_before_any_call(self):
        old = os.path.join(self.tmp, "old-ref")
        os.makedirs(old)
        _write(os.path.join(old, "remediation_plan.py"),
               "import argparse\nap = argparse.ArgumentParser()\nap.add_argument('--api-diff-file')\nap.parse_args()\n")
        _write(os.path.join(old, "remediation_apply.py"), "")
        self.env["TORANA_SCAN_REF"] = old
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        self.assertEqual([c for c in calls if not c.startswith("HTTP")], [])
        self.assertIn("--fix-scope-file", p.stdout)
        self.assertIn("Nothing was written", p.stdout)

    def test_an_old_cli_stops_the_run_before_any_call(self):
        self.scenario["old_cli"] = True
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        self.assertEqual([c for c in calls if not c.startswith("HTTP")], [])
        self.assertIn("fix-scope", p.stdout)



# The inherited dry-run tests already run in test_remediate.py; only this file's own run here.
for _name in [n for n in dir(DryRun) if n.startswith("test_")]:
    if _name not in ProposeApiDiffs.__dict__:
        setattr(ProposeApiDiffs, _name, None)
del DryRun                                       # keep the loader from collecting the imported class here


if __name__ == "__main__":
    unittest.main()
