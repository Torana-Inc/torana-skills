"""actions/remediate: the planner stays credential-free, so this script reads the stored "must move together" sets
and the upgrade cards itself (FIX_KNOWLEDGE_CONVERGENCE § 3.4.6, § 3.6.7 (f), § 3.6.11).

⛔ WHAT THIS GUARDS. A planner fetching for itself in CI would fail unauthenticated: every row would read
`api_diff unavailable`, no CI plan would reach class 4, and every plan would fall to `lever_scope_unverified`. And a
plugin copy older than this script must stop BEFORE any write, not fail half-way.

    python3 -m unittest discover -s actions/remediate/tests -p 'test_propose_cards.py' -v
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


class ProposeCards(DryRun):

    def _planner_runs(self, calls):
        return [c for c in calls if c.startswith("script remediation_plan.py")]

    def _stub_file(self, name):
        return json.loads(_read(self.log + f".{name}.json"))

    def test_no_card_wanted_means_one_planner_run_with_cards_off(self):
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        runs = self._planner_runs(calls)
        self.assertEqual(len(runs), 1, runs)
        self.assertIn("--cards off", runs[0])
        self.assertFalse([c for c in calls if "upgrade-card" in c])

    def test_wanted_cards_are_read_with_request_then_planned_from_the_file(self):
        self.scenario["cards_wanted"] = [PAIR, {**PAIR, "package": "litellm"}]
        self.scenario["cards"] = {"starlette": {"state": "pending"}}       # litellm → 429, a refusal
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        runs = self._planner_runs(calls)
        self.assertEqual(len(runs), 2, runs)
        self.assertIn("--cards off", runs[0])
        self.assertIn("--cards-file cards.json", runs[1])
        self.assertNotIn("--cards off", runs[1])
        reads = [c for c in calls if c.startswith("torana remediation-plans upgrade-card get")]
        self.assertEqual(len(reads), 2)
        self.assertTrue(all("--request" in c and "--origin-url https://pypi.org/simple" in c for c in reads))
        views = {v["key"]["package"]: v for v in self._stub_file("cards")}
        self.assertEqual(views["starlette"]["state"], "pending",
                         "a pending card is recorded as asked, not as nobody asked")
        self.assertEqual(views["starlette"]["key"], {k: PAIR[k] for k in ("ecosystem", "package", "from", "to")})
        self.assertEqual(views["litellm"]["state"], "unavailable")
        self.assertIn("quota_exhausted", views["litellm"]["reason"], "a refusal is recorded, never a failed run")

    def test_the_move_together_file_reaches_both_planner_runs(self):
        self.scenario["move_together"] = {"a1": SET}
        self.scenario["cards_wanted"] = [PAIR]
        self.scenario["cards"] = {"starlette": {"state": "pending"}}
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        runs = self._planner_runs(calls)
        self.assertTrue(all("--move-together-file move-together.json" in r for r in runs), runs)
        self.assertEqual(self._stub_file("move-together"), [SET])

    def test_an_unreadable_set_is_left_out_not_a_failure(self):
        p, calls = self.run_action()                   # the stub answers 404 for a1
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self._stub_file("move-together"), [])

    def test_only_pypi_alerts_are_read_and_at_most_ten_per_package(self):
        self.scenario["queue"] = (
            [{"ecosystem": "pypi", "package": "pyjwt", "installed": "2.14.0", "fixed": "2.15.0",
              "alert_id": f"p{i}"} for i in range(12)]
            + [{"ecosystem": "npm", "package": "lodash", "installed": "4.17.20", "fixed": "4.17.21",
                "alert_id": "n1"}])
        _, calls = self.run_action()
        reads = [c for c in calls if " move-together" in c and c.startswith("torana alert")]
        self.assertEqual(len(reads), 10, reads)
        self.assertFalse([c for c in reads if "alert n1 " in c])

    def test_the_probe_records_co_mover_cards_as_not_asked(self):
        """W3-14 (d): a co-mover's card would need a second resolve in CI, so the probe records it as not asked."""
        p, _ = self.run_action()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(_read(self.log + ".co-mover-cards"), "ci")

    # ── § 3.6.11 the startup guard ──────────────────────────────────────────────────

    def test_an_old_planner_stops_the_run_before_any_call(self):
        old = os.path.join(self.tmp, "old-ref")
        os.makedirs(old)
        _write(os.path.join(old, "remediation_plan.py"),
               "import argparse\nap = argparse.ArgumentParser()\nap.add_argument('--cards-file')\nap.parse_args()\n")
        _write(os.path.join(old, "remediation_apply.py"), "")
        self.env["TORANA_SCAN_REF"] = old
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        self.assertEqual([c for c in calls if not c.startswith("HTTP")], [])
        self.assertIn("--move-together-file", p.stdout)
        self.assertIn("Nothing was written", p.stdout)

    def test_an_old_cli_stops_the_run_before_any_call(self):
        self.scenario["old_cli"] = True
        p, calls = self.run_action()
        self.assertEqual(p.returncode, 1)
        self.assertEqual([c for c in calls if not c.startswith("HTTP")], [])
        self.assertIn("move-together", p.stdout)



# The inherited dry-run tests already run in test_remediate.py; only this file's own run here.
for _name in [n for n in dir(DryRun) if n.startswith("test_")]:
    if _name not in ProposeCards.__dict__:
        setattr(ProposeCards, _name, None)
del DryRun                                       # keep the loader from collecting the imported class here


if __name__ == "__main__":
    unittest.main()
