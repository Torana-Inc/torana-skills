"""actions/scan, EM S-07b m3: the release vendors ONE CLI wheel, and it is one that understands what the Action sends.

`action.yml` installs `"$WHEELS"/pantheon_shared-*.whl "$WHEELS"/torana_cli-*.whl`. A glob over two versions makes the
installed CLI undefined, and a CLI older than 0.1.3 fails the push with "no such option: --run-id" (the Action passes
`--run-id/--run-attempt` since plugin 0.10.0). So the release REPLACES the wheel, and this test installs the committed
wheels into a fresh venv and reads the real `--help` (needs pip to reach PyPI for the CLI's dependencies):

    python3 -m unittest discover -s actions/scan/tests -p 'test_release_wheels.py' -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
WHEELS = os.path.join(REPO, "plugins", "torana", "skills", "torana-skill", "wheels")
PLUGIN = os.path.join(REPO, "plugins", "torana", ".claude-plugin", "plugin.json")


def wheels(prefix: str):
    return sorted(f for f in os.listdir(WHEELS) if f.startswith(prefix) and f.endswith(".whl"))


class TheVendoredWheels(unittest.TestCase):
    def test_exactly_one_of_each(self):
        for prefix in ("torana_cli-", "pantheon_shared-"):
            self.assertEqual(len(wheels(prefix)), 1,
                             f"expected exactly one {prefix}*.whl in {WHEELS}, found {wheels(prefix)}: action.yml "
                             "installs them with a glob, so two versions make the installed CLI undefined")

    def test_the_cli_is_at_least_0_1_3(self):
        version = wheels("torana_cli-")[0].split("-")[1]
        self.assertGreaterEqual(tuple(int(p) for p in version.split(".")), (0, 1, 3),
                                f"torana_cli {version} has no --run-id: rebuild the plugin tree (make customer-plugin)")

    def test_the_plugin_version_moved(self):
        self.assertGreaterEqual(tuple(int(p) for p in json.load(open(PLUGIN))["version"].split(".")), (0, 10, 0))

    def test_the_vendored_cli_lists_the_run_key(self):
        """The real `--help` of the committed wheel, installed beside the committed shared wheel."""
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, "-m", "venv", tmp], check=True, capture_output=True)
            py = os.path.join(tmp, "bin", "python")
            inst = subprocess.run([py, "-m", "pip", "install", "--quiet",
                                   *[os.path.join(WHEELS, w) for w in wheels("pantheon_shared-") + wheels("torana_cli-")]],
                                  capture_output=True, text=True)
            self.assertEqual(inst.returncode, 0, inst.stderr[-800:])
            out = subprocess.run([os.path.join(tmp, "bin", "torana"), "ingest", "sarif", "--help"],
                                 capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr[-400:])
        self.assertIn("--run-id", out.stdout)
        self.assertIn("--run-attempt", out.stdout)


if __name__ == "__main__":
    unittest.main()
