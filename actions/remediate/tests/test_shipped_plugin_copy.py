"""actions/remediate: the SHIPPED plugin copy is the one CI actually runs (FIX_KNOWLEDGE_CONVERGENCE § 3.6.11 item 4).

⛔ WHAT THIS GUARDS, AND WHY THE EXISTING TESTS DO NOT.
`action.yml` sets `REF=…/plugins/torana/skills/torana-scan/references` and installs the `torana` CLI from
`…/torana-skill/wheels`, so a CI run of this Action uses THAT tree — not `pantheon-cli/skills/torana-scan/references`,
which is where the work is done. (Torana is pre-prod: the live consumer today is our own
`pantheon-auth/.github/workflows/torana-reachability.yml`, through `actions/scan`, which reads the same two paths.) The two are joined only by `make -C pantheon-cli customer-plugin`, and nothing fails when the
build is skipped: the Action installs, plans, and answers from whatever vintage is committed here.

§ 3.6.11's other tests (`test_propose_api_diffs.py`) prove the startup guard's LOGIC against synthetic stubs — a fake
`old-ref` directory and an `old_cli` scenario flag. Those pass no matter what this repository actually ships, which is
exactly how the divergence found on **2026-10-28** survived: the committed copy was `torana-reachability` **1.13.0,
INDEX_FORMAT 4, with no `js_front.py` at all**, while `action.yml` had just been taught to install the JavaScript and
TypeScript grammars. So CI installed four parsers and then loaded a library that could not use two of them — and said
nothing, because a missing front end is not an error, only a `method_why` field. Every npm class-4 question answered
from that tree was answered by word match.

These tests therefore read the real tree, with no stubs:

    python3 -m unittest discover -s actions/remediate/tests -p 'test_shipped_plugin_copy.py' -v
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ACTION = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(ACTION))
#: The two paths `action.yml` derives from `github.action_path`; kept here as the ONE place the test states them.
REF = os.path.join(REPO, "plugins", "torana", "skills", "torana-scan", "references")
WHEELS = os.path.join(REPO, "plugins", "torana", "skills", "torana-skill", "wheels")
#: The hash-pinned file `action.yml` installs the parsers from (`pip install --require-hashes -r …`).
PARSER_REQUIREMENTS = os.path.join(ACTION, "parser-requirements.txt")
#: What `remediate.py` refuses to run without (its own `PLANNER_FLAGS`, restated so a drift in either is a failure).
PLANNER_FLAGS = ("--fix-scope-file", "--api-diff-file")


def _load_shipped_library():
    """Import the SHIPPED vendored library by path, without putting it on `sys.path` for anyone else."""
    init = os.path.join(REF, "lib", "torana_reachability", "__init__.py")
    spec = importlib.util.spec_from_file_location("shipped_torana_reachability", init,
                                                  submodule_search_locations=[os.path.dirname(init)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ShippedPluginCopy(unittest.TestCase):

    def test_the_shipped_planner_offers_the_flags_remediate_requires(self):
        """`remediate.py` stops the run when these are missing, so a copy without them makes the Action inert."""
        plan = os.path.join(REF, "remediation_plan.py")
        self.assertTrue(os.path.isfile(plan),
                        f"no remediation_plan.py at {REF} — run `make -C pantheon-cli customer-plugin`")
        out = subprocess.run([sys.executable, plan, "--help"], capture_output=True, text=True).stdout
        missing = [f for f in PLANNER_FLAGS if f not in out]
        self.assertEqual(missing, [], f"the shipped planner has no {missing}: rebuild the plugin tree")

    def test_the_shipped_cli_wheel_offers_alert_fix_scope(self):
        """⛔ `alert fix-scope`, NOT `alert move-together`.

        § 3.6.11 item 3 names the guard condition as "`torana alert --help` must list `move-together`". No such
        command ever shipped — the verb is `fix-scope` ("Everything that must move together to fix this item's ..."),
        and `remediate.py`'s own `stale_copy()` already checks for that name. Asserting the spec's wording literally
        would fail against every correct CLI. Checked here against the committed wheel, by name, so neither drifts.
        """
        wheels = [f for f in os.listdir(WHEELS) if f.startswith("torana_cli-") and f.endswith(".whl")]
        self.assertEqual(len(wheels), 1,
                         f"expected exactly one torana_cli wheel in {WHEELS}, found {sorted(wheels)}: "
                         "action.yml installs them with a glob, so two versions make the installed CLI undefined")
        with tempfile.TemporaryDirectory() as tmp:
            py = os.path.join(tmp, "bin", "python")
            subprocess.run([sys.executable, "-m", "venv", tmp], check=True, capture_output=True)
            shared = [f for f in os.listdir(WHEELS) if f.startswith("pantheon_shared-") and f.endswith(".whl")]
            subprocess.run([py, "-m", "pip", "install", "--quiet",
                            *[os.path.join(WHEELS, w) for w in shared + wheels], ], check=True, capture_output=True)
            out = subprocess.run([os.path.join(tmp, "bin", "torana"), "alert", "--help"],
                                 capture_output=True, text=True).stdout
        self.assertIn("fix-scope", out, "the shipped CLI wheel has no `alert <id> fix-scope`: rebuild the plugin tree")

    def test_every_grammar_the_action_installs_has_a_front_end_in_the_shipped_library(self):
        """⭐ THE 2026-10-28 BUG, as a test.

        `action.yml` installs the grammars; the shipped library is what consumes them. Nothing joined the two, so a
        library predating the JavaScript front end accepted four parsers and used two. This asserts the coherence
        directly: every ecosystem `action.yml` pins a grammar for must be a language the shipped call graph reports on.
        It does NOT require the grammars to be installed here — only that the library KNOWS about them — so it runs
        anywhere, which is the point of a guard.
        """
        with open(PARSER_REQUIREMENTS) as f:
            pinned = set(re.findall(r"^tree-sitter-([a-z]+)==", f.read(), re.MULTILINE))
        self.assertIn("python", pinned, f"{PARSER_REQUIREMENTS} no longer pins the Python grammar")
        lib = _load_shipped_library()
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "src"))
            for rel, body in (("src/a.py", "import os\n"), ("src/a.js", "const x = require('left-pad');\n"),
                              ("src/a.ts", "import {y} from 'rxjs';\n")):
                with open(os.path.join(tmp, rel), "w") as f:
                    f.write(body)
            languages = lib.index_tree(tmp).callgraph.get("languages") or {}
        # tree-sitter-typescript is one wheel carrying .ts and .tsx; both are the javascript front end's job.
        want = {"python": "python", "javascript": "javascript", "typescript": "javascript"}
        for grammar in sorted(pinned):
            front = want.get(grammar)
            self.assertIsNotNone(front, f"action.yml pins tree-sitter-{grammar}, which this test does not know how "
                                        "to map to a front end — extend `want` deliberately")
            self.assertIn(front, languages,
                          f"the Action installs tree-sitter-{grammar} but the shipped library reports no "
                          f"'{front}' front end (it has {sorted(languages)}): CI would answer that ecosystem by "
                          "word match. Rebuild the plugin tree from pantheon-cli.")

    def test_the_shipped_apply_offers_every_flag_the_action_passes_it(self):
        """⭐ THE DRIFT THAT ACTUALLY HAPPENED, as a test (2026-10-28).

        `action.yml` runs the SHIPPED `remediation_apply.py`, while `remediate.py` is hand-maintained in this
        repo — so a new flag added in `pantheon-cli` and passed by the Action is an `argparse` usage error on
        every real run until `make -C pantheon-cli customer-plugin` regenerates `plugins/`. Measured: adding
        `--gates-45` to `remediate.py` turned 33 green tests into 8 failures + 1 error, all of them
        `unrecognized arguments: --gates-45`, and NONE of them pointed at the rebuild.

        ⛔ The stub under `tests/stubs/` cannot catch this — it is a different file with its own argparse, which
        is exactly why it had to be taught the flag by hand. Only the real shipped script can.
        """
        apply_py = os.path.join(REF, "remediation_apply.py")
        self.assertTrue(os.path.isfile(apply_py), f"no remediation_apply.py at {REF}")
        out = subprocess.run([sys.executable, apply_py, "--help"], capture_output=True, text=True).stdout
        with open(os.path.join(ACTION, "remediate.py"), encoding="utf-8") as fh:
            caller = fh.read()
        # Every long flag the Action hands the apply script, read off the source rather than listed here, so a
        # flag added to `remediate.py` tomorrow is checked without anybody remembering to extend this test.
        # ⚠️ SCOPED TO `apply_plan_id`, the one function that builds this script's argv. Scanning the whole
        # file swept up every flag `remediate.py` passes to the `torana` CLI (`--state`, `--limit`,
        # `--subject-repository` …) and reported 27 of them as missing — a true statement about the wrong
        # question, and the kind of confident wrong answer a guard must not give.
        body = caller.split("def apply_plan_id", 1)
        self.assertEqual(len(body), 2, "remediate.py no longer defines apply_plan_id: re-scope this test")
        body = re.split(r"\ndef ", body[1], 1)[0]
        passed = set(re.findall(r'"(--[a-z0-9][a-z0-9-]+)"', body))
        self.assertIn("--gates-45", passed, "remediate.py no longer asks for gates 4/5 at --open-pr (spec P3)")
        missing = sorted(f for f in passed if f not in out and f"{f} " not in out)
        self.assertEqual(missing, [], f"remediate.py passes {missing} to the shipped remediation_apply.py, "
                                      "which does not accept them — run `make -C pantheon-cli customer-plugin`")

    def test_the_shipped_vendored_library_is_self_consistent(self):
        """Its own vendoring hash, so a hand-edit of `plugins/` (which torana-skills/CLAUDE.md forbids) is caught.

        `check()` takes the package DIRECTORY and raises `ValueError` when the tree no longer hashes to the sha256 its
        `VENDORED.json` pins, so calling it is the assertion. Passing an absolute path matters: it resolves
        `VENDORED.json` relative to what it is given, not to the working directory.
        """
        lib = _load_shipped_library()
        vendoring = importlib.import_module(f"{lib.__name__}.vendoring")
        pkg = os.path.join(REF, "lib", "torana_reachability")
        result = vendoring.check(pkg)                      # raises if the shipped copy was edited in place
        self.assertEqual(result.get("version"), lib.__version__,
                         "VENDORED.json and __init__.py disagree on the shipped version")


if __name__ == "__main__":
    unittest.main()
