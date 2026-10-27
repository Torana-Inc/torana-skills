#!/usr/bin/env python3
"""Stub planner: the argv contract of remediation_plan.py (--repo, --with ROOT…, --findings, --fix-scope-file,
--api-diff / --api-diff-file, --json) and a minimal plan whose scope labels follow `_label` (path relative to --repo's
parent). `api_diffs_wanted` comes from the scenario (`$STUB_SCENARIO` key `api_diffs_wanted`) on a run without an API-diff
file; the files it was handed are copied beside the log for the test to read."""

import argparse
import json
import os

ap = argparse.ArgumentParser()
ap.add_argument("--repo")
ap.add_argument("--with", dest="with_roots", action="append", default=[])
ap.add_argument("--findings")
ap.add_argument("--fix-scope-file")
ap.add_argument("--api-diff", choices=("off", "read", "request"))
ap.add_argument("--api-diff-file")
ap.add_argument("--json", action="store_true")
a = ap.parse_args()
assert not (a.api_diff and a.api_diff_file), "TEST FAILURE: --api-diff and --api-diff-file together"

with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write("script remediation_plan.py --repo {} {} --findings {}{}{}{}\n".format(
        os.path.basename(a.repo), " ".join("--with " + os.path.relpath(w, os.path.dirname(a.repo))
                                           for w in a.with_roots), os.path.basename(a.findings),
        f" --fix-scope-file {os.path.basename(a.fix_scope_file)}" if a.fix_scope_file else "",
        f" --api-diff {a.api_diff}" if a.api_diff else "",
        f" --api-diff-file {os.path.basename(a.api_diff_file)}" if a.api_diff_file else ""))
for flag, path in (("fix-scope", a.fix_scope_file), ("api_diffs", a.api_diff_file)):
    if path:
        with open(path) as src, open(os.environ["STUB_LOG"] + "." + flag + ".json", "w") as dst:
            dst.write(src.read())
sc = json.load(open(os.environ["STUB_SCENARIO"]))
for k in ("TORANA_TOKEN", "TORANA_TOKEN_CMD", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
    assert k not in os.environ, f"TEST FAILURE: {k} reached the planner"
for p in [a.repo, *a.with_roots]:
    assert os.path.isdir(p), p
parent = os.path.dirname(os.path.abspath(a.repo))
print(json.dumps({"engine": "stub", "repo": os.path.basename(a.repo),
                  "scope": [{"repo": os.path.relpath(os.path.abspath(p), parent), "path": p, "commit": None}
                            for p in [a.repo, *a.with_roots]],
                  "findings": len(json.load(open(a.findings))), "groups": [], "rows": [],
                  "api_diffs_wanted": [] if a.api_diff_file else sc.get("api_diffs_wanted", [])}))
