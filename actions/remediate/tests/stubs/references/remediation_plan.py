#!/usr/bin/env python3
"""Stub planner: the argv contract of remediation_plan.py (--repo, --with ROOT…, --findings, --json) and a minimal
plan whose scope labels follow `_label` (path relative to --repo's parent)."""

import argparse
import json
import os

ap = argparse.ArgumentParser()
ap.add_argument("--repo")
ap.add_argument("--with", dest="with_roots", action="append", default=[])
ap.add_argument("--findings")
ap.add_argument("--json", action="store_true")
a = ap.parse_args()
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write("script remediation_plan.py --repo {} {} --findings {}\n".format(
        os.path.basename(a.repo), " ".join("--with " + os.path.relpath(w, os.path.dirname(a.repo))
                                           for w in a.with_roots), os.path.basename(a.findings)))
for p in [a.repo, *a.with_roots]:
    assert os.path.isdir(p), p
parent = os.path.dirname(os.path.abspath(a.repo))
print(json.dumps({"engine": "stub", "repo": os.path.basename(a.repo),
                  "scope": [{"repo": os.path.relpath(os.path.abspath(p), parent), "path": p, "commit": None}
                            for p in [a.repo, *a.with_roots]],
                  "findings": len(json.load(open(a.findings))), "groups": [], "rows": []}))
