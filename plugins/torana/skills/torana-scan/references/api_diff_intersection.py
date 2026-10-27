#!/usr/bin/env python3
"""Does an upgrade's API diff touch THIS tree's code? (FIX_PR phase 3 § 3.4.6 step 3; FIX_KNOWLEDGE_CONVERGENCE § 3.6.5.)

    an API diff (what the package changed)  +  this tree's imports and call graph  ->  class 3 or class 4

An API diff says what version N+1 removed, renamed or re-signed. It is keyed on `(ecosystem, package, from, to)` and
nothing else, so it is the same for every customer. This script answers the half that is about one tree: of those
changed symbols, which ones does THIS code use? Empty intersection -> class 3. Non-empty -> class 4, which needs a
person.

⭐ A THIN CALLER. The check itself is the shared library's `torana_reachability.api_diff_check.intersect`, the ONE
computation the Atlas also runs over a stored snapshot (one definition = one computation). This file only builds
its inputs from a checkout (usage records + call graph) and keeps the CLI and the names `remediation_plan.py`
imports. Over the call graph a symbol is matched by what the code really binds and calls (aliases, from-imports,
class bases, module-scope references); the whole-word match survives only for npm or when no parser is installed
(`method: word`, `method_why: npm | parser_missing | truncated`), and every call-graph result says what it cannot
see (`blind_to`).

⛔ PURE over its inputs: no network, no platform, no model. ⚠️ ABSENCE IS NOT SAFETY: an incomplete API diff, a package
this tree never imports directly, an uncovered npm subpath each return `unavailable` (or say so), never a clean 3.

Usage:
    python3 api_diff_intersection.py --repo PATH --API diff API diff.json --package starlette [--ecosystem pypi] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "lib"))

from torana_reachability import locks                              # noqa: E402
from torana_reachability import manifests                          # noqa: E402
from torana_reachability import api as rapi                        # noqa: E402
from torana_reachability.api_diff_check import (                       # noqa: E402,F401
    MAX_TOUCHED, NAMED_BY, binds_module, bound_names, changed_symbols, leaf, reached_through, word_intersect)
from torana_reachability.api_diff_check import intersect as _intersect  # noqa: E402

#: A file larger than this is not read for the word path; it counts as a hit for what it imports (conservative).
MAX_FILE_BYTES = 2 * 1024 * 1024

Usage = Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]


def usage_for(root: str, repository: str = "local", commit: str = "unknown") -> Usage:
    """(usage records, call-graph document) for the tree. The primary tree only: a `--with` tree's code is searched
    by its own run.

    ⛔ `declared` reaches the call graph: without it no call is `external` (api.py) and the API diff check would see
    NOTHING."""
    records = manifests.read_manifests(root)
    declared = {e: manifests.packages_declared(records, e) for e in ("pypi", "npm")}
    idx = rapi.index_tree(root, commit=commit, repository=repository, declared={"pypi": declared["pypi"]})
    return rapi.usage_records(idx, root, declared=declared), idx.callgraph


def intersect(doc: Dict[str, Any], usage: Usage, read: Optional[Callable[[str], Optional[str]]], *,
              package: str, ecosystem: str, through: Sequence[str] = ()) -> Dict[str, Any]:
    """The library's check over `usage_for`'s pair. A graph of `None` means "no parser": the word path."""
    recs, graph = usage
    return _intersect(doc, recs, graph, read, package=package, ecosystem=ecosystem, through=through)


def reader(root: str) -> Callable[[str], Optional[str]]:
    def read(rel: str) -> Optional[str]:
        path = os.path.join(root, rel)
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                return None
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
    return read


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--diff", required=True, help="an API diff JSON (torana.api_diff.v1)")
    ap.add_argument("--package", required=True)
    ap.add_argument("--ecosystem", default="pypi", choices=("pypi", "npm"))
    ap.add_argument("--json", dest="as_json", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.repo)
    with open(a.diff, encoding="utf-8") as fh:
        doc = json.load(fh)
    usage = usage_for(root)
    # ⛔ COMPUTED HERE, NOT INSIDE `intersect`: the check is pure over its inputs, and reading a lock off the disk
    # inside it would end that.
    res = intersect(doc, usage, reader(root), package=a.package, ecosystem=a.ecosystem,
                    through=reached_through(a.package, locks.read_requirements(root), usage[0]))
    if a.as_json:
        print(json.dumps(res, indent=2))
        return 0
    print(f"class {res['verdict']}  state={res['state']}" + (f"  ({res['reason']})" if res.get("reason") else ""))
    print(f"  API diff: removed={res['removed']} renamed={res['renamed']} "
          f"signature_changed={res['signature_changed']} complete={res['complete']}")
    if res.get("method_words"):                          # the library's words, verbatim
        print(f"  method: {res['method_words']}")
    if res.get("blind_to_words"):
        print(f"  cannot see: {', '.join(res['blind_to_words'])}")
    touched = res.get("touched") or []
    named = [h for h in touched if h.get("by") in NAMED_BY]
    for h in named + [h for h in touched if h.get("by") not in NAMED_BY]:
        mark = "TOUCHED  " if h.get("by") in NAMED_BY else "also     "
        print(f"  {mark}{h['symbol']}  ({h['change']})  {h['file']}:{h['line']}  [by {h.get('by')}]"
              + ("" if h.get("by") in NAMED_BY else "   [name appears in the file, not in the import]"))
    for h in res.get("deprecated") or []:
        print(f"  deprecated {h['symbol']}  ({h['change']})  {h['file']}:{h['line']} — served by a runtime shim")
    for u in res.get("uncovered_imports") or []:
        print(f"  uncovered subpath {u['subpath']}  {u['file']}:{u['line']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
