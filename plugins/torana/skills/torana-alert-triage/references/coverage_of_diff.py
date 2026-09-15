#!/usr/bin/env python3
"""T7 — coverage-of-diff: is the CHANGED code actually covered by the suite?

Intersects a coverage artifact's covered lines with the lines a fix changed
(`git diff -U0 <base>..HEAD`), per file. Returns:

    {status: covered | uncovered | no-suite,
     changed_lines: N, covered_changed: M, uncovered_changed: [{file, line}], ...}

`covered`   — every changed executable line in the fixed file(s) is in the covered set.
`uncovered` — at least one changed line is not covered.
`no-suite`  — no coverage artifact (no runner detected / coverage tool absent).

Pure stdlib. Supports the three artifacts T7 §3.3 lists:
  Python  pytest --cov --cov-report=json   → coverage.json
  Node    nyc/jest --coverageReporters=json → coverage-final.json
  Go      go test -coverprofile=cov.out     → cov.out

Usage:
    python3 coverage_of_diff.py <repo> <base_sha> <coverage_artifact>
    (prints the JSON verdict; exit 0 covered, 1 uncovered, 2 no-suite)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Set, Tuple


def _git(repo: str, *args: str) -> str:
    out = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return out.stdout if out.returncode == 0 else ""


def changed_lines(repo: str, base: str) -> Dict[str, Set[int]]:
    """Map file → set of changed (added/modified) line numbers at HEAD, from
    `git diff -U0 <base>..HEAD`. Only new-side hunks (the post-fix lines)."""
    diff = _git(repo, "diff", "--unified=0", "--diff-filter=ACMR", f"{base}..HEAD")
    result: Dict[str, Set[int]] = {}
    cur_file = None
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            cur_file = line[6:]
            result.setdefault(cur_file, set())
        elif line.startswith("@@") and cur_file is not None:
            m = hunk_re.match(line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                for ln in range(start, start + max(count, 1)):
                    result[cur_file].add(ln)
    # drop files with no added lines (pure deletions)
    return {f: s for f, s in result.items() if s}


def _covered_python(artifact: str) -> Dict[str, Set[int]]:
    with open(artifact) as f:
        data = json.load(f)
    out: Dict[str, Set[int]] = {}
    for path, info in (data.get("files") or {}).items():
        covered = set(info.get("executed_lines") or [])
        out[_norm(path)] = covered
    return out


def _covered_node(artifact: str) -> Dict[str, Set[int]]:
    with open(artifact) as f:
        data = json.load(f)
    out: Dict[str, Set[int]] = {}
    for path, info in data.items():
        # istanbul: statementMap {id: {start:{line}}}, s {id: hitcount}
        smap = info.get("statementMap") or {}
        s = info.get("s") or {}
        covered = set()
        for sid, loc in smap.items():
            if s.get(sid, 0) > 0:
                ln = (loc.get("start") or {}).get("line")
                if ln:
                    covered.add(ln)
        out[_norm(path)] = covered
    return out


def _covered_go(artifact: str) -> Dict[str, Set[int]]:
    # go cover profile: `mode: set` then lines `file:startLine.col,endLine.col n stmts count`
    out: Dict[str, Set[int]] = {}
    line_re = re.compile(r"^(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)$")
    with open(artifact) as f:
        for line in f:
            m = line_re.match(line.strip())
            if not m:
                continue
            path, a, b, count = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
            if count > 0:
                out.setdefault(_norm(path), set()).update(range(a, b + 1))
    return out


def _norm(path: str) -> str:
    """Normalize a coverage path to a repo-relative-ish tail for matching diff paths."""
    p = path.replace("\\", "/")
    return p[2:] if p.startswith("./") else p


def covered_lines(artifact: str) -> Dict[str, Set[int]]:
    """Parse a coverage artifact (auto-detect by name/content) → file → covered lines."""
    name = os.path.basename(artifact).lower()
    if name.endswith(".out"):
        return _covered_go(artifact)
    # JSON: istanbul (coverage-final) vs coverage.py (has "files")
    with open(artifact) as f:
        head = f.read(4096)
    if '"statementMap"' in head:
        return _covered_node(artifact)
    return _covered_python(artifact)


def _match(cov: Dict[str, Set[int]], diff_file: str) -> Set[int]:
    """Find the covered-line set for a diff file by longest common path tail."""
    if diff_file in cov:
        return cov[diff_file]
    for cpath, lines in cov.items():
        if cpath.endswith(diff_file) or diff_file.endswith(cpath):
            return lines
    return set()


def analyze(repo: str, base: str, artifact: str) -> Dict:
    if not artifact or not os.path.exists(artifact):
        return {"status": "no-suite", "reason": "no coverage artifact"}
    changed = changed_lines(repo, base)
    if not changed:
        return {"status": "covered", "changed_lines": 0, "covered_changed": 0,
                "uncovered_changed": [], "note": "no changed executable lines"}
    cov = covered_lines(artifact)
    total_changed = 0
    covered_changed = 0
    uncovered: List[Dict] = []
    for f, lines in changed.items():
        cset = _match(cov, f)
        for ln in sorted(lines):
            total_changed += 1
            if ln in cset:
                covered_changed += 1
            else:
                uncovered.append({"file": f, "line": ln})
    status = "covered" if not uncovered else "uncovered"
    return {"status": status, "changed_lines": total_changed,
            "covered_changed": covered_changed, "uncovered_changed": uncovered}


def main(argv: List[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    repo, base = argv[0], argv[1]
    artifact = argv[2] if len(argv) > 2 else ""
    verdict = analyze(repo, base, artifact)
    print(json.dumps(verdict, indent=2))
    return {"covered": 0, "uncovered": 1, "no-suite": 2}.get(verdict["status"], 1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
