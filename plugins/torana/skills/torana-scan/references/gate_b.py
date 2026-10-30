#!/usr/bin/env python3
"""Gate B — how we know a SOURCE change is correct (FIX_PR_PHASE5_CODEMOD_SPEC § 3.4).

⛔ WHY THIS FILE EXISTS AT ALL. Gates 1–5 were built for a LOCK RECOMPILE: resolve, blast radius,
lane, build, tests. None of them can say whether an edit to someone's Python is right — a rename that
missed half its call sites compiles, installs and passes a test suite that never touched them. So
phase 5 could not reuse the ladder; it needed a design for knowing a source change is correct, and
this is it.

The levels, and what each one is FOR:

  L0  files        did we change only the files we listed?        — catches a 4c draft that strayed
  L1  syntax       does the output re-parse, and is the diff
                   confined to the lines we said we changed?      — catches a writer that mangled
  L2  closed loop  does the instrument that RAISED the class
                   now agree the site is fixed?                   — the load-bearing one
  L3  build/tests/coverage (gates 4–5 + coverage_of_diff)         — runs at --commit, after approval

⭐ L2 IS THE POINT, and its strength is that it is not a second opinion: it re-indexes the APPLIED
copy and runs the SAME API-diff check that raised class 4 in the first place. The proof and the
instrument are one code path, so a rewrite the checker cannot clear is refused rather than argued.

⚠️ EVERY LEVEL REFUSES RATHER THAN DOWNGRADES. A failure means the file's original bytes go back and
its sites are listed with the reason — never "probably fine".
"""
from __future__ import annotations

import difflib
import os
import sys
from typing import Any, Dict, List, Sequence

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

import api_diff_intersection as ci                      # noqa: E402
from torana_reachability import call_narrowing as cn     # noqa: E402
from torana_reachability import callgraph                # noqa: E402


# ── L0: files ───────────────────────────────────────────────────────────────

def l0_files(sites: Sequence[Dict[str, Any]], changed: Sequence[str]) -> Dict[str, Any]:
    """Did we change only the files we listed? (`changed` excludes manifests and locks.)

    ⚠️ `outside_sites` is IMPOSSIBLE for 4a/4b — the codemod opens listed files only — so it exists
    for 4c, where a model-authored hunk could touch a file nobody listed. ⛔ On failure the whole
    group is refused and NOTHING is proposed, not even the bump: a plan carrying the bump alone would
    claim a code change it does not actually contain.
    """
    listed = {s["file"] for s in sites}
    extra = sorted(set(changed) - listed)
    missing = sorted(
        f for f in listed
        if f not in changed and any(s["status"] == "rewritten" for s in sites if s["file"] == f)
    )
    ok = not extra and not missing
    return {
        "ok": ok,
        "changed": sorted(changed),
        "outside_sites": extra,
        "listed_unchanged": missing,
        "words": "only listed files changed" if ok else
                 (f"changed outside the site list: {', '.join(extra)}" if extra else
                  f"reported as rewritten but unchanged: {', '.join(missing)}"),
    }


# ── L1: syntax and minimality, per rewritten file ───────────────────────────

def _tree_sitter_ok(code: str, language: str = "python") -> bool:
    """⛔ BOTH PARSERS, and tree-sitter is not redundant with libcst.

    libcst re-parsing proves the WRITER's own invariant. tree-sitter proves **L2 can see the file** —
    and L2 is the level that matters. A file tree-sitter rejects would leave the checker blind at
    exactly the rewritten site, so a rewrite could pass L2 by being invisible to it rather than by
    being correct.
    """
    parser = callgraph.python_parser() if language == "python" else None
    if parser is None:
        return True                       # no grammar: L2 will report `method: word` and refuse there
    try:
        tree = parser.parse(code.encode("utf-8"))
    except Exception:                     # noqa: BLE001 — a parser crash is not a pass
        return False
    root = tree.root_node
    return not (root.has_error if hasattr(root, "has_error") else root.type == "ERROR")


def _changed_lines(before: str, after: str) -> List[int]:
    """Changed line numbers on BOTH sides, from a zero-context diff."""
    out: set = set()
    for line in difflib.unified_diff(before.splitlines(), after.splitlines(), n=0, lineterm=""):
        if not line.startswith("@@"):
            continue
        # @@ -<a>[,<n>] +<b>[,<m>] @@
        parts = line.split()
        for tok in (parts[1], parts[2]):
            start, _, count = tok[1:].partition(",")
            n = int(count or 1)
            if n:
                out.update(range(int(start), int(start) + n))
    return sorted(out)


def _in_touch_ranges(i1: int, i2: int, ranges: Sequence[Sequence[int]]) -> bool:
    """Old-side opcode coordinates (`i1:i2`, 0-based) inside ONE granted touch range (1-based).

    ⚠️ A PURE INSERTION (`i1 == i2`) is anchored at `i1` and may land inside a range OR at its
    end + 1 — appending a line at the bottom of a granted span is still inside the grant.
    """
    lo, hi = i1 + 1, i2            # 1-based inclusive; for an insertion hi == lo - 1
    for a, b in ranges:
        if i1 == i2:
            if a <= lo <= b + 1:
                return True
        elif a <= lo and hi <= b:
            return True
    return False


def l1_syntax(before: str, after: str, reported_lines: Sequence[int], *,
              model_authored: bool = False, touch_ranges: Sequence[Sequence[int]] = (),
              language: str = "python") -> Dict[str, Any]:
    """`{"ok": bool, "why": str|None, "changed_lines": [...]}` for ONE rewritten file.

    ⛔ TWO MINIMALITY MODES, and the difference is not a loosening. A rename or a keyword shift never
    adds or removes a line, so both sides' changed-line numbers agree and must equal exactly what the
    codemod reported. A 4c draft MAY add or remove lines, so after-side numbers are meaningless — a
    deletion at 41–43 would shift a second site at 80 out of its range purely as an artefact. So for
    a model-authored file the check is on OLD-SIDE coordinates only (M6), against the brief's granted
    `touch` ranges.
    """
    if after.count("\r\n") != before.count("\r\n"):
        # ⛔ Refused, not normalised: rewriting line endings touches every line, which destroys the
        # minimality guarantee and makes the diff unreadable for the person who must approve it.
        return {"ok": False, "why": "newline_changed", "changed_lines": []}
    try:
        import libcst as cst
        if cst.parse_module(after).code != after:
            return {"ok": False, "why": "unparsable_output", "changed_lines": []}
    except ImportError:
        pass                              # the caller reports libcst_unavailable; nothing to check
    except Exception:                     # noqa: BLE001 — a parse failure IS the finding
        return {"ok": False, "why": "unparsable_output", "changed_lines": []}
    if not _tree_sitter_ok(after, language):
        return {"ok": False, "why": "unparsable_output", "changed_lines": []}

    changed = _changed_lines(before, after)
    if model_authored:
        bl, al = before.splitlines(), after.splitlines()
        for tag, i1, i2, _j1, _j2 in difflib.SequenceMatcher(None, bl, al).get_opcodes():
            if tag == "equal":
                continue
            if not _in_touch_ranges(i1, i2, touch_ranges):
                return {"ok": False, "why": f"not_minimal: a {tag} at old lines {i1 + 1}-{i2} is "
                                            f"outside the granted ranges {list(touch_ranges)}",
                        "changed_lines": changed}
        return {"ok": True, "why": None, "changed_lines": changed}

    if changed != sorted(set(reported_lines)):
        return {"ok": False, "why": f"not_minimal: the diff changes {changed}, the codemod reported "
                                    f"{sorted(set(reported_lines))}", "changed_lines": changed}
    return {"ok": True, "why": None, "changed_lines": changed}


# ── L2: the closed loop ─────────────────────────────────────────────────────

#: Statuses a site may legitimately STILL be a hit under (B2). Everything still touched must be a
#: site we reported as one of these, or the run is refused `unlisted_use`.
#: ⚠️ `needs_person` is here because until 5c EVERY 4c site is one (N1): listed, left for a person,
#: and still a hit by construction. Leaving it out would refuse every partial 4a run.
_LEFT_OK = ("refused", "no_change", "needs_person")


def l2_closed_loop(copy_root, repository, commit, doc, package, ecosystem, through,
                   sites, read, basis) -> Dict[str, Any]:
    """Re-index the APPLIED copy and ask the instrument that raised the class whether it agrees.

    ⭐ THE SAME CODE PATH, not a second opinion. For 4b this is literally `narrow`'s decision
    procedure run on the new call shape, which is what makes the equivalence argument checkable
    rather than merely argued.
    """
    usage2 = ci.usage_for(copy_root, repository=repository, commit=commit)
    res2 = ci.intersect(doc, usage2, read, package=package, ecosystem=ecosystem, through=through)
    if res2.get("state") != "ready":
        # ⛔ The instrument went blind. That is NOT a pass: a check that cannot run must never report
        # the thing it could not check as fine.
        return {"ok": False, "basis": basis, "why": f"re-check {res2.get('state')}: {res2.get('reason')}",
                "res": res2}
    if res2.get("method") != "callgraph":
        return {"ok": False, "basis": basis, "why": "re-check by name search", "res": res2}

    still = {(h["file"], h["line"], h["symbol"]): h for h in res2.get("touched") or []}
    by_key = {(s["file"], s["line"], s["symbol"]): s for s in sites}
    problems: List[Dict[str, Any]] = []

    for key, s in by_key.items():
        h = still.get(key)
        if s["status"] == "rewritten" and s["sub"] == "4a" and h is not None:
            problems.append({"site": key, "why": "incomplete_migration: the old name is still used here"})
        if s["sub"] == "4b" and s["status"] in ("rewritten", "no_change"):
            # ⚠️ A 4b site is STILL A HIT — the symbol is genuinely still used. What must have changed
            # is its call_verdict, so testing for the hit's absence would refuse every correct shift.
            if h is None or h.get("call_verdict") != cn.SAFE:
                problems.append({"site": key,
                                 "why": f"call still {(h or {}).get('call_verdict', 'absent')} after the shift"})
        if s["status"] == "drafted" and any(k[0] == key[0] and k[2] == key[2] for k in still):
            problems.append({"site": key, "why": "the draft still uses the changed symbol"})

    for key in still:
        s = by_key.get(key)
        if s is None or (s["status"] not in _LEFT_OK
                         and not (s["sub"] == "4b" and s["status"] == "rewritten")):
            problems.append({"site": key,
                             "why": "unlisted_use: the API diff still touches a site no codemod reported"})

    # (b) THE POSITIVE CONTROL (M3). Absence of the old name is only half an answer — a rewrite that
    # deleted the call would also satisfy it. So the NEW name must be SEEN where we wrote it, asked of
    # the same instrument via a synthetic diff naming the fully qualified new symbol.
    for key, s in by_key.items():
        if s["status"] == "rewritten" and s["sub"] == "4a":
            probe = {**doc, "api_diff": {**doc["api_diff"],
                                         "removed": [{"symbol": f"{s['parent']}.{s['new']}", "kind": s["kind"]}],
                                         "renamed": [], "signature_changed": []}}
            res3 = ci.intersect(probe, usage2, read, package=package, ecosystem=ecosystem, through=through)
            if not any(h["file"] == s["file"] and h["line"] == s["line"]
                       for h in res3.get("touched") or []):
                problems.append({"site": key, "why": "rewrite_not_recorded: the new name is not seen at this site"})

    weak = basis == "convention"
    words = ("the API-diff check no longer touches any rewritten site, and sees the new name at each one"
             if not problems else
             "; ".join(f"{p['site'][0]}:{p['site'][1]} {p['why']}" for p in problems[:5]))
    if weak and not problems:
        # ⚠️ STATED, never silently counted as a full pass: with no measured module mapping the call
        # graph could not place this package's calls, so only import lines were really checked.
        words = ("the call graph could not place this package's calls (no measured module mapping): "
                 "only import lines were checked")
    return {"ok": not problems, "problems": problems, "remaining": sorted(still),
            "method": res2.get("method"), "basis": basis, "words": words}
