"""D-06 slice 1: the plan's ASSUMPTIONS as data (FIX_PR_CODE_MEASURES_LLM_VETS_SPEC.md § 5, § 0.1).

Code measures; an AI review vets. The review can only check what code CLAIMED, so every claim the fix rests on is
stated here as `{key, claim, basis, evidence}`, one entry per fixed key, never as prose buried in `evidence`:

    planner (per package)   provenance · parents_admit · override_forced · target_line · api_check · runtime_floor
                            · lock_fresh
    apply (per group)       moved · tests

`basis`: `measured` (code ran something and read the answer), `inferred` (code reasoned from a partial answer),
`unknown` (nobody looked, or the look failed). ⛔ A key that does not apply is still STATED, as `measured`
"not applicable: <why>": an absent key reads as an unchecked one, and the reviewer must be able to tell them apart.

Pure: no I/O, no network. Every input is a field an earlier pass already wrote.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

PLAN_KEYS = ("provenance", "parents_admit", "override_forced", "target_line", "api_check", "runtime_floor",
             "lock_fresh")
APPLY_KEYS = ("moved", "tests")
KEYS = PLAN_KEYS[:5] + ("runtime_floor", "moved", "tests", "lock_fresh")   # spec § 5 order
assert set(KEYS) == set(PLAN_KEYS) | set(APPLY_KEYS)

MEASURED, INFERRED, UNKNOWN = "measured", "inferred", "unknown"

#: The review must open the Dockerfile itself whenever provenance is not measured (lead, 2026-11-04): A1 merged a
#: lock no image reads.
CHECK_THE_DOCKERFILE = ("check that the image is built from this lock (read the Dockerfile: does it install from "
                        "this file?)")

_CLASS_LOCK = "2"


def _a(key: str, claim: str, basis: str, evidence: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"key": key, "claim": claim, "basis": basis, "evidence": [str(e) for e in (evidence or []) if e]}


def _na(key: str, why: str) -> Dict[str, Any]:
    return _a(key, f"not applicable: {why}", MEASURED)


# ── planner keys ───────────────────────────────────────────────────────────────────

def provenance(row: Dict[str, Any]) -> Dict[str, Any]:
    """`measured` ONLY when the Atlas returned the must-move set and nothing in it is stale, out of scope or under
    review. Anything else is `unknown`, and the claim tells the reviewer to read the Dockerfile. What the lock's own
    Dockerfiles said (rule R1, `lock_provenance`) is added as evidence either way."""
    out = _provenance(row)
    lp = row.get("lock_provenance")
    if isinstance(lp, dict) and lp.get("state"):
        out["evidence"] = out["evidence"] + [f"Dockerfiles of the lock's tree: {lp['state']} ({lp.get('why')})"] + \
            [str(e) for e in lp.get("evidence") or []]
    return out


def _provenance(row: Dict[str, Any]) -> Dict[str, Any]:
    pkg = row.get("package")
    ms = row.get("move_scope")
    if not isinstance(ms, dict):
        return _a("provenance", f"nobody asked the Atlas which locks ship {pkg}; {CHECK_THE_DOCKERFILE}", UNKNOWN)
    src = ms.get("source")
    if src != "atlas":
        return _a("provenance", f"the Atlas did not verify which locks ship {pkg} ({src}: {ms.get('why') or '?'}); "
                                f"{CHECK_THE_DOCKERFILE}", UNKNOWN)
    gaps = []
    if ms.get("stale"):
        gaps.append(f"{len(ms['stale'])} place(s) the Atlas could not verify")
    if ms.get("out_of_scope"):
        gaps.append(f"{len(ms['out_of_scope'])} other repository pin(s) outside this plan")
    if ms.get("review"):
        gaps.append("a build step patches the package")
    ev = [f"{x.get('repository')}/{x.get('file')}" for k in ("stale", "out_of_scope") for x in ms.get(k) or []
          if isinstance(x, dict)]
    ev += [f"{x.get('repository')}/{x.get('dockerfile') or x.get('file')}: {x.get('words') or ''}".rstrip(": ")
           for x in ms.get("review") or [] if isinstance(x, dict)]
    if gaps:
        return _a("provenance", f"the Atlas answered but not fully ({'; '.join(gaps)}); {CHECK_THE_DOCKERFILE}",
                  UNKNOWN, ev)
    return _a("provenance", f"the Atlas confirmed every lock that ships {pkg} is in this plan"
                            + (f" (as of {ms['as_of']})" if ms.get("as_of") else ""), MEASURED, ev)


def _is_override(row: Dict[str, Any]) -> bool:
    return (row.get("verdict") == _CLASS_LOCK and row.get("ecosystem") == "npm"
            and (not row.get("declared_here") or bool(row.get("nested_copies"))))


def parents_admit(row: Dict[str, Any]) -> Dict[str, Any]:
    pa = row.get("parents_admit")
    if isinstance(pa, dict):
        ev = [f"{p.get('name')} `{p.get('declared')}` admits={p.get('admits')}" for p in pa.get("parents") or []
              if isinstance(p, dict)]
        return _a("parents_admit", str(pa.get("claim") or ""), str(pa.get("basis") or UNKNOWN), ev)
    if row.get("verdict") == _CLASS_LOCK and not row.get("declared_here"):
        return _a("parents_admit", "transitive, fixed by a re-resolve (no override): gate 1's resolver must satisfy "
                                   "every parent's declared range", INFERRED)
    return _na("parents_admit", "the package is declared directly here; no parent's range is overridden")


def override_forced(row: Dict[str, Any]) -> Dict[str, Any]:
    forced = row.get("override_forced")
    if forced is True:
        return _a("override_forced", "an override takes the package outside at least one parent's declared range",
                  MEASURED, [(row.get("parents_admit") or {}).get("claim")])
    if forced is False:
        return _a("override_forced", "the override stays inside every parent's declared range", MEASURED)
    if _is_override(row):
        return _a("override_forced", "the parents' ranges could not be read, so whether the override forces one is "
                                     "unknown", UNKNOWN)
    return _na("override_forced", "no override is written")


def target_line(row: Dict[str, Any]) -> Dict[str, Any]:
    tl = row.get("target_line")
    if isinstance(tl, dict):
        return _a("target_line", str(tl.get("claim") or ""), str(tl.get("basis") or UNKNOWN), tl.get("evidence"))
    return _a("target_line", f"the target {row.get('target')} was not checked against the advisories' per-line "
                             f"fixes (--target-line off)", UNKNOWN)


def api_check(row: Dict[str, Any]) -> Dict[str, Any]:
    d = row.get("api_diff")
    if not isinstance(d, dict):
        # ⛔ "not applicable" ONLY for a lock move PROVEN to stay on the installed major line. Found by the first live
        # review (2026-11-04): a 1.x → 5.x override with no `api_question` flag read "inside the installed major
        # line", and the reviewer rightly called the claim false.
        crosses = (bool(row.get("api_question")) or row.get("verdict") != _CLASS_LOCK
                   or bool((row.get("target_line") or {}).get("major_jump"))
                   or _major(row.get("installed")) != _major(row.get("target")))
        if not crosses:
            return _na("api_check", "a lock-only move inside the installed major line")
        return _a("api_check", "no API diff was read for this move: what the upgrade changes is unknown", UNKNOWN)
    state = d.get("state")
    if state != "ready":
        why = d.get("why") or d.get("reason") or "no reason recorded"
        return _a("api_check", f"the API diff is {state}: {why}", UNKNOWN)
    touched = len(d.get("touched") or [])
    ev = [f"blind to: {w}" for w in d.get("blind_to_words") or []]
    weak = [w for w in d.get("weakly_checked") or [] if isinstance(w, dict)]
    ev += [f"weak: {w.get('words')}" + (f" ({w.get('repo') + '/' if w.get('repo') else ''}{w.get('file')}:"
                                        f"{w.get('line')})" if w.get("file") else "") for w in weak]
    method = d.get("method_words") or d.get("method") or "?"
    claim = f"{touched} changed symbol(s) used here, {method}"
    if weak:
        return _a("api_check", claim + "; WEAKLY CHECKED: this tree may reach the package in ways the check cannot "
                                       "follow", INFERRED, ev)
    if d.get("method") != "callgraph" or d.get("complete") is False:
        return _a("api_check", claim + ("; the API diff is incomplete" if d.get("complete") is False else ""),
                  INFERRED, ev)
    return _a("api_check", claim, MEASURED, ev)


def _major(v: Any) -> Optional[str]:
    """The leading release component ('1' of 1.1.15; '0.4' for a 0.x line), or None when unreadable."""
    parts = str(v or "").lstrip("vV=^~ ").split(".")
    if not parts or not parts[0].isdigit():
        return None
    return parts[0] if parts[0] != "0" else ".".join(parts[:2])


def runtime_floor(row: Dict[str, Any]) -> Dict[str, Any]:
    rf = row.get("runtime_floor")
    if isinstance(rf, dict):
        return _a("runtime_floor", str(rf.get("claim") or ""), str(rf.get("basis") or UNKNOWN), rf.get("evidence"))
    return _a("runtime_floor", "the target's runtime floor was not read (--runtime-floor off)", UNKNOWN)


def lock_fresh(row: Dict[str, Any]) -> Dict[str, Any]:
    checks = [c for c in row.get("lock_check") or [] if isinstance(c, dict)]
    if not checks:
        return _a("lock_fresh", "the lock was not checked against its manifest (--lock-check off)", UNKNOWN)
    ev = [f"{c.get('lock')}: {c.get('state')}" + (f" ({c['why']})" if c.get("why") else "") for c in checks]
    if all(c.get("state") == "fresh" for c in checks):
        return _a("lock_fresh", "re-locking with no upgrade changes nothing: the lock is current with its manifest",
                  MEASURED, ev)
    return _a("lock_fresh", "whether the lock is current with its manifest is unknown (the resolver did not answer)",
              UNKNOWN, ev)


def plan_assumptions(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The seven planner keys for one fixable row, in a fixed order."""
    return [provenance(row), parents_admit(row), override_forced(row), target_line(row), api_check(row),
            runtime_floor(row), lock_fresh(row)]


# ── apply keys ─────────────────────────────────────────────────────────────────────

def moved(report: Dict[str, Any]) -> Dict[str, Any]:
    g2 = report.get("gate_2_blast_radius")
    if not isinstance(g2, list) or not g2:
        return _a("moved", "gate 2 did not run, so what else the resolve moved is unknown", UNKNOWN)
    ms = [m for g in g2 for m in g.get("moved") or [] if isinstance(m, dict)]
    if not ms:
        return _a("moved", "nothing else moved: the resolve changed only the planned package(s)", MEASURED)
    ev = [f"{m.get('package')} {m.get('from')} → {m.get('to')}" + (" (DOWNGRADE)" if m.get("downgrade") else "")
          for m in ms]
    return _a("moved", f"{len(ms)} other package(s) moved with the fix", MEASURED, ev)


def tests(report: Dict[str, Any]) -> Dict[str, Any]:
    """⚠️ Even a pass says nothing about whether the suite exercises the changed package: stated every time."""
    g4, g5 = report.get("gate_4_build") or {}, report.get("gate_5_tests") or {}
    s4, s5 = g4.get("status"), g5.get("status")
    ev = [f"gate 4 (build): {s4} — {g4.get('why') or ''}".rstrip(" —"), f"gate 5 (tests): {s5} — "
                                                                          f"{g5.get('why') or ''}".rstrip(" —")]
    cov = "; coverage of the changed package by the suite is unknown"
    if s4 in ("failed", "error") or s5 in ("failed", "error"):
        return _a("tests", f"the build or the tests did not pass (build {s4}, tests {s5})", MEASURED, ev)
    if s4 == "passed" and s5 in ("passed", "pre_existing"):
        extra = " (red before the fix too, so not this fix's fault)" if s5 == "pre_existing" else ""
        return _a("tests", f"the project builds and its tests pass on the fixed copy{extra}{cov}", MEASURED, ev)
    return _a("tests", f"the project's build and tests were not run or found (build {s4}, tests {s5}){cov}",
              UNKNOWN, ev)


def apply_assumptions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [moved(report), tests(report)]


def merged(plan_list: List[Dict[str, Any]], apply_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """All nine keys in spec § 5 order (plan keys win for theirs, apply keys for theirs)."""
    by = {a["key"]: a for a in plan_list + apply_list}
    return [by[k] for k in KEYS if k in by]
