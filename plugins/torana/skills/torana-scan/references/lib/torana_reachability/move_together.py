"""Everything that must move together to ship package P at a fixed version (FIX_KNOWLEDGE_CONVERGENCE.md § 3.4.2).

Two pure steps, no I/O, no network, no clock:

- `pins_on_path(trees, primary, edges, ecosystem, package, scanned, not_checked=)` -> PinSet: every declaration,
  resolution and build patch of P on the primary tree's install path, each with its ROLE. It does not depend on the
  target, so the Atlas computes it once and stores it.
- `must_move(pins, target)` -> MoveSet: which pins must change for P to ship at `target` (members), which only need a
  person to look (review), which already admit it (fine), and which the policy cannot decide (undecidable).

Why two steps: the two readers use different targets for the same pins. The Atlas has ONE alert's fixed version; the
fix planner uses the HIGHEST fix across a group. The pins are a fact about the code; the judgment is a pure function of
pins and target, so each reader runs it with its own target, in this code.

⭐ MEASURED (2026-10-27, § 2.5): with only the base lock's input bumped (litellm 1.82.6 -> 1.88.6), every service still
ships 1.82.6. The install wrapper tries an offline install first; a shared library's wheel requests
`litellm==1.82.6`, the offline install fails, and the online fallback re-installs 1.82.6. That request is a `request`
pin whose spec rejects the target: "would pull the old version back". So the set is three places, not the one the
Atlas used to name.

⛔ Edges are INPUT. Which locks and wheels a tree installs from is read from Dockerfiles by the Atlas's own extractor,
which this library does not have (D-W1.1). The walk follows whatever edges it is given.

⛔ Not in the set (one fixed sentence, `NOT_LISTED`): packages the recompile moves WITH P (litellm 1.88.6 takes openai
3.16.2 -> 2.x). They are a fact of the resolve, which no model-free reader can know; apply gate 2 reports them.

The words are written here, once: readers print `words` / `why` verbatim.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from . import manifests, policy
from .firstparty import normalize

SCHEMA_PINS = "torana-reachability/pin-set.v1"
SCHEMA_MOVE = "torana-reachability/move-set.v1"

#: The caps (§ 3.4.2). Past either one the set is `complete: false`, with a `not_checked` entry whose reason is `cap`.
MAX_PINS = 200
MAX_TREES = 20

ROLES = ("source", "ships", "request", "patch")
NOT_LISTED = "Packages the recompile moves with it are not listed here; the fix's resolve reports them (gate 2)."
WHY_SHIPS = "ships it"
WHY_PULLS_BACK = "would pull the old version back"
#: Copied from the pin onto every members/review/fine/undecidable entry, null when unknown.
_LINK_KEYS = ("repository", "commit", "anchor")


@dataclass(frozen=True)
class Tree:
    """One repository's manifests at one commit. `records` is exactly `manifests.read_manifests()` output: the
    Atlas's `facts/manifests.json` records have that shape, and a checkout produces it by calling read_manifests."""
    label: str                      # the tree's key: the Atlas passes the repository subject, a checkout its root label
    repository: Optional[str]       # source-neutral key "repo:github.com/org/name"; None for an unkeyed checkout
    commit: Optional[str]
    records: Sequence[Dict[str, Any]]
    patches: Sequence[Dict[str, Any]] = field(default=())   # build "patch" records (Atlas facts/build.json)


@dataclass(frozen=True)
class Edge:
    """`src` installs something `dst` provides."""
    src: str                        # the installing tree's label
    dst: str                        # the providing tree's label
    kind: Literal["provider_lock", "wheel"]
    file: str                       # provider_lock: the lock in dst; wheel: the wheel path src installs
    via: str = ""                   # the install step id in src (e.g. "Dockerfile:58:0"), for the words


# ── small helpers ─────────────────────────────────────────────────────────────────────────────────────────────

def short_name(label: Optional[str]) -> str:
    """The name words use: `repo:github.com/acme/billing-api` -> `billing-api`."""
    s = str(label or "")
    return s.removeprefix("repo:").rstrip("/").rsplit("/", 1)[-1] or s


def _pkg(eco: str, name: str) -> str:
    return normalize(name) if eco == "pypi" else name


def _anchor(rec: Dict[str, Any]) -> Optional[str]:
    a = rec.get("anchors")
    return a[0] if isinstance(a, (list, tuple)) and a else rec.get("anchor")


def _same_version(eco: str, a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    if eco == "pypi":
        return policy.admits("pypi", f"=={a}", b) is True
    return a == b


def _at_least(eco: str, version: Optional[str], target: str) -> Optional[bool]:
    if not version:
        return None
    return policy.admits(eco, f">={target}", version)


def propose_spec(eco: str, spec: str, syntax: str, target: str) -> Tuple[Optional[str], Optional[str]]:
    """(the declaration rewritten to admit `target`, or None with why). Only the shapes whose rewrite is
    mechanical: an exact pin, a lower bound, npm's `^` / `~` / exact. ⛔ An upper bound that excludes the fix is a
    human's decision (it was written for a reason), so it is not rewritten.

    MOVED from the fix planner (`remediation_plan.py` `propose_spec`, unchanged body) so both readers rewrite a
    spec the same way; the planner imports it from here once this version is vendored."""
    s = (spec or "").strip()
    new: Optional[str] = None
    if eco == "pypi" and (syntax or "pep508") == "pep508":
        parts = [p.strip() for p in s.split(",") if p.strip()]
        out = []
        for p in parts:
            if p.startswith(("==", ">=", "~=")) and not p.startswith("==="):
                out.append(p[:2] + target)
            elif policy.admits(eco, p, target) is False:
                return None, f"`{p}` excludes {target}: an upper bound or exclusion is not rewritten mechanically"
            else:
                out.append(p)
        new = ",".join(out)
    elif eco == "npm":
        if s[:1] in ("^", "~") and policy.admits(eco, s[1:], s[1:]):
            new = s[0] + target
        elif policy.admits(eco, s, s):
            new = target
    if new is None:
        return None, f"no mechanical rewrite for `{spec}` ({syntax})"
    if policy.admits(eco, new, target, syntax) is not True:
        return None, f"the rewrite `{new}` does not admit {target}"
    return new, None


# ── step 1: the pins (target-free) ────────────────────────────────────────────────────────────────────────────

def _walk(trees: Dict[str, Tree], primary: str, edges: Sequence[Edge]
          ) -> Tuple[List[str], List[Tuple[Edge, int]], List[Dict[str, Any]]]:
    """(the reached tree labels in walk order, the edges taken with their depth, the gaps found while walking).
    Breadth-first from `primary`; a tree is visited once; at most MAX_TREES trees."""
    order: List[str] = [primary]
    taken: List[Tuple[Edge, int]] = []
    gaps: List[Dict[str, Any]] = []
    seen = {primary}
    queue = deque([(primary, 0)])
    out_of = {}
    for e in sorted(edges, key=lambda e: (e.src, e.dst, e.kind, e.file, e.via)):
        out_of.setdefault(e.src, []).append(e)
    while queue:
        label, depth = queue.popleft()
        for e in out_of.get(label, ()):
            if e.dst not in trees:
                gaps.append({"tree": e.dst, "name": short_name(e.dst), "why": "not loaded",
                             "words": f"{short_name(e.dst)} is installed from ({e.kind} {e.file}) but its manifests "
                                      f"were not read"})
                continue
            if e.dst in seen:
                taken.append((e, depth + 1))            # a second edge into a visited tree (e.g. a lock AND a wheel)
                continue
            if len(order) >= MAX_TREES:
                gaps.append({"tree": e.dst, "name": short_name(e.dst), "why": "cap",
                             "words": f"more than {MAX_TREES} repositories are on the install path; "
                                      f"{short_name(e.dst)} and any after it were not checked"})
                continue
            taken.append((e, depth + 1))
            seen.add(e.dst)
            order.append(e.dst)
            queue.append((e.dst, depth + 1))
    return order, taken, gaps


def _unreadable(tree: Tree, eco: str) -> Optional[str]:
    """Why this tree's declarations of `eco` cannot be trusted to be complete, or None."""
    recs = [r for r in tree.records if r.get("ecosystem") == eco]
    if manifests.declarations_complete(list(recs), eco):
        return None
    files = [r for r in recs if r.get("kind") == "manifest_file" and r.get("manifest_kind") != "lockfile"]
    if not files:
        return f"no {eco} manifest was found"
    bad = sorted(r.get("file") or "?" for r in files if not r.get("readable"))
    return f"{', '.join(bad[:3]) or 'a manifest'} could not be read"


def _base(tree: Tree, rec: Dict[str, Any], role: str, **extra: Any) -> Dict[str, Any]:
    pin = {"role": role, "tree": tree.label, "name": short_name(tree.label), "repository": tree.repository,
           "commit": tree.commit, "file": rec.get("file"), "line": rec.get("line")}
    a = _anchor(rec)
    if a:
        pin["anchor"] = a
    pin.update({k: v for k, v in extra.items() if v not in (None, "")})
    return pin


def pins_on_path(trees: Dict[str, Tree], primary: str, edges: Sequence[Edge], ecosystem: str, package: str,
                 scanned: Optional[str], *, not_checked: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """The PinSet (schema `torana-reachability/pin-set.v1`) for `package` on `primary`'s install path.

    Roles: `ships` (a resolution an install on the path takes), `source` (the input that resolution is compiled from),
    `request` (a declaration an install on the path brings in: the primary's own manifests and a wheel's runtime
    dependencies), `patch` (a build step of the primary that rewrites the package's installed files).

    `scanned` is the version the finding was scanned at. A declaration that does not admit it, and a resolution at
    another version, did not produce the scanned artifact: it is `ignored` with its reason, never a pin (the rule from
    the planner's `classify`). With `scanned=None` nothing is ignored. `not_checked` carries gaps only the caller can
    see (e.g. a second hop the Atlas did not load); `complete` is false whenever any gap exists."""
    eco = (ecosystem or "").lower()
    pkg = _pkg(eco, package)
    gaps: List[Dict[str, Any]] = [dict(g) for g in not_checked or ()]
    if primary not in trees:
        gaps.append({"tree": primary, "name": short_name(primary), "why": "not loaded",
                     "words": f"{short_name(primary)}'s manifests were not read"})
        return _pinset(eco, pkg, scanned, primary, [], [], [], gaps)
    order, taken, walk_gaps = _walk(trees, primary, edges)
    gaps += walk_gaps
    for label in order:
        why = _unreadable(trees[label], eco)
        if why:
            gaps.append({"tree": label, "name": short_name(label), "why": "unreadable",
                         "words": f"{short_name(label)}: {why}, so a pin there may be missed"})

    pins: List[Dict[str, Any]] = []
    ignored: List[Dict[str, Any]] = []

    def mine(tree: Tree, kind: str) -> List[Dict[str, Any]]:
        return [r for r in tree.records if r.get("kind") == kind and r.get("ecosystem") == eco
                and _pkg(eco, r.get("package") or "") == pkg and r.get("installed_by_build") is not False]

    def ignore(tree: Tree, rec: Dict[str, Any], why: str) -> None:
        ignored.append({"tree": tree.label, "name": short_name(tree.label), "file": rec.get("file"),
                        "line": rec.get("line"), "spec": rec.get("version_spec") or rec.get("version"), "why": why,
                        "words": f"{short_name(tree.label)} {rec.get('file')}:{rec.get('line')} "
                                 f"`{rec.get('version_spec') or rec.get('version')}` {why}"})

    def declaration_ok(tree: Tree, d: Dict[str, Any]) -> bool:
        if scanned and policy.admits(eco, d.get("version_spec") or "", scanned, d.get("syntax")) is False:
            ignore(tree, d, f"does not admit the scanned {scanned}: not part of this resolve")
            return False
        return True

    def ship(tree: Tree, via: str, lock_file: Optional[str] = None) -> None:
        """The resolutions of P this install takes (in `lock_file`, or every lock of the primary), and their sources."""
        for r in mine(tree, "resolution"):
            if lock_file is not None and r.get("file") != lock_file:
                continue
            if scanned and not _same_version(eco, scanned, r.get("version")):
                ignore(tree, r, f"resolves {r.get('version')}, not the scanned {scanned}: not part of this resolve")
                continue
            src = r.get("compiled_from")
            pins.append(_base(tree, r, "ships", version=r.get("version"), lock_format=r.get("lock_format"),
                              compiled_from=src, via=via))
            if not src:
                continue
            # ⛔ No "rejects the scanned version" test on a SOURCE: it is the lock's input by construction. One that
            # no longer admits what the lock holds (the input bumped, the lock not yet recompiled) is exactly the
            # half-done fix this set exists to finish, and must stay visible, not be ignored.
            for d in mine(tree, "declaration"):
                if d.get("file") == src:
                    pins.append(_base(tree, d, "source", spec=d.get("version_spec") or "", syntax=d.get("syntax"),
                                      compiles_into=r.get("file"), via=via))

    # the primary: its own locks, its own requests, its own build patches
    P = trees[primary]
    ship(P, "")
    for d in mine(P, "declaration"):
        if d.get("manifest_kind") not in ("pyproject", "requirements", "package.json") or d.get("group") != "main":
            continue
        if any(p["tree"] == P.label and p["file"] == d.get("file") and p["line"] == d.get("line") for p in pins):
            continue                                    # already a `source` (pyproject behind uv.lock)
        if any(p["tree"] == P.label and p["role"] == "ships" and p["file"] == d.get("file") for p in pins):
            continue                                    # a hand-pinned requirements line: `ships`, not also a request
        if declaration_ok(P, d):
            pins.append(_base(P, d, "request", spec=d.get("version_spec") or "", syntax=d.get("syntax")))
    for b in P.patches or ():
        if b.get("kind", "patch") != "patch" or b.get("default_active") is False:
            continue
        if _pkg(eco, b.get("package") or "") != pkg and _pkg(eco, b.get("import_root") or "") != pkg:
            continue
        pins.append({"role": "patch", "tree": P.label, "name": short_name(P.label), "repository": P.repository,
                     "commit": P.commit, "file": b.get("file") or b.get("target_path"),
                     "line": b.get("apply_line"), "dockerfile": b.get("dockerfile"),
                     "copy_line": b.get("copy_line"), "apply_line": b.get("apply_line"), "method": b.get("method"),
                     **({"anchor": _anchor(b)} if _anchor(b) else {})})

    # every tree an edge reaches: a provider lock's line, a wheel's runtime requests
    for e, _depth in taken:
        D = trees[e.dst]
        if e.kind == "provider_lock":
            ship(D, e.via, lock_file=e.file)
        else:
            for d in mine(D, "declaration"):
                if (d.get("file") in ("pyproject.toml", "package.json")
                        and d.get("manifest_kind") in ("pyproject", "package.json") and d.get("group") == "main"
                        and declaration_ok(D, d)):
                    pins.append(_base(D, d, "request", spec=d.get("version_spec") or "", syntax=d.get("syntax"),
                                      reached_by=f"wheel {e.file}", via=e.via))

    seen_keys = set()
    unique = []
    for p in sorted(pins, key=_pin_key):
        k = (p["tree"], p["file"], p["line"], p["role"])
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append(p)
    if len(unique) > MAX_PINS:
        unique = unique[:MAX_PINS]
        gaps.append({"tree": "*", "name": "*", "why": "cap",
                     "words": f"more than {MAX_PINS} places hold {pkg}; the rest were not listed"})
    return _pinset(eco, pkg, scanned, primary, unique, ignored, order, gaps)


def _pin_key(p: Dict[str, Any]) -> Tuple:
    return (p["tree"], str(p.get("file") or ""), int(p.get("line") or 0), ROLES.index(p["role"]))


def _pinset(eco: str, pkg: str, scanned: Optional[str], primary: str, pins: List[Dict[str, Any]],
            ignored: List[Dict[str, Any]], checked: List[str], gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
    gaps_sorted = sorted({(g.get("tree"), g.get("why")): g for g in gaps}.values(),
                         key=lambda g: (str(g.get("tree")), str(g.get("why"))))
    return {"schema": SCHEMA_PINS, "ecosystem": eco, "package": pkg, "scanned": scanned, "primary": primary,
            "pins": pins,
            "ignored": sorted(ignored, key=lambda x: (x["tree"], str(x.get("file")), int(x.get("line") or 0))),
            "checked": sorted(checked), "not_checked": gaps_sorted, "complete": not gaps_sorted}


# ── step 2: the judgment ──────────────────────────────────────────────────────────────────────────────────────

def _place(p: Dict[str, Any]) -> str:
    return f"{p.get('name') or short_name(p.get('tree'))} {p.get('file')}" + (f":{p['line']}" if p.get("line") else "")


def must_move(pins: Dict[str, Any], target: str) -> Dict[str, Any]:
    """The MoveSet (schema `torana-reachability/move-set.v1`) for shipping the PinSet's package at `target`."""
    eco, pkg = pins.get("ecosystem") or "pypi", pins.get("package") or ""
    members: List[Dict[str, Any]] = []
    review: List[Dict[str, Any]] = []
    fine: List[Dict[str, Any]] = []
    undecidable: List[Dict[str, Any]] = []
    all_pins = list(pins.get("pins") or [])
    sources = {(p["tree"], p.get("compiles_into")): p for p in all_pins if p["role"] == "source"}

    def keep(p: Dict[str, Any], **kw: Any) -> Dict[str, Any]:
        # `to: null` is kept on purpose: with `needs_human` it is the "a person must change it" member (§ 3.4.2).
        # `repository`, `commit` and `anchor` are ALWAYS present (null when unknown): readers link from the entry
        # itself and must never re-join it to the pins (lead 2026-10-27, B3's question).
        out = {k: v for k, v in {**p, **kw}.items() if v is not None or k in _LINK_KEYS or k == "to"}
        for k in _LINK_KEYS:
            out.setdefault(k, p.get(k))
        return out

    def bump(p: Dict[str, Any], frm: str, why: str, then: Optional[str] = None) -> None:
        to, stuck = propose_spec(eco, frm, p.get("syntax") or ("pep508" if eco == "pypi" else ""), target)
        tail = f", then {then}" if then else ""
        if to is None:
            members.append(keep(p, action="bump", **{"from": frm, "to": None}, needs_human=stuck, why=why, then=then,
                                words=f"{_place(p)} `{frm}` must change to admit {target} ({why}){tail}; "
                                      f"a person must change it: {stuck}"))
        else:
            members.append(keep(p, action="bump", **{"from": frm, "to": to}, why=why, then=then,
                                words=f"{_place(p)} `{frm}` → `{to}` ({why}){tail}"))

    def cannot(p: Dict[str, Any], spec: str) -> None:
        undecidable.append(keep(p, words=f"{_place(p)}: the policy cannot decide whether `{spec}` admits {target}"))

    for p in all_pins:
        role = p["role"]
        if role == "patch":
            step = f"{p.get('dockerfile')}:{p.get('apply_line')}" if p.get("dockerfile") else _place(p)
            review.append(keep(p, words=f"{p.get('name')} {step} runs {p.get('file')} on the installed {pkg}; "
                                        f"check it still applies to {target}"))
        elif role in ("source", "request"):
            spec = p.get("spec") or ""
            ok = policy.admits(eco, spec, target, p.get("syntax"))
            if ok is None:
                cannot(p, spec)
            elif ok:
                fine.append(keep(p, words=f"{_place(p)} `{spec or '(any)'}` admits {target}"))
            elif role == "source":
                bump(p, spec, WHY_SHIPS, then=f"recompile {p.get('compiles_into')}")
            else:
                bump(p, spec, WHY_PULLS_BACK)
        elif role == "ships":
            at = _at_least(eco, p.get("version"), target)
            if at is None:
                cannot(p, f">={target}")
                continue
            if at:
                fine.append(keep(p, words=f"{_place(p)} already ships {p.get('version')}, at or above {target}"))
                continue
            src = sources.get((p["tree"], p.get("file")))
            if src is not None:
                ok = policy.admits(eco, src.get("spec") or "", target, src.get("syntax"))
                if ok is False or ok is None:
                    continue                            # the source member (or its undecidable entry) carries it
                members.append(keep(p, action="recompile", why=WHY_SHIPS,
                                    words=f"{_place(p)} ships {p.get('version')}: recompile it ({WHY_SHIPS}; its "
                                          f"input {src.get('file')}:{src.get('line')} already admits {target})"))
            else:
                frm = f"=={p.get('version')}" if eco == "pypi" else str(p.get("version"))
                bump(p, frm, WHY_SHIPS)

    order = lambda x: _pin_key(x)                       # noqa: E731 - the same (tree, file, line, role) order as pins
    return {"schema": SCHEMA_MOVE, "ecosystem": eco, "package": pkg, "target": target,
            "members": sorted(members, key=order), "review": sorted(review, key=order),
            "fine": sorted(fine, key=order), "undecidable": sorted(undecidable, key=order),
            "ignored": list(pins.get("ignored") or []), "not_checked": list(pins.get("not_checked") or []),
            "complete": bool(pins.get("complete")), "decided": not undecidable, "not_listed": NOT_LISTED}
