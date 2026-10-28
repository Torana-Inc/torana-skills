#!/usr/bin/env python3
"""Can a `signature_changed` entry break a CALL SITE? (FIX_PR phase 3 § 3.4.6 step 3b.)

An API diff's `signature_changed` list says that a symbol's declaration moved. It does NOT say whether anyone
calling that symbol has to change. `api_diff_check` used to treat every entry alike, so an added
keyword-only argument with a default and a dropped required parameter produced the IDENTICAL class-4
verdict. This module reads the `from` / `to` declarations the API diff already carries and says which of the
two it is.

⛔ PURE, AND TEXT-ONLY. Two declaration strings in, a class and a one-line reason out. No network, no
imports of the package being described, no model.

⭐ WHY THIS EARNS ITS PLACE — MEASURED 2026-10-27 over 93 real `signature_changed` entries from four
cached cards (pyjwt 2.9.0→2.15.0 and 2.14.0→2.15.0, cryptography 45.0.6→50.0.0, starlette 0.52.1→1.10.0):

    annotation_only  44   nothing a caller passes or receives changed
    value_changed    13   an attribute's initialiser moved
    kind_changed     14   a class or function became a re-exported attribute
    default_changed  10   a parameter's default moved
    params_changed   12   a caller can break
    bases_changed     5   a class's base list moved

So **12 of 93 can break a call site, and 44 provably cannot.** Treating all 93 as class 4 is what made the
verdict untrustworthy: a reviewer told "32 signatures changed" learns nothing and stops reading.

⚠️ THE SAFE DIRECTION IS UNCHANGED. Only `annotation_only` and `identical` lose their hit. Everything this
module cannot parse stays a hit (`opaque`), a kind change stays a hit even though the call usually still
works, and a moved default stays a hit because the call still compiles and does something else — which is
the one failure a build gate does NOT catch. `api_diff_check`'s cost rule still holds: a false class 3
merges a build break, a false class 4 costs a reviewer ten minutes.

⛔ IT READS DECLARATIONS, NEVER CALLS. `params_changed` means "a caller COULD break", never "your caller
WILL break" — nothing here parses a call expression, so it cannot tell a keyword caller from a positional
one. MEASURED 2026-10-27: pyjwt 2.9.0 -> 2.15.0 inserts `subject` before `issuer`, which breaks a
positional caller; the real call sites found in one shared library pass `algorithms=`, `audience=` and
`options=` by keyword and are therefore fine. The hit is still correct and still worth a person — the
symbol IS used and its signature DID move in a breaking way — and a reviewer confirms it in seconds by
looking at the call. Narrowing that further needs an AST of the call site, which `card_intersection`
deliberately does not build (it has import records and a word search, no call graph).

⛔ AN ANNOTATION CHANGE IS NOT A RUNTIME CHANGE, BUT IT IS NOT NOTHING. A NARROWED annotation
(starlette's `protocol: str` → `Literal['http', 'websocket', '']`) fails a type checker while the call
runs fine. That is why `annotation_only` entries are RECORDED on the row rather than dropped, and why
gates 4-5 (build, tests) remain the backstop for the class-3 lane — a repo that runs mypy in its build
sees the narrowing there, which is the right place to see it.

The declaration format is the extractor's (`torana_upgrade_card/pypi.py::_signature`), which renders
griffe's model:

    function   (<kind>:<name>[: <annotation>][ = <default>], ...) -> <returns>
    class      class(<base>, ...)
    attribute  <annotation> = <value>
    module     module
    alias      alias -> <target path>

Usage (as a library):
    import signature_delta
    signature_delta.classify(entry["from"], entry["to"], entry.get("kind"), entry.get("to_kind"))
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

#: griffe's `ParameterKind.value` strings, exactly as the extractor renders them before the `:`.
POSITIONAL_ONLY = "positional-only"
POSITIONAL_OR_KEYWORD = "positional or keyword"
VARIADIC_POSITIONAL = "variadic positional"
KEYWORD_ONLY = "keyword-only"
VARIADIC_KEYWORD = "variadic keyword"
KINDS = (POSITIONAL_ONLY, POSITIONAL_OR_KEYWORD, VARIADIC_POSITIONAL, KEYWORD_ONLY, VARIADIC_KEYWORD)

#: A caller addresses these by position, in this order.
_POSITIONAL = (POSITIONAL_ONLY, POSITIONAL_OR_KEYWORD)
#: A caller addresses these by name.
_BY_NAME = (POSITIONAL_OR_KEYWORD, KEYWORD_ONLY)

IDENTICAL = "identical"
ANNOTATION_ONLY = "annotation_only"
DEFAULT_CHANGED = "default_changed"
VALUE_CHANGED = "value_changed"
KIND_CHANGED = "kind_changed"
BASES_CHANGED = "bases_changed"
PARAMS_CHANGED = "params_changed"
OPAQUE = "opaque"

#: ⛔ THE ONLY TWO CLASSES THAT DO NOT PUT A HUMAN ON THE ROW. Everything else — including every class this
#: module could not parse — keeps today's behaviour and contributes a class-4 hit. Adding a member here is
#: a decision to merge that change on green, so it needs the measurement that says nobody can break.
COMPATIBLE = (IDENTICAL, ANNOTATION_ONLY)

#: The reason travels in `api_diff`, which the server caps at 16 KiB for the whole block
#: (`remediation_api_diff.MAX_API_DIFF_BYTES`), and a real declaration runs to 800 characters a side. So a
#: reason is a SHORT sentence a reviewer reads, never the two declarations — those stay in the card, which
#: every surface can already show.
MAX_DETAIL = 240

_OPEN, _CLOSE = "([{", ")]}"

#: PEP 585: the `typing` spellings and their builtin equivalents name the SAME type, and a package moving
#: from one to the other has changed nothing. Measured: 10 of the 23 moved values in the sample are this
#: churn alone (`Dict[str, Any]` → `dict[str, Any]`, `typing.Type[X]` → `type[X]`).
_PEP585 = {"Dict": "dict", "List": "list", "Set": "set", "FrozenSet": "frozenset", "Tuple": "tuple",
           "Type": "type", "Deque": "deque", "DefaultDict": "defaultdict", "OrderedDict": "OrderedDict",
           "Counter": "Counter", "ChainMap": "ChainMap"}


# ── bracket- and quote-aware string walking ──────────────────────────────────────────────────────────
# ⛔ NEVER `str.split(",")` ON A TYPE EXPRESSION. `Callable[[int, str], None]` holds two commas that are
# not parameter separators, and `protocol: Literal['http', 'websocket', ''] = ''` holds both a comma and a
# `:` inside quotes. Every split below walks the string tracking bracket depth and quote state.

def _walk(s: str):
    """Yield `(index, char, depth)` for `s`, where `depth` is the depth of the context the character sits
    IN — so a bracket is reported at the depth outside the group it opens or closes, and `[` in
    `Dict[str, Any]` is depth 0 while the `,` inside it is depth 1. Characters inside quotes are reported
    at -1 so no caller mistakes them for structure."""
    depth, quote, i = 0, None, 0
    while i < len(s):
        c = s[i]
        if quote is not None:
            if c == "\\":
                yield i, c, -1
                if i + 1 < len(s):
                    yield i + 1, s[i + 1], -1
                i += 2
                continue
            if c == quote:
                quote = None
            yield i, c, -1
            i += 1
            continue
        if c in "'\"":
            quote = c
            yield i, c, -1
            i += 1
            continue
        if c in _OPEN:
            yield i, c, depth
            depth += 1
        elif c in _CLOSE:
            depth -= 1
            yield i, c, depth
        else:
            yield i, c, depth
        i += 1


def split_top(s: str, sep: str = ",") -> List[str]:
    """`s` split on every `sep` that is outside both brackets and quotes."""
    out, start = [], 0
    for i, c, depth in _walk(s):
        if c == sep and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


def find_top(s: str, needle: str) -> int:
    """The index of the first `needle` outside both brackets and quotes, or -1."""
    for i, _c, depth in _walk(s):
        if depth == 0 and s.startswith(needle, i):
            return i
    return -1


def _close_of_first_group(s: str) -> int:
    """The index of the bracket closing the group `s` opens with, or -1."""
    for i, _c, depth in _walk(s):
        if depth == 0 and i > 0:
            return i
    return -1


# ── type-expression canonicalisation (for COMPARISON only, never for display) ────────────────────────

def canon_type(expr: Optional[str]) -> Optional[str]:
    """A type expression rewritten so two spellings of one type compare equal.

    Handles exactly three equivalences, all of them spelling and not meaning: the `typing` aliases of
    builtin generics (PEP 585), `Optional[X]` as `X | None`, and `A | B` as `Union[A, B]` (PEP 604) with
    the members sorted so member order stops mattering.

    ⛔ IT MUST ONLY EVER COLLAPSE SPELLINGS. This function decides whether a moved attribute value counts
    as no change at all, so a rewrite that equates two DIFFERENT types would merge a break. Anything it
    does not recognise is returned with its structure intact rather than guessed at.
    """
    if expr is None:
        return None
    s = expr.strip()
    if not s:
        return s
    # `A | B` at the top level is a union, whatever its members are.
    parts = [p.strip() for p in split_top(s, "|")]
    if len(parts) > 1:
        return _union(parts)
    # `Name[...]` — canonicalise the head, then each argument.
    open_at = find_top(s, "[")
    if open_at > 0 and s.endswith("]"):
        head, inner = s[:open_at].strip(), s[open_at + 1:-1]
        bare = _unqualified(head)
        args = [p.strip() for p in split_top(inner)]
        if bare == "Optional" and len(args) == 1:
            return _union([args[0], "None"])
        if bare == "Union":
            return _union(args)
        return f"{_PEP585.get(bare, head)}[{', '.join(canon_type(a) or '' for a in args)}]"
    return _PEP585.get(_unqualified(s), s)


#: ⛔ ONLY THESE PREFIXES ARE DROPPED. `typing.Counter` and `collections.Counter` are one type, but
#: `mymod.Counter` is somebody else's class — stripping every prefix would equate the two and could call a
#: real change a non-change, which is the direction this module must never take.
_TYPING_MODULES = ("typing", "typing_extensions", "t", "collections", "collections.abc")


def _unqualified(name: str) -> str:
    """`typing.Dict` -> `Dict`, but `mymod.Dict` -> `mymod.Dict` (see `_TYPING_MODULES`)."""
    module, _, bare = name.rpartition(".")
    return bare if module in _TYPING_MODULES else name


def _union(members: Sequence[str]) -> str:
    """`Union[...]` over canonicalised members, flattened and sorted. `X | None | None` is `X | None`."""
    flat: List[str] = []
    for m in members:
        c = canon_type(m) or ""
        if c.startswith("Union[") and c.endswith("]"):
            flat.extend(p.strip() for p in split_top(c[6:-1]))
        else:
            flat.append(c)
    return "Union[" + ", ".join(sorted(set(flat))) + "]"


def _same_type(a: Optional[str], b: Optional[str]) -> bool:
    return canon_type(a) == canon_type(b)


# ── parsing the extractor's declaration shapes ───────────────────────────────────────────────────────

def parse_function(sig: str) -> Optional[Tuple[List[Dict[str, Any]], Optional[str]]]:
    """`(kind:name: ann = default, ...) -> ret` → `([param, ...], ret)`, or None when it is not a
    function declaration or cannot be parsed confidently."""
    s = (sig or "").strip()
    if not s.startswith("("):
        return None
    close = _close_of_first_group(s)
    if close < 0:
        return None
    inner, tail = s[1:close], s[close + 1:]
    ret = tail.split("->", 1)[1].strip() if "->" in tail else None
    params: List[Dict[str, Any]] = []
    for raw in split_top(inner) if inner.strip() else []:
        piece = raw.strip()
        if not piece:
            continue
        kind = next((k for k in KINDS if piece.startswith(k + ":")), None)
        if kind is None:
            return None                                  # an unknown shape is never guessed at
        rest = piece[len(kind) + 1:]
        eq = find_top(rest, " = ")
        default = rest[eq + 3:].strip() if eq >= 0 else None
        head = rest[:eq] if eq >= 0 else rest
        colon = find_top(head, ": ")
        name = (head[:colon] if colon >= 0 else head).strip()
        annotation = head[colon + 2:].strip() if colon >= 0 else None
        if not name.isidentifier():
            return None
        params.append({"kind": kind, "name": name, "annotation": annotation, "default": default})
    return params, ret


def parse_attribute(sig: str) -> Optional[Tuple[str, str]]:
    """`<annotation> = <value>` → `(annotation, value)`, either of which may be empty."""
    s = sig or ""
    eq = find_top(s, " = ")
    if eq < 0:
        return None
    return s[:eq].strip(), s[eq + 3:].strip()


def parse_class(sig: str) -> Optional[List[str]]:
    """`class(<base>, ...)` → the base list."""
    s = (sig or "").strip()
    if not s.startswith("class(") or not s.endswith(")"):
        return None
    inner = s[len("class("):-1]
    return [p.strip() for p in split_top(inner)] if inner.strip() else []


# ── the parameter diff ───────────────────────────────────────────────────────────────────────────────

def _param_delta(old: Sequence[Dict[str, Any]], new: Sequence[Dict[str, Any]]
                 ) -> Tuple[str, List[str], List[Dict[str, Any]]]:
    """`(class, reasons, facts)` for one function whose parameters may have moved.

    ⭐ `facts` IS THE SAME INFORMATION AS `reasons`, STRUCTURED. A reason is a sentence for a reviewer; a fact
    is `{"rule": …, "name": …, "index": …}` for a MACHINE — specifically for `call_narrowing`, which asks
    whether a given call site can actually be broken by this particular change. ⛔ Narrowing a verdict by
    re-reading those sentences would be the fragile thing this repo keeps warning about, so the facts travel
    beside them and `_brk` appends BOTH or neither, which is what stops the two drifting apart.

    ⭐ POSITION IS CHECKED, NOT JUST MEMBERSHIP, and this is the check that earns the module. MEASURED
    2026-10-27: pyjwt 2.9.0 → 2.15.0 inserts `subject: str | None = None` BETWEEN `audience` and `issuer`,
    both positional-or-keyword. Every parameter the old signature had is still present, and every added one
    has a default — so a membership-only rule calls it compatible. A caller passing `issuer` positionally
    now passes it as `subject`, silently, with no error at all. That is the worst failure available here,
    and only comparing the positional SEQUENCE catches it.
    """
    breaking: List[str] = []
    behaviour: List[str] = []
    notes: List[str] = []
    facts: List[Dict[str, Any]] = []

    def _brk(reason: str, rule: str, **fact: Any) -> None:
        """One breaking change, as a sentence AND a fact. ⛔ Never append to `breaking` directly."""
        breaking.append(reason)
        facts.append({"rule": rule, **fact})

    old_pos = [p for p in old if p["kind"] in _POSITIONAL]
    new_pos = [p for p in new if p["kind"] in _POSITIONAL]
    new_named = {p["name"]: p for p in new if p["kind"] in _BY_NAME}
    old_names = {p["name"] for p in old}
    new_all = {p["name"]: p for p in new}

    # 0. positional-only parameters have no name a caller can see, so the ONLY evidence that one was added
    #    or dropped is how many there are. ⛔ A rename among them is not a change and must stay compatible,
    #    which means the index-by-index test below has to ignore their names — and that alone would miss an
    #    INSERTION, which shifts every argument after it. Comparing the count is what closes that, and it is
    #    deliberately coarse: a simultaneous add and drop is indistinguishable from a rename here, and no
    #    name exists to tell them apart. (Measured 2026-10-27: 0 of 408 parameters in the sample were
    #    positional-only, so this is correctness for a rare shape, not a hot path.)
    old_po = [p for p in old if p["kind"] == POSITIONAL_ONLY]
    new_po = [p for p in new if p["kind"] == POSITIONAL_ONLY]
    if len(old_po) != len(new_po):
        _brk(f"positional-only parameter count {len(old_po)} -> {len(new_po)}",
             "positional_only_count", was=len(old_po), now=len(new_po))

    # 1. the positional sequence, index by index: a caller passing N arguments binds the first N.
    for i, p in enumerate(old_pos):
        q = new_pos[i] if i < len(new_pos) else None
        if q is None:
            dest = new_all.get(p["name"])
            if dest is None:
                _brk(f"positional parameter `{p['name']}` removed",
                     "positional_removed", name=p["name"], index=i)
            elif dest["kind"] in _POSITIONAL:
                # Still positional, but the sequence ahead of it got shorter, so its index moved and a
                # positional caller binds it to the wrong parameter.
                _brk(f"`{p['name']}` moved from position {i} to {new_pos.index(dest)}",
                     "moved", name=p["name"], was=i, now=new_pos.index(dest))
            else:
                _brk(f"`{p['name']}` is now {dest['kind']}, so it cannot be passed positionally",
                     "now_keyword_only", name=p["name"], index=i)
        elif q["name"] != p["name"] and p["kind"] != POSITIONAL_ONLY:
            # ⛔ A positional-only parameter's NAME is invisible to callers, so a rename there is not a
            # change. For everything else the name at this index is what a positional caller binds.
            _brk(f"position {i} was `{p['name']}`, now `{q['name']}`",
                 "position_renamed", index=i, was=p["name"], now=q["name"])

    # 2. every name a caller could pass by keyword must still accept it by keyword.
    for p in old:
        if p["kind"] not in _BY_NAME:
            continue
        q = new_named.get(p["name"])
        if q is None:
            if p["name"] not in new_all:
                if f"positional parameter `{p['name']}` removed" not in breaking:
                    _brk(f"keyword parameter `{p['name']}` removed",
                         "keyword_removed", name=p["name"])
            else:
                _brk(f"`{p['name']}` can no longer be passed by keyword",
                     "no_longer_keyword", name=p["name"])
            continue
        if p["default"] is not None and q["default"] is None:
            _brk(f"`{p['name']}` lost its default, so omitting it now fails",
                 "lost_default", name=p["name"])
        elif p["default"] != q["default"] and not _same_type(p["default"], q["default"]):
            behaviour.append(f"`{p['name']}` default {p['default']} -> {q['default']}")
        if not _same_type(p["annotation"], q["annotation"]):
            notes.append(f"`{p['name']}`: {p['annotation']} -> {q['annotation']}")

    # 3. a variadic a caller may already be feeding must not vanish.
    for kind, label in ((VARIADIC_POSITIONAL, "*args"), (VARIADIC_KEYWORD, "**kwargs")):
        was = next((p for p in old if p["kind"] == kind), None)
        now = next((p for p in new if p["kind"] == kind), None)
        if was is not None and now is None:
            _brk(f"{label} (`{was['name']}`) removed, so extra arguments now fail",
                 "variadic_removed", name=was["name"], variadic=label)

    # 4. anything added. Required is always breaking; optional is safe only where it cannot shift an
    #    existing parameter's position (keyword-only, a variadic, or appended after all of them).
    # ⛔ ONLY PAST THE OLD POSITIONAL SEQUENCE. Every index below `len(old_pos)` was already paired with an
    # old parameter in step 1, which reported any mismatch there; treating the new name at such an index as
    # an ADDITION double-counts it, and for a positional-only parameter — whose name step 1 correctly
    # ignores — it invented a "required parameter added" for a plain rename.
    for i in range(len(old_pos), len(new_pos)):
        q = new_pos[i]
        if q["name"] in old_names:
            continue
        if q["default"] is None:
            _brk(f"required parameter `{q['name']}` added", "required_added", name=q["name"], index=i)
        elif any(p["name"] in old_names for p in new_pos[i + 1:]):
            _brk(f"optional `{q['name']}` inserted at position {i}, shifting the parameters after it",
                 "optional_inserted", name=q["name"], index=i)
        else:
            notes.append(f"appended optional `{q['name']}`")
    for q in new:
        if q["name"] in old_names or q["kind"] in _POSITIONAL:
            continue
        if q["kind"] == KEYWORD_ONLY and q["default"] is None:
            _brk(f"required keyword-only `{q['name']}` added",
                 "required_kwonly_added", name=q["name"])
        else:
            notes.append(f"added {q['kind']} `{q['name']}`")

    if breaking:
        return PARAMS_CHANGED, breaking + behaviour, facts
    if behaviour:
        return DEFAULT_CHANGED, behaviour, []
    return ANNOTATION_ONLY, notes, []


def _detail(reasons: Sequence[str]) -> str:
    """The reasons as one bounded sentence."""
    text = "; ".join(r for r in reasons if r)
    return text if len(text) <= MAX_DETAIL else text[:MAX_DETAIL - 1].rstrip(" ;") + "…"


def classify(frm: Optional[str], to: Optional[str],
             kind: Optional[str] = None, to_kind: Optional[str] = None) -> Dict[str, str]:
    """`{"class": ..., "detail": ...}` for one `signature_changed` entry.

    `kind` / `to_kind` are the API diff's own fields. They are checked FIRST because a class that became an
    attribute has two declarations in different shapes, which no signature comparison can read.
    """
    frm, to = frm or "", to or ""
    # ⛔ ABSENCE IS NOT SAFETY — the rule `card_intersection` is built on, and the one this function broke
    # when it was first written. An entry with no declarations recorded (an older extractor, a hand-built
    # card, a fixture) compared EQUAL as two empty strings and came back `identical`, which silently turned
    # every such signature change into a non-event. A missing declaration is the one case where nothing is
    # known, so it is `opaque` and keeps its hit. Caught by `test_an_imported_owner_reaches_its_member`.
    if not frm or not to:
        return {"class": OPAQUE, "detail": "the API diff records no declaration for one or both sides"}
    if kind and to_kind and kind != to_kind:
        # ⚠️ USUALLY the call still works — `cryptography` 50 replaces `HKDF` the Python class with an
        # attribute bound to the Rust implementation, and `HKDF(...)` is unaffected. But `isinstance`,
        # subclassing and the old base list are all live questions a reviewer has to answer, and 14 of the
        # 93 measured entries are this. So it is reported precisely and still routed to a person.
        return {"class": KIND_CHANGED, "detail": f"{kind} became {to_kind}"}
    if frm == to:
        return {"class": IDENTICAL, "detail": ""}

    fp, tp = parse_function(frm), parse_function(to)
    if fp is not None and tp is not None:
        cls, reasons, facts = _param_delta(fp[0], tp[0])
        if not _same_type(fp[1], tp[1]):
            reasons = list(reasons) + [f"returns {fp[1]} -> {tp[1]}"]
        detail = _detail(reasons)
        if cls == ANNOTATION_ONLY and not detail:
            # ⚠️ AN EMPTY REASON READS AS "NOTHING WAS COMPUTED", which is the one thing this block must
            # never imply. It happens when the whole move was a respelling the canonicaliser absorbed —
            # measured: pyjwt's `jwt.help.info` is `() -> Dict[str, Dict[str, str]]` becoming
            # `() -> dict[str, dict[str, str]]`, no parameters either side — so it is said out loud.
            detail = "declaration respelled; nothing a caller passes or receives changed"
        # ⛔ `breaks` ONLY where there is something to narrow, so a reader can tell "no fact was computed"
        # from "the facts say nothing is breakable". A return-type move carries no fact: it is not something
        # a CALL can avoid, so it is deliberately absent here and keeps its hit.
        # ⛔ `self_bound` TRAVELS WITH THE FACTS, because an index is useless without it. A declaration's
        # index 0 is `self` for a method, so a call's FIRST positional argument binds declaration index 1.
        # Narrowing without that offset would call a breaking call site safe — the one direction that merges
        # a build break. `call_narrowing` requires it and refuses to narrow when it is missing.
        return {"class": cls, "detail": detail,
                **({"breaks": facts, "self_bound": bool(fp[0]) and fp[0][0]["name"] in ("self", "cls")}
                   if facts else {})}
    if fp is not None or tp is not None:
        return {"class": OPAQUE, "detail": "one side is not a readable function declaration"}

    fb, tb = parse_class(frm), parse_class(to)
    if fb is not None and tb is not None:
        if [canon_type(b) for b in fb] == [canon_type(b) for b in tb]:
            return {"class": IDENTICAL, "detail": ""}
        # ⛔ A LOST BASE LOSES ITS MEMBERS. Dropping a base removes every inherited name with it, which no
        # `removed` entry of this card reports — the extractor only diffs what each class declares.
        return {"class": BASES_CHANGED,
                "detail": _detail([f"bases ({', '.join(fb) or 'none'}) -> ({', '.join(tb) or 'none'})"])}

    fa, ta = parse_attribute(frm), parse_attribute(to)
    if fa is not None and ta is not None:
        if not _same_type(fa[1], ta[1]):
            return {"class": VALUE_CHANGED, "detail": _detail([f"value {fa[1]} -> {ta[1]}"])}
        if not _same_type(fa[0], ta[0]):
            return {"class": ANNOTATION_ONLY, "detail": _detail([f"annotation {fa[0]} -> {ta[0]}"])}
        return {"class": IDENTICAL, "detail": ""}

    return {"class": OPAQUE, "detail": "neither side is a readable declaration"}


def breaks_callers(entry: Dict[str, Any]) -> bool:
    """Does this `signature_changed` entry need a person? True for everything but a provable non-change.

    ⛔ FAIL-SAFE BY CONSTRUCTION: anything not in `COMPATIBLE` — including `opaque` — is True.
    """
    return classify(entry.get("from"), entry.get("to"),
                    entry.get("kind"), entry.get("to_kind"))["class"] not in COMPATIBLE
