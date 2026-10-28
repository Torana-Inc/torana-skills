"""Does a SPECIFIC call site actually break under a specific signature change? (phase 5, gate A)

    signature_delta's `breaks` facts  +  the call graph's (file, line)  +  the file's source  ->  safe | breaks | unknown

⛔ WHAT THIS EXISTS TO FIX. `signature_delta` reads DECLARATIONS and says so in its own header: `params_changed`
means "a caller COULD break", never "your caller WILL break". MEASURED 2026-10-27: pyjwt 2.9.0 -> 2.15.0 inserts
`subject` before `issuer`, which breaks a positional caller — and the real call sites in one shared library pass
`algorithms=`, `audience=` and `options=` BY KEYWORD, so not one of them can break. A reviewer told "12 signatures
changed" learns nothing; told "12 changed, 9 of your calls cannot be affected, here are the 3 that can" they are
reading a finding. A codemod needs the same thing one step further: not "might break" but "this call, this argument".

⭐ IT ADDS NO INPUT. `api_diff_check.intersect` already receives the call graph (which names the call sites) and a
file reader (which can fetch their source). The declaration side already parses parameters. This only crosses them.

⛔ THE SAFE DIRECTION IS THE WHOLE DESIGN, and it is asymmetric on purpose. `api_diff_check`'s cost rule: a false
class 3 MERGES A BUILD BREAK, a false class 4 costs a reviewer ten minutes. So `safe` is returned only when EVERY
fact is provably harmless at this call; anything unparsed, unrecognised or starred is `unknown`, which keeps the
hit. A rule is added here only with the argument for why it cannot be wrong.

⚠️ AND IT NARROWS THE EVIDENCE, NOT THE VERDICT. The caller records this beside the hit; moving a row from class 4
to class 3 on the strength of a parsed call expression is a separate decision, with its own measurement, for the
phase-5 spec. Nothing here does it.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence, Set

SAFE, BREAKS, UNKNOWN = "safe", "breaks", "unknown"

#: Rules whose safety depends on HOW MANY positional arguments a call passes: the change touches declaration
#: index `index`, so a call that never reaches that slot cannot be affected by it.
_BY_INDEX = {
    "position_renamed",      # the name at this index changed: a positional caller binds the wrong parameter
    "moved",                 # the parameter is still positional, at a different index
    "now_keyword_only",      # it can no longer be passed positionally
    "optional_inserted",     # an optional was inserted here, shifting everything after it
}

#: ⛔ THE ONE DUAL-AXIS RULE, and getting it wrong returned `safe` for a call that breaks. A REMOVED parameter
#: has no index to reach AND no name to pass: it breaks a positional caller that gets that far *and* a keyword
#: caller that names it. Classifying it as index-only called `decode(tok, verify=False)` safe when `verify` had
#: been deleted — caught by `test_a_removed_keyword_breaks_only_the_calls_that_pass_it`. Every other index rule
#: leaves the parameter reachable by keyword, which is why they are genuinely one-axis.
_BY_BOTH = {"positional_removed"}

#: Rules whose safety depends on WHETHER A KEYWORD IS PASSED by this call.
_BY_KEYWORD = {"keyword_removed", "no_longer_keyword"}

#: ⛔ NEVER NARROWABLE, listed so the omission is a decision and not a gap:
#:   required_added / required_kwonly_added  a new required parameter breaks EVERY existing call, by definition
#:   lost_default                            breaks the calls that OMIT it; "omits" is not visible from one call
#:                                           expression alone (a **kwargs splat may supply it)
#:   variadic_removed                        breaks a call passing extras; a splat makes the count unknowable
#:   positional_only_count                   deliberately coarse (no names exist to tell add from rename)
#: A new REQUIRED parameter breaks every existing call by definition, so a call site cannot clear it.
_ALWAYS_BREAKS = {"required_added", "required_kwonly_added"}
#: Not decidable from one call expression, so they keep the hit.
_NOT_DECIDABLE = {"lost_default", "variadic_removed", "positional_only_count"}


def _short(symbol: str) -> str:
    """The last segment of a dotted symbol — what a call expression actually spells."""
    return str(symbol or "").rsplit(".", 1)[-1]


def call_shape(src: str, line: int, symbol: str) -> Optional[Dict[str, Any]]:
    """`{"positional": n, "keywords": {...}, "starred": bool}` for the call to `symbol` at `line`, or None.

    ⚠️ `line` is 1-based, as the call graph records it. A call spanning several lines is matched when it STARTS
    on that line or when it contains it, because the graph's line is the call's own start and a reader of a
    reformatted file should not silently lose the match.

    Returns None when the file cannot be parsed or no such call is found — never a guess.
    """
    from . import callgraph
    parser = callgraph.python_parser()
    if parser is None:
        return None
    want = _short(symbol)
    if not want:
        return None
    try:
        blob = src.encode("utf-8")
        tree = parser.parse(blob)
    except Exception:                                   # a parser that cannot read it tells us nothing
        return None

    best: Optional[Dict[str, Any]] = None
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or _short(blob[fn.start_byte:fn.end_byte].decode("utf-8", "replace")) != want:
            continue
        starts_here = node.start_point[0] == line - 1
        if not (starts_here or node.start_point[0] <= line - 1 <= node.end_point[0]):
            continue
        shape = _args(blob, node.child_by_field_name("arguments"))
        if starts_here:
            return shape                                # an exact start wins outright
        best = best or shape
    return best


def _args(blob: bytes, args: Any) -> Dict[str, Any]:
    """The call's argument shape. ⛔ A splat sets `starred`, which makes every count a lower bound and so
    forces `unknown` — a `*args` call could be passing anything at any position."""
    positional, keywords, starred = 0, set(), False
    for c in (args.children if args is not None else ()):
        if not c.is_named or c.type == "comment":
            continue
        if c.type == "keyword_argument":
            name = c.child_by_field_name("name")
            if name is not None:
                keywords.add(blob[name.start_byte:name.end_byte].decode("utf-8", "replace"))
            continue
        if c.type in ("list_splat", "dictionary_splat"):
            starred = True
            continue
        positional += 1
    return {"positional": positional, "keywords": keywords, "starred": starred}


def narrow(breaks: Sequence[Dict[str, Any]], self_bound: Optional[bool],
           shape: Optional[Dict[str, Any]]) -> str:
    """`safe` only when EVERY fact is provably harmless at this call. Otherwise `breaks` or `unknown`.

    ⛔ `self_bound` IS REQUIRED FOR AN INDEX RULE. A method's declaration index 0 is `self`, so a call's first
    positional argument binds declaration index 1. Narrowing without that offset would call a breaking site
    safe. `None` means nobody computed it, which is `unknown` — never an assumed 0.
    """
    if not breaks:
        return UNKNOWN                                  # nothing to narrow is not a safety claim
    if shape is None or shape.get("starred"):
        return UNKNOWN
    reached = int(shape["positional"]) + (1 if self_bound else 0)
    keywords: Set[str] = set(shape.get("keywords") or ())
    verdict = SAFE
    for f in breaks:
        rule, name, index = f.get("rule"), f.get("name"), f.get("index")
        if rule in _ALWAYS_BREAKS:
            return BREAKS
        if rule in _NOT_DECIDABLE:
            return UNKNOWN
        if rule in _BY_INDEX or rule in _BY_BOTH:
            if index is None or self_bound is None:
                return UNKNOWN
            lowest = min([i for i in (index, f.get("was"), f.get("now")) if isinstance(i, int)])
            # A call that passes `reached` arguments binds declaration indices 0 .. reached-1.
            if reached > lowest:
                verdict = BREAKS
            if rule in _BY_BOTH:
                if not name:
                    return UNKNOWN
                if name in keywords:
                    verdict = BREAKS
        elif rule in _BY_KEYWORD:
            if not name:
                return UNKNOWN
            if name in keywords:
                verdict = BREAKS
        else:
            return UNKNOWN                              # an unknown rule is never evidence of safety
    return verdict
