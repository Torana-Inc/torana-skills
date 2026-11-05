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
fact is provably harmless at this call; anything unparsed, unrecognised or `*args`-splatted is `unknown`, which
keeps the hit, and a `**kw` splat is `unknown` for any fact on the keyword axis. A rule is added here only with the
argument for why it cannot be wrong.

⭐ THE CALLER NOW ACTS ON `safe` (Bhakta 2026-11-04). `api_diff_check._clear_proven_safe` moves a `safe` hit out of
`touched` into `call_safe`, so a row whose every call is proven safe is no longer class 4. Measured on litellm
1.82.6 -> 1.100.4 (inserted optional parameters, keyword-only callers). `unknown` and `breaks` never move.
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
#: `default_changed` (review of d896b08): a default moved beside a breaking change. A call that omits the argument now
#: gets a different value, and "omits" is not provable from one call expression (a `**kw` splat may supply it).
_NOT_DECIDABLE = {"lost_default", "variadic_removed", "positional_only_count", "default_changed"}


def _short(symbol: str) -> str:
    """The last segment of a dotted symbol — what a call expression actually spells."""
    return str(symbol or "").rsplit(".", 1)[-1]


def call_shape(src: str, line: int, symbol: str) -> Optional[Dict[str, Any]]:
    """`{"positional": n, "keywords": {...}, "starred": bool}` for the call to `symbol` at `line`, or None.

    ⚠️ `line` is 1-based, as the call graph records it. A call spanning several lines is matched when it STARTS
    on that line or when it contains it, because the graph's line is the call's own start and a reader of a
    reformatted file should not silently lose the match.

    Returns None when the file cannot be parsed or no such call is found — never a guess.

    ⛔ AND NONE WHEN THE LINE IS AMBIGUOUS (review of d896b08, 2026-11-04). The call graph keys a hit by (symbol,
    file, line), so two uses on one line become ONE hit, and returning the first parsed call let the other decide:
    `completion('x', 5), completion(model='x')` read safe in one order and breaking in the other; a nested
    `completion(model=completion('x', 5))` and a same-line callback `pool.submit(completion, 'x', 5)` read safe.
    So the line must hold EXACTLY ONE call to the symbol, and the symbol's name must appear on it exactly once (as
    that call's own function): a second call, a nested one, or a bare mention (a callback, a stored reference, a
    keyword spelled like it) makes the shape unknowable, and unknowable is `None`, which is `unknown`.
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

    row = line - 1
    exact: list = []                                    # calls to `want` that START on the line
    spanning: list = []                                 # calls to `want` that only CONTAIN it
    mentions = 0                                        # every identifier spelled `want` on the line
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "identifier" and node.start_point[0] == row \
                and blob[node.start_byte:node.end_byte].decode("utf-8", "replace") == want:
            mentions += 1
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or _short(blob[fn.start_byte:fn.end_byte].decode("utf-8", "replace")) != want:
            continue
        if node.start_point[0] == row:
            exact.append(node)
        elif node.start_point[0] <= row <= node.end_point[0]:
            spanning.append(node)
    if exact:
        # One call, and the name used nowhere else on its line: each call's function contributes exactly one
        # identifier `want` (the last segment of `litellm.completion`, or the bare `completion`).
        if len(exact) != 1 or mentions != 1:
            return None
        return _args(blob, exact[0].child_by_field_name("arguments"))
    if len(spanning) != 1:
        return None
    return _args(blob, spanning[0].child_by_field_name("arguments"))


def _args(blob: bytes, args: Any) -> Dict[str, Any]:
    """The call's argument shape.

    ⭐ THE TWO SPLATS ARE DIFFERENT FACTS (Bhakta 2026-11-04, the litellm 1.82.6 -> 1.100.4 false class 4).
    `*args` (`args_splat`) makes the POSITIONAL count a lower bound: the call could pass anything at any
    position, so no index rule can be cleared. `**kw` (`kwargs_splat`) passes KEYWORDS only, which bind by name
    and can never reach a shifted index, so it leaves the positional count exact; it only makes the KEYWORD set
    a lower bound. `starred` stays for any older reader: true when either splat is present."""
    positional, keywords, args_splat, kwargs_splat = 0, set(), False, False
    for c in (args.children if args is not None else ()):
        if not c.is_named or c.type == "comment":
            continue
        if c.type == "keyword_argument":
            name = c.child_by_field_name("name")
            if name is not None:
                keywords.add(blob[name.start_byte:name.end_byte].decode("utf-8", "replace"))
            continue
        if c.type == "list_splat":
            args_splat = True
            continue
        if c.type == "dictionary_splat":
            kwargs_splat = True
            continue
        positional += 1
    return {"positional": positional, "keywords": keywords, "args_splat": args_splat,
            "kwargs_splat": kwargs_splat, "starred": args_splat or kwargs_splat}


def narrow(breaks: Sequence[Dict[str, Any]], self_bound: Optional[bool],
           shape: Optional[Dict[str, Any]]) -> str:
    """`safe` only when EVERY fact is provably harmless at this call. Otherwise `breaks` or `unknown`.

    ⛔ `self_bound` IS REQUIRED FOR AN INDEX RULE. A method's declaration index 0 is `self`, so a call's first
    positional argument binds declaration index 1. Narrowing without that offset would call a breaking site
    safe. `None` means nobody computed it, which is `unknown` — never an assumed 0.
    """
    if not breaks:
        return UNKNOWN                                  # nothing to narrow is not a safety claim
    if shape is None:
        return UNKNOWN
    # ⛔ `*args` makes the positional count unknowable, so nothing can be proved. A shape from before the two
    # splats were told apart carries only `starred`, and is read the cautious way: as a positional splat.
    args_splat = shape.get("args_splat") if "args_splat" in shape else bool(shape.get("starred"))
    if args_splat:
        return UNKNOWN
    # `**kw` passes keywords only: the positional count stays exact, and only the keyword axis is a lower bound.
    kwargs_splat = bool(shape.get("kwargs_splat"))
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
            # ⭐ `moved` carries `was` / `now` and no `index` (signature_delta step 1), so the lowest of the three
            # integers is the slot a positional caller must not reach. None of them → nothing to judge, `unknown`.
            idxs = [i for i in (index, f.get("was"), f.get("now")) if isinstance(i, int)]
            if not idxs or self_bound is None:
                return UNKNOWN
            lowest = min(idxs)
            # A call that passes `reached` arguments binds declaration indices 0 .. reached-1.
            if reached > lowest:
                verdict = BREAKS
            if rule in _BY_BOTH:
                if not name:
                    return UNKNOWN
                if name in keywords:
                    verdict = BREAKS
                elif kwargs_splat:
                    return UNKNOWN                      # the splat may pass the removed name
        elif rule in _BY_KEYWORD:
            if not name:
                return UNKNOWN
            if name in keywords:
                verdict = BREAKS
            elif kwargs_splat:
                return UNKNOWN                          # the splat may pass the name that changed
        else:
            return UNKNOWN                              # an unknown rule is never evidence of safety
    return verdict
