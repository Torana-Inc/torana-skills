"""Which codemod, if any, fixes ONE class-4 hit (FIX_PR_PHASE5_CODEMOD_SPEC § 3.5.1). Pure: a hit and its symbol in,
a decision out. ⛔ It never widens what a codemod may do: every op here is one Gate B L2 can PROVE."""
from typing import Any, Dict

from . import signature_delta as _sigd
from .call_narrowing import SAFE

SUB_4A, SUB_4B, SUB_4C, NONE = "4a", "4b", "4c", "none"
#: Rules a keyword shift clears: the change moves a declaration index, and a keyword argument has no index.
_SHIFT = {"optional_inserted", "moved", "now_keyword_only"}
#: Rules no mechanical rewrite can clear (the argument for each is in call_narrowing's header): 4c.
_UNFIXABLE = {"required_added", "required_kwonly_added", "keyword_removed", "positional_removed", "no_longer_keyword",
              "lost_default", "variadic_removed", "positional_only_count"}
_SITE_BY = ("import_name", "call", "reference")
#: The kinds a caller may pass by keyword: the library's own tuple (`signature_delta.py:76`, the hyphenated strings
#: `positional-or-keyword` / `keyword-only`), never re-spelled here.
_KEYWORDABLE = set(_sigd._BY_NAME)


def _parent(symbol: str, eco: str) -> str:
    return symbol.rpartition("#")[0] if eco == "npm" else symbol.rpartition(".")[0]


def _leaf(symbol: str, eco: str) -> str:
    return symbol.rpartition("#")[2] if eco == "npm" else symbol.rpartition(".")[2]


def decide(hit: Dict[str, Any], symbol: Dict[str, Any], *, ecosystem: str, method: str) -> Dict[str, Any]:
    none = lambda why: {"sub": NONE, "op": None, "why": why}          # noqa: E731
    c4 = lambda why: {"sub": SUB_4C, "op": "draft", "why": why}      # noqa: E731
    if method != "callgraph":
        return none("word_method")                                   # a name search is not a site list
    if hit.get("by") not in _SITE_BY:
        return none(f"by_{hit.get('by')}")                           # an override is a subclass's def: a person decides
    if hit.get("inherited_fallback"):
        return none("inherited_fallback")                            # the name may still resolve through a base
    change = symbol["change"]
    if change == "renamed":
        to = symbol.get("to")
        if not to:
            return c4("renamed_without_target")
        if _parent(symbol["symbol"], ecosystem) != _parent(to, ecosystem):
            return c4("moved_parent")                                # D5: a move needs a new import; not v1
        return {"sub": SUB_4A, "op": "rename", "why": "", "old": _leaf(symbol["symbol"], ecosystem),
                "new": _leaf(to, ecosystem), "parent": _parent(symbol["symbol"], ecosystem)}
    if change == "removed":
        return c4("removed_no_replacement")
    # signature_changed
    if hit.get("by") == "import_name":
        return none("import_unaffected")                             # M4: an import binds the name; a signature cannot break it
    if hit.get("by") == "reference" and not hit.get("call_parsed"):
        # ⛔ WHY THIS IS CONDITIONAL, AND WHAT IT COST WHEN IT WAS NOT (§ 3.12.12, measured 2026-10-30).
        # The rule is right in its own terms: a bare mention of a function may be a value passed
        # elsewhere and called where the graph cannot see, and rewriting arguments at a non-call is wrong.
        # But MEASURED over all three Python call shapes, the indexer labels every real call site
        # `lib_ref` → `by: "reference"`; `by: "call"` comes only from a `lib_call` or `class_base` record,
        # which ordinary Python calls do not produce. So an unconditional refusal fired on 100% of call
        # sites, and TWO branches the spec treats as live were dead: D4's `call_safe` and D6's entire
        # `4b` / keywordify mechanism. The narrower would open the file, parse the call, prove it `safe`,
        # and this line would then discard that verdict and ask for a model draft.
        # ⭐ `call_parsed` is set by `_narrow_touched` only when `call_shape` actually found and parsed a
        # call expression at this line. It adds NO new trust: that is the same instrument which has to
        # clear the rewrite anyway. A reference with no parsed call keeps the refusal — which is the case
        # the original argument genuinely describes.
        # ⚠️ A SPLAT call (`decode(*args)`) parses, so it arrives here as a call and may be stamped 4b.
        # That is deliberate: the refusal belongs in the transformer, which rejects every `*`/`**` arg
        # (§ 3.5.3 m1), and the site is then reported as refused with the plan in state `partial` —
        # rather than being hidden from the plan a person approves.
        return c4("reference_not_call")
    if ecosystem != "pypi":
        return c4("npm_signature")                                   # D7: no breaks facts for npm
    facts = symbol.get("breaks") or []
    if not facts:
        return c4(f"no_structured_facts:{symbol.get('sig_class')}")  # kind_changed / default_changed / opaque / bases
    if hit.get("call_verdict") == SAFE:
        return none("call_safe")                                     # nothing to change at this call (D4); live since B2
    rules = {f["rule"] for f in facts}
    if rules & _UNFIXABLE or not rules <= (_SHIFT | {"position_renamed"}):
        return c4("unfixable:" + ",".join(sorted(rules & _UNFIXABLE or rules)))
    old = _sigd.parse_function(symbol.get("decl_from"))
    new = _sigd.parse_function(symbol.get("decl_to"))
    if old is None or new is None:
        return c4("declaration_unparsed")
    old_params, new_params = old[0], new[0]
    new_by = {p["name"]: p for p in new_params}
    old_names = {p["name"] for p in old_params}
    renamed: Dict[str, str] = {}
    for f in facts:
        if f["rule"] == "position_renamed":
            # ⛔ MEASURED 2026-10-29: an INSERTION shows up as `position_renamed` at every index after it (pyjwt's
            # `subject` gives `{8: issuer→subject}, {9: leeway→issuer}`), never as `optional_inserted` — step 1 of
            # `_param_delta` pairs indices before step 4 can see the addition. So: the old name still exists in the
            # new declaration → a SHIFT (keyword it under its own name); the old name is gone and the new one is new
            # → a pure rename (keyword it under `now`); anything else is a swap or reorder → 4c.
            if f["was"] in new_by:
                continue
            if f["now"] not in old_names:
                renamed[f["was"]] = f["now"]
            else:
                return c4("position_renamed_impure")
    idx = [i for f in facts for i in (f.get("index"), f.get("was"), f.get("now")) if isinstance(i, int)]
    if not idx:
        return c4("no_index")
    lowest = min(idx)
    old_pos = [p for p in old_params if p["kind"] in _sigd._POSITIONAL]
    names = []
    for p in old_pos[lowest:]:
        if p["kind"] not in _KEYWORDABLE:
            return c4(f"not_keywordable_old:{p['name']}")            # m5: the no-op-under-the-OLD-signature argument needs it
        target = renamed.get(p["name"], p["name"])
        q = new_by.get(target)
        if q is None or q["kind"] not in _KEYWORDABLE:
            return c4(f"not_keywordable:{p['name']}")
        names.append(target)
    sb = symbol.get("self_bound")
    if sb is None:
        return c4("self_bound_unknown")
    return {"sub": SUB_4B, "op": "keywordify" if names else "rename_keyword", "why": "",
            "shift": {"from_index": lowest, "self_bound": bool(sb), "names": names, "renamed": renamed}}
