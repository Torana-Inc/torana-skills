"""Does an upgrade's API diff touch THIS tree's code? Over the call graph (FIX_KNOWLEDGE_CONVERGENCE.md § 3.6.4).

    an API diff (what the package changed)  +  this tree's usage records and call graph  ->  class 3 or class 4

⛔ PURE. No network, no platform, no model, no clock: an API diff, the tree's usage records (`api.usage_records`), its
call-graph document (`index/callgraph.json`, format 4) and an optional file reader in; the `api_diff` block out. The
planner runs it over a checkout (`torana-scan` `api_diff_intersection.py`, a thin caller); the Atlas runs it over a stored
snapshot (the API-diff check read, § 3.6.5).

⭐ WHY THE CALL GRAPH. Measured 2026-10-27 on litellm 1.82.6 -> 1.88.6 x a large internal Python service: the word
match (`word_intersect`, below) gave 80 hits, 61 in src/, all noise (`model`, `message`, `create` …), because
`import litellm` reaches every `litellm.*` name. The call graph resolves imports, aliases and scope and gives 2, both
real (src 0 · tests 1 · scripts 1). The word match survives ONLY for npm (the graph is Python-only) and for a missing
or truncated graph, and the result says which (`method`, `method_why`).

⚠️ AN ANSWER, NOT A PROOF OF ABSENCE. A `callgraph` result always carries `blind_to` (`BLIND_TO`): what this method
cannot see. The helpers from `leaf` to `reached_through`, and `word_intersect`, moved here from
`torana-scan/references/api_diff_intersection.py` unchanged (their measured-evidence comments included); `changed_symbols`
gained one key, `kind`.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence

from .firstparty import normalize

#: The `by` values a reviewer reads; `word` (the parser-missing fallback) is skimmed.
NAMED_BY = ("import_name", "call", "reference", "override", "attribute")
#: What this method cannot see, ALWAYS on a `ready` result (an answer, not a proof of absence).
BLIND_TO = ("returned_object",     # r = litellm.Router(); r.acompletion(): the receiver is an opaque value
            "star_import",         # from litellm import *: binds nothing the graph can name
            "dynamic_name",        # getattr(litellm, name), patch("litellm.x"), importlib
            "wrapper_package",     # reached through another package (google.adk LiteLlm, FastAPI over Starlette)
            "class_body_import")   # an import inside a class body is skipped (callgraph.py, `in_class`)
#: ⛔ THE WORDS ARE WRITTEN HERE, ONCE (lead 2026-10-27): every reader (CLI, FE, PR body, Atlas) prints
#: `blind_to_words` / `method_words` from the result verbatim and never maps the codes itself. A reader's own map is
#: only a fallback for an answer stored before these fields existed. Same order as BLIND_TO.
BLIND_TO_WORDS = {
    "returned_object": "methods on returned objects",
    "star_import": "import *",
    "dynamic_name": "names built at runtime (getattr, patch strings)",
    "wrapper_package": "use through a wrapper package",
    "class_body_import": "imports inside a class body",
}
#: Why the check fell back to the name search (`method_why` -> words).
METHOD_WHY_WORDS = {"parser_missing": "no parser", "npm": "npm: the call graph reads Python only",
                    "truncated": "the call graph was truncated"}
METHOD_CALLGRAPH_WORDS = "checked on the call graph"
#: Past this many hits the list is truncated and says so: a reviewer needs the shape, not every line.
MAX_TOUCHED = 50


def leaf(symbol: str, eco: str) -> str:
    """The name a consumer writes. pypi: after the last `.`; npm: after `#` (the API diff's subpath#name shape).

    ⭐ A DUNDER TAIL IS NOT A NAME. `starlette.responses.Response.__init__` is searched for as `Response`: nobody
    writes `__init__`, it appears in every Python file, and the question a changed constructor asks is "do you use
    Response?". Searching the owning name is both more precise AND the right question."""
    name = symbol.rsplit("#", 1)[-1] if eco == "npm" else symbol.rsplit(".", 1)[-1]
    if name.startswith("__") and name.endswith("__"):
        parts = symbol.replace("#", ".").split(".")
        return parts[-2] if len(parts) > 1 else name
    return name


def reachable(symbol: str, module: str, eco: str) -> bool:
    """Is `symbol` reachable from an import of `module`? (§ 3.4.6: `pkg.mod.Name` from `pkg.mod` or any parent.)

    npm compares the SUBPATH the symbol belongs to against the subpath the import resolves to."""
    if eco == "npm":
        return symbol.split("#", 1)[0] == module
    return symbol == module or symbol.startswith(module + ".")


def npm_subpath(specifier: str, package: str) -> str:
    """`echarts/core` -> `./core`, `echarts` -> `.` (§ 3.4.6)."""
    rest = specifier[len(package):]
    return "." + rest if rest else "."


def word_in(text: str, name: str) -> bool:
    """`name` as a whole word. `$` counts as a word character so `foo$bar` is not a hit for `foo`."""
    return re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", text) is not None


def bound_names(text: str, line: int) -> set:
    """The names an import statement at `line` actually BINDS: `from x import a, b as c` -> {a, b, c}.

    `by` is read off this: `import_name` when the changed symbol is named in the import statement itself,
    `word` when it was only found in the file's text. A reviewer reads the first kind and skims the second, which
    is what keeps a list of 11 hits useful when `app` and `state` are among the names.

    ⛔ A WORD HIT COUNTS ONLY WHERE `binds_module` SAYS IT CAN — see there for why.
    """
    lines = text.splitlines()
    first = lines[line - 1] if 0 < line <= len(lines) else ""
    m = re.search(r"\bimport\b(.*)", first)             # ⛔ this line only: a later line's `(` is not ours
    if not m:
        return set()
    seg = m.group(1)
    if "(" in seg:                                       # a parenthesised list continues until its `)`
        rest = "\n".join(lines[line:line + 20])
        seg = seg.split("(", 1)[1] + "\n" + rest.split(")", 1)[0]
    elif seg.rstrip().endswith("\\"):                     # a backslash continuation
        seg += " " + " ".join(x.strip().rstrip("\\") for x in lines[line:line + 5])
    out = set()
    for part in seg.replace("\\", " ").split(","):
        piece = part.strip()
        if not piece:
            continue
        head, _, alias = piece.partition(" as ")
        out.add(head.strip().split(".")[0])
        if alias.strip():
            out.add(alias.strip())
    return {x for x in out if x.isidentifier()}


def binds_module(text: str, line: int) -> bool:
    """Does the import statement at `line` bind the MODULE (so `module.anything` is reachable), or only the names
    it lists?

    ⛔ THIS IS WHAT MAKES A WORD HIT MEAN ANYTHING. `from starlette.routing import compile_path` binds exactly
    `compile_path`: `Router.route` cannot be reached through that statement under any alias, so the bare word
    `route` elsewhere in the file is not a use of it. `import starlette.routing`, `import x as y` and
    `from x import *` DO bind the module, and then `routing.route` is reachable without ever being named in the
    statement — which is the case the word search exists for.

    MEASURED 2026-10-20: starlette 0.52.1 → 1.9.0 removes `starlette.routing.Router.route`. one shared library's
    `ci_binding.py` imports only `compile_path` but writes the word "route" 14 times in its docstrings, log
    messages and a local variable, and the bare word alone made the whole upgrade class 4 — refusing a correct
    fix on the strength of prose. A false class 4 is the expensive direction: it sends a fixable finding to a
    person and stops the automated lane.

    ⚠️ npm: `bound_names` cannot read a JS import statement (`import {{ init }} from 'echarts/core'` binds
    nothing it recognises), so every npm line is treated as module-binding and npm keeps today's conservative
    word matching. The same false positive is therefore still possible on npm; it is stated, not fixed here."""
    lines = text.splitlines()
    first = lines[line - 1] if 0 < line <= len(lines) else ""
    if "*" in first.split("import", 1)[-1]:              # `from x import *`: every name is reachable
        return True
    return not re.match(r"\s*from\b", first)


def owner_names(symbol: str, eco: str) -> List[str]:
    """Every name the symbol hangs off, nearest first: `starlette.responses.Response.delete_cookie` ->
    ['Response', 'responses', 'starlette'].

    ⛔ A FROM-IMPORT OF AN OWNER REACHES ITS MEMBERS. `from starlette.responses import Response` binds only
    `Response`, and `Response.delete_cookie` is reached through it without `delete_cookie` ever appearing in the
    import statement. MEASURED 2026-10-20: starlette 0.52.1 → 1.9.0 changes
    `starlette.responses.Response.delete_cookie` and `starlette.responses.FileResponse.__init__`, and
    a shared library imports `Response` — a leaf-only test dropped both."""
    parts = symbol.replace("#", ".").split(".")
    return list(reversed(parts[:-1]))


def changed_symbols(api_diff: Dict[str, Any]) -> List[Dict[str, str]]:
    """Every symbol the upgrade moved, with which kind of move it was. `renamed` contributes its OLD name: that is
    what this tree still says."""
    # ⛔ `inherited_fallback` IS NOT `dynamic_fallback`, and must never be bucketed with it. A dynamic fallback is
    # CERTAIN — the module has a `__getattr__`, so the name resolves and the row is an acknowledgement, not a code
    # change. An inherited fallback is UNCERTAIN: the API diff names a base class from another distribution that the
    # extractor does not load, so the name MIGHT still resolve. Treating it as proof would merge a build break,
    # which is the one direction this file refuses (see the cost note at the top). So it stays class 4 and travels
    # as a LEAD on the hit: "check `httpx.Client` first", not "you are fine".
    # `kind` (FIX_KNOWLEDGE_CONVERGENCE § 3.6.4): the diff's own kind (`to_kind` for a renamed row), so `_hits` can
    # tell a module (reached THROUGH by a longer name) from a class (never: a re-based class is not a member change).
    out = [{"symbol": r["symbol"], "change": "removed", "kind": r.get("kind"),
            "dynamic_fallback": bool(r.get("dynamic_fallback")),
            "inherited_fallback": list(r.get("inherited_fallback") or [])}
           for r in api_diff.get("removed") or []]
    out += [{"symbol": r["from"], "change": "renamed", "to": r.get("to"), "kind": r.get("to_kind") or r.get("kind"),
             "dynamic_fallback": bool(r.get("dynamic_fallback")), "inherited_fallback": []}
            for r in api_diff.get("renamed") or []]
    # ⚠️ Only a REMOVAL can be explained by inheritance. A renamed or re-signed member is still declared on the
    # class, so a base class says nothing about it; the API diff does not set the field on those and neither do we.
    out += [{"symbol": r["symbol"] if isinstance(r, dict) else r, "change": "signature_changed",
             "kind": r.get("kind") if isinstance(r, dict) else None,
             "dynamic_fallback": False, "inherited_fallback": []}
            for r in api_diff.get("signature_changed") or []]
    return out


def reached_through(package: str, resolutions: Sequence[Dict[str, Any]],
                    imports: Sequence[Dict[str, Any]]) -> List[str]:
    """The packages that DECLARE `package` and that this tree imports itself.

    ⛔ THE BLIND SPOT THIS NAMES. A removal can be real, called, and invisible: starlette deletes
    `Starlette.middleware`, one service calls it as `@app.middleware("http")`, and that service imports
    starlette ZERO times — `app` is a FastAPI, and FastAPI SUBCLASSES Starlette. An import scan cannot
    follow that, so `intersect` correctly answers `not_imported_directly` and refuses to call it safe.
    What it could not do until now is say WHERE to look.

    ⭐ Both halves are already in hand, so this needs no extraction and no network. A lock records its own
    edges (pip-compile's `# via`, npm's `requires`), stored parent → children; inverting them gives every
    package that declares this one. ⚠️ Any lock in scope that records the edge states the same fact, because
    "fastapi declares starlette" is a property of fastapi and not of our build — so this stays usable even
    on a lock that no image actually installs, at the cost of possibly naming a declarer that is not
    deployed. A
    wrong name in a LEAD costs a reader one lookup, which is the right side of that trade. Intersecting THAT with the packages this tree actually imports leaves
    the intermediaries a call could plausibly arrive through — for starlette in the shared base lock, five
    packages declare it and `fastapi` is the one this tree imports.

    ⛔ IT IS A LEAD, NEVER A VERDICT, and the asymmetry is why. To answer the question you need the
    intermediary's OWN surface (does FastAPI define `middleware` itself? it does, delegating to
    `add_middleware`, which survives) and that is an extraction this function does not do. Guessing from
    the chain alone would mean downgrading a class 4 on a coarse name match — and a false class 3 merges a
    build break while a false class 4 costs a reviewer ten minutes. So the verdict never moves here.
    """
    want = normalize(package)
    declarers = {normalize(r.get("package") or "") for r in resolutions
                 if any(normalize(x) == want for x in (r.get("requires") or []))}
    declarers.discard(want)
    imported = {normalize(r.get("package") or "") for r in imports}
    return sorted(declarers & imported)


def word_intersect(doc: Dict[str, Any], imports: Sequence[Dict[str, Any]],
                   read: Callable[[str], Optional[str]],
              *, package: str, ecosystem: str, through: Sequence[str] = ()) -> Dict[str, Any]:
    """The WORD path (today's `api_diff_intersection.intersect`, unchanged): only for npm, or when the call graph is
    missing or truncated (§ 3.6.4). The `api_diff` block for one plan row, and the class it implies. `read(file)` returns the file's text, or
    None when it could not be read or is over the cap."""
    api_diff = doc.get("api_diff") or {}
    out: Dict[str, Any] = {
        "state": "ready",
        "diff_ref": {**(doc.get("key") or {}), "extractor_version": (doc.get("extractor") or {}).get("version")},
        "removed": len(api_diff.get("removed") or []), "renamed": len(api_diff.get("renamed") or []),
        "signature_changed": len(api_diff.get("signature_changed") or []),
        "complete": bool(api_diff.get("complete")), "touched": [], "touched_truncated": False,
        "deprecated": [], "uncovered_imports": [], "oversized_files": [],
    }

    # ⛔ FIRST, BEFORE ANY INTERSECTION. An incomplete API diff's empty `removed` list proves nothing, so no amount of
    # "nothing touched" earns a class-3 verdict from it.
    if not api_diff.get("complete"):
        reasons = api_diff.get("incomplete_reasons") or []
        return {**out, "state": "unavailable", "verdict": "3",
                "reason": "incomplete: " + (reasons[0] if reasons else "no reason recorded")}

    mine = [r for r in imports if normalize(r.get("package") or "") == normalize(package)]
    # ⛔ NEVER IMPORTED HERE MEANS THE QUESTION WAS NOT ANSWERED, NOT THAT THE ANSWER IS "SAFE". A transitive
    # package's API is reached through whatever declared it, and an import scan cannot follow that. MEASURED
    # 2026-10-20: starlette 0.46.2 -> 1.9.0 REMOVES `Starlette.middleware`, one service calls it at
    # src/main.py:312 as `@app.middleware("http")`, and that service imports starlette ZERO times — `app` is a
    # FastAPI, and FastAPI SUBCLASSES Starlette. An inherited symbol is invisible to this method, as is one
    # re-exported by a wrapper. Returning `ready` with nothing touched would state an absence as a fact.
    # ⚠️ The verdict stays 3 rather than 4 on purpose: most packages in a lock are transitive, so answering 4
    # here would route almost every upgrade to a person and end the automated lane. This is the same trade the
    # design already makes for an incomplete API diff — stay in the lane, say loudly that the API question went
    # unanswered — and gates 4 and 5 (build, tests) are what actually cover it.
    if not mine:
        # ⭐ `reached_through` turns "I cannot tell" into "look here" without claiming anything. See its
        # docstring for why it must not move the verdict.
        lead = (f" This tree does reach it through {', '.join(through)}, which it imports — check whether "
                f"{'one of those' if len(through) > 1 else through[0]} defines the changed name itself."
                if through else "")
        return {**out, "state": "unavailable", "verdict": "3", "reason": "not_imported_directly",
                **({"reached_through": list(through)} if through else {}),
                "why": f"`{package}` is never imported in this tree, so its changed symbols cannot be placed. "
                       f"A transitive package is reached through whatever declares it (inheritance, a re-export), "
                       f"which an import scan does not follow.{lead}"}
    if ecosystem == "npm":
        entries = set(api_diff.get("entries") or [])
        for r in mine:
            sub = npm_subpath(r.get("module") or "", package)
            if sub not in entries:
                out["uncovered_imports"].append({"subpath": sub, "file": r["file"], "line": r["line"]})

    if through:
        out["reached_through"] = list(through)
    symbols = changed_symbols(api_diff)
    for rec in mine:
        # ⛔ npm compares SUBPATHS, not specifiers: a API diff's symbol is `./core#init` while the import record's
        # module is `echarts/core`. Comparing them raw matched nothing, so every covered npm subpath came back
        # class 3 (found by the test below, 2026-10-20).
        module = (npm_subpath(rec.get("module") or "", package) if ecosystem == "npm"
                  else (rec.get("module") or ""))
        text = read(rec["file"])
        if text is None:
            out["oversized_files"].append(rec["file"])
        names = bound_names(text, rec["line"]) if text is not None else set()
        module_bound = binds_module(text, rec["line"]) if text is not None else True
        for s in symbols:
            if not reachable(s["symbol"], module, ecosystem):
                continue
            name = leaf(s["symbol"], ecosystem)
            if text is None:
                by = "word"                              # unreadable or oversized: a hit for every symbol it
            elif name in names:                          # imports, conservative by design and said in the result
                by = "import_name"
            elif not word_in(text, name):
                continue                                 # the changed name appears nowhere in the file
            elif any(o in names for o in owner_names(s["symbol"], ecosystem)):
                by = "attribute"                         # an owner this statement binds, member used by name
            elif module_bound:
                by = "word"
            else:
                continue                                 # named nowhere this statement can reach: not a use
            hit = {"symbol": s["symbol"], "change": s["change"], "file": rec["file"], "line": rec["line"],
                   "by": by}
            if s.get("inherited_fallback"):
                hit["inherited_fallback"] = list(s["inherited_fallback"])
            bucket = "deprecated" if s["dynamic_fallback"] else "touched"
            if hit not in out[bucket]:
                out[bucket].append(hit)

    if len(out["touched"]) > MAX_TOUCHED:
        out["touched"], out["touched_truncated"] = out["touched"][:MAX_TOUCHED], True

    # ⚠️ A `dynamic_fallback` symbol is served at runtime by a module-level `__getattr__` (a deprecation shim), so
    # the code still works and this is an acknowledgement, not a code change (§ 3.4.7).
    if out["touched"]:
        return {**out, "verdict": "4"}
    if out["uncovered_imports"]:
        return {**out, "state": "unavailable", "verdict": "3", "reason": "uncovered_subpath"}
    return {**out, "verdict": "3"}


# ── the call-graph path (§ 3.6.4) ───────────────────────────────────────────────────────────────────────────────

def word_method_words(why: str) -> str:
    """`method_words` for the name-search fallback: "checked by name search (no parser), which over-reports"."""
    w = METHOD_WHY_WORDS.get(why, why.replace("_", " "))
    return f"checked by name search ({w}), which over-reports" if w else "checked by name search, which over-reports"


def _q(rec: Dict[str, Any]) -> str:
    return rec["module"] + ("." + rec["attr"] if rec.get("attr") else "")


def _canon(q: str, aliases: Dict[str, str]) -> str:
    """`q` with its longest public-alias prefix replaced by the canonical path (§ 3.6.4.3): `litellm.CustomLogger.x`
    -> `litellm.integrations.custom_logger.CustomLogger.x`. Unchanged when no prefix is an alias."""
    parts = q.split(".")
    for i in range(len(parts), 0, -1):
        head = ".".join(parts[:i])
        if head in aliases:
            return ".".join([aliases[head]] + parts[i:])
    return q


def _hits(q: str, symbols: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The API diff symbols a qualified use `q` reaches: the symbol itself, its constructor, or - ONLY for a module
    symbol - anything through it (`q` = litellm.a2a_protocol.providers.litellm_completion.handler.x reaches the
    RENAMED module). ⛔ Never a prefix match on a class: the API diff lists a class as `signature_changed` when only its
    BASES change (API-diff `pypi.py:120-121`, signature `class(bases)`), and the litellm 1.82.6->1.88.6 API diff has two
    such classes (`litellm.integrations.opentelemetry.OpenTelemetry`, `…interactions.http_handler.InteractionsHTTPHandler`);
    a prefix match would turn every member use of them into a false class 4. For the same reason a re-based class
    (`kind == "class"`, `change == "signature_changed"`) is not matched here at all: a constructor change is listed
    separately as `<Class>.__init__`. A re-based class is a hit only through `class_base` (a subclass), below."""
    return [s for name, s in symbols.items()
            if not (s.get("kind") == "class" and s["change"] == "signature_changed")
            and (q == name or name == q + ".__init__" or (s.get("kind") == "module" and q.startswith(name + ".")))]


def _head(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The block's fixed keys (today's `intersect` :231-238), shared by both paths."""
    api_diff = doc.get("api_diff") or {}
    return {
        "state": "ready",
        "diff_ref": {**(doc.get("key") or {}), "extractor_version": (doc.get("extractor") or {}).get("version")},
        "removed": len(api_diff.get("removed") or []), "renamed": len(api_diff.get("renamed") or []),
        "signature_changed": len(api_diff.get("signature_changed") or []),
        "complete": bool(api_diff.get("complete")), "touched": [], "touched_truncated": False,
        "deprecated": [], "uncovered_imports": [], "oversized_files": [],
    }


def _gates(doc: Dict[str, Any], imports: Sequence[Dict[str, Any]], out: Dict[str, Any], *, package: str,
           ecosystem: str, through: Sequence[str] = ()) -> Optional[Dict[str, Any]]:
    """Today's gates (`intersect` :240-277), in the same order, for the call-graph path: the early result, or None
    (and `out` carries `uncovered_imports` / `reached_through`). See `word_intersect` for why each one exists:
    an incomplete API diff proves nothing; a package never imported here was not answered; an npm subpath the API diff does
    not cover is unavailable."""
    api_diff = doc.get("api_diff") or {}
    if not api_diff.get("complete"):
        reasons = api_diff.get("incomplete_reasons") or []
        return {**out, "state": "unavailable", "verdict": "3",
                "reason": "incomplete: " + (reasons[0] if reasons else "no reason recorded")}
    mine = [r for r in imports if normalize(r.get("package") or "") == normalize(package)]
    if not mine:
        lead = (f" This tree does reach it through {', '.join(through)}, which it imports — check whether "
                f"{'one of those' if len(through) > 1 else through[0]} defines the changed name itself."
                if through else "")
        return {**out, "state": "unavailable", "verdict": "3", "reason": "not_imported_directly",
                **({"reached_through": list(through)} if through else {}),
                "why": f"`{package}` is never imported in this tree, so its changed symbols cannot be placed. "
                       f"A transitive package is reached through whatever declares it (inheritance, a re-export), "
                       f"which an import scan does not follow.{lead}"}
    if ecosystem == "npm":
        entries = set(api_diff.get("entries") or [])
        for r in mine:
            sub = npm_subpath(r.get("module") or "", package)
            if sub not in entries:
                out["uncovered_imports"].append({"subpath": sub, "file": r["file"], "line": r["line"]})
    if through:
        out["reached_through"] = list(through)
    return None


def intersect(doc: Dict[str, Any], usage: Sequence[Dict[str, Any]], callgraph: Optional[Dict[str, Any]],
              read: Optional[Callable[[str], Optional[str]]] = None, *, package: str, ecosystem: str,
              through: Sequence[str] = ()) -> Dict[str, Any]:
    """The `api_diff` block for one plan row over the CALL GRAPH, and the class it implies (§ 3.6.4). An API diff can only
    RAISE the class: the caller moves a row only on verdict 4."""
    out = _head(doc)
    early = _gates(doc, usage, out, package=package, ecosystem=ecosystem, through=through)
    if early is not None:                               # incomplete API diff, not_imported_directly: unchanged
        return early
    parsed = (callgraph is not None and not callgraph.get("truncated")
              and (callgraph.get("languages") or {}).get("python") == "parsed")
    if ecosystem != "pypi" or not parsed:
        # ⛔ the word match survives ONLY here: npm (the graph is Python-only) or no usable graph
        res = word_intersect(doc, usage, read, package=package, ecosystem=ecosystem, through=through)
        res["method"] = "word"
        res["method_why"] = "npm" if ecosystem != "pypi" else (
            "truncated" if callgraph and callgraph.get("truncated") else "parser_missing")
        res["method_words"] = word_method_words(res["method_why"])
        return res
    # ⛔ OLD-FORMAT GRAPHS (§ 3.6.4, lead 2026-10-27). Below format 4 a from-bind's `lib_call.attr` is "" and there
    # is no `from_import`, so exactly the from-import uses go missing. MEASURED: the full litellm API diff on Atlas's
    # stored PAB snapshot 6 (format 3) gave 0 touched; the truth is 2. Unavailable, never the word path: the word
    # match is the false class 4 this module exists to remove, and `unavailable` is the honest answer.
    fmt = callgraph.get("index_format") or 1
    if fmt < 4:
        return {**out, "state": "unavailable", "verdict": "3", "reason": f"index_format_{fmt}"}
    symbols = {s["symbol"]: s for s in changed_symbols(doc.get("api_diff") or {})}
    aliases = (doc.get("api_diff") or {}).get("aliases") or {}      # § 3.6.4.3; {} on an API diff older than extractor 4
    files = callgraph.get("files") or []
    defs = {r["id"]: r for r in callgraph["records"] if r.get("kind") == "def"}
    fail = {p["file"] for p in callgraph.get("parse_failures") or () if p.get("reason") != "syntax_error"}
    seen: set = set()

    def add(sym, file, line, by):
        key = (sym["symbol"], file, line)
        if key in seen:                                 # e.g. a base class is both a lib_ref and a class_base
            return
        seen.add(key)
        hit = {"symbol": sym["symbol"], "change": sym["change"], "file": file, "line": line, "by": by}
        if sym.get("inherited_fallback"):
            hit["inherited_fallback"] = list(sym["inherited_fallback"])
        bucket = "deprecated" if sym["dynamic_fallback"] else "touched"
        out[bucket].append(hit)

    for r in callgraph["records"]:
        k = r.get("kind")
        if k == "module_import":                        # importing a removed/renamed module or name breaks at import
            # ⛔ A bound name is a member of the module ONLY for `from m import n` (`from_import`, § 3.6.3), and the
            # member is the REAL name (`name`), never the local alias (`as`, = `binds[i]`). `import m as n` binds the
            # module itself: appending `n` would invent `m.n`. A record stored before INDEX_FORMAT 4 has no
            # `from_import`; it is read as the module alone (no member), never guessed.
            names = [e["name"] for e in (r.get("from_import") or [])]
            for q in ([_canon(r["module"] + "." + n, aliases) for n in names] or [_canon(r["module"], aliases)]):
                for s in _hits(q, symbols):
                    add(s, files[r["f"]], r["line"], "import_name")
        elif k == "lib_call":
            for s in _hits(_canon(_q(r), aliases), symbols):
                add(s, r["from"].split("::")[0], r["line"], "call")
        elif k == "lib_ref":
            for s in _hits(_canon(_q(r), aliases), symbols):
                add(s, r["from"].split("::")[0], r["line"], "reference")
        elif k == "class_base":
            base = _canon(_q(r), aliases)                # `from litellm import CustomLogger` -> the canonical class
            for s in _hits(base, symbols):              # the base class itself removed / renamed
                add(s, r["class"].split("::")[0], r["line"], "call")
            rebased = symbols.get(base)                 # bases changed: a subclass's MRO changes (the one place it counts)
            if rebased is not None and rebased.get("kind") == "class" and rebased["change"] == "signature_changed":
                add(rebased, r["class"].split("::")[0], r["line"], "override")
            prefix = r["class"] + "."
            for d in defs.values():                     # an override of a changed member
                if d["id"].startswith(prefix) and d["id"].count(".") == r["class"].count(".") + 1:
                    s = symbols.get(base + "." + d["name"])
                    if s is not None:
                        add(s, files[d["f"]], d["line"], "override")
    if fail:
        out["unparsed_files"] = sorted(fail)            # no answer for these files; stated, never silent
    out["method"] = "callgraph"
    out["method_words"] = METHOD_CALLGRAPH_WORDS
    out["blind_to"] = list(BLIND_TO)
    out["blind_to_words"] = [BLIND_TO_WORDS[c] for c in BLIND_TO]
    out["touched"].sort(key=lambda h: (h["file"], h["line"], h["symbol"]))
    if len(out["touched"]) > MAX_TOUCHED:
        out["touched"], out["touched_truncated"] = out["touched"][:MAX_TOUCHED], True
    return {**out, "verdict": "4" if out["touched"] else "3"}
