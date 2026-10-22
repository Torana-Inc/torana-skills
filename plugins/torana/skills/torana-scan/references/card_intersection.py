#!/usr/bin/env python3
"""Does an upgrade's API diff touch THIS tree's code? (FIX_PR phase 3 § 3.4.6 step 3.)

    an upgrade card (what the package changed)  +  this tree's imports  ->  class 3 or class 4

A card says what version N+1 removed, renamed or re-signed. It is keyed on `(ecosystem, package, from, to)` and
nothing else, so it is the same for every customer. This script answers the half that is about one tree: of those
changed symbols, which ones does THIS code use? Empty intersection -> class 3, a lock or manifest edit a reviewer
merges on green. Non-empty -> class 4, which needs a person (and, later, a codemod).

⛔ PURE. No network, no platform, no model: a card in, usage records in, a verdict out. The card is built by
the `torana-upgrade-card` tool from two unpacked artifacts; the usage records come from the
vendored `torana_reachability` (`api.usage_records`). Neither is computed here.

⭐ OVER-MATCHING IS THE SAFE DIRECTION, and it is a deliberate choice, not a shortcut. There is no call graph here,
so every import span counts; a symbol's leaf name is matched as a WHOLE WORD in the text of any file that imports
its module, not resolved. So a name that merely appears in a comment makes the package class 4 and puts a human on
it. The costs are not symmetric: a false class 4 costs a reviewer ten minutes, a false class 3 merges a build
break. The one blind spot left is a name built at runtime (`getattr(mod, name)`), and § 3.6.4 says it goes on the
plan rather than being quietly absent.

⛔ WHAT THIS METHOD CANNOT SEE, each stated in the result rather than quietly absent: a symbol reached through
INHERITANCE or a wrapper's re-export (measured: starlette's removed `Starlette.middleware` is called in
one service as `@app.middleware("http")`, where `app` is a FastAPI — and that service imports starlette zero
times); a name built at runtime (`getattr(mod, name)`); a package this tree never imports at all, which is
`not_imported_directly` and NOT a clean bill of health.

⚠️ ABSENCE IS NOT SAFETY. `api_diff.complete == false` means the extractor could not read the package (a namespace
package, a C extension with no stub, a missing `.d.ts`), so an EMPTY `removed` list is not evidence of anything.
That case returns `state: "unavailable"` with the reason, never `ready` with nothing touched. Same for an npm
import that only an `uncovered_patterns` entry reaches: the card says nothing about that subpath, so neither do we.

Usage:
    python3 card_intersection.py --repo PATH --card card.json --package starlette [--ecosystem pypi] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "lib"))

from torana_reachability import manifests                          # noqa: E402
from torana_reachability import api as rapi                        # noqa: E402
from torana_reachability.firstparty import normalize               # noqa: E402
from torana_reachability.index import build_imports                # noqa: E402

#: Past this many hits the list is truncated and says so: a reviewer needs the shape, not every line.
#: A hit whose `by` is one of these was found through a name the import statement itself binds: precise, and
#: read rather than skimmed. `word` is the weaker kind, and only `binds_module` lines can produce it.
NAMED_BY = ("import_name", "attribute")
MAX_TOUCHED = 50
#: A file bigger than this is not word-searched. It counts as a hit for every symbol it imports — conservative,
#: and stated in the result rather than silently skipped.
MAX_FILE_BYTES = 2 * 1024 * 1024


def leaf(symbol: str, eco: str) -> str:
    """The name a consumer writes. pypi: after the last `.`; npm: after `#` (the card's subpath#name shape).

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
    out = [{"symbol": r["symbol"], "change": "removed", "dynamic_fallback": bool(r.get("dynamic_fallback"))}
           for r in api_diff.get("removed") or []]
    out += [{"symbol": r["from"], "change": "renamed", "to": r.get("to"),
             "dynamic_fallback": bool(r.get("dynamic_fallback"))} for r in api_diff.get("renamed") or []]
    out += [{"symbol": r["symbol"] if isinstance(r, dict) else r, "change": "signature_changed",
             "dynamic_fallback": False} for r in api_diff.get("signature_changed") or []]
    return out


def intersect(card: Dict[str, Any], imports: Sequence[Dict[str, Any]], read: Callable[[str], Optional[str]],
              *, package: str, ecosystem: str) -> Dict[str, Any]:
    """The `api_diff` block for one plan row, and the class it implies. `read(file)` returns the file's text, or
    None when it could not be read or is over the cap."""
    api_diff = card.get("api_diff") or {}
    out: Dict[str, Any] = {
        "state": "ready",
        "card_ref": {**(card.get("key") or {}), "extractor_version": (card.get("extractor") or {}).get("version")},
        "removed": len(api_diff.get("removed") or []), "renamed": len(api_diff.get("renamed") or []),
        "signature_changed": len(api_diff.get("signature_changed") or []),
        "complete": bool(api_diff.get("complete")), "touched": [], "touched_truncated": False,
        "deprecated": [], "uncovered_imports": [], "oversized_files": [],
    }

    # ⛔ FIRST, BEFORE ANY INTERSECTION. An incomplete card's empty `removed` list proves nothing, so no amount of
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
    # design already makes for an incomplete card — stay in the lane, say loudly that the API question went
    # unanswered — and gates 4 and 5 (build, tests) are what actually cover it.
    if not mine:
        return {**out, "state": "unavailable", "verdict": "3", "reason": "not_imported_directly",
                "why": f"`{package}` is never imported in this tree, so its changed symbols cannot be placed. "
                       f"A transitive package is reached through whatever declares it (inheritance, a re-export), "
                       f"which an import scan does not follow."}
    if ecosystem == "npm":
        entries = set(api_diff.get("entries") or [])
        for r in mine:
            sub = npm_subpath(r.get("module") or "", package)
            if sub not in entries:
                out["uncovered_imports"].append({"subpath": sub, "file": r["file"], "line": r["line"]})

    symbols = changed_symbols(api_diff)
    for rec in mine:
        # ⛔ npm compares SUBPATHS, not specifiers: a card's symbol is `./core#init` while the import record's
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


def usage_for(root: str, repository: str = "local", commit: str = "unknown") -> List[Dict[str, Any]]:
    """This tree's import records. The primary tree only: a `--with` tree's code is searched by its own run."""
    doc = build_imports(root, commit=commit, repository=repository)
    records = manifests.read_manifests(root)
    return rapi.usage_records(doc, root, declared={e: manifests.packages_declared(records, e)
                                                   for e in ("pypi", "npm")})


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
    ap.add_argument("--card", required=True, help="a card JSON (torana.upgrade_card.v1)")
    ap.add_argument("--package", required=True)
    ap.add_argument("--ecosystem", default="pypi", choices=("pypi", "npm"))
    ap.add_argument("--json", dest="as_json", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.repo)
    with open(a.card, encoding="utf-8") as fh:
        card = json.load(fh)
    res = intersect(card, usage_for(root), reader(root), package=a.package, ecosystem=a.ecosystem)
    if a.as_json:
        print(json.dumps(res, indent=2))
        return 0
    print(f"class {res['verdict']}  state={res['state']}" + (f"  ({res['reason']})" if res.get("reason") else ""))
    print(f"  card: removed={res['removed']} renamed={res['renamed']} "
          f"signature_changed={res['signature_changed']} complete={res['complete']}")
    named = [h for h in res["touched"] if h.get("by") in NAMED_BY]
    for h in named + [h for h in res["touched"] if h.get("by") not in NAMED_BY]:
        mark = "TOUCHED  " if h.get("by") in NAMED_BY else "also     "
        print(f"  {mark}{h['symbol']}  ({h['change']})  {h['file']}:{h['line']}"
              + (f"   [via the imported `{h['by']}`]" if h.get("by") == "attribute" else "")
              + ("" if h.get("by") in NAMED_BY else "   [name appears in the file, not in the import]"))
    for h in res["deprecated"]:
        print(f"  deprecated {h['symbol']}  ({h['change']})  {h['file']}:{h['line']} — served by a runtime shim")
    for u in res["uncovered_imports"]:
        print(f"  uncovered subpath {u['subpath']}  {u['file']}:{u['line']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
