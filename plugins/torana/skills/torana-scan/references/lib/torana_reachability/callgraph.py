"""The Python call graph: the in-memory graph the pass builds today, and the stored `index/callgraph.json`.

`build_callgraph`, `_resolve_callee`, `_path_to`, `_def_site`, `python_parser` and the parser-remedy helpers are moved
from `reachability_pass.py:506-726` (4222f48) with their behaviour unchanged, except that files come from
`paths.walk_files` (a symlinked file is skipped). `build_callgraph_index` writes the v1 document of
REACHABILITY_EXTRACTOR.md § 3.3.2.2 (qualified names, decorators, four entry kinds, module-scope calls, module imports),
and `graph_from_index` reads it back into the shape `code_verdict` takes, recomputing `reach` (never stored, so the
stored graph cannot disagree with the code that reads it).

⚠️ TWO FRONT ENDS, ONE DOCUMENT, AND EACH SAYS WHAT IT COVERS rather than silently covering less than it claims.
Python is here; JavaScript / TypeScript is `js_front.py`, whose records live in the document's `npm` block
(1.15.0). tree-sitter is OPTIONAL: without it a language is `parser_missing` and every code question about it is
`inconclusive` with that as the reason.

⛔ THE TWO LANGUAGES ARE NOT ADMITTED ON THE SAME TERMS. Python's entry grammar is closed-form (route / cli / task
decorators, the `__main__` guard), so `languages.python == "parsed"` is enough to answer reachability.
JavaScript's is not, so `graph_from_index` admits the npm block only when `npm.entry_coverage.complete` says this
tree's entry-defining dependencies are all enumerated — see `js_front.entry_coverage` for what a partial entry set
would otherwise claim. The API-diff records need no entries and are read either way.
"""
from __future__ import annotations

import builtins
import collections
import glob
import hashlib
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Tuple

from . import ENGINE, INDEX_FORMAT, firstparty
from .js_front import js_block
from .grammar import distribution_of, normalize
from .paths import is_runtime, walk_files

SCHEMA_CALLGRAPH = "atlas/index/callgraph.v1"

#: The `--engines` name that installs the call graph's parser. ⚠️ Must match the entry in
#: `scan_pack.json` -> libraries[].name, or every message here points at a flag that does
#: nothing. The package half of the queue needs none of this.
_TREE_SITTER_ENGINE = "tree-sitter"

#: Where `install_engines.sh` puts the parser — the scan pack's ISOLATED venv, which is NOT
#: the interpreter running this script. Same override the installer honours.
_SCAN_PACK = os.environ.get("TORANA_SCAN_PACK_DIR") or os.path.join(
    os.path.expanduser("~"), ".torana", "scan-pack")

_ROUTE_DECOS = ("get", "post", "put", "patch", "delete", "websocket", "route", "api_route",
                "middleware", "on_event")

#: v1 entry kinds beyond a route (§ 3.3.2.2): a CLI command or group, a task queue task.
_CLI_DECO = re.compile(r"^@\s*[\w.]*?\b(?:command|group)\b")
_TASK_DECO = re.compile(r"^@\s*(?:[\w.]*\.)?(?:task|shared_task)\b")
_MAIN_GUARD = re.compile(r"""__name__\s*==\s*['"]__main__['"]|['"]__main__['"]\s*==\s*__name__""")

#: The separator in a call-graph node id, `rel/path.py::function`.
QSEP = "::"

#: A decorator line kept in a `def` record is cut at this many characters.
DECORATOR_MAX = 200


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _scan_pack_site_packages() -> Optional[str]:
    """The scan pack's site-packages for THIS interpreter, or None.

    ⛔ MATCHED ON THE MINOR VERSION, deliberately. tree-sitter ships a C extension, so a
    directory built for 3.12 imported under 3.11 raises an ABI error that reads exactly like
    a missing package — and "the installer ran, the import still fails" is a failure shape
    this platform already pays for elsewhere (a current `deps/` is not a live change).
    """
    sp = os.path.join(_SCAN_PACK, "venv", "lib",
                      f"python{sys.version_info[0]}.{sys.version_info[1]}", "site-packages")
    return sp if os.path.isdir(sp) else None


def _other_pack_pythons() -> Optional[str]:
    """Which python the scan pack's venv WAS built for, when it was not built for ours.

    ⛔ MEASURED, 2026-10-13: `install_engines.sh` created the venv with the ambient
    `python3` (3.12) and the pass was then run under a 3.13 interpreter. The install
    succeeded, the import found nothing, and "install the engines" was the wrong advice —
    it was already installed, for another interpreter. An install cannot fix this; only
    running the pass under the matching python can, so the message has to say which.
    """
    mine = f"python{sys.version_info[0]}.{sys.version_info[1]}"
    others = sorted({os.path.basename(d) for d in
                     glob.glob(os.path.join(_SCAN_PACK, "venv", "lib", "python3.*"))
                     if os.path.basename(d) != mine})
    return ", ".join(others) or None


def parser_remedy() -> str:
    """What to DO about a missing parser — the cause decides, and there are two."""
    other = _other_pack_pythons() if _scan_pack_site_packages() is None else None
    if other:
        return (f"the scan pack's venv is {other} but this pass is running under "
                f"python{sys.version_info[0]}.{sys.version_info[1]}; run it with "
                f"{os.path.join(_SCAN_PACK, 'venv', 'bin', 'python')}, or re-run "
                f"install_engines.sh under this interpreter")
    return f"install_engines.sh --engines {_TREE_SITTER_ENGINE} provides it"


def python_parser():
    """A tree-sitter parser for Python, or None. Tried in cost order.

    ⭐ `tree_sitter` + `tree_sitter_python` FIRST: two small wheels for the one grammar this
    pass asks for. `tree_sitter_language_pack` is only the fallback — it carries grammars for
    dozens of languages this pass never parses, which is fine on a runner that already has it
    and wrong to make a customer's CI download on every run.
    """
    sp = _scan_pack_site_packages()
    if sp and sp not in sys.path:
        sys.path.append(sp)       # APPEND: never shadow a package the runner already has
    try:
        import tree_sitter_python
        from tree_sitter import Language, Parser
        return Parser(Language(tree_sitter_python.language()))
    except Exception:             # noqa: BLE001 — any failure here means "not available"
        pass
    try:
        from tree_sitter_language_pack import get_parser
        return get_parser("python")
    except Exception:             # noqa: BLE001
        return None


def _resolve_callee(name: str, caller_file: str,
                    by_name: Dict[str, Any]) -> Tuple[Tuple[str, ...], bool]:
    """Every definition a call to bare `name` from `caller_file` can mean, and whether that
    resolution is CERTAIN.

    ⛔ IT DOES NOT CUT AMBIGUITY, AND THAT IS DELIBERATE. Our two errors are not symmetric:

      over-approximate (follow a call that is not really made) -> a false `reachable`, which
        records and moves nothing. Harmless.
      under-approximate (drop a call that IS made) -> a false `no_path_from_entry_point`,
        which lowers a live finding. The one error this pass must never make.

    And our callee token is the bare name after the last dot (`obj.save()` and `save()` are
    indistinguishable), so cutting candidates would drop real edges. So ambiguity is FOLLOWED,
    and reported instead: `certain` is False, the BFS records it on the hop, and a verdict
    whose path crosses an uncertain hop says so. Precision we cannot have, we disclose.

    ⛔ NOT EVEN A SAME-FILE PREFERENCE. This function shipped with one, and on demo 2026-10-14
    (an API gateway repository) `api/routes/health.py::health_check` calls `proxy_service.health_check()`;
    the preference dropped `services/proxy_service.py::health_check` and the reachable set fell
    from 31 nodes to 25, turning a `reachable` eval finding into `no_path_from_entry_point`.

    `caller_file` is therefore evidence, not a filter — it is kept in the signature because a
    future resolver with real import bindings needs it, and because its absence is how the
    preference came back once already.

    Certain means: exactly one definition of that name in the whole tree (a same-file-only
    definition is that case). Anything else is followed in full and flagged uncertain.
    ⚠️ Sorted at every step: this pass is deterministic or it is not evidence.
    """
    cands = sorted(by_name.get(name) or ())
    return tuple(cands), len(cands) <= 1


def _path_to(reach: Dict[str, Tuple[Optional[str], bool]],
             node: str) -> Tuple[List[str], int]:
    """The entry-point -> `node` chain read back off the BFS parents, and how many of its
    hops rested on a call this analysis could not resolve (see `_resolve_callee`)."""
    out: List[str] = []
    unresolved = 0
    seen = set()
    cur: Optional[str] = node
    while cur is not None and cur not in seen:
        seen.add(cur)
        out.append(cur)
        parent, certain = reach.get(cur, (None, True))
        if parent is not None and not certain:
            unresolved += 1
        cur = parent
    return list(reversed(out)), unresolved


def _def_site(graph: Dict[str, Any], qname: str) -> str:
    """`file:line` of a node's definition — so a reader can check the verdict without
    re-running the pass. A function name alone is a ground that cannot be shown."""
    rel, start, _end, _nm = graph["defs"][qname]
    return f"{rel}:{start}"


def _bfs(entries, calls: Dict[str, Any], by_name: Dict[str, Any]) -> Dict[str, Tuple[Optional[str], bool]]:
    """⛔ `reach` MAPS A NODE TO (the caller it was reached from, was that hop certain), not
    just membership. `reachable` REQUIRES a `path` (invariant 2), and a path built over an
    unresolved call has to say so, or an over-approximation reads exactly like a proven one."""
    reach: Dict[str, Tuple[Optional[str], bool]] = {e: (None, True) for e in sorted(entries)}
    q = collections.deque(sorted(entries))
    while q:
        caller = q.popleft()
        caller_file = caller.rsplit(QSEP, 1)[0]
        for callee in sorted(calls.get(caller, ())):
            targets, certain = _resolve_callee(callee, caller_file, by_name)
            for t in targets:
                if t not in reach:
                    reach[t] = (caller, certain)
                    q.append(t)
    return reach


def _py_files(repo: str | Path) -> List[str]:
    return sorted(f for f in walk_files(repo) if f.endswith(".py"))


def build_callgraph(repo: str) -> Optional[Dict[str, Any]]:
    """Function spans, call edges and framework entry points for the Python tree (the pass's in-memory graph:
    node ids `rel/path.py::name`, route entries only). Returns `{defs, reach, entries, files}` or None.

    ⚠️ THIS BUILDER IS PYTHON ONLY, and it SAYS SO rather than silently covering less than it claims: a
    finding in another language returns `inconclusive` with that as the reason. ⛔ It is NOT the live path —
    `build_callgraph_index` + `graph_from_index` is, and that one reads JavaScript too. This one survives as
    the parity oracle the stored graph is compared against (`tests/test_callgraph_index.py`,
    `tests/test_parity.py`), so it is deliberately not extended.
    """
    parser = python_parser()
    if parser is None:
        log(f"callgraph: unavailable (no tree-sitter parser for Python) — {parser_remedy()}")
        return None

    defs: Dict[str, Tuple[str, int, int, str]] = {}
    calls: Dict[str, set] = collections.defaultdict(set)
    by_name: Dict[str, set] = collections.defaultdict(set)
    entries: set = set()

    def walk(node, src, rel, enclosing=None):
        if node.type == "function_definition":
            nm = next((src[c.start_byte:c.end_byte].decode()
                       for c in node.children if c.type == "identifier"), None)
            if nm:
                q = f"{rel}{QSEP}{nm}"
                defs[q] = (rel, node.start_point[0] + 1, node.end_point[0] + 1, nm)
                by_name[nm].add(q)
                par = node.parent
                if par is not None and par.type == "decorated_definition":
                    dtxt = src[par.start_byte:node.start_byte].decode(errors="ignore")
                    if any(f".{v}(" in dtxt for v in _ROUTE_DECOS):
                        entries.add(q)
                enclosing = q
        if node.type == "call" and enclosing and node.children:
            fn = node.children[0]
            callee = src[fn.start_byte:fn.end_byte].decode(errors="ignore").split(".")[-1].strip()
            if callee.isidentifier():
                calls[enclosing].add(callee)
        for c in node.children:
            walk(c, src, rel, enclosing)

    n = 0
    for rel in _py_files(repo):
        try:
            src = open(os.path.join(repo, rel), "rb").read()
            walk(parser.parse(src).root_node, src, rel)
            n += 1
        except Exception:      # noqa: BLE001 — one unparseable file must not stop the pass
            continue

    return {"defs": defs, "reach": _bfs(entries, calls, by_name), "entries": entries, "files": n}


# ── the stored graph (callgraph.v1) ──────────────────────────────────────────────────

def _text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode(errors="ignore")


def _ident(src: bytes, node) -> Optional[str]:
    return next((_text(src, c) for c in node.children if c.type == "identifier"), None)


def _callee(src: bytes, call) -> Optional[str]:
    """The bare callee name of a call node, exactly as today (the token after the last dot), or None."""
    if not call.children:
        return None
    callee = _text(src, call.children[0]).split(".")[-1].strip()
    return callee if callee.isidentifier() else None


def _receiver(src: bytes, fn) -> Optional[str]:
    """OI-171: what the receiver of an attribute call `<recv>.name(…)` is, as pass 2 needs it. None: a plain dotted
    name (`self.x`, `mod.f`) or no receiver at all. `""`: OPAQUE, a literal, a subscript, a parenthesised or any other
    expression (`"; ".join`, `x[k].append`). A call result is opaque too, unless its function is a dotted name: then
    that text is returned, and pass 2 keeps the site as today when the head is bound by an import
    (`get_embedding_service().embed`)."""
    if fn is None or fn.type != "attribute":
        return None
    obj = fn.child_by_field_name("object")
    while obj is not None and obj.type == "attribute":
        obj = obj.child_by_field_name("object")
    if obj is None or obj.type == "identifier":
        return None
    if obj.type == "call":
        inner = "".join(_text(src, obj.child_by_field_name("function")).split()) \
            if obj.child_by_field_name("function") is not None else ""
        return inner if _CALLEE_TEXT.fullmatch(inner) else ""
    return ""


def _module_candidates(module: str, rel: str, level: int) -> List[str]:
    """Paths a (possibly relative) module name can resolve to inside the tree, most specific first."""
    parts = [p for p in module.split(".") if p]
    if level:
        folder = rel.split("/")[:-1]
        up = level - 1
        if up > len(folder):
            return []
        stems = ["/".join(folder[:len(folder) - up] + parts)]
    else:
        stems = ["/".join(parts), "/".join(["src"] + parts)]
    out = []
    for stem in stems:
        if not stem:
            continue
        out += [f"{stem}.py", f"{stem}/__init__.py"]
    return out


class _Bind(NamedTuple):
    """What one import statement binds one name to (CODE_WALKER.md § 3.3.2). `how`: `import` (`import a.b` binds `a`),
    `import_as` (`import a.b as c` binds `c` to `a.b`) or `from` (`from m import n [as k]` binds to (`m`, `n`))."""
    how: str
    module: str
    level: int
    name: Optional[str]


def _imports_of(src: bytes, node) -> List[Tuple[int, str, int, List[Tuple[str, _Bind]]]]:
    """(line, module, relative level, [(bound name, binding)]) for an `import` / `from … import` statement node.
    `from m import *` binds nothing."""
    line = node.start_point[0] + 1
    if node.type == "import_statement":
        out = []
        for c in node.children:
            if c.type == "dotted_name":
                mod = _text(src, c)
                out.append((line, mod, 0, [(mod.split(".")[0], _Bind("import", mod, 0, None))]))
            elif c.type == "aliased_import":
                name = c.child_by_field_name("name")
                alias = c.child_by_field_name("alias")
                if name is not None:
                    mod = _text(src, name)
                    binds = [(_text(src, alias), _Bind("import_as", mod, 0, None))] if alias is not None else []
                    out.append((line, mod, 0, binds))
        return out
    # import_from_statement: `from <module_name> import …`
    mod = node.child_by_field_name("module_name")
    if mod is None:
        return []
    txt = _text(src, mod).strip()
    level = len(txt) - len(txt.lstrip("."))
    module = txt.lstrip(".")
    binds = []
    for i, c in enumerate(node.children):
        if node.field_name_for_child(i) != "name":
            continue
        if c.type == "dotted_name":
            n = _text(src, c)
            binds.append((n, _Bind("from", module, level, n)))
        elif c.type == "aliased_import":
            name, alias = c.child_by_field_name("name"), c.child_by_field_name("alias")
            if name is not None and alias is not None:
                binds.append((_text(src, alias), _Bind("from", module, level, _text(src, name))))
    return [(line, module, level, binds)]


#: A stored `callee_text` / `lib_call.attr`: identifiers and dots only, so it can never carry a literal (§ 3.7.3).
_CALLEE_TEXT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
#: Names a bare `__main__` call can mean without any def in the tree (`print`, `len`, …): never unresolved.
BUILTINS = frozenset(dir(builtins))
#: OI-171b: the (non-dunder) methods of the builtin value types. A by-name `x.append(…)` / `seen.add(…)` /
#: `d.items()` on a plain value is far more often the builtin than the one in-tree def of that name.
BUILTIN_METHODS = frozenset(n for t in (list, dict, set, str, bytes, tuple, frozenset, int) for n in dir(t)
                            if not n.startswith("__"))
#: The route decorator attribute -> HTTP method; `route` / `api_route` read `methods=[…]`; the rest are not HTTP routes.
_HTTP = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "websocket": "WEBSOCKET"}
_MULTI = ("route", "api_route")
#: What a flagged decorator / `via` text is stored as (§ 3.7.3).
WITHHELD = "[withheld]"


def _collapse(text: str) -> str:
    """A decorator as stored: newlines and runs of whitespace collapsed to one space, cut at `DECORATOR_MAX`."""
    return " ".join(text.split())[:DECORATOR_MAX]


def _str_lit(src: bytes, node) -> Optional[str]:
    """A plain string literal's value, or None (an f-string, a concatenation, a name, anything else)."""
    if node is None or node.type != "string":
        return None
    parts = []
    for c in node.children:
        if c.type == "string_start":
            if "f" in _text(src, c).lower():
                return None
        elif c.type == "interpolation":
            return None
        elif c.type in ("string_content", "escape_sequence"):
            parts.append(_text(src, c))
    return "".join(parts)


def _kwarg(src: bytes, args, name: str):
    """The value node of keyword `name` in an `argument_list`, or None."""
    for c in (args.children if args is not None else ()):
        if c.type == "keyword_argument":
            k = c.child_by_field_name("name")
            if k is not None and _text(src, k) == name:
                return c.child_by_field_name("value")
    return None


def _positional(args) -> List[Any]:
    return [c for c in (args.children if args is not None else ())
            if c.is_named and c.type not in ("keyword_argument", "comment", "list_splat", "dictionary_splat")]


def _targets(src: bytes, node) -> List[str]:
    """The plain names an assignment-like target binds (`a`, `a, (b, c)`, `*d`); `x.y` / `x[0]` bind none."""
    if node is None:
        return []
    if node.type == "identifier":
        return [_text(src, node)]
    if node.type in ("attribute", "subscript"):
        return []
    return [n for c in node.children for n in _targets(src, c)]


def _params(src: bytes, node) -> List[str]:
    out = []
    for c in (node.children if node is not None else ()):
        if c.type == "identifier":
            out.append(_text(src, c))
        elif c.type in ("default_parameter", "typed_default_parameter", "typed_parameter",
                        "list_splat_pattern", "dictionary_splat_pattern"):
            nm = c.child_by_field_name("name")
            if nm is None:
                nm = next((x for x in c.children if x.type == "identifier"), None)
            if nm is not None:
                out.append(_text(src, nm))
    return out


def _outer_verb(src: bytes, deco) -> Optional[str]:
    """The attribute of a decorator's OUTER call (`@router.get(…)` -> `get`), or None. OI-174 (a): a route verb inside
    another decorator's arguments (`@pytest.mark.skipif(os.environ.get(…))`) is not a route."""
    expr = next((c for c in deco.children if c.is_named), None)
    fn = expr.child_by_field_name("function") if expr is not None and expr.type == "call" else None
    attr = fn.child_by_field_name("attribute") if fn is not None and fn.type == "attribute" else None
    return _text(src, attr) if attr is not None else None


def _route_details(src: bytes, deco) -> Dict[str, Any]:
    """`{method, path, router}` of a route decorator, from its tree (OI-164; never regex)."""
    expr = next((c for c in deco.children if c.is_named), None)
    out: Dict[str, Any] = {"method": None, "path": None, "router": None}
    if expr is None or expr.type != "call":
        return out
    fn, args = expr.child_by_field_name("function"), expr.child_by_field_name("arguments")
    if fn is None or fn.type != "attribute":
        return out
    obj, attr = fn.child_by_field_name("object"), fn.child_by_field_name("attribute")
    out["router"] = _text(src, obj) if obj is not None else None
    verb = _text(src, attr) if attr is not None else ""
    if verb in _HTTP:
        out["method"] = _HTTP[verb]
    elif verb in _MULTI:
        lst = _kwarg(src, args, "methods")
        if lst is not None and lst.type in ("list", "tuple"):
            vals = [_str_lit(src, x) for x in lst.children if x.is_named]
            if vals and all(v is not None for v in vals):
                out["method"] = "|".join(v.upper() for v in vals)
    else:
        return out                                # middleware / on_event: an entry, not an HTTP route
    pos = _positional(args)
    out["path"] = _str_lit(src, pos[0]) if pos else _str_lit(src, _kwarg(src, args, "path"))
    return out


class _File:
    """One file's binding tables (pass 1), read by pass 2 and by the `__main__` / mount resolution."""

    def __init__(self, f: int, rel: str):
        self.f, self.rel = f, rel
        self.file_binds: Dict[str, List[_Bind]] = collections.defaultdict(list)
        self.file_locals: set = set()
        self.scoped: Dict[str, Dict[str, List[_Bind]]] = collections.defaultdict(lambda: collections.defaultdict(list))
        self.locals: Dict[str, set] = collections.defaultdict(set)
        self.parent: Dict[str, Optional[str]] = {}
        self.sites: List[Tuple[str, str, str, int, Optional[str]]] = []  # (enclosing, callee, text, line, receiver)
        self.main_calls: List[Tuple[str, str, int, str]] = []      # (callee, text, line, guard)
        self.routers: Dict[str, Optional[str]] = {}                # module-scope APIRouter/Blueprint name -> prefix
        self.includes: List[Tuple[Optional[str], str, str]] = []   # (enclosing, ref text, literal prefix)
        #: § 3.6.3 `lib_ref` sites, merged per (enclosing, text) in walk order: [first line, sites, any store]
        self.refs: Dict[Tuple[Optional[str], str], List[Any]] = {}
        #: § 3.6.3 `class_base` sites: (enclosing, class id, base text, class line)
        self.bases: List[Tuple[Optional[str], str, str, int]] = []

    def lookup(self, enclosing: Optional[str], head: str) -> Optional[List[_Bind]]:
        """The bindings `head` has at a call in `enclosing` (Python scoping, innermost first), or None (unbound, or
        shadowed by a local name: a parameter, an assignment, a loop / with / except target, a nested def)."""
        d = enclosing
        while d is not None:
            if head in self.locals[d]:
                return None
            if head in self.scoped[d]:
                return self.scoped[d][head]
            d = self.parent.get(d)
        if head in self.file_locals:
            return None
        return self.file_binds.get(head) or None


class _Ctx(NamedTuple):
    known: Optional[set]          # normalised declared ∪ locked pypi names; None = `declared` not given: nothing external
    local_roots: set
    tree_names: set               # every directory name and module stem in the tree
    pos: Dict[str, int]


def _in_tree(module: str, rel: str, ctx: _Ctx) -> bool:
    segs = module.split(".")
    return any(c in ctx.pos for i in range(len(segs), 0, -1)
               for c in _module_candidates(".".join(segs[:i]), rel, 0))


def _is_external(module: str, level: int, ctx: _Ctx, rel: str) -> bool:
    """⛔ POSITIVE evidence that `module` is outside the repository (CODE_WALKER.md § 3.3.2, R1-B2): stdlib, or a
    declared / locked distribution `distribution_of` maps it to on a measured basis. A relative import, a module the
    tree holds ANYWHERE (a root, a candidate path, any directory or module of that name), or an unattributable or
    only-guessed name is never external: "not found in the tree" alone is not evidence."""
    if ctx.known is None or level or not module:
        return False
    top = module.split(".")[0]
    if top in ctx.local_roots or top in ctx.tree_names or _in_tree(module, rel, ctx):
        return False
    if top in sys.stdlib_module_names:
        return True
    hit = distribution_of(module, ctx.known)
    return hit is not None and hit[1] != "convention"


def _bind_module(b: _Bind, text: str) -> Tuple[str, str]:
    """(the module a call's text reaches through binding `b`, the rest of the text after it)."""
    head, _, rest = text.partition(".")
    if b.how == "import":
        segs = b.module.split(".")
        for i in range(len(segs), 0, -1):
            p = ".".join(segs[:i])
            if text == p or text.startswith(p + "."):
                return p, text[len(p) + 1:]
        return segs[0], rest
    if b.how == "from" and b.name:
        return (f"{b.module}.{b.name}" if b.module else b.name), rest
    return b.module, rest


def _bind_target(b: _Bind, text: str, rel: str, pos: Dict[str, int]) -> Optional[int]:
    """The in-tree file a binding names (`m.n` tried first, then `m`), or None."""
    mod, _ = _bind_module(b, text)
    tries = [mod] + ([b.module] if b.how == "from" else [])
    return next((pos[c] for m in tries for c in _module_candidates(m, rel, b.level) if c in pos), None)


def _classify(fs: _File, enclosing: Optional[str], text: str, ctx: _Ctx) -> Tuple:
    """One call site: `("external", module, attr)`, `("bound", file index)` or `("name",)` (§ 3.3.2)."""
    if not _CALLEE_TEXT.fullmatch(text):
        return ("name",)
    head = text.partition(".")[0]
    binds = fs.lookup(enclosing, head)
    if not binds:
        return ("name",)
    ext = []
    for b in binds:
        mod, rest = _bind_module(b, text)
        if not _is_external(mod, b.level, ctx, fs.rel):
            break
        # ⛔ A FROM-BINDING KEEPS ITS BOUND NAME (FIX_KNOWLEDGE_CONVERGENCE § 3.6.2): `from litellm.utils import
        # get_optional_params; get_optional_params()` is `litellm.utils` · `get_optional_params`, so `module.attr` is
        # always the qualified name the call reaches. It was `attr: ""`, and the API-diff check lost the symbol.
        ext.append((b.module if b.how == "from" else mod,
                    rest if b.how != "from" else ".".join(p for p in (b.name, text.partition(".")[2]) if p)))
    else:
        return ("external",) + ext[0]
    tfs = {_bind_target(b, text, fs.rel, ctx.pos) for b in binds}
    if len(tfs) == 1 and None not in tfs:
        return ("bound", tfs.pop())
    return ("name",)


def _receiver_kind(fs: _File, enclosing: Optional[str], callee: str, text: str, site: Tuple, recv: Optional[str],
                   ctx: _Ctx) -> Optional[str]:
    """What makes this site's receiver unknown, or None: `opaque` (OI-171), or `builtin_method` (OI-171b: a by-name
    dotted call of a builtin type's method on a plain value, `out.append`, `self.rows.add`; never `self.append` /
    `cls.append`, a method called on the instance itself)."""
    if _opaque(fs, enclosing, recv, ctx):
        return "opaque"
    if (site[0] == "name" and callee in BUILTIN_METHODS and "." in text and _CALLEE_TEXT.fullmatch(text)
            and text not in (f"self.{callee}", f"cls.{callee}")):
        return "builtin_method"
    return None


def _opaque(fs: _File, enclosing: Optional[str], recv: Optional[str], ctx: _Ctx) -> bool:
    """OI-171: is this site's receiver opaque (a literal, a subscript, a call result: no evidence for any def)?
    `recv` comes from `_receiver`. A call result stays as today only when its function's head is bound by an import
    that is NOT external: an in-tree factory (`get_embedding_service().embed`) can return an in-tree object; a library
    call (`requests.get(u).json()`) cannot be evidence for a def in this tree."""
    if recv is None:
        return False
    if not recv:
        return True
    binds = fs.lookup(enclosing, recv.partition(".")[0])
    return not binds or all(_is_external(_bind_module(b, recv)[0], b.level, ctx, fs.rel) for b in binds)


# ── § 3.6.3 (FIX_KNOWLEDGE_CONVERGENCE): references that are not calls, and library base classes ──────────────────

#: The `from` of a `lib_ref` made at module or class-body scope: `<path>::<module>`.
MODULE_SCOPE = "<module>"
#: Parents whose identifier children are names a statement declares or binds, never a reference to one.
_NAME_PARENTS = frozenset({"dotted_name", "aliased_import", "relative_import", "parameters", "lambda_parameters",
                           "typed_parameter", "list_splat_pattern", "dictionary_splat_pattern", "global_statement",
                           "nonlocal_statement"})
#: Parents an assignment target is wrapped in (`a, b = …`, `(a) = …`), climbed to find the assignment's `left`.
_TARGET_WRAPPERS = frozenset({"pattern_list", "tuple_pattern", "list_pattern", "tuple", "list", "expression_list",
                              "parenthesized_expression"})


def _same(a, b) -> bool:
    return a is not None and b is not None and (a.type, a.start_byte, a.end_byte) == (b.type, b.start_byte, b.end_byte)


def _ref_role(node, enclosing: Optional[str]) -> Optional[str]:
    """What an `identifier` / `attribute` node is as a `lib_ref` site: `"load"`, `"store"`, or None (not a site).

    A site is a MAXIMAL dotted name: a node inside a longer attribute chain is not one (its chain is). Never a site:
    a name a statement declares (an import's names, a def or class name, a parameter, a keyword-argument name), and
    the `function` of a call inside a def (that is a `lib_call`). ⭐ The function of a call at module or class-body
    scope IS a site (`load`): such a call is only an unclassified `module_call` (:755), so without this a module-scope
    `litellm.set_verbose(True)` would be seen by nothing (§ 2.6 miss (b))."""
    par = node.parent
    if par is None or par.type == "attribute":
        return None
    if node.type == "identifier":
        if par.type in _NAME_PARENTS:
            return None
        if (par.type in ("function_definition", "class_definition", "keyword_argument", "default_parameter",
                         "typed_default_parameter") and _same(par.child_by_field_name("name"), node)):
            return None
    if par.type == "call" and _same(par.child_by_field_name("function"), node):
        return "load" if enclosing is None else None
    cur = node
    while cur.parent is not None and cur.parent.type in _TARGET_WRAPPERS:
        cur = cur.parent
    top = cur.parent
    if top is not None and top.type in ("assignment", "augmented_assignment") \
            and _same(top.child_by_field_name("left"), cur):
        return "store"
    return "load"


def _not_stdlib(module: str) -> bool:
    """API diffs exist only for registry packages; a stdlib reference (`os.environ`) is never recorded."""
    return module.split(".")[0] not in sys.stdlib_module_names


def build_callgraph_index(root: str | Path, *, commit: Optional[str] = None,
                          repository: Optional[str] = None, parser=None,
                          declared: Optional[Iterable[str]] = None,
                          locked: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """The `index/callgraph.json` document (schema `atlas/index/callgraph.v1`, index format 2) for the Python tree at
    `root`.

    Records: `def` (id `<path>::<qualname>`, `Class.method` for a method; whole decorators), `entry` (route / cli /
    task / main; a route with its method, path, router, router prefix and mounts), `module_call` (a call at module
    scope: it runs on import), `call` (one per (caller, bare name): every same-named def as a target unless every site
    is `external`; `resolution`, `bound_target`, `sites`, `callee_text`), `lib_call` (one per external call site),
    `lib_ref` (format 4: a non-call reference to a non-stdlib library name, or a module/class-scope call's function,
    merged per (from, module, attr); `store` when any site is assigned to), `class_base` (format 4: a class whose
    base is a non-stdlib library class), `module_import` (the first-party file it resolves to, or null; what it
    `binds`; its function `scope`; for `from … import`, `from_import` pairs each REAL name with its local `as`).
    Header: `index_format`, `main_unresolved` (§ 3.3.4). Format 4: FIX_KNOWLEDGE_CONVERGENCE § 3.6.3.

    `declared`: PEP 503 names of the tree's declared pypi dependencies (an iterable, or `{"pypi": …}`); `locked`: the
    tree's pypi `requirement` records. ⛔ `declared=None` -> no call is ever `external` (1.5.0's edges).
    Without a parser: no records, `languages.python = "parser_missing"`."""
    base = Path(root)
    # ONE tree walk for both front ends: `walk_files` runs a git subprocess (see `js_front.js_block`).
    walked = list(walk_files(base))
    rels = sorted(f for f in walked if f.endswith(".py"))
    header = {"schema": SCHEMA_CALLGRAPH, "engine": ENGINE, "index_format": INDEX_FORMAT, "commit": commit,
              "repository": repository, "files": rels, "file_sha": [_sha1(base / r) for r in rels],
              "parse_failures": [], "languages": {"python": "absent" if not rels else "parsed"}, "truncated": False,
              "main_unresolved": [], "records": []}
    # ⭐ THE npm FRONT END, BEFORE EVERY PYTHON EARLY RETURN. A tree can hold JavaScript and no Python, or
    # run on a host with a JS grammar and no Python one; computing the block after those returns gave a
    # JS-only repository a document with no npm coverage at all. Its own `files`/`records` — see
    # `js_front.js_block` for why they are NOT merged into the lists above.
    npm = js_block(base, walked=walked)
    header["npm"] = npm
    header["languages"]["javascript"] = npm["language"]
    if not rels:
        return header
    parser = parser if parser is not None else python_parser()
    if parser is None:
        header["languages"]["python"] = "parser_missing"
        return header

    if isinstance(declared, dict):
        declared = declared.get("pypi") or ()
    known = None
    if declared is not None:
        known = {normalize(x) for x in declared}
        known |= {normalize(r["package"]) for r in locked or () if r.get("ecosystem", "pypi") == "pypi"}
    pos = {r: i for i, r in enumerate(rels)}
    tree_names = {seg[:-3] if seg.endswith(".py") else seg for r in rels for seg in r.split("/")}
    ctx = _Ctx(known, firstparty.local_roots(base, known or set()) if known is not None else set(), tree_names, pos)
    defs: Dict[str, Dict[str, Any]] = {}
    entries: List[Dict[str, Any]] = []
    module_calls: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    failures: List[Dict[str, str]] = []
    states: List[_File] = []
    pending_routes: List[Tuple[Dict[str, Any], _File]] = []

    def walk(node, src, fs, classes, enclosing, guard):
        t = node.type
        rel, f = fs.rel, fs.f
        scope_locals = (fs.locals[enclosing] if enclosing is not None
                        else fs.file_locals if not classes else None)       # a class body binds class attributes
        if t == "class_definition":
            nm = _ident(src, node)
            if nm:
                if scope_locals is not None:
                    scope_locals.add(nm)
                # § 3.6.3 class_base: the class id follows the def rule below (:qual), classified in `enclosing`
                cid = f"{rel}{QSEP}{'.'.join(classes + (nm,)) if classes and enclosing is None else nm}"
                sup = node.child_by_field_name("superclasses")
                for base in (sup.children if sup is not None else ()):
                    if base.type in ("identifier", "attribute"):
                        btxt = "".join(_text(src, base).split())
                        if _CALLEE_TEXT.fullmatch(btxt):
                            fs.bases.append((enclosing, cid, btxt, node.start_point[0] + 1))
                classes = classes + (nm,)
        elif t == "function_definition":
            nm = _ident(src, node)
            if nm:
                if scope_locals is not None:
                    scope_locals.add(nm)
                qual = ".".join(classes + (nm,)) if classes and enclosing is None else nm
                did = f"{rel}{QSEP}{qual}"
                decos: List[Tuple[Any, str, int]] = []
                par = node.parent
                if par is not None and par.type == "decorated_definition":
                    for c in par.children:
                        if c.type == "decorator":
                            decos.append((c, _text(src, c), c.start_point[0] + 1))
                if did not in defs:
                    fs.parent[did] = enclosing
                    fs.locals[did].update(_params(src, node.child_by_field_name("parameters")))
                    defs[did] = {"kind": "def", "id": did, "f": f, "line": node.start_point[0] + 1,
                                 "end_line": node.end_point[0] + 1, "name": nm,
                                 "decorators": [_collapse(d) for _, d, _ in decos],
                                 "async": any(c.type == "async" for c in node.children)}
                    if decos:
                        defs[did]["decorators_at"] = decos[0][2]
                    for dnode, dtxt, dline in decos:
                        first = dtxt.splitlines()[0][:DECORATOR_MAX]      # classification reads the first line, as 1.5.0
                        kind = ("route" if any(f".{v}(" in first for v in _ROUTE_DECOS) and _outer_verb(src, dnode)
                                in _ROUTE_DECOS
                                else "cli" if _CLI_DECO.search(first)
                                else "task" if _TASK_DECO.search(first) else None)
                        if kind:
                            e = {"kind": "entry", "def": did, "entry_kind": kind, "via": _collapse(dtxt),
                                 "f": f, "line": dline}
                            if kind == "route":
                                e.update(_route_details(src, dnode))
                                pending_routes.append((e, fs))
                            entries.append(e)
                enclosing = did
                classes = ()
        elif t in ("import_statement", "import_from_statement"):
            in_class = enclosing is None and bool(classes)
            for line, module, level, binds in _imports_of(src, node):
                target = next((pos[c] for c in _module_candidates(module, rel, level) if c in pos), None)
                rec = {"kind": "module_import", "f": f, "line": line, "module": "." * level + module,
                       "target_f": target, "binds": [n for n, _ in binds], "scope": enclosing}
                if t == "import_from_statement":
                    # § 3.6.3: `binds` holds the LOCAL name (the alias); the API-diff check needs the REAL one, so
                    # `from litellm.utils import get_optional_params as gop` is {name: get_optional_params, as: gop}
                    rec["from_import"] = [{"name": b.name, "as": n} for n, b in binds]
                imports.append(rec)
                if in_class:
                    continue
                table = fs.scoped[enclosing] if enclosing is not None else fs.file_binds
                for n, b in binds:
                    table[n].append(b)
        elif t in ("assignment", "augmented_assignment", "for_statement", "for_in_clause"):
            if scope_locals is not None:
                scope_locals.update(_targets(src, node.child_by_field_name("left")))
            if (t == "assignment" and enclosing is None and not classes):
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None and right.type == "call":
                    fn = right.child_by_field_name("function")
                    ctor = _text(src, fn).split(".")[-1] if fn is not None else ""
                    if ctor in ("APIRouter", "Blueprint"):
                        args = right.child_by_field_name("arguments")
                        kw = _kwarg(src, args, "prefix" if ctor == "APIRouter" else "url_prefix")
                        fs.routers[_text(src, left)] = _str_lit(src, kw)
        elif t == "named_expression":
            if scope_locals is not None:
                scope_locals.update(_targets(src, node.child_by_field_name("name")))
        elif t == "as_pattern":
            if scope_locals is not None:
                scope_locals.update(_targets(src, node.child_by_field_name("alias")))
        elif t == "if_statement" and enclosing is None and guard is None:
            cond = node.child_by_field_name("condition")
            if cond is not None and _MAIN_GUARD.search(_text(src, cond)):
                guard = _text(src, node).splitlines()[0][:DECORATOR_MAX]
        elif t == "call":
            callee = _callee(src, node)
            fn = node.children[0] if node.children else None
            if fn is not None and fn.type == "attribute":
                attr = fn.child_by_field_name("attribute")
                verb = _text(src, attr) if attr is not None else ""
                if verb in ("include_router", "register_blueprint"):
                    args = node.child_by_field_name("arguments")
                    ref = _positional(args)
                    kw = _kwarg(src, args, "prefix" if verb == "include_router" else "url_prefix")
                    lit = "" if kw is None else _str_lit(src, kw)
                    if ref and lit is not None:
                        fs.includes.append((enclosing, "".join(_text(src, ref[0]).split()), lit))
            if callee:
                line = node.start_point[0] + 1
                text = "".join(_text(src, fn).split()) if fn is not None else callee
                if enclosing is not None:
                    fs.sites.append((enclosing, callee, text, line, _receiver(src, fn)))
                else:
                    module_calls.append({"kind": "module_call", "f": f, "line": line, "callee": callee})
                    if guard is not None:
                        fs.main_calls.append((callee, text, line, guard))
        if t in ("identifier", "attribute"):
            role = _ref_role(node, enclosing)
            if role is not None:
                rtxt = "".join(_text(src, node).split())
                if _CALLEE_TEXT.fullmatch(rtxt):
                    site = fs.refs.get((enclosing, rtxt))
                    if site is None:
                        fs.refs[(enclosing, rtxt)] = [node.start_point[0] + 1, 1, role == "store"]
                    else:
                        site[1] += 1
                        site[2] = site[2] or role == "store"
        for c in node.children:
            walk(c, src, fs, classes, enclosing, guard)

    for rel in rels:
        try:
            src = (base / rel).read_bytes()
            tree = parser.parse(src)
        except Exception as exc:      # noqa: BLE001 — one unparseable file must not stop the build
            failures.append({"file": rel, "reason": type(exc).__name__})
            continue
        if tree.root_node.has_error:
            # Parsed with error nodes: still walked (tree-sitter recovers), and said, so a reader knows.
            failures.append({"file": rel, "reason": "syntax_error"})
        fs = _File(pos[rel], rel)
        states.append(fs)
        walk(tree.root_node, src, fs, (), None, None)

    by_name: Dict[str, set] = collections.defaultdict(set)
    for d in defs.values():
        by_name[d["name"]].add(d["id"])

    # pass 2: classify every site with the whole file's bindings, then merge per (caller, bare name) (R1-B1)
    merged: Dict[Tuple[str, str], List[Tuple[str, int, Tuple, Optional[str]]]] = {}
    lib_calls: List[Dict[str, Any]] = []
    for fs in states:
        for enclosing, callee, text, line, recv in fs.sites:
            site = _classify(fs, enclosing, text, ctx)
            merged.setdefault((enclosing, callee), []).append(
                (text, line, site, _receiver_kind(fs, enclosing, callee, text, site, recv, ctx)))
            if site[0] == "external":
                lib_calls.append({"kind": "lib_call", "from": enclosing, "module": site[1],
                                  "attr": site[2] if _CALLEE_TEXT.fullmatch(site[2] or "x") else "", "line": line})
    call_records = [_call_record(frm, callee, sites, by_name, defs, rels)
                    for (frm, callee), sites in merged.items()]

    # § 3.6.3: `lib_ref` (merged per (from, module, attr): first line in walk order, sites summed, store if any) and
    # `class_base`, each classified like a call site, kept only when external AND not stdlib
    lib_refs: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    class_bases: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}
    for fs in states:
        for (enclosing, text), (line, n, store) in fs.refs.items():
            site = _classify(fs, enclosing, text, ctx)
            if site[0] != "external" or not _not_stdlib(site[1]):
                continue
            frm = enclosing if enclosing is not None else f"{fs.rel}{QSEP}{MODULE_SCOPE}"
            attr = site[2] if _CALLEE_TEXT.fullmatch(site[2] or "x") else ""
            got = lib_refs.get((frm, site[1], attr))
            if got is None:
                lib_refs[(frm, site[1], attr)] = {"kind": "lib_ref", "from": frm, "module": site[1], "attr": attr,
                                                  "line": line, "sites": n, "store": store}
            else:
                got["sites"] += n
                got["store"] = got["store"] or store
        for enclosing, cid, text, line in fs.bases:
            site = _classify(fs, enclosing, text, ctx)
            if site[0] != "external" or not _not_stdlib(site[1]):
                continue
            attr = site[2] if _CALLEE_TEXT.fullmatch(site[2] or "x") else ""
            class_bases[(cid, site[1], attr, line)] = {"kind": "class_base", "class": cid, "module": site[1],
                                                       "attr": attr, "line": line}

    # `__main__` blocks: an entry in another file only through a resolved import (§ 3.3.4, R1-B3)
    unresolved: List[Dict[str, Any]] = []
    for fs in states:
        for callee, text, line, guard in fs.main_calls:
            head, _, rest = text.partition(".")
            binds = fs.lookup(None, head) if _CALLEE_TEXT.fullmatch(text) else None
            if binds and all(_is_external(_bind_module(b, text)[0], b.level, ctx, fs.rel) for b in binds):
                continue                     # sys.exit, asyncio.run, uvicorn.run, a from-import of a library
            if not rest and head in BUILTINS and not binds:
                continue                     # print, len, range …
            same = sorted(i for i in by_name.get(callee, ()) if i.startswith(fs.rel + QSEP))
            if not same and binds:
                tfs = {_bind_target(b, text, fs.rel, pos) for b in binds}
                if len(tfs) == 1 and None not in tfs:
                    trel = rels[tfs.pop()]
                    same = sorted(i for i in by_name.get(callee, ()) if i.startswith(trel + QSEP))
            if same:
                for did in same:
                    entries.append({"kind": "entry", "def": did, "entry_kind": "main", "via": guard, "f": fs.f,
                                    "line": line})
            elif not binds and not rest and by_name.get(callee):
                unresolved.append({"f": fs.f, "line": line, "callee": callee, "candidates": sorted(by_name[callee])})

    # mounts: `<x>.include_router(<ref>, prefix=…)` resolved to (file, router name), one level only (R1-Q11)
    mounts: Dict[Tuple[int, str], set] = collections.defaultdict(set)
    for fs in states:
        for enclosing, ref, lit in fs.includes:
            for key in _mount_keys(fs, enclosing, ref, pos):
                mounts[key].add(lit)
    for e, fs in pending_routes:
        router = e.get("router")
        e["router_prefix"] = fs.routers.get(router) if router else None
        e["mounts"] = sorted(mounts.get((fs.f, router), ())) if router else []

    header["parse_failures"] = sorted(failures, key=lambda x: x["file"])
    header["main_unresolved"] = sorted(unresolved, key=lambda u: (u["f"], u["line"], u["callee"]))
    records = (sorted(defs.values(), key=lambda r: (r["f"], r["line"], r["id"]))
               + sorted({(e["def"], e["entry_kind"], e["via"], e["f"], e["line"]): e for e in entries}.values(),
                        key=lambda r: (r["def"], r["entry_kind"], r["line"], r["via"]))
               + sorted(module_calls, key=lambda r: (r["f"], r["line"], r["callee"]))
               + sorted(call_records, key=lambda r: (r["from"], r["callee"]))
               + sorted(lib_calls, key=lambda r: (r["from"], r["line"], r["module"], r["attr"]))
               + sorted(lib_refs.values(), key=lambda r: (r["from"], r["module"], r["attr"]))
               + sorted(class_bases.values(), key=lambda r: (r["class"], r["line"], r["module"], r["attr"]))
               + sorted(imports, key=lambda r: (r["f"], r["line"], r["module"])))
    header["records"] = records
    return header


def _call_record(frm: str, callee: str, sites: List[Tuple[str, int, Tuple, bool]], by_name: Dict[str, set],
                 defs: Dict[str, Dict[str, Any]], rels: List[str]) -> Dict[str, Any]:
    """Every site of one (caller, bare name), merged (R1-B1): `external` only when EVERY site is; else `name` if any
    site is; else `bound`. A `bound` site never removes a by-name target (R1-B2). `receiver` when every non-external
    site's receiver is unknown: `opaque` (OI-171) if any is, else `builtin_method` (OI-171b); one plain site is
    evidence for the edge on its own."""
    kinds = [s[0] for _, _, s, _ in sites]
    resolution = ("external" if all(k == "external" for k in kinds)
                  else "name" if "name" in kinds else "bound")
    targets = [] if resolution == "external" else sorted(by_name.get(callee, ()))
    bound_target = None
    if resolution == "bound":
        tfs = {s[1] for _, _, s, _ in sites if s[0] == "bound"}
        if len(tfs) == 1:
            trel = rels[tfs.pop()]
            hits = [t for t in targets if t.startswith(trel + QSEP) and defs[t]["name"] == callee]
            bound_target = hits[0] if len(hits) == 1 else None
    ext = next((txt for txt, _, s, _ in sites if s[0] == "external"), None)
    text = ext if ext is not None else sites[0][0]
    rec = {"kind": "call", "from": frm, "callee": callee, "line": sites[0][1], "targets": targets,
           "resolution": resolution, "bound_target": bound_target, "sites": len(sites)}
    kinds_rx = [rx for _, _, s, rx in sites if s[0] != "external"]
    if targets and all(kinds_rx):
        rec["receiver"] = "opaque" if "opaque" in kinds_rx else "builtin_method"
    rec["certain"] = len(targets) == 0 or (len(targets) == 1 and edge_certain(rec, targets[0]))
    if _CALLEE_TEXT.fullmatch(text) and len(text) <= DECORATOR_MAX:
        rec["callee_text"] = text
    return rec


def _mount_keys(fs: _File, enclosing: Optional[str], ref: str, pos: Dict[str, int]) -> List[Tuple[int, str]]:
    """(file index, router name) an `include_router` reference names, through this file's bindings; [] when unknown."""
    if not _CALLEE_TEXT.fullmatch(ref):
        return []
    head, _, rest = ref.partition(".")
    binds = fs.lookup(enclosing, head)
    if not binds:
        return [(fs.f, ref)] if not rest else []
    out = []
    for b in binds:
        if b.how == "from" and not rest:
            mod, obj = b.module, b.name
        elif b.how == "import":
            mod, tail = _bind_module(b, ref)
            mod, obj = (mod, tail) if tail and "." not in tail else (None, None)
        elif "." not in rest:
            mod, obj = _bind_module(b, head)[0], rest
        else:
            mod, obj = None, None
        if mod is None or not obj:
            continue
        tries = [mod] + ([b.module] if b.how == "from" else [])
        tf = next((pos[c] for m in tries for c in _module_candidates(m, fs.rel, b.level) if c in pos), None)
        if tf is not None:
            out.append((tf, obj))
    return out


def _sha1(path: Path) -> str:
    try:
        return hashlib.sha1(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def edge_certain(record: Dict[str, Any], target: str, files: Optional[List[str]] = None) -> bool:
    """⛔ THE certainty rule for one stored edge (CODE_WALKER.md § 3.3.2; `graph_from_index`, `answer` and the walker
    all call this): certain iff the call has one target or `target` is its `bound_target`, AND it is not a runtime
    caller reaching a non-runtime (tests/, docs/ …) target, AND (OI-171) its receiver is not opaque (`"; ".join`,
    `x[k].append`) or a builtin type's method on a plain value (`out.append`, OI-171b): format 3; a format-2 record
    has no `receiver` and reads as before). Targets are never dropped by
    certainty. `files` is accepted for the signature the spec names; ids carry their paths."""
    if record.get("receiver"):                  # "opaque" (OI-171) or "builtin_method" (OI-171b)
        return False
    caller_file, target_file = record["from"].rsplit(QSEP, 1)[0], target.rsplit(QSEP, 1)[0]
    if is_runtime(caller_file) and not is_runtime(target_file):
        return False
    return len(record.get("targets") or ()) == 1 or (record.get("bound_target") is not None
                                                     and target == record.get("bound_target"))


def _bfs_edges(entries, by_from: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Tuple[Optional[str], bool]]:
    """`_bfs` over the STORED edges of a format-2 document, `edge_certain` per edge."""
    reach: Dict[str, Tuple[Optional[str], bool]] = {e: (None, True) for e in sorted(entries)}
    q = collections.deque(sorted(entries))
    while q:
        caller = q.popleft()
        for rec in by_from.get(caller, ()):
            for t in rec.get("targets") or ():
                if t not in reach:
                    reach[t] = (caller, edge_certain(rec, t))
                    q.append(t)
    return reach


def graph_from_index(doc: Dict[str, Any], *, entry_kinds: Optional[Tuple[str, ...]] = None
                     ) -> Optional[Dict[str, Any]]:
    """The `{defs, reach, entries, files, reach_unresolved}` graph `code_verdict` reads, from a stored callgraph.v1
    document. None when the document has neither parsed Python nor a JavaScript block whose entry set is
    believed complete (see the gate below). `entry_kinds` limits the entries (default: every kind).

    Format >= 2: `reach` follows the STORED targets with `edge_certain` per edge, so a reader can never disagree with
    the stored resolution; `reach_unresolved` = {def: callee} reached only from the candidates of `main_unresolved`
    (§ 3.3.4). Format 1: by bare name, as 1.5.0, and `reach_unresolved` is empty."""
    # ⛔ EACH LANGUAGE IS ADMITTED ON ITS OWN TERMS, and JavaScript's terms are stricter.
    # Python: `parsed` is enough — its entry grammar (route / cli / task / __main__ decorators and guards)
    # is closed-form and has been the basis of every stored answer.
    # JavaScript: `parsed` is NOT enough. Its entry shapes have no closed form, so the npm block states
    # whether the entry set can be believed complete FOR THIS TREE (every entry-defining package the tree
    # declares is one the front end enumerates). Without that, enumerating some frameworks and not others
    # gives a non-empty entry set over which the BFS runs and returns `no_path_from_entry_point` for a
    # function reachable only through a route nobody enumerated — a confident false negative. `answer`
    # cannot catch it: its own guard only fires when the entry set is EMPTY.
    py_ok = (doc.get("languages") or {}).get("python") == "parsed"
    npm = doc.get("npm") or {}
    js_ok = (npm.get("language") == "parsed"
             and bool((npm.get("entry_coverage") or {}).get("complete")))
    if not py_ok and not js_ok:
        return None
    sources: List[Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]] = []
    if py_ok:
        sources.append((doc.get("records") or [], doc.get("files") or [], doc.get("parse_failures") or []))
    if js_ok:
        sources.append((npm.get("records") or [], npm.get("files") or [],
                        npm.get("parse_failures") or []))
    fmt = doc.get("index_format") or 1
    defs: Dict[str, Tuple[str, int, int, str]] = {}
    calls: Dict[str, set] = collections.defaultdict(set)
    by_from: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    by_name: Dict[str, set] = collections.defaultdict(set)
    entries: set = set()
    n_files = 0
    for records, files, failures in sources:
        # ⚠️ `f` INDEXES ITS OWN BLOCK'S `files`. The npm block keeps a separate list (see `js_front`), so a
        # record must be resolved against the list it was written beside, never the document's.
        n_files += len(files) - sum(1 for p in failures if p.get("reason") != "syntax_error")
        for r in records:
            k = r.get("kind")
            if k == "def":
                defs[r["id"]] = (files[r["f"]], r["line"], r["end_line"], r["name"])
                by_name[r["name"]].add(r["id"])
            elif k == "call":
                calls[r["from"]].add(r["callee"])
                by_from[r["from"]].append(r)
            elif k == "entry" and (entry_kinds is None or r["entry_kind"] in entry_kinds):
                entries.add(r["def"])
    entries &= set(defs)
    for recs in by_from.values():
        recs.sort(key=lambda r: r["callee"])
    reach = _bfs_edges(entries, by_from) if fmt >= 2 else _bfs(entries, calls, by_name)
    reach_unresolved: Dict[str, str] = {}
    if py_ok and fmt >= 2 and (entry_kinds is None or "main" in entry_kinds):
        for u in sorted(doc.get("main_unresolved") or (), key=lambda u: (u["callee"], u["f"], u["line"])):
            for node in _bfs_edges([c for c in u["candidates"] if c in defs], by_from):
                if node not in reach and node not in reach_unresolved:
                    reach_unresolved[node] = u["callee"]
    # ⛔ THE GRAPH CARRIES WHAT IT COVERS, AND WHY IT DOES NOT. `code_verdict` is handed only this graph,
    # so without these it cannot tell "this file's language was never read" from "this file holds no
    # function" — and the second reads as a finding about the file when it is a fact about the analysis.
    covered = (["python"] if py_ok else []) + (["javascript"] if js_ok else [])
    not_covered: Dict[str, str] = {}
    if not js_ok and npm.get("language") == "parsed":
        not_covered["javascript"] = ((npm.get("entry_coverage") or {}).get("why")
                                     or "this repository's JavaScript entry points are not enumerated")
    elif npm.get("language") == "parser_missing":
        not_covered["javascript"] = ("no tree-sitter JavaScript/TypeScript grammar was available when this "
                                     "graph was built")
    return {"defs": defs, "reach": reach, "entries": entries, "reach_unresolved": reach_unresolved,
            "files": n_files, "languages": covered, "not_covered": not_covered}


def withhold_texts(doc: Dict[str, Any], *, flag_text: Optional[Callable[[str], Optional[str]]],
                   flagged_lines: Optional[Dict[str, Iterable[int]]] = None) -> int:
    """Secret-scan support for a callgraph document, in place (CODE_WALKER.md § 3.7.3; the caller runs the scanner).

    Every stored text taken from a decorator or a `__main__` guard (`def.decorators`, `entry.via`, `router_prefix`,
    `mounts`) is replaced by `WITHHELD` when `flag_text(text)` returns a rule, or when a workspace-scan hit
    (`flagged_lines`: path -> lines) falls in the def's decorator block (`decorators_at` .. the `def` line). A withheld
    route keeps no `method` / `path`. ⛔ `flag_text=None` means the scanner is MISSING: fail closed, every text is
    withheld. Returns how many texts were withheld. `callee_text` / `lib_call.attr` admit identifiers and dots only and
    are never scanned."""
    files = doc.get("files") or []
    hits = {p: set(ls) for p, ls in (flagged_lines or {}).items()}
    records = doc.get("records") or []
    defs = {r["id"]: r for r in records if r.get("kind") == "def"}

    def block(d: Optional[Dict[str, Any]]) -> bool:
        lines = hits.get(files[d["f"]]) if d is not None else None
        return bool(lines) and any(d.get("decorators_at", d["line"]) <= ln < d["line"] for ln in lines)

    def bad(text: Optional[str], blk: bool) -> bool:
        return text not in (None, WITHHELD) and (flag_text is None or blk or bool(flag_text(text)))

    n = 0
    for r in records:
        if r.get("kind") == "def":
            blk = block(r)
            new = [WITHHELD if bad(t, blk) else t for t in r["decorators"]]
            n += sum(1 for a, b in zip(r["decorators"], new) if a != b)
            r["decorators"] = new
        elif r.get("kind") == "entry":
            line_hit = r["line"] in hits.get(files[r["f"]], ())
            blk = line_hit or (r["entry_kind"] != "main" and block(defs.get(r["def"])))
            if bad(r["via"], blk):
                r["via"] = WITHHELD
                n += 1
                if "path" in r:
                    r["method"], r["path"] = None, None
            if bad(r.get("router_prefix"), blk):
                r["router_prefix"] = None
                n += 1
            if r.get("mounts"):
                kept = [m for m in r["mounts"] if not bad(m, blk)]
                n += len(r["mounts"]) - len(kept)
                r["mounts"] = kept
    return n
