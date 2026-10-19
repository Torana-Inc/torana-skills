"""The Python call graph: the in-memory graph the pass builds today, and the stored `index/callgraph.json`.

`build_callgraph`, `_resolve_callee`, `_path_to`, `_def_site`, `python_parser` and the parser-remedy helpers are moved
from `reachability_pass.py:506-726` (4222f48) with their behaviour unchanged, except that files come from
`paths.walk_files` (a symlinked file is skipped). `build_callgraph_index` writes the v1 document of
REACHABILITY_EXTRACTOR.md § 3.3.2.2 (qualified names, decorators, four entry kinds, module-scope calls, module imports),
and `graph_from_index` reads it back into the shape `code_verdict` takes, recomputing `reach` (never stored, so the
stored graph cannot disagree with the code that reads it).

⚠️ Python only, and it SAYS SO rather than silently covering less than it claims. tree-sitter is OPTIONAL: without
it the graph is None / `languages.python = "parser_missing"`, and every code question is `inconclusive` with that as
the reason.
"""
from __future__ import annotations

import collections
import glob
import hashlib
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from torana_reachability import ENGINE
from torana_reachability.paths import walk_files

SCHEMA_CALLGRAPH = "atlas/index/callgraph.v1"

#: The `--engines` name that installs the call graph's parser. ⚠️ Must match the entry in
#: `scan_pack.json` -> libraries[].name, or every message here points at a flag that does
#: nothing. The package half of the queue needs none of this.
_TREE_SITTER_ENGINE = "tree-sitter"

#: Where `install_engines.sh` puts the parser — the scan pack's ISOLATED venv, which is NOT
#: the interpreter running this script. Same override the installer honours.
_SCAN_PACK = os.environ.get("TORANA_SCAN_PACK_DIR") or os.path.join(
    os.path.expanduser("~"), ".torana", "scan-pack")

_ROUTE_DECOS = ("get", "post", "put", "patch", "delete", "websocket", "route",
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
    (pantheon-api-gw) `api/routes/health.py::health_check` calls `proxy_service.health_check()`;
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

    ⚠️ Python only in this version, and it SAYS SO rather than silently covering less than it
    claims. A finding in another language returns `inconclusive` with that as the reason.
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


def _imports_of(src: bytes, node, rel: str) -> List[Tuple[int, str, int]]:
    """(line, module, relative level) for an `import` / `from … import` statement node."""
    line = node.start_point[0] + 1
    if node.type == "import_statement":
        out = []
        for c in node.children:
            if c.type == "dotted_name":
                out.append((line, _text(src, c), 0))
            elif c.type == "aliased_import":
                name = next((x for x in c.children if x.type == "dotted_name"), None)
                if name is not None:
                    out.append((line, _text(src, name), 0))
        return out
    # import_from_statement: `from <module_name> import …`
    mod = node.child_by_field_name("module_name")
    if mod is None:
        return []
    txt = _text(src, mod).strip()
    level = len(txt) - len(txt.lstrip("."))
    return [(line, txt.lstrip("."), level)]


def build_callgraph_index(root: str | Path, *, commit: Optional[str] = None,
                          repository: Optional[str] = None, parser=None) -> Dict[str, Any]:
    """The `index/callgraph.json` document (schema `atlas/index/callgraph.v1`) for the Python tree at `root`.

    Records: `def` (id `<path>::<qualname>`, `Class.method` for a method), `entry` (route / cli / task / main),
    `module_call` (a call at module scope: it runs on import), `call` (bare callee, every same-named def as a
    target, `certain` iff at most one), `module_import` (with the first-party file it resolves to, or null).
    Without a parser: no records, `languages.python = "parser_missing"`."""
    base = Path(root)
    rels = _py_files(base)
    header = {"schema": SCHEMA_CALLGRAPH, "engine": ENGINE, "commit": commit, "repository": repository,
              "files": rels, "file_sha": [_sha1(base / r) for r in rels], "parse_failures": [],
              "languages": {"python": "absent" if not rels else "parsed"}, "truncated": False, "records": []}
    if not rels:
        return header
    parser = parser if parser is not None else python_parser()
    if parser is None:
        header["languages"]["python"] = "parser_missing"
        return header

    pos = {r: i for i, r in enumerate(rels)}
    defs: Dict[str, Dict[str, Any]] = {}
    calls: Dict[Tuple[str, str], int] = {}
    entries: List[Dict[str, Any]] = []
    module_calls: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    main_calls: List[Tuple[int, str, int, str]] = []          # (f, callee, line, guard text)
    failures: List[Dict[str, str]] = []

    def walk(node, src, rel, f, classes, enclosing, guard):
        t = node.type
        if t == "class_definition":
            nm = _ident(src, node)
            if nm:
                classes = classes + (nm,)
        elif t == "function_definition":
            nm = _ident(src, node)
            if nm:
                qual = ".".join(classes + (nm,)) if classes and enclosing is None else nm
                did = f"{rel}{QSEP}{qual}"
                decos: List[Tuple[str, int]] = []
                par = node.parent
                if par is not None and par.type == "decorated_definition":
                    for c in par.children:
                        if c.type == "decorator":
                            decos.append((_text(src, c).splitlines()[0][:DECORATOR_MAX], c.start_point[0] + 1))
                if did not in defs:
                    defs[did] = {"kind": "def", "id": did, "f": f, "line": node.start_point[0] + 1,
                                 "end_line": node.end_point[0] + 1, "name": nm,
                                 "decorators": [d for d, _ in decos],
                                 "async": any(c.type == "async" for c in node.children)}
                    for dtxt, dline in decos:
                        kind = ("route" if any(f".{v}(" in dtxt for v in _ROUTE_DECOS)
                                else "cli" if _CLI_DECO.search(dtxt)
                                else "task" if _TASK_DECO.search(dtxt) else None)
                        if kind:
                            entries.append({"kind": "entry", "def": did, "entry_kind": kind, "via": dtxt,
                                            "f": f, "line": dline})
                enclosing = did
                classes = ()
        elif t in ("import_statement", "import_from_statement"):
            for line, module, level in _imports_of(src, node, rel):
                target = next((pos[c] for c in _module_candidates(module, rel, level) if c in pos), None)
                imports.append({"kind": "module_import", "f": f, "line": line,
                                "module": "." * level + module, "target_f": target})
        elif t == "if_statement" and enclosing is None and guard is None:
            cond = node.child_by_field_name("condition")
            if cond is not None and _MAIN_GUARD.search(_text(src, cond)):
                guard = _text(src, node).splitlines()[0][:DECORATOR_MAX]
        elif t == "call":
            callee = _callee(src, node)
            if callee:
                line = node.start_point[0] + 1
                if enclosing is not None:
                    calls.setdefault((enclosing, callee), line)
                else:
                    module_calls.append({"kind": "module_call", "f": f, "line": line, "callee": callee})
                    if guard is not None:
                        main_calls.append((f, callee, line, guard))
        for c in node.children:
            walk(c, src, rel, f, classes, enclosing, guard)

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
        walk(tree.root_node, src, rel, pos[rel], (), None, None)

    by_name: Dict[str, set] = collections.defaultdict(set)
    for d in defs.values():
        by_name[d["name"]].add(d["id"])
    call_records = []
    for (frm, callee), line in calls.items():
        targets, certain = _resolve_callee(callee, frm.rsplit(QSEP, 1)[0], by_name)
        call_records.append({"kind": "call", "from": frm, "callee": callee, "line": line,
                             "targets": list(targets), "certain": certain})
    for f, callee, line, guard in main_calls:
        rel = rels[f]
        same = sorted(i for i in by_name.get(callee, ()) if i.startswith(rel + QSEP))
        for did in same or sorted(by_name.get(callee, ())):
            entries.append({"kind": "entry", "def": did, "entry_kind": "main", "via": guard, "f": f, "line": line})

    header["parse_failures"] = sorted(failures, key=lambda x: x["file"])
    records = (sorted(defs.values(), key=lambda r: (r["f"], r["line"], r["id"]))
               + sorted({(e["def"], e["entry_kind"], e["via"], e["f"], e["line"]): e for e in entries}.values(),
                        key=lambda r: (r["def"], r["entry_kind"], r["line"], r["via"]))
               + sorted(module_calls, key=lambda r: (r["f"], r["line"], r["callee"]))
               + sorted(call_records, key=lambda r: (r["from"], r["callee"]))
               + sorted(imports, key=lambda r: (r["f"], r["line"], r["module"])))
    header["records"] = records
    return header


def _sha1(path: Path) -> str:
    try:
        return hashlib.sha1(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def graph_from_index(doc: Dict[str, Any], *, entry_kinds: Optional[Tuple[str, ...]] = None
                     ) -> Optional[Dict[str, Any]]:
    """The `{defs, reach, entries, files}` graph `code_verdict` reads, from a stored callgraph.v1 document, with
    `reach` recomputed by the same BFS as `build_callgraph`. None when the document has no parsed Python
    (`languages.python != "parsed"`). `entry_kinds` limits the entries (default: every kind)."""
    if (doc.get("languages") or {}).get("python") != "parsed":
        return None
    files = doc.get("files") or []
    defs: Dict[str, Tuple[str, int, int, str]] = {}
    calls: Dict[str, set] = collections.defaultdict(set)
    by_name: Dict[str, set] = collections.defaultdict(set)
    entries: set = set()
    for r in doc.get("records") or ():
        k = r.get("kind")
        if k == "def":
            defs[r["id"]] = (files[r["f"]], r["line"], r["end_line"], r["name"])
            by_name[r["name"]].add(r["id"])
        elif k == "call":
            calls[r["from"]].add(r["callee"])
        elif k == "entry" and (entry_kinds is None or r["entry_kind"] in entry_kinds):
            entries.add(r["def"])
    entries &= set(defs)
    return {"defs": defs, "reach": _bfs(entries, calls, by_name), "entries": entries,
            "files": len(files) - sum(1 for p in doc.get("parse_failures") or () if p.get("reason") != "syntax_error")}
