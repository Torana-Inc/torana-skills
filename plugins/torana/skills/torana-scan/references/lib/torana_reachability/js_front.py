"""The JavaScript / TypeScript front end of the one call graph: the parser, the file set, and what an
import statement BINDS.

⭐ WHY THIS IS A FRONT END AND NOT A SECOND CALL GRAPH. `callgraph.build_callgraph_index` emits records
whose kinds are language-neutral (`def`, `entry`, `module_import`, `module_call`, `lib_call`, `lib_ref`,
`class_base`) into a document whose `languages` header is a MAP, not a flag. So another language is another
front end over the same walk feeding the same document, read by the same two readers — never a parallel graph
that could disagree with the Python one about the same tree.

⛔ THE TWO READERS NEED DIFFERENT THINGS, AND ONLY ONE OF THEM IS SAFE TODAY.
  · `api_diff_check.intersect` reads `module_import` / `lib_call` / `lib_ref` / `class_base` and NEVER an
    `entry` or `reach`. Bindings alone answer it, so npm comes off word matching the moment they land.
  · `callgraph.graph_from_index` → the SAST reachability lane needs `entry` records and a BFS. JS entry
    points have no closed form (an Express route is `app.get('/x', h)` — a call, with `app` named anything;
    a Next.js entry is a FILENAME; a `bin` is a package.json pointer; a React component is an entry only by
    being mounted), and a MISSED entry reads as `no_path` — an absence asserted from an incomplete grammar.
    So this module claims bindings, not reachability, and the SAST lane keeps saying `inconclusive` for JS
    until a framework's entries are enumerated and that coverage is recorded in the document.

⚠️ THE ERROR DIRECTIONS ARE NOT SYMMETRIC (`grammar.py`'s rule, restated because it decides every doubt
here): over-matching a binding yields a hit, which records and moves nothing; under-matching yields
`not_imported`, which can lower a live finding. When a shape is ambiguous, bind it.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

#: Which grammar reads which extension. ⛔ `tree_sitter_typescript` is ONE wheel exposing TWO languages:
#: `.tsx` read with the `.ts` parser does not parse, and a file that fails to parse contributes no bindings
#: — the under-match direction. Keyed by extension so the caller never has to know that.
_EXT_GRAMMAR = {
    ".js": ("tree_sitter_javascript", "language"),
    ".jsx": ("tree_sitter_javascript", "language"),      # the javascript grammar parses JSX
    ".mjs": ("tree_sitter_javascript", "language"),
    ".cjs": ("tree_sitter_javascript", "language"),
    ".ts": ("tree_sitter_typescript", "language_typescript"),
    ".tsx": ("tree_sitter_typescript", "language_tsx"),
}

#: Extensions this front end can read, in `grammar.py::_SOURCE_EXTS["npm"]` order.
JS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

_PARSERS: Dict[str, Any] = {}


def _scan_pack_site_packages() -> Optional[str]:
    """The scan pack's site-packages for THIS interpreter, or None. Deferred to `callgraph` so the two
    front ends cannot drift about where the installer put a grammar (or about the minor-version match)."""
    from .callgraph import _scan_pack_site_packages as sp
    return sp()


def js_parser(ext: str = ".js"):
    """A tree-sitter parser for one JS/TS extension, or None. Cached per extension.

    Same cost order and the same ⭐ reasoning as `callgraph.python_parser`: the two small pinned wheels
    first, `tree_sitter_language_pack` only as the fallback a runner may already have.
    """
    ext = ext.lower()
    if ext in _PARSERS:
        return _PARSERS[ext]
    pair = _EXT_GRAMMAR.get(ext)
    if pair is None:
        return None
    module, factory = pair
    sp = _scan_pack_site_packages()
    if sp and sp not in sys.path:
        sys.path.append(sp)       # APPEND: never shadow a package the runner already has
    parser = None
    try:
        from tree_sitter import Language, Parser
        grammar = __import__(module)
        parser = Parser(Language(getattr(grammar, factory)()))
    except Exception:             # noqa: BLE001 — any failure here means "not available"
        try:
            from tree_sitter_language_pack import get_parser
            parser = get_parser("tsx" if ext == ".tsx" else
                                "typescript" if ext == ".ts" else "javascript")
        except Exception:         # noqa: BLE001
            parser = None
    _PARSERS[ext] = parser
    return parser


def parser_remedy() -> str:
    """What to DO about a missing JS grammar. Shares `callgraph`'s two causes (wrong interpreter vs not
    installed) and only renames the engine, so one message cannot say install while the other says re-run."""
    from .callgraph import parser_remedy as py_remedy
    return py_remedy().replace("--engines tree-sitter ", "--engines tree-sitter-javascript,tree-sitter-typescript ")


class JsBind(NamedTuple):
    """What one import binds one name to — `callgraph._Bind` plus the two facts JS adds.

    `how`:
      · `import`    — the specifier itself is the bound name (no JS form produces this today; kept so a
                      shared emitter can accept either language's binding without a branch)
      · `import_as` — the bound name IS the module: `import * as x from 'm'`, `const x = require('m')`,
                      `const x = await import('m')`, `import x = require('m')` (TS)
      · `from`      — the bound name is one EXPORT of the module; `name` is the real exported name, with
                      `default` for a default import
      · `reexport`  — `export { n } from 'm'`: nothing is bound in this file, but forwarding a name is a
                      real use of it, and it breaks at import if the package drops it. The pair's key is
                      what the outside sees, `name` is what the package is asked for.
    `level`: Python's relative-import dots, carried over. 0 = the specifier is a PACKAGE name (what the
    npm ecosystem's `_ABSENCE` rule and `api_diff_check.npm_subpath` read); non-zero = first-party in this
    tree, `./x` -> 1, `../x` -> 2, matching `from . import x` / `from .. import x`.
    `type_only`: a TypeScript type-only import or re-export. NOT a runtime use, so the consumer must be
    able to tell — recorded with the flag rather than dropped, because a removed type still breaks a build.
    """
    how: str
    module: str
    level: int
    name: Optional[str]
    type_only: bool


def _text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _unquote(text: str) -> str:
    """An ES2022 arbitrary module namespace name (`{ 'weird-name' as W }`) arrives quoted; the package
    exports it unquoted."""
    if len(text) > 1 and text[0] in "'\"`" and text[-1] == text[0]:
        return text[1:-1]
    return text


def _specifier_level(spec: str) -> int:
    """0 for a package specifier, else the relative depth. `/abs` is treated as relative (level 1): it is
    not a package name, and calling it one would attribute a file to a dependency that does not exist."""
    if spec.startswith("./"):
        return 1
    if spec.startswith("../"):
        return 1 + sum(1 for part in spec.split("/") if part == "..")
    if spec.startswith("/") or spec in (".", ".."):
        return 1
    return 0


def _source_string(src: bytes, node) -> Optional[str]:
    """The module specifier of an `import`/`export` statement, or None when it has no `source:` — which is
    what separates `export { n } from 'm'` from a local `export { n }`, a statement that names no module."""
    s = node.child_by_field_name("source")
    if s is None:
        return None
    for c in s.children:
        if c.type == "string_fragment":
            return _text(src, c)
    return _text(src, s).strip("'\"`")


def _has_type_keyword(node) -> bool:
    """A TS `type` modifier, which tree-sitter exposes as an UNNAMED child — on the statement for
    `import type { X } from 'm'`, and on the specifier for `import { type X, y } from 'm'`."""
    return any(not c.is_named and c.type == "type" for c in node.children)


def _named_import_pairs(src: bytes, clause, module: str, level: int, stmt_type_only: bool,
                        how: str, name_field: str, alias_field: str) -> List[Tuple[str, JsBind]]:
    """`{ a, b as c }` for both `import_specifier` (name/alias) and `export_specifier` (name/alias).

    ⚠️ `name:` IS ALWAYS POPULATED, including where the s-expression does not show it: for `{ default as E }`
    it is the unnamed keyword token `default`, and for ES2022's `{ 'weird-name' as W }` it is the string
    literal WITH ITS QUOTES — which is why the real name is unquoted here. Passing `'weird-name'` on as the
    exported name would match no symbol, and a name that matches nothing is the under-match direction."""
    out = []
    for spec in clause.children:
        if not spec.is_named or not spec.type.endswith("_specifier"):
            continue
        type_only = stmt_type_only or _has_type_keyword(spec)
        nm = spec.child_by_field_name(name_field)
        alias = spec.child_by_field_name(alias_field)
        if nm is None:                               # no shape produces this; a future one must not
            continue                                 # be read as "binds nothing" by accident
        real = _unquote(_text(src, nm))
        local = _text(src, alias) if alias is not None else real
        out.append((local, JsBind(how, module, level, real, type_only)))
    return out


def _import_statement(src: bytes, node) -> List[Tuple[int, str, int, List[Tuple[str, JsBind]]]]:
    """`import …` and the TS `import x = require('m')`."""
    module = _source_string(src, node)
    clause = next((c for c in node.children if c.type == "import_require_clause"), None)
    if clause is not None:                       # TS: import x = require('m')
        module = _source_string(src, clause)
        ident = next((c for c in clause.children if c.type == "identifier"), None)
        if module is None or ident is None:
            return []
        lvl = _specifier_level(module)
        return [(node.start_point[0] + 1, module, lvl,
                 [(_text(src, ident), JsBind("import_as", module, lvl, None, False))])]
    if module is None:
        return []
    lvl = _specifier_level(module)
    type_only = _has_type_keyword(node)
    binds: List[Tuple[str, JsBind]] = []
    for clause in (c for c in node.children if c.type == "import_clause"):
        for c in clause.children:
            if c.type == "identifier":                       # default: import x from 'm'
                binds.append((_text(src, c), JsBind("from", module, lvl, "default", type_only)))
            elif c.type == "namespace_import":               # import * as x from 'm'
                ident = next((g for g in c.children if g.type == "identifier"), None)
                if ident is not None:
                    binds.append((_text(src, ident), JsBind("import_as", module, lvl, None, type_only)))
            elif c.type == "named_imports":                   # import { a, b as c } from 'm'
                binds += _named_import_pairs(src, c, module, lvl, type_only, "from", "name", "alias")
    return [(node.start_point[0] + 1, module, lvl, binds)]


def _export_statement(src: bytes, node) -> List[Tuple[int, str, int, List[Tuple[str, JsBind]]]]:
    """`export … from 'm'` only. ⛔ A local `export { n }` has no `source:` and names NO module; counting
    it would invent a dependency the file does not have."""
    module = _source_string(src, node)
    if module is None:
        return []
    lvl = _specifier_level(module)
    type_only = _has_type_keyword(node)
    binds: List[Tuple[str, JsBind]] = []
    for clause in (c for c in node.children if c.type == "export_clause"):
        binds += _named_import_pairs(src, clause, module, lvl, type_only, "reexport", "name", "alias")
    return [(node.start_point[0] + 1, module, lvl, binds)]


def _require_specifier(src: bytes, value) -> Optional[str]:
    """The module of `require('m')`, `import('m')` or `await import('m')`, or None if `value` is neither.

    `require` is NOT a node type — it is a `call_expression` whose `function` is an identifier with that
    text — while a dynamic `import('m')` has an `import` function node. Both are ordinary expressions, so
    they are legal anywhere, which is why the walk below does not stop at the top level."""
    if value is None:
        return None
    if value.type == "await_expression":
        inner = next((c for c in value.children if c.is_named), None)
        return _require_specifier(src, inner)
    if value.type != "call_expression":
        return None
    fn = value.child_by_field_name("function")
    if fn is None:
        return None
    if not (fn.type == "import" or (fn.type == "identifier" and _text(src, fn) == "require")):
        return None
    args = value.child_by_field_name("arguments")
    if args is None:
        return None
    for a in args.children:
        if a.type == "string":
            for g in a.children:
                if g.type == "string_fragment":
                    return _text(src, g)
    return None


def _declarator(src: bytes, node) -> List[Tuple[int, str, int, List[Tuple[str, JsBind]]]]:
    """One `variable_declarator`: `const x = require('m')` or `const { a, b: c } = require('m')`.

    ⚠️ IN AN OBJECT PATTERN THE ROLES INVERT vs `import { a as b }`: `key` is the real exported name and
    `value` is the local one. Reading them the other way round binds a name the package never exported and
    leaves the real use unseen."""
    module = _require_specifier(src, node.child_by_field_name("value"))
    if module is None:
        return []
    lvl = _specifier_level(module)
    target = node.child_by_field_name("name")
    binds: List[Tuple[str, JsBind]] = []
    if target is not None and target.type == "identifier":
        binds.append((_text(src, target), JsBind("import_as", module, lvl, None, False)))
    elif target is not None and target.type == "object_pattern":
        for c in target.children:
            if c.type == "shorthand_property_identifier_pattern":        # { init }
                n = _text(src, c)
                binds.append((n, JsBind("from", module, lvl, n, False)))
            elif c.type == "pair_pattern":                                # { init: go }
                key, val = c.child_by_field_name("key"), c.child_by_field_name("value")
                if key is not None and val is not None:
                    binds.append((_text(src, val), JsBind("from", module, lvl, _text(src, key), False)))
    return [(node.start_point[0] + 1, module, lvl, binds)]


def js_imports_of(src: bytes, node) -> List[Tuple[int, str, int, List[Tuple[str, JsBind]]]]:
    """`(line, module, level, [(bound name, JsBind)])` for ONE statement node, mirroring
    `callgraph._imports_of`. `[]` when the node is not an import of any shape."""
    if node.type == "import_statement":
        return _import_statement(src, node)
    if node.type == "export_statement":
        return _export_statement(src, node)
    if node.type == "variable_declarator":
        return _declarator(src, node)
    return []


def js_imports_in(src: bytes, root) -> List[Tuple[int, str, int, List[Tuple[str, JsBind]]]]:
    """Every import in a whole tree, in source order.

    ⛔ WALKS THE WHOLE TREE, not just the top level. `import` is top-level-only but `require` and dynamic
    `import()` are ordinary calls, and a lazy `require` inside a request handler is exactly where a heavy
    dependency gets loaded — the use most worth seeing."""
    out: List[Tuple[int, str, int, List[Tuple[str, JsBind]]]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        out += js_imports_of(src, node)
        stack.extend(reversed(node.children))
    # A bare `import('m').then(...)` is a module use that binds nothing and sits inside an expression, so
    # it is not reached by any of the statement shapes above.
    stack = [root]
    seen = {(line, mod) for line, mod, _lvl, _b in out}
    while stack:
        node = stack.pop()
        if node.type == "call_expression" and node.parent is not None \
                and node.parent.type != "await_expression" \
                and (node.parent.type != "variable_declarator"):
            mod = _require_specifier(src, node)
            line = node.start_point[0] + 1
            if mod is not None and (line, mod) not in seen:
                out.append((line, mod, _specifier_level(mod), []))
                seen.add((line, mod))
        stack.extend(reversed(node.children))
    out.sort(key=lambda r: (r[0], r[1]))
    return out


def js_files(repo: str | os.PathLike) -> List[str]:
    """Every JS/TS source file under `repo`, repo-relative and sorted — the npm analogue of
    `callgraph._py_files`.

    ⛔ SAME WALKER, so one tree cannot become two file sets. `paths.walk_files` is what decides what counts
    as this repository's code: inside a git work tree only the files git would ship, never a gitignored
    build output, never `node_modules`, never a symlink out of the tree. A hand-rolled rglob here would
    have read every vendored copy under `node_modules` as first-party source."""
    from .paths import walk_files
    return sorted(f for f in walk_files(repo) if f.lower().endswith(JS_EXTS))


# ── the npm records (INDEX_FORMAT 5) ────────────────────────────────────────────────────────────────

#: A reference at file scope, not inside a function — the `<module>` of a `from` id. Same spelling as
#: `callgraph.MODULE_SCOPE` so one reader can split either language's `from` on `::` and get a file.
MODULE_SCOPE = "<module>"

#: ⛔ THE SAME SEPARATOR AS PYTHON, imported rather than re-spelled: every reader splits an id or a `from`
#: on it to get a file, and two spellings of `::` would make one of them silently wrong.
QSEP = "::"

#: A stored `callee_text` carries identifiers and dots only, so it can never hold a literal — the same
#: constraint the schema puts on the Python side.
_CALLEE_TEXT_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")

#: Node types that own a scope for the purposes of a `from` id.
_SCOPED = frozenset({"function_declaration", "generator_function_declaration", "method_definition",
                     "class_declaration", "function_expression", "arrow_function", "class"})

#: Node types that own a scope for the purposes of a `from` id — see `_SCOPED` above.


def _scope_of(node, synthetic: Optional[Dict[Tuple[int, int], str]] = None) -> str:
    """The nearest enclosing named function, method or class, else `<module>`.

    ⛔ `synthetic` MAPS AN ANONYMOUS FUNCTION'S SPAN TO A NAME, and it is not optional for reachability.
    An inline route handler — `app.get('/x', (req, res) => { work(); })` — is anonymous, so without this
    the call to `work` is attributed to `<module>` while the ENTRY points at the handler's synthetic def.
    The entry then has no outgoing edge, the BFS reaches nothing, and every function behind a route reads
    as `no_path_from_entry_point`. MEASURED as a test failure before this argument existed.

    ⚠️ For the `lib_call` / `lib_ref` records the scope is best effort only: `api_diff_check` reads
    `from.split("::")[0]`, the FILE, so an approximate scope name cannot move an API-diff verdict."""
    cur = node.parent
    while cur is not None:
        if synthetic:
            nm = synthetic.get((cur.start_byte, cur.end_byte))
            if nm is not None:
                return nm
        if cur.type in _SCOPED:
            nm2 = cur.child_by_field_name("name")
            if nm2 is not None:
                return nm2.text.decode("utf-8", "replace")
        cur = cur.parent
    return MODULE_SCOPE


def _binding_spans(src: bytes, root) -> List[Tuple[int, int]]:
    """The byte spans that NAME a binding rather than use it — skipped by the use walk.

    ⛔ THIS IS NOT "every import or export statement". `export function draw() { echarts.init(el) }` is an
    `export_statement` whose body is ordinary code, and skipping the statement skipped the call inside it.
    Only three things are binding sites: an `import` statement (which holds no code), an `export … from`
    (a re-export, which holds no code either — a local `export` has no `source` and is not one), and the
    NAME side of a `const x = require('m')`, where the identifier is the binding being created.
    Counting a binding site as a use would report a library call at every import line."""
    spans: List[Tuple[int, int]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "import_statement":
            spans.append((node.start_byte, node.end_byte))
        elif node.type == "export_statement" and node.child_by_field_name("source") is not None:
            spans.append((node.start_byte, node.end_byte))
        elif node.type == "variable_declarator" and _require_specifier(src, node.child_by_field_name("value")):
            nm = node.child_by_field_name("name")
            if nm is not None:
                spans.append((nm.start_byte, nm.end_byte))
    return spans


def _in_spans(node, spans: List[Tuple[int, int]]) -> bool:
    return any(a <= node.start_byte and node.end_byte <= b for a, b in spans)


def _same(a, b) -> bool:
    """⛔ NEVER `is`. tree-sitter hands back a NEW Python object for the same node on every access, so
    `parent.child_by_field_name("object") is node` is always False and every member-access use goes
    unrecorded — a whole class of library call silently missing. Node ids are stable; the objects are not."""
    return a is not None and b is not None and a.id == b.id


class _Use(NamedTuple):
    kind: str          # "lib_call" | "lib_ref"
    module: str
    attr: str
    line: int
    scope: str
    store: bool


def _binding_table(src: bytes, root) -> Tuple[Dict[str, JsBind], List[Tuple[int, str, int, List[Tuple[str, JsBind]]]]]:
    """`{local name: JsBind}` for the PACKAGE imports of one file, plus every import the file makes.

    ⚠️ ONE FLAT TABLE PER FILE, so a local variable that reuses an imported name is still resolved to the
    package. That over-matches, which yields an extra hit a reviewer skims; the alternative — real scope
    analysis — risks dropping a use, and a dropped use is what makes an upgrade look safe when it is not.
    ⛔ RELATIVE SPECIFIERS ARE EXCLUDED (`level != 0`): `./core` is this tree's own file, and attributing it
    to a package named `core` is how a first-party call becomes a false library call."""
    imports = js_imports_in(src, root)
    table: Dict[str, JsBind] = {}
    for _line, _module, level, pairs in imports:
        if level != 0:
            continue
        for name, bind in pairs:
            table[name] = bind
    return table, imports


def _uses_in(src: bytes, root, table: Dict[str, JsBind], spans: List[Tuple[int, int]]) -> List[_Use]:
    """Every call of, and reference to, a package-bound name in one file.

    How a binding turns into a (module, attr) pair:
      · `import_as` (`import * as e from 'echarts'`, `const e = require('echarts')`) — the bound name IS the
        module, so the ATTRIBUTE comes from the member access: `e.init()` -> attr `init`.
      · `from` (`import { init } from 'echarts/core'`) — the bound name is already the export, so the attr is
        the REAL exported name, never the local alias. A member access on it (`init.extend`) is recorded as
        BOTH a reference to `init` and a call of `init.extend`: you cannot reach the member without the export,
        and over-recording here is the safe direction.
      · `reexport` — nothing is bound locally, so there is no use to walk; the forward itself is the use and is
        reported by the `module_import` record.
    """
    out: List[_Use] = []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "identifier" or _in_spans(node, spans):
            continue
        local = node.text.decode("utf-8", "replace")
        bind = table.get(local)
        if bind is None or bind.how == "reexport":
            continue
        parent = node.parent
        if parent is None:
            continue
        # the name is the OBJECT of a member access: `local.attr`
        if parent.type == "member_expression" and _same(parent.child_by_field_name("object"), node):
            prop = parent.child_by_field_name("property")
            member = prop.text.decode("utf-8", "replace") if prop is not None else ""
            gp = parent.parent
            called = (gp is not None and gp.type == "call_expression"
                      and _same(gp.child_by_field_name("function"), parent))
            stored = (gp is not None and gp.type == "assignment_expression"
                      and _same(gp.child_by_field_name("left"), parent))
            line, scope = node.start_point[0] + 1, _scope_of(node)
            if bind.how == "import_as":
                out.append(_Use("lib_call" if called else "lib_ref", bind.module, member, line, scope, stored))
            else:
                attr = bind.name or ""
                out.append(_Use("lib_ref", bind.module, attr, line, scope, stored))
                if called and member:
                    out.append(_Use("lib_call", bind.module, f"{attr}.{member}", line, scope, False))
            continue
        # the name itself is called: `local(...)`
        if parent.type == "call_expression" and _same(parent.child_by_field_name("function"), node):
            attr = "" if bind.how == "import_as" else (bind.name or "")
            out.append(_Use("lib_call", bind.module, attr, node.start_point[0] + 1, _scope_of(node), False))
            continue
        # any other mention: a reference
        attr = "" if bind.how == "import_as" else (bind.name or "")
        stored = (parent.type == "assignment_expression"
                  and _same(parent.child_by_field_name("left"), node))
        out.append(_Use("lib_ref", bind.module, attr, node.start_point[0] + 1, _scope_of(node), stored))
    return out


def js_file_records(src: bytes, root, rel: str, f: int, table: Optional[Dict[str, JsBind]] = None,
                    imports: Optional[List[Tuple[int, str, int, List[Tuple[str, JsBind]]]]] = None
                    ) -> List[Dict[str, Any]]:
    """Every npm record for ONE parsed file, in the document's field shapes.

    `module` is the SPECIFIER as written (`echarts/core`), not a subpath: the record stays faithful to the
    source and `api_diff_check` converts it with `npm_subpath` at the join, which is the one place that
    already knows a diff's symbols are `./core#member`."""
    if table is None or imports is None:
        table, imports = _binding_table(src, root)
    records: List[Dict[str, Any]] = []
    for line, module, level, pairs in imports:
        if level != 0:
            continue                                     # first-party; no reader resolves JS targets yet
        rec: Dict[str, Any] = {"kind": "module_import", "f": f, "line": line, "module": module,
                               "target_f": None}
        local = [n for n, _b in pairs]
        if local:
            rec["binds"] = local
        members = [{"name": b.name, "as": n} for n, b in pairs if b.how in ("from", "reexport") and b.name]
        if members:
            rec["from_import"] = members
        records.append(rec)
    calls: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}
    refs: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for u in _uses_in(src, root, table, _binding_spans(src, root)):
        frm = f"{rel}::{u.scope}"
        if u.kind == "lib_call":
            key = (frm, u.module, u.attr, u.line)
            calls.setdefault(key, {"kind": "lib_call", "from": frm, "module": u.module,
                                   "attr": u.attr[:200], "line": u.line})
        else:
            key2 = (frm, u.module, u.attr)
            cur = refs.get(key2)
            if cur is None:
                refs[key2] = {"kind": "lib_ref", "from": frm, "module": u.module, "attr": u.attr[:200],
                              "line": u.line, "sites": 1, "store": u.store}
            else:
                cur["sites"] += 1
                cur["line"] = min(cur["line"], u.line)
                cur["store"] = cur["store"] or u.store
    records += sorted(calls.values(), key=lambda r: (r["from"], r["line"], r["module"], r["attr"]))
    records += sorted(refs.values(), key=lambda r: (r["from"], r["module"], r["attr"]))
    return records


def js_block(root_dir: str | os.PathLike, walked: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """The document's `npm` block: `{language, files, file_sha, parse_failures, entry_coverage, records}`.

    ⛔ WHY npm GETS ITS OWN `files` LIST INSTEAD OF JOINING THE DOCUMENT'S. `api_diff_check._shadowed_modules`
    treats EVERY path segment of `callgraph["files"]` as a module name this tree owns, and blinds a pypi check
    whose package shares one. MEASURED 2026-10-27 on a 1390-file Angular tree: its JS directories contribute
    the segments `core`, `models` and `types`, so merging the lists would newly report `module_shadowed_in_tree`
    for any pypi package imported under one of those names — a pypi answer lost to adding npm coverage. A list
    of its own also keeps every `f` index in this block unambiguous, and leaves `graph_from_index`'s file
    count exact.

    ⭐ TWO PASSES, because resolution is a whole-tree question. Pass 1 parses every file and collects its
    `def` records; pass 2 emits the records that need to know what the rest of the tree defines (`call`
    targets, a route handler imported from another file). One parse per file either way: the trees from
    pass 1 are kept.
    """
    from pathlib import Path

    from .callgraph import _sha1
    from .paths import walk_files
    base = Path(root_dir)
    # ⛔ ONE WALK PER DOCUMENT. `paths.walk_files` runs `git_visible_files`, a git SUBPROCESS, so a second
    # walk here doubled it for every call graph built — measured as the library's own suite going from 30s
    # to 156s. The caller that already walked the tree hands the list over.
    paths = list(walked) if walked is not None else list(walk_files(base))
    rels = sorted(f for f in paths if f.lower().endswith(JS_EXTS))
    manifests = [f for f in paths if f.rsplit("/", 1)[-1] == "package.json"]
    declared = declared_npm_packages(base, manifests)
    block: Dict[str, Any] = {"language": "absent" if not rels else "parsed", "files": rels,
                             "file_sha": [], "parse_failures": [], "records": []}
    if not rels:
        block["entry_coverage"] = entry_coverage(declared, set())
        return block
    block["file_sha"] = [_sha1(base / r) for r in rels]
    if all(js_parser(Path(r).suffix) is None for r in rels):
        block["language"] = "parser_missing"
        block["entry_coverage"] = entry_coverage(declared, set())
        return block

    # ── pass 1: parse, and collect every named definition ──────────────────────────────────────────
    parsed: List[Tuple[int, str, bytes, Any]] = []
    defs: List[Dict[str, Any]] = []
    for f, rel in enumerate(rels):
        parser = js_parser(Path(rel).suffix)
        if parser is None:
            block["parse_failures"].append({"file": rel, "reason": "parser_missing"})
            continue
        try:
            src = (base / rel).read_bytes()
        except OSError as exc:
            block["parse_failures"].append({"file": rel, "reason": f"unreadable: {type(exc).__name__}"})
            continue
        tree_root = parser.parse(src).root_node
        if tree_root.has_error:
            # ⚠️ RECORDED, AND THE FILE IS STILL READ. tree-sitter's error node is local, so the imports
            # outside it are real; what must never happen is a parse error read as "this file imports
            # nothing". MEASURED: 4 of one 1390-file tree, all on the TS `import()` type annotation.
            block["parse_failures"].append({"file": rel, "reason": "syntax_error"})
        parsed.append((f, rel, src, tree_root))
        defs += js_defs_of(src, tree_root, rel, f)

    file_set = set(rels)
    defs_by_name: Dict[str, List[str]] = {}
    for d in defs:
        defs_by_name.setdefault(d["name"], []).append(d["id"])
    defs_by_id = {d["id"] for d in defs}

    # ── pass 2: the records that need the whole tree ───────────────────────────────────────────────
    lib_records: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []
    entries: List[Dict[str, Any]] = []
    frameworks: set = set()
    for f, rel, src, tree_root in parsed:
        pkg_table, file_imports = _binding_table(src, tree_root)
        fp_binds = _first_party_binds(src, tree_root, rel, file_set)
        lib_records += js_file_records(src, tree_root, rel, f, pkg_table, file_imports)
        # ⛔ ENTRIES BEFORE CALLS: the entry pass is what names an inline route handler, and the call pass
        # needs that name to attribute the handler's BODY to it. Reversed, the entry has no outgoing edge.
        ents, synth, spans = js_entries_of(src, tree_root, rel, f, pkg_table, defs_by_name, defs_by_id,
                                           fp_binds)
        calls += js_calls_of(src, tree_root, rel, defs_by_name, defs_by_id, pkg_table, fp_binds, spans)
        if ents:
            frameworks.add("express")
        entries += ents
        defs += synth
        for d in synth:
            defs_by_id.add(d["id"])

    block["entry_coverage"] = entry_coverage(declared, frameworks)
    block["records"] = (sorted(defs, key=lambda r: (r["f"], r["line"], r["id"]))
                        + sorted(entries, key=lambda r: (r["def"], r["line"], r["via"]))
                        + sorted(calls, key=lambda r: (r["from"], r["callee"]))
                        + lib_records)
    return block


# ── def and call records (INDEX_FORMAT 5, build item 1 step 5) ───────────────────────────────────────

#: A callable VALUE: what a declarator, pair or default export has to hold to be a definition.
_FN_VALUE = frozenset({"arrow_function", "function_expression", "generator_function"})
#: A callable DECLARATION: named where it stands.
_FN_DECL = frozenset({"function_declaration", "generator_function_declaration", "method_definition"})
#: The extensions a relative specifier may resolve to, in resolution order (Node's own order, `.ts`/`.tsx`
#: appended because a TS tree imports `./x` and ships `x.ts`).
_RESOLVE_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _own_name(src: bytes, node) -> Optional[str]:
    """The name a callable node is known by where it stands, or None when it is anonymous.

    The six routes, all measured against the grammar: a `function_declaration`'s `name`; a
    `method_definition`'s `name` (a `property_identifier`, in a class body OR an object literal); a
    `variable_declarator` whose value is a function; a `pair` whose value is a function (`{ n: () => 1 }`);
    `export default function named()`, which is an ordinary declaration under an `export_statement`; and
    `export default` of an anonymous function, which is named `default` because that IS the name importers
    use (`import x from './m'` binds this)."""
    if node.type in _FN_DECL:
        nm = node.child_by_field_name("name")
        return _node_text(src, nm) if nm is not None else None
    if node.type in _FN_VALUE:
        parent = node.parent
        if parent is None:
            return None
        if parent.type == "variable_declarator":
            nm = parent.child_by_field_name("name")
            return _node_text(src, nm) if nm is not None and nm.type == "identifier" else None
        if parent.type == "pair":
            key = parent.child_by_field_name("key")
            return _node_text(src, key) if key is not None else None
        if parent.type == "export_statement" and _same(parent.child_by_field_name("value"), node):
            return "default"
    return None


def _qual_prefix(src: bytes, node) -> List[str]:
    """The dotted prefix a definition hangs under: enclosing classes, enclosing named functions, and the
    variable an object literal was assigned to (`const o = { m() {} }` -> `o.m`)."""
    parts: List[str] = []
    cur = node.parent
    while cur is not None:
        if cur.type in ("class_declaration", "class"):
            nm = cur.child_by_field_name("name")
            if nm is not None:
                parts.append(_node_text(src, nm))
        elif cur.type in _FN_DECL or cur.type in _FN_VALUE:
            own = _own_name(src, cur)
            if own is not None:
                parts.append(own)
        elif cur.type == "object":
            holder = cur.parent
            if holder is not None and holder.type == "variable_declarator":
                nm = holder.child_by_field_name("name")
                if nm is not None and nm.type == "identifier":
                    parts.append(_node_text(src, nm))
        cur = cur.parent
    return list(reversed(parts))


def _is_async(node) -> bool:
    return any(not c.is_named and c.type == "async" for c in node.children)


def js_defs_of(src: bytes, root, rel: str, f: int) -> List[Dict[str, Any]]:
    """Every NAMED callable in one file, as `def` records with ids `<path>::<qualname>`.

    ⚠️ AN ANONYMOUS CALLABLE IS NOT A DEF. `arr.map(x => x * 2)` has no name, so nothing can call it by
    name and it can never be a resolution target; emitting it would add a node no edge can reach and make
    the def count read as coverage it is not. Python's walk does the same (it emits `def`/`class` only)."""
    out: List[Dict[str, Any]] = []
    seen: set = set()
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _FN_DECL and node.type not in _FN_VALUE:
            continue
        name = _own_name(src, node)
        if name is None:
            continue
        qual = ".".join(_qual_prefix(src, node) + [name])
        did = f"{rel}{QSEP}{qual}"
        if did in seen:
            continue
        seen.add(did)
        out.append({"kind": "def", "id": did, "f": f, "line": node.start_point[0] + 1,
                    "end_line": node.end_point[0] + 1, "name": name, "decorators": [],
                    "async": _is_async(node)})
    return sorted(out, key=lambda r: (r["line"], r["id"]))


def _resolve_relative(spec: str, from_rel: str, files: set) -> Optional[str]:
    """`./bar` in `src/a.js` -> `src/bar.js`, or `src/bar/index.js`, or None.

    ⛔ A MISS RESOLVES TO NOTHING RATHER THAN TO A GUESS. An edge to a file that does not exist is an edge
    the BFS can follow to a node no reader can open."""
    from posixpath import normpath
    base = from_rel.rsplit("/", 1)[0] if "/" in from_rel else ""
    target = normpath(f"{base}/{spec}" if base else spec).lstrip("./")
    if target in files:
        return target
    for ext in _RESOLVE_EXTS:
        if target + ext in files:
            return target + ext
    for ext in _RESOLVE_EXTS:
        if f"{target}/index{ext}" in files:
            return f"{target}/index{ext}"
    return None


def _first_party_binds(src: bytes, root, rel: str, files: set) -> Dict[str, Tuple[str, str]]:
    """`{local name: (target file, real exported name)}` for this file's RELATIVE imports — the precise
    half of call resolution. A name imported from `./bar` has exactly one definition, so the edge is
    certain; a bare name resolved across the tree is not."""
    out: Dict[str, Tuple[str, str]] = {}
    for _line, module, level, pairs in js_imports_in(src, root):
        if level == 0:
            continue
        target = _resolve_relative(module, rel, files)
        if target is None:
            continue
        for name, bind in pairs:
            if bind.how in ("from", "reexport") and bind.name:
                out[name] = (target, bind.name)
    return out


def js_calls_of(src: bytes, root, rel: str, defs_by_name: Dict[str, List[str]], defs_by_id: set,
                pkg_table: Dict[str, JsBind], fp_binds: Dict[str, Tuple[str, str]],
                synthetic: Optional[Dict[Tuple[int, int], str]] = None) -> List[Dict[str, Any]]:
    """`call` records for one file: one per (caller, callee name), merged, with every candidate target.

    ⛔ RESOLUTION IS THREE RULES, MOST PRECISE FIRST, and the LEAST precise is deliberately left uncertain
    rather than dropped:
      1. the name came from a relative import — exactly one definition, so `bound_target` is set and
         `edge_certain` accepts the edge;
      2. a definition of that name in THIS file — the one JS scope rule that holds without flow analysis;
      3. every definition of that name anywhere in the tree — `targets` carries them all and `certain` is
         False, which `answer` renders as "possible, not proven" with a caveat on the path.
    ⚠️ A MEMBER CALL IS MARKED `receiver: "opaque"`. `obj.handle()` resolves only by the bare name `handle`,
    and which `handle` depends on what `obj` holds at runtime. `edge_certain` already refuses an opaque
    receiver, so the edge exists for the BFS but never claims certainty — the same rule Python uses (OI-171).
    """
    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None:
            continue
        opaque = False
        if fn.type == "identifier":
            name = _node_text(src, fn)
        elif fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            if prop is None:
                continue
            name = _node_text(src, prop)
            opaque = True
        else:
            continue
        if name in pkg_table:
            continue                                   # a library call; `lib_call` already carries it
        line = node.start_point[0] + 1
        frm = f"{rel}{QSEP}{_scope_of(node, synthetic)}"
        bound = None
        if name in fp_binds:
            tf, real = fp_binds[name]
            cand = f"{tf}{QSEP}{real}"
            targets, resolution = ([cand], "bound") if cand in defs_by_id else ([], "external")
            bound = cand if targets else None
        else:
            here = [d for d in defs_by_name.get(name, ()) if d.rsplit(QSEP, 1)[0] == rel]
            targets = here or list(defs_by_name.get(name, ()))
            resolution = "name"
        if not targets:
            continue                                   # a global, a builtin, or a name defined nowhere here
        key = (frm, name)
        rec = out.get(key)
        if rec is None:
            rec = {"kind": "call", "from": frm, "callee": name, "line": line,
                   "targets": sorted(targets), "certain": False, "resolution": resolution, "sites": 1}
            if bound is not None:
                rec["bound_target"] = bound
            if opaque:
                rec["receiver"] = "opaque"
            if _CALLEE_TEXT_OK.match(name):
                rec["callee_text"] = name[:200]
            out[key] = rec
        else:
            rec["sites"] += 1
            rec["line"] = min(rec["line"], line)
            rec["targets"] = sorted(set(rec["targets"]) | set(targets))
            if opaque:
                rec["receiver"] = "opaque"
        rec["certain"] = (len(rec["targets"]) == 1 or rec.get("bound_target") is not None) \
            and "receiver" not in rec
    return sorted(out.values(), key=lambda r: (r["from"], r["callee"]))


# ── entry records and the coverage gate (INDEX_FORMAT 5, build item 1 step 6) ────────────────────────

#: HTTP verbs an Express app or Router registers a handler under. `use` is included: a mounted middleware
#: runs on every request to its path, which is an entry by the same argument a route is.
_EXPRESS_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "all", "use"})

#: Packages whose entry shapes THIS front end enumerates, by the name a tree declares them under.
#: ⛔ ADD A FRAMEWORK HERE ONLY WHEN ITS ENTRIES ARE ACTUALLY FOUND. The table is what `entry_coverage`
#: compares a tree's declared dependencies against, so a name listed here and not implemented turns an
#: incomplete entry set into a claimed-complete one — the single way this gate can produce a false
#: `no_path_from_entry_point`.
ENUMERATED_FRAMEWORKS = frozenset({"express"})

#: Packages that serve HTTP (or otherwise call into a tree's own code) whose entry shapes are NOT
#: enumerated. A tree that declares one of these cannot have a complete entry set, and the block names
#: which one, so the refusal says what is missing instead of "unsupported".
#: ⚠️ NOT an exhaustive list of web frameworks — it does not need to be. `entry_coverage` is computed from
#: what the TREE declares, so an unlisted framework is simply an unrecognised dependency; this table only
#: makes the common cases name themselves in the reason.
KNOWN_ENTRY_FRAMEWORKS = frozenset({
    "express", "koa", "fastify", "@hapi/hapi", "hapi", "restify", "next", "nuxt", "@nestjs/core",
    "@sveltejs/kit", "remix", "@remix-run/node", "apollo-server", "@apollo/server", "aws-lambda",
    "serverless-http", "express-ws", "socket.io", "@angular/core", "react", "vue", "svelte",
})


def _express_binding_names(src: bytes, root, pkg_table: Dict[str, JsBind]) -> set:
    """Local names holding an Express app or Router: `const app = express()`, `express.Router()`.

    Found through the PACKAGE binding, never by the variable being called `app`: a tree is free to name it
    `server`, and a tree with its own unrelated `app` must not have its methods read as routes."""
    express_locals = {n for n, b in pkg_table.items() if b.module == "express"}
    if not express_locals:
        return set()
    out: set = set()
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "variable_declarator":
            continue
        value, nm = node.child_by_field_name("value"), node.child_by_field_name("name")
        if value is None or nm is None or nm.type != "identifier" or value.type != "call_expression":
            continue
        fn = value.child_by_field_name("function")
        if fn is None:
            continue
        if fn.type == "identifier" and _node_text(src, fn) in express_locals:
            out.add(_node_text(src, nm))                         # const app = express()
        elif fn.type == "member_expression":
            obj, prop = fn.child_by_field_name("object"), fn.child_by_field_name("property")
            if obj is not None and prop is not None and obj.type == "identifier" \
                    and _node_text(src, obj) in express_locals and _node_text(src, prop) == "Router":
                out.add(_node_text(src, nm))                     # const router = express.Router()
    return out


def js_entries_of(src: bytes, root, rel: str, f: int, pkg_table: Dict[str, JsBind],
                  defs_by_name: Dict[str, List[str]], defs_by_id: set,
                  fp_binds: Dict[str, Tuple[str, str]]
                  ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[Tuple[int, int], str]]:
    """`(entry records, synthetic def records)` for one file's Express routes.

    ⭐ AN INLINE HANDLER GETS A SYNTHETIC `def`. `app.get('/x', (req, res) => …)` is the commonest route
    shape in JavaScript and its handler is ANONYMOUS, so there is no named definition to point an entry at
    — and without one, nothing the handler calls is reachable. The handler is therefore emitted as a def
    named `<handler@LINE>`: a name no source can collide with, stable across runs because it is the line,
    and reached only through the entry that created it. This is the one place an anonymous callable becomes
    a def, because a route handler IS a reachable node even though nothing calls it by name.
    """
    holders = _express_binding_names(src, root, pkg_table)
    if not holders:
        return [], [], {}
    entries: List[Dict[str, Any]] = []
    extra_defs: List[Dict[str, Any]] = []
    spans: Dict[Tuple[int, int], str] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        obj, prop = fn.child_by_field_name("object"), fn.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "identifier":
            continue
        holder, verb = _node_text(src, obj), _node_text(src, prop)
        if holder not in holders or verb not in _EXPRESS_VERBS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        path = None
        line = node.start_point[0] + 1
        via = f"{holder}.{verb}"
        for a in args.children:
            if a.type == "string" and path is None:
                path = "".join(_node_text(src, g) for g in a.children if g.type == "string_fragment")
                continue
            did = None
            if a.type == "identifier":
                nm = _node_text(src, a)
                if nm in fp_binds:                               # a handler imported from this tree
                    tf, real = fp_binds[nm]
                    cand = f"{tf}{QSEP}{real}"
                    did = cand if cand in defs_by_id else None
                if did is None:
                    here = [d for d in defs_by_name.get(nm, ()) if d.rsplit(QSEP, 1)[0] == rel]
                    did = here[0] if here else None
            elif a.type in _FN_VALUE:
                qual = f"<handler@{a.start_point[0] + 1}>"
                did = f"{rel}{QSEP}{qual}"
                spans[(a.start_byte, a.end_byte)] = qual
                extra_defs.append({"kind": "def", "id": did, "f": f, "line": a.start_point[0] + 1,
                                   "end_line": a.end_point[0] + 1, "name": qual,
                                   "decorators": [], "async": _is_async(a)})
            if did is None:
                continue
            e: Dict[str, Any] = {"kind": "entry", "def": did, "entry_kind": "route", "via": via,
                                 "f": f, "line": line}
            if verb != "use":
                e["method"] = verb.upper()
            if path is not None:
                e["path"] = path
            e["router"] = holder
            entries.append(e)
    return entries, extra_defs, spans


def declared_npm_packages(root_dir: str | os.PathLike, manifests: Optional[Iterable[str]] = None) -> set:
    """Every package the tree declares in a `package.json` — `dependencies`, `devDependencies`,
    `peerDependencies`, `optionalDependencies`. The set `entry_coverage` is judged against.

    ⚠️ `manifests` lets the caller hand over paths it already walked. `paths.walk_files` SHELLS OUT TO GIT
    (`git_visible_files`), so walking the tree again here doubled the subprocess cost of every document."""
    import json
    from pathlib import Path

    from .paths import walk_files
    base = Path(root_dir)
    out: set = set()
    for rel in (manifests if manifests is not None else walk_files(base)):
        if rel.rsplit("/", 1)[-1] != "package.json":
            continue
        try:
            data = json.loads((base / rel).read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            block = data.get(field)
            if isinstance(block, dict):
                out |= {k for k in block if isinstance(k, str)}
    return out


def entry_coverage(declared: set, found_frameworks: set) -> Dict[str, Any]:
    """Whether this tree's entry set can be believed COMPLETE, and what is missing when it cannot.

    ⛔ COMPLETENESS IS RELATIVE TO WHAT THE TREE DECLARES, and it is the only form of it that can be
    checked. Nobody can prove an entry grammar covers every framework in existence; what can be proven is
    that every entry-defining dependency THIS tree declares is one this front end enumerates. The test
    fails closed: a declared framework that is not enumerated, or no entry-defining framework at all,
    both give `complete: false`.

    ⚠️ WHY THIS GATE HAS TO EXIST. `answer` already refuses when the entry set is EMPTY ("no entry point
    found is not 'nothing calls it'"). It cannot refuse when the set is PARTIAL: a tree running Express and
    Next.js whose Express routes alone were enumerated gives a non-empty entry set, the BFS runs, and a
    function reachable only through a Next.js route comes back `no_path_from_entry_point` — a confident
    false negative on a live finding. That is the one outcome the error-direction rule forbids.
    """
    entry_defining = {p for p in declared if p in KNOWN_ENTRY_FRAMEWORKS}
    missing = sorted(entry_defining - ENUMERATED_FRAMEWORKS)
    enumerated = sorted(entry_defining & ENUMERATED_FRAMEWORKS)
    cov: Dict[str, Any] = {"frameworks": enumerated, "not_enumerated": missing,
                           "complete": bool(enumerated) and not missing}
    if not cov["complete"]:
        cov["why"] = (
            f"this tree declares {', '.join(missing)}, whose entry points this call graph does not "
            f"enumerate, so its entry set is partial and a reachability answer over it could call a live "
            f"finding unreachable" if missing else
            "this tree declares no framework whose entry points this call graph enumerates, so it has no "
            "starting node and reachability cannot discriminate")
    cov["found_in_tree"] = sorted(found_frameworks)
    return cov
