"""The calls a consumer makes (REACHABILITY_EXTRACTOR.md § 3.3.3, "The library API this extractor calls").

    idx = index_tree(root, commit=…, repository=…, ecosystems=ABSENCE_PROVEN, max_bytes=…)
    usage = usage_records(idx, root, declared={"pypi": {...}, "npm": {...}})
    side_files = {"index/imports.json": dumps(idx.imports), "index/callgraph.json": dumps(idx.callgraph)}

All pure: no network, no clock, no platform import.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

from . import firstparty
from .callgraph import build_callgraph_index
from .index import ImportIndex, build_imports

#: A usage record's quote is cut at this many characters (the contract's quote limit).
QUOTE_MAX = 200

_SPEC = re.compile(r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|^\s*import\s*)["']([^"']+)["']""")


class Index(NamedTuple):
    """The two documents of one tree (§ 3.3.2): `index/imports.json` and `index/callgraph.json`."""
    imports: Dict[str, Any]
    callgraph: Dict[str, Any]


def dumps(doc: Dict[str, Any]) -> bytes:
    """Canonical JSON (sorted keys, no whitespace, UTF-8): what is stored, and what `max_bytes` measures."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _bounded(doc: Dict[str, Any], max_bytes: Optional[int]) -> Dict[str, Any]:
    """⛔ NEVER CUT PARTWAY (§ 3.6 E3). A document over `max_bytes` becomes its header alone, `truncated: true`, and
    every question on it answers `inconclusive`: a partial index could answer an absence."""
    if not max_bytes or len(dumps(doc)) <= max_bytes:
        return doc
    return {**doc, "records": [], "truncated": True}


def index_tree(root: str | Path, *, commit: Optional[str] = None, repository: Optional[str] = None,
               ecosystems: Optional[Iterable[str]] = None, max_bytes: Optional[int] = None,
               parser=None, declared: "Optional[Iterable[str] | Dict[str, Iterable[str]]]" = None) -> Index:
    """Both documents for the tree at `root`. `ecosystems` selects which ecosystems get span records (Atlas:
    `ABSENCE_PROVEN`, review N2; the CI pass: all, the default). `max_bytes` bounds each document (§ 3.6 E3).
    `declared`: the tree's declared pypi dependencies (names, or `usage_records`' `{"pypi": …}`), computed by the
    caller; the call graph then marks a call on a declared or locked library `external` (CODE_WALKER.md § 3.3.2).
    ⛔ None (the default) = 1.5.0's edges: no call is ever external."""
    imports = build_imports(root, commit=commit, repository=repository, ecosystems=ecosystems)
    locked = [r for r in imports["records"] if r["kind"] == "requirement" and r["ecosystem"] == "pypi"]
    callgraph = build_callgraph_index(root, commit=commit, repository=repository, parser=parser,
                                      declared=declared, locked=locked)
    return Index(_bounded(imports, max_bytes), _bounded(callgraph, max_bytes))


def _js_spec(text: str) -> Optional[str]:
    m = _SPEC.search(text.lstrip(":;} \t\n"))
    return m.group(1) if m else None


def _parser_imports(callgraph: Optional[Dict[str, Any]]) -> Tuple[set, set]:
    """(the {(file, line, module)} the parser saw, the files it can speak for: read and parsed without a failure).
    Both empty when the call graph cannot confirm anything (absent, no parsed Python, truncated)."""
    if (not callgraph or callgraph.get("truncated")
            or (callgraph.get("languages") or {}).get("python") != "parsed"):
        return set(), set()
    files = callgraph.get("files") or []
    confirmed = {(files[r["f"]], r["line"], r["module"]) for r in callgraph.get("records") or ()
                 if r.get("kind") == "module_import"}
    return confirmed, set(files) - {p["file"] for p in callgraph.get("parse_failures") or ()}


def usage_records(idx: "Index | Dict[str, Any]", root: str | Path, *,
                  declared: Dict[str, Iterable[str]]) -> List[Dict[str, Any]]:
    """The `usage.json` projection (§ 3.3.2.1, last paragraph; § 3.3.3): import-scan@2's record shape, from the pypi
    and npm statement spans, one record per (file, line, module).

    Fields: `package` (pypi: the PEP 503-normalised top module; npm: the specifier's package), `ecosystem`, `module`
    (pypi: the dotted module; npm: the specifier), `file`, `line`, `kind: "import"`, `declared` (the package is in
    `declared[ecosystem]`, a set the CALLER computed, review C9), `runtime`, `text` (the span's first line, for the
    anchor's quote). Dropped as import-scan@2 drops them: relative imports, the standard library, Node built-ins, the
    tree's first-party roots. A cut or withheld span yields nothing (its text is not the source).

    ⛔ OI-163: a pypi module counts only when the parser confirms it, i.e. the call graph has a `module_import` of that
    module on that line (docstring prose such as "from the database" and docstring examples are spans, not imports).
    Where nothing can confirm (an imports document alone, no parser, a truncated call graph, a file the parser
    failed on or never read), the span counts as before: a dropped real import is a false `not_imported`."""
    doc = idx.imports if isinstance(idx, Index) else idx
    confirmed, parsed = _parser_imports(idx.callgraph if isinstance(idx, Index) else None)
    ix = ImportIndex.of(doc)
    py_declared = {firstparty.normalize(x) for x in declared.get("pypi", ())}
    js_declared = set(declared.get("npm", ()))
    local = firstparty.local_roots(Path(root), py_declared)
    out: Dict[tuple, Dict[str, Any]] = {}
    for r in ix.records("span"):
        eco = r["ecosystem"]
        if r.get("cut") or r["template"] not in firstparty.STATEMENT_TEMPLATES.get(eco, ()):
            continue
        file, line = ix.files[r["f"]], r["line"]
        text = r["text"].lstrip("\n").splitlines()[0][:QUOTE_MAX] if r["text"].strip() else ""
        found = []
        if eco == "pypi":
            for module in firstparty.statement_modules(r["text"], eco):
                top = module.split(".")[0]
                if module.startswith(".") or top in sys.stdlib_module_names or top in local:
                    continue
                if file in parsed and (file, line, module) not in confirmed:
                    continue
                pkg = firstparty.normalize(top)
                found.append((pkg, module, pkg in py_declared))
        elif eco == "npm":
            spec = _js_spec(r["text"])
            pkg = firstparty._js_package(spec) if spec else None
            if pkg:
                found.append((pkg, spec, pkg in js_declared))
        for pkg, module, is_declared in found:
            out.setdefault((file, line, module), {
                "package": pkg, "ecosystem": eco, "module": module, "file": file, "line": line, "kind": "import",
                "declared": is_declared, "runtime": bool(r.get("runtime")), "text": text})
    return [out[k] for k in sorted(out)]
