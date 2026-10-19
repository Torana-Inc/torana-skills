"""The import index (`index/imports.json`, schema `atlas/index/imports.v1`) and the query over it.

REACHABILITY_EXTRACTOR.md § 3.3.2.1. The scan this replaces ran each package's patterns over the WHOLE file text,
and several of its grammars are not anchored to an import statement (`\\b{m}::`, Go's quoted path anywhere,
`require(` mid-expression; `\\s*` crosses newlines). An index of import LINES would miss those, and a miss in pypi,
npm, golang/go or cargo is `not_imported`: the unsafe direction. So the index stores SPANS of a superset regex:

1. each template's superset `S` = the template with `{m}` = the ecosystem's name class (`grammar.NAME`);
2. spans = every match of `S` at EVERY start position of the file, found with `(?=(S))` so overlapping matches
   are all kept, de-duplicated per (file, template) by text, each with the line of its first occurrence;
3. a query builds today's package pattern `P` per template and reports a hit in file F iff `P.search(span)` for
   some span of F under the SAME template id. A span starts where `S` matched, so every anchor `S` needed was true
   in the file; inside the span `^` / `\\b` at its ends only see a string edge (more permissive), and the greedy
   name class at the same start ends at or after `P`'s match. So the query can over-match (harmless) and does not
   under-match: `tests/test_span_property.py` is the property test, `tests/test_parity.py` the fixtures.

⛔ `PARITY_PROVEN` gates every answer: an ecosystem absent from it answers `inconclusive`, never from the index.

OI-141 (§ 3.3.2.5) added templates for forms today's scan misses. The index stores spans for every template; a query
uses the `full` grammar unless asked for `frozen` (today's templates only, which must equal the oracle exactly).
"""
from __future__ import annotations

import bisect
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from torana_reachability import ENGINE
from torana_reachability.grammar import (_ABSENCE, _ECOSYSTEM_EXT, _IMPORT_NAME, _SOURCE_ECOSYSTEMS,
                                         ABSENCE_PROVEN, TEMPLATES, import_names, superset, template_patterns)
from torana_reachability.paths import _scope_of, is_runtime, source_files

SCHEMA_IMPORTS = "atlas/index/imports.v1"

#: Ecosystem spellings that share one grammar; the index keys spans by the canonical one.
ECO_ALIAS = {"go": "golang"}

#: Every ecosystem the index can hold spans for (canonical spellings).
INDEXABLE = tuple(sorted({ECO_ALIAS.get(e, e) for e in TEMPLATES}))

#: ⛔ The ecosystems whose fixtures prove index ⇄ scan parity (§ 3.3.2.1 step 5 and 6). Every other ecosystem
#: answers `inconclusive` "parity with the import scan is not proven for '<eco>' yet". Each entry is held by a
#: usage-only + multi-line fixture in `tests/test_parity.py` (`test_parity_proven_is_backed_by_a_fixture`).
PARITY_PROVEN = frozenset({"pypi", "npm", "golang", "go", "cargo", "gem", "nuget", "composer", "maven"})

#: A span longer than this is stored cut, with `cut: true`; a cut span matches every package of its ecosystem.
SPAN_MAX = 400

#: Non-literal dynamic imports (an input to certainty, § 3.11.5 K4): the first argument is not a string literal.
_DYNAMIC_NONLITERAL = {
    "pypi": ((re.compile(r"\b(?:importlib\s*\.\s*)?import_module\(\s*(?=[^'\"\s)])"), "importlib.import_module"),
             (re.compile(r"\b__import__\(\s*(?=[^'\"\s)])"), "__import__")),
    "npm": ((re.compile(r"(?<![\w.$])import\(\s*(?=[^'\"\s)])"), "import()"),
            (re.compile(r"(?<![\w.$])require\(\s*(?=[^'\"\s)])"), "require()")),
}


def canonical(eco: Optional[str]) -> str:
    e = (eco or "").lower()
    return ECO_ALIAS.get(e, e)


def read_text(path: Path) -> Optional[str]:
    """A source file's text exactly as the scan read it (UTF-8, errors ignored, universal newlines)."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def spans_of(text: str, eco: str, template, name_class: Optional[str] = None) -> List[Tuple[str, int]]:
    """Every (span, line) of `template`'s superset in `text`, de-duplicated by text (first line kept).

    ⚠️ A span that starts with a newline is dropped: only a `^\\s*` template can produce one (its `\\s*` ran over
    blank lines), and the match that starts after the newline is a line start too and yields the same span less
    its leading whitespace, which any `P` that matched the longer one also matches."""
    s = superset(eco, template, name_class)
    seen: Dict[str, int] = {}
    nl = None
    for m in re.finditer(f"(?=({s.pattern}))", text, s.flags):
        span = m.group(1)
        if not span or span[0] == "\n" or span in seen:
            continue
        nl = nl if nl is not None else newline_offsets(text)
        seen[span] = line_at(nl, m.start())
    return sorted(seen.items(), key=lambda kv: (kv[1], kv[0]))


def newline_offsets(text: str) -> List[int]:
    return [i for i, ch in enumerate(text) if ch == "\n"]


def line_at(offsets: List[int], pos: int) -> int:
    """1-based line of character `pos` (== `text.count("\n", 0, pos) + 1`)."""
    return bisect.bisect_left(offsets, pos) + 1


def _sha1(path: Path) -> str:
    try:
        return hashlib.sha1(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def build_imports(root: str | Path, *, commit: Optional[str] = None, repository: Optional[str] = None,
                  ecosystems: Optional[Iterable[str]] = None, files: Optional[List[str]] = None,
                  with_locks: bool = True) -> Dict[str, Any]:
    """The `index/imports.json` document for the tree at `root`.

    `ecosystems`: which ecosystems get span records (canonical or alias spellings). Default: all of them (the CI
    pass, in memory). Atlas passes `ABSENCE_PROVEN` (the other four can never answer `not_imported`, review N2).
    `files`: the source file list (default `paths.source_files(root)`).
    """
    base = Path(root)
    want = {canonical(e) for e in (ecosystems if ecosystems is not None else INDEXABLE)}
    rels = list(files) if files is not None else source_files(base)
    records: List[Dict[str, Any]] = []
    present: set = set()
    for f, rel in enumerate(rels):
        ext_ecos = [e for e in INDEXABLE if rel.endswith(_ECOSYSTEM_EXT[e])]
        present.update(ext_ecos)
        ecos = [e for e in ext_ecos if e in want]
        if not ecos and not any(rel.endswith(_ECOSYSTEM_EXT[e]) for e in _DYNAMIC_NONLITERAL):
            continue
        text = read_text(base / rel)
        if text is None:
            continue
        runtime = is_runtime(rel)
        for eco in ecos:
            for t in TEMPLATES[eco]:
                for span, line in spans_of(text, eco, t):
                    rec: Dict[str, Any] = {"kind": "span", "f": f, "line": line, "ecosystem": eco,
                                           "template": t.id, "text": span[:SPAN_MAX], "runtime": runtime}
                    if len(span) > SPAN_MAX:
                        rec["cut"] = True
                    records.append(rec)
        for eco, forms in _DYNAMIC_NONLITERAL.items():
            if not rel.endswith(_ECOSYSTEM_EXT[eco]):
                continue
            for pat, form in forms:
                for m in pat.finditer(text):
                    records.append({"kind": "dynamic_nonliteral", "f": f,
                                    "line": text.count("\n", 0, m.start()) + 1, "ecosystem": eco,
                                    "form": form, "runtime": runtime})
    if with_locks:
        from torana_reachability import locks
        reqs = locks.read_requirements(base)
        records.extend(reqs)
        records.extend(_distributions(base, reqs))
    languages = {e: ("absent" if e not in present else "indexed" if e in want else "not_indexed")
                 for e in INDEXABLE}
    return {
        "schema": SCHEMA_IMPORTS, "engine": ENGINE, "commit": commit, "repository": repository,
        "files": rels, "file_sha": [_sha1(base / r) for r in rels], "parse_failures": [],
        "languages": languages, "truncated": False,
        "records": sorted(records, key=_record_key),
    }


def _record_key(r: Dict[str, Any]) -> Tuple:
    return (r["kind"], r.get("f", -1), r.get("file", ""), r.get("ecosystem", ""), r.get("template", ""),
            r.get("line", 0), r.get("text", ""), r.get("form", ""), r.get("package", ""), r.get("name", ""))


def _distributions(base: Path, reqs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """`distribution` records: this tree's own project, then every pypi package its locks name."""
    from torana_reachability import firstparty
    out: List[Dict[str, Any]] = []
    name = firstparty.project_name(base)
    if name:
        out.append({"kind": "distribution", "ecosystem": "pypi", "name": firstparty.normalize(name),
                    "modules": sorted(firstparty._project_packages(base)), "basis": "first_party_pyproject"})
    for pkg in sorted({r["package"] for r in reqs if r["ecosystem"] == "pypi"}):
        out.append({"kind": "distribution", "ecosystem": "pypi", "name": pkg,
                    "modules": sorted(import_names(pkg, "pypi")),
                    "basis": "mapping_table" if pkg in _IMPORT_NAME else "convention"})
    return out


# ── the query ────────────────────────────────────────────────────────────────────────

class ImportIndex:
    """A loaded `imports.json` document with its spans grouped for the query."""

    def __init__(self, doc: Dict[str, Any]):
        self.doc = doc
        self.files: List[str] = list(doc.get("files") or [])
        self.languages: Dict[str, str] = dict(doc.get("languages") or {})
        self._spans: Dict[Tuple[int, str, str], List[Dict[str, Any]]] = {}
        for r in doc.get("records") or ():
            if r.get("kind") == "span":
                self._spans.setdefault((r["f"], r["ecosystem"], r["template"]), []).append(r)

    @classmethod
    def of(cls, index: "ImportIndex | Dict[str, Any]") -> "ImportIndex":
        return index if isinstance(index, ImportIndex) else cls(index)

    def records(self, kind: str) -> List[Dict[str, Any]]:
        return [r for r in self.doc.get("records") or () if r.get("kind") == kind]

    def hit(self, f: int, eco: str, template_id: str, pattern: "re.Pattern[str]") -> bool:
        for r in self._spans.get((f, eco, template_id), ()):
            if r.get("cut") or pattern.search(r["text"]):
                return True
        return False


def imports_of(index: "ImportIndex | Dict[str, Any]", files: List[str], package: str,
               ecosystem: Optional[str], *, grammar: str = "full") -> Dict[str, Any]:
    """Where, if anywhere, this package is imported among `files` (paths of the index) — split by runtime vs not.
    The same shape as the frozen scan's `scan_imports`. `grammar="frozen"` asks today's templates only (the
    strict-parity proof, § 3.3.2.5); `full` (default) adds OI-141's, which can only add hits."""
    ix = ImportIndex.of(index)
    eco = canonical(ecosystem)
    mods = import_names(package, ecosystem)
    pats = template_patterns(ecosystem, mods, grammar)
    static = [(t, p) for t, p in pats if not t.dynamic]
    dyn = [(t, p) for t, p in pats if t.dynamic]
    pos = {path: i for i, path in enumerate(ix.files)}
    runtime, non_runtime, dynamic = [], [], []
    for rel in files:
        f = pos.get(rel)
        if f is None:
            continue
        hit = any(ix.hit(f, eco, t.id, p) for t, p in static)
        dhit = any(ix.hit(f, eco, t.id, p) for t, p in dyn)
        if not (hit or dhit):
            continue
        (runtime if is_runtime(rel) else non_runtime).append(rel)
        if dhit:
            dynamic.append(rel)
    return {"modules_tried": mods, "runtime": runtime, "patterns": len(static),
            "non_runtime": non_runtime, "dynamic": dynamic}


def package_verdict(index: "ImportIndex | Dict[str, Any]", pkg: Dict[str, Any], commit: str, repo_key: str, *,
                    analyzer: str, gate: bool = True, grammar: str = "full") -> Dict[str, Any]:
    """One verdict for one package, with the evidence the API requires — the frozen scan's `package_verdict`,
    answered from the index. `gate=False` skips `PARITY_PROVEN` and `grammar="frozen"` drops OI-141's templates
    (both for the parity tests only)."""
    ix = ImportIndex.of(index)
    name, eco = pkg.get("package_name"), (pkg.get("ecosystem") or "").lower()
    base = {"commit": commit, "analyzer": analyzer, "repository": repo_key}

    if eco and eco not in _SOURCE_ECOSYSTEMS:
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": f"ecosystem '{eco}' is not a source-import "
                                               "ecosystem; its use is a question about the "
                                               "built image, not about source imports",
                             "package_name": name}}
    if gate and eco and eco not in PARITY_PROVEN:
        return {"verdict": "inconclusive",
                "evidence": {**base, "package_name": name,
                             "reason": f"parity with the import scan is not proven for '{eco}' yet"}}

    # ⛔ ONLY THE FILES THAT COULD CARRY THE IMPORT, and inconclusive when there are none.
    # A Go package searched in a repository with no Go source is absent by construction, and
    # reporting that as `not_imported` lowers an item on evidence the scan never had.
    exts = _ECOSYSTEM_EXT.get(eco) if eco else None
    scope = [f for f in ix.files if f.endswith(exts)] if exts else ix.files
    if exts and not scope:
        return {"verdict": "inconclusive",
                "evidence": {**base, "package_name": name,
                             "reason": f"this repository holds no {'/'.join(exts)} source, so "
                                       f"an import scan cannot discriminate for a '{eco}' "
                                       "package: its absence here is guaranteed, not measured"}}
    if eco and ix.languages.get(canonical(eco)) == "not_indexed":
        return {"verdict": "inconclusive",
                "evidence": {**base, "package_name": name, "files_scanned": len(scope),
                             "reason": f"not indexed: '{eco}' cannot prove an absence, so its import "
                                       "sites are not stored in this index"}}

    found = imports_of(ix, scope, name, eco, grammar=grammar)
    ev = {**base, "files_scanned": len(scope), "package_name": name,
          "modules_tried": found["modules_tried"]}

    # ⛔ A GRAMMAR THAT COULD NOT BE BUILT HAS NOT LOOKED (a bare Maven artifact id).
    if not found["patterns"]:
        return {"verdict": "inconclusive",
                "evidence": {**ev, "reason": f"no import pattern can be built for a '{eco}' "
                                             f"package named {name!r}: "
                                             + (_ABSENCE.get(eco) or "its import syntax is "
                                                "not derivable from this name")}}

    if found["runtime"]:
        # ⚠️ Imported on the running surface. Recorded, never promoted.
        return {"verdict": "reachable",
                "evidence": {**ev, "function": f"import {name}",
                             "path": found["runtime"][:20]}}
    if found["non_runtime"]:
        return {"verdict": "build_only",
                "evidence": {**ev, "scopes": sorted({_scope_of(p) for p in found["non_runtime"]}),
                             "import_sites": found["non_runtime"][:20]}}

    # ⛔ THE MISS. Only an ecosystem whose grammar can also prove an ABSENCE may say so.
    why = _ABSENCE.get(eco, "this ecosystem's import mapping has not been established")
    if why is not None:
        return {"verdict": "inconclusive",
                "evidence": {**ev, "reason": f"{name!r} was not found in {len(scope)} "
                                             f"'{eco}' source file(s), but {why}"}}
    return {"verdict": "not_imported", "evidence": ev}


__all__ = ["ABSENCE_PROVEN", "ImportIndex", "PARITY_PROVEN", "SCHEMA_IMPORTS", "build_imports", "canonical",
           "imports_of", "package_verdict", "spans_of"]
