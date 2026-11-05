"""B58: is a `ready` API-diff answer only WEAKLY checked? (FIX_PR_CODE_MEASURES_LLM_VETS_SPEC.md § 0.1, § 5 row 2.)

⛔ WHY NOT `blind_to`. Every call-graph answer carries the same fixed `BLIND_TO` list (api_diff_check.py), so "it
states a blind spot" is true of every answer and would draft every class-3 bump. "Weakly checked" must be MEASURED on
this tree: does the tree hold a construct of a blind class that can reach THIS package?

    answer-level   name_search        the check fell back to name search (no call graph)
                   unparsed_files     files the check could not parse
                   rebound_unchecked  whether a module name is assigned again could not be checked (no source)
    per file       dynamic_name       getattr(<name bound to the package's module>, …) / `pkg[expr]` (B1)
                   dynamic_import     import_module / __import__ / import() / require() with a computed name, in a
                                      file that names the package in a string (B2)
                   package_path_string a string that is a dotted path into the package: a patch target, a dotted
                                      config (shipped code only)

⚠️ NOT DETECTED, by decision (lead 2026-11-04, option (i)): a method called on an untyped object (B3,
`app.add_event_handler(...)` on a parameter). Code has no cheap per-tree signal for it; the vetter's brief names it.
⚠️ TEST FILES ARE NOT READ. A test that reaches a removed name breaks the suite, which gate 5 runs by default where a
PR opens (B57); it does not ship. Counting `mock.patch("pkg.x")` in tests would draft nearly every bump.
⭐ MEASURED NOISE (2026-11-04, read-only over our own checkouts): 8 package moves × 6 services = 48 pairs. The
first draft flagged 15 (logger names, config keys, strings in trailing comments, a literal-name getattr, docs/);
this version flags 3, all on the safe side (a draft, never a wrong class): a logger-name LIST split over several
lines (a shared library's logging.py) and a docstring quoting `mock.patch("litellm.utils.decode")`. Excluding them
needs multi-line parsing; not worth it while a false weak costs only a draft.
⭐ ANY HIT MAKES THE ANSWER WEAK, and DF turns a weak answer into the `api_diff_unknown` acknowledgement (a draft).
It never raises the class: the use is POSSIBLE, not proven. Proving it is the vetter's job.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: Per answer: past this many entries the list ends with one `more` entry giving the count.
MAX_WEAK = 10
#: Files read per tree, and bytes per file. Past the file cap the answer says so (`scan_truncated`).
MAX_FILES = 20000
MAX_FILE_BYTES = 1_000_000

_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "env", "dist", "build", "site-packages",
                        "__pycache__", ".angular", "coverage", ".tox", ".mypy_cache", ".pytest_cache",
                        "tests", "test", "__tests__", "e2e", "spec", "docs"})
_EXT = {"pypi": (".py",), "npm": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")}
_TEST_FILE = re.compile(r"(^test_.*\.py$|_test\.py$|^conftest\.py$|\.(spec|test)\.[mc]?[jt]sx?$)")

WORDS = {
    "name_search": "the check fell back to name search, so calls were matched by name only",
    "unparsed_files": "{n} file(s) could not be parsed, so their calls were not checked",
    "rebound_unchecked": "whether a module name is assigned again could not be checked (no source)",
    "scan_truncated": "only the first {n} files were read for runtime-built uses",
    "dynamic_name": "a name built at runtime is looked up on {pkg} here, which the call graph cannot follow",
    "dynamic_import": "a module is imported by a computed name in a file that names {pkg}",
    "package_path_string": "a string names a path inside {pkg} (a patch target or dotted path)",
    "more": "{n} more",
}


def _changes(api_diff: Dict[str, Any]) -> List[str]:
    out = [str(r.get("symbol")) for r in api_diff.get("removed") or [] if isinstance(r, dict)]
    out += [str(r.get("from")) for r in api_diff.get("renamed") or [] if isinstance(r, dict)]
    out += [str(r.get("symbol") if isinstance(r, dict) else r) for r in api_diff.get("signature_changed") or []]
    return [s for s in out if s and s != "None"]


def _roots(eco: str, package: str, symbols: Sequence[str]) -> List[str]:
    """The names code writes to reach the package: pypi = each changed symbol's top module (`pyjwt` → `jwt`),
    npm = the package name."""
    if eco == "npm":
        return [package]
    return sorted({s.split(".", 1)[0] for s in symbols if s} or {package.replace("-", "_")})


_FILES_CACHE: Dict[Tuple[str, str], Tuple[List[str], bool]] = {}


def _files(path: str, eco: str) -> Tuple[List[str], bool]:
    """Shipped source files of one ecosystem under `path`, walked once per (tree, ecosystem) per process: a plan asks
    once per row, and every row of a tree reads the same files."""
    key = (os.path.realpath(path), eco)
    if key not in _FILES_CACHE:
        _FILES_CACHE[key] = _walk(path, eco)
    return _FILES_CACHE[key]


def _walk(path: str, eco: str) -> Tuple[List[str], bool]:
    out: List[str] = []
    exts = _EXT[eco]
    for d, dirs, names in os.walk(path):
        dirs[:] = sorted(x for x in dirs if x not in _SKIP_DIRS and not x.startswith("."))
        for n in sorted(names):
            if n.endswith(exts) and not _TEST_FILE.search(n):
                out.append(os.path.relpath(os.path.join(d, n), path))
                if len(out) >= MAX_FILES:
                    return out, True
    return out, False


def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def _prefixes(symbols: Sequence[str]) -> set:
    """`root.first_submodule` of every changed pypi symbol (`starlette.routing`), and the bare root for a top-level
    symbol. A dotted path in a string can only reach a change when it starts the same way."""
    out = set()
    for s in symbols:
        segs = s.split(".")
        out.add(".".join(segs[:2]) if len(segs) > 2 else segs[0])
    return out


#: A line that configures logging: its dotted strings are logger names, not paths into a package.
_LOGGING_LINE = re.compile(r"\blogging\.|\bgetLogger\(|\blogger\b|_loggers?\b")


def _relevant(path: str, prefixes: set) -> bool:
    segs = path.split(".")
    return ".".join(segs[:2]) in prefixes or segs[0] in prefixes


def _code_part(line: str) -> str:
    """The line up to a `#` that is outside every string: a comment cannot reach anything."""
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#":
            return line[:i]
        i += 1
    return line


def _py_hits(text: str, roots: Sequence[str], prefixes: set) -> List[Tuple[str, int]]:
    """⛔ MEASURED NOISE (2026-11-04, our own repos): logger names (`getLogger("sqlalchemy.engine")`), config keys
    (`"sqlalchemy.url"`) and strings inside trailing comments were flagged when ANY string starting with the package's
    name counted. Now a string counts only when its dotted path is `_relevant` to a changed symbol, and a computed
    import only in a file holding such a string."""
    alt = "|".join(re.escape(r) for r in roots)
    bound: set = set()
    for m in re.finditer(rf"^\s*import\s+((?:{alt})(?:\.\w+)*)(?:\s+as\s+(\w+))?", text, re.M):
        bound.add(m.group(2) or m.group(1).split(".", 1)[0])
    for m in re.finditer(rf"^\s*from\s+(?:{alt})(?:\.\w+)*\s+import\s+\(?([^)\n]+)", text, re.M):
        for part in m.group(1).split(","):
            bits = part.split()
            if bits and bits[0] != "*":
                bound.add(bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0])
    path_str = re.compile(rf"""['"]((?:{alt})(?:\.\w+)+)""")
    dyn_import = re.compile(r"\b(?:import_module|__import__)\(\s*(['\"]?)")
    # ⚠️ A COMPUTED attribute name only: `getattr(mod, "_flag", False)` is a static access the call graph reads
    # like `mod._flag` (measured 2026-11-04: agent-builder `getattr(rest_api_tool, "_torana_tracing_patched")`).
    getattr_on = re.compile(rf"\bgetattr\(\s*({'|'.join(re.escape(b) for b in sorted(bound))})\s*,(?!\s*[\'\"])") \
        if bound else None
    lines = [_code_part(x) for x in text.splitlines()]

    def relevant_paths(s: str) -> bool:
        # ⛔ LOGGER NAMES FOLLOW MODULE NAMES by convention, so they pass `_relevant` and reach nothing
        # (measured: `"sqlalchemy.engine": logging.WARNING` in 6 services, `getLogger("google.adk")`).
        if _LOGGING_LINE.search(s):
            return False
        return any(_relevant(m.group(1), prefixes) for m in path_str.finditer(s))

    file_names_change = any(relevant_paths(x) for x in lines)
    out: List[Tuple[str, int]] = []
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if getattr_on is not None and getattr_on.search(line):
            out.append(("dynamic_name", i))
        m = dyn_import.search(line)
        if m and (relevant_paths(line[m.start():]) if m.group(1) else file_names_change):
            out.append(("dynamic_import", i))
        if relevant_paths(line):
            out.append(("package_path_string", i))
    return out


def _npm_hits(text: str, package: str) -> List[Tuple[str, int]]:
    q = re.escape(package)
    names_pkg = re.compile(rf"""['"`]{q}(?:['"`/])""")
    bound: set = set()
    for m in re.finditer(rf"""import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+['"]{q}['"]""", text):
        bound.add(m.group(1))
    for m in re.finditer(rf"""(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+import|require)\(\s*['"]{q}['"]\s*\)""",
                         text):
        bound.add(m.group(1))
    member = re.compile(rf"""\(?\s*\b({'|'.join(re.escape(b) for b in sorted(bound))})\b(?:\s+as\s+\w+)?\s*\)?"""
                        rf"""\s*\[\s*(?!['"`\d])""") if bound else None
    dyn = re.compile(r"""(?<![\w.$])(?:import|require)\(\s*(?!['"`])""")
    file_names_pkg = bool(names_pkg.search(text))
    out: List[Tuple[str, int]] = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.lstrip()
        if s.startswith("//") or s.startswith("*"):
            continue
        if member is not None and member.search(line):
            out.append(("dynamic_name", i))
        if file_names_pkg and dyn.search(line):
            out.append(("dynamic_import", i))
    return out


def _entry(code: str, pkg: str, n: int = 0, **where: Any) -> Dict[str, Any]:
    return {"code": code, "words": WORDS[code].format(pkg=pkg, n=n), **where}


def weakly_checked(answer: Dict[str, Any], api_diff: Dict[str, Any], trees: Iterable[Tuple[str, str]], eco: str,
                   package: str) -> List[Dict[str, Any]]:
    """`[{code, words, repo?, file?, line?}]` for one READY answer, `[]` when it is not weak (or not ready: a
    non-ready answer is already `api_diff_unknown` by its state). `trees` = (label, checkout path)."""
    if (answer or {}).get("state") != "ready":
        return []
    symbols = _changes(api_diff or {})
    if not symbols:
        return []                                       # nothing changed: nothing a hidden use could break
    out: List[Dict[str, Any]] = []
    if answer.get("method") == "word":
        out.append(_entry("name_search", package))
    if answer.get("unparsed_files"):
        out.append(_entry("unparsed_files", package, len(answer["unparsed_files"])))
    if "rebound_module" in (answer.get("blind_to") or []):
        out.append(_entry("rebound_unchecked", package))
    if eco not in _EXT:
        return out
    roots = _roots(eco, package, symbols)
    prefixes = _prefixes(symbols)
    found: List[Dict[str, Any]] = []
    for label, path in trees:
        files, truncated = _files(path, eco)
        if truncated:
            out.append(_entry("scan_truncated", package, MAX_FILES, repo=label))
        for rel in files:
            text = _read(os.path.join(path, rel))
            if not text or not any(r in text for r in roots):
                continue
            seen = set()
            for code, line in (_py_hits(text, roots, prefixes) if eco == "pypi" else _npm_hits(text, package)):
                if code not in seen:                    # one entry per (file, signal): the first line
                    seen.add(code)
                    found.append(_entry(code, package, repo=label, file=rel, line=line))
    out += sorted(found, key=lambda e: (e["repo"], e["file"], e["line"], e["code"]))
    if len(out) > MAX_WEAK:
        out = out[:MAX_WEAK] + [_entry("more", package, len(out) - MAX_WEAK)]
    return out
