"""First-party import roots, and the module names an import statement span names.

Moved from pantheon-knowledge `src/extractors/import_scan.py:37-110` (`_is_alembic_script_dir`, `_project_packages`,
`_local_roots`, `_py_modules`, `_js_package`), so Atlas's `usage.json` and the index read one rule
(REACHABILITY_EXTRACTOR.md § 3.3.2.1, last paragraph). `declared` is NOT computed here (review C9): the caller passes
the set its own manifest extractors return.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Set

try:
    import tomllib
except ModuleNotFoundError:             # Python < 3.11: no pyproject reading, so fewer first-party roots
    tomllib = None                      # type: ignore[assignment]

NODE_BUILTINS = frozenset({
    "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns", "events", "fs", "http",
    "http2", "https", "net", "os", "path", "perf_hooks", "process", "querystring", "readline", "stream",
    "string_decoder", "timers", "tls", "tty", "url", "util", "v8", "vm", "worker_threads", "zlib",
})

_PY_IMPORT = re.compile(r"^\s*import\s+(.+?)\s*(#.*)?$")
_PY_FROM = re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\b")
_JS_SPEC = re.compile(r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|^\s*import\s+)["']([^"']+)["']""")

#: The pypi / npm templates whose spans are import STATEMENTS (the projection `usage.json` reads).
STATEMENT_TEMPLATES = {"pypi": ("py_from", "py_import", "py_import_ext", "py_from_ext"),
                       "npm": ("js_require", "js_import", "js_export", "js_dynamic", "js_from", "js_import_inline")}

_SPEC = re.compile(r"""["']([^"']+)["']""")


def normalize(name: str) -> str:
    """PEP 503 normalised distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_alembic_script_dir(p: Path) -> bool:
    """An Alembic migrations folder (`env.py` + `script.py.mako` or `versions/`): never importable as a package."""
    return (p / "env.py").is_file() and ((p / "script.py.mako").is_file() or (p / "versions").is_dir())


def project_name(workspace: Path) -> Optional[str]:
    """`[project] name` (or poetry's name) of the root `pyproject.toml`, as written, or None."""
    data = _pyproject(workspace)
    name = (data.get("project") or {}).get("name") or ((data.get("tool") or {}).get("poetry") or {}).get("name")
    return name if isinstance(name, str) and name else None


def _pyproject(workspace: Path) -> dict:
    path = workspace / "pyproject.toml"
    if tomllib is None or not path.is_file():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except tomllib.TOMLDecodeError:
        return {}


def _project_packages(workspace: Path) -> Set[str]:
    """Import roots the root `pyproject.toml` declares for THIS project: `[project] name` (as an import name),
    hatch `packages = ["src/x"]` (base names) and setuptools `packages` / `packages.find.include`."""
    data = _pyproject(workspace)
    if not data:
        return set()
    out = set()
    name = project_name(workspace)
    if name:
        out.add(re.sub(r"[-.]+", "_", name).lower())
    tool = data.get("tool") or {}
    hatch = ((((tool.get("hatch") or {}).get("build") or {}).get("targets") or {}).get("wheel") or {}).get("packages")
    setuptools = tool.get("setuptools") or {}
    packages = setuptools.get("packages")
    find = (packages or {}).get("find") if isinstance(packages, dict) else None
    for entry in [*(hatch or []), *(packages if isinstance(packages, list) else []), *((find or {}).get("include") or [])]:
        if isinstance(entry, str) and entry:
            out.add(entry.rstrip("/").rsplit("/", 1)[-1].split(".", 1)[0].rstrip("*"))
    return {p for p in out if p}


def _local_roots(workspace: Path, declared: Set[str]) -> Set[str]:
    """The first-party import roots: what an import of THIS project resolves to, never a third-party package.

    - a top-level `.py` module, or a top-level directory that is a package (`__init__.py`);
    - a package under a `src/` layout (`src/<x>/__init__.py`, or a `src/<x>.py` module);
    - the project's own declared packages (`_project_packages`: `[project] name`, hatch / setuptools packages);
    - a top-level directory with no `__init__.py` (a namespace package) only when no manifest of this repository
      declares a dependency of that name, and never an Alembic migrations folder: `alembic/` beside a declared
      `alembic` dependency is the migrations folder, and `from alembic import op` is the third-party package.

    `declared` holds PEP 503 normalised names (`normalize`)."""
    roots = set(_project_packages(workspace))
    for p in workspace.iterdir():
        if p.name.startswith("."):
            continue
        if p.is_dir():
            if (p / "__init__.py").is_file():
                roots.add(p.name)
            elif not _is_alembic_script_dir(p) and normalize(p.name) not in declared:
                roots.add(p.name)
        elif p.suffix == ".py":
            roots.add(p.stem)
    src = workspace / "src"
    if src.is_dir() and not (src / "__init__.py").is_file():
        for p in src.iterdir():
            if (p.is_dir() and (p / "__init__.py").is_file()) or p.suffix == ".py":
                roots.add(p.stem if p.suffix == ".py" else p.name)
    return roots


local_roots = _local_roots


def _py_modules(line: str) -> List[str]:
    m = _PY_FROM.match(line)
    if m:
        return [m.group(1)]
    m = _PY_IMPORT.match(line)
    if not m:
        return []
    return [part.strip().split(" as ")[0].strip() for part in m.group(1).split(",") if part.strip()]


def _js_package(spec: str) -> Optional[str]:
    if spec.startswith((".", "/")) or spec.startswith("node:"):
        return None
    parts = spec.split("/")
    pkg = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
    return None if pkg in NODE_BUILTINS else pkg


def statement_modules(span: str, eco: str) -> List[str]:
    """The module / package names an import-statement span names (pypi: modules; npm: packages, built-ins and
    relative specifiers dropped). A leading `:` / `;` / `}` (an OI-141 span starts there) is dropped, and a Python
    backslash continuation is joined, before parsing. A caller counting sites de-duplicates per (file, line, module):
    one statement can yield spans under two templates."""
    text = span.lstrip(":;} \t\n")
    if eco == "pypi":
        text = re.sub(r"\\\s*\n", " ", text)
        first = text.splitlines()[0] if text.strip() else ""
        m = re.match(r"^\s*from\s+([A-Za-z_][\w.]*)", first)
        if m:
            return [m.group(1)]
        return [x for x in _py_modules(first) if re.fullmatch(r"[A-Za-z_][\w.]*", x)]
    if eco == "npm":
        m = _JS_SPEC.search(text) or _SPEC.search(text)
        pkg = _js_package(m.group(1)) if m else None
        return [pkg] if pkg else []
    return []
