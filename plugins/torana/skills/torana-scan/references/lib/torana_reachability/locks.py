"""Requirement-graph readers (REACHABILITY_EXTRACTOR.md § 3.11.2): which package requires which, from a lock.

v1 readers: `uv.lock` (`[[package]]` name/version + `dependencies[].name`), pip-compile `requirements*.lock|txt` (a
`# via X` line is the edge X -> this package), `poetry.lock` (`[package.dependencies]`), `package-lock.json` v2/v3
(`packages[*].dependencies`). Each package is one `requirement` record, anchored on its line in the lock.

⛔ A file is read as a lock only when it carries edges: a requirements file with no `# via` line is a list of pins,
not a graph, and is skipped. So "this ecosystem has requirement records" == "a graph exists for it"
(`graph_complete`). Other ecosystems have no reader in v1, so their graph is never complete.

Edges over-approximate on purpose (optional dependencies count): an extra edge can only turn `not_imported` into
`imported_transitively`, which moves nothing.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from torana_reachability.firstparty import normalize
from torana_reachability.paths import walk_files

try:
    import tomllib
except ModuleNotFoundError:             # Python < 3.11: the TOML locks are not read (their graph stays incomplete)
    tomllib = None                      # type: ignore[assignment]

_PIP_LOCK = re.compile(r"(^|/)requirements[^/]*\.(lock|txt)$")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==|===)\s*([^\s;\\#]+)")
_VIA_INLINE = re.compile(r"^\s+#\s+via\s+(.+?)\s*$")
_VIA_HEAD = re.compile(r"^\s+#\s+via\s*$")
_VIA_ITEM = re.compile(r"^\s+#\s{2,}(\S.*?)\s*$")

#: The ecosystems a v1 reader exists for.
GRAPH_ECOSYSTEMS = frozenset({"pypi", "npm"})


def _req(eco: str, file: str, line: int, package: str, version: Optional[str], requires: Set[str]
         ) -> Dict[str, Any]:
    return {"kind": "requirement", "ecosystem": eco, "file": file, "line": line, "package": package,
            "version": version, "requires": sorted(requires)}


def read_pip_compile(text: str, file: str) -> List[Dict[str, Any]]:
    """pip-compile output: `name==version` lines, each followed by the `# via` lines naming who requires it."""
    pins: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    requires: Dict[str, Set[str]] = {}
    has_via = False
    current: Optional[str] = None
    in_via = False
    for n, line in enumerate(text.splitlines(), 1):
        m = _PIN.match(line)
        if m:
            current, in_via = normalize(m.group(1)), False
            if current not in pins:
                pins[current] = {"line": n, "version": m.group(2)}
                order.append(current)
            continue
        if current is None:
            continue
        vi = _VIA_INLINE.match(line)
        if vi:
            has_via = True
            in_via = False
            _via(vi.group(1), current, requires)
            continue
        if _VIA_HEAD.match(line):
            has_via, in_via = True, True
            continue
        it = _VIA_ITEM.match(line) if in_via else None
        if it:
            _via(it.group(1), current, requires)
            continue
        if not line.strip().startswith(("#", "--hash")) and line.strip():
            in_via = False
    if not has_via:
        return []
    return [_req("pypi", file, pins[p]["line"], p, pins[p]["version"], requires.get(p, set())) for p in order]


def _via(text: str, child: str, requires: Dict[str, Set[str]]) -> None:
    """One `via` entry: a package name is an edge parent -> child; `-r file` / `-c file` is a top-level spec."""
    for part in text.split(","):
        part = part.strip()
        # `-r file` / `-c file` and `name (pyproject.toml)` name a top-level spec, not a parent package.
        if not part or part.startswith(("-r", "-c", "--")) or "(" in part:
            continue
        name = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", part)
        if name:
            requires.setdefault(normalize(name.group(0)), set()).add(child)


def _lines_of_names(text: str) -> Dict[str, int]:
    """For a TOML lock: the line of each `[[package]]` block's `name = "…"` (first occurrence wins)."""
    out: Dict[str, int] = {}
    in_pkg = False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("["):
            in_pkg = s == "[[package]]"
            continue
        m = re.match(r'name\s*=\s*"([^"]+)"', s) if in_pkg else None
        if m:
            out.setdefault(normalize(m.group(1)), n)
            in_pkg = False
    return out


def read_uv_lock(text: str, file: str) -> List[Dict[str, Any]]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    lines = _lines_of_names(text)
    out = []
    for pkg in data.get("package") or ():
        name = normalize(str(pkg.get("name") or ""))
        if not name:
            continue
        deps: Set[str] = set()
        for key in ("dependencies",):
            for d in pkg.get(key) or ():
                if isinstance(d, dict) and d.get("name"):
                    deps.add(normalize(d["name"]))
        for group in (pkg.get("optional-dependencies") or {}).values():
            for d in group or ():
                if isinstance(d, dict) and d.get("name"):
                    deps.add(normalize(d["name"]))
        out.append(_req("pypi", file, lines.get(name, 1), name, pkg.get("version"), deps))
    return out


def read_poetry_lock(text: str, file: str) -> List[Dict[str, Any]]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    lines = _lines_of_names(text)
    out = []
    for pkg in data.get("package") or ():
        name = normalize(str(pkg.get("name") or ""))
        if not name:
            continue
        deps = {normalize(k) for k in (pkg.get("dependencies") or {})}
        out.append(_req("pypi", file, lines.get(name, 1), name, pkg.get("version"), deps))
    return out


def read_package_lock(text: str, file: str) -> List[Dict[str, Any]]:
    """npm `package-lock.json` v2/v3 (`packages`); v1 (only `dependencies`) has no reader."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return []
    line_of: Dict[str, int] = {}
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r'\s*"(node_modules/[^"]+)"\s*:', line)
        if m:
            line_of.setdefault(m.group(1), n)
    merged: Dict[str, Dict[str, Any]] = {}
    for key in sorted(packages):
        if not key.startswith("node_modules/") and "/node_modules/" not in key:
            continue                                # the root project ("") and workspace folders
        meta = packages[key] or {}
        name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
        deps = set((meta.get("dependencies") or {}).keys()) | set((meta.get("optionalDependencies") or {}).keys())
        if name in merged:
            merged[name]["requires"] |= deps
            continue
        merged[name] = {"line": line_of.get(key, 1), "version": meta.get("version"), "requires": deps}
    return [_req("npm", file, v["line"], name, v["version"], v["requires"]) for name, v in sorted(merged.items())]


def read_lock(rel: str, text: str) -> List[Dict[str, Any]]:
    """The requirement records of one lock file (by its path), or [] for a file no v1 reader takes."""
    name = rel.rsplit("/", 1)[-1]
    if name == "uv.lock":
        return read_uv_lock(text, rel)
    if name == "poetry.lock":
        return read_poetry_lock(text, rel)
    if name == "package-lock.json":
        return read_package_lock(text, rel)
    if _PIP_LOCK.search(rel):
        return read_pip_compile(text, rel)
    return []


def is_lock(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name in ("uv.lock", "poetry.lock", "package-lock.json") or bool(_PIP_LOCK.search(rel))


def read_requirements(root: str | Path, files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Every `requirement` record of every lock under `root` (sorted by file, then line)."""
    base = Path(root)
    out: List[Dict[str, Any]] = []
    for rel in (files if files is not None else [f for f in walk_files(base) if is_lock(f)]):
        try:
            text = (base / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out.extend(read_lock(rel, text))
    return sorted(out, key=lambda r: (r["file"], r["line"], r["package"]))


def graph_complete(records: List[Dict[str, Any]], eco: str) -> bool:
    """True when some lock gave requirement edges for `eco` (golang/go and the rest: never, in v1)."""
    e = (eco or "").lower()
    return e in GRAPH_ECOSYSTEMS and any(r.get("kind") == "requirement" and r["ecosystem"] == e for r in records)
