"""Requirement-graph readers (REACHABILITY_EXTRACTOR.md § 3.11.2): which package requires which, from a lock.

v1 readers: `uv.lock` (`[[package]]` name/version + `dependencies[].name`), pip-compile `requirements*.lock|txt` (a
`# via X` line is the edge X -> this package), `poetry.lock` (`[package.dependencies]`), `package-lock.json` v2/v3
(`packages[*].dependencies`). Each package is one `requirement` record, anchored on its line in the lock.

⛔ A file is read as a lock only when it carries edges: a requirements file with no `# via` line is a list of pins,
not a graph, and is skipped. So "this ecosystem has requirement records" == "a graph exists for it"
(`graph_complete`). Other ecosystems have no reader in v1, so their graph is never complete.

Edges over-approximate on purpose (optional dependencies count): an extra edge can only turn `not_imported` into
`imported_transitively`, which moves nothing.

1.9.0 (OI-192): an npm record also carries `dev` (every copy of the package in the lock is `"dev": true`, i.e. it is
reachable only from `devDependencies`) and `dev_optional` (every copy is dev or `devOptional`, and not all are dev).
A package that is in the production tree anywhere in the lock is neither.

1.9.0 (OI-190): `read_resolutions` is the second view of the same parse: one `resolution` record per resolved
package, anchored on the line that sets its VERSION (not its name), for `manifests.read_manifests`. It adds the two
formats that carry no edges here (`yarn.lock` v1, `pnpm-lock.yaml`), so they have resolutions and never requirement
records: `graph_complete` does not move.

1.10.0 (upgrade card, FIX_PR phase 3): every `resolution` record carries `origin = {verdict, source, url}`, WHERE
the lock says the version came from (`origin_of`). `verdict` is one of three, and only the first lets a package's
(ecosystem, name, version) leave the platform for an upgrade card (Bhakta 2026-10-19, P2 = A):
- `public`: the lock RECORDS the ecosystem's public registry (`PUBLIC_REGISTRIES`: pypi.org, registry.npmjs.org);
- `other`: the lock records any other origin (a private registry, git, a path, a direct URL), named in `url`;
- `unknown`: the lock records no origin, or several indexes and none for this package. ⛔ `unknown` is NOT public: an
  index the file does not record may be a private mirror shadowing a public name. `is_public(origin)` is the test.
Credentials, query and fragment are stripped from every URL before it reaches a record.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit, urlunsplit

from .firstparty import normalize
from .paths import walk_files

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
        dev, dev_opt = bool(meta.get("dev")), bool(meta.get("devOptional"))
        if name in merged:
            merged[name]["requires"] |= deps
            merged[name]["dev"] &= dev
            merged[name]["dev_or_opt"] &= dev or dev_opt
            continue
        merged[name] = {"line": line_of.get(key, 1), "version": meta.get("version"), "requires": deps,
                        "dev": dev, "dev_or_opt": dev or dev_opt}
    return [{**_req("npm", file, v["line"], name, v["version"], v["requires"]),
             "dev": v["dev"], "dev_optional": v["dev_or_opt"] and not v["dev"]}
            for name, v in sorted(merged.items())]


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


# ---------------------------------------------------------------------------------------------------------------
# Resolutions (1.9.0, OI-190): which version each lock RESOLVES, anchored on the line that sets it.
# ---------------------------------------------------------------------------------------------------------------

_NAME_LINE = re.compile(r'^name\s*=\s*"([^"]+)"')
_VERSION_LINE = re.compile(r'^version\s*=\s*"([^"]+)"')
_ROOT_SOURCE = re.compile(r'^source\s*=\s*\{\s*(?:editable|virtual)\s*=\s*"([^"]*)"')
_LOCK_KEY = re.compile(r'^\s*"((?:[^"]*/)?node_modules/((?:@[^"/]+/)?[^"/]+))"\s*:\s*\{')
_LOCK_VERSION = re.compile(r'^\s*"version"\s*:\s*"([^"]*)"')
_YARN_HEAD = re.compile(r'^"?((?:@[^@"\s,]+/)?[^@"\s,]+)@[^:]*:\s*$|^"?((?:@[^@"\s,]+/)?[^@"\s,]+)@.*,\s*$')
_YARN_VERSION = re.compile(r'^\s+version\s+"?([^"\s]+)"?\s*$')
_YARN_RESOLVED = re.compile(r'^\s+resolved\s+"?([^"\s]+)"?\s*$')
_PNPM_KEY = re.compile(r"""^\s{2}['"]?/?((?:@[^/@'"]+/)?[^/@'":]+)(?:@|/)(\d[^'":(]*)(?:\([^:]*\))*['"]?:\s*$""")


#: The public registries (1.10.0), as `origin_of` normalises them. Only these give `verdict: public`.
PUBLIC_REGISTRIES: Dict[str, frozenset] = {
    "pypi": frozenset({"https://pypi.org/simple", "https://pypi.python.org/simple", "https://pypi.org/pypi"}),
    "npm": frozenset({"https://registry.npmjs.org", "https://registry.yarnpkg.com"}),
}
_GIT_PREFIXES = ("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:")


def clean_url(url: str) -> str:
    """`url` without credentials, query or fragment, scheme and host lower-cased, no trailing `/`, for every URL with
    a host (`git+https://user:token@…` too). A value with no host (a path, `file:`) comes back stripped only."""
    url = (url or "").strip()
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:                                  # an unparsable netloc: keep nothing that could be a secret
        return ""
    if not parts.scheme or not parts.hostname:
        return url.rstrip("/")
    host = parts.hostname.lower() + (f":{port}" if port else "")
    return urlunsplit((parts.scheme.lower(), host, parts.path.rstrip("/"), "", ""))


def suspicious_authority(url: Optional[str]) -> bool:
    """1.10.1: the RAW url's authority (between `://` and the next `/`) holds a `\\`, whitespace or `@`. Parsers
    disagree about such a URL: `https://evil.com\\@pypi.org/simple` is host `pypi.org` to Python's `urlsplit` and
    host `evil.com` to Node / npm and to browsers. It is never trusted as public."""
    raw = url or ""
    if "://" not in raw:
        return False
    authority = raw.split("://", 1)[1].split("/", 1)[0]
    return any(c in authority for c in ("\\", "@")) or any(c.isspace() for c in authority)


def origin_of(eco: str, source: str, url: Optional[str] = None, *, raw: Optional[str] = None) -> Dict[str, Any]:
    """`{verdict, source, url}`. `source`: `registry` | `git` | `path` | `url` (a direct artifact URL) | `unrecorded`
    (the lock names no origin) | `ambiguous` (several indexes, none named for this package). `verdict`: `public` only
    for a `registry` source in `PUBLIC_REGISTRIES[eco]` whose raw URL (`raw`, else `url`) has an unambiguous authority
    (`suspicious_authority`, 1.10.1); `unknown` for `unrecorded` / `ambiguous`; else `other`."""
    if source in ("unrecorded", "ambiguous"):
        return {"verdict": "unknown", "source": source, "url": None}
    u = clean_url(url) if url else None
    public = (source == "registry" and u in PUBLIC_REGISTRIES.get(eco, frozenset())
              and not suspicious_authority(raw if raw is not None else url))
    return {"verdict": "public" if public else "other", "source": source, "url": u}


def is_public(origin: Optional[Dict[str, Any]]) -> bool:
    """True only for a recorded public registry. ⛔ `unknown` (and a record with no `origin`) is not public."""
    return bool(origin) and origin.get("verdict") == "public"


def npm_origin(resolved: Optional[str], package: str) -> Dict[str, Any]:
    """The origin of a package-lock / yarn `resolved` value. A registry tarball is `<registry>/<name>/-/<file>`, so
    the registry is the part before `/<name>/-/`; any other http(s) URL is a direct `url`."""
    r = (resolved or "").strip()
    if not r:
        return origin_of("npm", "unrecorded")
    if r.startswith(_GIT_PREFIXES) or ("://github.com/" in r and r.endswith(".git")):
        return origin_of("npm", "git", r)
    if r.startswith(("file:", "link:", ".", "/")):
        return origin_of("npm", "path", r)
    u = clean_url(r)
    marker = f"/{package}/-/"
    if marker in u:
        return origin_of("npm", "registry", u.split(marker, 1)[0], raw=r)
    return origin_of("npm", "url", u, raw=r)


def _uv_origin(src: Any) -> Dict[str, Any]:
    """A uv.lock `source = { registry | git | url | path | directory = ... }`."""
    if not isinstance(src, dict) or not src:
        return origin_of("pypi", "unrecorded")
    if "registry" in src:
        reg = str(src["registry"])
        return origin_of("pypi", "registry" if reg.startswith(("http://", "https://")) else "path", reg)
    for key, kind in (("git", "git"), ("url", "url"), ("path", "path"), ("directory", "path")):
        if key in src:
            return origin_of("pypi", kind, str(src[key]))
    return origin_of("pypi", "unrecorded")


def _poetry_origin(src: Any) -> Dict[str, Any]:
    """poetry.lock writes `[package.source]` only for a package NOT from PyPI; its absence IS the format's record
    that the package came from PyPI. 1.10.1: anything else that is not a readable table, and a `legacy` source with no
    `url`, is `unknown` (it used to read as PyPI: fail-open)."""
    if src is None or src == {}:
        return origin_of("pypi", "registry", "https://pypi.org/simple")
    if not isinstance(src, dict):
        return origin_of("pypi", "unrecorded")
    kind = str(src.get("type") or "")
    url = str(src.get("url") or "")
    if kind == "legacy":
        return origin_of("pypi", "registry", url) if url else origin_of("pypi", "unrecorded")
    if kind == "pypi":
        return origin_of("pypi", "registry", url or "https://pypi.org/simple")
    if kind == "git":
        return origin_of("pypi", "git", url)
    if kind in ("directory", "file"):
        return origin_of("pypi", "path", url)
    if kind == "url":
        return origin_of("pypi", "url", url)
    return origin_of("pypi", "unrecorded")


def _res(eco: str, file: str, line: int, package: str, version: str, fmt: str, **extra: Any) -> Dict[str, Any]:
    return {"kind": "resolution", "ecosystem": eco, "file": file, "line": line, "package": package,
            "version": version, "lock_format": fmt, **extra}


def _toml_blocks(text: str) -> List[Dict[str, Any]]:
    """Each `[[package]]` block's top-level `name` / `version` lines, in file order, and the root project's
    directory when the block is the project itself (`source = { editable | virtual = "<dir>" }`)."""
    blocks: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip() == "[[package]]":
            cur = {"name_line": n, "version_line": 0, "root": None}
            blocks.append(cur)
            continue
        if line.startswith("["):
            cur = None                              # a sub-table: what follows is not the block's own keys
            continue
        if cur is None:
            continue
        if _VERSION_LINE.match(line) and not cur["version_line"]:
            cur["version_line"] = n
        elif (m := _ROOT_SOURCE.match(line)):
            cur["root"] = m.group(1)
    return blocks


def _read_toml_resolutions(text: str, file: str, fmt: str) -> List[Dict[str, Any]]:
    if tomllib is None:
        return []
    try:
        packages = tomllib.loads(text).get("package") or []
    except tomllib.TOMLDecodeError:
        return []
    blocks = _toml_blocks(text)
    aligned = len(blocks) == len(packages)
    by_name = _lines_of_names(text)
    out = []
    for i, pkg in enumerate(packages):
        name, version = normalize(str(pkg.get("name") or "")), pkg.get("version")
        src = pkg.get("source") or {}
        root = src.get("editable", src.get("virtual")) if isinstance(src, dict) else None
        if root is not None:
            continue                                # the project itself is not a resolved dependency
        if not name or not version:
            continue
        line = (blocks[i]["version_line"] or blocks[i]["name_line"]) if aligned else by_name.get(name, 1)
        out.append(_res("pypi", file, line, name, str(version), fmt,
                        origin=_uv_origin(src) if fmt == "uv" else _poetry_origin(src)))
    return out


def lock_root(text: str) -> Optional[str]:
    """The directory (relative to a uv.lock) of the project the lock was resolved for, or None."""
    for b in _toml_blocks(text):
        if b["root"] is not None:
            return b["root"]
    return None


def _read_package_lock_resolutions(text: str, file: str) -> List[Dict[str, Any]]:
    """One record per `node_modules/<pkg>` key, at the line of its `"version"`.

    ⭐ A NESTED COPY IS A RESOLUTION TOO, and carries `nested_under` — its parent chain, outermost first.
    This overturns "a nested copy is another package's private dependency" (the rule until 2026-10-20).
    npm installs two versions of one package when two dependents need different majors, and BOTH are on
    disk and BOTH ship, so a scanner reports findings against the nested one. With it absent from the
    resolution set the planner cannot place that finding and invents an explanation instead — a
    `declaration_conflict`, a `lock_drift`, or `not_declared_here`. Measured: 42 of nodejs-goof's 133 rows.

    ⛔ `nested_under` IS LOAD-BEARING. The lever for a nested copy is an npm `overrides` entry, and the
    unscoped form `{"semver": "5.7.2"}` rewrites EVERY copy — downgrading the top-level one. Only
    `{"a": {"semver": "5.7.2"}}` touches the nested copy, and that needs this chain."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return []
    version_line: Dict[str, int] = {}
    pending: Optional[str] = None
    for n, line in enumerate(text.splitlines(), 1):
        m = _LOCK_KEY.match(line)
        if m:
            pending = m.group(1) if m.group(1) not in version_line else None
            continue
        v = _LOCK_VERSION.match(line)
        if v and pending:
            version_line[pending] = n
            pending = None
    out = []
    for key in sorted(packages):
        if "node_modules/" not in key:
            continue                                # the root project ("") and workspace folders
        meta = packages[key] or {}
        version = meta.get("version")
        if not version:
            continue                                # a link or a bundled entry: nothing resolved here
        # `node_modules/a/node_modules/semver` -> parents ["a"], pkg "semver". A scoped name holds a
        # slash but never a `node_modules/` segment, so splitting on the segment keeps `@scope/x` whole.
        segments = key.split("node_modules/")[1:]
        pkg, parents = segments[-1], [s.rstrip("/") for s in segments[:-1]]
        if not pkg:
            continue                                # a malformed `node_modules/` key names nothing
        extra: Dict[str, Any] = {"dev": bool(meta.get("dev"))}
        if parents:
            extra["nested_under"] = parents
        if meta.get("name") and meta["name"] != pkg:
            extra["resolved_name"] = meta["name"]   # an alias: `"node_modules/x": {"name": "y"}`
        extra["origin"] = npm_origin(meta.get("resolved"), meta.get("name") or pkg)
        out.append(_res("npm", file, version_line.get(key, 1), pkg, version, "npm", **extra))
    return sorted(out, key=lambda r: (r["line"], r["package"]))


def _read_yarn_resolutions(text: str, file: str) -> List[Dict[str, Any]]:
    """yarn v1: each entry's `version` line, its origin from the entry's `resolved` line. No edges are read (no
    requirement records)."""
    out: List[Dict[str, Any]] = []
    name: Optional[str] = None
    entry: Optional[Dict[str, Any]] = None
    for n, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith((" ", "#")):
            m = _YARN_HEAD.match(line.strip())
            name = (m.group(1) or m.group(2)) if m else None
            entry = None
            continue
        v = _YARN_VERSION.match(line)
        if v and name:
            entry = _res("npm", file, n, name, v.group(1), "yarn", origin=origin_of("npm", "unrecorded"))
            out.append(entry)
            name = None
            continue
        r = _YARN_RESOLVED.match(line)
        if r and entry is not None:
            entry["origin"] = npm_origin(r.group(1), entry["package"])
    return out


def _read_pnpm_resolutions(text: str, file: str) -> List[Dict[str, Any]]:
    """pnpm-lock.yaml: each key under `packages:` (v5 `/name/1.2.3`, v6+ `/name@1.2.3`). Origin `unrecorded`: a
    registry package carries only `resolution: {integrity}`, and the registry it came from lives in `.npmrc`."""
    out, inside = [], False
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("packages:"):
            inside = True
            continue
        if inside and line and not line.startswith(" "):
            inside = False
        if inside and (m := _PNPM_KEY.match(line)):
            out.append(_res("npm", file, n, m.group(1), m.group(2), "pnpm", origin=origin_of("npm", "unrecorded")))
    return out


def read_resolutions(rel: str, text: str) -> List[Dict[str, Any]]:
    """The `resolution` records of one TOML / npm-family lock (pip-compile output is a requirements file and is
    read by `manifests`, which knows from its header whether it is one)."""
    name = rel.rsplit("/", 1)[-1]
    if name == "uv.lock":
        return _read_toml_resolutions(text, rel, "uv")
    if name == "poetry.lock":
        return _read_toml_resolutions(text, rel, "poetry")
    if name == "package-lock.json":
        return _read_package_lock_resolutions(text, rel)
    if name == "yarn.lock":
        return _read_yarn_resolutions(text, rel)
    if name == "pnpm-lock.yaml":
        return _read_pnpm_resolutions(text, rel)
    return []
