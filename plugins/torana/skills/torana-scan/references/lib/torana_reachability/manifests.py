"""Declared and resolved dependency versions, each with its file and line (1.9.0, OI-190; FIX_PR_BUILD_PLAN phase 1).

The one manifest reader: Atlas's `python-manifests` / `node-manifests` extractors, the torana-scan pass and the
remediation planner read the same records from here, so "what do we declare" has one definition.

`read_manifests(root)` returns, sorted by (file, line, package):

- `declaration`: a dependency a manifest DECLARES, on the line that declares it.
  `{kind, ecosystem, file, line, package, version_spec, group, manifest_kind, syntax[, compiled_into][, line_approx]}`
  - `manifest_kind`: `pyproject` | `requirements` | `lock_input` (a pip-compile input spec; `compiled_into` names
    the lock) | `package.json`.
  - `group`: `main` for runtime; `dev`, `peer`, `optional` (npm sections), a poetry group name, a PEP 621
    optional-dependencies extra, or a PEP 735 / `tool.uv` dependency group. This is how the dev/prod split reaches
    the remediation Approval column; on PyPI it is the ONLY place that split is machine-readable.
  - `syntax`: how `version_spec` is written, which is what `policy.admits` needs: `pep508` | `poetry` | `npm`.
  - `line_approx: true`: the TOML/JSON parser saw the dependency but no line declared it in a form the line scanner
    reads (e.g. a one-line inline table); the record is anchored on its table/section header instead of dropped.
- `resolution`: a version a lock RESOLVES (`locks.read_resolutions`, plus pip-compile output found by its header),
  on the line that sets the version. `{kind, ecosystem, file, line, package, version, lock_format, origin
  [, compiled_from]}`. `origin` (1.10.0) = `{verdict, source, url}`, where the lock says the version came from;
  `verdict` is `public` | `other` | `unknown`, and only `public` passes `locks.is_public` (`locks.origin_of`;
  pip-compile: `pip_compile_origins`).
- `manifest_file`: one per manifest or lock considered, `{kind, ecosystem, file, manifest_kind, readable}`. A file
  that does not parse is `readable: false` and makes `declarations_complete` false: an absence from an unreadable
  manifest is not an absence.

Pure stdlib, no network, deterministic.
"""
from __future__ import annotations

import json
import posixpath
import re
import shlex
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from . import locks
from .firstparty import normalize
from .paths import walk_files

try:
    import tomllib
except ModuleNotFoundError:             # Python < 3.11: pyproject.toml is scanned by line only, never cross-checked
    tomllib = None                      # type: ignore[assignment]

#: Ecosystems a declaration reader exists for.
DECLARATION_ECOSYSTEMS = frozenset({"pypi", "npm"})

_TABLE = re.compile(r"^\s*\[([^\[\]]+)\]\s*(#.*)?$")
_POETRY_DEP = re.compile(r"""^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=\s*(.+?)\s*(#.*)?$""")
_ARRAY_START = re.compile(r"""^\s*["']?([A-Za-z0-9_.-]+)["']?\s*=\s*\[(.*)$""")
_STRING = re.compile(r""""([^"]*)"|'([^']*)'""")
_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


# ----- PEP 508 strings and TOML lines ---------------------------------------------------------------------------

def _code(text: str) -> str:
    """The line without its trailing comment (a '#' inside a string is kept)."""
    out, quote = [], None
    for ch in text:
        if quote:
            quote = None if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out)


def _strings(text: str) -> List[str]:
    """The quoted strings on a line (comments dropped)."""
    return [a or b for a, b in _STRING.findall(_code(text)) if a or b]


def _closes_array(text: str) -> bool:
    return "]" in _STRING.sub("", _code(text))


def split_requirement(req: str) -> Optional[Tuple[str, str]]:
    """'uvicorn[standard]==0.30.1 ; python_version >= "3.12"' -> ('uvicorn', '==0.30.1'). A trailing line
    continuation (`\\`) is not part of the spec."""
    m = _REQ.match(req.split(";", 1)[0].strip())
    if not m:
        return None
    spec = m.group(3).strip()
    if spec.endswith("\\"):
        spec = spec[:-1].rstrip()
    return normalize(m.group(1)), spec


def _poetry_spec(value: str) -> str:
    """'"^1.40"' -> '^1.40'; '{version = "^2", extras = [...]}' -> '^2'; a git/path dep -> ''."""
    value = value.strip()
    if value.startswith("{"):
        m = re.search(r"""version\s*=\s*["']([^"']*)["']""", value)
        return m.group(1) if m else ""
    m = _STRING.match(value)
    return (m.group(1) or m.group(2) or "") if m else value


def _poetry_group(table: str) -> Optional[str]:
    if table == "tool.poetry.dependencies":
        return "main"
    if table == "tool.poetry.dev-dependencies":
        return "dev"
    m = re.fullmatch(r"tool\.poetry\.group\.([A-Za-z0-9_-]+)\.dependencies", table)
    return m.group(1) if m else None


def _array_group(table: str, key: str) -> Optional[Tuple[str, str]]:
    """(group, source) when `key = [` in `table` opens a PEP 508 dependency array, else None."""
    if table == "project" and key == "dependencies":
        return "main", "project"
    if table == "project.optional-dependencies":
        return key, "optional"
    if table == "dependency-groups":                    # PEP 735
        return key, "dependency-groups"
    if table == "tool.uv" and key == "dev-dependencies":
        return "dev", "tool.uv"
    return None


def parse_pyproject(lines: List[str]) -> List[Tuple[int, str, str, str, str]]:
    """(line, package, version_spec, group, syntax) for every dependency a pyproject.toml declares, by line."""
    out: List[Tuple[int, str, str, str, str]] = []
    table = ""
    array_group: Optional[str] = None
    for n, line in enumerate(lines, 1):
        if array_group is not None:
            for s in _strings(line):
                parsed = split_requirement(s)
                if parsed:
                    out.append((n, parsed[0], parsed[1], array_group, "pep508"))
            if _closes_array(line):
                array_group = None
            continue
        m = _TABLE.match(line)
        if m:
            table = m.group(1).strip()
            continue
        a = _ARRAY_START.match(line)
        ag = _array_group(table, a.group(1)) if a else None
        if a and ag:
            rest = a.group(2)
            for s in _strings(rest):
                parsed = split_requirement(s)
                if parsed:
                    out.append((n, parsed[0], parsed[1], ag[0], "pep508"))
            if not _closes_array(rest):
                array_group = ag[0]
            continue
        group = _poetry_group(table)
        if group:
            d = _POETRY_DEP.match(line)
            if d and d.group(1).lower() != "python":
                out.append((n, normalize(d.group(1)), _poetry_spec(d.group(2)), group, "poetry"))
    return out


def _pyproject_expected(text: str) -> Optional[List[Tuple[str, str, str, str]]]:
    """(group, package, table, syntax) for every dependency the TOML parser sees, or None when it cannot parse."""
    if tomllib is None:
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    out: List[Tuple[str, str, str, str]] = []

    def reqs(items: Any, group: str, table: str) -> None:
        for s in items if isinstance(items, list) else ():
            parsed = split_requirement(s) if isinstance(s, str) else None
            if parsed:
                out.append((group, parsed[0], table, "pep508"))

    project = data.get("project") or {}
    reqs(project.get("dependencies"), "main", "project")
    for extra, items in (project.get("optional-dependencies") or {}).items():
        reqs(items, extra, "project.optional-dependencies")
    for grp, items in (data.get("dependency-groups") or {}).items():
        reqs(items, grp, "dependency-groups")
    reqs(((data.get("tool") or {}).get("uv") or {}).get("dev-dependencies"), "dev", "tool.uv")
    poetry = (data.get("tool") or {}).get("poetry") or {}
    tables = [("main", "tool.poetry.dependencies", poetry.get("dependencies")),
              ("dev", "tool.poetry.dev-dependencies", poetry.get("dev-dependencies"))]
    tables += [(g, f"tool.poetry.group.{g}.dependencies", (v or {}).get("dependencies"))
               for g, v in (poetry.get("group") or {}).items()]
    for group, table, deps in tables:
        for name in deps if isinstance(deps, dict) else ():
            if name.lower() != "python":
                out.append((group, normalize(name), table, "poetry"))
    return out


def _header_lines(lines: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for n, line in enumerate(lines, 1):
        m = _TABLE.match(line)
        if m:
            out.setdefault(m.group(1).strip(), n)
    return out


def parse_requirements(lines: List[str]) -> List[Tuple[int, str, str]]:
    """(line, package, version_spec) for every requirement line; options, includes, hashes and URLs are skipped."""
    out = []
    for n, line in enumerate(lines, 1):
        text = line.split(" #", 1)[0].strip()
        if not text or text.startswith(("#", "-", "git+", "http:", "https:", ".", "/", "\\")):
            continue
        parsed = split_requirement(text)
        if parsed:
            out.append((n, parsed[0], parsed[1]))
    return out


# ----- pip-compile: which requirements file is an OUTPUT, and of which input -----------------------------------

#: The COMMAND line of the header (`#    pip-compile …`, `#    uv pip compile …`). Anchored at the start of the comment:
#: pip-tools' first line "autogenerated by pip-compile with Python 3.12" is prose, and reading it as the command made
#: "with" the input (Atlas python-manifests@3 had this defect). Matched on the comment's body (1.9.2: the one tokenizer).
_COMMAND =re.compile(r"^(?:\S*/)?(?:uv\s+pip\s+compile|pip-compile|pip\s+compile)(?:\s|$)")
#: How far into the file the command may START (it may continue past it with `\`).
_HEADER_LINES = 15

#: Options that take a VALUE, per tool (1.9.2), so the token after one is never read as the input. Taken from
#: `uv pip compile --help` (uv 0.9.2) and `pip-compile --help` (pip-tools 7.5.1), every value-taking option of each.
#: ⛔ Per tool, because they disagree: `-p` is uv's `--python <PYTHON>` but pip-compile's boolean `--pre`. And
#: `--universal` / `--emit-index-url` are BOOLEAN in both (up to 1.9.1 they were listed as value-taking, so `--universal -o x`
#: lost the output and `--universal requirements.in` lost the input).
_UV_VALUE_FLAGS = frozenset({
    "-c", "--constraints", "--constraint", "--overrides", "-b", "--build-constraints", "-o", "--output-file",
    "--annotation-style", "--custom-compile-command", "--no-emit-package", "--extra", "--group", "--format",
    "-i", "--index-url", "--extra-index-url", "--index", "--default-index", "-f", "--find-links", "--index-strategy",
    "--keyring-provider", "--resolution", "--prerelease", "--fork-strategy", "--exclude-newer",
    "--exclude-newer-package", "--no-binary", "--only-binary", "--no-build-isolation-package", "-C",
    "--config-setting", "--config-settings-package", "--link-mode", "-P", "--upgrade-package", "--refresh-package",
    "-p", "--python", "--python-version", "--python-platform", "--torch-backend", "--allow-insecure-host",
    "--cache-dir", "--config-file", "--directory", "--project", "--color"})
_PIP_COMPILE_VALUE_FLAGS = frozenset({
    "--extra", "-f", "--find-links", "-i", "--index-url", "--extra-index-url", "--cert", "--client-cert",
    "--trusted-host", "-P", "--upgrade-package", "-o", "--output-file", "--newline", "--max-rounds", "--cache-dir",
    "--pip-args", "--resolver", "--unsafe-package", "--config", "-c", "--constraint", "--build-deps-for"})


def pip_compile_argv(lines: List[str]) -> Optional[List[str]]:
    """The command a pip-compile / `uv pip compile` output's header records, as argv: the comment's `#` and
    indentation removed, `\\` continuation lines joined, split with shell quoting (`shlex`). None when the header
    names no command. The remediation applier re-runs EXACTLY this (plus its `--upgrade-package` pins): a hand-built
    command drops flags such as `--universal --python-version 3.13`."""
    text: Optional[str] = None
    for n, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("#"):
            if text is None and n >= _HEADER_LINES:
                return None
            if text is None:
                continue
            break
        body = stripped[1:].strip()
        if text is None:
            if n >= _HEADER_LINES:
                return None
            if not _COMMAND.match(body):
                continue
            text = ""
        if body.endswith("\\"):
            text += body[:-1].rstrip() + " "
            continue
        text += body
        break
    if not text or not text.strip():
        return None
    try:
        return shlex.split(text)
    except ValueError:                                 # an unbalanced quote: split on whitespace rather than fail
        return text.split()


_INDEX_FLAGS = frozenset({"-i", "--index-url", "--default-index"})
_EXTRA_INDEX_FLAGS = frozenset({"--extra-index-url", "--index", "-f", "--find-links"})
_BODY_OPTION = re.compile(r"^\s*(--index-url|-i|--extra-index-url|--find-links|-f)[\s=]+(\S+)")
_FROM_ANNOTATION = re.compile(r"^\s+#\s+from\s+(\S+)\s*$")


def pip_compile_origins(lines: List[str]) -> Tuple[Dict[str, Any], Dict[int, Dict[str, Any]]]:
    """(the origin every pin of a pip-compile output shares, {pin line: its own origin}) (1.10.0).

    - A pin followed by a `# from <index>` comment (`uv pip compile --emit-index-annotation`) came from that index.
    - Otherwise ONE index named by the header command (`-i` / `--index-url` / `--default-index`) or by a body
      option line (`--emit-index-url`), with no extra index or find-links, is every pin's origin.
    - More than one place to look is `ambiguous`; nothing named is `unrecorded`; both are verdict `unknown`, NOT
      public. ⛔ Neither is PyPI: the tool's
      default index comes from the environment (`PIP_INDEX_URL`, `UV_INDEX_URL`, a config file), which the file does
      not record."""
    primary: List[str] = []
    extra: List[str] = []
    argv = pip_compile_argv(lines) or []
    skip: Optional[str] = None
    for a in argv:
        if skip:
            (primary if skip in _INDEX_FLAGS else extra).append(a)
            skip = None
        elif "=" in a and a.startswith("--") and a.split("=", 1)[0] in _INDEX_FLAGS | _EXTRA_INDEX_FLAGS:
            flag, value = a.split("=", 1)
            (primary if flag in _INDEX_FLAGS else extra).append(value)
        elif a in _INDEX_FLAGS or a in _EXTRA_INDEX_FLAGS:
            skip = a
    per_line: Dict[int, Dict[str, Any]] = {}
    pin: Optional[int] = None
    for n, line in enumerate(lines, 1):
        if (m := _BODY_OPTION.match(line)):
            (primary if m.group(1) in ("--index-url", "-i") else extra).append(m.group(2))
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            pin = n
            continue
        if pin is not None and (f := _FROM_ANNOTATION.match(line)):
            per_line[pin] = locks.origin_of("pypi", "registry", f.group(1))
    indexes = sorted({locks.clean_url(u) for u in primary})
    if extra or len(indexes) > 1:
        default = locks.origin_of("pypi", "ambiguous")
    elif indexes:
        bad = next((u for u in primary if locks.suspicious_authority(u)), None)
        default = locks.origin_of("pypi", "registry", indexes[0], raw=bad)
    else:
        default = locks.origin_of("pypi", "unrecorded")
    return default, per_line


def _compile_operands(argv: List[str]) -> Tuple[str, str]:
    """(the first positional operand, the `-o` value) of a compile argv, with the tool's own value-flag set."""
    if len(argv) > 2 and argv[1:3] == ["pip", "compile"]:            # `uv pip compile`, `/path/to/uv pip compile`
        args, flags = argv[3:], _UV_VALUE_FLAGS
    elif argv[:2] == ["pip", "compile"]:
        args, flags = argv[2:], _UV_VALUE_FLAGS
    else:                                                             # `pip-compile`, `/path/to/pip-compile`
        args, flags = argv[1:], _PIP_COMPILE_VALUE_FLAGS
    positional, output, skip = "", "", None
    for a in args:
        if skip:
            output = a if skip in ("-o", "--output-file") else output
            skip = None
        elif a.startswith("--") and "=" in a:
            flag, value = a.split("=", 1)
            output = value if flag == "--output-file" else output
        elif a in flags:
            skip = a
        elif a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
            output = a[2:]                              # `-orequirements.txt`
        elif not a.startswith("-") and not positional:
            positional = a
    return positional, output


def pip_compile_header(lines: List[str]) -> Tuple[str, str, bool]:
    """(input, output, autogenerated) from the first comment lines of a `pip-compile` / `uv pip compile` output.
    The command is read by `pip_compile_argv` (1.9.2: one tokenizer for both)."""
    autogenerated = any(line.lstrip().startswith("#") and "autogenerated" in line.lower()
                        for line in lines[:_HEADER_LINES])
    argv = pip_compile_argv(lines)
    return (*(_compile_operands(argv) if argv else ("", "")), autogenerated)


def pip_compile_input(lines: List[str], name: Optional[str] = None) -> Tuple[bool, str]:
    """(is a pip-compile OUTPUT, the input its header names or ""). A file whose comments only quote the command
    (an input saying how to recompile it) is not an output: the header must say autogenerated, or `-o` must name it."""
    source, output, autogenerated = pip_compile_header(lines)
    if not (source or output):
        return False, ""
    if name is not None and name.endswith(".in"):
        return False, ""
    is_output = autogenerated or (name is not None and output.rsplit("/", 1)[-1] == name)
    return (True, source) if is_output else (False, "")


def _is_requirements(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name.startswith("requirements") and name.rsplit(".", 1)[-1] in ("txt", "lock", "in") and "." in name


def _join(base_file: str, rel_path: str) -> str:
    return posixpath.normpath(posixpath.join(posixpath.dirname(base_file), rel_path))


def _lines(base: Path, rel: str) -> Optional[List[str]]:
    try:
        return (base / rel).read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        return None


# ----- package.json --------------------------------------------------------------------------------------------

NPM_SECTIONS = {"dependencies": "main", "devDependencies": "dev", "peerDependencies": "peer",
                "optionalDependencies": "optional"}
_SECTION_START = re.compile(r'^\s*"(%s)"\s*:\s*\{' % "|".join(NPM_SECTIONS))
_ENTRY = re.compile(r'^\s*"((?:@[^"/]+/)?[^"]+)"\s*:\s*"([^"]*)"')


def parse_package_json(lines: List[str]) -> List[Tuple[int, str, str, str]]:
    """(line, package, version_spec, group) for every entry of a dependency section, by line."""
    out = []
    section: Optional[str] = None
    depth = 0
    for n, line in enumerate(lines, 1):
        if section is None:
            m = _SECTION_START.match(line)
            if m:
                section, depth = m.group(1), line.count("{") - line.count("}")
                if depth <= 0:
                    section = None
            continue
        e = _ENTRY.match(line)
        if e and depth == 1:
            out.append((n, e.group(1), e.group(2), NPM_SECTIONS[section]))
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            section = None
    return out


# ----- the reader ----------------------------------------------------------------------------------------------

def _decl(eco: str, file: str, line: int, package: str, spec: str, group: str, kind: str, syntax: str,
          **extra: Any) -> Dict[str, Any]:
    return {"kind": "declaration", "ecosystem": eco, "file": file, "line": line, "package": package,
            "version_spec": spec, "group": group, "manifest_kind": kind, "syntax": syntax, **extra}


def _mfile(eco: str, file: str, kind: str, readable: bool) -> Dict[str, Any]:
    return {"kind": "manifest_file", "ecosystem": eco, "file": file, "manifest_kind": kind, "readable": readable}


def _read_pyproject(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    scanned = parse_pyproject(lines)
    out = [_decl("pypi", rel, n, pkg, spec, group, "pyproject", syntax) for n, pkg, spec, group, syntax in scanned]
    expected = _pyproject_expected("\n".join(lines))
    out.insert(0, _mfile("pypi", rel, "pyproject", expected is not None or tomllib is None))
    if expected:
        seen: Dict[Tuple[str, str], int] = {}
        for _, pkg, _, group, _ in scanned:
            seen[(group, pkg)] = seen.get((group, pkg), 0) + 1
        headers = _header_lines(lines)
        for group, pkg, table, syntax in expected:
            if seen.get((group, pkg), 0) > 0:
                seen[(group, pkg)] -= 1
                continue
            out.append(_decl("pypi", rel, headers.get(table, 1), pkg, "", group, "pyproject", syntax,
                             line_approx=True))
    return out


def _read_package_json(rel: str, text: str, lines: List[str]) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return [_mfile("npm", rel, "package.json", False)]
    out = [_mfile("npm", rel, "package.json", True)]
    scanned = parse_package_json(lines)
    out += [_decl("npm", rel, n, pkg, spec, group, "package.json", "npm") for n, pkg, spec, group in scanned]
    seen = {(group, pkg) for _, pkg, _, group in scanned}
    starts = {}
    for n, line in enumerate(lines, 1):
        m = _SECTION_START.match(line)
        if m:
            starts.setdefault(m.group(1), n)
    for section, group in NPM_SECTIONS.items():
        deps = data.get(section) if isinstance(data, dict) else None
        for pkg, spec in (deps.items() if isinstance(deps, dict) else ()):
            if (group, pkg) not in seen and isinstance(spec, str):
                out.append(_decl("npm", rel, starts.get(section, 1), pkg, spec, group, "package.json", "npm",
                                 line_approx=True))
    return out


def _pip_inputs(base: Path, rels: Iterable[str]) -> Dict[str, str]:
    """Repository path of each pip-compile INPUT spec -> the lock compiled from it (first in path order)."""
    out: Dict[str, str] = {}
    for rel in rels:
        if not _is_requirements(rel) or rel.endswith(".in"):
            continue
        lines = _lines(base, rel) or []
        compiled, source = pip_compile_input(lines, rel.rsplit("/", 1)[-1])
        if (compiled or rel.endswith(".lock")) and source:
            candidate = _join(rel, source)
            if (base / candidate).is_file():
                out.setdefault(candidate, rel)
    return out


def _sibling(base: Path, rel: str, name: str) -> Optional[str]:
    p = _join(rel, name)
    return p if (base / p).is_file() else None


def is_manifest(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return (name in ("pyproject.toml", "package.json", "uv.lock", "poetry.lock", "package-lock.json", "yarn.lock",
                     "pnpm-lock.yaml") or _is_requirements(rel))


def read_manifests(root: str | Path, files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Every declaration, resolution and manifest_file record under `root` (see the module docstring)."""
    base = Path(root)
    rels = [f for f in (files if files is not None else walk_files(base)) if is_manifest(f)]
    inputs = _pip_inputs(base, rels)
    out: List[Dict[str, Any]] = []
    for rel in rels:
        name = rel.rsplit("/", 1)[-1]
        lines = _lines(base, rel)
        if lines is None:
            eco = "npm" if name.endswith((".json", ".yaml")) or name == "yarn.lock" else "pypi"
            out.append(_mfile(eco, rel, "unreadable", False))
            continue
        text = "\n".join(lines)
        if name in ("uv.lock", "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            res = locks.read_resolutions(rel, text)
            eco = "pypi" if name.endswith(".lock") and name != "yarn.lock" else "npm"
            out.append(_mfile(eco, rel, "lockfile", bool(res) or not text.strip()))
            source: Optional[str] = None
            if name == "uv.lock":
                root_dir = locks.lock_root(text)
                source = _sibling(base, rel, posixpath.join(root_dir, "pyproject.toml")) if root_dir is not None else None
            elif name == "poetry.lock":
                source = _sibling(base, rel, "pyproject.toml")
            else:
                source = _sibling(base, rel, "package.json")
            out += [{**r, **({"compiled_from": source} if source else {})} for r in res]
        elif name == "pyproject.toml":
            out += _read_pyproject(rel, lines)
        elif name == "package.json":
            out += _read_package_json(rel, text, lines)
        else:                                       # requirements*.txt|lock|in
            compiled, source_in = pip_compile_input(lines, name)
            if (compiled or rel.endswith(".lock")) and rel not in inputs:
                src = None
                if source_in:
                    cand = _join(rel, source_in)
                    src = cand if (base / cand).is_file() else source_in
                out.append(_mfile("pypi", rel, "lockfile", True))
                default_origin, pin_origin = pip_compile_origins(lines)
                for n, pkg, spec in parse_requirements(lines):
                    version = spec[3:] if spec.startswith("===") else spec[2:] if spec.startswith("==") else None
                    out.append({**locks._res("pypi", rel, n, pkg, version, "pip-compile",
                                             origin=pin_origin.get(n, default_origin)),
                                **({"version_spec": spec} if version is None else {}),
                                **({"compiled_from": src} if src else {})})
                continue
            kind = "lock_input" if rel in inputs else "requirements"
            out.append(_mfile("pypi", rel, kind, True))
            reqs = parse_requirements(lines)
            out += [_decl("pypi", rel, n, pkg, spec, "main", kind, "pep508",
                          **({"compiled_into": inputs[rel]} if kind == "lock_input" else {}))
                    for n, pkg, spec in reqs]
            # ⭐ AN `==` PIN IS A RESOLUTION, as well as a declaration. `pip install -r requirements.txt` plus
            # `pip freeze > requirements.txt` is the oldest and commonest Python workflow, and it produces ONE
            # file that is both "what I want" and "what I got". Only a pip-compile header or a `.lock` name made
            # a requirements file a lock above, so a plainly pinned requirements.txt resolved NOTHING and every
            # finding against it was declined `lock_drift` — "this scope did not build the scanned artifact" —
            # when the installed version was on the line the planner had already read. MEASURED 2026-10-20:
            # pygoat, 14 findings, 14 declines. ⭐ PER LINE, NOT PER FILE: a half-pinned file needs no verdict
            # about itself, because `==` states a version and a range does not. A wildcard (`==1.2.*`) names no
            # single version, so it states nothing. ⛔ Never for a `lock_input`: a `.in` compiled into a `.lock`
            # has its resolution THERE, and a second one here would compete with it.
            # ⚠️ `lock_format` is `requirements`, not `pip-compile`: there is no header to recompile with, and
            # nothing to recompile — editing the pin IS the whole change (the collapse Go has, for its own
            # reason).
            if kind == "requirements":
                default_origin, pin_origin = pip_compile_origins(lines)
                for n, pkg, spec in reqs:
                    v = spec[3:] if spec.startswith("===") else spec[2:] if spec.startswith("==") else None
                    if not v or "*" in v:
                        continue
                    out.append(locks._res("pypi", rel, n, pkg, v, "requirements",
                                          origin=pin_origin.get(n, default_origin)))
    order = {"manifest_file": 0, "declaration": 1, "resolution": 2}
    return sorted(out, key=lambda r: (r["file"], r.get("line", 0), order[r["kind"]], r.get("package", "")))


def declarations_complete(records: List[Dict[str, Any]], eco: str) -> bool:
    """True when a declaration reader exists for `eco`, at least one of its manifests was found, and every one
    of them was readable. Only then is "not declared here" an absence rather than a gap."""
    e = (eco or "").lower()
    files = [r for r in records if r.get("kind") == "manifest_file" and r["ecosystem"] == e
             and r["manifest_kind"] != "lockfile"]
    return e in DECLARATION_ECOSYSTEMS and bool(files) and all(r["readable"] for r in files)


def declared(records: List[Dict[str, Any]], eco: str, package: str) -> List[Dict[str, Any]]:
    """Every declaration of `package` (PyPI names compared normalised)."""
    e = (eco or "").lower()
    want = normalize(package) if e == "pypi" else package
    return [r for r in records if r.get("kind") == "declaration" and r["ecosystem"] == e and r["package"] == want]


def packages_declared(records: List[Dict[str, Any]], eco: str) -> Set[str]:
    return {r["package"] for r in records if r.get("kind") == "declaration" and r["ecosystem"] == eco}
