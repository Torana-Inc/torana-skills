#!/usr/bin/env python3
"""Answer Torana's reachability queue for one checkout — deterministically, no model.

    torana alerts reachability-queue  →  this script  →  torana alert <id> reachability

⛔ NO LLM, AND THAT IS THE POINT, not a cost saving. A priority change has to be defensible:
the proof layer's rule is that model text is a label and never evidence, and "the model
thought it wasn't reachable" cannot be a pointer. "`litellm` appears in `uv.lock` and in zero
`.py` files at commit a1b2c3d" can — anyone can re-run it and get the same answer. Determinism
is also what stops an item flapping priority between runs for no reason a reader can see.

TWO QUESTIONS, TWO ANALYSES, and they are not the same cost:

  packages       does THIS REPO import the package at all?    an import scan of the tree
  code_findings  is this function reachable from an entry?     a call graph over the repo

⛔ `--repo-key` IS REQUIRED, AND IT IS THE SCOPE. An answer measured in one checkout is only
about that checkout: the queue returns only findings bound to that repository, and the write
is refused for anything else. ⚠️ An Inbox ENTRY ("Upgrade litellm to 1.88.6") is never one of
them — it groups every place the package appears, across repositories and container images,
so no single checkout can answer it. Entries still move: the ranking derives an entry's
position from its members, so lowering the members lowers the entry.

The import scan is the one that moves priorities — measured across 12 Torana repos: 5 of 12
never import `litellm` and 0 of 12 import `pip`. The call graph mostly CONFIRMS, which is
worth recording but rarely changes an order. So the scan always runs; the call graph runs only
when tree-sitter is present and a code finding asks for it.

⛔ EACH LANGUAGE IS READ WITH ITS OWN GRAMMAR, AND A MISS IS NOT ALWAYS AN ABSENCE. The import
scan carries one pattern set per ecosystem (`_IMPORT_GRAMMAR`) and one answer per ecosystem to
"may a miss be reported as `not_imported`?" (`_ABSENCE`). Both exist because over-matching is
harmless here — it yields `reachable`, which records and moves nothing — while under-matching
yields `not_imported` at priority 85, below every severity the ranking can assign. The call
graph is PYTHON ONLY and says so: a finding in another language is `inconclusive` with that as
the stated reason, never an absence.

⚠️ CALLS THE PLATFORM ONLY THROUGH THE `torana` CLI: no platform import, no source tree of the
platform, no database. It must work on a CI runner that has a checkout, the CLI and a token.

⚠️ `--json` EMITS ONLY JSON on stdout; every diagnostic goes to stderr.

Usage:
    python3 reachability_pass.py --repo . --repo-key repo:host/org/repo [--commit SHA]
                                [--apply] [--json]

Without `--apply` nothing is written: it prints what it would record. ⛔ That default is
deliberate — the first thing anyone does with a new analysis is run it to see what it says,
and a pass that silently re-prioritises an estate on its first run is unforgivable.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

ANALYZER_IMPORTS = "import-index/1"
ANALYZER_CALLGRAPH = "callgraph/1"

#: The `--engines` name that installs the call graph's parser. ⚠️ Must match the entry in
#: `scan_pack.json` -> libraries[].name, or every message here points at a flag that does
#: nothing. The package half of the queue needs none of this.
_TREE_SITTER_ENGINE = "tree-sitter"

#: Directories that never hold shipping code. Excluded from BOTH analyses.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
              "dist", "build", ".tox", ".pytest_cache", "target", "vendor", ".idea"}

#: ⚠️ A path segment that marks code as NOT on the running surface. This is what separates
#: `build_only` from `not_imported`: a package imported solely by a test or a build script is
#: present in the tree and absent from the product.
_NON_RUNTIME = re.compile(r"(^|/)(tests?|testing|spec|specs|e2e|examples?|samples?|docs?|"
                          r"scripts?|tools?|benchmarks?|fixtures?|migrations?|\.github)(/|$)")

#: PyPI name -> the module(s) it actually installs. A distribution name is NOT an import name,
#: and guessing wrong reports "not imported" about a package that is imported everywhere —
#: the one error this pass must never make, because it silently lowers a real finding.
#: ⚠️ Unlisted names fall back to the normalised distribution name, which is right for the
#: large majority (requests, aiohttp, litellm, starlette...). An entry here is a MEASURED
#: exception, not a guess.
_IMPORT_NAME = {
    "pyjwt": ["jwt"], "pyyaml": ["yaml"], "pyopenssl": ["OpenSSL"],
    "beautifulsoup4": ["bs4"], "pillow": ["PIL"], "python-dateutil": ["dateutil"],
    "msgpack-python": ["msgpack"], "protobuf": ["google.protobuf"],
    "scikit-learn": ["sklearn"], "opencv-python": ["cv2"],
    "snowflake-connector-python": ["snowflake.connector", "snowflake"],
    "google-cloud-storage": ["google.cloud.storage"],
    "python-multipart": ["multipart"], "python-jose": ["jose"],
    "typing-extensions": ["typing_extensions"], "attrs": ["attr", "attrs"],
    "setuptools": ["setuptools", "pkg_resources"],
}

#: Ecosystems this pass can answer at all. ⛔ Everything else returns `inconclusive` WITH a
#: reason rather than a guess: a deb/apk package's "use" is a question about the built image
#: (is the .so linked, is the binary invoked), not about source imports, and answering it from
#: a source scan would be confidently wrong on the largest population in the estate.
_SOURCE_ECOSYSTEMS = {"pypi", "npm", "golang", "go", "maven", "nuget", "gem", "cargo",
                      "composer"}

#: The source files an ecosystem's imports can appear in.
#:
#: ⛔ WHY THIS EXISTS: AN ABSENCE THAT WAS GUARANTEED IS NOT A MEASUREMENT. Measured on demo
#: 2026-10-13, the first run after image findings entered the queue: pantheon-admin is a Python
#: repository, and the pass reported `not_imported` for `github-com/docker/docker`,
#: `github-com/containerd/containerd/v2` and `github-com/moby/go-archive` — Go packages that
#: arrive in the base image. The repository holds not one `.go` file, so the scan could never
#: have found them however reachable they were. "We looked and it is absent" and "we could not
#: have seen it" are the same output and completely different facts, and only the first may
#: lower an item.
#:
#: ⚠️ It also makes `files_scanned` honest: the evidence now counts the files that could
#: have carried the import, not every source file in the tree.
_ECOSYSTEM_EXT = {
    "pypi": (".py",),
    "npm": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    "golang": (".go",), "go": (".go",),
    "maven": (".java", ".kt", ".scala"),
    "nuget": (".cs",),
    "gem": (".rb",),
    "cargo": (".rs",),
    "composer": (".php",),
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def torana_cli() -> str:
    """Where the `torana` CLI actually is.

    ⛔ NEVER A BARE `torana`, and this is the skills' own rule, not a preference:
    "Always invoke via `"$TORANA"` — the variable is stable across shell invocations;
    bare `torana` relies on PATH which may not be set." A customer's install puts the
    CLI in a dedicated venv (`$TORANA_VENV/bin/torana`) and does NOT add it to PATH, so
    a bare call dies with "No such file or directory" on the very machine this pass is
    written for — and the first thing to fail is the queue read, which reads like the
    platform has no such command rather than like a CLI nobody could find.

    ⚠️ It worked for us only because every run exported the venv's bin onto PATH first.
    """
    direct = os.environ.get("TORANA")
    if direct and os.path.exists(direct):
        return direct
    venv = os.environ.get("TORANA_VENV") or os.path.join(os.path.expanduser("~"),
                                                         ".torana-venv")
    candidate = os.path.join(venv, "bin", "torana")
    if os.path.exists(candidate):
        return candidate
    return "torana"      # PATH — correct in CI, where pip installs the wheel


def run_cli(args: List[str], *, parse_json: bool = True) -> Tuple[int, Any]:
    """Call the `torana` CLI. Returns (returncode, parsed-or-text)."""
    cmd = [torana_cli(), *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        # ⚠️ SAY WHICH ONE WAS MISSING. "No such file or directory" with no path reads
        # as a missing capability; naming the resolution order sends the reader to the
        # install, which is where the problem is.
        return 127, {"_err": f"the torana CLI was not found (tried $TORANA, "
                             f"$TORANA_VENV/bin/torana, then PATH as {cmd[0]!r}). "
                             f"Load the torana-skill bootstrap, or export TORANA."}
    if not parse_json:
        return p.returncode, (p.stdout or "").strip()
    try:
        return p.returncode, json.loads(p.stdout or "null")
    except json.JSONDecodeError:
        return p.returncode, {"_raw": (p.stdout or "").strip(),
                              "_err": (p.stderr or "").strip()[:400]}


# ── the import index ─────────────────────────────────────────────────────────────────

def source_files(repo: str) -> List[str]:
    """Every source file that could import something, as repo-relative paths."""
    exts = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java", ".rb",
            ".cs", ".php", ".rs", ".kt", ".scala")
    out = []
    for dirpath, dirnames, files in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for f in files:
            if f.endswith(exts):
                out.append(os.path.relpath(os.path.join(dirpath, f), repo))
    return out


#: ⛔ CAN A MISS BE REPORTED AS AN ABSENCE? One answer per ecosystem, and it is the whole
#: soundness question of the import scan.
#:
#: A grammar that OVER-matches is harmless: it yields `reachable`, which records and moves
#: nothing. One that UNDER-matches yields `not_imported` -> priority 85, below every severity
#: the ranking can assign. So every grammar below is built to over-match, and where a package
#: name cannot be mapped to what source actually writes, A MISS IS INCONCLUSIVE.
#:
#: ⚠️ MEASURED 2026-10-13 against a repo that genuinely uses each package. The single pattern
#: set this table replaced knew Python, Node and Go, but `_ECOSYSTEM_EXT` offered it `.rb`,
#: `.rs`, `.cs`, `.php`, `.java` as well — so it reported `not_imported` for Ruby
#: (`require 'nokogiri'` has no parentheses, so the Node pattern missed it), Rust
#: (`use serde::` — no pattern at all), C# (`using Newtonsoft.Json;`), PHP (`use Symfony\...`),
#: Maven (an artifact id never appears in an import) and Go (the platform keys a module as
#: `github-com/...` while the source says `github.com/...`). Six of nine ecosystems, each one
#: lowering a live finding on evidence the scan never had.
#:
#: None = a miss IS a measured absence. A string = why a miss may be the mapping, not the code.
_ABSENCE: Dict[str, Optional[str]] = {
    "pypi": None,     # distribution -> module is conventional; `_IMPORT_NAME` has the exceptions
    "npm": None,      # the import specifier IS the package name
    "golang": None,   # the import path IS the module path
    "go": None,
    "cargo": None,    # the crate identifier is the name with '-' -> '_', a language rule
    "gem": "a gem's require name is conventional and not derivable (`activerecord` is "
           "required as `active_record`), so a miss may be the mapping and not the code",
    "nuget": "a NuGet package id is not always its namespace (`...Logging.Abstractions` "
             "ships `...Logging`), so a miss may be the mapping and not the code",
    "composer": "a composer `vendor/package` does not name its PHP namespace "
                "(`nesbot/carbon` is `Carbon\\`), so a miss may be the mapping and not the code",
    "maven": "a Maven artifact id never appears in an import — only a groupId names a "
             "package — so a miss may be the mapping and not the code",
}


def import_names(package: str, ecosystem: Optional[str]) -> List[str]:
    """The name(s) an import statement would use for this package, in its own ecosystem.

    ⚠️ ECOSYSTEM-SPECIFIC, because the mapping is. PyPI normalises '-' and '.' to '_';
    npm does NOT (`date-fns` is imported as `date-fns`, and normalising it produced a second
    pattern that could only ever over-match); Cargo's '-' -> '_' is a language rule; a gem
    `foo-bar` is conventionally required as `foo/bar`. The rest carry the key's own spelling
    and let their grammar take the part that appears in source (a groupId, a vendor).
    """
    p = (package or "").strip().lower()
    eco = (ecosystem or "").lower()
    if eco in ("golang", "go"):
        return [package]                      # a Go import path is the package path itself
    if eco in ("maven", "nuget", "composer"):
        return [package]                      # the grammar extracts the namespace-bearing part
    if eco == "npm":
        return [package.strip()]              # the specifier is the name, dashes and all
    if eco == "cargo":
        return list(dict.fromkeys([p.replace("-", "_"), p]))
    if eco == "gem":
        return list(dict.fromkeys([p, p.replace("-", "/"), p.replace("-", "_")]))
    if p in _IMPORT_NAME:
        return _IMPORT_NAME[p]
    # PyPI normalises '-'/'.' to '_' in the module name far more often than not. ⚠️ Deduped
    # in order: a name with neither character yields the same string twice, and `modules_tried`
    # is stored evidence a person reads — "litellm, litellm" reads like a bug in the analysis.
    return list(dict.fromkeys([p.replace("-", "_").replace(".", "_"), p]))


def _dots_or_dashes(s: str) -> str:
    """`s` as a regex in which '.' and '-' are interchangeable. ⛔ GO ONLY.

    The platform keys a Go module as `github-com/moby/go-archive` (verified against the live
    finding keys) while the source says `github.com/moby/go-archive` — a normalisation that
    replaced the host's dots with dashes. WHICH segment was the host is not recoverable from
    the key, so each separator is matched as a class instead of guessed. Over-matching here is
    inconsequential: two Go modules differing only in '.' versus '-' do not coexist.
    """
    return "".join("[-.]" if ch in "-." else re.escape(ch) for ch in s)


def _dotted_prefixes(name: str) -> List[str]:
    """`A.B.C` -> ['A.B.C', 'A.B']. ⚠️ Never the bare first segment: `Microsoft` alone would
    match every Microsoft.* using-directive in the tree, which is over-matching with no
    discriminating power left at all."""
    seg = [s for s in name.split(".") if s]
    return [".".join(seg[:i]) for i in range(len(seg), 1, -1)] or [name]


def _py_patterns(mods: List[str]) -> List[re.Pattern]:
    pats = []
    for mod in mods:
        m, top = re.escape(mod), re.escape(mod.split(".")[0])
        pats += [
            re.compile(rf"(?m)^\s*from\s+{m}(?:[\s.]|$)"),
            re.compile(rf"(?m)^\s*import\s+{m}\b"),
            re.compile(rf"(?m)^\s*from\s+{top}(?:[\s.]|$)"),
            re.compile(rf"(?m)^\s*import\s+{top}\b"),
        ]
    return pats


def _js_patterns(mods: List[str]) -> List[re.Pattern]:
    """`require('x')`, `import … 'x'`, a re-export, and a dynamic `import('x')` — all of
    which take the package name whole or followed by a subpath."""
    pats = []
    for mod in mods:
        m, tail = re.escape(mod), r"""(?:/[^'"]*)?['"]"""
        pats += [
            re.compile(rf"""require\(\s*['"]{m}{tail}"""),
            re.compile(rf"""(?m)^\s*import\s[^;\n]*['"]{m}{tail}"""),
            re.compile(rf"""(?m)^\s*export\s[^;\n]*from\s*['"]{m}{tail}"""),
            re.compile(rf"""import\(\s*['"]{m}{tail}"""),
        ]
    return pats


def _go_patterns(mods: List[str]) -> List[re.Pattern]:
    """A Go import is the quoted module path — alone on a line, in an import block, or
    aliased. Matching the quoted path anywhere covers all three."""
    return [re.compile(rf'"{_dots_or_dashes(mod)}(?:/[^"]*)?"') for mod in mods]


def _rb_patterns(mods: List[str]) -> List[re.Pattern]:
    """`require 'x'` — with or without parentheses, which is what the Node pattern missed."""
    return [re.compile(rf"""(?m)^\s*require\s*\(?\s*['"]{re.escape(mod)}(?:/[^'"]*)?['"]""")
            for mod in mods]


def _rs_patterns(mods: List[str]) -> List[re.Pattern]:
    pats = []
    for mod in mods:
        m = re.escape(mod)
        pats += [
            re.compile(rf"(?m)^\s*(?:pub\s+)?use\s+(?:::)?{m}(?:::|\s*;|\s+as\b)"),
            re.compile(rf"(?m)^\s*extern\s+crate\s+{m}\b"),
            re.compile(rf"\b{m}::"),
        ]
    return pats


def _cs_patterns(mods: List[str]) -> List[re.Pattern]:
    """A using-directive, an alias, or a fully-qualified use — against the package id and
    every dotted prefix of it, because the id is not always the namespace."""
    pats = []
    for mod in mods:
        for ns in _dotted_prefixes(mod):
            m = re.escape(ns)
            pats += [
                re.compile(rf"(?m)^\s*(?:global\s+)?using\s+(?:static\s+)?{m}(?:\.|\s*;)"),
                re.compile(rf"(?m)^\s*using\s+\w+\s*=\s*{m}\."),
                re.compile(rf"\b{m}\."),
            ]
    return pats


def _php_patterns(mods: List[str]) -> List[re.Pattern]:
    """The vendor segment tried as a namespace prefix, case-insensitively — `guzzlehttp`
    for `GuzzleHttp\\`. It finds Symfony, Monolog, Psr, Doctrine, League; it does NOT find
    `nesbot/carbon`, which is exactly why composer may not report an absence."""
    pats = []
    for mod in mods:
        vendor = re.escape(mod.split("/", 1)[0])
        pats += [
            re.compile(rf"(?m)^\s*use\s+\\?{vendor}\\", re.I),
            re.compile(rf"\b{vendor}\\", re.I),
        ]
    return pats


def _jvm_patterns(mods: List[str]) -> List[re.Pattern]:
    """⛔ ONLY A groupId, AND ONLY WHEN THE KEY CARRIES ONE. An artifact id never appears in
    a Java import, so `jackson-databind` is unmatchable and this returns [] — which the
    caller reports as inconclusive rather than as an absence.

    ⚠️ The pattern set this replaced took `split('.')[0]` of a `groupId:artifactId`, i.e.
    `com`, and so matched ANY `import com.*`: measured, `com.nobody.unused:not-here` came back
    `reachable` citing a file that imports Jackson. Wrong in both directions at once.
    """
    pats = []
    for mod in mods:
        group = mod.split(":", 1)[0] if ":" in mod else ""
        if "." not in group:
            continue
        # ⚠️ AND ITS DOTTED PREFIXES, because a groupId is not always a prefix of the
        # import: `com.fasterxml.jackson.core` ships `com.fasterxml.jackson.databind.*`.
        # `_dotted_prefixes` never yields the bare first segment, which is what made the old
        # pattern match every `import com.*`; and since maven may not report an absence
        # anyway, an over-match here can only ever produce `reachable`.
        for ns in _dotted_prefixes(group):
            m = re.escape(ns)
            pats += [
                re.compile(rf"(?m)^\s*import\s+(?:static\s+)?{m}\."),
                re.compile(rf"\b{m}\."),
            ]
    return pats


#: ecosystem -> the grammar of its language's import statement. ⛔ An ecosystem absent here
#: gets no patterns, and `package_verdict` then answers `inconclusive`: fail closed, exactly as
#: `_SOURCE_ECOSYSTEMS` and `_ECOSYSTEM_EXT` already do one level up.
_IMPORT_GRAMMAR = {
    "pypi": _py_patterns, "npm": _js_patterns,
    "golang": _go_patterns, "go": _go_patterns,
    "gem": _rb_patterns, "cargo": _rs_patterns, "nuget": _cs_patterns,
    "composer": _php_patterns, "maven": _jvm_patterns,
}


def _import_patterns(mods: List[str], ecosystem: Optional[str]) -> List[re.Pattern]:
    """The patterns an import of `mods` would match IN THIS ECOSYSTEM'S LANGUAGE, or []."""
    build = _IMPORT_GRAMMAR.get((ecosystem or "").lower())
    return build(mods) if build else []


def _dynamic_patterns(mods: List[str], ecosystem: Optional[str]) -> List[re.Pattern]:
    """⚠️ The case a naive grep gets WRONG. A dynamic import is still a use, and reporting
    'not imported' about `importlib.import_module("x")` would lower a live finding.

    ⚠️ Python only: the other languages' dynamic forms take a path or a type name, not a
    package, and `import('x')` is already in the JS grammar above.
    """
    if (ecosystem or "").lower() != "pypi":
        return []
    return [re.compile(rf"""(?:__import__|import_module|importlib\.import_module)"""
                       rf"""\(\s*['"]{re.escape(m.split('.')[0])}""")
            for m in mods]


def scan_imports(repo: str, files: List[str], package: str,
                 ecosystem: Optional[str]) -> Dict[str, Any]:
    """Where, if anywhere, this package is imported — split by runtime vs not."""
    mods = import_names(package, ecosystem)
    pats = _import_patterns(mods, ecosystem)
    dyn = _dynamic_patterns(mods, ecosystem)
    runtime, non_runtime, dynamic = [], [], []
    for rel in files:
        try:
            txt = open(os.path.join(repo, rel), encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        hit = any(p.search(txt) for p in pats)
        dhit = any(p.search(txt) for p in dyn)
        if not (hit or dhit):
            continue
        (non_runtime if _NON_RUNTIME.search(rel) else runtime).append(rel)
        if dhit:
            dynamic.append(rel)
    return {"modules_tried": mods, "runtime": runtime, "patterns": len(pats),
            "non_runtime": non_runtime, "dynamic": dynamic}


def package_verdict(repo: str, files: List[str], pkg: Dict[str, Any],
                    commit: str, repo_key: str) -> Dict[str, Any]:
    """One verdict for one package alert, with the evidence the API requires."""
    name, eco = pkg.get("package_name"), (pkg.get("ecosystem") or "").lower()
    base = {"commit": commit, "analyzer": ANALYZER_IMPORTS, "repository": repo_key}

    if eco and eco not in _SOURCE_ECOSYSTEMS:
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": f"ecosystem '{eco}' is not a source-import "
                                               "ecosystem; its use is a question about the "
                                               "built image, not about source imports",
                             "package_name": name}}

    # ⛔ ONLY THE FILES THAT COULD CARRY THE IMPORT, and inconclusive when there are none.
    # See `_ECOSYSTEM_EXT`: a Go package searched in a repository with no Go source is absent
    # by construction, and reporting that as `not_imported` lowers an item on evidence the
    # scan never had.
    exts = _ECOSYSTEM_EXT.get(eco) if eco else None
    scope = [f for f in files if f.endswith(exts)] if exts else files
    if exts and not scope:
        return {"verdict": "inconclusive",
                "evidence": {**base, "package_name": name,
                             "reason": f"this repository holds no {'/'.join(exts)} source, so "
                                       f"an import scan cannot discriminate for a '{eco}' "
                                       "package: its absence here is guaranteed, not measured"}}

    found = scan_imports(repo, scope, name, eco)
    ev = {**base, "files_scanned": len(scope), "package_name": name,
          "modules_tried": found["modules_tried"]}

    # ⛔ A GRAMMAR THAT COULD NOT BE BUILT HAS NOT LOOKED. `_jvm_patterns` returns nothing
    # for a bare artifact id, because no Java import contains one; scanning with zero patterns
    # finds zero hits, and reporting THAT as `not_imported` is the "we could not have seen it"
    # error with the ecosystem gate passed.
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

    # ⛔ THE MISS. Only an ecosystem whose grammar can also prove an ABSENCE may say so;
    # for the rest a miss is indistinguishable from a name this pass could not map, and the
    # cost of guessing is a real finding at priority 85. See `_ABSENCE`.
    why = _ABSENCE.get(eco, "this ecosystem's import mapping has not been established")
    if why is not None:
        return {"verdict": "inconclusive",
                "evidence": {**ev, "reason": f"{name!r} was not found in {len(scope)} "
                                             f"'{eco}' source file(s), but {why}"}}
    return {"verdict": "not_imported", "evidence": ev}


def _scope_of(path: str) -> str:
    m = _NON_RUNTIME.search(path)
    return m.group(2) if m else "other"


# ── the call graph (optional: only with a tree-sitter parser) ────────────────────────

#: Where `install_engines.sh` puts the parser — the scan pack's ISOLATED venv, which is NOT
#: the interpreter running this script. Same override the installer honours.
_SCAN_PACK = os.environ.get("TORANA_SCAN_PACK_DIR") or os.path.join(
    os.path.expanduser("~"), ".torana", "scan-pack")


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
    import glob
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


_ROUTE_DECOS = ("get", "post", "put", "patch", "delete", "websocket", "route",
                "middleware", "on_event")


#: The separator in a call-graph node id, `rel/path.py::function`.
QSEP = "::"


def _resolve_callee(name: str, caller_file: str,
                    by_name: Dict[str, Any]) -> Tuple[Tuple[str, ...], bool]:
    """Every definition a call to bare `name` from `caller_file` can mean, and whether that
    resolution is CERTAIN.

    ⛔ IT DOES NOT CUT AMBIGUITY, AND THAT IS DELIBERATE — the first version of this
    function did, and it was the wrong trade. Borrowed shape: Visa's VVAH resolves a bare
    callee to <=3 definitions, ranked same-file > unique > nearest directory
    (`_resolve_callee_files`, with the note that file-qualified nodes stop "polymorphic names
    like save()/process()" collapsing the repo into one BFS component). That is right for
    VVAH, which uses the graph to pick code for an LLM to read.

    It is wrong HERE, because our two errors are not symmetric:

      over-approximate (follow a call that is not really made) -> a false `reachable`, which
        records and moves nothing. Harmless.
      under-approximate (drop a call that IS made) -> a false `no_path_from_entry_point`,
        which lowers a live finding to 75. The one error this pass must never make.

    And our callee token is the bare name after the last dot (`obj.save()` and `save()` are
    indistinguishable), so cutting candidates would drop real edges. So ambiguity is FOLLOWED,
    and reported instead: `certain` is False, the BFS records it on the hop, and a verdict
    whose path crosses an uncertain hop says so. Precision we cannot have, we disclose.

    ⛔ NOT EVEN A SAME-FILE PREFERENCE. This function shipped with one — "a definition in the
    caller's own file shadows anything imported, so resolve to it and drop the rest" — which
    is true for a BARE call in Python and false for the token this pass actually has. Measured
    on demo 2026-10-14, pantheon-api-gw: `api/routes/health.py::health_check` (a route
    handler) calls `proxy_service.health_check()`, the preference kept the handler's own
    definition and dropped `services/proxy_service.py::health_check`, and the repository's
    reachable set fell from 31 nodes to 25 — taking `auth_manager.py::initialize` with it, so
    the eval finding in that file turned from `reachable` into `no_path_from_entry_point`.
    A live finding lowered to 75 by a cut: exactly the error named above.

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


def build_callgraph(repo: str) -> Optional[Dict[str, Any]]:
    """Function spans, call edges and framework entry points for the Python tree.

    ⚠️ Python only in this version, and it SAYS SO rather than silently covering less than it
    claims. A finding in another language returns `inconclusive` with that as the reason.
    """
    parser = python_parser()
    if parser is None:
        log(f"callgraph: unavailable (no tree-sitter parser for Python) — {parser_remedy()}")
        return None

    import collections
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
    for dirpath, dirnames, files in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for f in files:
            if not f.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, f), repo)
            try:
                src = open(os.path.join(repo, rel), "rb").read()
                walk(parser.parse(src).root_node, src, rel)
                n += 1
            except Exception:      # noqa: BLE001 — one unparseable file must not stop the pass
                continue

    # ⛔ `reach` MAPS A NODE TO (the caller it was reached from, was that hop certain), not
    # just membership. `reachable` REQUIRES a `path` (invariant 2) and the single-element list
    # this used to store was not one; and a path built over an unresolved call has to say so,
    # or an over-approximation reads exactly like a proven one.
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
    return {"defs": defs, "reach": reach, "entries": entries, "files": n}


def code_verdict(graph: Optional[Dict[str, Any]], cf: Dict[str, Any],
                 commit: str, repo_key: str) -> Dict[str, Any]:
    """One verdict for one code finding."""
    base = {"commit": commit, "analyzer": ANALYZER_CALLGRAPH, "file": cf.get("file"),
            "repository": repo_key}
    path = cf.get("file") or ""

    if graph is None:
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": "no call graph available: no tree-sitter "
                                               "parser for Python on this runner "
                                               f"({parser_remedy()})"}}
    if not path.endswith(".py"):
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": f"this pass builds a call graph for Python "
                                               f"only; {path} is not covered"}}

    in_file = sorted(q for q, v in graph["defs"].items() if v[0] == path)
    if not in_file:
        # ⚠️ No function at all in that file: module-level code, which RUNS ON IMPORT. The
        # honest answer is that reachability does not discriminate here, not "unreachable".
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": "no function found in this file; the finding is "
                                               "module-level code, which runs on import and "
                                               "reachability does not discriminate"}}

    n_entries = len(graph["entries"])
    reachable = [q for q in in_file if q in graph["reach"]]

    # ⛔ NO ENTRY POINT FOUND IS NOT "NOTHING CALLS IT". With an empty entry set the BFS
    # cannot reach anything, so EVERY function in the repository comes back unreachable —
    # measured on a Click CLI repo: 0 entry points, and every code finding deprioritised to
    # 75 on an analysis that never had a starting node. This pass recognises framework route
    # decorators only (`_ROUTE_DECOS`), so a worker, a CLI or a library legitimately has none.
    # ⚠️ Checked AFTER the module-level case, which has its own and better reason, and
    # after `reachable` — which an empty entry set makes empty anyway, so the order only
    # matters if a later edit seeds entries some other way.
    if not reachable and not n_entries:
        return {"verdict": "inconclusive",
                "evidence": {**base, "entry_points_considered": 0,
                             "function": graph["defs"][in_file[0]][3],
                             "function_at": _def_site(graph, in_file[0]),
                             "reason": "the call graph found no entry point in this repository "
                                       "(this pass recognises framework route decorators "
                                       "only), so 'nothing reaches this code' cannot be "
                                       "distinguished from 'nothing here could reach "
                                       "anything'"}}

    if reachable:
        # ⚠️ The MOST CERTAIN chain, then the shortest: evidence a reader can check, rather
        # than whichever function happened to sort first. A path with no unresolved hop is a
        # proven one and is always preferred to a shorter path that rests on a guess.
        paths = {n: _path_to(graph["reach"], n) for n in reachable}
        q = min(reachable, key=lambda n: (paths[n][1], len(paths[n][0]), n))
        chain, unresolved = paths[q]
        return {"verdict": "reachable",
                "evidence": {**base, "function": graph["defs"][q][3],
                             "function_at": _def_site(graph, q),
                             "entry_points_considered": n_entries,
                             "path": chain, "path_unresolved_hops": unresolved,
                             **({"caveat": f"{unresolved} hop(s) on this path rest on a call "
                                           "this analysis could not resolve to one definition "
                                           "(a bare name defined in several files), so the "
                                           "path is possible, not proven"}
                                if unresolved else {})}}
    return {"verdict": "no_path_from_entry_point",
            "evidence": {**base, "function": graph["defs"][in_file[0]][3],
                         "function_at": _def_site(graph, in_file[0]),
                         "entry_points_considered": n_entries}}


# ── the pass ─────────────────────────────────────────────────────────────────────────

def git_head(repo: str) -> Optional[str]:
    p = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    return (p.stdout or "").strip() or None


def git_repo_key(repo: str) -> Optional[str]:
    """`repo:<host>/<org>/<repo>` from the `origin` remote, or None.

    ⚠️ The platform's source-neutral id, so an https remote and an ssh one must reduce to the
    SAME key — otherwise the same repository is two scopes and a verdict measured under one
    never matches a finding stored under the other.
    """
    p = subprocess.run(["git", "-C", repo, "remote", "get-url", "origin"],
                       capture_output=True, text=True)
    url = (p.stdout or "").strip()
    if not url:
        return None
    url = re.sub(r"\.git$", "", url)
    m = re.match(r"^(?:https?://|ssh://)?(?:[^@/]+@)?([^/:]+)[/:](.+)$", url)
    if not m:
        return None
    host, path = m.group(1).lower(), m.group(2).strip("/").lower()
    return f"repo:{host}/{path}" if "/" in path else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", help="the checkout to analyse")
    ap.add_argument("--commit", default=None, help="default: git rev-parse HEAD")
    ap.add_argument("--repo-key", default=None,
                    help="repo:<host>/<org>/<repo> — the SCOPE of this pass. Derived from the "
                         "git remote when omitted; the pass refuses if neither is available.")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--apply", action="store_true",
                    help="write the verdicts back. Default is a dry run.")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="only JSON on stdout")
    a = ap.parse_args()

    repo = os.path.abspath(a.repo)
    commit = a.commit or git_head(repo)
    if not commit:
        log("ERROR: no commit. Pass --commit, or run inside a git checkout.\n"
            "       ⛔ Refusing rather than guessing: a reachability claim with no commit "
            "reads as permanent when it is about one tree.")
        return 2

    repo_key = a.repo_key or git_repo_key(repo)
    if not repo_key:
        log("ERROR: no repository key. Pass --repo-key repo:<host>/<org>/<repo>, or run in a "
            "checkout with an 'origin' remote.\n"
            "       ⛔ Refusing rather than guessing: the key is the SCOPE of every answer "
            "this pass writes. Measured in one tree, a verdict must not be able to move an "
            "item in another — and the platform refuses one that tries.")
        return 2

    q = ["alerts", "reachability-queue", "--repository", repo_key,
         "--commit", commit, "--limit", str(a.limit), "--format", "json"]
    rc, queue = run_cli(q)
    if rc != 0 or not isinstance(queue, dict):
        log(f"ERROR: could not read the queue (rc={rc}): {str(queue)[:300]}")
        return 1

    packages = queue.get("packages") or []
    code_findings = queue.get("code_findings") or []
    members = sum(len(p.get("alert_ids") or []) for p in packages)
    log(f"queue at {commit[:7]} in {repo_key}: {len(packages)} package(s) over {members} "
        f"member alert(s), {len(code_findings)} code finding(s)")

    files = source_files(repo) if packages else []
    graph = build_callgraph(repo) if code_findings else None
    if code_findings and graph is None:
        log("note: no call graph — the code findings will be inconclusive, WITH that as the "
            f"stated reason ({parser_remedy()}). The package list above does not need it.")

    # ⚠️ ONE VERDICT PER PACKAGE, WRITTEN TO EVERY MEMBER IT ANSWERS FOR. "Does this repo
    # import litellm" has one answer however many CVEs are open against it, so the queue
    # returns the members grouped and the tree is scanned once — not once per CVE.
    results = []
    for p in packages:
        v = package_verdict(repo, files, p, commit, repo_key)
        for aid in p.get("alert_ids") or []:
            results.append({"alert_id": aid, "kind": "package",
                            "subject": p.get("package_name"), **v})
    for cf in code_findings:
        v = code_verdict(graph, cf, commit, repo_key)
        results.append({"alert_id": cf["alert_id"], "kind": "code_finding",
                        "subject": cf.get("file"), **v})

    written = []
    if a.apply:
        for r in results:
            ev_path = os.path.join(repo, ".torana-reachability-evidence.json")
            with open(ev_path, "w", encoding="utf-8") as fh:
                json.dump(r["evidence"], fh)
            rc2, out = run_cli(["alert", r["alert_id"], "reachability",
                                "--verdict", r["verdict"], "--commit", commit,
                                "--analyzer", r["evidence"]["analyzer"],
                                "--repository", repo_key,
                                "--evidence-file", ev_path, "--format", "json"])
            written.append({"alert_id": r["alert_id"], "rc": rc2,
                            "outcome": (out or {}).get("outcome") if isinstance(out, dict) else None})
            if rc2 != 0:
                log(f"  WARN {r['alert_id']}: write failed rc={rc2} {str(out)[:200]}")
            try:
                os.unlink(ev_path)
            except OSError:
                pass

    summary = {"commit": commit, "repo": repo, "repository": repo_key,
               "files_scanned": len(files),
               "callgraph": ({"files": graph["files"], "entry_points": len(graph["entries"]),
                              "reachable": len(graph["reach"])} if graph else None),
               "counts": {v: sum(1 for r in results if r["verdict"] == v)
                          for v in sorted({r["verdict"] for r in results})},
               "applied": bool(a.apply), "results": results,
               **({"written": written} if a.apply else {})}

    # ⛔ WHAT THE WRITES DID, and in text mode too. Measured on demo 2026-10-13: an --apply
    # run posted 129 verdicts and printed only the verdict table — identical to a dry run's
    # output apart from one missing line, so an operator could not tell a recorded pass from
    # a refused one. The server's own outcome words are the report: `deprioritised` moved an
    # item, `recorded` kept its order, `already_recorded` means this commit was answered
    # before, and a non-zero rc is a REFUSAL (a wrong repository, an entry, an image member).
    failed = [w for w in written if w["rc"] != 0]
    outcomes = sorted({w["outcome"] for w in written}, key=str)
    summary["write_outcomes"] = {o: sum(1 for w in written if w["outcome"] == o)
                                 for o in outcomes}
    summary["write_failures"] = len(failed)

    if a.as_json:
        print(json.dumps(summary, indent=2))
    else:
        for r in results:
            print(f"  {r['verdict']:<26} {r['kind']:<13} {r['subject']}")
        print(f"\n{summary['counts']}")
        if not a.apply:
            print("\nDry run — nothing written. Re-run with --apply to record these.")
        else:
            print(f"\nWritten: {len(written)} verdict(s) → {summary['write_outcomes']}")
            if failed:
                print(f"REFUSED: {len(failed)} write(s) — see the WARN lines above. A refusal "
                      f"is the server declining an answer it cannot attribute to this "
                      f"repository, not a transport error.")

    # ⚠️ A REFUSED WRITE MUST NOT EXIT 0. This runs as a CI step: with a zero exit a gate
    # goes green while every verdict was declined, which is the quiet failure the whole
    # refusal exists to prevent.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
