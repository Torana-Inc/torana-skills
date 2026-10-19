"""The import grammar: per ecosystem, how source names a package, and whether a miss is an absence.

Moved from pantheon-cli `skills/torana-scan/references/reachability_pass.py` (`:84-125`, `:192-414` at
4222f48), with one refactor the spec requires (REACHABILITY_EXTRACTOR.md § 3.3.2.1 step 1): every pattern
builder became a TEMPLATE with one placeholder `{m}` and its regex flags held OUTSIDE the string. A package's
patterns are exactly today's (`tests/test_templates_match_oracle.py` compares them with the frozen oracle).

⛔ WHY THE FLAGS ARE NOT INLINE. The index wraps each superset in a lookahead, `(?=(S))`. Python >= 3.11 raises
`re.error: global flags not at the start of the expression` for an inline `(?m)` inside it (checked on 3.12.8 and
3.13.3). So a template never carries `(?m)` / `(?i)`; its `flags` do.

⛔ THE ASYMMETRY EVERY TABLE HERE SERVES. Over-matching yields `reachable`, which records and moves nothing.
Under-matching yields `not_imported`, which may lower a live finding. Every grammar is built to over-match, and
where a package name cannot be mapped to what source writes, a miss is `inconclusive` (`_ABSENCE`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

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

#: Every extension the import scan reads (`source_files`). The union of `_ECOSYSTEM_EXT`.
SOURCE_EXT = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java", ".rb",
              ".cs", ".php", ".rs", ".kt", ".scala")

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

#: The ecosystems whose miss is a measured absence (`_ABSENCE[eco] is None`). Only these can answer
#: `not_imported`, so only their spans are stored in an Atlas index (§ 3.3.2.1 records, review N2).
ABSENCE_PROVEN = frozenset(eco for eco, why in _ABSENCE.items() if why is None)


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


# ── templates ─────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Template:
    """One import form of one ecosystem: `template` holds `{m}` where the package part goes.

    `part(mod)` gives the substitutions (already regex text) for one import name: usually
    `[re.escape(mod)]`, the dotted prefixes for C#/JVM, the vendor for PHP, `_dots_or_dashes` for Go,
    nothing at all for a JVM name with no groupId. `dynamic` marks Python's dynamic-import form, which the
    scan reports separately (`dynamic` list). `since` is None for the frozen grammar (today's scan, parity-proven
    against the oracle) and names the change that ADDED the template otherwise (§ 3.3.2.5: templates are only added).
    """
    id: str
    template: str
    flags: int
    part: Callable[[str], List[str]]
    dynamic: bool = False
    since: Optional[str] = None

    def fill(self, value: str) -> str:
        return self.template.replace("{m}", value)

    def compile(self, value: str) -> "re.Pattern[str]":
        return re.compile(self.fill(value), self.flags)


def _esc(mod: str) -> List[str]:
    return [re.escape(mod)]


def _esc_top(mod: str) -> List[str]:
    return [re.escape(mod.split(".")[0])]


def _esc_go(mod: str) -> List[str]:
    return [_dots_or_dashes(mod)]


def _esc_prefixes(mod: str) -> List[str]:
    return [re.escape(ns) for ns in _dotted_prefixes(mod)]


def _esc_vendor(mod: str) -> List[str]:
    return [re.escape(mod.split("/", 1)[0])]


def _esc_group_prefixes(mod: str) -> List[str]:
    """⛔ ONLY A groupId, AND ONLY WHEN THE KEY CARRIES ONE. An artifact id never appears in
    a Java import, so `jackson-databind` is unmatchable and this returns [] — which the
    caller reports as inconclusive rather than as an absence.

    ⚠️ The pattern set this replaced took `split('.')[0]` of a `groupId:artifactId`, i.e.
    `com`, and so matched ANY `import com.*`: measured, `com.nobody.unused:not-here` came back
    `reachable` citing a file that imports Jackson. Wrong in both directions at once.

    ⚠️ AND ITS DOTTED PREFIXES, because a groupId is not always a prefix of the
    import: `com.fasterxml.jackson.core` ships `com.fasterxml.jackson.databind.*`.
    `_dotted_prefixes` never yields the bare first segment, which is what made the old
    pattern match every `import com.*`; and since maven may not report an absence
    anyway, an over-match here can only ever produce `reachable`.
    """
    group = mod.split(":", 1)[0] if ":" in mod else ""
    if "." not in group:
        return []
    return [re.escape(ns) for ns in _dotted_prefixes(group)]


_JS_TAIL = r"""(?:/[^'"]*)?['"]"""

# ── OI-141 (§ 3.3.2.5): forms today's grammar MISSES in the four ABSENCE_PROVEN ecosystems ─────────────────────
#: ⛔ ONLY ADDED, NEVER CHANGED. A hit is `any(P.search)`, so an added template can only add hits: a verdict moves
#: only towards `build_only` / `reachable`, which move nothing. Each was MEASURED as an oracle `not_imported` on a
#: file that imports the package (`tests/test_oi141.py` holds one fixture per template).
_OI141 = "OI-141"
_PY_LIST = r"(?:[A-Za-z_][\w.]*(?:\s+as\s+[A-Za-z_]\w*)?[\s\\]*,[\s\\]*)*"
_PY_EXT = (
    # `import os, yaml` · `import a as b, yaml` · a backslash continuation · `try: import yaml` · `x = 1; import yaml`
    Template("py_import_ext", r"(?:^|[:;])[^\S\n]*import\s+" + _PY_LIST + r"{m}\b", re.M, _esc, since=_OI141),
    Template("py_import_ext_top", r"(?:^|[:;])[^\S\n]*import\s+" + _PY_LIST + r"{m}\b", re.M, _esc_top,
             since=_OI141),
    # `if X: from yaml import load` · `x = 1; from yaml import a`
    Template("py_from_ext", r"[:;][^\S\n]*from\s+{m}(?:[\s.]|$)", re.M, _esc, since=_OI141),
    Template("py_from_ext_top", r"[:;][^\S\n]*from\s+{m}(?:[\s.]|$)", re.M, _esc_top, since=_OI141),
)
_JS_EXT = (
    # the `from 'x'` of a multi-line `import {…} from` / `export {…} from` (the usual TypeScript style), or of a
    # second statement after `;` on one line
    Template("js_from", r"""\bfrom\s*['"]{m}""" + _JS_TAIL, 0, _esc, since=_OI141),
    # a side-effect `import 'x'` after `;` or `}` on the same line
    Template("js_import_inline", r"""[;}][^\S\n]*import\s*['"]{m}""" + _JS_TAIL, 0, _esc, since=_OI141),
)
_RS_EXT = (
    # `pub(crate) use serde;` · `use {serde, tokio};` · `fn a() {} use serde as s;`
    Template("rs_use_ext", r"(?:^|[;{}\]])\s*(?:pub(?:\s*\([^)]*\))?\s+)?use\s+(?:::)?(?:\{[^}]*\b)?{m}"
             r"(?:::|\s*[;,}]|\s+as\b)", re.M, _esc, since=_OI141),
    # `#[macro_use] extern crate serde;`
    Template("rs_extern_ext", r"(?:^|[;{}\]])\s*extern\s+crate\s+{m}\b", re.M, _esc, since=_OI141),
)
#: a raw-string import path (valid Go): import (`github.com/x/y`)
_GO_EXT = (Template("go_raw", r"`{m}(?:/[^`]*)?`", 0, _esc_go, since=_OI141),)

#: ecosystem -> its templates, IN TODAY'S ORDER (per import name, the templates in this order; C#/JVM: per
#: dotted prefix, the templates in this order). Template ids are the record ids of § 3.3.2.1.
_PY = (
    # `from x` / `import x`, for the module and for its top segment.
    Template("py_from", r"^\s*from\s+{m}(?:[\s.]|$)", re.M, _esc),
    Template("py_import", r"^\s*import\s+{m}\b", re.M, _esc),
    Template("py_from_top", r"^\s*from\s+{m}(?:[\s.]|$)", re.M, _esc_top),
    Template("py_import_top", r"^\s*import\s+{m}\b", re.M, _esc_top),
)
#: ⚠️ The case a naive grep gets WRONG. A dynamic import is still a use, and reporting
#: 'not imported' about `importlib.import_module("x")` would lower a live finding.
#: ⚠️ Python only: the other languages' dynamic forms take a path or a type name, not a
#: package, and `import('x')` is already in the JS grammar.
_PY_DYNAMIC = Template("py_dynamic",
                       r"""(?:__import__|import_module|importlib\.import_module)\(\s*['"]{m}""",
                       0, _esc_top, dynamic=True)
_JS = (
    # `require('x')`, `import … 'x'`, a re-export, and a dynamic `import('x')` — all of
    # which take the package name whole or followed by a subpath.
    Template("js_require", r"""require\(\s*['"]{m}""" + _JS_TAIL, 0, _esc),
    Template("js_import", r"""^\s*import\s[^;\n]*['"]{m}""" + _JS_TAIL, re.M, _esc),
    Template("js_export", r"""^\s*export\s[^;\n]*from\s*['"]{m}""" + _JS_TAIL, re.M, _esc),
    Template("js_dynamic", r"""import\(\s*['"]{m}""" + _JS_TAIL, 0, _esc),
)
#: A Go import is the quoted module path — alone on a line, in an import block, or
#: aliased. Matching the quoted path anywhere covers all three.
_GO = (Template("go_quoted", r'"{m}(?:/[^"]*)?"', 0, _esc_go),)
#: `require 'x'` — with or without parentheses, which is what the Node pattern missed.
_RB = (Template("rb_require", r"""^\s*require\s*\(?\s*['"]{m}(?:/[^'"]*)?['"]""", re.M, _esc),)
_RS = (
    Template("rs_use", r"^\s*(?:pub\s+)?use\s+(?:::)?{m}(?:::|\s*;|\s+as\b)", re.M, _esc),
    Template("rs_extern", r"^\s*extern\s+crate\s+{m}\b", re.M, _esc),
    Template("rs_path", r"\b{m}::", 0, _esc),
)
#: A using-directive, an alias, or a fully-qualified use — against the package id and
#: every dotted prefix of it, because the id is not always the namespace.
_CS = (
    Template("cs_using", r"^\s*(?:global\s+)?using\s+(?:static\s+)?{m}(?:\.|\s*;)", re.M, _esc_prefixes),
    Template("cs_alias", r"^\s*using\s+\w+\s*=\s*{m}\.", re.M, _esc_prefixes),
    Template("cs_qualified", r"\b{m}\.", 0, _esc_prefixes),
)
#: The vendor segment tried as a namespace prefix, case-insensitively — `guzzlehttp`
#: for `GuzzleHttp\\`. It finds Symfony, Monolog, Psr, Doctrine, League; it does NOT find
#: `nesbot/carbon`, which is exactly why composer may not report an absence.
_PHP = (
    Template("php_use", r"^\s*use\s+\\?{m}\\", re.M | re.I, _esc_vendor),
    Template("php_qualified", r"\b{m}\\", re.I, _esc_vendor),
)
_JVM = (
    Template("jvm_import", r"^\s*import\s+(?:static\s+)?{m}\.", re.M, _esc_group_prefixes),
    Template("jvm_qualified", r"\b{m}\.", 0, _esc_group_prefixes),
)

#: ecosystem -> the grammar of its language's import statement, as templates. ⛔ An ecosystem absent
#: here gets no patterns, and the verdict is then `inconclusive`: fail closed.
TEMPLATES: Dict[str, Tuple[Template, ...]] = {
    "pypi": _PY + (_PY_DYNAMIC,) + _PY_EXT, "npm": _JS + _JS_EXT,
    "golang": _GO + _GO_EXT, "go": _GO + _GO_EXT,
    "gem": _RB, "cargo": _RS + _RS_EXT, "nuget": _CS,
    "composer": _PHP, "maven": _JVM,
}

#: The two grammars a query can use: `full` (the default every runner uses) and `frozen` (today's scan only: the
#: strict-parity proof that the MOVE changed nothing, § 3.3.2.5).
GRAMMARS = ("full", "frozen")

#: The templates added by OI-141 (`tests/test_templates_match_oracle.py` pins this set).
OI141_TEMPLATES = frozenset(t.id for ts in TEMPLATES.values() for t in ts if t.since == _OI141)

#: Per ecosystem, one NAME CLASS: a regex matching every string `re.escape(x)` (or `_dots_or_dashes(x)`) can
#: stand for in that ecosystem, greedily (§ 3.3.2.1 step 2). The superset of a template is the template with
#: `{m}` = this class; an index stores the spans the superset matches.
NAME: Dict[str, str] = {
    "pypi": r"[A-Za-z_][A-Za-z0-9_.]*",
    "npm": r"[@A-Za-z0-9_.~\-][@A-Za-z0-9_.~/\-]*",
    "golang": r"[A-Za-z0-9_.~\-][A-Za-z0-9_.~/\-]*",
    "go": r"[A-Za-z0-9_.~\-][A-Za-z0-9_.~/\-]*",
    "cargo": r"[A-Za-z_][A-Za-z0-9_]*",
    "gem": r"[A-Za-z0-9_.\-][A-Za-z0-9_./\-]*",
    "nuget": r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
    "maven": r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
    "composer": r"[A-Za-z_][A-Za-z0-9_]*",
}


def superset(eco: str, t: Template, name_class: Optional[str] = None) -> "re.Pattern[str]":
    """The template's superset `S`: `{m}` = the ecosystem's name class (or `name_class`, for the property test's
    positive control)."""
    return t.compile(name_class if name_class is not None else NAME[eco])


def templates_of(eco: Optional[str], grammar: str = "full") -> Tuple[Template, ...]:
    """The ecosystem's templates in `grammar` (`full`, or `frozen` = only `since is None`)."""
    if grammar not in GRAMMARS:
        raise ValueError(f"grammar must be one of {GRAMMARS}, not {grammar!r}")
    ts = TEMPLATES.get((eco or "").lower(), ())
    return ts if grammar == "full" else tuple(t for t in ts if t.since is None)


def template_patterns(eco: Optional[str], mods: List[str], grammar: str = "full"
                      ) -> List[Tuple[Template, "re.Pattern[str]"]]:
    """Every (template, package pattern) for `mods`: per name, per template, per part."""
    out: List[Tuple[Template, "re.Pattern[str]"]] = []
    for mod in mods:
        for t in templates_of(eco, grammar):
            for value in t.part(mod):
                out.append((t, t.compile(value)))
    return out


def _patterns(eco: str, mods: List[str], *, dynamic: bool, grammar: str = "full") -> List["re.Pattern[str]"]:
    return [p for t, p in template_patterns(eco, mods, grammar) if t.dynamic is dynamic]


def _py_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("pypi", mods, dynamic=False)


def _js_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("npm", mods, dynamic=False)


def _go_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("golang", mods, dynamic=False)


def _rb_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("gem", mods, dynamic=False)


def _rs_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("cargo", mods, dynamic=False)


def _cs_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("nuget", mods, dynamic=False)


def _php_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("composer", mods, dynamic=False)


def _jvm_patterns(mods: List[str]) -> List["re.Pattern[str]"]:
    return _patterns("maven", mods, dynamic=False)


#: ecosystem -> the grammar of its language's import statement. ⛔ An ecosystem absent here
#: gets no patterns, and the verdict then answers `inconclusive`: fail closed, exactly as
#: `_SOURCE_ECOSYSTEMS` and `_ECOSYSTEM_EXT` already do one level up.
_IMPORT_GRAMMAR = {
    "pypi": _py_patterns, "npm": _js_patterns,
    "golang": _go_patterns, "go": _go_patterns,
    "gem": _rb_patterns, "cargo": _rs_patterns, "nuget": _cs_patterns,
    "composer": _php_patterns, "maven": _jvm_patterns,
}


def _import_patterns(mods: List[str], ecosystem: Optional[str], grammar: str = "full"
                     ) -> List["re.Pattern[str]"]:
    """The patterns an import of `mods` would match IN THIS ECOSYSTEM'S LANGUAGE, or []."""
    eco = (ecosystem or "").lower()
    if eco not in _IMPORT_GRAMMAR:
        return []
    return _patterns(eco, mods, dynamic=False, grammar=grammar)


def _dynamic_patterns(mods: List[str], ecosystem: Optional[str], grammar: str = "full"
                      ) -> List["re.Pattern[str]"]:
    """Python's dynamic-import patterns (`__import__`, `import_module`) for `mods`, or [] elsewhere."""
    if (ecosystem or "").lower() != "pypi":
        return []
    return _patterns("pypi", mods, dynamic=True, grammar=grammar)
