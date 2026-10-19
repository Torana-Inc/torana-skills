"""Resolution policy: does what we DECLARE already admit version V? (1.9.0, OI-191; REMEDIATION_ECOSYSTEMS.md
§ "Three resolution policies"). This one test separates remediation class 2 (the fix is in range: lock only) from
class 3 (our own declaration blocks it), and is the same computation as Atlas's `lock_drift`.

    admits(ecosystem, spec, version, syntax=None) -> True | False | None

`None` means the policy cannot decide (an unparsable spec or version, a URL / path / tag / workspace spec, or an
ecosystem with no policy yet: Go, whose minimum-version selection makes the range test vacuous, and Maven / Gradle,
whose nearest-wins mediation is a graph question). It never guesses.

- PyPI, `syntax` `pep508` (default): PEP 440 specifiers, with pre-releases ADMITTED (the semantics of
  `packaging.specifiers.SpecifierSet(spec, prereleases=True)`, which Atlas's install-marking uses). The tests check
  this module against `packaging` itself.
- PyPI, `syntax` `poetry`: poetry constraints (`^`, `~`, bare `1.2.3`, `*`, `||`) rewritten to PEP 440.
- npm: node-semver ranges (`^`, `~`, x-ranges, hyphen ranges, `||`), with node-semver's default pre-release rule (a
  pre-release satisfies a range only if some comparator of the same set names a pre-release of the same
  `major.minor.patch`). `npm:<pkg>@<range>` aliases are evaluated on the range.

An empty spec admits everything (nothing is declared against it). Stdlib only: there is no `packaging` and no
`node` on a customer's runner.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

POLICY_ECOSYSTEMS = frozenset({"pypi", "npm"})


def admits(ecosystem: str, spec: Optional[str], version: str, syntax: Optional[str] = None) -> Optional[bool]:
    eco = (ecosystem or "").lower()
    spec = (spec or "").strip()
    try:
        if eco == "pypi":
            if syntax == "poetry":
                pep = poetry_to_pep440(spec)
                return None if pep is None else pep440_admits(pep, version)
            return pep440_admits(spec, version)
        if eco == "npm":
            return npm_admits(spec, version)
    except _Undecidable:
        return None
    return None


class _Undecidable(Exception):
    pass


# =============================================================================================================
# PEP 440
# =============================================================================================================

_PEP440 = re.compile(r"""
    ^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""", re.VERBOSE | re.IGNORECASE)


class Pep440:
    __slots__ = ("epoch", "release", "pre", "post", "dev", "local")

    def __init__(self, text: str):
        m = _PEP440.match(text)
        if not m:
            raise _Undecidable(text)
        self.epoch = int(m.group("epoch") or 0)
        self.release = tuple(int(x) for x in m.group("release").split("."))
        pl = (m.group("pre_l") or "").lower()
        self.pre = None if not pl else ({"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}
                                        .get(pl, pl), int(m.group("pre_n") or 0))
        if m.group("post_n1") is not None:
            self.post: Optional[int] = int(m.group("post_n1"))
        elif m.group("post_l"):
            self.post = int(m.group("post_n2") or 0)
        else:
            self.post = None
        self.dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
        loc = m.group("local")
        self.local = tuple(int(p) if p.isdigit() else p.lower() for p in re.split(r"[-_.]", loc)) if loc else None

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None or self.dev is not None

    def replace(self, **kw: object) -> "Pep440":
        v = object.__new__(Pep440)
        for f in self.__slots__:
            setattr(v, f, kw[f] if f in kw else getattr(self, f))
        return v

    @property
    def public(self) -> "Pep440":
        return self.replace(local=None)

    def __str__(self) -> str:
        s = (f"{self.epoch}!" if self.epoch else "") + ".".join(str(x) for x in self.release)
        if self.pre is not None:
            s += f"{self.pre[0]}{self.pre[1]}"
        if self.post is not None:
            s += f".post{self.post}"
        if self.dev is not None:
            s += f".dev{self.dev}"
        if self.local is not None:
            s += "+" + ".".join(str(x) for x in self.local)
        return s

    def key(self) -> Tuple:
        rel = list(self.release)
        while len(rel) > 1 and rel[-1] == 0:
            rel.pop()
        if self.pre is None and self.post is None and self.dev is not None:
            pre: Tuple = (0,)                       # 1.0.dev0 sorts before 1.0a0
        elif self.pre is None:
            pre = (2,)
        else:
            pre = (1, self.pre[0], self.pre[1])
        post = (0,) if self.post is None else (1, self.post)
        dev = (1,) if self.dev is None else (0, self.dev)
        local = (0,) if self.local is None else (1, tuple((1, p, "") if isinstance(p, int) else (0, 0, p)
                                                          for p in self.local))
        return (self.epoch, tuple(rel), pre, post, dev, local)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Pep440) and self.key() == other.key()

    def __lt__(self, other: "Pep440") -> bool:
        return self.key() < other.key()

    def __le__(self, other: "Pep440") -> bool:
        return self.key() <= other.key()

    def __gt__(self, other: "Pep440") -> bool:
        return self.key() > other.key()

    def __ge__(self, other: "Pep440") -> bool:
        return self.key() >= other.key()


_SPEC = re.compile(r"^\s*(===|~=|==|!=|<=|>=|<|>)\s*(\S+)\s*$")


def _prefix_match(v: Pep440, prefix_text: str) -> bool:
    """`==<prefix>.*`: the release, zero-padded, starts with the prefix's release (same epoch)."""
    p = Pep440(prefix_text)
    if p.pre is not None or p.post is not None or p.dev is not None or p.local is not None:
        raise _Undecidable(prefix_text)             # a wildcard after a pre/post/dev segment: rare, not modelled
    if v.epoch != p.epoch:
        return False
    rel = v.release + (0,) * max(0, len(p.release) - len(v.release))
    return rel[:len(p.release)] == p.release


def _one(op: str, target: str, v: Pep440, raw: str) -> bool:
    if op == "===":
        return raw.strip().lower() == target.lower()
    if op in ("==", "!=") and target.endswith(".*"):
        hit = _prefix_match(v, target[:-2])
        return hit if op == "==" else not hit
    t = Pep440(target)
    if op in ("==", "!="):
        hit = (v == t) if t.local is not None else (v.public == t)
        return hit if op == "==" else not hit
    if t.local is not None:
        raise _Undecidable(target)                  # an ordered comparison may not name a local version
    if op == "~=":
        if len(t.release) < 2:
            raise _Undecidable(target)
        prefix = ".".join(str(x) for x in t.release[:-1])
        if t.epoch:
            prefix = f"{t.epoch}!{prefix}"
        return v.public >= t and _prefix_match(v, prefix)
    if op == "<=":
        return v.public <= t
    if op == ">=":
        return v.public >= t
    if op == "<":                                   # packaging's rules, verbatim (tests/test_policy.py)
        if not v < t:
            return False
        return not (not t.is_prerelease and v.is_prerelease and v >= t.replace(dev=0, local=None))
    if op == ">":
        if not v > t:
            return False
        if t.post is None and v.post is not None and v.replace(post=None, dev=None, local=None) == t:
            return False
        return not (v.local is not None and v.public == t)
    raise _Undecidable(op)


def pep440_admits(spec: str, version: str) -> Optional[bool]:
    """PEP 440 `SpecifierSet(spec, prereleases=True).contains(version)`; None when either cannot be parsed."""
    spec = spec.strip()
    if spec.startswith("(") and spec.endswith(")"):
        spec = spec[1:-1]                           # legacy `name (>=1.0)`
    if spec.startswith("@"):
        return None                                 # a direct reference (`name @ git+…`): no version range
    try:
        v = Pep440(version)
    except _Undecidable:
        v = None
    parts = [p for p in spec.split(",") if p.strip()]
    if not parts:
        return True if v is not None else None
    for part in parts:
        m = _SPEC.match(part)
        if not m:
            return None
        op, target = m.groups()
        if op == "===":
            if (str(v) if v is not None else version.strip()).lower() != target.lower():
                return False
            continue
        if v is None:
            return None
        try:
            if not _one(op, target, v, version):
                return False
        except _Undecidable:
            return None
    return True


# ----- poetry -> PEP 440 ---------------------------------------------------------------------------------------

_POETRY_TOKEN = re.compile(r"^(\^|~=|~|==|!=|>=|<=|>|<|=)?\s*v?(\*|[0-9][0-9A-Za-z.!+*-]*)$")


def _poetry_one(tok: str) -> Optional[List[str]]:
    m = _POETRY_TOKEN.match(tok.strip())
    if not m:
        return None
    op, ver = m.group(1) or "", m.group(2)
    if ver == "*":
        return [] if op in ("", "=", "==", ">=") else None
    if op == "=":
        op = "=="
    if op in ("==", "!=") or op in (">=", "<=", ">", "<", "~="):
        return [f"{op}{ver}"]
    if op == "" and "*" in ver:
        return [f"=={ver}"]
    if op == "":
        return [f"=={ver}"]
    nums = re.match(r"^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?", ver)
    if not nums:
        return None
    parts = [int(x) for x in nums.groups() if x is not None]
    if op == "~":
        upper = [parts[0] + 1] if len(parts) == 1 else [parts[0], parts[1] + 1]
    else:                                           # ^: bump the left-most non-zero of the GIVEN parts
        idx = next((i for i, x in enumerate(parts) if x != 0), len(parts) - 1)
        upper = parts[:idx] + [parts[idx] + 1]
    return [f">={ver}", "<" + ".".join(str(x) for x in upper)]


def poetry_to_pep440(spec: str) -> Optional[str]:
    """A poetry constraint as a PEP 440 specifier set; `||` alternatives are not one set, so they return None
    unless there is only one. An empty or `*` constraint is ''."""
    spec = spec.strip()
    if "||" in spec or re.search(r"(?<![|])\|(?![|])", spec):
        alts = [a for a in re.split(r"\|\|?", spec) if a.strip()]
        if len(alts) != 1:
            return None
        spec = alts[0]
    spec = re.sub(r"(\^|~=|~|==|!=|>=|<=|>|<|=)\s+", r"\1", spec)
    out: List[str] = []
    for tok in re.split(r"[,\s]+", spec):
        if not tok:
            continue
        one = _poetry_one(tok)
        if one is None:
            return None
        out += one
    return ",".join(out)


# =============================================================================================================
# npm (node-semver)
# =============================================================================================================

_SEMVER = re.compile(r"^\s*[v=]?\s*(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                     r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\s*$")
_XR = r"(?:x|X|\*|0|[1-9]\d*)"
_PARTIAL = re.compile(r"^(<=|>=|<|>|=|~>|~|\^)?v?(" + _XR + r")(?:\.(" + _XR + r")(?:\.(" + _XR + r")"
                      r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-.]+)?)?)?$")
_HYPHEN = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")

SemVer = Tuple[int, int, int, Tuple]


def _pre_tuple(pre: Optional[str]) -> Tuple:
    if not pre:
        return ()
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))


def parse_semver(text: str) -> SemVer:
    m = _SEMVER.match(text)
    if not m:
        raise _Undecidable(text)
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), _pre_tuple(m.group(4))


def _cmp(a: SemVer, b: SemVer) -> int:
    if a[:3] != b[:3]:
        return -1 if a[:3] < b[:3] else 1
    pa, pb = a[3], b[3]
    if pa == pb:
        return 0
    if not pa:
        return 1                                    # a release sorts after its pre-releases
    if not pb:
        return -1
    return -1 if pa < pb else 1                     # identifier-wise; a shorter equal prefix sorts first


def _is_x(p: Optional[str]) -> bool:
    return p is None or p in ("x", "X", "*")


_ZERO_PRE: Tuple = ()                               # node-semver adds `-0` to an upper bound only with includePrerelease


def _desugar(tok: str) -> List[Tuple[str, SemVer]]:
    """One range token -> comparators [(op, version)]; [] = any version."""
    m = _PARTIAL.match(tok)
    if not m:
        raise _Undecidable(tok)
    op, M, mi, p, pre = m.group(1) or "", m.group(2), m.group(3), m.group(4), m.group(5)
    xM, xm, xp = _is_x(M), _is_x(mi), _is_x(p)
    Mi = 0 if xM else int(M)
    mii = 0 if xm else int(mi)
    pi = 0 if xp else int(p)
    pt = _pre_tuple(pre)
    if op in ("~", "~>"):
        if xM:
            return []
        if xm:
            return [(">=", (Mi, 0, 0, ())), ("<", (Mi + 1, 0, 0, _ZERO_PRE))]
        return [(">=", (Mi, mii, pi, pt)), ("<", (Mi, mii + 1, 0, _ZERO_PRE))]
    if op == "^":
        if xM:
            return []
        if xm:
            return [(">=", (Mi, 0, 0, ())), ("<", (Mi + 1, 0, 0, _ZERO_PRE))]
        if xp:
            upper = (Mi + 1, 0, 0, _ZERO_PRE) if Mi > 0 else (0, mii + 1, 0, _ZERO_PRE)
            return [(">=", (Mi, mii, 0, ())), ("<", upper)]
        if Mi > 0:
            upper = (Mi + 1, 0, 0, _ZERO_PRE)
        elif mii > 0:
            upper = (0, mii + 1, 0, _ZERO_PRE)
        else:
            upper = (0, 0, pi + 1, _ZERO_PRE)
        return [(">=", (Mi, mii, pi, pt)), ("<", upper)]
    # plain comparator or x-range
    if xM:
        if op in ("<", ">"):
            return [("<", (0, 0, 0, _ZERO_PRE))]    # nothing
        return []
    if xm or xp:
        if op in ("", "="):
            upper = (Mi + 1, 0, 0, _ZERO_PRE) if xm else (Mi, mii + 1, 0, _ZERO_PRE)
            return [(">=", (Mi, mii, 0, ())), ("<", upper)]
        if op == ">":
            return [(">=", (Mi + 1, 0, 0, ()) if xm else (Mi, mii + 1, 0, ()))]
        if op == ">=":
            return [(">=", (Mi, mii, 0, ()))]
        if op == "<":
            return [("<", (Mi, mii, 0, _ZERO_PRE))]
        if op == "<=":
            return [("<", (Mi + 1, 0, 0, _ZERO_PRE) if xm else (Mi, mii + 1, 0, _ZERO_PRE))]
    return [(op or "=", (Mi, mii, pi, pt))]


def _test(op: str, v: SemVer, c: SemVer) -> bool:
    r = _cmp(v, c)
    return {"=": r == 0, "<": r < 0, ">": r > 0, "<=": r <= 0, ">=": r >= 0}[op]


def _set_admits(comps: List[Tuple[str, SemVer]], v: SemVer) -> bool:
    if not all(_test(op, v, c) for op, c in comps):
        return False
    if v[3]:                                        # the pre-release rule
        return any(c[3] and c[:3] == v[:3] for _, c in comps)
    return True


def _comparator_set(text: str) -> List[Tuple[str, SemVer]]:
    text = text.strip()
    h = _HYPHEN.match(text)
    if h:
        lo = _desugar(h.group(1))
        lo = [(">=", c) for _, c in lo[:1]] if lo else []
        hm = _PARTIAL.match(h.group(2))
        if not hm or hm.group(1):
            raise _Undecidable(text)
        if _is_x(hm.group(2)):
            hi: List[Tuple[str, SemVer]] = []
        elif _is_x(hm.group(3)):
            hi = [("<", (int(hm.group(2)) + 1, 0, 0, _ZERO_PRE))]
        elif _is_x(hm.group(4)):
            hi = [("<", (int(hm.group(2)), int(hm.group(3)) + 1, 0, _ZERO_PRE))]
        else:
            hi = [("<=", (int(hm.group(2)), int(hm.group(3)), int(hm.group(4)), _pre_tuple(hm.group(5))))]
        return lo + hi
    text = re.sub(r"(<=|>=|<|>|=|~>|~|\^)\s+", r"\1", text)
    comps: List[Tuple[str, SemVer]] = []
    for tok in text.split():
        comps += _desugar(tok)
    return comps


_NOT_A_RANGE = re.compile(r"^(?:[a-z+]+:|\.{1,2}/|/|~/|git|github:|https?:|file:|link:|workspace:|catalog:)", re.I)


def npm_admits(spec: str, version: str) -> Optional[bool]:
    """node-semver `satisfies(version, spec)` (default options); None for a tag, URL, path or workspace spec."""
    spec = spec.strip()
    alias = re.match(r"^npm:(?:@[^/@]+/)?[^@]+@(.*)$", spec)
    if alias:
        spec = alias.group(1).strip()
    if spec in ("", "*", "x", "X"):
        try:
            v = parse_semver(version)
        except _Undecidable:
            return None
        return not v[3]                             # `*` admits every release, no pre-release
    if _NOT_A_RANGE.match(spec) or re.fullmatch(r"(?![vV]?\d)[A-Za-z][\w.-]*", spec):
        return None                                 # a dist-tag (`latest`, `next`), a URL, a path, a workspace
    try:
        v = parse_semver(version)
        sets = [_comparator_set(s) for s in spec.split("||")]
    except _Undecidable:
        return None
    return any(_set_admits(c, v) for c in sets)
