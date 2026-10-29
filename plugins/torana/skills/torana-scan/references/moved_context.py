#!/usr/bin/env python3
"""Context for every package a fix moves that the developer did not ask to move.

When a dependency fix recompiles a lock, other packages can move too (gate 2's `moved`), some of them
BACKWARDS. A bare "openai 3.16.2 -> 2.54.0" asks a person to decide with nothing to decide on. For each
moved package this prints four things, all computed, none guessed:

  1. How it got here: the commit that set the current version in the lock, and what it was before.
  2. Why it moves:    the requirement of the package being fixed that forces it (PyPI metadata, both versions).
  3. Who it affects:  direct imports and other declarations of it in the checkouts in scope.
  4. Verdict:         one plain sentence built from 1-3 (pinned on purpose / no upper limit, now capped / needed).

Inputs are the planner's plan and the applier's probe (`remediation_apply.py --apply --json`). It reads the
developer's own checkouts at the planned ref (`git log`, `git grep`, `git show`), never their working tree,
and PyPI's JSON API. ⛔ A fact it cannot establish is printed as "not checked: <why>", never as an absence.

Usage:
  python3 moved_context.py --plan plan.json --probe probe.json [--json] [--offline]
Exit: 0 printed (also when nothing moved), 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "lib"))
from torana_reachability import grammar, policy  # noqa: E402

_PYPI = "https://pypi.org/pypi/{name}/{version}/json"
_NPM = "https://registry.npmjs.org/{name}/{version}"
_SKIP_DIRS = (":(exclude)**/node_modules/**", ":(exclude)**/.venv/**", ":(exclude)**/site-packages/**")
_MANIFEST_GLOBS = ("*.toml", "*.txt", "*.in", "*.cfg", "package.json")


def norm(name: str) -> str:
    """PEP 503 name: case and -_. runs do not matter."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def git(path: str, *args: str) -> Tuple[int, str]:
    p = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True)
    return p.returncode, p.stdout


# ------------------------------------------------------------------ 1. how it got here

def _line_range(rel: str, pkg: str) -> Optional[str]:
    """A `git log -L` range covering the package's VERSION line in this lock format. ⚠️ `,+N` is N lines
    counting the matched one, so a name line followed by its version line needs `,+2`."""
    base = os.path.basename(rel)
    esc = re.escape(pkg).replace("/", r"\/")
    if base == "package-lock.json":
        return rf'/"node_modules\/{esc}"/,+3'          # the key, then "version" (pretty-printed or not)
    if base in ("uv.lock", "poetry.lock", "Cargo.lock"):
        return rf'/^name = "{esc}"$/,+2'
    # pip-compile / uv pip compile style: `pkg==1.2.3`, case-insensitive name
    return rf'/^{_ci(pkg)}==/,+1'


def _ci(pkg: str) -> str:
    out = []
    for ch in pkg:
        if ch.isalpha():
            out.append(f"[{ch.lower()}{ch.upper()}]")
        elif ch in "-_.":
            out.append("[-_.]")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def _version_in(text: str, rel: str, pkg: str) -> Optional[str]:
    base = os.path.basename(rel)
    if base == "package-lock.json":
        try:
            d = json.loads(text)
            return ((d.get("packages") or {}).get(f"node_modules/{pkg}") or {}).get("version")
        except ValueError:
            return None
    if base in ("uv.lock", "poetry.lock", "Cargo.lock"):
        m = re.search(rf'^name = "{re.escape(pkg)}"\nversion = "([^"]+)"', text, re.M)
        return m.group(1) if m else None
    m = re.search(rf"^{_ci(pkg)}==([^\s;\\]+)", text, re.M)
    return m.group(1) if m else None


def _via(text: str, pkg: str) -> List[str]:
    """pip-compile's `# via` lines under the package: who pulls it into the lock."""
    m = re.search(rf"^{_ci(pkg)}==[^\n]*\n((?:[ \t]*#[^\n]*\n|[ \t]+--hash[^\n]*\n)*)", text, re.M)
    if not m:
        return []
    names: List[str] = []
    for ln in m.group(1).splitlines():
        ln = ln.strip().lstrip("#").strip()
        if ln.startswith("via "):
            ln = ln[4:]
        # `# from <index-url>` is uv's index annotation, not a dependent
        if ln and not ln.startswith(("--hash", "via", "from ")):
            names.append(ln)
    return names


def history(path: str, ref: str, rel: str, pkg: str) -> Dict[str, Any]:
    rc, now = git(path, "show", f"{ref}:{rel}")
    if rc != 0:
        return {"checked": False, "why": f"{rel} is not at {ref}"}
    rng = _line_range(rel, pkg)
    rc, out = git(path, "log", "-n1", "--format=@@%H|%h|%ad|%an|%s", "--date=short", "-L", f"{rng}:{rel}", ref)
    head = next((ln[2:] for ln in out.splitlines() if ln.startswith("@@")), None)
    if rc != 0 or not head:
        return {"checked": False, "why": f"git log could not follow {pkg}'s line in {rel}"}
    full, short, date, author, subject = head.split("|", 4)
    rc, before = git(path, "show", f"{full}^:{rel}")
    prev = _version_in(before, rel, pkg) if rc == 0 else None
    return {"checked": True, "commit": short, "date": date, "author": author, "subject": subject,
            "before": prev, "file_existed_before": rc == 0, "via": _via(now, pkg)}


# ------------------------------------------------------------------ 2. why it moves

def _get_json(url: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        with urllib.request.urlopen(url, timeout=10, context=_ssl_context()) as r:
            return json.load(r), None
    except (urllib.error.URLError, OSError, ValueError) as e:
        # A Python without a CA bundle (python.org builds on macOS) cannot verify TLS; curl uses the system's.
        p = subprocess.run(["curl", "-fsS", "--max-time", "10", url], capture_output=True, text=True) \
            if _has_curl() else None
        if p is not None and p.returncode == 0:
            try:
                return json.loads(p.stdout), None
            except ValueError:
                pass
        return None, f"{url.split('/')[2]} could not be read ({type(e).__name__})"


def requires(eco: str, name: str, version: str, offline: bool) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """{normalised dependency name: spec} that `name==version` declares, from its registry."""
    if offline:
        return None, "offline"
    if eco == "pypi":
        d, err = _get_json(_PYPI.format(name=name, version=version))
        if d is None:
            return None, err
        out: Dict[str, str] = {}
        for r in (d.get("info") or {}).get("requires_dist") or []:
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*\(?([^;)]*)\)?", r)
            marker = r.split(";", 1)[1] if ";" in r else ""
            if m and "extra ==" not in marker:          # an optional extra does not force anything
                out.setdefault(norm(m.group(1)), m.group(3).strip())
        return out, None
    if eco == "npm":
        d, err = _get_json(_NPM.format(name=urllib.parse.quote(name, safe="@"), version=version))
        if d is None:
            return None, err
        out = {}
        for key in ("dependencies", "peerDependencies", "optionalDependencies"):
            for dep, spec in (d.get(key) or {}).items():
                out.setdefault(norm(dep), str(spec))
        return out, None
    return None, f"requirement metadata is read for PyPI and npm, not {eco or 'this ecosystem'}"


def _ssl_context():
    import ssl
    try:
        import certifi  # noqa: F401  (optional: present in most venvs)
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _has_curl() -> bool:
    from shutil import which
    return which("curl") is not None


def has_ceiling(eco: str, spec: str) -> bool:
    """Does the spec bound the version from above? (PEP 440: <, ~=, ==; npm: <, ~, ^, an exact or x-range.)"""
    s = (spec or "").strip()
    if eco == "npm":
        return bool(s) and s not in ("*", "latest", "x") and not re.fullmatch(r">=?\s*[\w.\-+]+", s)
    return bool(re.search(r"(<|~=|==)", s))


def reasons(eco: str, movers: List[Dict[str, Any]], pkg: str, offline: bool) -> Dict[str, Any]:
    """Which of the packages that moved (the fixed ones AND every other mover: a chain is explained by its link)
    declares a requirement on `pkg`, at its old version and its new one."""
    out: List[Dict[str, Any]] = []
    for p in movers:
        if norm(p["package"]) == norm(pkg):
            continue
        old_r, err1 = requires(eco, p["package"], p["installed"], offline)
        new_r, err2 = requires(eco, p["package"], p["target"], offline)
        if err1 or err2:
            return {"checked": False, "why": err1 or err2}
        old_s, new_s = old_r.get(norm(pkg)), new_r.get(norm(pkg))
        if old_s is None and new_s is None:
            continue
        out.append({"parent": p["package"], "from": p["installed"], "to": p["target"],
                    "old_spec": old_s, "new_spec": new_s})
    return {"checked": True, "by": out}


# ------------------------------------------------------------------ 3. who it affects

def _ere(text: str) -> str:
    """`text` as a literal in a POSIX ERE (`git grep -E`): bracket every metacharacter."""
    return "".join(f"[{c}]" if c in ".^$*+?()[]{}|\\" else c for c in text)


def _hit(repo: str, grep_line: str) -> str:
    """`<ref>:<file>:<line>:<code>` from `git grep -n <ref>` → `repo/file:line `code``, code trimmed."""
    _ref, f, n, code = grep_line.split(":", 3)
    code = code.strip()
    return f"{repo}/{f}:{n} `{code[:60]}{'…' if len(code) > 60 else ''}`"


def usage(scope: List[Dict[str, Any]], pkg: str, eco: str, limit: int = 8) -> Dict[str, Any]:
    """Direct imports of `pkg` and other declarations of it, in every checkout in scope, at the planned ref.
    The import name comes from the library's mapping (pyjwt → jwt, Pillow → PIL, wheel metadata), never from
    the distribution name alone."""
    # ⚠️ POSIX ERE for `git grep -E`: no `\s`, so [[:space:]] (a `\s` pattern silently matches nothing)
    if eco == "npm":
        pat = rf"""(require\(|from[[:space:]]+|import[[:space:]]+|import\()['"]{_ere(pkg)}(['"/])"""
        globs: Tuple[str, ...] = ("*.js", "*.ts", "*.mjs", "*.cjs", "*.tsx", "*.jsx")
        how = f"`require('{pkg}')` / `import … from '{pkg}'`"
    elif eco == "pypi":
        mods = grammar.import_names(pkg, eco) or [pkg]
        alt = "|".join(_ere(m) for m in mods)
        pat = rf"^[[:space:]]*(import|from)[[:space:]]+({alt})([.,]|[[:space:]]|$)"
        globs = ("*.py",)
        how = " / ".join(f"`import {m}` / `from {m} …`" for m in mods)
    else:
        pat, globs, how = "", (), ""
    imports: List[str] = []
    decls: List[str] = []
    for s in scope:
        if pat:
            rc, out = git(s["path"], "grep", "-n", "-E", pat, s["ref"], "--", *globs, *_SKIP_DIRS)
            imports += [_hit(s["repo"], ln) for ln in out.splitlines() if ln.count(":") >= 3]
        dpat = rf"""^[[:space:]]*["']?{_ci(pkg)}["']?[[:space:]]*(\[[^]]*\])?[[:space:]]*([=<>~!:]|["',]|$)"""
        rc, out = git(s["path"], "grep", "-n", "-E", dpat, s["ref"], "--", *_MANIFEST_GLOBS, *_SKIP_DIRS)
        for ln in out.splitlines():
            parts = ln.split(":", 3)
            if len(parts) == 4 and not parts[1].endswith((".lock", "-lock.json")):
                decls.append(f"{s['repo']}/{parts[1]}:{parts[2]} {parts[3].strip()}")
    return {"searched_for": how, "import_search": bool(pat), "imports": imports[:limit],
            "imports_total": len(imports), "declarations": decls[:limit], "declarations_total": len(decls)}


# ------------------------------------------------------------------ 4. verdict

def verdict(pkg: str, mv: Dict[str, Any], hist: Dict[str, Any], why: Dict[str, Any], use: Dict[str, Any],
            eco: str) -> str:
    """One plain sentence a developer can act on. ⛔ No resolver vocabulary ("resolve", "uncapped", "spec"): say
    who asked for which versions and what that does to this package."""
    frm, to = mv["from"], mv["to"]
    for d in use["declarations"]:
        if re.search(rf"==\s*{re.escape(frm)}\b", d):
            return (f"someone pinned {pkg} to {frm} on purpose ({d.split(' ', 1)[0]}), and this fix moves it to {to}: "
                    "ask them why it was pinned before accepting.")
    for r in why.get("by") or []:
        old_s, new_s = r["old_spec"], r["new_spec"]
        if new_s is None:
            continue
        old_ok = policy.admits(eco, old_s or "", frm) if old_s is not None else True
        new_ok = policy.admits(eco, new_s, frm)
        if new_ok is False and old_ok is not False:
            new_p, old_p = f"{r['parent']} {r['to']}", f"{r['parent']} {r['from']}"
            # "took the newest release" explains only a move BACKWARDS: the old version was above the new range
            if mv.get("downgrade") and (old_s is None or not has_ceiling(eco, old_s)):
                limit = f"set no upper limit on {pkg} (`{old_s}`)" if old_s else f"did not limit {pkg}"
                return (f"{old_p} {limit}, so the lock took the newest release, {frm}. {new_p} only allows "
                        f"`{new_s}`, so {pkg} goes back to {to}, a version the new {r['parent']} supports.")
            return f"{new_p} needs {pkg} `{new_s}`, which {frm} does not meet, so {pkg} moves to {to}."
    if why.get("checked") is False:
        return "not decided: what makes it move could not be read (see above)."
    return (f"the fixed package does not ask for {pkg} directly; another package in the lock does, and its new "
            f"version moves {pkg} to {to}.")


# ------------------------------------------------------------------ main

def build(plan: Dict[str, Any], probe: Dict[str, Any], offline: bool) -> List[Dict[str, Any]]:
    scope = plan.get("scope") or []
    by_repo = {s["repo"]: s for s in scope}
    out: List[Dict[str, Any]] = []
    for g in probe.get("groups") or []:
        idx = g.get("group")
        pg = (plan.get("groups") or [{}])[idx] if isinstance(idx, int) and idx < len(plan.get("groups") or []) else {}
        parents = [p for p in (pg.get("packages") or g.get("packages") or [])
                   if isinstance(p, dict) and p.get("installed") and p.get("target")]
        eco = (next((p.get("ecosystem") for p in parents if p.get("ecosystem")), None)
               or (pg.get("resolve") or {}).get("ecosystem") or "pypi").lower()
        asked = {norm(p["package"]) for p in parents}
        moved_all = [(lk, mv) for lk in g.get("gate_2_blast_radius") or [] for mv in lk.get("moved") or []
                     if mv.get("package") and mv.get("from") and mv.get("to")]
        # Every package that moved can be the link that moves another: the fixed ones and the other movers.
        movers = parents + [{"package": mv["package"], "installed": mv["from"], "target": mv["to"]}
                            for _, mv in moved_all if norm(mv["package"]) not in asked]
        for lock, mv in moved_all:
            rel_full = lock.get("lock") or ""
            repo, _, rel = rel_full.partition("/")
            s = by_repo.get(repo)
            pkg = mv["package"]
            if norm(pkg) in asked:
                continue
            hist = history(s["path"], s["ref"], rel, pkg) if s else {"checked": False,
                                                                   "why": f"{repo} is not in the scope"}
            why = reasons(eco, movers, pkg, offline)
            use = usage(scope, pkg, eco)
            out.append({"group": idx, "lock": rel_full, "package": pkg, "from": mv["from"], "to": mv["to"],
                        "downgrade": bool(mv.get("downgrade")), "history": hist, "why": why, "usage": use,
                        "verdict": verdict(pkg, mv, hist, why, use, eco)})
    return out


def render(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "No other package moves: the fix changes only the packages it was asked to."
    lines: List[str] = []
    for it in items:
        arrow = "moves BACKWARDS" if it["downgrade"] else "also moves"
        lines.append(f"{it['package']} {arrow}: {it['from']} → {it['to']}  ({it['lock']})")
        h = it["history"]
        if h.get("checked"):
            before = (f"it was {h['before']} before" if h.get("before")
                      else "it was not in the lock before" if h.get("file_existed_before") else "the lock was created")
            lines.append(f"  How it got here: {h['commit']} on {h['date']} by {h['author']}, \"{h['subject']}\"; "
                         f"{before}.")
            if h.get("via"):
                lines.append(f"  In the lock because: {', '.join(h['via'])} needs it.")
        else:
            lines.append(f"  How it got here: not checked: {h.get('why')}.")
        w = it["why"]
        if w.get("checked"):
            for r in w["by"]:
                lines.append(f"  Why it moves: {r['parent']} {r['from']} asks for "
                             f"`{r['old_spec'] or 'any version'}`; {r['parent']} {r['to']} asks for "
                             f"`{r['new_spec'] or 'any version'}`.")
            if not w["by"]:
                lines.append("  Why it moves: the fixed package does not name it directly.")
        else:
            lines.append(f"  Why it moves: not checked: {w.get('why')}.")
        u = it["usage"]
        more = f" (+{u['imports_total'] - len(u['imports'])} more)" if u["imports_total"] > len(u["imports"]) else ""
        imp = (f"{u['imports_total']} direct import(s): {', '.join(u['imports'])}{more}" if u["imports_total"]
               else f"no direct import in these checkouts (searched for {u['searched_for']})" if u["import_search"]
               else "imports not checked: the import search covers PyPI and npm")
        dec = (f"declared at {'; '.join(u['declarations'])}" if u["declarations_total"]
               else "declared in no manifest here")
        lines.append(f"  Who it affects: {imp}. It is {dec}.")
        lines.append(f"  Verdict: {it['verdict']}")
    lines.append("Only these checkouts were searched: a repository outside them that installs this lock is not seen.")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--plan", required=True)
    ap.add_argument("--probe", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--offline", action="store_true", help="do not read PyPI (the 'why' line says so)")
    a = ap.parse_args(argv)
    try:
        plan = json.load(open(a.plan))
        probe = json.load(open(a.probe))
    except (OSError, ValueError) as e:
        print(f"ERROR: cannot read the plan or probe: {e}", file=sys.stderr)
        return 2
    items = build(plan, probe, a.offline)
    print(json.dumps({"moved": items}, indent=1) if a.json else render(items))
    return 0


if __name__ == "__main__":
    sys.exit(main())
