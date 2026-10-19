#!/usr/bin/env python3
"""Discover how a checkout installs and tests itself. DISCOVERY ONLY: it returns commands, it runs nothing.

    a checkout  →  this script  →  per ecosystem: the install command and the test command, or why there is none

FIX_PR_DESIGN.md § "What runs before the PR opens" (gates 4 and 5 run the customer's OWN commands, discovered from
the repo rather than assumed) and FIX_PR_BUILD_PLAN.md § "Phase 4" (gates 4 and 5 reuse the triage skill's ladder
rather than a second implementation). The ladder was prose in the triage skill, which a model
executes; this is the same ladder as code, so the apply job and the skill read one answer.

THE LADDER, v1 (uv and npm, as phase 2):

  pypi   install  uv.lock                  → `uv sync --frozen`
                  poetry.lock / no lock    → unsupported (v1 runs uv only; without a lock an install re-resolves)
         test     pytest configured        → `uv run --frozen pytest` (uv.lock) or `pytest`
                  (pytest.ini, pyproject `[tool.pytest.ini_options]`, setup.cfg `[tool:pytest]`, tox.ini `[pytest]`,
                  a root conftest.py)
                  else a tox.ini with `[tox]` or `[testenv]` → `tox`
  npm    install  package-lock.json / npm-shrinkwrap.json → `npm ci`
                  yarn.lock / pnpm-lock.yaml / no lock    → unsupported
         test     `scripts.test`, unless it is npm init's placeholder → `npm test`
  make   test     a `test:` target in the root Makefile → `make test` (the old ladder's middle rung)

⭐ `not_detected` IS AN ANSWER, NOT AN ERROR. "No test suite found" is information a reviewer needs (FD § "What runs
before the PR opens"), so every step carries a status and a `why`: `detected` (with `cmd`), `not_detected` (nothing
found) or `unsupported` (found, but v1 does not run it). ⛔ A missing step is never reported as a passed one.

⚠️ WHAT RUNS, WHERE, AND WITH WHICH FLAGS IS NOT DECIDED HERE. The commands are the customer's own; whoever runs them
(gates 4 and 5) applies the bounds: their own compute only (Bhakta 2026-10-19), a time cap, a scrubbed environment.

⚠️ `--json` EMITS ONLY JSON on stdout.

Usage:
    python3 test_ladder.py --repo PATH [--json]
"""

from __future__ import annotations

import argparse
import configparser
import glob
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
# ⭐ VENDORED PURE-PYTHON WHEELS are imported from the zip (`vendor/VENDORED.json`), as remediation_apply.py.
for _whl in sorted(glob.glob(os.path.join(_HERE, "vendor", "*.whl"))):
    sys.path.insert(0, _whl)

LADDER_VERSION = "1"
DETECTED, NOT_DETECTED, UNSUPPORTED = "detected", "not_detected", "unsupported"

#: What `npm init` writes into `scripts.test`. Running it fails by design, so it is not a suite.
_NPM_PLACEHOLDER = re.compile(r'echo\s+\\?"Error: no test specified\\?"\s*&&\s*exit\s+1')
_MAKE_TEST = re.compile(r"^test\s*:(?!=)", re.M)


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _step(status: str, why: str, cmd: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"status": status, **({"cmd": cmd} if cmd else {}), "why": why}


def _exists(root: str, name: str) -> bool:
    return os.path.isfile(os.path.join(root, name))


def _read(root: str, name: str) -> Optional[str]:
    try:
        with open(os.path.join(root, name), encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def _toml(text: str) -> Optional[Dict[str, Any]]:
    try:
        import tomllib
        loads = tomllib.loads
    except ImportError:                                  # Python < 3.11: the vendored tomlkit
        import tomlkit

        def loads(t: str) -> Dict[str, Any]:
            return tomlkit.parse(t).unwrap()
    try:
        return loads(text)
    except ValueError:
        return None


def _ini_sections(root: str, name: str) -> List[str]:
    text = _read(root, name)
    if text is None:
        return []
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read_string(text)
    except configparser.Error:
        return []
    return cp.sections()


# ── pypi ─────────────────────────────────────────────────────────────────────────────

def pytest_config(root: str) -> Optional[str]:
    """Where this checkout configures pytest, or None."""
    if _exists(root, "pytest.ini"):
        return "pytest.ini"
    py = _read(root, "pyproject.toml")
    if py is not None:
        data = _toml(py) or {}
        if "ini_options" in ((data.get("tool") or {}).get("pytest") or {}):
            return "pyproject.toml [tool.pytest.ini_options]"
    if "tool:pytest" in _ini_sections(root, "setup.cfg"):
        return "setup.cfg [tool:pytest]"
    if "pytest" in _ini_sections(root, "tox.ini"):
        return "tox.ini [pytest]"
    if _exists(root, "conftest.py"):
        return "conftest.py"
    return None


def python_ladder(root: str) -> Optional[Dict[str, Any]]:
    if not any(_exists(root, f) for f in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")):
        return None
    uv = _exists(root, "uv.lock")
    if uv:
        install = _step(DETECTED, "uv.lock at the root", ["uv", "sync", "--frozen"])
    elif _exists(root, "poetry.lock"):
        install = _step(UNSUPPORTED, "poetry.lock at the root: v1 installs uv projects only")
    else:
        install = _step(UNSUPPORTED, "no uv.lock at the root: an install without a lock re-resolves, so it would "
                                     "not test the locked versions")
    where = pytest_config(root)
    if where:
        test = _step(DETECTED, f"pytest configured in {where}",
                     ["uv", "run", "--frozen", "pytest"] if uv else ["pytest"])
    elif {"tox", "testenv"} & set(_ini_sections(root, "tox.ini")):
        test = _step(DETECTED, "tox.ini declares [tox] / [testenv]", ["tox"])
    else:
        hint = " (a tests/ directory exists, but nothing configures pytest)" if os.path.isdir(
            os.path.join(root, "tests")) else ""
        test = _step(NOT_DETECTED, "no pytest configuration (pytest.ini, pyproject [tool.pytest.ini_options], "
                                   "setup.cfg [tool:pytest], tox.ini [pytest], conftest.py) and no tox.ini" + hint)
    return {"ecosystem": "pypi", "manager": "uv" if uv else None, "install": install, "test": test}


# ── npm ──────────────────────────────────────────────────────────────────────────────

def npm_ladder(root: str) -> Optional[Dict[str, Any]]:
    text = _read(root, "package.json")
    if text is None:
        return None
    try:
        pj = json.loads(text)
    except ValueError:
        pj = None
    lock = next((f for f in ("package-lock.json", "npm-shrinkwrap.json") if _exists(root, f)), None)
    if lock:
        install = _step(DETECTED, f"{lock} at the root", ["npm", "ci"])
    else:
        other = next((f for f in ("yarn.lock", "pnpm-lock.yaml") if _exists(root, f)), None)
        install = _step(UNSUPPORTED, f"{other} at the root: v1 installs npm projects only" if other else
                        "no package-lock.json at the root: an install without a lock re-resolves")
    if not isinstance(pj, dict):
        test = _step(NOT_DETECTED, "package.json is not a JSON object")
    else:
        script = ((pj.get("scripts") or {}) if isinstance(pj.get("scripts"), dict) else {}).get("test")
        if not script or not str(script).strip():
            test = _step(NOT_DETECTED, "package.json has no scripts.test")
        elif _NPM_PLACEHOLDER.search(str(script)):
            test = _step(NOT_DETECTED, "scripts.test is npm init's placeholder (it exits 1 by design)")
        else:
            test = _step(DETECTED, f"package.json scripts.test: {script}", ["npm", "test"])
    return {"ecosystem": "npm", "manager": "npm" if lock else None, "install": install, "test": test}


# ── make ─────────────────────────────────────────────────────────────────────────────

def make_ladder(root: str) -> Optional[Dict[str, Any]]:
    text = _read(root, "Makefile")
    if text is None or not _MAKE_TEST.search(text):
        return None
    return {"ecosystem": "make", "manager": "make",
            "install": _step(NOT_DETECTED, "make has no install step of its own"),
            "test": _step(DETECTED, "a test: target in the root Makefile", ["make", "test"])}


# ── the run ──────────────────────────────────────────────────────────────────────────

def discover(root: str) -> Dict[str, Any]:
    """Every ecosystem the root of `root` declares, with its install and test step. Only the root is read: a
    nested project is its own checkout to the gates."""
    root = os.path.abspath(root)
    found = [x for x in (python_ladder(root), npm_ladder(root), make_ladder(root)) if x]
    tests = [x for x in found if x["test"]["status"] == DETECTED]
    return {"ladder": LADDER_VERSION, "root": root, "ecosystems": found,
            "tests": DETECTED if tests else NOT_DETECTED}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", help="the checkout to read")
    ap.add_argument("--json", dest="as_json", action="store_true", help="only JSON on stdout")
    a = ap.parse_args()
    if not os.path.isdir(a.repo):
        log(f"ERROR: not a directory: {a.repo}")
        return 2
    out = discover(a.repo)
    if a.as_json:
        print(json.dumps(out, indent=2))
        return 0
    if not out["ecosystems"]:
        print("no ecosystem detected at the root: no install step, no test suite")
    for x in out["ecosystems"]:
        for step in ("install", "test"):
            s = x[step]
            cmd = " ".join(s["cmd"]) if s.get("cmd") else "—"
            print(f"[{x['ecosystem']}] {step:7} {s['status']:12} {cmd}    ({s['why']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
