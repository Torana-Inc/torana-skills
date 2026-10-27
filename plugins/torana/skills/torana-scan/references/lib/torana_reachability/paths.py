"""Which files both runners read, and which of them are on the running surface.

`_SKIP_DIRS`, `_NON_RUNTIME` and `_scope_of` are moved from `reachability_pass.py` (`:69-76`, `:501-503` at
4222f48). `walk_files` carries Atlas's rule (the knowledge service's `src/extractors/base.py:155-213`): a tracked
symlink or special file is DATA, never opened or followed, so the CI pass and an Atlas build read the same files.

⚠️ THE ONE DELIBERATE CHANGE AGAINST THE FROZEN PASS (lead-approved 2026-10-18, recorded in the spec's § 4.0):
the pass's `os.walk` opened a symlinked source file; the library skips it. A repository is untrusted, and a link
can point outside the checkout. `tests/test_paths.py` pins it.
"""
from __future__ import annotations

import fnmatch
import os
import re
import stat
from pathlib import Path
from typing import Iterator, List, Optional

from .grammar import SOURCE_EXT

#: Directories that never hold shipping code. Excluded from BOTH analyses.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
              "dist", "build", ".tox", ".pytest_cache", "target", "vendor", ".idea"}

#: ⚠️ A path segment that marks code as NOT on the running surface. This is what separates
#: `build_only` from `not_imported`: a package imported solely by a test or a build script is
#: present in the tree and absent from the product.
#: ⚠️ OI-172 (1.8.0): `scripts?` / `tools?` count only as the TOP segment (`scripts/backfill.py`, `tools/gen.py`).
#: Inside a package they are product code: an agent service's `src/tools/` holds the live ADK tools (245 defs).
_NON_RUNTIME = re.compile(r"(^|/)(tests?|testing|spec|specs|e2e|examples?|samples?|docs?|"
                          r"benchmarks?|fixtures?|migrations?|\.github)(/|$)|^(scripts?|tools?)(/|$)")

#: Secret-bearing file names Atlas never shows a model (the knowledge service's `base.py`
#: `WITHHELD_NAME_RULES`). None of them is a source extension today; kept so a walk never yields one.
_WITHHELD_KEEP_SUFFIXES = (".example", ".sample", ".template")
_WITHHELD_NAME_RULES = (("env_file", (".env", ".env.*")), ("ssh_private_key", ("id_rsa*", "id_ed25519*")),
                        ("key_material", ("*.key", "*.p12", "*.pfx", "*.jks", "*.keystore")),
                        ("private_key_json", ("private_key*.json",)))


def _scope_of(path: str) -> str:
    m = _NON_RUNTIME.search(path)
    return (m.group(2) or m.group(4)) if m else "other"


def is_runtime(path: str) -> bool:
    """True when `path` is on the running surface (no `_NON_RUNTIME` segment)."""
    return not _NON_RUNTIME.search(path)


def unsafe_entry_reason(path: Path, root: Path) -> Optional[str]:
    """Why a tree entry is DATA to record, never to open or follow (None = a plain file or directory).
    A repository is untrusted: a tracked symlink can dangle, loop, or point outside the workspace."""
    try:
        mode = path.lstat().st_mode
    except OSError:
        return "unreadable"
    if stat.S_ISLNK(mode):
        try:
            target = path.resolve(strict=True)
        except (OSError, RuntimeError):
            return "dangling_symlink"              # missing target, or a loop
        return "symlink" if target.is_relative_to(root.resolve()) else "symlink_outside_workspace"
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return "special_file"
    return None


def withheld_name_reason(name: str) -> Optional[str]:
    """Why a file of this NAME is withheld, or None."""
    low = name.lower()
    if low.endswith(_WITHHELD_KEEP_SUFFIXES) or low.endswith(".pub"):
        return None
    for reason, patterns in _WITHHELD_NAME_RULES:
        if any(fnmatch.fnmatchcase(low, pat) for pat in patterns):
            return reason
    return None


#: Directory NAMES that hold installed third-party code whatever they are called around them.
_INSTALLED_DIRS = {"site-packages", "dist-packages", "node_modules"}


def _is_environment(dirpath: Path, name: str) -> bool:
    """True for a directory that holds installed packages, not the repository's own code: a virtualenv (it holds
    `pyvenv.cfg`, whatever its name: `.venv-svc/` was missed by the name list) or a `site-packages`/`node_modules`."""
    if name in _INSTALLED_DIRS:
        return True
    try:
        return (dirpath / name / "pyvenv.cfg").is_file()
    except OSError:
        return False


def git_visible_files(root: str | Path) -> Optional[set]:
    """The files git would ship from `root`: tracked plus untracked-not-ignored, relative to `root`. None when `root`
    is not inside a git work tree or git cannot answer (the caller then walks without it).

    ⛔ A local checkout holds what was never committed: a gitignored virtualenv inside it put 50 site-packages files in
    an API-diff check and pushed the repository's own 4 uses past the cap (2026-10-27). An Atlas snapshot never had them
    (it fetches from GitHub), so this makes the laptop read what the Atlas reads.
    ⚠️ The repository is untrusted: fsmonitor and the untracked cache are switched off, so its config runs nothing."""
    import subprocess
    try:
        out = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", str(root),
             "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return {p for p in out.stdout.decode("utf-8", "surrogateescape").split("\0") if p}


def walk_files(root: str | Path) -> Iterator[str]:
    """Every regular file under `root` except `_SKIP_DIRS` and installed-package directories (a virtualenv, by its
    `pyvenv.cfg`; `site-packages`; `node_modules`), sorted, as `/`-separated relative paths. Inside a git work tree,
    only the files git would ship (`git_visible_files`): a gitignored file is not the repository's code.
    Symlinks and special files are skipped; directory links are never descended."""
    base = Path(root)
    visible = git_visible_files(base)
    for dirpath, dirs, files in os.walk(base, followlinks=False):
        here = Path(dirpath)
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not _is_environment(here, d))
        for name in sorted(files):
            p = here / name
            rel = p.relative_to(base).as_posix()
            if visible is not None and rel not in visible:
                continue
            if unsafe_entry_reason(p, base) is None and not withheld_name_reason(name):
                yield rel


def source_files(root: str | Path) -> List[str]:
    """Every source file that could import something, as repo-relative paths, sorted by path (the `f` order)."""
    return sorted(f for f in walk_files(root) if f.endswith(SOURCE_EXT))
