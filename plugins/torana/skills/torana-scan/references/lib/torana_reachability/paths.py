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

from torana_reachability.grammar import SOURCE_EXT

#: Directories that never hold shipping code. Excluded from BOTH analyses.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
              "dist", "build", ".tox", ".pytest_cache", "target", "vendor", ".idea"}

#: ⚠️ A path segment that marks code as NOT on the running surface. This is what separates
#: `build_only` from `not_imported`: a package imported solely by a test or a build script is
#: present in the tree and absent from the product.
_NON_RUNTIME = re.compile(r"(^|/)(tests?|testing|spec|specs|e2e|examples?|samples?|docs?|"
                          r"scripts?|tools?|benchmarks?|fixtures?|migrations?|\.github)(/|$)")

#: Secret-bearing file names Atlas never shows a model (pantheon-knowledge `base.py`
#: `WITHHELD_NAME_RULES`). None of them is a source extension today; kept so a walk never yields one.
_WITHHELD_KEEP_SUFFIXES = (".example", ".sample", ".template")
_WITHHELD_NAME_RULES = (("env_file", (".env", ".env.*")), ("ssh_private_key", ("id_rsa*", "id_ed25519*")),
                        ("key_material", ("*.key", "*.p12", "*.pfx", "*.jks", "*.keystore")),
                        ("private_key_json", ("private_key*.json",)))


def _scope_of(path: str) -> str:
    m = _NON_RUNTIME.search(path)
    return m.group(2) if m else "other"


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


def walk_files(root: str | Path) -> Iterator[str]:
    """Every regular file under `root` except `_SKIP_DIRS`, sorted, as `/`-separated relative paths.
    Symlinks and special files are skipped; directory links are never descended."""
    base = Path(root)
    for dirpath, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            p = Path(dirpath) / name
            if unsafe_entry_reason(p, base) is None and not withheld_name_reason(name):
                yield p.relative_to(base).as_posix()


def source_files(root: str | Path) -> List[str]:
    """Every source file that could import something, as repo-relative paths, sorted by path (the `f` order)."""
    return sorted(f for f in walk_files(root) if f.endswith(SOURCE_EXT))
