"""The tree hash a vendored copy is pinned by (REACHABILITY_EXTRACTOR.md § 3.3.1, authority chain).

`VENDORED.json` = `{version, sha256}` where `sha256` is the SHA-256 of the sorted lines `"<path>\\t<sha256 of the
file>\\n"` over every file of the package directory (paths relative to it, `/`-separated), leaving out
`VENDORED.json` itself and `__pycache__/`. A consumer's unit test calls `check(<its copy>)` (catches a hand edit) and,
when the source checkout is beside it, compares `tree_sha256` of both (catches a stale copy).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple

MANIFEST = "VENDORED.json"


def tree_files(package_dir: str | Path) -> List[Tuple[str, str]]:
    """Sorted (relative path, sha256) for every file of the package that the pin covers."""
    base = Path(package_dir)
    out = []
    for p in sorted(base.rglob("*")):
        rel = p.relative_to(base).as_posix()
        if not p.is_file() or rel == MANIFEST or "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        out.append((rel, hashlib.sha256(p.read_bytes()).hexdigest()))
    return out


def tree_sha256(package_dir: str | Path) -> str:
    lines = "".join(f"{rel}\t{sha}\n" for rel, sha in tree_files(package_dir))
    return hashlib.sha256(lines.encode()).hexdigest()


def manifest(package_dir: str | Path, version: str) -> Dict[str, str]:
    return {"version": version, "sha256": tree_sha256(package_dir)}


def check(package_dir: str | Path) -> Dict[str, str]:
    """Raise `ValueError` when the copy no longer matches its `VENDORED.json`; return the manifest otherwise."""
    base = Path(package_dir)
    pinned = json.loads((base / MANIFEST).read_text(encoding="utf-8"))
    actual = tree_sha256(base)
    if pinned.get("sha256") != actual:
        raise ValueError(f"{base} was edited after vendoring: VENDORED.json pins {pinned.get('sha256')}, "
                         f"the tree hashes to {actual}. Edit the source package, then re-run "
                         "scripts/vendor_reachability.sh")
    return pinned
