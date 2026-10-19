"""Which library a module import belongs to (1.7.0, CODE_WALKER.md § 3.3.7). Pure: no I/O, no clock.

    library_kind(module, level, *, local_roots, stdlib, ours, known_dists) -> {kind, name, basis, node}

One computation for every reader that groups imports into libraries (the Atlas code walker today), so a module is
attributed the same way `answer` and the call graph attribute it (`grammar.distribution_of`, `firstparty.normalize`).
It says what the code IMPORTS, never whether a library is used.
"""
from __future__ import annotations

from typing import Any, Dict, FrozenSet, Iterable, Optional, Set, Tuple

from .firstparty import normalize
from .grammar import distribution_of

KINDS = ("first_party_file", "builtin", "ours", "third_party")


def _out(kind: str, name: str, basis: Optional[str], node: Optional[str] = None) -> Dict[str, Any]:
    return {"kind": kind, "name": name, "basis": basis, "node": node}


def library_kind(module: str, level: int, *, local_roots: Set[str], stdlib: FrozenSet[str],
                 ours: Dict[str, Tuple[str, str]], known_dists: Iterable[str]) -> Dict[str, Any]:
    """The library of one `module_import` (`module` without its leading dots, `level` = the number of dots).

    In order, first match wins:
    1. `first_party_file` (not a library): a relative import, `__future__`, or a top segment that is one of this tree's
       own roots (`local_roots`, from `firstparty.local_roots_of_files`). name = the module as written, basis None.
    2. `builtin`: the top segment is in `stdlib` (the caller passes `sys.stdlib_module_names`). name = the top
       segment, basis `"stdlib"`.
    3. `ours`: the top segment is another service's first-party module (`ours`: module -> (node path, distribution),
       from that service's `first_party_pyproject` distribution records). name = the normalised distribution, basis
       `"first_party_pyproject"`, node = that service's node path.
    4. `third_party` attributed by `grammar.distribution_of` over `known_dists` (declared ∪ locked names): its name
       and its stored basis word (`mapping_table` | `wheel_metadata` | `convention`).
    5. `third_party` unattributed: name = the normalised top segment, basis `"convention"` (a guess from the name)."""
    module = (module or "").lstrip(".")
    top = module.split(".")[0]
    if level or not module or top == "__future__" or top in local_roots:
        return _out("first_party_file", module, None)
    if top in stdlib:
        return _out("builtin", top, "stdlib")
    if top in ours:
        node, dist = ours[top]
        return _out("ours", normalize(dist), "first_party_pyproject", node)
    hit = distribution_of(module, known_dists)
    if hit is not None:
        return _out("third_party", hit[0], hit[1])
    return _out("third_party", normalize(top), "convention")


__all__ = ["KINDS", "library_kind"]
