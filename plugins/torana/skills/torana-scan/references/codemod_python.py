#!/usr/bin/env python3
"""The Python codemods: 4a (a same-parent rename) and 4b (a positional-binding shift).

FIX_PR_PHASE5_CODEMOD_SPEC § 3.5.2 / § 3.5.3.

⛔ RUNS ONLY FROM THE SCAN PACK'S VENV. libcst is installed there, hash-pinned (§ 3.5.6); it is NOT a
dependency of the host venv and must never become one. A caller that cannot import it reports
`libcst_unavailable` and declines — it never falls back to a text edit.

⚠️ WHY libcst AND NOT `ast`. `ast` discards formatting, so re-emitting a file reproduces the tool's
layout rather than the author's and every line reads as changed. libcst is a CONCRETE syntax tree:
parse → change one node → emit, and every byte that was not the target is unchanged. That is what
makes a machine edit reviewable, and L1's minimality check (§ 3.4.3) is only meaningful because of it.

⛔ REFUSE RATHER THAN APPROXIMATE, everywhere in this file. A refusal is listed in the PR and left for
a person; a wrong rewrite is a silent change to someone's source. The refusals below are not
defensive padding — each one names a shape where the rewrite would be WRONG, not merely unproven.

Run (the skill's hand runs; the applier imports `rewrite_file` instead):
    python3 codemod_python.py --file F --ops ops.json --aliases aliases.json --json
    python3 codemod_python.py --file F --modules m1,m2 --old-leaves a,b --scan-dynamic --json
"""
import argparse
import json
import sys

import libcst as cst
from libcst.helpers import get_full_name_for_node
from libcst.metadata import (
    MetadataWrapper,
    PositionProvider,
    QualifiedNameProvider,
    ScopeProvider,
)


class RenameSymbols(cst.CSTTransformer):
    """4a: rewrite every site of `parent.old` to `parent.new`, or refuse the file.

    ⛔ THE SOLE-BINDING RULE IS THE WHOLE SAFETY ARGUMENT (prototype § 2): rewrite only when the op's
    target is the ONLY qualified name the resolver gives a node. One of several means the name is
    shadowed — an import plus a local `def`, say — and renaming it would change whichever one the
    reader did not mean.
    """

    METADATA_DEPENDENCIES = (QualifiedNameProvider, PositionProvider, ScopeProvider)

    def __init__(self, ops):
        # ops: [{"parent": "oldlib.util", "old": "fetch_all", "new": "fetch_many",
        #        "targets": {"oldlib.util.fetch_all", ...}}]
        super().__init__()
        self.ops, self.rewritten, self.refused = ops, [], []
        self.by_old = {o["old"]: o for o in ops}
        self.modules = {o["parent"] for o in ops}

    def _line(self, node):
        return self.get_metadata(PositionProvider, node).start.line

    def _target_op(self, node, old):
        """The op whose target is the ONLY qualified name of `node`, else None."""
        op = self.by_old.get(old)
        if op is None:
            return None
        names = {q.name for q in self.get_metadata(QualifiedNameProvider, node, set())}
        if not names & op["targets"]:
            return None
        if len(names) > 1:                         # ⛔ an import shadowed by a local def
            self.refused.append({"line": self._line(node), "why": f"ambiguous binding: {sorted(names)}"})
            return None
        return op

    def visit_Module(self, node):
        """(2) collision: refuse the whole file BEFORE touching it.

        MEASURED 2026-10-29: `GlobalScope.get_qualified_names_for(name)` answers `{jwt.utils.fetch_many}`
        when the name is bound by an import of the new symbol itself (an `ImportAssignment`; NOT a
        collision) and `{fetch_many}` when a module-level assignment binds it (a collision).
        ⚠️ `scope.assignments` alone cannot tell the two apart, which refused the fully-renamed golden
        as a collision on the first run — so subtracting the canonical name is load-bearing, not tidying.
        """
        scope = self.get_metadata(ScopeProvider, node)
        for op in self.ops:
            canon = f"{op['parent']}.{op['new']}"
            others = {q.name for q in scope.get_qualified_names_for(op["new"])} - {canon}
            if others:
                self.refused.append({
                    "line": 1,
                    "why": f"name_collision: `{op['new']}` is already bound in this module ({sorted(others)})",
                })
        return not self.refused

    def leave_ImportFrom(self, original, updated):
        mod = original.module and get_full_name_for_node(original.module)
        if mod not in self.modules:
            return updated
        if isinstance(updated.names, cst.ImportStar):
            self.refused.append({"line": self._line(original), "why": "star import"})
            return updated
        names = []
        for alias in updated.names:
            op = self.by_old.get(alias.name.value) if isinstance(alias.name, cst.Name) else None
            if op and op["parent"] == mod:
                # `as x` stays: x's uses need no rename, because x is the binding the reader sees.
                alias = alias.with_changes(name=cst.Name(op["new"]))
                self.rewritten.append({"line": self._line(original), "kind": "import"})
            names.append(alias)
        return updated.with_changes(names=names)

    def leave_Name(self, original, updated):
        op = self._target_op(original, original.value)
        if op:
            self.rewritten.append({"line": self._line(original), "kind": "name"})
            return updated.with_changes(value=op["new"])
        return updated

    def leave_Attribute(self, original, updated):
        op = self._target_op(original, original.attr.value)
        if op:
            self.rewritten.append({"line": self._line(original), "kind": "attribute"})
            return updated.with_changes(attr=cst.Name(op["new"]))
        return updated

    def visit_Call(self, node):
        """⛔ REFUSE, NEVER APPROXIMATE: `getattr(<module>, ...)`.

        The attribute name may be computed, so no parse can know whether this site uses the old
        symbol. Guessing either way is wrong; the site is listed for a person.
        """
        if isinstance(node.func, cst.Name) and node.func.value == "getattr" and node.args:
            names = {q.name for q in self.get_metadata(QualifiedNameProvider, node.args[0].value, set())}
            if names & self.modules:
                self.refused.append({"line": self._line(node), "why": "getattr on the module"})


def _resolve_targets(ops, aliases):
    """Each op's `targets`: the canonical name AND every public alias path of it.

    ⚠️ Code written `litellm.CustomLogger` against a diff naming
    `litellm.integrations.custom_logger.CustomLogger` must still be found, or a real site is missed and
    the plan claims `complete`. The API diff's `aliases` map is `{alias_path: canonical_path}` for
    CLASSES (FIX_KNOWLEDGE_CONVERGENCE § 3.6.4.3), so it is inverted here.
    """
    inv = {}
    for alias, canon in (aliases or {}).items():
        inv.setdefault(canon, set()).add(alias)
    for op in ops:
        canon = f"{op['parent']}.{op['old']}"
        op["targets"] = {canon} | {
            f"{a}.{op['old']}" if "." in canon and a.endswith(op["parent"].rpartition(".")[2]) else a
            for a in inv.get(canon, ())
        }
    return ops


def rewrite_file(path, ops, aliases):
    """`{"code": str|None, "rewritten_lines": [int], "refused": [{line, why}]}`.

    `code` is None when the file is REFUSED — the caller writes nothing in that case. A file with
    refusals but no collision still returns `code`: partial is a real outcome (D3), and the refused
    sites travel in `refused[]` so the PR lists them and the plan state becomes `partial`.
    """
    ops = _resolve_targets(list(ops), aliases)
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        src = raw.decode("utf-8")
    except UnicodeDecodeError:
        # ⛔ Not an error to swallow: a non-UTF-8 source cannot be re-emitted byte-faithfully, so the
        # minimality guarantee would not hold. Refuse and say which file.
        return {"code": None, "rewritten_lines": [], "refused": [{"line": 0, "why": "not_utf8"}]}
    tree = cst.parse_module(src)
    t = RenameSymbols(ops)
    out = MetadataWrapper(tree).visit(t)
    if any(r["why"].startswith("name_collision") for r in t.refused):
        return {"code": None, "rewritten_lines": [], "refused": t.refused}
    return {
        "code": out.code,
        "rewritten_lines": sorted({r["line"] for r in t.rewritten}),
        "refused": t.refused,
    }


# ── 4b: the keyword shift (§ 3.5.3) ────────────────────────────────────────

class KeywordShift(cst.CSTTransformer):
    """4b: convert the positional arguments a shifted declaration index affects into keywords.

    ⭐ WHY THIS IS ADMISSIBLE WITHOUT A MODEL. For a positional-or-keyword parameter, binding by
    position and binding by its own name are the SAME binding in Python. `names[j]` is the OLD
    declaration's name at the shifted index (`decide` read it from `decl_from`), so the values reach
    the same parameters under the old version — the rewrite is a NO-OP where the code runs today —
    while under the new version a keyword has no index, so no shifted slot is reached.

    ⛔ AND WHY IT IS STILL REFUSED IN FOUR SHAPES. Each is a case where the rewrite would be WRONG,
    not merely unproven: a splat hides the argument count; a call already naming the parameter would
    bind it twice; more positionals than names means the call was already wrong or a variadic
    absorbed them; a positional after a keyword is not valid Python and is kept as a guard.

    ⚠️ L2 PROVES IT, with the same instrument that raised the class: after the rewrite, narrowing the
    re-indexed site with the same facts must return `safe`. The proof and the check are one code path.
    """

    METADATA_DEPENDENCIES = (QualifiedNameProvider, PositionProvider)

    def __init__(self, line, leaf, shift, import_names):
        super().__init__()
        self.line, self.leaf = int(line), leaf
        self.names = list(shift.get("names") or [])
        self.renamed = dict(shift.get("renamed") or {})
        # `k` is the first CALL position that binds declaration index `from_index`. ⛔ `self` shifts
        # every index by one, so omitting it would keyword the wrong argument.
        self.k = int(shift["from_index"]) - (1 if shift.get("self_bound") else 0)
        self.import_names = tuple(import_names or ())
        self.status, self.why, self.rewritten_lines = None, None, []

    def _line(self, node):
        return self.get_metadata(PositionProvider, node).start.line

    def _is_site(self, node):
        """The ONE call at the hit's line whose function's last segment is the symbol's leaf."""
        if self._line(node) != self.line:
            return False
        func = node.func
        last = func.value if isinstance(func, cst.Name) else (
            func.attr.value if isinstance(func, cst.Attribute) else None)
        if last != self.leaf:
            return False
        names = {q.name for q in self.get_metadata(QualifiedNameProvider, func, set())}
        if not names or not self.import_names:
            return False
        # ⚠️ EVERY name must be the package's, not just one: a shadowed binding is not this site.
        return all(any(n == p or n.startswith(p + ".") for p in self.import_names) for n in names)

    def leave_Call(self, original, updated):
        if self.status is not None or not self._is_site(original):
            return updated
        args = list(updated.args)
        starred = [a for a in args if a.star in ("*", "**")]
        positional = [a for a in args if a.keyword is None and a.star not in ("*", "**")]
        keywords = {a.keyword.value for a in args if a.keyword is not None}

        # Step 1 — the no-op case. ⚠️ THE ORDER IS THE MEASURED CODE'S (m1): a splat call with few
        # positionals is NOT `no_change`; it falls to step 2 and is refused.
        if len(positional) <= self.k and not starred:
            self.status = "no_change"
            return updated
        # Step 2 — the refusals.
        if starred:
            self.status, self.why = "refused", "starred_call"
            return updated
        if keywords & set(self.names):
            self.status, self.why = "refused", "keyword_already_passed"
            return updated
        if len(positional) - self.k > len(self.names):
            self.status, self.why = "refused", "more_positionals_than_names"
            return updated
        seen_kw = False
        for a in args:
            if a.keyword is not None:
                seen_kw = True
            elif seen_kw:
                self.status, self.why = "refused", "positional_after_keyword"
                return updated
        # Step 3 — keyword the positionals at call positions k, k+1, … IN PLACE. Everything else is
        # the original node: commas, comments and line breaks are untouched, which is what keeps the
        # diff to the one line and lets L1's minimality check mean something.
        out, j, pos_i = [], 0, 0
        for a in args:
            if a.keyword is None and a.star not in ("*", "**"):
                if pos_i >= self.k and j < len(self.names):
                    a = a.with_changes(
                        keyword=cst.Name(self.names[j]),
                        equal=cst.AssignEqual(whitespace_before=cst.SimpleWhitespace(""),
                                              whitespace_after=cst.SimpleWhitespace("")),
                    )
                    j += 1
                pos_i += 1
            elif a.keyword is not None and a.keyword.value in self.renamed:
                # Step 4 — an existing keyword the rename moved.
                a = a.with_changes(keyword=cst.Name(self.renamed[a.keyword.value]))
            out.append(a)
        self.status = "rewritten"
        self.rewritten_lines.append(self._line(original))
        return updated.with_changes(args=out)


def shift_file(path, line, leaf, shift, import_names):
    """`{"code": str|None, "status": ..., "why": ..., "rewritten_lines": [int]}`.

    `status` is `rewritten` | `no_change` | `refused` | `site_not_resolved`. ⛔ `code` is None unless
    the status is `rewritten`: a `no_change` site must not rewrite the file (there is nothing to
    change), and a refusal must not write a partial edit.
    """
    try:
        with open(path, "rb") as fh:
            src = fh.read().decode("utf-8")
    except UnicodeDecodeError:
        return {"code": None, "status": "refused", "why": "not_utf8", "rewritten_lines": []}
    tree = cst.parse_module(src)
    t = KeywordShift(line, leaf, shift, import_names)
    out = MetadataWrapper(tree).visit(t)
    if t.status is None:
        # ⚠️ STATED, never assumed harmless: the hit's line named a call this pass could not resolve
        # to the package, so nothing is edited and a person is told which site.
        return {"code": None, "status": "site_not_resolved", "why": "site_not_resolved",
                "rewritten_lines": []}
    return {"code": out.code if t.status == "rewritten" else None, "status": t.status,
            "why": t.why, "rewritten_lines": t.rewritten_lines}


# ── the dynamic-use pass (B4) ───────────────────────────────────────────────

class _DynamicUses(cst.CSTVisitor):
    """Refusal visitors ONLY — it never rewrites anything.

    ⛔ WHY IT EXISTS. `getattr(m, "old")`, `importlib.import_module("pkg")` and a bare string equal to
    the old leaf are ALL invisible to the call graph (`import m as u` binds the module, not the member),
    so such a file has no graph hit, is never opened, is never refused, and the plan says `complete`
    while a real use of the old name still sits there. MEASURED on the reviewer's `tree2/`.
    """

    METADATA_DEPENDENCIES = (QualifiedNameProvider, PositionProvider)

    def __init__(self, modules, old_leaves, import_names):
        super().__init__()
        self.modules, self.old_leaves = set(modules), set(old_leaves)
        self.import_names = tuple(import_names or ())
        self.refused = []

    def _line(self, node):
        return self.get_metadata(PositionProvider, node).start.line

    def visit_Call(self, node):
        func = node.func
        name = func.value if isinstance(func, cst.Name) else (
            get_full_name_for_node(func) if isinstance(func, cst.Attribute) else None)
        if name == "getattr" and node.args:
            names = {q.name for q in self.get_metadata(QualifiedNameProvider, node.args[0].value, set())}
            if names & self.modules:
                self.refused.append({"line": self._line(node), "why": "getattr on the module"})
            return
        if name in ("importlib.import_module", "__import__") and node.args:
            arg = node.args[0].value
            if isinstance(arg, cst.SimpleString):
                val = arg.raw_value if hasattr(arg, "raw_value") else arg.value.strip("'\"")
                if self.import_names and val.split(".")[0] in {n.split(".")[0] for n in self.import_names}:
                    self.refused.append({
                        "line": self._line(node),
                        "why": f"dynamic import of `{val}`: the member used from it cannot be seen",
                    })

    def visit_SimpleString(self, node):
        # ⚠️ A WEAK SIGNAL, and labelled as one. A string equal to the old leaf may be unrelated; it is
        # reported so a person looks, never acted on.
        val = node.raw_value if hasattr(node, "raw_value") else node.value.strip("'\"")
        if val in self.old_leaves:
            self.refused.append({"line": self._line(node), "why": "string names the old symbol"})


def scan_dynamic_uses(path, modules, old_leaves, import_names=()):
    """`{"refused": [{file, line, why}]}` for ONE importing file with no graph hit. Writes nothing."""
    try:
        with open(path, "rb") as fh:
            src = fh.read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {"refused": [{"file": path, "line": 0, "why": f"unreadable: {type(exc).__name__}"}]}
    try:
        tree = cst.parse_module(src)
    except Exception as exc:                        # noqa: BLE001 — an unparsable file proves nothing
        return {"refused": [{"file": path, "line": 0, "why": f"unparsable: {type(exc).__name__}"}]}
    v = _DynamicUses(modules, old_leaves, import_names)
    MetadataWrapper(tree).visit(v)
    return {"refused": [{**r, "file": path} for r in v.refused]}


def main(argv=None):
    ap = argparse.ArgumentParser(description="The Python 4a/4b codemods (phase 5).")
    ap.add_argument("--file", required=True)
    ap.add_argument("--ops", help="JSON file: [{parent, old, new}]")
    ap.add_argument("--aliases", help="JSON file: {alias_path: canonical_path}")
    ap.add_argument("--scan-dynamic", action="store_true", help="run the dynamic-use pass alone")
    ap.add_argument("--modules", default="", help="--scan-dynamic: comma-separated module paths")
    ap.add_argument("--old-leaves", default="", help="--scan-dynamic: comma-separated old leaf names")
    ap.add_argument("--import-names", default="", help="--scan-dynamic: the package's import names")
    ap.add_argument("--json", action="store_true", help="print JSON (the only supported output)")
    a = ap.parse_args(argv)
    # ⛔ stdout is JSON and nothing else (skills/CLAUDE.md): a caller does json.load on it.
    if a.scan_dynamic:
        out = scan_dynamic_uses(a.file, _split(a.modules), _split(a.old_leaves), _split(a.import_names))
    else:
        if not a.ops:
            print(json.dumps({"error": "--ops is required without --scan-dynamic"}))
            return 2
        ops = json.load(open(a.ops))
        aliases = json.load(open(a.aliases)) if a.aliases else {}
        out = rewrite_file(a.file, ops, aliases)
    print(json.dumps(out))
    return 0


def _split(s):
    return [x for x in (s or "").split(",") if x]


if __name__ == "__main__":
    sys.exit(main())
