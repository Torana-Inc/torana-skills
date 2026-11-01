#!/usr/bin/env python3
"""The codemod block: how each call site gets its status, and what the block as a whole says.

FIX_PR_PHASE5_CODEMOD_SPEC § 3.6.1.

⛔ THE WORDS ARE WRITTEN ONCE, HERE. `codemod.words`, each `gate_b.*.words`, each `sites[].why` and
each `refused[].why` are computed by the applier; DF, the CLI, the FE and the PR body print them
VERBATIM. A reader's own map exists only for the five `state` values and the `decline` codes. Two
places computing the same sentence is how they come to disagree, and the one a person reads is then
a coin toss.

⚠️ WHY A SEPARATE MODULE rather than more lines in `remediation_apply.py` (a deliberate, recorded
deviation from § 3.6.2's implied location): the derivation below is PURE — hits and refusals in, a
block out — and `remediation_apply.py` is already ~2500 lines of orchestration with filesystem and
subprocess side effects. Keeping it separate is what lets every row of the status table be tested
directly, without a repository, a copy or an engine. `remediation_apply.run_group` imports it.

⭐ EVERY SITE IS REPORTED, whatever happened to it. A site the codemod could not touch is `refused`
with a reason, never dropped — the done bar for phase 5 is a rewrite AND a refusal in one run, and a
silently omitted site is how "complete" comes to mean "we stopped looking".
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence

#: The two `none` codes that mean "there is nothing to change at this call", as opposed to "we will
#: not change it". ⛔ They are NOT refusals: `call_safe` is D4 (the narrower proved this call already
#: satisfies the new signature) and `import_unaffected` is M4 (a signature change cannot break an
#: import line). Calling either a refusal would report a healthy site as unmigrated and make every
#: such plan `partial` for no reason.
NOTHING_TO_CHANGE = ("call_safe", "import_unaffected")

#: A site whose status leaves the plan NOT complete. `needs_person` is here because a 4c site nobody
#: drafted IS an unmigrated site — until 5c lands, every 4c site is one (N1).
_INCOMPLETE = ("refused", "needs_person")

#: File-level refusals: the whole file is untouched, so EVERY site in it is refused with that reason.
FILE_REFUSALS = ("name_collision", "not_utf8", "unparsable_output", "not_minimal", "newline_changed")


def derive_site(hit: Dict[str, Any], *, file_refusal: Optional[str] = None,
                line_refusals: Optional[Dict[int, str]] = None,
                rewritten_lines: Sequence[int] = (),
                drafted: bool = False) -> Dict[str, Any]:
    """One `sites[]` entry from one `api_diff.touched` hit (§ 3.6.1's table, in its order).

    The ORDER of the rules is the contract, not an implementation detail: a file refused as a whole
    outranks a per-line refusal, which outranks "it was rewritten", which outranks the fallback. Get
    the order wrong and a site in a refused file can report `rewritten` — a claim that the file on
    disk flatly contradicts.
    """
    cm = hit.get("codemod") or {}
    sub, code = cm.get("sub"), cm.get("why") or ""
    site = {
        "file": hit.get("file"), "line": hit.get("line"), "symbol": hit.get("symbol"),
        "change": hit.get("change"), "sub": sub, "op": cm.get("op"),
        "old": cm.get("old"), "new": cm.get("new"), "parent": cm.get("parent"),
        "kind": hit.get("kind"), "shift": cm.get("shift"), "lines": [],
    }

    def done(status, why):
        site["status"], site["why"] = status, why
        return site

    # 1. nothing to change here / 2. a `none` we will not act on
    if sub == "none":
        if code in NOTHING_TO_CHANGE:
            return done("no_change", code)
        return done("refused", code)
    # 3. a 4c site: a person's, until a draft is accepted
    if sub == "4c":
        return done("drafted" if drafted else "needs_person", code)
    # 4. the file was refused as a whole — every site in it, with the file's reason
    if file_refusal:
        return done("refused", file_refusal)
    # 5. a transformer refusal naming this exact line
    at_line = (line_refusals or {}).get(site["line"])
    if at_line:
        return done("refused", at_line)
    # 6. the line was actually rewritten
    if site["line"] in set(rewritten_lines or ()):
        site["lines"] = [site["line"]]
        return done("rewritten", "")
    # 7. the fallback — reported, never silent. ⚠️ These two are NOT failures: a 4a alias site is
    # already fixed by the import line that moved, and a 4b call below the shifted slot binds the
    # same parameters either way.
    return done("no_change",
                "alias through a rewritten import" if sub == "4a"
                else "call does not reach the shifted slot")


def block_state(sites: Sequence[Dict[str, Any]], refused: Sequence[Dict[str, Any]],
                *, decline: Optional[str] = None, l0_ok: bool = True,
                l2_ok: Optional[bool] = True, dynamic_ok: Optional[bool] = True) -> str:
    """`complete` | `partial` | `refused` — the block's own verdict.

    ⛔ `refused` BEATS EVERYTHING. If L0 or L2 FAILED, or a decline is set, the block is refused
    whatever the individual sites say: a site list that looks fine while the closed loop disagrees is
    exactly the case where the sites are not to be trusted.

    ⚠️ `l2_ok=None` MEANS "THE CLOSED LOOP DID NOT RUN", WHICH IS NOT THE SAME AS FAILING, and
    conflating the two is a mistake this file made on its first run: it reported `refused` ("nothing
    is proposed") while still listing the rewritten files, so the block contradicted itself. They are
    different facts and must not read alike — "the checker disagreed" is a verdict, "the checker was
    absent" is a gap. ⭐ But a gap is still not a pass: without L2 the block can never be `complete`,
    because `complete` claims every site was handled AND checked by the level that decides.
    """
    if decline or not l0_ok or l2_ok is False:
        return "refused"
    if l2_ok is None or any(s.get("status") in _INCOMPLETE for s in sites) or list(refused):
        return "partial"
    # ⚠️ THE SAME RULE FOR THE DYNAMIC-USE PASS (B4), for the same reason. It is the only level that
    # can see a `getattr` or a string naming the old symbol — the call graph is blind to all three — so a
    # block that never ran it cannot claim every use was handled. `None` is "it did not run"; its
    # FINDINGS travel in `refused[]` above and make the state `partial` on their own.
    if dynamic_ok is None:
        return "partial"
    return "complete"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_record(path: str, before: str, after: str, lines: Sequence[int],
                subs: Sequence[str], *, model_authored: bool = False,
                diff: str = "", revision: int = 0) -> Dict[str, Any]:
    """One `files[]` entry.

    ⭐ BOTH HASHES, and they are the lane's whole check for a source file (D9). No per-line rule for
    Python can be written honestly, so the platform instead requires the pushed blob to hash to
    `sha256_after` and its base to `sha256_before` — byte identity with what the applier produced and
    the plan recorded, which is stronger than any line rule and is what the fingerprint already
    approves.
    """
    return {"file": path, "sha256_before": _sha256(before), "sha256_after": _sha256(after),
            "lines": sorted(set(lines)), "subs": sorted(set(subs)),
            "model_authored": bool(model_authored), "diff": diff, "diff_omitted": not diff,
            "critique": None, "revision": int(revision)}


def _count(sites, status):
    return sum(1 for s in sites if s.get("status") == status)


def block_words(sites: Sequence[Dict[str, Any]], refused: Sequence[Dict[str, Any]],
                state: str, decline: Optional[str], gate_b: Dict[str, Any],
                dynamic: Optional[Dict[str, Any]] = None) -> str:
    """The one sentence every surface prints. Plain, counted, and it NAMES what was refused."""
    if decline:
        return {
            "libcst_unavailable": "the Python codemod engine is not installed for this platform, so no "
                                  "source change was attempted",
            "node_unavailable": "node is not available, so the npm codemod was not attempted",
            "node_too_old": "node is too old for the npm codemod, so it was not attempted",
            "too_many_sites": "more than 50 call sites; the codemod does not run on a truncated list",
            "codemod_cross_repo": "the code that must change and the version bump are in different "
                                  "repositories, which this version does not handle",
        }.get(decline, f"the codemod did not run: {decline}")
    total = len(sites)
    rewritten, no_change = _count(sites, "rewritten"), _count(sites, "no_change")
    person = _count(sites, "needs_person")
    ops = sorted({s["op"] for s in sites if s.get("status") == "rewritten" and s.get("op")})
    parts = []
    if rewritten:
        parts.append(f"{rewritten} of {total} site(s) rewritten mechanically"
                     + (f" ({', '.join(ops)})" if ops else ""))
    if no_change:
        parts.append(f"{no_change} needed no change")
    # ⛔ A REFUSAL IS NAMED, with its file and line. "1 refused" with no location is a dead end for
    # the person who has to finish the job.
    for s in sites:
        if s.get("status") == "refused":
            parts.append(f"refused: {s['file']}:{s['line']} {s.get('why') or ''}".rstrip())
    if person:
        parts.append(f"{person} site(s) left for a person to change")
    for r in refused:
        parts.append(f"also refused: {r.get('file')}:{r.get('line')} {r.get('why') or ''}".rstrip())
    checked = [k.split("_", 1)[1] if "_" in k else k
               for k in ("l0_files", "l1_syntax", "l2_closed_loop")
               if (gate_b.get(k) or {}).get("ok") is True]
    if checked:
        parts.append("Checked: " + ", ".join(checked))
    # ⛔ AN ABSENT CHECK IS NAMED, never left to be inferred from a shorter "Checked:" list.
    if (gate_b.get("l2_closed_loop") or {}).get("ok") is None and "l2_closed_loop" in gate_b:
        parts.append("the closed loop did NOT run, so this is not reported as complete")
    if dynamic is not None and dynamic.get("ok") is None:
        parts.append("the dynamic-use pass did NOT run" + (f" ({dynamic['why']})" if dynamic.get("why") else "")
                     + ", so a getattr or a string naming the old symbol would not have been seen")
    if state == "refused":
        parts.append("the block is refused, so nothing is proposed")
    return "; ".join(parts) if parts else "no call sites to change"


def assemble_block(sites: Sequence[Dict[str, Any]], files: Sequence[Dict[str, Any]],
                   refused: Sequence[Dict[str, Any]], gate_b: Dict[str, Any],
                   *, engine: Optional[Dict[str, Any]] = None,
                   decline: Optional[str] = None,
                   dynamic: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The whole § 3.6.1 block, with `state` and `words` derived — never passed in.

    ⭐ `dynamic` is the dynamic-use pass's own report (B4), kept as its own key rather than folded
    into `gate_b`: it is not a gate B level (DF's `validate_codemod` demands exactly four of those for
    a `complete`/`partial` block), and a reader needs to tell "ran, nothing found" from "never ran"
    without parsing a sentence. Its findings are already in `refused[]`.
    """
    state = block_state(sites, refused, decline=decline,
                        l0_ok=(gate_b.get("l0_files") or {}).get("ok", True),
                        l2_ok=(gate_b.get("l2_closed_loop") or {}).get("ok", True),
                        dynamic_ok=(dynamic or {}).get("ok", True))
    return {
        "version": "1", "state": state,
        "engine": engine or {"python": None, "npm": None, "node": None},
        "decline": decline,
        "sites": list(sites),
        # ⚠️ `files: []` when nothing was rewritten is CORRECT, not an omission (D4): an all-safe
        # class-4 row gets a codemod with zero rewrites and the PR carries the bump alone.
        "files": list(files),
        "refused": list(refused),
        "gate_b": gate_b,
        **({"dynamic_uses": dynamic} if dynamic is not None else {}),
        "words": block_words(sites, refused, state, decline, gate_b, dynamic),
    }


# ── the orchestration (§ 3.6.2) ─────────────────────────────────────────────

#: The extensions the npm engine owns (§ 3.5.4). ⛔ Must stay in step with PI's `_SOURCE_EXT` and DF's
#: `SOURCE_EXT`, which already admit all six — the verification lane was built ecosystem-complete.
_JS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

#: Wall-clock cap on ONE node run (§ 3.5.4).
JS_TIMEOUT_S = 60


def engine_for(path: str) -> Optional[str]:
    """`"python"` | `"npm"` | `None` — which engine can rewrite this file, by its extension.

    `None` is a file no engine owns. It is a per-file refusal, never a block-level decline: the
    `decline` codes are a closed list (§ 3.6.1) and inventing one for a `.go` hit would put a word on
    a plan that no reader's map explains.
    """
    ext = _os_path_ext(path)
    if ext in _PY_EXT:
        return "python"
    if ext in _JS_EXT:
        return "npm"
    return None


def _os_path_ext(path: str) -> str:
    import os as _o
    return _o.path.splitext(path)[1].lower()


def npm_engine() -> Dict[str, Any]:
    """The npm engine probe: node AND ts-morph, or a decline code (§ 3.5.4).

    ⚠️ NOT CACHED, deliberately. The absent-node path costs one `shutil.which`, and a cached probe is
    a module global that a test must remember to reset — which is how a suite comes to assert the
    previous test's answer.
    """
    try:
        import codemod_node_probe as _np
    except Exception as exc:                            # noqa: BLE001 — a missing probe is a decline
        return {"usable": False, "decline": "node_unavailable",
                "detail": f"the node probe could not be imported: {exc}"}
    return _np.engine_for_codemod()


def engines() -> Dict[str, Any]:
    """What is actually usable here. ⛔ THE IMPORT IS THE TEST, not the installer's exit code — for
    both engines, and for the same measured reason (§ 3.5.6): `import libcst` caught a wheel that
    installed cleanly and then raised `cannot import name 'native'`, and `require('ts-morph')` is its
    npm counterpart."""
    out = {"python": None, "npm": None, "node": None}
    try:
        import libcst                                   # noqa: F401
        out["python"] = "libcst 1.9.0"
    except Exception:                                   # noqa: BLE001 — any import failure is a decline
        pass
    probe = npm_engine()
    if probe.get("usable"):
        out["node"] = f"node {probe.get('version')}"
        out["npm"] = f"ts-morph {probe.get('ts_morph')}"
    return out


def js_rename(copy_root: str, path: str, ops: Sequence[Dict[str, Any]], *,
              node: str, node_modules: Optional[str] = None,
              timeout: int = JS_TIMEOUT_S, run=None) -> Dict[str, Any]:
    """Run the npm 4a codemod on ONE file. Returns `codemod_python.rewrite_file`'s shape —
    `{"code": str|None, "rewritten_lines": [int], "refused": [{line, why}]}` — so the caller's
    per-file logic stays ONE path for both engines.

    ⛔ `code` is None when the file is REFUSED, and the caller then writes nothing. Exit 3 from
    `rename.js` means it threw; an empty stdout with exit 0 would read as "the file became empty",
    which is why the script writes its report to stderr and its source to stdout.

    ⚠️ A MINIMAL ENV, like `gate_env()`: PATH, HOME and NODE_PATH only. A codemod runs over a
    customer's checkout and has no business inheriting this process's secrets.
    """
    import json as _json
    import os as _o
    import subprocess as _sp
    import tempfile as _tf

    here = _o.path.dirname(_o.path.abspath(__file__))
    script = _o.path.join(here, "codemod_js", "rename.js")
    if not _o.path.exists(script):
        return {"code": None, "rewritten_lines": [],
                "refused": [{"line": 0, "why": "ts_morph_error: codemod_js/rename.js is not installed"}]}
    # `module` is the specifier as the IMPORT writes it, which is the hit's own parent — npm symbols
    # are `package[/subpath]#name`, so `_parent` already returned exactly that (§ 3.5.4).
    js_ops = [{"module": o.get("parent") or "", "old": o["old"], "new": o["new"]} for o in ops]
    env = {"PATH": _o.environ.get("PATH", ""), "HOME": _o.environ.get("HOME", "")}
    if node_modules:
        env["NODE_PATH"] = node_modules
    runner = run or _sp.run
    with _tf.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        _json.dump(js_ops, fh)
        ops_path = fh.name
    try:
        p = runner([node, script, _o.path.join(copy_root, path), "--ops", ops_path],
                   capture_output=True, text=True, timeout=timeout, cwd=copy_root, env=env)
    except _sp.TimeoutExpired:
        return {"code": None, "rewritten_lines": [],
                "refused": [{"line": 0, "why": f"ts_morph_error: ran past {timeout}s and was killed"}]}
    except OSError as exc:
        return {"code": None, "rewritten_lines": [],
                "refused": [{"line": 0, "why": f"ts_morph_error: {exc}"}]}
    finally:
        try:
            _os_unlink(ops_path)
        except OSError:
            pass
    try:
        report = _json.loads((p.stderr or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        report = {"refused": [{"line": 0, "why": "ts_morph_error: no report on stderr"}]}
    if p.returncode != 0:
        return {"code": None, "rewritten_lines": [],
                "refused": report.get("refused") or [
                    {"line": 0, "why": f"ts_morph_error: rename.js exited {p.returncode}"}]}
    return {"code": p.stdout, "rewritten_lines": report.get("rewritten") or [],
            "refused": report.get("refused") or []}


def _os_unlink(path: str) -> None:
    import os as _o
    _o.unlink(path)


def _sites_for(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every `api_diff.touched` hit of every row, as a raw site (status derived later).

    ⚠️ EVERY touched hit is a site, including the ones no codemod will act on — § 3.4.1. A hit left
    off the list is a use of the changed symbol that nobody is told about.
    """
    out = []
    for r in rows:
        for hit in ((r.get("api_diff") or {}).get("touched") or []):
            out.append(hit)
    return out


def truncated(rows: Sequence[Dict[str, Any]]) -> bool:
    """⛔ m3: a TRUNCATED hit list is not a site list. With more than MAX_TOUCHED sites the library
    stopped recording, so "every site was handled" cannot be claimed — and claiming it is exactly the
    silent half-fix this design refuses. Nothing is opened."""
    return any((r.get("api_diff") or {}).get("touched_truncated") for r in rows)


# ── the dynamic-use pass (B4, § 3.5.2) ─────────────────────────────────────────────────

#: The pass is libcst's, so Python only. A `.pyi` holds no runtime call but can still hold a string.
_PY_EXT = (".py", ".pyi")


def _modules_and_leaves(rows: Sequence[Dict[str, Any]]):
    """`(modules, old_leaves)` — what a dynamic use would have to name to matter.

    Every hit contributes, including a `call_safe` one: a string naming a symbol that MOVED is worth a
    person's look whether or not that symbol's own call site needed rewriting.
    """
    mods, leaves = set(), set()
    for h in _sites_for(rows):
        c = h.get("codemod") or {}
        sym = str(h.get("symbol") or "")
        parent = c.get("parent") or sym.rpartition(".")[0]
        old = c.get("old") or sym.rpartition(".")[2]
        if parent:
            mods.add(parent)
        if old:
            leaves.add(old)
    return mods, leaves


def import_names_for(rows: Sequence[Dict[str, Any]]) -> tuple:
    """The package's top-level import name(s) — `pyjwt` -> `jwt`, from the library's measured table.

    ⚠️ pypi only: the pass is libcst's. An npm row contributes nothing and is not an error.
    """
    try:
        import api_diff_intersection as _ci
    except Exception:                                  # noqa: BLE001 — no library is "the pass cannot run"
        return ()
    out = set()
    for r in rows:
        pkg = r.get("package")
        if pkg and (r.get("ecosystem") or "pypi") == "pypi":
            out |= {n for n in (_ci.import_names(pkg, "pypi") or ())}
    return tuple(sorted(out))


def dynamic_pass(copy_root: str, rows: Sequence[Dict[str, Any]], usage: Optional[Any], *,
                 import_names: Sequence[str], scan, read_file,
                 exclude: Sequence[Any] = ()) -> Dict[str, Any]:
    """`{"ok": True|None, "scanned": n, "refused": [{file, line, why}], "why": ""}` — the uses the SITE
    LIST cannot hold, and nothing is ever written.

    ⛔ WHY THIS EXISTS AT ALL (B4). `getattr(m, "old")`, `importlib.import_module("pkg")` and a string
    naming the old symbol are invisible to the call graph, so a file holding one has no hit, is never
    opened, and the plan says `complete` while a real use of the old name sits there. MEASURED twice:
    on the reviewer's `tree2/` (a `getattr`) and on the real class-4 run of 2026-10-31, where
    `mock.patch("litellm.utils.decode")` was what made gate 5 fail — and the only signal a reader got
    was `exited 1`.

    ⭐ THE FILE SET IS WIDER THAN § 3.5.2 SAID, and the measurement is why. The spec bounded it to
    "every file with a `module_import` record of the package"; the file that actually held the measured
    use — `tests/test_tokens.py` — **imports the package nowhere**: it imports `unittest.mock` and the
    tree's own module, and names litellm only inside a string. Under the specified rule the pass would
    never have opened the one file it exists for. So the set is every Python file of the indexed tree
    whose text NAMES an import root of the package (one read each, no parse), and only those are
    parsed. That root is the package's own name, so the pre-filter is tight; the old leaf is NOT part
    of it, because a leaf like `decode` matches half a tree and would parse it all.

    ⚠️ A file with a graph hit is scanned too, and `exclude` drops the `(file, line)` pairs the
    transformer already reported — `RenameSymbols` covers `getattr` but has no string rule, so a
    `mock.patch` beside a rewritten call site would otherwise be invisible for the same reason.

    `ok: None` means the pass DID NOT RUN, which the block states; it is never silently a pass.
    """
    import os as _os

    mods, leaves = _modules_and_leaves(rows)
    roots = {str(n).split(".")[0] for n in import_names if n}
    if not leaves and not mods:
        return {"ok": True, "scanned": 0, "refused": [], "why": ""}
    if not roots:
        return {"ok": None, "scanned": 0, "refused": [],
                "why": "the package's import name could not be resolved"}
    recs, graph = (usage if usage else (None, None))
    paths: List[str] = []
    if isinstance(graph, dict) and not graph.get("truncated") \
            and (graph.get("languages") or {}).get("python") == "parsed":
        paths = [str(p) for p in (graph.get("files") or [])]
    elif recs:
        # A record list without a parsed graph still names the importers — § 3.5.2's own rule, which is
        # narrower than the one above and is used only when the wider input is unavailable.
        paths = [str(r.get("file")) for r in recs if r.get("file")]
    if not paths:
        return {"ok": None, "scanned": 0, "refused": [],
                "why": "the tree has no parsed Python call graph"}
    skip = {(str(f), int(ln)) for f, ln in exclude}
    refused: List[Dict[str, Any]] = []
    scanned = 0
    for rel in sorted(set(paths)):
        if not rel.endswith(_PY_EXT):
            continue
        try:
            text = read_file(rel)
        except (OSError, UnicodeDecodeError):
            continue                                   # ⚠️ an unreadable file proves nothing
        if not text or not any(r in text for r in roots):
            continue
        scanned += 1
        out = scan(_os.path.join(copy_root, rel), mods, leaves, import_names)
        for r in out.get("refused") or []:
            line = r.get("line") or 0
            if (rel, int(line)) in skip:
                continue
            refused.append({"file": rel, "line": line, "why": r.get("why") or ""})
    return {"ok": True, "scanned": scanned, "refused": refused, "why": ""}


def run_codemods(copy_root: str, rows: Sequence[Dict[str, Any]], *,
                 l2: Optional[Any] = None, usage: Optional[Any] = None, write: bool = True,
                 read_file=None, write_file=None) -> Dict[str, Any]:
    """Run the 4a/4b codemods on the APPLIED COPY and gate the result. Returns the § 3.6.1 block.

    `l2` is a callable `l2(sites) -> gate_b.l2_closed_loop`'s dict, injected because it needs the
    whole indexing stack (and the caller already has the plan, package and reader). ⚠️ It takes the
    DERIVED sites, because L2's whole job is to check each site's claimed status against what the
    re-indexed copy says — a zero-argument version could only re-derive them and the two copies would
    drift. `None` means L2 did not run, which is REPORTED and makes the block `partial` — never a pass.

    `usage` is the dynamic-use pass's input (B4, § 3.5.2): `usage_for`'s `(records, call graph)` pair
    for this copy, or a callable returning it (lazy, so an early decline costs no indexing run).
    Injected for the same reason as `l2` — it needs the whole indexing stack. `None` means the pass did
    not run, which is REPORTED and makes the block `partial`, never a pass: it is the ONLY level that
    can see a `getattr` or a string naming the old symbol.

    ⛔ ON AN L2 FAILURE EVERY TOUCHED FILE IS RESTORED and the state is `refused`. A half-applied
    rewrite left on the copy would be committed by the next step; the only safe answer to "the closed
    loop disagrees" is to put the originals back.
    """
    import os as _os

    # ⛔ THE ENGINE CHECK COMES FIRST, BEFORE THE IMPORT THAT NEEDS IT. `codemod_python` does
    # `import libcst` at module scope, so importing it above this check raised ModuleNotFoundError on
    # every platform libcst has no wheel for (§ 3.12.13: Intel macOS, Windows) — a crash instead of the
    # `libcst_unavailable` decline the next four lines exist to return. ⚠️ Measured 2026-10-31 while
    # writing the class-4 reachability test: on this laptop the applier died rather than declining.
    if truncated(rows):
        blk = unavailable("too_many_sites",
                          "more than 50 call sites; the codemod does not run on a truncated list")
        blk["state"] = "refused"
        return blk

    hits = _sites_for(rows)
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for h in hits:
        by_file.setdefault(h.get("file"), []).append(h)

    # ⛔ THE ENGINE CHECK IS PER-ECOSYSTEM, AND IT COMES BEFORE THE IMPORT THAT NEEDS IT.
    # Two measured defects live in these six lines. (1) § 3.12.13: `import codemod_python` above the
    # check raised ModuleNotFoundError on every platform libcst has no wheel for — a crash instead of
    # the `libcst_unavailable` decline. (2) MEASURED 2026-10-31: the check asked only about PYTHON, so
    # an npm class-4 rename — which `decide()` stamps `4a`, with no ecosystem guard — walked past it
    # and handed a `.ts` file to libcst, which raised `ParserSyntaxError` out of the applier. Also a
    # crash, for the sibling reason. The engine a run needs is decided by the FILES it must rewrite.
    needed = {engine_for(p) for p in by_file}
    eng = engines()
    if "python" in needed and eng["python"] is None:
        return unavailable("libcst_unavailable",
                           "the Python codemod engine is not installed for this platform, so no "
                           "source change was attempted")
    npm = npm_engine() if "npm" in needed else {"usable": False}
    if "npm" in needed and not npm.get("usable"):
        # ⛔ NEVER A PYTHON FALLBACK AND NEVER A REGEX (§ 3.5.4). A rename applied by text search is
        # the silent half-fix this design exists to prevent, so a missing npm engine is a decline.
        decline = npm.get("decline") or "node_unavailable"
        return unavailable(decline, {
            "node_unavailable": "node is not available, so the npm codemod was not attempted",
            "node_too_old": "node is too old for the npm codemod, so it was not attempted",
        }.get(decline, f"the npm codemod engine is not usable here: {npm.get('detail') or decline}"))
    cp = None
    if "python" in needed:
        import codemod_python as _cp
        cp = _cp
    import gate_b as gb

    read_file = read_file or (lambda path: open(_os.path.join(copy_root, path), encoding="utf-8").read())
    def _default_write(path, text):
        with open(_os.path.join(copy_root, path), "w", encoding="utf-8") as fh:
            fh.write(text)
    write_file = write_file or _default_write

    sites: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    refused: List[Dict[str, Any]] = []
    originals: Dict[str, str] = {}
    # Every (file, line) a site or a transformer refusal already speaks for, so the dynamic-use pass
    # does not report the same line a second time under a different name.
    reported: set = set()

    for path, fhits in sorted(by_file.items()):
        engine = engine_for(path)
        subs = {(h.get("codemod") or {}).get("sub") for h in fhits}
        ops = [{"parent": c["parent"], "old": c["old"], "new": c["new"]}
               for c in ((h.get("codemod") or {}) for h in fhits)
               if c.get("sub") == "4a" and c.get("op") == "rename" and c.get("parent")]
        # ⭐ SEVERAL OPS PER FILE IN ONE PASS (§ 3.5.2 (3)): two renamed symbols in one file are ONE
        # transformer run with a list of targets, so L1 judges minimality once over one diff instead
        # of twice over two.
        dedup, seen = [], set()
        for o in ops:
            k = (o["parent"], o["old"], o["new"])
            if k not in seen:
                seen.add(k)
                dedup.append(o)
        try:
            before = read_file(path)
        except (OSError, UnicodeDecodeError) as exc:
            refused.append({"file": path, "line": 0, "why": f"unreadable: {type(exc).__name__}"})
            for h in fhits:
                sites.append(derive_site(h, file_refusal="not_utf8"))
            continue
        originals[path] = before
        file_refusal, rewritten_lines, after = None, [], before
        line_refusals: Dict[int, str] = {}

        if engine is None:
            # A hit in a file no engine owns (a `.go`, a `.rb`). Refused here rather than declined for
            # the whole block: `decline` is a closed list and inventing a code puts a word on a plan
            # that no reader's map explains.
            file_refusal = "unsupported_language"
            dedup = []
        if dedup and engine == "npm":
            res = js_rename(copy_root, path, dedup, node=npm["node"],
                            node_modules=npm.get("node_modules"))
        elif dedup:
            res = cp.rewrite_file(_os.path.join(copy_root, path), dedup, {})
        if dedup:
            # ⛔ A REFUSAL AT A LINE THAT IS NO HIT STILL BELONGS ON THE RECORD (§ 3.6.1: "`refused[]`
            # carries every refusal that is NOT a site"). `line_refusals` is keyed by line and only
            # ever read by `derive_site`, so a refusal the transformer raised somewhere the site list
            # does not mention was silently dropped. MEASURED 2026-10-31 on the npm engine: the
            # computed access `o["fetchAll"]` was refused by `rename.js` and vanished, leaving a block
            # that said "2 of 2 site(s) rewritten mechanically" and never mentioned the use it had
            # just declined to touch. The spec's own `rename/` fixture (lines 8 and 19) is the Python
            # half of the same hole.
            hit_lines = {int(h.get("line") or 0) for h in fhits}
            for r in res.get("refused") or []:
                why = str(r.get("why", ""))
                if why.startswith("name_collision"):
                    file_refusal = "name_collision"
                elif int(r.get("line") or 0) in hit_lines:
                    line_refusals[r.get("line")] = r["why"]
                else:
                    refused.append({"file": path, "line": r.get("line") or 0, "why": r["why"]})
                    reported.add((path, int(r.get("line") or 0)))
            if res.get("code") is None:
                # ⚠️ THE REASON MUST NAME THE ENGINE THAT REFUSED. `not_utf8` on a perfectly good
                # TypeScript file sends a reader to check the file's encoding; `ts_morph_error` sends
                # them to the refusal that `refused[]` already carries.
                file_refusal = file_refusal or ("ts_morph_error" if engine == "npm" else "not_utf8")
            else:
                after, rewritten_lines = res["code"], res.get("rewritten_lines") or []

        for h in fhits:
            c = h.get("codemod") or {}
            if c.get("sub") != "4b" or file_refusal:
                continue
            if engine == "npm":
                # ⛔ D7: there are no structured breaks facts for npm, so `decide()` routes an npm
                # signature change to 4c (a draft) and never to 4b. A 4b site on a `.ts` file means
                # something upstream changed its mind; it is refused and named, never attempted with
                # the Python shift transformer.
                line_refusals[h["line"]] = "npm_4b_unsupported"
                continue
            # ⚠️ 4b is per SITE, not per file: each call has its own shift, so each is its own run.
            r = cp.shift_file(_os.path.join(copy_root, path), h["line"], (c.get("old") or
                              str(h.get("symbol", "")).rpartition(".")[2]), c["shift"], [])
            if r["status"] == "rewritten":
                after = r["code"]
                rewritten_lines = sorted(set(rewritten_lines) | set(r["rewritten_lines"]))
                write_file(path, after)
            elif r["status"] in ("refused", "site_not_resolved"):
                line_refusals[h["line"]] = r.get("why") or r["status"]

        if not file_refusal and after != before:
            l1 = gb.l1_syntax(before, after, rewritten_lines, ext=_os_path_ext(path))
            if not l1["ok"]:
                file_refusal = (l1["why"] or "").split(":")[0]
                after = before                         # ⛔ put the original back; nothing half-written
            elif write:
                write_file(path, after)

        for h in fhits:
            sites.append(derive_site(h, file_refusal=file_refusal, line_refusals=line_refusals,
                                     rewritten_lines=rewritten_lines))
            reported.add((path, int(h.get("line") or 0)))
        for ln in line_refusals:
            reported.add((path, int(ln or 0)))
        if not file_refusal and after != before:
            files.append(file_record(path, before, after, rewritten_lines,
                                     [x for x in subs if x]))

    # ⭐ THE DYNAMIC-USE PASS RUNS HERE: after the transformers (so their own refusals are known and
    # not reported twice) and before gate B (so its findings are in `refused[]` when the state is
    # derived). It writes nothing, so it cannot affect L0's "only listed files changed".
    if cp is None:
        # ⛔ NOT APPLICABLE IS STILL NOT A PASS. The pass is libcst's, so an npm group has no
        # equivalent — and npm has the same hole it exists to close: a computed access `o["old"]` or a
        # `require()` in a file with NO graph hit is invisible to the site list, and `rename.js` only
        # refuses those in the files it is asked to open. So an npm block reports the pass as absent
        # and can never be `complete`; every npm class 4 is a draft until § 3.5.2 has an npm half.
        dyn = {"ok": None, "scanned": 0, "refused": [],
               "why": "it is libcst's, and no npm equivalent is built"}
    else:
        dyn = dynamic_pass(copy_root, rows, usage() if callable(usage) else usage,
                           import_names=import_names_for(rows), scan=cp.scan_dynamic_uses,
                           read_file=read_file, exclude=sorted(reported))
    refused.extend(dyn["refused"])

    gate_b: Dict[str, Any] = {"l0_files": gb.l0_files(sites, [f["file"] for f in files])}
    if files:
        gate_b["l1_syntax"] = {"ok": True,
                               "words": "every rewritten file re-parses (libcst, tree-sitter); the "
                                        "diff is exactly the reported lines"}
    if l2 is not None:
        gate_b["l2_closed_loop"] = l2(sites)
        if not gate_b["l2_closed_loop"].get("ok"):
            # ⛔ RESTORE EVERY TOUCHED FILE. The closed loop is the level that decides, so its refusal
            # must leave the tree as it was — otherwise the next step commits a rewrite the checker
            # just rejected.
            for path, text in originals.items():
                write_file(path, text)
            blk = assemble_block(sites, [], refused, gate_b, engine=eng, dynamic=dyn)
            blk["state"] = "refused"
            blk["words"] = ("the API-diff check does not agree the sites are fixed, so every file was "
                            "restored and nothing is proposed: "
                            + (gate_b["l2_closed_loop"].get("words") or ""))
            return blk
    else:
        # ⚠️ `ok: None`, not False: see `block_state` — absent is not failed, and neither is a pass.
        gate_b["l2_closed_loop"] = {"ok": None, "words": "the closed loop did not run"}

    gate_b["l3"] = {"status": "not_run",
                    "words": "build, tests and coverage run at --commit (after approval)"}
    return assemble_block(sites, files, refused, gate_b, engine=eng, dynamic=dyn)


def not_run(decline: Optional[str] = None) -> Dict[str, Any]:
    """The block on a dry run, a `--codemod off` run, or a gate-1 decline that returned early (m2).

    ⚠️ `not_run` and `complete` must never read alike: "nobody looked" is not "looked, nothing to do".
    """
    words = ("the codemod did not run: " + decline) if decline else \
            "the codemod did not run (dry run, or --codemod off)"
    return {"version": "1", "state": "not_run",
            "engine": {"python": None, "npm": None, "node": None},
            "decline": decline, "sites": [], "files": [], "refused": [],
            "gate_b": {}, "words": words}


def unavailable(decline: str, words: str) -> Dict[str, Any]:
    """A missing engine or a cross-repo group: stated, with the reason, and nothing attempted."""
    return {"version": "1", "state": "unavailable",
            "engine": {"python": None, "npm": None, "node": None},
            "decline": decline, "sites": [], "files": [], "refused": [],
            "gate_b": {}, "words": words}
