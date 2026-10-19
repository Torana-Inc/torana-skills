#!/usr/bin/env python3
"""Answer Torana's reachability queue for one checkout — deterministically, no model.

    torana alerts reachability-queue  →  this script  →  torana alert <id> reachability

⛔ NO LLM, AND THAT IS THE POINT, not a cost saving. A priority change has to be defensible:
the proof layer's rule is that model text is a label and never evidence, and "the model
thought it wasn't reachable" cannot be a pointer. "`<package>` appears in `uv.lock` and in zero
`.py` files at commit a1b2c3d" can — anyone can re-run it and get the same answer. Determinism
is also what stops an item flapping priority between runs for no reason a reader can see.

TWO QUESTIONS, TWO ANALYSES, and they are not the same cost:

  packages       does THIS REPO import the package at all?    an import scan of the tree
  code_findings  is this function reachable from an entry?     a call graph over the repo

⛔ `--repo-key` IS REQUIRED, AND IT IS THE SCOPE. An answer measured in one checkout is only
about that checkout: the queue returns only findings bound to that repository, and the write
is refused for anything else. ⚠️ An Inbox ENTRY ("Upgrade <package> to <version>") is never one of
them — it groups every place the package appears, across repositories and container images,
so no single checkout can answer it. Entries still move: the ranking derives an entry's
position from its members, so lowering the members lowers the entry.

The import scan is the one that moves priorities — measured across a set of repositories: some
never import the package a finding names. The call graph mostly CONFIRMS, which is
worth recording but rarely changes an order. So the scan always runs; the call graph runs only
when tree-sitter is present and a code finding asks for it.

⛔ EACH LANGUAGE IS READ WITH ITS OWN GRAMMAR, AND A MISS IS NOT ALWAYS AN ABSENCE. The import
scan carries one pattern set per ecosystem (`_IMPORT_GRAMMAR`) and one answer per ecosystem to
"may a miss be reported as `not_imported`?" (`_ABSENCE`). Both exist because over-matching is
harmless here — it yields `reachable`, which records and moves nothing — while under-matching
yields `not_imported` at priority 85, below every severity the ranking can assign. The call
graph is PYTHON ONLY and says so: a finding in another language is `inconclusive` with that as
the stated reason, never an absence.

⭐ THE ENGINE IS THE VENDORED `torana_reachability` LIBRARY (`lib/`), the same code Atlas pins: one import grammar,
one call graph, one absence rule, so a CI fact and an Atlas fact cannot disagree about the same tree. This file is
the runner: read the queue, index the tree once, ask the library per question, write each answer back. Its grammar
also finds the forms the pre-library scan missed (`import os, yaml`, a multi-line TypeScript `import {…} from`,
`#[macro_use] extern crate`, …), and only ever towards "imported".

⚠️ CALLS THE PLATFORM ONLY THROUGH THE `torana` CLI: no platform import, no source tree of the
platform, no database. It must work on a CI runner that has a checkout, the CLI and a token.

⚠️ `--json` EMITS ONLY JSON on stdout; every diagnostic goes to stderr.

Usage:
    python3 reachability_pass.py --repo . --repo-key repo:host/org/repo [--commit SHA]
                                [--apply] [--json]

Without `--apply` nothing is written: it prints what it would record. ⛔ That default is
deliberate — the first thing anyone does with a new analysis is run it to see what it says,
and a pass that silently re-prioritises an estate on its first run is unforgivable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# ⭐ THE ENGINE IS A VENDORED LIBRARY, not code in this file: `lib/torana_reachability/` is a pinned copy of the
# standalone torana-reachability package (its `VENDORED.json` holds the tree hash; `tests/test_vendored_library.py`
# recomputes it). ⛔ Never edit the copy: edit the package and re-vendor it. A self-relative path, which a skill may
# use (it reaches into its own folder, never into a platform checkout).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from torana_reachability import (ANALYZER_CALLGRAPH, ANALYZER_IMPORTS,  # noqa: E402
                                 ENGINE_VERSION)
from torana_reachability import answer as _answer  # noqa: E402
from torana_reachability.answer import components_of  # noqa: E402
from torana_reachability.callgraph import (QSEP, _path_to, _resolve_callee,  # noqa: E402,F401
                                           build_callgraph, build_callgraph_index, graph_from_index,
                                           parser_remedy, python_parser)
from torana_reachability.grammar import (_ABSENCE, _ECOSYSTEM_EXT, _IMPORT_GRAMMAR,  # noqa: E402,F401
                                         _IMPORT_NAME, _SOURCE_ECOSYSTEMS, _dotted_prefixes,
                                         _go_patterns, import_names)
from torana_reachability.index import PARITY_PROVEN, build_imports  # noqa: E402
from torana_reachability.paths import _NON_RUNTIME, _SKIP_DIRS, source_files  # noqa: E402,F401

#: What a pass written before `imported_transitively` existed records instead, when the platform refuses the new
#: verdict (spec § 3.12.6, review N4): a fact that moves nothing.
_PREDATES = "the platform predates the imported_transitively verdict"


# ── one question, answered by the library ────────────────────────────────────────────

def _package_not_known(name: str, eco: str, commit: str, repo_key: str) -> Dict[str, Any]:
    """The library answers an ecosystem with no grammar `not_known: language_unsupported`; the write path needs a
    verdict, so it is today's `inconclusive` with today's reason."""
    return {"verdict": "inconclusive",
            "evidence": {"commit": commit, "analyzer": ANALYZER_IMPORTS, "repository": repo_key,
                         "package_name": name,
                         "reason": f"ecosystem '{eco}' is not a source-import ecosystem; its use is a "
                                   "question about the built image, not about source imports"}}


def answer_package(index: Dict[str, Any], pkg: Dict[str, Any], commit: str, repo_key: str) -> Dict[str, Any]:
    """`{verdict, evidence}` for one queued package, over the repository's index (built once per run). The subject
    is the repository: its one component is this checkout, and its graph is this checkout's lock files."""
    name, eco = pkg.get("package_name"), (pkg.get("ecosystem") or "").lower()
    a = _answer.answer({"kind": "package", "ecosystem": eco, "package": name}, components_of(index),
                       repository=repo_key, commit=commit,
                       binding={"state": "measured", "alert_commit": commit})
    if a["state"] == "not_known":
        return _package_not_known(name, eco, commit, repo_key)
    return {"verdict": a["verdict"], "evidence": a["evidence"]}


def answer_code(index: Dict[str, Any], cg: Optional[Dict[str, Any]], cf: Dict[str, Any], commit: str,
                repo_key: str) -> Dict[str, Any]:
    """`{verdict, evidence}` for one queued code finding, over the stored call graph (every entry kind: route,
    CLI, task, `__main__`). A file the graph cannot cover, or a run with no parser, is `inconclusive` with the
    reason today's pass gives."""
    path = cf.get("file") or ""
    base = {"commit": commit, "analyzer": ANALYZER_CALLGRAPH, "file": path, "repository": repo_key}
    if cg is None or (cg.get("languages") or {}).get("python") == "parser_missing":
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": "no call graph available: no tree-sitter parser for Python on "
                                               f"this runner ({parser_remedy()})"}}
    a = _answer.answer({"kind": "code", "file": path, "function": cf.get("function")},
                       components_of(index, cg), repository=repo_key, commit=commit,
                       binding={"state": "measured", "alert_commit": commit})
    if a["state"] == "not_known":
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": f"this pass builds a call graph for Python only; {path} is not "
                                               "covered"}}
    return {"verdict": a["verdict"], "evidence": a["evidence"]}


def ci_evidence(ev: Dict[str, Any], kind: str, commit: str, repo_key: str) -> Dict[str, Any]:
    """Every field the platform's shape gate reads (spec § 3.12.6, review N3), on every verdict this pass writes.

    ⚠️ `alert_commit` is this pass's own `--commit`: the platform stores it as a claim and binds the fact to the
    alert's scanned commit itself, so a CI runner cannot make an absence `known` by asserting a commit."""
    out = dict(ev)
    out.setdefault("engine", ENGINE_VERSION)
    out.setdefault("subject", "repository")
    out.setdefault("state", "measured")
    out.setdefault("alert_commit", commit)
    out.setdefault("components", [{"repository": repo_key, "commit": commit}])
    out.setdefault("components_complete", True)
    out.setdefault("certainty", "believed")
    out.setdefault("certainty_unmet", [])
    out.setdefault("parity_proven", sorted(PARITY_PROVEN))
    return out


# ── the pre-library entry points, kept for callers and the skill's own tests ─────────

def package_verdict(repo: str, files: List[str], pkg: Dict[str, Any],
                    commit: str, repo_key: str) -> Dict[str, Any]:
    """One verdict for one package alert (the pre-library signature): indexes `files` of `repo`, then asks the
    library. The pass itself indexes once per run (`main`)."""
    return answer_package(build_imports(repo, commit=commit, repository=repo_key, files=files), pkg, commit,
                          repo_key)


def code_verdict(graph: Optional[Dict[str, Any]], cf: Dict[str, Any],
                 commit: str, repo_key: str) -> Dict[str, Any]:
    """One verdict for one code finding over an in-memory graph (`build_callgraph` / `graph_from_index`)."""
    return _answer.code_verdict(graph, cf, commit, repo_key)


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def torana_cli() -> str:
    """Where the `torana` CLI actually is.

    ⛔ NEVER A BARE `torana`, and this is the skills' own rule, not a preference:
    "Always invoke via `"$TORANA"` — the variable is stable across shell invocations;
    bare `torana` relies on PATH which may not be set." A customer's install puts the
    CLI in a dedicated venv (`$TORANA_VENV/bin/torana`) and does NOT add it to PATH, so
    a bare call dies with "No such file or directory" on the very machine this pass is
    written for — and the first thing to fail is the queue read, which reads like the
    platform has no such command rather than like a CLI nobody could find.

    ⚠️ It worked for us only because every run exported the venv's bin onto PATH first.
    """
    direct = os.environ.get("TORANA")
    if direct and os.path.exists(direct):
        return direct
    venv = os.environ.get("TORANA_VENV") or os.path.join(os.path.expanduser("~"),
                                                         ".torana-venv")
    candidate = os.path.join(venv, "bin", "torana")
    if os.path.exists(candidate):
        return candidate
    return "torana"      # PATH — correct in CI, where pip installs the wheel


def run_cli(args: List[str], *, parse_json: bool = True) -> Tuple[int, Any]:
    """Call the `torana` CLI. Returns (returncode, parsed-or-text)."""
    cmd = [torana_cli(), *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        # ⚠️ SAY WHICH ONE WAS MISSING. "No such file or directory" with no path reads
        # as a missing capability; naming the resolution order sends the reader to the
        # install, which is where the problem is.
        return 127, {"_err": f"the torana CLI was not found (tried $TORANA, "
                             f"$TORANA_VENV/bin/torana, then PATH as {cmd[0]!r}). "
                             f"Load the torana-skill bootstrap, or export TORANA."}
    if not parse_json:
        return p.returncode, (p.stdout or "").strip()
    try:
        parsed = json.loads(p.stdout or "null")
    except json.JSONDecodeError:
        parsed = None
    else:
        # ⚠️ A FAILED CALL WITH NOTHING ON STDOUT still says why, on stderr (a click usage error, a 422). Keep it:
        # the `imported_transitively` fallback reads the refusal's words.
        if p.returncode == 0 or parsed is not None:
            return p.returncode, parsed
        return p.returncode, {"_err": (p.stderr or "").strip()[:400]}
    if parsed is None:
        return p.returncode, {"_raw": (p.stdout or "").strip(),
                              "_err": (p.stderr or "").strip()[:400]}


# ── the pass ─────────────────────────────────────────────────────────────────────────

def write_verdict(repo: str, alert_id: str, verdict: str, evidence: Dict[str, Any], commit: str,
                  repo_key: str) -> Tuple[int, Any]:
    """Post one verdict through `torana alert <id> reachability` (the evidence goes in a file beside the tree)."""
    ev_path = os.path.join(repo, ".torana-reachability-evidence.json")
    with open(ev_path, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh)
    try:
        return run_cli(["alert", alert_id, "reachability",
                        "--verdict", verdict, "--commit", commit,
                        "--analyzer", evidence["analyzer"],
                        "--repository", repo_key,
                        "--evidence-file", ev_path, "--format", "json"])
    finally:
        try:
            os.unlink(ev_path)
        except OSError:
            pass


def _names_the_new_verdict(out: Any) -> bool:
    """Did the refusal name `imported_transitively`? (an old CLI's invalid choice, or the platform's 422)"""
    try:
        return "imported_transitively" in json.dumps(out)
    except (TypeError, ValueError):
        return "imported_transitively" in str(out)


def git_head(repo: str) -> Optional[str]:
    p = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    return (p.stdout or "").strip() or None


def git_repo_key(repo: str) -> Optional[str]:
    """`repo:<host>/<org>/<repo>` from the `origin` remote, or None.

    ⚠️ The platform's source-neutral id, so an https remote and an ssh one must reduce to the
    SAME key — otherwise the same repository is two scopes and a verdict measured under one
    never matches a finding stored under the other.
    """
    p = subprocess.run(["git", "-C", repo, "remote", "get-url", "origin"],
                       capture_output=True, text=True)
    url = (p.stdout or "").strip()
    if not url:
        return None
    url = re.sub(r"\.git$", "", url)
    m = re.match(r"^(?:https?://|ssh://)?(?:[^@/]+@)?([^/:]+)[/:](.+)$", url)
    if not m:
        return None
    host, path = m.group(1).lower(), m.group(2).strip("/").lower()
    return f"repo:{host}/{path}" if "/" in path else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", help="the checkout to analyse")
    ap.add_argument("--commit", default=None, help="default: git rev-parse HEAD")
    ap.add_argument("--repo-key", default=None,
                    help="repo:<host>/<org>/<repo> — the SCOPE of this pass. Derived from the "
                         "git remote when omitted; the pass refuses if neither is available.")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--apply", action="store_true",
                    help="write the verdicts back. Default is a dry run.")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="only JSON on stdout")
    a = ap.parse_args()

    repo = os.path.abspath(a.repo)
    commit = a.commit or git_head(repo)
    if not commit:
        log("ERROR: no commit. Pass --commit, or run inside a git checkout.\n"
            "       ⛔ Refusing rather than guessing: a reachability claim with no commit "
            "reads as permanent when it is about one tree.")
        return 2

    repo_key = a.repo_key or git_repo_key(repo)
    if not repo_key:
        log("ERROR: no repository key. Pass --repo-key repo:<host>/<org>/<repo>, or run in a "
            "checkout with an 'origin' remote.\n"
            "       ⛔ Refusing rather than guessing: the key is the SCOPE of every answer "
            "this pass writes. Measured in one tree, a verdict must not be able to move an "
            "item in another — and the platform refuses one that tries.")
        return 2

    q = ["alerts", "reachability-queue", "--repository", repo_key,
         "--commit", commit, "--limit", str(a.limit), "--format", "json"]
    rc, queue = run_cli(q)
    if rc != 0 or not isinstance(queue, dict):
        log(f"ERROR: could not read the queue (rc={rc}): {str(queue)[:300]}")
        return 1

    packages = queue.get("packages") or []
    code_findings = queue.get("code_findings") or []
    members = sum(len(p.get("alert_ids") or []) for p in packages)
    log(f"queue at {commit[:7]} in {repo_key}: {len(packages)} package(s) over {members} "
        f"member alert(s), {len(code_findings)} code finding(s)")

    # ⭐ INDEX ONCE, THEN ASK PER QUESTION. The import index (spans of the grammar over the whole tree, plus the
    # tree's lock files) and the call graph are built once per run; every queued question is a read over them.
    index = (build_imports(repo, commit=commit, repository=repo_key) if packages
             else {"repository": repo_key, "commit": commit, "files": []})
    cg = build_callgraph_index(repo, commit=commit, repository=repo_key) if code_findings else None
    graph = graph_from_index(cg) if cg else None
    if code_findings and graph is None:
        log("note: no call graph — the code findings will be inconclusive, WITH that as the "
            f"stated reason ({parser_remedy()}). The package list above does not need it.")

    # ⚠️ ONE VERDICT PER PACKAGE, WRITTEN TO EVERY MEMBER IT ANSWERS FOR. "Does this repo
    # import <package>" has one answer however many CVEs are open against it, so the queue
    # returns the members grouped and the tree is scanned once — not once per CVE.
    results = []
    for p in packages:
        v = answer_package(index, p, commit, repo_key)
        v = {**v, "evidence": ci_evidence(v["evidence"], "package", commit, repo_key)}
        for aid in p.get("alert_ids") or []:
            results.append({"alert_id": aid, "kind": "package",
                            "subject": p.get("package_name"), **v})
    for cf in code_findings:
        v = answer_code(index, cg, cf, commit, repo_key)
        v = {**v, "evidence": ci_evidence(v["evidence"], "code", commit, repo_key)}
        results.append({"alert_id": cf["alert_id"], "kind": "code_finding",
                        "subject": cf.get("file"), **v})

    written = []
    if a.apply:
        for r in results:
            rc2, out = write_verdict(repo, r["alert_id"], r["verdict"], r["evidence"], commit, repo_key)
            if rc2 != 0 and r["verdict"] == "imported_transitively" and _names_the_new_verdict(out):
                # ⚠️ AN OLDER PLATFORM (or CLI) DOES NOT KNOW THIS VERDICT YET (spec § 3.12.6, N4). Record the one
                # fact it does accept, which moves nothing, instead of leaving the member unanswered.
                log(f"  note {r['alert_id']}: {_PREDATES}; recording it as inconclusive")
                r["verdict"], r["evidence"] = "inconclusive", {**r["evidence"], "reason": _PREDATES}
                rc2, out = write_verdict(repo, r["alert_id"], r["verdict"], r["evidence"], commit, repo_key)
            written.append({"alert_id": r["alert_id"], "rc": rc2,
                            "outcome": (out or {}).get("outcome") if isinstance(out, dict) else None})
            if rc2 != 0:
                log(f"  WARN {r['alert_id']}: write failed rc={rc2} {str(out)[:200]}")

    summary = {"commit": commit, "repo": repo, "repository": repo_key,
               "engine": ENGINE_VERSION,
               "files_scanned": len(index.get("files") or []),
               "callgraph": ({"files": graph["files"], "entry_points": len(graph["entries"]),
                              "reachable": len(graph["reach"])} if graph else None),
               "counts": {v: sum(1 for r in results if r["verdict"] == v)
                          for v in sorted({r["verdict"] for r in results})},
               "applied": bool(a.apply), "results": results,
               **({"written": written} if a.apply else {})}

    # ⛔ WHAT THE WRITES DID, and in text mode too. Measured on demo 2026-10-13: an --apply
    # run posted 129 verdicts and printed only the verdict table — identical to a dry run's
    # output apart from one missing line, so an operator could not tell a recorded pass from
    # a refused one. The server's own outcome words are the report: `deprioritised` moved an
    # item, `recorded` kept its order, `already_recorded` means this commit was answered
    # before, and a non-zero rc is a REFUSAL (a wrong repository, an entry, an image member).
    failed = [w for w in written if w["rc"] != 0]
    outcomes = sorted({w["outcome"] for w in written}, key=str)
    summary["write_outcomes"] = {o: sum(1 for w in written if w["outcome"] == o)
                                 for o in outcomes}
    summary["write_failures"] = len(failed)

    if a.as_json:
        print(json.dumps(summary, indent=2))
    else:
        for r in results:
            print(f"  {r['verdict']:<26} {r['kind']:<13} {r['subject']}")
        print(f"\n{summary['counts']}")
        if not a.apply:
            print("\nDry run — nothing written. Re-run with --apply to record these.")
        else:
            print(f"\nWritten: {len(written)} verdict(s) → {summary['write_outcomes']}")
            if failed:
                print(f"REFUSED: {len(failed)} write(s) — see the WARN lines above. A refusal "
                      f"is the server declining an answer it cannot attribute to this "
                      f"repository, not a transport error.")

    # ⚠️ A REFUSED WRITE MUST NOT EXIT 0. This runs as a CI step: with a zero exit a gate
    # goes green while every verdict was declined, which is the quiet failure the whole
    # refusal exists to prevent.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
