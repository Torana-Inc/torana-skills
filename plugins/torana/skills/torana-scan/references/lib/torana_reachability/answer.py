"""The engine's answer (REACHABILITY_EXTRACTOR.md § 3.11.3): one question, the components of its subject, the
requirement graph -> a verdict with evidence and certainty.

Package questions:
1. an ecosystem with no grammar -> `not_known: language_unsupported`;
2. per component, the import index (`index.package_verdict`, gated by `PARITY_PROVEN`): any runtime site ->
   `reachable` (the sites, <= 20, the component named); non-runtime only -> `build_only`;
3. else `D` = the distributions any component imports at runtime; `package` reachable from `D` over the requirement
   graph -> `imported_transitively` with `via` = the shortest chain (sorted, deterministic);
4. else the `_ABSENCE` rule: a miss that may be the mapping -> `inconclusive`;
5. else, with an incomplete component set -> `inconclusive` naming the missing components (never `not_imported`,
   OI-126 F1); otherwise `not_imported`.

Code questions run `code_verdict` (moved verbatim from `reachability_pass.py:729-797`) over the stored call graph
after recomputing `reach`; a `function` narrows the file's defs to that one.

The library knows nothing about commits beyond what it is told: the caller (Atlas, detection or the CI pass) decides
the state (`measured` / `measured_at_other_commit`) and passes it in `binding`, so certainty can apply K1.
"""
from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional

from torana_reachability import ANALYZER_CALLGRAPH, ANALYZER_IMPORTS, ENGINE_VERSION
from torana_reachability.callgraph import _def_site, _path_to, graph_from_index, parser_remedy
from torana_reachability.certainty import certainty
from torana_reachability.firstparty import STATEMENT_TEMPLATES, normalize, statement_modules
from torana_reachability.grammar import _ABSENCE, _ECOSYSTEM_EXT, TEMPLATES, import_names
from torana_reachability.index import PARITY_PROVEN, ImportIndex, canonical, package_verdict
from torana_reachability.locks import graph_complete as _graph_complete

#: `not_known` reasons the library itself can give (a subset of § 3.4.1.3; the rest are the caller's).
REASON_TEXT = {
    "language_unsupported": "Atlas cannot analyse this language yet.",
    "index_missing": "Built before the code index existed; it will be added on the next build.",
    "parser_missing": "The Python parser was not available when this was built.",
}


def _not_known(reason: str) -> Dict[str, Any]:
    return {"state": "not_known", "reason": reason, "reason_text": REASON_TEXT[reason], "verdict": None,
            "certainty": None, "evidence": None}


def code_verdict(graph: Optional[Dict[str, Any]], cf: Dict[str, Any],
                 commit: str, repo_key: str, *, analyzer: str = ANALYZER_CALLGRAPH,
                 function: Optional[str] = None) -> Dict[str, Any]:
    """One verdict for one code finding. `function` (a def's name or qualified name) narrows the file's defs."""
    base = {"commit": commit, "analyzer": analyzer, "file": cf.get("file"),
            "repository": repo_key}
    path = cf.get("file") or ""

    if graph is None:
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": "no call graph available: no tree-sitter "
                                               "parser for Python on this runner "
                                               f"({parser_remedy()})"}}
    if not path.endswith(".py"):
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": f"this pass builds a call graph for Python "
                                               f"only; {path} is not covered"}}

    in_file = sorted(q for q, v in graph["defs"].items() if v[0] == path)
    if function:
        in_file = [q for q in in_file if graph["defs"][q][3] == function or q.endswith(f"::{function}")]
    if not in_file:
        # ⚠️ No function at all in that file: module-level code, which RUNS ON IMPORT. The
        # honest answer is that reachability does not discriminate here, not "unreachable".
        return {"verdict": "inconclusive",
                "evidence": {**base, "reason": "no function found in this file; the finding is "
                                               "module-level code, which runs on import and "
                                               "reachability does not discriminate"}}

    n_entries = len(graph["entries"])
    reachable = [q for q in in_file if q in graph["reach"]]

    # ⛔ NO ENTRY POINT FOUND IS NOT "NOTHING CALLS IT". With an empty entry set the BFS
    # cannot reach anything, so EVERY function in the repository comes back unreachable —
    # measured on a Click CLI repo: 0 entry points, and every code finding deprioritised to
    # 75 on an analysis that never had a starting node.
    if not reachable and not n_entries:
        return {"verdict": "inconclusive",
                "evidence": {**base, "entry_points_considered": 0,
                             "function": graph["defs"][in_file[0]][3],
                             "function_at": _def_site(graph, in_file[0]),
                             "reason": "the call graph found no entry point in this repository "
                                       "(this pass recognises framework route decorators "
                                       "only), so 'nothing reaches this code' cannot be "
                                       "distinguished from 'nothing here could reach "
                                       "anything'"}}

    if reachable:
        # ⚠️ The MOST CERTAIN chain, then the shortest: evidence a reader can check, rather
        # than whichever function happened to sort first.
        paths = {n: _path_to(graph["reach"], n) for n in reachable}
        q = min(reachable, key=lambda n: (paths[n][1], len(paths[n][0]), n))
        chain, unresolved = paths[q]
        return {"verdict": "reachable",
                "evidence": {**base, "function": graph["defs"][q][3],
                             "function_at": _def_site(graph, q),
                             "entry_points_considered": n_entries,
                             "path": chain, "path_unresolved_hops": unresolved,
                             **({"caveat": f"{unresolved} hop(s) on this path rest on a call "
                                           "this analysis could not resolve to one definition "
                                           "(a bare name defined in several files), so the "
                                           "path is possible, not proven"}
                                if unresolved else {})}}
    return {"verdict": "no_path_from_entry_point",
            "evidence": {**base, "function": graph["defs"][in_file[0]][3],
                         "function_at": _def_site(graph, in_file[0]),
                         "entry_points_considered": n_entries}}


# ── package questions ────────────────────────────────────────────────────────────────

def _runtime_modules(ix: ImportIndex, eco: str) -> List[str]:
    """Module (pypi) / package (npm) names the index's runtime statement spans name."""
    want = STATEMENT_TEMPLATES.get(eco, ())
    out = set()
    for r in ix.records("span"):
        if r["ecosystem"] == eco and r["template"] in want and r.get("runtime") and not r.get("cut"):
            out.update(statement_modules(r["text"], eco))
    return sorted(out)


def _distributions_of(modules: List[str], eco: str, graph: List[Dict[str, Any]],
                      dist_records: List[Dict[str, Any]]) -> List[str]:
    """Module -> distribution, by the `distribution` records and `import_names` reversed over the graph's packages; a
    module no known distribution claims maps to every graph package whose normalised name is its top segment (an
    over-match: the safe error)."""
    if eco != "pypi":
        return sorted(set(modules))
    claims: Dict[str, set] = collections.defaultdict(set)
    for d in dist_records:
        for m in d.get("modules") or ():
            claims[m.split(".")[0]].add(normalize(d["name"]))
    for r in graph:
        if r.get("kind") == "requirement" and r["ecosystem"] == "pypi":
            for m in import_names(r["package"], "pypi"):
                claims[m.split(".")[0]].add(normalize(r["package"]))
    out = set()
    for mod in modules:
        top = mod.split(".")[0]
        out |= claims.get(top) or {normalize(top)}
    return sorted(out)


def _chain(graph: List[Dict[str, Any]], eco: str, roots: List[str], package: str) -> Optional[List[str]]:
    """The shortest root -> … -> package chain over the requirement edges (BFS, sorted), or None."""
    norm = normalize if eco == "pypi" else (lambda x: x)
    edges: Dict[str, set] = collections.defaultdict(set)
    for r in graph:
        if r.get("kind") == "requirement" and r["ecosystem"] == eco:
            edges[norm(r["package"])] |= {norm(x) for x in r.get("requires") or ()}
    target = norm(package)
    parent: Dict[str, Optional[str]] = {}
    q = collections.deque()
    for root in sorted({norm(x) for x in roots}):
        if root not in parent:
            parent[root] = None
            q.append(root)
    while q:
        cur = q.popleft()
        if cur == target:
            chain = [cur]
            while parent[chain[-1]] is not None:
                chain.append(parent[chain[-1]])
            return list(reversed(chain))
        for nxt in sorted(edges.get(cur, ())):
            if nxt not in parent:
                parent[nxt] = cur
                q.append(nxt)
    return None


def answer(question: Dict[str, Any], components: List[Dict[str, Any]], graph: Optional[List[Dict[str, Any]]] = None,
           *, repository: str, commit: str, subject: Optional[str] = None,
           components_complete: bool = True, missing: Optional[List[str]] = None,
           locks: Optional[List[Dict[str, str]]] = None, binding: Optional[Dict[str, Any]] = None
           ) -> Dict[str, Any]:
    """Answer one question over the components of its subject.

    `question`: `{kind: "package"|"code", ecosystem, package, file, function, subject}` (the § 3.4.1.1 fields).
    `components`: `[{repository, commit, imports: <imports.json doc or ImportIndex>, callgraph: <callgraph.json doc
    or None>, node_path?, version?}]`, the subject's own repository first.
    `graph`: requirement records of the lock(s) (default: the components' own `requirement` records); `locks`:
    `[{repository, file}]` they came from (evidence only).
    `binding`: `{state, alert_commit, commit_matches_scanned}` from the caller (certainty K1); default `measured`
    with no alert commit.

    Returns `{state, reason, reason_text, verdict, certainty, evidence}` (§ 3.4.1.2 without `id` / `node`)."""
    binding = binding or {}
    state = binding.get("state", "measured")
    subject = subject or question.get("subject") or "repository"
    comp_ev = [{k: c.get(k) for k in ("repository", "node_path", "version", "commit") if c.get(k) is not None}
               for c in components]
    if question.get("kind") == "code":
        return _answer_code(question, components, repository=repository, commit=commit, subject=subject,
                            comp_ev=comp_ev, state=state)

    eco_raw = (question.get("ecosystem") or "").lower()
    package = question.get("package") or ""
    if eco_raw not in TEMPLATES:
        return _not_known("language_unsupported")
    eco = canonical(eco_raw)
    indexes = [ImportIndex.of(c["imports"]) for c in components]
    if graph is None:
        graph = [r for ix in indexes for r in ix.records("requirement")]
    if locks is None:
        locks = sorted({(c.get("repository"), r["file"]) for c, ix in zip(components, indexes)
                        for r in ix.records("requirement")})
        locks = [{"repository": rep, "file": f} for rep, f in locks]
    g_complete = _graph_complete(graph, eco_raw)
    base = {"analyzer": ANALYZER_IMPORTS, "engine": ENGINE_VERSION, "parity_proven": sorted(PARITY_PROVEN),
            "commit": commit, "repository": repository, "subject": subject, "components": comp_ev,
            "components_complete": components_complete, **({"missing": list(missing)} if missing else {}),
            "graph": {"locks": locks, "complete": g_complete}, "package_name": package}

    per = []
    for c, ix in zip(components, indexes):
        v = package_verdict(ix, {"package_name": package, "ecosystem": eco_raw}, c.get("commit") or commit,
                            c.get("repository") or repository, analyzer=ANALYZER_IMPORTS)
        per.append((c, ix, v))
    files_scanned = sum(v["evidence"].get("files_scanned", 0) for _, _, v in per)
    modules_tried = import_names(package, eco_raw)
    ev = {**base, "files_scanned": files_scanned, "modules_tried": modules_tried}

    def done(verdict: str, extra: Dict[str, Any]) -> Dict[str, Any]:
        evidence = {**ev, **extra}
        cert, unmet = certainty(
            verdict, ecosystem=eco_raw, package=package, subject=subject, state=state,
            alert_commit=binding.get("alert_commit"),
            commit_matches_scanned=bool(binding.get("commit_matches_scanned")),
            components_complete=components_complete, graph_complete=g_complete, graph=graph,
            dynamic_nonliteral=[r for ix in indexes for r in ix.records("dynamic_nonliteral")])
        evidence.update({"state": state, "alert_commit": binding.get("alert_commit"),
                         "certainty": cert, "certainty_unmet": unmet})
        return {"state": state, "reason": None, "reason_text": None, "verdict": verdict, "certainty": cert,
                "evidence": evidence}

    for c, _, v in per:
        if v["verdict"] == "reachable":
            return done("reachable", {"function": v["evidence"]["function"], "path": v["evidence"]["path"],
                                      "component": c.get("repository")})
    for c, _, v in per:
        if v["verdict"] == "build_only":
            return done("build_only", {"scopes": v["evidence"]["scopes"],
                                       "import_sites": v["evidence"]["import_sites"],
                                       "component": c.get("repository")})

    # 3. Imported by nothing directly: is it required by something that is imported?
    roots = set()
    dist_records = [r for ix in indexes for r in ix.records("distribution")]
    for ix in indexes:
        roots.update(_distributions_of(_runtime_modules(ix, eco), eco_raw, graph, dist_records))
    chain = _chain(graph, eco_raw, sorted(roots), package) if roots else None
    if chain and len(chain) > 1:
        return done("imported_transitively", {"via": chain})

    # 4. The miss. A component that holds no source of this ecosystem could never import it: its absence is
    # guaranteed, so it is set aside, unless no component has any (then the frozen scan's inconclusive stands).
    exts = _ECOSYSTEM_EXT[eco_raw]
    looked = [(c, v) for c, ix, v in per if any(f.endswith(exts) for f in ix.files)]
    if not looked:
        first = per[0][2] if per else None
        reason = (first["evidence"]["reason"] if first else f"no component holds {'/'.join(exts)} source")
        return done("inconclusive", {"reason": reason})
    for c, v in looked:
        if v["verdict"] != "not_imported":
            return done("inconclusive", {"reason": v["evidence"]["reason"], "component": c.get("repository")})
    why = _ABSENCE.get(eco_raw)
    if why is not None:                     # unreachable today: package_verdict already said inconclusive
        return done("inconclusive", {"reason": why})
    # 5. ⛔ AN ABSENCE OVER PART OF THE SUBJECT IS NOT AN ABSENCE OF THE SUBJECT (§ 3.11.3 step 5, OI-126 F1). With a
    # component missing (a wheel the image installs that maps to no selected, built repository), "imported by none
    # of the components read" says nothing about the one that was not read: measured, pantheon-shared imports or
    # requires all four EXP-03 rows that came back `not_imported` without it. So it is `inconclusive`, naming what
    # is missing, at any certainty. Steps 2-3 are unaffected: a site found in a component that was read is real.
    if not components_complete:
        miss = list(missing) if missing else ["an unnamed component"]
        read = ", ".join(sorted({c.get("repository") or "?" for c in components})) or "no component"
        return done("inconclusive", {
            "reason": f"{package!r} is not imported by {read}, but the component set is incomplete: "
                      f"{', '.join(miss)} not analysed, so an absence was not measured",
            "missing": miss})
    return done("not_imported", {})


def _answer_code(question: Dict[str, Any], components: List[Dict[str, Any]], *, repository: str, commit: str,
                 subject: str, comp_ev: List[Dict[str, Any]], state: str) -> Dict[str, Any]:
    path = question.get("file") or ""
    if not path.endswith(".py"):
        return _not_known("language_unsupported")
    doc = components[0].get("callgraph") if components else None
    if doc is None:
        return _not_known("index_missing")
    if (doc.get("languages") or {}).get("python") == "parser_missing":
        return _not_known("parser_missing")
    graph = graph_from_index(doc)
    v = code_verdict(graph, {"file": path}, commit, repository, function=question.get("function"))
    evidence = {**v["evidence"], "engine": ENGINE_VERSION, "subject": subject, "components": comp_ev,
                "components_complete": True, "state": state, "certainty": "believed", "certainty_unmet": []}
    return {"state": state, "reason": None, "reason_text": None, "verdict": v["verdict"], "certainty": "believed",
            "evidence": evidence}


def components_of(index_doc: Dict[str, Any], callgraph_doc: Optional[Dict[str, Any]] = None
                  ) -> List[Dict[str, Any]]:
    """A one-component list for a repository subject (the CI pass's case)."""
    return [{"repository": index_doc.get("repository"), "commit": index_doc.get("commit"),
             "imports": index_doc, "callgraph": callgraph_doc}]


__all__ = ["REASON_TEXT", "answer", "code_verdict", "components_of"]
