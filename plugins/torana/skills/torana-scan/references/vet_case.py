#!/usr/bin/env python3
"""D-06 slice 1: the AI review of a fix ("code measures, an LLM vets").

FIX_PR_CODE_MEASURES_LLM_VETS_SPEC.md § 5 (contract), § 5.1 (vet.json, FROZEN), § 10 (slice 1).

    vet_case.py --plan plan.json --group N --report commit.json --plan-id ID --fingerprint sha256:… \\
                --tree LABEL=PATH [--tree …] [--api-diff-file diffs.json] --out vet.json [--loop 0]

1. BUILD a case dir: PROPOSAL.md + proposal.json (the group: verdict, edits, evidence, API diff, the nine
   assumptions as data, the gates, the diff). The reviewer sees what code CLAIMED, so it can check it.
2. RUN one cold, read-only review: `claude -p` with Read/Grep/Glob only, a $0.50 hard cap, no settings, no skills.
3. WRITE vet.json in the § 5.1 shape. Anything that is not a valid verdict (cap, error, timeout, bad JSON) is
   `unvetted`, which counts as draft — never confirm.

⛔ ONE-WAY AUTHORITY. The review may confirm, draft or refuse, and may PROPOSE an `alternative` that code then
re-plans and measures (max 2 loops). It never upgrades a code verdict, picks a version code did not measure, or
widens a lane: `final_state` is the stricter of the two (refuse > draft = unvetted > confirm), computed here and
wherever it is shown, never stored.

⛔ NO NETWORK TOOL, deliberately. The reviewer reads untrusted text (the repository, changelogs) that may try to
steer it. With Read/Grep/Glob only, a steered reviewer can at worst block or draft a good fix. With WebFetch it
could also send the customer's code to a URL the text names. Upstream material it needs (the API diff) is put in
the case dir by code.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import posixpath
import re
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import assumptions as asm  # noqa: E402

SCHEMA = "torana.remediation_vet.v1"
VERDICTS = ("confirm", "draft", "refuse", "unvetted")
UNVETTED_WHY = ("cap", "error", "timeout", "no_verdict")
CHECKS = ("agree", "disagree", "unchecked")
BUDGET_USD = 0.50                       # Bhakta 2026-11-04, decision 4
MAX_LOOPS = 2                           # decision 1
MAX_BYTES = 16 * 1024
MAX_REASON, MAX_EVIDENCE, MAX_QUOTE, MAX_ALT_WHY = 2000, 20, 300, 1000
TIMEOUT_S = 900
_RANK = {"confirm": 0, "draft": 1, "unvetted": 1, "refuse": 2}

#: The fixed brief. ⛔ NEUTRAL: it names no defect. It names the KNOWN BLIND SPOTS of the code's measurements so the
#: reviewer checks them instead of trusting a summary (the spec's half-catches A1 and B4 were the reviewer believing
#: "0 touched" and "this lock ships").
BRIEF = """You are reviewing an automated dependency fix before a pull request opens. Code planned it and measured it.
Your job: decide whether it is safe to open as a ready-for-review PR.

Read PROPOSAL.md first. It opens with what THIS PR changes (installed version → new version, from the resolver's
result). Packages listed under "NOT in this PR" were split out by code (no fix resolves for them here) and get their
own decision: review only what lands, and a split-out package is never a reason to refuse. It lists every assumption
the code made, each with a basis (measured / inferred / unknown)
and evidence. Then check the assumptions against the source trees named there. Trust a `measured` claim only as far
as its evidence goes; check every `inferred` and `unknown` one yourself where you can.

Known blind spots of the code, check them:
- code cannot see calls through untyped objects: check methods called on objects returned by this package, and on
  objects of it passed in as parameters, against what the upgrade removes or changes;
- names built at runtime (getattr, importlib, patch strings) and use through a wrapper package;
- whether the image that ships is built from the lock this fix changes: if provenance is not measured, read the
  Dockerfile(s) and say whether they install from this lock;
- behaviour changes with no API change (defaults, themes, layout): read the API diff and any changelog in the case.

When gates 4 and 5 (build, tests) read `not_run` because the repository's own CI runs them on the draft PR, nobody
has run the tests yet: mark `tests` unchecked, and never confirm or refuse on that alone. The PR stays a draft until
that CI passes.

Search recipe (you have a hard budget): start from the files and symbols the proposal names, then the changed
symbols' names. Never grep a whole tree for the package name alone, and skip vendored/dist/build output.

Verdicts:
- confirm: you found nothing that makes the fix unsafe, and the claims you checked hold;
- draft: it may be fine, but a human must look first (name what to look at);
- refuse: the fix is wrong as planned (it breaks something, or a claim it rests on is false).
You may also propose an `alternative` (another version, or removing the package) with why; code will re-plan and
measure it. You may NOT approve anything code declined, choose a version yourself, or widen what the fix changes.

Cite every evidence `file` as a path RELATIVE to the root of the source tree it is in, with `repo` set to that tree's
label as PROPOSAL.md names it (never an absolute path), and `line` from 1.

Answer with the JSON object only."""

#: What the reviewer returns (structured output). `plan_id`, `fingerprint`, model, cost, session and loop are filled
#: by code, never by the model.
ANSWER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["verdict", "reason", "evidence", "assumptions_checked", "alternative"],
    "properties": {
        "verdict": {"enum": ["confirm", "draft", "refuse"]},
        "reason": {"type": "string"},
        "evidence": {"type": "array", "items": {
            "type": "object", "required": ["file", "line"],
            "properties": {"repo": {"type": "string"}, "file": {"type": "string"}, "line": {"type": "integer"},
                           "quote": {"type": "string"}}}},
        "assumptions_checked": {"type": "object", "properties": {k: {"enum": list(CHECKS)} for k in asm.KEYS}},
        "alternative": {"anyOf": [{"type": "null"}, {
            "type": "object", "required": ["package", "action", "why"],
            "properties": {"package": {"type": "string"}, "action": {"enum": ["target", "remove"]},
                           "target": {"type": ["string", "null"]}, "why": {"type": "string"}}}]},
    },
}


class VetError(ValueError):
    """A vet object that does not meet § 5.1."""


# ── the case ───────────────────────────────────────────────────────────────────────

def _group(plan: Dict[str, Any], index: int) -> Dict[str, Any]:
    groups = plan.get("groups") or []
    for g in groups:
        if int(g.get("index", -1)) == index:
            return g
    if 0 <= index < len(groups):
        return groups[index]
    raise VetError(f"the plan has no group {index}")


def _report_group(report: Dict[str, Any], index: int) -> Dict[str, Any]:
    if isinstance(report.get("groups"), list):
        for g in report["groups"]:
            if int(g.get("group", -1)) == index:
                return g
        return report["groups"][0] if report["groups"] else {}
    return report.get("report") if isinstance(report.get("report"), dict) else report


def _norm(name: Any) -> str:
    return re.sub(r"[-_.]+", "-", str(name or "")).lower()


def landed_packages(rep: Dict[str, Any]) -> Optional[Dict[str, Dict[str, Any]]]:
    """What gate 1 says LANDED in the lock(s): `{package: {from, to}}`, or None for a report without gate 1's record
    (then the plan's packages are all a reader has). ⛔ This, not the plan, is what the PR contains (§ 11 F1)."""
    gates = [g for g in rep.get("gate_1_resolve") or [] if isinstance(g, dict) and isinstance(g.get("landed"), dict)]
    if not gates:
        return None
    out: Dict[str, Dict[str, Any]] = {}
    for g in gates:
        for pkg, v in g["landed"].items():
            if isinstance(v, dict):
                out.setdefault(str(pkg), v)
    return out


def _in_pr(group: Dict[str, Any], rep: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The plan's packages that are IN this PR: all of them, unless gate 1 recorded what landed."""
    landed = landed_packages(rep)
    pk = group.get("packages") or []
    if landed is None:
        return list(pk)
    names = {_norm(k) for k in landed}
    return [p for p in pk if _norm(p.get("package")) in names]


def case_assumptions(group: Dict[str, Any], rep: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """package → the nine assumptions (planner seven from the plan package, apply two from the report), for the
    packages IN this PR only: a split-out package's claims are not this PR's (§ 11 F1)."""
    apply_list = rep.get("assumptions") if isinstance(rep.get("assumptions"), list) \
        else asm.apply_assumptions(rep)
    return {str(p.get("package")): asm.merged(p.get("assumptions") or [], apply_list)
            for p in _in_pr(group, rep)}


def _versions(v: Any) -> str:
    return ", ".join(str(x) for x in v) if isinstance(v, list) else str(v if v is not None else "?")


def changes_markdown(group: Dict[str, Any], rep: Dict[str, Any]) -> List[str]:
    """The case's FIRST section (§ 11 F1 + F3): installed → new for what lands, then what was split out and why."""
    landed = landed_packages(rep)
    out = ["## What this PR changes (read this first)",
           "The installed version is the one in the lock today; a manifest specifier such as `>=23.11` is a floor, "
           "not the installed version."]
    if landed is None:
        out += [f"- `{p.get('package')}`: installed {p.get('installed') or '?'} → {p.get('target') or 'removed'}"
                for p in group.get("packages") or []]
    else:
        by = {_norm(p.get("package")): p for p in group.get("packages") or []}
        for pkg, v in sorted(landed.items()):
            plan_target = (by.get(_norm(pkg)) or {}).get("target")
            out.append(f"- `{pkg}`: installed {_versions(v.get('from'))} → {_versions(v.get('to'))}"
                       + (f" (planned target {plan_target})" if plan_target and plan_target != v.get("to") else ""))
        moved = [x for x in rep.get("also_moved") or [] if isinstance(x, dict)]
        out += [f"- also moves: `{x.get('package')}` {x.get('from')} → {x.get('to')}" for x in moved]
    split = [x for x in rep.get("split_out") or [] if isinstance(x, dict)]
    gone = set() if landed is None else {_norm(k) for k in landed}
    unlanded = [] if landed is None else [p for p in group.get("packages") or [] if _norm(p.get("package")) not in gone
                                          and _norm(p.get("package")) not in {_norm(x.get("package")) for x in split}]
    if split or unlanded:
        out += ["", "## NOT in this PR (code split these out; they are decided separately)"]
        out += [f"- `{x.get('package')}` → {x.get('target') or '?'}: {x.get('why') or 'split out'} (class 5)"
                for x in split]
        out += [f"- `{p.get('package')}` → {p.get('target') or '?'}: planned, but the resolver did not land it here"
                for p in unlanded]
    return out + [""]


def proposal_markdown(group: Dict[str, Any], rep: Dict[str, Any], trees: Dict[str, str],
                      diff_text: str, api_diff_names: List[str]) -> str:
    out = [f"# Proposal: class {group.get('class')} fix", ""]
    out += changes_markdown(group, rep)
    out += ["## Edits"] + [f"- {e.get('repo')}/{e.get('file')}:{e.get('line')} {e.get('action')} "
                           f"`{e.get('from')}` → `{e.get('to')}`" for e in group.get("edits") or []] + [""]
    out += ["## Code's evidence"] + [f"- {e}" for e in group.get("evidence") or []] + [""]
    out += ["## Assumptions (what the code claims, and on what basis)"]
    for pkg, items in case_assumptions(group, rep).items():
        out += [f"### {pkg}", "| key | basis | claim | evidence |", "|---|---|---|---|"]
        for a in items:
            ev = "; ".join(a.get("evidence") or [])[:600].replace("|", "\\|").replace("\n", " ")
            out.append(f"| {a['key']} | {a['basis']} | {str(a['claim']).replace('|', '/')} | {ev} |")
        out.append("")
    out += ["## Gates", f"- status: {rep.get('status')}"]
    for k in ("gate_1_resolve", "gate_2_blast_radius", "gate_3_lane", "gate_4_build", "gate_5_tests"):
        if k in rep:
            out.append(f"- {k}: {json.dumps(rep[k], default=str)[:800]}")
    out += ["", "## Source trees (read-only)"] + [f"- {lb}: {p}" for lb, p in trees.items()]
    if api_diff_names:
        out += ["", "## Upstream material in this case dir"] + [f"- {n}" for n in api_diff_names]
    out += ["", "## The diff", "```diff", diff_text[:60_000], "```", ""]
    return "\n".join(out)


def build_case(case_dir: str, plan: Dict[str, Any], group_index: int, report: Dict[str, Any],
               trees: Dict[str, str], api_diff_docs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Write PROPOSAL.md, proposal.json and upstream/*.json into `case_dir`; return the proposal object."""
    os.makedirs(os.path.join(case_dir, "upstream"), exist_ok=True)
    group, rep = _group(plan, group_index), _report_group(report, group_index)
    names = []
    for i, d in enumerate(api_diff_docs or []):
        k = d.get("key") or {}
        stem = "".join(c if c.isalnum() or c in ".-" else "_"
                       for c in f"{k.get('package', i)}-{k.get('from')}-{k.get('to')}")
        name = f"upstream/api-diff-{stem}.json"
        with open(os.path.join(case_dir, name), "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=1)
        names.append(name)
    diff_text = ""
    if rep.get("diff") and os.path.isfile(str(rep["diff"])):
        with open(rep["diff"], encoding="utf-8", errors="replace") as fh:
            diff_text = fh.read()
    proposal = {"group": group, "report": {k: v for k, v in rep.items() if k != "diff"},
                "assumptions": case_assumptions(group, rep), "trees": trees}
    with open(os.path.join(case_dir, "proposal.json"), "w", encoding="utf-8") as fh:
        json.dump(proposal, fh, indent=1, default=str)
    with open(os.path.join(case_dir, "PROPOSAL.md"), "w", encoding="utf-8") as fh:
        fh.write(proposal_markdown(group, rep, trees, diff_text, names))
    return proposal


# ── the run ────────────────────────────────────────────────────────────────────────

def review_command(case_dir: str, trees: Dict[str, str], budget: float = BUDGET_USD,
                   model: Optional[str] = None) -> List[str]:
    cmd = ["claude", "-p", BRIEF, "--output-format", "json", "--tools", "Read,Grep,Glob",
           "--allowed-tools", "Read,Grep,Glob", "--max-budget-usd", f"{budget:.2f}",
           "--json-schema", json.dumps(ANSWER_SCHEMA), "--setting-sources", "project",
           "--disable-slash-commands", "--permission-mode", "dontAsk",
           # EM D-23 S3 (em3 r1 B1): no MCP server from any config file, ever. The case dir is built by code, but a
           # tree it reads is the customer's (and, in CI, an artifact a resolver ran next to).
           "--strict-mcp-config"]
    for p in trees.values():
        cmd += ["--add-dir", p]
    if model:
        cmd += ["--model", model]
    return cmd


#: EM D-23 S3: the ONLY variables `claude` gets with `--clean-env` (the remediate Action's review job): what it
#: needs to run and reach the API through a proxy or a custom CA (em3 r1 m5), and the ONE model credential the job
#: was given: an API key or a Claude subscription token (`claude setup-token`; delta d2 § 5). HOME is a fresh empty
#: dir, so no user-level settings, hooks or MCP config exist either.
CLEAN_ENV_KEEP = ("PATH", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy",
                  "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE",
                  "LANG", "LC_ALL", "TMPDIR")


#: Set in every clean env (em3 d2 m2): `claude` sends no telemetry, error reports or update checks, so the only host
#: it needs is the model API (what the isolated runner's proxy allows, delta d2 § 3.3).
CLEAN_ENV_SET = {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}


def clean_env(env: Dict[str, str], home: str) -> Dict[str, str]:
    """`env` reduced to `CLEAN_ENV_KEEP`, plus `CLEAN_ENV_SET`, with HOME = `home` (created empty by the caller)."""
    return {**{k: env[k] for k in CLEAN_ENV_KEEP if env.get(k)}, **CLEAN_ENV_SET, "HOME": home}


def run_review(case_dir: str, trees: Dict[str, str], budget: float = BUDGET_USD, model: Optional[str] = None,
               runner: Callable[..., Any] = subprocess.run, timeout: int = TIMEOUT_S,
               env: Optional[Dict[str, str]] = None,
               command: Optional[List[str]] = None) -> Tuple[Optional[dict], str]:
    """(the CLI's JSON result or None, the unvetted reason when None). `env` None = inherit (the laptop).
    `command` (EM D-23 S2): another reviewer command run the same way (`judge_case.py`'s); default the plan review."""
    try:
        p = runner(command or review_command(case_dir, trees, budget, model), cwd=case_dir, capture_output=True,
                   text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except OSError:
        return None, "error"
    try:
        res = json.loads(p.stdout or "")
    except ValueError:
        return None, "error"
    return (res if isinstance(res, dict) else None), ("" if isinstance(res, dict) else "error")


def _answer_of(res: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    a = res.get("structured_output")
    if isinstance(a, dict):
        return a
    try:
        a = json.loads(res.get("result") or "")
    except (TypeError, ValueError):
        return None
    return a if isinstance(a, dict) else None


#: A model or session the run did not report (it failed before one existed). DF requires 1..200 characters.
UNKNOWN = "none"


def _reviewing_model(usage: Any) -> str:
    """The model that DID the review: the `modelUsage` key with the largest `costUSD` (§ 11 F2). The first key is often
    a helper model the CLI ran on the side (7 of 8 reviews credited a haiku under --model sonnet)."""
    if not isinstance(usage, dict) or not usage:
        return ""
    def cost(item):
        v = item[1] if isinstance(item[1], dict) else {}
        try:
            return float(v.get("costUSD") or 0.0)
        except (TypeError, ValueError):
            return 0.0
    return str(max(usage.items(), key=cost)[0])


def _evidence_place(e: Dict[str, Any], trees: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """One reviewer citation as DF accepts it, or None to drop it (D-06 review M3).

    The reviewer reads the trees by ABSOLUTE path (`--add-dir`), so it often cites `/var/folders/…/a.py`. Such a path
    is made relative to the tree that holds it and `repo` is set to that tree's label; a path in no tree, or one that
    escapes its tree, is dropped (it cannot be shown or checked). A relative path is kept as is. `line` is clamped
    to at least 1."""
    f = str(e.get("file") or "").strip()
    repo = str(e["repo"]) if e.get("repo") else None
    if f.startswith("/"):
        real = os.path.realpath(f)
        hit = None
        for label, root in sorted(trees.items(), key=lambda kv: -len(kv[1])):
            r = os.path.realpath(root)
            if real == r or real.startswith(r + os.sep):
                hit = (label, os.path.relpath(real, r))
                break
        if hit is None:
            return None
        repo, f = hit
    f = f.replace(os.sep, "/")
    if not f or "\\" in f or posixpath.normpath(f).startswith("..") or len(f) > 1024:
        return None
    x: Dict[str, Any] = {"file": f, "line": max(1, int(e["line"]))}
    if repo:
        x["repo"] = repo[:512]
    if e.get("quote"):
        x["quote"] = str(e["quote"])[:MAX_QUOTE]
    return x


def to_vet(res: Optional[Dict[str, Any]], why: str, plan_id: str, fingerprint: str, loop: int = 0,
           model: Optional[str] = None, trees: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The § 5.1 object. Every failure becomes `unvetted` with its reason; never confirm. ⛔ Always one DF accepts
    (D-06 review M3): evidence repo-relative, `model` / `session_id` never empty."""
    base: Dict[str, Any] = {
        "schema": SCHEMA, "plan_id": plan_id, "fingerprint": fingerprint, "verdict": "unvetted",
        "unvetted_why": None, "reason": "", "evidence": [],
        "assumptions_checked": {k: "unchecked" for k in asm.KEYS}, "alternative": None,
        "model": model or UNKNOWN, "cost_usd": 0.0, "session_id": UNKNOWN, "loop": int(loop),
        "vetted_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if res:
        base["cost_usd"] = round(float(res.get("total_cost_usd") or 0.0), 4)
        base["session_id"] = str(res.get("session_id") or "")[:200] or UNKNOWN
        base["model"] = (_reviewing_model(res.get("modelUsage")) or model or UNKNOWN)[:200]
        sub = str(res.get("subtype") or "")
        if "budget" in sub:
            why = "cap"
        elif res.get("is_error") or (sub and sub != "success"):
            why = why or "error"
    answer = _answer_of(res) if res and not why else None
    if answer is None or answer.get("verdict") not in ("confirm", "draft", "refuse"):
        base["unvetted_why"] = why or "no_verdict"
        base["reason"] = {"cap": f"the review hit its ${BUDGET_USD:.2f} cap before a verdict",
                          "timeout": "the review timed out", "error": "the review failed to run",
                          "no_verdict": "the review returned no valid verdict"}[base["unvetted_why"]]
        base["cost_usd"] = min(base["cost_usd"], BUDGET_USD)
        return base
    base["verdict"] = answer["verdict"]
    base["reason"] = str(answer.get("reason") or "")[:MAX_REASON]
    ev = []
    for e in answer.get("evidence") or []:
        if isinstance(e, dict) and e.get("file") and isinstance(e.get("line"), int) and not isinstance(e["line"], bool):
            x = _evidence_place(e, trees or {})
            if x is not None:
                ev.append(x)
    base["evidence"] = ev[:MAX_EVIDENCE]
    ac = answer.get("assumptions_checked") or {}
    base["assumptions_checked"] = {k: (ac.get(k) if ac.get(k) in CHECKS else "unchecked") for k in asm.KEYS}
    alt = answer.get("alternative")
    if isinstance(alt, dict) and alt.get("package") and alt.get("action") in ("target", "remove"):
        base["alternative"] = {"package": str(alt["package"]), "action": alt["action"],
                               "target": (str(alt["target"]) if alt.get("target") else None),
                               "why": str(alt.get("why") or "")[:MAX_ALT_WHY]}
    if base["cost_usd"] > BUDGET_USD:            # § 5.1: never above the cap
        return to_vet(None, "cap", plan_id, fingerprint, loop, base["model"], trees) | {
            "cost_usd": BUDGET_USD, "session_id": base["session_id"]}
    validate_vet(base)
    return base


_FP = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_KEYS = {"repo", "file", "line", "quote"}
_ALT_KEYS = {"package", "action", "target", "why"}


def _repo_relative(path: Any) -> bool:
    """DF `VetEvidence.file`: repo-relative, 1..1024 chars, no absolute path, no backslash, never out of the tree."""
    p = str(path or "")
    return 0 < len(p) <= 1024 and not p.startswith("/") and "\\" not in p and \
        not posixpath.normpath(p).startswith("..")


def validate_vet(v: Dict[str, Any]) -> Dict[str, Any]:
    """§ 5.1, checked. Raises VetError. ⛔ EXACTLY DF's rules (`remediation_vet.VetIn`, D-06 review M3): both sides are
    tested against ONE table (tests/fixtures/vet_contract_cases.json), so a vet this accepts is never DF's 422. The
    laptop also requires every key present (it always writes them all)."""
    want = {"schema", "plan_id", "fingerprint", "verdict", "unvetted_why", "reason", "evidence",
            "assumptions_checked", "alternative", "model", "cost_usd", "session_id", "loop", "vetted_at"}
    if not isinstance(v, dict) or set(v) != want:
        raise VetError(f"vet.json must have exactly {sorted(want)}")
    if v["schema"] != SCHEMA:
        raise VetError(f"schema must be {SCHEMA}")
    if not (isinstance(v["plan_id"], str) and 0 < len(v["plan_id"]) <= 36):
        raise VetError("plan_id must be 1..36 characters")
    if v["verdict"] not in VERDICTS:
        raise VetError(f"verdict must be one of {VERDICTS}")
    if (v["verdict"] == "unvetted") != (v["unvetted_why"] is not None) or \
            (v["unvetted_why"] is not None and v["unvetted_why"] not in UNVETTED_WHY):
        raise VetError("unvetted_why is set exactly when verdict is unvetted, from " + str(UNVETTED_WHY))
    if not _FP.match(str(v["fingerprint"])):
        raise VetError("fingerprint must be sha256:<64 lowercase hex>")
    if not isinstance(v["reason"], str) or len(v["reason"]) > MAX_REASON:
        raise VetError(f"reason must be a string of at most {MAX_REASON} characters")
    ev = v["evidence"]
    if not isinstance(ev, list) or len(ev) > MAX_EVIDENCE:
        raise VetError(f"evidence must be a list of at most {MAX_EVIDENCE}")
    for e in ev:
        if not isinstance(e, dict) or not set(e) <= _EVIDENCE_KEYS or not _repo_relative(e.get("file")):
            raise VetError("each evidence entry is {repo?, file (repo-relative), line?, quote?}")
        line = e.get("line")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            raise VetError("evidence line must be >= 1")
        if len(str(e.get("quote") or "")) > MAX_QUOTE or len(str(e.get("repo") or "")) > 512:
            raise VetError(f"evidence quote is at most {MAX_QUOTE} characters, repo 512")
    ac = v["assumptions_checked"]
    if not isinstance(ac, dict) or set(ac) != set(asm.KEYS) or any(x not in CHECKS for x in ac.values()):
        raise VetError("assumptions_checked must name all nine keys, each agree|disagree|unchecked")
    alt = v["alternative"]
    if alt is not None:
        if not isinstance(alt, dict) or not ({"package", "action", "why"} <= set(alt) <= _ALT_KEYS) or \
                alt.get("action") not in ("target", "remove") or not (0 < len(str(alt.get("package") or "")) <= 214) \
                or len(str(alt.get("why"))) > MAX_ALT_WHY or len(str(alt.get("target") or "")) > 128:
            raise VetError("alternative must be null or {package, action: target|remove, target, why}")
    for k in ("model", "session_id"):
        if not (isinstance(v[k], str) and 0 < len(v[k]) <= 200):
            raise VetError(f"{k} must be 1..200 characters (a placeholder such as 'none' when unknown)")
    if isinstance(v["loop"], bool) or not isinstance(v["loop"], int) or not (0 <= v["loop"] <= MAX_LOOPS):
        raise VetError(f"loop must be 0..{MAX_LOOPS}")
    try:
        cost = float(v["cost_usd"])
    except (TypeError, ValueError):
        raise VetError("cost_usd must be a number")
    if cost < 0 or (cost > BUDGET_USD + 1e-9 and v["verdict"] != "unvetted"):
        raise VetError(f"cost_usd must be >= 0, and above the ${BUDGET_USD:.2f} cap only as unvetted")
    try:
        at = datetime.datetime.fromisoformat(str(v["vetted_at"]).replace("Z", "+00:00"))
    except ValueError:
        raise VetError("vetted_at must be ISO 8601")
    if at.tzinfo is None:
        raise VetError("vetted_at must carry a timezone (ISO 8601 UTC)")
    if len(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_BYTES:
        raise VetError("vet.json is larger than 16 KiB")
    return v


# ── combining and showing ──────────────────────────────────────────────────────────

def final_state(code: str, vet: Optional[Dict[str, Any]]) -> str:
    """The stricter of code and review. No review = unvetted = draft. ⛔ Never looser than code."""
    review = (vet or {}).get("verdict") or "unvetted"
    worst = max((code, review), key=lambda x: _RANK.get(x, 1))
    return "draft" if worst == "unvetted" else worst


def vet_for_plan(vet: Optional[Dict[str, Any]], plan_id: str, fingerprint: str) -> Tuple[Optional[Dict[str, Any]],
                                                                                          str]:
    """The vet if it is valid and is about THIS plan at THIS fingerprint, else (None, why). A stale vet reads
    unvetted (§ 7): the edit it reviewed is not the edit about to open."""
    if vet is None:
        return None, "no review was run"
    try:
        validate_vet(vet)
    except VetError as exc:
        return None, f"the review file is invalid: {exc}"
    if vet["plan_id"] != plan_id:
        return None, "the review is about another plan"
    if vet["fingerprint"] != fingerprint:
        return None, "the review is stale: the plan changed after it was reviewed"
    return vet, ""


def review_block(code: str, vet: Optional[Dict[str, Any]], why_missing: str = "",
                 overruled: Optional[str] = None) -> str:
    """The PR body's "AI review" block: both verdicts, the final one, and the review's reason and evidence."""
    fin = final_state(code, vet)
    lines = ["", "## AI review", "",
             f"Code: **{code}** · Review: **{(vet or {}).get('verdict', 'unvetted')}** · Final: **{fin}**"
             + (f" (a person overruled the refusal: {overruled})" if overruled else ""), ""]
    if not vet:
        lines.append(f"Not reviewed ({why_missing or 'no review'}): an unreviewed fix opens as a draft.")
        return "\n".join(lines) + "\n"
    if vet.get("unvetted_why"):
        lines.append(f"Not reviewed ({vet['reason']}): an unreviewed fix opens as a draft.")
    else:
        lines.append(vet.get("reason") or "")
    for e in vet.get("evidence") or []:
        at = f"{e['repo'] + '/' if e.get('repo') else ''}{e['file']}:{e['line']}"
        lines.append(f"- `{at}`" + (f": {e['quote']}" if e.get("quote") else ""))
    dis = [k for k, x in (vet.get("assumptions_checked") or {}).items() if x == "disagree"]
    if dis:
        lines.append(f"- The review DISAGREES with: {', '.join(dis)}")
    if vet.get("alternative"):
        alt = vet["alternative"]
        lines.append(f"- Proposed instead: {alt['action']} `{alt['package']}`"
                     + (f" → {alt['target']}" if alt.get("target") else "") + f" ({alt.get('why')})")
    lines.append(f"\n<sub>{vet.get('model') or 'model ?'} · ${float(vet.get('cost_usd') or 0):.2f} · "
                 f"session {vet.get('session_id') or '?'} · loop {vet.get('loop')}</sub>")
    return "\n".join(lines)[:6000] + "\n"


def default_trees(report_path: str) -> Dict[str, str]:
    """The applied scratch copies `remediation_apply.py` left beside its report (`group-N/<label>`), never the
    pristine baselines: the reviewer reads the tree as it WILL be after the fix."""
    root = os.path.dirname(os.path.abspath(report_path))
    out = {}
    for g in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        gd = os.path.join(root, g)
        if g.startswith("group-") and not g.endswith("-baseline") and os.path.isdir(gd):
            for lb in sorted(os.listdir(gd)):
                if os.path.isdir(os.path.join(gd, lb)):
                    out[lb] = os.path.join(gd, lb)
    return out


# ── the script ─────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plan", required=True,
                    help="the plan: `torana remediation-plan <ID> get --format json` (plan id, fingerprint and the "
                         "planner group come from it), or remediation_plan.py --json output")
    ap.add_argument("--group", type=int, default=0)
    ap.add_argument("--report", required=True, help="the apply report (--commit / --apply --json) of that group")
    ap.add_argument("--plan-id", default=None, help="default: the plan record's id")
    ap.add_argument("--fingerprint", default=None, help="default: the plan record's effective_fingerprint")
    ap.add_argument("--tree", action="append", default=[], metavar="LABEL=PATH",
                    help="a read-only source tree (default: the applied copies next to --report)")
    ap.add_argument("--api-diff-file", default=None, help="the planner's --api-diffs-out documents")
    ap.add_argument("--case", default=None, help="where the case dir goes (default: next to --out)")
    ap.add_argument("--out", required=True, help="vet.json to write")
    ap.add_argument("--loop", type=int, default=0)
    ap.add_argument("--model", default=None)
    ap.add_argument("--budget", type=float, default=BUDGET_USD, help=argparse.SUPPRESS)
    ap.add_argument("--quiet", action="store_true",
                    help="print the verdict and cost only, never the reason (EM D-23 S3: a CI log can be public)")
    ap.add_argument("--clean-env", dest="clean_env", action="store_true",
                    help="run the reviewer with only PATH, the key, proxy/CA variables and an empty HOME (CI)")
    a = ap.parse_args(argv)
    if not 0 <= a.loop <= MAX_LOOPS:
        print(f"ERROR: --loop must be 0..{MAX_LOOPS} (decision 1: at most two re-plans)", file=sys.stderr)
        return 2
    if a.budget > BUDGET_USD:
        print(f"ERROR: the cap is ${BUDGET_USD:.2f} (decision 4)", file=sys.stderr)
        return 2
    with open(a.plan, encoding="utf-8") as fh:
        plan = json.load(fh)
    plan_id = a.plan_id or plan.get("id")
    fingerprint = a.fingerprint or plan.get("effective_fingerprint")
    if not plan_id or not fingerprint:
        print("ERROR: pass the plan RECORD (remediation-plan get --format json), or --plan-id and --fingerprint",
              file=sys.stderr)
        return 2
    if isinstance(plan.get("planner_group"), dict):
        plan = plan["planner_group"]
    trees = dict(t.split("=", 1) for t in a.tree) or default_trees(a.report)
    with open(a.report, encoding="utf-8") as fh:
        report = json.load(fh)
    docs = []
    if a.api_diff_file:
        with open(a.api_diff_file, encoding="utf-8") as fh:
            d = json.load(fh)
        docs = d.get("api_diffs") if isinstance(d, dict) and "api_diffs" in d else (d if isinstance(d, list) else [d])
    case = a.case or os.path.join(os.path.dirname(os.path.abspath(a.out)), f"vet-case-{a.group}-loop{a.loop}")
    build_case(case, plan, a.group, report, trees, docs)
    env = None
    if a.clean_env:
        home = os.path.join(os.path.dirname(os.path.abspath(case)), f".home-{os.path.basename(case)}")
        os.makedirs(home, exist_ok=False)
        env = clean_env(dict(os.environ), home)
    res, why = run_review(case, trees, a.budget, a.model, env=env)
    vet = to_vet(res, why, plan_id, fingerprint, a.loop, a.model, trees)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(vet, fh, indent=1)
    shown = {"verdict": vet["verdict"], "unvetted_why": vet["unvetted_why"], "reason": vet["reason"],
             "alternative": vet["alternative"], "cost_usd": vet["cost_usd"], "case": case, "out": a.out}
    if a.quiet:
        # ⛔ EM D-23 S3 (em3 r1 M2c): the reason and the alternative's why are free text the model wrote, and a CI log
        # is public on a public repository. They are in vet.json, which only the posting job reads.
        shown = {k: v for k, v in shown.items() if k not in ("reason", "alternative")}
    print(json.dumps(shown, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
