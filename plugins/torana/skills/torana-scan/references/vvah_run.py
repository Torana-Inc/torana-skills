#!/usr/bin/env python3
"""
vvah_run.py — the Torana deep-tier (VVAH) runner (SC2, Option B).

The Visa Vulnerability Agentic Harness (VVAH) is a *more sophisticated* SAST engine
than semgrep/Claude-review (threat-model → taint chunks → adversarial verify →
exploit-chain). Torana's posture is "ingest, don't compete": run VVAH as an OPT-IN
deep tier and merge its native SARIF 2.1.0 into the same scan_id as the fast tier.

Why a dedicated runner and NOT a scan_pack.json engine: VVAH breaks the Scan-Pack
engine contract (one pinned binary → one `command` → SARIF at `{out}`). It is an
LLM-driven multi-stage pipeline that needs a model backend + credentials, carries
SQLite checkpoint state + per-stage budget, and writes SARIF to a computed
per-target path. Wrapping it keeps those oddities out of scan_pack.py's generic loop.
scan_pack.py calls this on `--deep`; the returned SARIF is folded into build_sarif's
`--merge-sarif vvah=<path>` set (registered `vvah→SAST` in build_sarif._NATIVE_ENGINES).

Packaging (verified against the repo 2026-07-07): VVAH is a pip package but NOT on
PyPI — install from source (`git clone <pin> && pip install .`) into the Scan Pack's
isolated venv (scan_pack/venv), the same venv semgrep lives in. It is an ENGINE, not
a Claude skill; it calls a model directly via one of three backends.

  - Backend `cli` (DEFAULT): reuses the `claude` CLI login — NO API key. Needs the
    `claude` CLI installed AND logged in (or CLAUDE_CODE_OAUTH_TOKEN in the env).
  - Backend `sdk`: needs ANTHROPIC_SDK_API_KEY (for headless CI).
  - Backend `openai`: needs OPENAI_API_KEY.

SAFETY INVARIANT (hard): a plain `vvaharness scan` runs all 11 stages including S10
*fix mode*, which EDITS SOURCE FILES in the target repo. Torana-scan must never
modify the target, so this runner ALWAYS passes `--stop-after s9` (detection only).
That flag is not optional and cannot be overridden.

CLI surface — VERIFIED against vvaharness 1.1.0 (commit d91b28d, 2026-07-07):
  - Scan (detection only): `vvaharness scan --repo <p> --stop-after s9`
    [--config <yaml>] [--application-id <id>] [--repo-name <tag>].
  - Backend/profile = a `--config <yaml>` file (NOT `--profile`). No `--config` →
    the packaged default profile = `cli` backend (Claude Code login, no key). Use
    `--config sdk.yaml` for the SDK backend.
  - `--application-id` is OPTIONAL (drives CMDB scoring + SARIF applicationId).
  - `estimate --repo <p>` prints a TOKEN/scope preview (code files, bytes, ~input
    tokens) — NOT a dollar figure. Dollar budgets are enforced by VVAH per-stage via
    the config's `step*.max_budget_usd`; this runner shows the estimate and offers a
    cheap `--max-input-tokens` pre-gate, and passes dollar caps through via `--config`.
  - SARIF at `<repo>/security-scan/<module>_<ts>_report.sarif`.
Run with `--dry-run` to inspect the exact command before a live run.

Stdlib-only, crash-proof, skip-with-message — matches scan_pack.py / build_sarif.py.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
# VVAH is a Python package → it installs into the isolated venv (like semgrep),
# NOT scan_pack/bin. Prefer that venv's console script over PATH.
_VENV_BIN = os.path.join(_HERE, "scan_pack", "venv", "bin")
# Detection-only stage boundary — see SAFETY INVARIANT above. Never remove.
_DETECTION_STOP = "s9"


def _resolve_vvaharness() -> Optional[str]:
    """Resolve the `vvaharness` console script: isolated venv → PATH. None → skip."""
    cand = os.path.join(_VENV_BIN, "vvaharness")
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return shutil.which("vvaharness")


def _packaged_profile(vvah: Optional[str], name: str) -> Optional[str]:
    """Absolute path to a VVAH packaged config profile (e.g. sdk.yaml) inside the venv,
    so the handoff command can point `--config` at it without the user copying files."""
    if not vvah:
        return None
    venv = os.path.dirname(os.path.dirname(vvah))  # <venv>/bin/vvaharness → <venv>
    hits = glob.glob(os.path.join(
        venv, "lib", "python*", "site-packages", "vvaharness", "config", "profiles", name))
    return hits[0] if hits else None


def _run(cmd: List[str], *, timeout: Optional[int], env: Dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


def _scan_cmd(vvah: str, repo: str, application_id: Optional[str],
              config: Optional[str], repo_name: Optional[str], extra: List[str]) -> List[str]:
    """Build the detection-only scan command. `--stop-after s9` is a HARD invariant
    (no S10 fix mode → never edits the target's source). Single source of truth so
    the dry-run preview and the live run can never diverge."""
    cmd = [vvah, "scan", "--repo", repo, "--stop-after", _DETECTION_STOP]
    if application_id:
        cmd += ["--application-id", application_id]
    if repo_name:
        cmd += ["--repo-name", repo_name]
    if config:
        cmd += ["--config", config]     # backend/profile + per-stage max_budget_usd caps
    return cmd + list(extra)


def _parse_est_tokens(text: str) -> Optional[int]:
    """Pull the '~input tokens : N' figure out of `vvaharness estimate` output
    (verified format, v1.1.0). estimate is TOKEN-based, not dollar-based — the real
    dollar cap is VVAH's per-stage `max_budget_usd` in the config. On no match →
    None (skip the cheap pre-gate; the config cap still applies during the run)."""
    if not text:
        return None
    m = re.search(r"input tokens\s*:\s*([\d,]+)", text, re.IGNORECASE)
    try:
        return int(m.group(1).replace(",", "")) if m else None
    except (ValueError, AttributeError):
        return None


def _build_env(backend: str, oauth_token: Optional[str]) -> Dict[str, str]:
    """Env for the child. The backend is selected by a profile YAML (see --profile);
    here we only make sure the matching credential is present/passed through."""
    env = dict(os.environ)
    if oauth_token and backend == "cli":
        env["CLAUDE_CODE_OAUTH_TOKEN"] = oauth_token
    return env


def _inside_claude_code(env: Dict[str, str]) -> bool:
    """True when this process is itself running inside a Claude Code session — so a
    `cli`-backend VVAH run would spawn `claude` INSIDE `claude` (nested)."""
    return env.get("CLAUDECODE") == "1" or bool(env.get("CLAUDE_CODE_SESSION_ID"))


def _backend_precheck(backend: str, env: Dict[str, str], vvah: str, allow_nested_cli: bool = False) -> Optional[str]:
    """Return a skip-reason string if the backend can't run reliably here, else None.

    HARD GUARD (learned the hard way): the `cli` backend shells out to `claude -p`.
    When we are already inside a Claude Code session (the skill's normal context),
    that nests `claude` inside `claude`, and the skill launches us via a Bash tool
    with stdin=/dev/null — so the nested `claude -p` gets EOF ("Input must be provided
    … when using --print") and WEDGES at stage 1. We refuse up front instead of
    hanging. The reliable paths are the `sdk` backend (an API key, no nested CLI) or
    running VVAH in a separate, non-nested terminal."""
    if backend == "cli":
        if _inside_claude_code(env) and not allow_nested_cli:
            return ("backend 'cli' can't run reliably from inside Claude Code — it would "
                    "nest `claude` inside `claude` and hang at stage 1 (nested CLI + "
                    "stdin=/dev/null). Use the 'sdk' backend (--deep-backend sdk with "
                    "ANTHROPIC_SDK_API_KEY), or run `vvaharness scan … --stop-after s9` "
                    "in a separate terminal and ingest the SARIF. Override with "
                    "--allow-nested-cli only if you know your setup handles it.")
        if "CLAUDE_CODE_OAUTH_TOKEN" not in env and not shutil.which("claude"):
            return ("backend 'cli' needs the `claude` CLI installed + logged in, or "
                    "CLAUDE_CODE_OAUTH_TOKEN in the env (neither found)")
    elif backend == "sdk" and not env.get("ANTHROPIC_SDK_API_KEY"):
        return "backend 'sdk' needs ANTHROPIC_SDK_API_KEY in the env"
    elif backend == "openai" and not env.get("OPENAI_API_KEY"):
        return "backend 'openai' needs OPENAI_API_KEY in the env"
    return None


def _discover_sarif(repo: str, since_mtime: float) -> Optional[str]:
    """Find the newest `<repo>/security-scan/*_report.sarif` written by this run.
    VVAH writes SARIF under the target (not our --out), possibly one per module —
    we take the most-recently-modified report produced at/after the run started."""
    pattern = os.path.join(repo, "security-scan", "*_report.sarif")
    reports = [p for p in glob.glob(pattern) if os.path.getmtime(p) >= since_mtime - 1]
    if not reports:
        # Fall back to any report (an older run may share the dir) — newest wins.
        reports = glob.glob(pattern)
    if not reports:
        return None
    return max(reports, key=os.path.getmtime)


def _count_results(sarif_path: str) -> Optional[int]:
    try:
        doc = json.load(open(sarif_path, encoding="utf-8"))
        return sum(len(r.get("results") or []) for r in (doc.get("runs") or []))
    except Exception:
        return None


def run_vvah(
    repo: str,
    *,
    out: Optional[str],
    backend: str,
    config: Optional[str],
    repo_name: Optional[str],
    application_id: Optional[str],
    max_input_tokens: Optional[int],
    extra: List[str],
    timeout: int,
    estimate_only: bool,
    dry_run: bool,
    allow_nested_cli: bool = False,
    print_command: bool = False,
) -> Dict[str, Any]:
    """Run VVAH detection-only and return a status dict. Never raises."""
    status: Dict[str, Any] = {"engine": "vvah", "status": "skipped", "sarif": None,
                              "results": None, "est_tokens": None, "reason": None}

    vvah = _resolve_vvaharness()
    # Actionable skip reason — the skill self-provisions VVAH (never asks the user to
    # install it), exactly like the fast-tier engines.
    _install_hint = "run `install_engines.sh --engines vvah` to provision it (source install)"

    # --print-command: HANDOFF. The skill NEVER runs VVAH itself (cli nests+hangs; sdk
    # would need a key we must not take in chat). Instead we emit the exact command for
    # the USER to run in their own terminal, with backend-appropriate auth setup they do
    # THERE (never in chat), plus how to ingest the resulting SARIF. No LLM spend here.
    if print_command:
        # For sdk, point --config at VVAH's packaged sdk.yaml (via: sdk) unless one was given.
        cfg = config
        if backend == "sdk" and not cfg:
            cfg = _packaged_profile(vvah, "sdk.yaml")
        scan_cmd = _scan_cmd(vvah or "vvaharness", repo, application_id, cfg, repo_name, extra)
        sarif_glob = os.path.join(repo, "security-scan", "*_report.sarif")
        if backend == "sdk":
            auth = ("AUTH (do this IN YOUR TERMINAL — never paste a key into this chat):\n"
                    "    export ANTHROPIC_SDK_API_KEY='sk-ant-…'   # or put it in a .env file\n"
                    "    (VVAH auto-loads a .env from the repo or a parent dir.)")
        else:
            auth = ("AUTH (in your terminal): be logged into Claude Code —\n"
                    "    claude        # then run /login once, if you aren't already\n"
                    "    (uses your Claude subscription; no API key needed.)")
        status["status"] = "handoff"
        status["cmd"] = " ".join(scan_cmd)
        status["backend"] = backend
        status["sarif_glob"] = sarif_glob
        status["reason"] = f"run in a separate terminal ({backend} backend), then ingest the SARIF"
        print("Run the VVAH deep pass YOURSELF in a SEPARATE, plain terminal (Terminal.app —\n"
              "NOT inside a claude session; nesting would hang it). The skill does not run it.\n\n"
              f"{auth}\n\n"
              "COMMAND (uses the skill's installed VVAH — nothing else to install):\n"
              f"    {' '.join(scan_cmd)}\n\n"
              f"OUTPUT lands at:\n    {sarif_glob}\n\n"
              "When it finishes, come back and give me that file — I'll ingest it with:\n"
              f"    scan_pack.py --repo {repo} --deep-sarif <that-report>.sarif  [--scan-types SAST]",
              file=sys.stderr)
        return status

    # --dry-run is for inspecting the exact invocation — honor it even when VVAH is
    # not installed (that's often precisely when you want to review the command).
    if dry_run:
        scan_cmd = _scan_cmd(vvah or "vvaharness", repo, application_id, config, repo_name, extra)
        status["status"] = "dry-run"
        status["reason"] = "dry-run" + ("" if vvah else " (vvaharness not installed)")
        status["cmd"] = " ".join(scan_cmd)
        print("DRY RUN — would execute (detection-only, --stop-after s9):\n  "
              + " ".join(scan_cmd), file=sys.stderr)
        return status

    if not vvah:
        status["reason"] = f"vvaharness not installed — {_install_hint} (fast tier still runs)"
        return status

    env = _build_env(backend, os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))

    # ── scope preview — `estimate` spends nothing (prints token scope, not dollars).
    # The authoritative DOLLAR cap is VVAH's per-stage max_budget_usd in --config;
    # here we surface the scope and offer a cheap --max-input-tokens pre-gate. ──────
    est_tokens = None
    try:
        est = _run([vvah, "estimate", "--repo", repo], timeout=300, env=env)
        est_tokens = _parse_est_tokens((est.stdout or "") + (est.stderr or ""))
        status["est_tokens"] = est_tokens
        if est.stdout:
            print(est.stdout.strip(), file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — estimate must never crash the run
        print(f"NOTE: `vvaharness estimate` failed ({type(exc).__name__}); "
              f"relying on the config's per-stage max_budget_usd cap", file=sys.stderr)
    if max_input_tokens is not None and est_tokens is not None and est_tokens > max_input_tokens:
        status["reason"] = (f"estimated ~{est_tokens} input tokens exceeds --max-input-tokens "
                            f"{max_input_tokens} — deep tier skipped (raise the cap, or set a "
                            f"dollar cap in --config, to run)")
        return status
    if estimate_only:
        status["status"] = "estimated"
        status["reason"] = (f"estimate-only (~{est_tokens} input tokens)"
                            if est_tokens is not None else "estimate-only")
        return status

    # A real scan needs a working, non-hanging backend — estimate/estimate-only above did not.
    pre = _backend_precheck(backend, env, vvah, allow_nested_cli=allow_nested_cli)
    if pre:
        status["reason"] = pre
        return status

    # ── detection-only scan — --stop-after s9 is a HARD invariant (no S10 fix mode) ─
    scan_cmd = _scan_cmd(vvah, repo, application_id, config, repo_name, extra)
    started = _now_mtime(repo)
    try:
        proc = _run(scan_cmd, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        status["status"] = "failed"
        status["reason"] = f"timeout ({timeout}s)"
        return status
    except Exception as exc:  # noqa: BLE001
        status["status"] = "failed"
        status["reason"] = f"{type(exc).__name__}: {exc}"
        return status

    sarif = _discover_sarif(repo, started)
    if not sarif:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] if proc else []
        status["status"] = "failed"
        status["reason"] = "no SARIF produced under <repo>/security-scan/" + (
            f": {tail[0][:160]}" if tail else f" (exit {proc.returncode})")
        return status

    # Optionally copy the report out of the target tree to a caller-chosen path.
    if out:
        try:
            shutil.copyfile(sarif, out)
            sarif = out
        except OSError as exc:
            print(f"NOTE: could not copy SARIF to {out} ({exc}); using in-repo path", file=sys.stderr)

    status["status"] = "ran"
    status["sarif"] = sarif
    status["results"] = _count_results(sarif)
    return status


def _now_mtime(repo: str) -> float:
    """A monotonic-ish 'start' marker for SARIF discovery. Date.now() is unavailable
    in some sandboxes; use the repo dir's current mtime as a stable baseline."""
    try:
        return os.path.getmtime(repo)
    except OSError:
        return 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description="Torana deep-tier runner — VVAH agentic SAST (SC2, Option B).")
    ap.add_argument("--repo", default=".", help="Repo path to scan. Default: cwd.")
    ap.add_argument("--out", help="Copy the produced SARIF to this path (default: leave in <repo>/security-scan/).")
    ap.add_argument("--backend", default="cli", choices=["cli", "sdk", "openai"],
                    help="LLM backend. Default 'cli' (Claude Code login, no API key). "
                         "'sdk' needs ANTHROPIC_SDK_API_KEY; 'openai' needs OPENAI_API_KEY.")
    ap.add_argument("--config", help="VVAH config YAML → selects backend (via:) + per-stage "
                                     "max_budget_usd caps. Omit for the packaged default (cli backend, no key).")
    ap.add_argument("--repo-name", dest="repo_name",
                    help="Module tag for the SARIF run.properties / report filename (default: dir name).")
    ap.add_argument("--application-id", dest="application_id",
                    help="VVAH application id (maps to the Torana asset; drives CMDB scoring + SARIF applicationId).")
    ap.add_argument("--max-input-tokens", dest="max_input_tokens", type=int,
                    help="Cheap pre-gate: skip if `vvaharness estimate` reports more ~input tokens "
                         "than this. The authoritative DOLLAR cap is the config's per-stage max_budget_usd.")
    ap.add_argument("--timeout", type=int, default=3600, help="Scan timeout in seconds (deep tier is slow).")
    ap.add_argument("--estimate-only", action="store_true", help="Run `estimate` and stop (spends nothing).")
    ap.add_argument("--allow-nested-cli", dest="allow_nested_cli", action="store_true",
                    help="Override the guard that blocks the 'cli' backend inside a Claude Code session "
                         "(nested `claude` + stdin=/dev/null → hang). Only if you know your setup handles it.")
    ap.add_argument("--dry-run", action="store_true", help="Print the exact command without running VVAH.")
    ap.add_argument("--print-command", dest="print_command", action="store_true",
                    help="Handoff for the 'run outside the skill' path: print the exact `vvaharness scan` "
                         "command to run in a separate terminal + how to ingest the SARIF. No LLM spend.")
    ap.add_argument("--json", action="store_true", help="Emit the status dict as JSON.")
    ap.add_argument("--extra", nargs=argparse.REMAINDER, default=[],
                    help="Verbatim extra args appended to `vvaharness scan` (everything after --extra).")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"ERROR: repo path not found: {repo}", file=sys.stderr)
        return 2

    st = run_vvah(
        repo,
        out=args.out, backend=args.backend, config=args.config, repo_name=args.repo_name,
        application_id=args.application_id, max_input_tokens=args.max_input_tokens,
        extra=args.extra, timeout=args.timeout,
        estimate_only=args.estimate_only, dry_run=args.dry_run,
        allow_nested_cli=args.allow_nested_cli, print_command=args.print_command,
    )

    if args.json:
        print(json.dumps(st, indent=2))
    else:
        icon = {"ran": "✓", "estimated": "≈", "dry-run": "·", "handoff": "→",
                "skipped": "–", "failed": "✗"}.get(st["status"], "?")
        detail = st.get("reason") or (f"{st.get('results', 0)} finding(s) → {st['sarif']}"
                                      if st["status"] == "ran" else "")
        print(f"  {icon} vvah (deep)   {st['status']} — {detail}")

    # Exit 0 for ran/estimated/dry-run/skipped (skip is not an error — fast tier stands);
    # nonzero only on a hard failure so a caller can distinguish.
    return 1 if st["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
