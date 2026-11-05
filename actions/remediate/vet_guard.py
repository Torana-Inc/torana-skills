#!/usr/bin/env python3
"""EM D-23 S3: the deterministic guards around the remediate Action's AI review (jobs 1, 2 and 3).

pantheon-deploy `docs/em/D23_AFTER_THE_FIX_PR_OPENS.md` § 3.7 and the S3 plan § 1. Stdlib only, no CLI: the review
job (2) imports it with nothing else installed.

- `find_secret` / `withhold`: every string in a vet against credential shapes and the exact values of this step's
  secrets; a hit REPLACES the vet with `unvetted` (the fix then opens as a draft; the run never fails on it).
  The same table as detection-framework's `remediation_vet.SECRET_PATTERNS` (DF refuses 422 `secret_in_text`).
  ⛔ It cannot see an ENCODED secret. What bounds that is where a CI review's text goes: Torana only, never the PR
  body (DF) or the job log (`vet_case.py --quiet`), and for a public repository not even the artifact (`public_reason`).
- `deny_scan`: before job 1 uploads a case, refuse it if the run WROTE a credential-named file or credential-shaped text
  into it (em3 r1 M2, build check M-A), or if it holds a symlink.
- `safe_extract`: job 2 and job 3 unpack a case with only regular files and directories, and job 2 refuses any
  Claude / MCP config at any depth (em3 r1 B1: a planted `.claude/settings.json` hook would run shell next to the key).
- `trim_evidence`: job 3 drops evidence whose file is not in the case's tree or whose line is past its end, so the
  PR shows only real locations (em3 r1 M3).
- `check_review_host`: job 2 refuses to start unless the host is the one the caller declared (`untrusted-runner`:
  GitHub-hosted, or our isolated runner with its baked marker), not as root, without OIDC, and with this runner's own
  credential in the filter (delta d2 § 3.4; `runner_facts`).
"""
from __future__ import annotations

import base64
import copy
import fnmatch
import json
import os
import re
import stat
import tarfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: detection-framework `remediation_vet.SECRET_PATTERNS`, the same five (a test pins the two tables equal).
SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"github_pat_")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY")),
)
#: A step's env var whose VALUE is never allowed in a vet: its name says it is a credential.
SECRET_ENV_NAME = re.compile(r"TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL", re.I)
SECRET_ENV_MIN_LEN = 16
WITHHELD_SECRET = "withheld: the review's text matched a secret pattern; the verdict was not kept"
#: Bhakta's decision b + the lead's call on em3 r2 M2': a public repository's artifacts are public for a day.
PUBLIC_REASON = "withheld: public repository; the verdict and evidence are recorded"
#: File names job 1 must never CREATE or CHANGE in a case (deny_scan), matched on the base name. ⚠️ Narrow on purpose
#: (em3 build check M-A): `.env.example` and `id_utils.py` are ordinary committed files.
DENY_NAMES = (".env", ".env.*", "*.pem", "*.key", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc",
              ".netrc", ".git-credentials", "*.p12", "*.pfx")
#: `.env.<x>` templates that hold no secret by convention.
ENV_TEMPLATES = (".example", ".sample", ".template", ".dist")
#: Claude / MCP configuration a review case must never carry, at ANY depth (B1).
CLAUDE_CONFIG = (".claude", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md", ".claude.json")
#: What job 2 copies out of a case (B1: an allow-list, never "everything but").
REVIEW_TOP = ("case.json", "plan_group.json", "report.json", "api_diffs.json", "gates.json", "changes.diff")
REVIEW_DIRS = ("trees",)
MAX_SCAN_BYTES = 2 * 1024 * 1024


class GuardError(Exception):
    """A case or a vet that must not be used. The message names a path and a rule, never the content."""


# ── secrets ─────────────────────────────────────────────────────────────────────

def secret_values(env: Dict[str, str]) -> List[str]:
    """The values of this step's credential-named env vars (≥ 16 characters), longest first."""
    vals = {v for k, v in env.items() if SECRET_ENV_NAME.search(k) and v and len(v) >= SECRET_ENV_MIN_LEN}
    return sorted(vals, key=len, reverse=True)


#: Where a runner keeps its own files when no live runner process names its root (delta d2 § 3.4 step 4). The hosted
#: image: `/home/runner/actions-runner/cached/<ver>/.credentials` (L0 census 2026-11-05). The official
#: `ghcr.io/actions/actions-runner` image, which our isolated runner is built from: `/home/runner/.credentials*`
#: (em3 d1 M2). ⛔ Module constants, never env vars: a variable in the job's env must not be able to move the filter
#: (tests monkeypatch these).
RUNNER_HOME = "/home/runner"
RUNNER_DIRS = ("/home/runner/actions-runner", "/home/runner/runners", "~/actions-runner")
PROC_ROOT = "/proc"
RUNNER_BINARIES = ("Runner.Listener", "Runner.Worker")
#: ⛔ `.credentials*` ONLY (#10 MAJOR, em3): `.runner` holds the runner's name, URLs and work folder, which a normal
#: review quotes, and a match there withheld good reviews. It is read for `ephemeral` alone.
RUNNER_FILES = (".credentials*",)
RUNNER_SCAN_DEPTH = 4
#: The runner reads any option from `ACTIONS_RUNNER_INPUT_<NAME>`; our isolated runner's entrypoint passes the JIT
#: config that way (never argv, which every host user can read in /proc). em3 d2 m1's fallback reads it back.
JIT_ENV = "ACTIONS_RUNNER_INPUT_JITCONFIG"
#: Baked into the isolated runner's image, root-owned, read-only (delta d2 § 3.4).
ISO_MARKER = "/etc/torana-iso-runner"
ISO_POOL = "review"
PTRACE_SCOPE = "/proc/sys/kernel/yama/ptrace_scope"
ROOT_UID = 0
UNTRUSTED_RUNNERS = ("github-hosted", "isolated")
CREDENTIAL_ENVS = (("ANTHROPIC_API_KEY", "api key"), ("CLAUDE_CODE_OAUTH_TOKEN", "subscription token"))


def _strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


#: Base64 / base64url-shaped: key material looks like this, and may begin with "/" (em3 build check m1).
_B64ISH = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def _secret_like(v: str) -> bool:
    """A credential value worth an exact match (#10 MAJOR): 16+ characters, and not a path, a URL or prose. A
    base64-shaped value is ALWAYS kept, even one starting with "/" (em3 build check m1: an RSA parameter can); the
    path/URL/whitespace rule applies only to the rest, which is what a normal review quotes."""
    if len(v) < SECRET_ENV_MIN_LEN:
        return False
    if _B64ISH.fullmatch(v):
        return True
    return not v.startswith("/") and "://" not in v and not re.search(r"\s", v)


def credential_values(text: str) -> List[str]:
    """The secret-like strings of one credential file's text (JSON values and keys, else whitespace-split words)."""
    try:
        found = list(_strings(json.loads(text)))
    except ValueError:
        found = re.split(r"\s+", text)
    return [v for v in found if _secret_like(v)]


@dataclass
class RunnerFacts:
    """What job 2 learned about its own runner before the reviewer starts. Values are never logged."""
    roots: List[str] = field(default_factory=list)
    values: List[str] = field(default_factory=list)
    credentials: bool = False           # a `.credentials` (file or JIT entry) was read: the filter is armed
    ephemeral: Optional[bool] = None    # from `.runner`, or True for a JIT runner
    jit: bool = False


def _read(path: str, limit: int = 1 << 20) -> Optional[bytes]:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def runner_processes(proc: Optional[str] = None) -> List[Tuple[str, str]]:
    """(pid dir, runner root) of every live Runner.Listener / Runner.Worker this uid can see: the binary's path from
    `exe` (same uid) or else `cmdline` (any uid), root = the parent of its `bin/`. em3 d2 (1): both readable without
    ptrace attach."""
    proc = proc or PROC_ROOT
    out = []
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
    except OSError:
        return out
    for pid in sorted(pids, key=int):
        d = os.path.join(proc, pid)
        try:
            path = os.readlink(os.path.join(d, "exe"))
        except OSError:
            raw = _read(os.path.join(d, "cmdline"), 4096) or b""
            path = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
        if os.path.basename(path) in RUNNER_BINARIES:
            out.append((d, os.path.dirname(os.path.dirname(path))))
    return out


def _jit_config(proc_dir: str) -> Optional[str]:
    """The encoded JIT config a Listener was started with: `ACTIONS_RUNNER_INPUT_JITCONFIG` in its environ, or
    `--jitconfig X` in its cmdline. None if neither (or unreadable)."""
    env = _read(os.path.join(proc_dir, "environ")) or b""
    for item in env.split(b"\0"):
        if item.startswith(JIT_ENV.encode() + b"="):
            return item.split(b"=", 1)[1].decode("ascii", "replace")
    args = (_read(os.path.join(proc_dir, "cmdline")) or b"").split(b"\0")
    for i, a in enumerate(args[:-1]):
        if a == b"--jitconfig":
            return args[i + 1].decode("ascii", "replace")
    return None


def _b64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def _ephemeral(text: bytes) -> Optional[bool]:
    try:
        doc = json.loads(text.decode("utf-8-sig", "replace"))
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    for k, v in doc.items():
        if str(k).lower() in ("ephemeral", "isephemeral"):
            return bool(v)
    return False


def _scan_dir(top: str, depth: int, facts: RunnerFacts) -> None:
    if not os.path.isdir(top):
        return
    base = top.rstrip(os.sep).count(os.sep)
    for d, subdirs, files in os.walk(top):
        subdirs[:] = [x for x in subdirs if x != "_work"]
        if d.count(os.sep) - base >= depth - 1:
            subdirs[:] = []
        for f in files:
            p = os.path.join(d, f)
            if f == ".runner":
                raw = _read(p)
                if raw is not None and facts.ephemeral is not True:
                    facts.ephemeral = _ephemeral(raw)
                continue
            if not any(fnmatch.fnmatch(f, pat) for pat in RUNNER_FILES):
                continue
            raw = _read(p)
            if raw is None:
                continue
            facts.values.extend(credential_values(raw.decode("utf-8", "replace")))
            if f == ".credentials":
                facts.credentials = True


def runner_facts(proc: Optional[str] = None) -> RunnerFacts:
    """This runner's own credential values (for the exact-value filter), whether one was found, and whether the runner
    is single-use. Read from: every live runner process's root (depth 1); `RUNNER_HOME` (depth 1, `_work` skipped);
    the hosted `RUNNER_DIRS` (`RUNNER_SCAN_DEPTH` deep). Fallback (em3 d2 m1, if a JIT runner keeps its files in
    memory only): the JIT config a Listener was started with, whose `.credentials*` entries are read the same way."""
    facts = RunnerFacts()
    procs = runner_processes(proc)
    for _, root in procs:
        if root and root not in facts.roots:
            facts.roots.append(root)
            _scan_dir(root, 1, facts)
    _scan_dir(RUNNER_HOME, 1, facts)
    for top in RUNNER_DIRS:
        _scan_dir(os.path.expanduser(top), RUNNER_SCAN_DEPTH, facts)
    for proc_dir, _ in procs:
        blob = _jit_config(proc_dir)
        if not blob:
            continue
        facts.jit = True
        if _secret_like(blob):
            facts.values.append(blob)
        try:
            files = json.loads(_b64(blob).decode("utf-8", "replace"))
        except (ValueError, TypeError):
            continue
        for name, content in (files.items() if isinstance(files, dict) else []):
            if not isinstance(content, str):
                continue
            if _secret_like(content):
                facts.values.append(content)
            try:
                text = _b64(content)
            except ValueError:
                continue
            if name == ".runner":
                facts.ephemeral = True          # a JIT runner is single-use, whatever its .runner says
            elif fnmatch.fnmatch(name, ".credentials*"):
                facts.values.extend(credential_values(text.decode("utf-8", "replace")))
                if name == ".credentials":
                    facts.credentials = True
        if facts.ephemeral is None:
            facts.ephemeral = True
    facts.values = sorted(set(facts.values), key=len, reverse=True)
    return facts


def runner_file_values(proc: Optional[str] = None) -> List[str]:
    """The filter's share of `runner_facts`: this runner's credential values, longest first. ⛔ Never printed or
    logged (callers report a count). ⚠️ An exact match only: an ENCODED copy is not caught."""
    return runner_facts(proc).values


def _marker_ok() -> Optional[str]:
    """None when `ISO_MARKER` is a root-owned regular file this uid cannot write, naming pool `review`; else why not."""
    try:
        st = os.lstat(ISO_MARKER)
    except OSError:
        return "no isolated-runner marker (this is not Torana's isolated runner)"
    if not stat.S_ISREG(st.st_mode):
        return "the isolated-runner marker is not a regular file"
    if st.st_uid != ROOT_UID or st.st_mode & 0o022 or os.access(ISO_MARKER, os.W_OK):
        return "the isolated-runner marker is not root-owned and read-only"
    lines = (_read(ISO_MARKER, 4096) or b"").decode("utf-8", "replace").split()
    if f"pool={ISO_POOL}" not in lines:
        return f"the isolated-runner marker does not name pool {ISO_POOL}"
    return None


def check_review_host(env: Dict[str, str], euid: Optional[int] = None,
                      proc: Optional[str] = None) -> Tuple[str, RunnerFacts]:
    """(the declared mode, this runner's facts), or GuardError naming the first rule broken (delta d2 § 3.4):
    no OIDC variable; not uid 0 (m4); the host is the one `untrusted-runner` declared: GitHub-hosted, or Torana's
    isolated runner (baked marker, self-hosted, single-use, ptrace_scope >= 1); and in isolated mode the filter
    holds this runner's own `.credentials` (M2: proof the exact-value filter is armed). A label is never trusted."""
    if env.get("ACTIONS_ID_TOKEN_REQUEST_URL") or env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        raise GuardError("the review job can request an OIDC token (id-token: write); it must not")
    if (os.geteuid() if euid is None else euid) == 0:
        raise GuardError("the review job runs as root (uid 0); it must not")
    mode = env.get("REMEDIATE_UNTRUSTED_RUNNER", "")
    if mode not in UNTRUSTED_RUNNERS:
        raise GuardError(f"untrusted-runner must be one of {', '.join(UNTRUSTED_RUNNERS)}, not {mode or 'empty'}")
    where = env.get("RUNNER_ENVIRONMENT") or "an unknown runner"
    facts = runner_facts(proc)
    if mode == "github-hosted":
        if where != "github-hosted":
            raise GuardError(f"untrusted-runner: github-hosted, but this job runs on {where}")
        return mode, facts
    if where != "self-hosted":
        raise GuardError(f"untrusted-runner: isolated, but this job runs on {where}")
    why = _marker_ok()
    if why:
        raise GuardError(why)
    raw = (_read(PTRACE_SCOPE, 16) or b"").strip()
    if not raw.isdigit() or int(raw) < 1:
        raise GuardError(f"kernel.yama.ptrace_scope is {raw.decode() or 'unreadable'}; the isolated runner needs >= 1")
    if facts.ephemeral is not True:
        raise GuardError("this runner is not single-use (no ephemeral .runner, no JIT config)")
    if not facts.credentials:
        raise GuardError("this runner's .credentials was not found, so the filter cannot hold it")
    return mode, facts


def review_credential(env: Dict[str, str]) -> str:
    """Which model credential job 2 holds ('api key' | 'subscription token'): exactly one, else GuardError."""
    held = [what for name, what in CREDENTIAL_ENVS if env.get(name)]
    if len(held) != 1:
        raise GuardError("the review needs exactly one of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN"
                         + ("" if held else ": pass one secret to the reusable workflow") + f" (got {len(held)})")
    return held[0]


def find_secret(obj: Any, values: Iterable[str] = (), path: str = "$") -> Optional[Tuple[str, str]]:
    """The first (JSON path, rule) where ANY string in `obj` (keys included) carries a credential shape or one of
    `values`, else None."""
    values = list(values)
    if isinstance(obj, str):
        for v in values:
            if v in obj:
                return path, "env_value"
        for name, rx in SECRET_PATTERNS:
            if rx.search(obj):
                return path, name
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            hit = find_secret(str(k), values, f"{path}.<key>") or find_secret(v, values, f"{path}.{k}")
            if hit:
                return hit
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            hit = find_secret(v, values, f"{path}[{i}]")
            if hit:
                return hit
    return None


def withhold(vet: Dict[str, Any], why: str = WITHHELD_SECRET) -> Dict[str, Any]:
    """The vet as `unvetted` (`error`), with every free-text field emptied: what is left is only the identity of the
    review (plan, fingerprint, model id, session, cost, time), which the posting job and DF still check."""
    out = copy.deepcopy(vet)
    out.update(verdict="unvetted", unvetted_why="error", reason=why, evidence=[], alternative=None)
    out["assumptions_checked"] = {k: "unchecked" for k in (vet.get("assumptions_checked") or {})}
    for k in ("model", "session_id"):
        if find_secret(out.get(k)):
            out[k] = "withheld"
    return out


def guard_vet(vet: Dict[str, Any], values: Iterable[str] = (), *, public: bool = False) -> Tuple[Dict[str, Any], str]:
    """(the vet to upload or post, what happened: `ok` | `withheld:<path>:<rule>` | `public_reason`)."""
    hit = find_secret(vet, values)
    if hit:
        return withhold(vet), f"withheld:{hit[0]}:{hit[1]}"
    if public and vet.get("reason"):
        out = dict(vet)
        out["reason"] = PUBLIC_REASON
        if isinstance(out.get("alternative"), dict):
            out["alternative"] = {**out["alternative"], "why": ""}
        out["evidence"] = [{k: v for k, v in e.items() if k != "quote"} for e in out.get("evidence") or []
                           if isinstance(e, dict)]
        return out, "public_reason"
    return vet, "ok"


# ── job 1: what may leave in a case ─────────────────────────────────────────────

def denied_name(name: str) -> bool:
    if name.startswith(".env.") and name.endswith(ENV_TEMPLATES):
        return False
    return any(fnmatch.fnmatch(name, pat) for pat in DENY_NAMES)


def _sig(p: str) -> Tuple[bool, bytes]:
    with open(p, "rb") as fh:
        return bool(os.lstat(p).st_mode & 0o111), fh.read()


def created_or_changed(case_dir: str) -> List[str]:
    """The case files job 1 CREATED or CHANGED, relative to `case_dir`: every file at the case's top (job 1 wrote
    them all), and every `trees/<label>/<path>` that is absent from `base/<label>/<path>` or differs in bytes or exec
    bit. A committed file the fix did not touch is not among them: its readers could already read it (em3 M-A)."""
    out: List[str] = []
    for name in sorted(os.listdir(case_dir)):
        if os.path.isfile(os.path.join(case_dir, name)) and not os.path.islink(os.path.join(case_dir, name)):
            out.append(name)
    trees = os.path.join(case_dir, "trees")
    for label in sorted(os.listdir(trees)) if os.path.isdir(trees) else []:
        troot, broot = os.path.join(trees, label), os.path.join(case_dir, "base", label)
        for d, _, files in os.walk(troot):
            for f in sorted(files):
                p = os.path.join(d, f)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                rel = os.path.relpath(p, troot)
                b = os.path.join(broot, rel)
                if not os.path.isfile(b) or os.path.islink(b) or _sig(b) != _sig(p):
                    out.append(os.path.join("trees", label, rel))
    return out


def deny_scan(root: str) -> Optional[str]:
    """None when the case at `root` may be uploaded, else '<relative path>: <rule>' for the first offence.

    - ANY symlink, hard link or special file, anywhere: refused for this plan only (an unpacking job refuses the whole
      artifact on one). The case writer already removes committed links (recorded in case.json) and copies hard
      links as plain files, so this is a backstop;
    - among what job 1 CREATED or CHANGED only (`created_or_changed`): a credential-named file, or text carrying a
      credential shape. That is where a resolver-written `.npmrc` with a token would land. Committed files the fix
      did not touch are not judged (em3 build check M-A: `.env.example`, `id_utils.py`, a committed test PEM)."""
    for d, dirs, files in os.walk(root):
        for name in sorted(dirs + files):
            p = os.path.join(d, name)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                return f"{os.path.relpath(p, root)}: a symlink"
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                return f"{os.path.relpath(p, root)}: not a regular file or directory"
            if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                # A backstop (em3 m-x): the case writer copies every file, so a case holds no hard link; a hard link
                # here would pack as a link member, which an unpacking job refuses for the whole artifact.
                return f"{os.path.relpath(p, root)}: a hard link"
    for rel in created_or_changed(root):
        p = os.path.join(root, rel)
        if denied_name(os.path.basename(rel)):
            return f"{rel}: a credential-named file written by this run"
        if os.path.getsize(p) <= MAX_SCAN_BYTES:
            with open(p, "rb") as fh:
                text = fh.read().decode("utf-8", "replace")
            for rule, rx in SECRET_PATTERNS:
                if rx.search(text):
                    return f"{rel}: text shaped like a credential ({rule}) written by this run"
    return None


def pack(src_dir: str, tar_path: str) -> None:
    """A tar of `src_dir`'s contents, member names relative, no owner names."""
    def anon(ti: tarfile.TarInfo) -> tarfile.TarInfo:
        ti.uname, ti.gname, ti.uid, ti.gid = "", "", 0, 0
        return ti
    with tarfile.open(tar_path, "w:gz") as tf:
        for name in sorted(os.listdir(src_dir)):
            tf.add(os.path.join(src_dir, name), arcname=name, filter=anon)


# ── jobs 2/3: unpacking ───────────────────────────────────────────────────────

def _member_ok(m: tarfile.TarInfo) -> bool:
    name = m.name
    return (m.isreg() or m.isdir()) and not name.startswith("/") and ".." not in name.split("/") and "\\" not in name


def safe_extract(tar_path: str, dest: str, *, review: bool = False, dropped: Optional[List[str]] = None) -> List[str]:
    """Unpack `tar_path` into `dest` (which must not exist). Only regular files and directories with relative,
    non-escaping names. With `review` (job 2): only `REVIEW_TOP` files and `REVIEW_DIRS` per plan; Claude / MCP
    configuration is REFUSED at a plan's top level (where a cwd would be) and DROPPED (named in `dropped`) at any
    other depth. Returns the plan ids found. Raises GuardError.

    ⚠️ Dropped, not refused, inside `trees/`: a customer repository often keeps a CLAUDE.md, and refusing it would
    leave every fix there unreviewed (a draft for ever). The reviewer's cwd is a directory vet_case.py builds itself,
    `claude` runs with `--strict-mcp-config`, `--setting-sources project` (the cwd only) and an empty HOME, so a tree's
    config would not be read anyway; dropping it removes even that dependency (the L0 hook plant proves it)."""
    if os.path.exists(dest):
        raise GuardError(f"{dest}: exists; a case is unpacked into a fresh directory only")
    os.makedirs(dest)
    plans = set()
    with tarfile.open(tar_path, "r:*") as tf:
        members = tf.getmembers()
        for m in members:
            if not _member_ok(m):
                raise GuardError(f"{m.name}: not a plain relative file or directory")
            parts = m.name.split("/")
            if review and any(p in CLAUDE_CONFIG for p in parts[:2]):
                raise GuardError(f"{m.name}: Claude or MCP configuration at the top of a review case")
        keep = []
        for m in members:
            parts = m.name.split("/")
            if review and len(parts) >= 2 and not (parts[1] in REVIEW_TOP and len(parts) == 2
                                                   or parts[1] in REVIEW_DIRS):
                continue
            if review and any(p in CLAUDE_CONFIG for p in parts):
                if dropped is not None:
                    dropped.append(m.name)
                continue
            if review and len(parts) == 1 and m.isreg():
                continue
            keep.append(m)
            if len(parts) >= 2 and parts[1] == "case.json":
                plans.add(parts[0])
        for m in keep:
            target = os.path.join(dest, m.name)
            if m.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(m)
            with open(target, "wb") as fh:
                fh.write(src.read() if src else b"")
            os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)
    return sorted(plans)


# ── job 3: the evidence a PR may show ───────────────────────────────────────────

def trim_evidence(vet: Dict[str, Any], case_dir: str, labels: Dict[str, str]) -> Dict[str, Any]:
    """Keep only evidence whose file exists in one of the case's trees (under its `repo` label when given) and whose
    line is within that file. em3 r1 M3: the PR shows `file:line`, so a made-up path must never reach it."""
    out = dict(vet)
    kept = []
    for e in vet.get("evidence") or []:
        if not isinstance(e, dict) or not isinstance(e.get("file"), str):
            continue
        rel = e["file"]
        if rel.startswith("/") or ".." in rel.split("/"):
            continue
        trees = [e["repo"]] if e.get("repo") in labels else list(labels)
        for lb in trees:
            p = os.path.join(case_dir, "trees", lb, rel)
            if os.path.isfile(p) and not os.path.islink(p):
                line = e.get("line")
                if line is not None:
                    with open(p, "rb") as fh:
                        n = fh.read().count(b"\n") + 1
                    if not isinstance(line, int) or line < 1 or line > n:
                        break
                kept.append(e)
                break
    out["evidence"] = kept
    return out


def load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
