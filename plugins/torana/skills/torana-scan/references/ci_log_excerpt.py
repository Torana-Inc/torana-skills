"""EM D-23 S2: one failed CI job's log, fetched and trimmed for a judgement (spec § 3.5.2, probes Q9-Q11).

ONE script for both lanes (A5). It FETCHES the failed job's log itself (review M1), so a raw log never passes
through a shell pipe or a model's context, and it fails LOUDLY (exit 2, one sentence) on a failed fetch or an
empty log, never printing an empty "excerpt" that looks like data.

    ci_log_excerpt.py --repo o/r --job 127084186161 [--client gh|direct] [--out DIR]

Clients (review M6, probe Q9):
  gh      lane A: `gh api --allow-escape-sequences repos/o/r/actions/jobs/<id>/logs`, the developer's own login.
          gh 2.102.0 sends Authorization to api.github.com only; the blob-storage redirect carries none (Q9a).
  direct  lane B: urllib with redirects OFF. Hop 1 = api.github.com with `Authorization: Bearer $GITHUB_TOKEN`
          (expects a 30x); hop 2 = a FRESH request to the `Location` (https only) WITHOUT Authorization.

The trim (review M7): a step is a `##[group]Run …` header, its `##[endgroup]`, then everything up to the next
`##[group]Run` or the end. Every step whose output holds a `##[error]` line is a failed step; the last MAX_STEPS of
them are kept, each by its LAST lines (the real failure is at the end), bounded per step and in total. ⚠️ The markers
are text the job prints, so a PR's output can forge them: the trim is a SIZE limit, not a trust boundary.

Secrets (review M8): GitHub's masking of registered secrets (`***`) is the primary control. This table is a backstop
for shapes masking misses (derived or printed values), applied to every line before anything is kept.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

MAX_STEPS = 3
MAX_LINES_PER_STEP = 120
MAX_STEP_CHARS = 4_000
MAX_LINE = 300
MAX_TOTAL = 12_000
MAX_BYTES = 10 * 1024 * 1024
TIMEOUT = 30
UA = "torana-ci-log-excerpt"

_TS = re.compile(r"^\ufeff?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
#: DF `remediation_vet.SECRET_PATTERNS` (5) first, then the log-only shapes (review M8). Each match → `[withheld]`.
SECRET_PATTERNS = (
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]*")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]*")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY[-A-Z ]*")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # 40 base64 chars with upper AND lower case: an AWS secret key's shape. A sha1 (hex, lower) never matches.
    ("aws_secret_key", re.compile(r"(?<![A-Za-z0-9/+=])(?=[A-Za-z0-9/+]*[A-Z])(?=[A-Za-z0-9/+]*[a-z])"
                                  r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*")),
)
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


class LogError(Exception):
    """A failed fetch or an empty log: exit 2 with this sentence, never an excerpt."""


# ── fetch ────────────────────────────────────────────────────────────────────────────────────────────────────────

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):   # noqa: D401 — never follow
        return None


def _tail(resp, limit: int = MAX_BYTES) -> bytes:
    buf = bytearray()
    while True:
        chunk = resp.read(65536)
        if not chunk:
            return bytes(buf)
        buf += chunk
        if len(buf) > limit:
            del buf[: len(buf) - limit]


def fetch_direct(repo: str, job: str, token: str, *, api: str = "https://api.github.com",
                 allow_http: bool = False) -> str:
    """Lane B. Hop 1 carries the token and must answer 30x (or 200, served directly); hop 2 is a fresh request to
    the Location with NO Authorization header."""
    if not token:
        raise LogError("no GITHUB_TOKEN: the collect job needs `actions: read` on its token")
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(f"{api.rstrip('/')}/repos/{repo}/actions/jobs/{job}/logs", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": UA,
        "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return _tail(r).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            raise LogError(f"GitHub answered {e.code} for job {job}'s log") from None
        loc = e.headers.get("Location") or ""
    if not (loc.startswith("https://") or (allow_http and loc.startswith("http://"))):
        raise LogError("GitHub's log redirect is not an https URL")
    try:
        with urllib.request.urlopen(urllib.request.Request(loc, headers={"User-Agent": UA}), timeout=TIMEOUT) as r:
            return _tail(r).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        raise LogError(f"the log download failed ({type(e).__name__})") from None


def fetch_gh(repo: str, job: str) -> str:
    """Lane A: the developer's own gh login. `--allow-escape-sequences` is required: without it gh refuses every
    Actions log (they all carry ANSI codes) with rc 1 and an empty stdout (review M1)."""
    try:
        p = subprocess.run(["gh", "api", "--allow-escape-sequences", f"repos/{repo}/actions/jobs/{job}/logs"],
                           capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LogError(f"gh could not be run ({type(e).__name__})") from None
    if p.returncode != 0:
        last = (p.stderr.decode("utf-8", "replace").strip().splitlines() or ["no message"])[-1][:200]
        raise LogError(f"gh failed (rc {p.returncode}): {last}")
    return p.stdout[-MAX_BYTES:].decode("utf-8", "replace")


# ── trim ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def _clean_lines(text: str, values=()) -> list:
    out, in_pem = [], False
    vals = sorted({v for v in values if len(v) >= 16}, key=len, reverse=True)
    for raw in text.splitlines():
        line = _CTRL.sub("", _ANSI.sub("", _TS.sub("", raw)))
        if in_pem:                                    # inside a PEM block: every line until its END is withheld
            in_pem = not _PEM_END.search(line)
            out.append("[withheld]")
            continue
        if _PEM_BEGIN.search(line):
            in_pem = not _PEM_END.search(line)
            out.append("[withheld]")
            continue
        for v in vals:
            line = line.replace(v, "[withheld]")
        for _, rx in SECRET_PATTERNS:
            line = rx.sub("[withheld]", line)
        out.append(line[:MAX_LINE])
    return out


def trim(text: str, values=()) -> dict:
    if not (text or "").strip():
        raise LogError("the job's log is empty: nothing to judge")
    lines = _clean_lines(text, values)
    steps, cur = [], None
    for x in lines:
        if x.startswith("##[group]Run "):
            cur = {"step": x[len("##[group]Run "):][:80], "body": [], "open": True}
            steps.append(cur)
        elif cur is not None and cur["open"]:
            if x.startswith("##[endgroup]"):
                cur["open"] = False
        elif cur is not None:
            cur["body"].append(x)
    failed = [s for s in steps if any(x.startswith("##[error]") for x in s["body"])][-MAX_STEPS:]
    if not failed:
        tail = lines[-MAX_LINES_PER_STEP:]
        return {"steps": [], "no_error_line": True, "chars": len("\n".join(tail)),
                "excerpt": "[no ##[error] line found; the job's last lines follow]\n" + "\n".join(tail)}
    blocks, used = [], 0
    budget = MAX_TOTAL // len(failed)
    out_steps = []
    for s in failed:
        body = s["body"][-MAX_LINES_PER_STEP:]
        block = "\n".join(body)[-min(MAX_STEP_CHARS, budget):]
        blocks.append(f"[step: {s['step']}]\n{block}")
        used += len(block)
        out_steps.append({"step": s["step"], "kept": len(body), "cut": max(0, len(s["body"]) - len(body))})
    return {"steps": out_steps, "no_error_line": False, "chars": used, "excerpt": "\n----\n".join(blocks)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--job", required=True)
    ap.add_argument("--client", choices=("gh", "direct"), default="gh")
    ap.add_argument("--out", default=None, help="write DIR/log_excerpt.txt instead of stdout")
    a = ap.parse_args(argv)
    try:
        text = fetch_gh(a.repo, a.job) if a.client == "gh" else fetch_direct(a.repo, a.job,
                                                                              os.environ.get("GITHUB_TOKEN", ""))
        res = trim(text)
    except LogError as e:
        print(f"ci_log_excerpt: {e}", file=sys.stderr)
        return 2
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "log_excerpt.txt"), "w", encoding="utf-8") as fh:
            fh.write(res["excerpt"] + "\n")
    else:
        print(res["excerpt"])
    print(f"ci_log_excerpt: {len(res['steps'])} failed step(s), {res['chars']} chars"
          + (" (no error line)" if res["no_error_line"] else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
