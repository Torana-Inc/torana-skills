"""D-06 rule R1 (decision 2: a crisp review catch becomes code): does the IMAGE read the lock a fix edits?

⛔ WHAT IT PREVENTS. A1 (spec § 2.1) and § 11 pick 6: a lock-only fix edits `uv.lock`, but the service's Dockerfile
installs from `pyproject.toml` (`uv-pip-install … -e .`) and never reads the lock, so the PR merges and the version
that ships does not move. Twice an AI review caught it; the code said `provenance: unknown` and planned anyway.

⭐ CONSERVATIVE BY CONSTRUCTION. `not_used` only when ALL of these hold, else `unknown` (never a decline):
  - the lock's tree has at least one Dockerfile at its root, and every one is read;
  - no RUN reads the lock: names it, mounts it, or runs a tool that reads it implicitly (`uv sync`, `--frozen`,
    `--locked`, `npm ci`, `npm install`, `yarn`, `pnpm install`, `poetry install`, `pipenv`, `pip-sync`, `pdm install`);
  - no RUN runs something whose behaviour is not visible here (`make`, a shell script, a `$VAR` install argument);
  - at least one RUN installs FROM THE MANIFEST: `pip install`/`uv pip install`/`uv-pip-install` of `.` or `-e .`.
A COPY of the lock is NOT a read: a service's `Dockerfile.dev` copies `uv.lock` "for reference/tooling
only" and installs `-e .`, and the lock decides nothing that ships.

Pure over file text; reads only the tree's root.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Dict, List, Optional, Tuple

USED, NOT_USED, UNKNOWN = "used", "not_used", "unknown"

_DOCKERFILE = re.compile(r"^(Dockerfile(\..+)?|.+\.Dockerfile)$")
#: Tools that read a lock in the working directory without naming it.
_IMPLICIT_READERS = re.compile(
    r"\buv\s+sync\b|\buv\s+export\b|--frozen\b|--locked\b|\bnpm\s+(ci|install|i)\b|\byarn\b|\bpnpm\s+(install|i)\b"
    r"|\bpoetry\s+install\b|\bpipenv\b|\bpip-sync\b|\bpdm\s+(install|sync)\b")
_SEGMENT = re.compile(r"&&|\|\||;|\|")
_KEYWORDS = {"if", "then", "else", "elif", "do", "fi", "done", "!"}


def _opaque(cmd: str) -> Optional[str]:
    """The first command segment that RUNS something this parser cannot see into: `make`, a shell script, or
    `bash`/`sh` with a file. A script named only as an argument (`chmod +x x.sh`) is not run."""
    for seg in _SEGMENT.split(cmd):
        words = [w for w in seg.strip().split() if w]
        while words and (words[0] in _KEYWORDS or words[0].startswith("[") or "=" in words[0]):
            if words[0].startswith("["):
                while words and not words[0].endswith("]"):
                    words.pop(0)
            words.pop(0) if words else None
        if not words:
            continue
        w = words[0]
        if w == "make" or (w in ("bash", "sh") and len(words) > 1 and not words[1].startswith("-c")) \
                or w.endswith(".sh"):
            return seg.strip()
    return None
_INSTALLERS = ("pip install", "pip3 install", "uv pip install", "uv-pip-install")


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """(first line number, instruction) with `\\` continuations joined and comments dropped."""
    out: List[Tuple[int, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if buf and line.startswith("#"):
            continue
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        out.append((start, buf))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def _installs_from_manifest(cmd: str) -> bool:
    for seg in re.split(r"&&|;|\|\|", cmd):
        s = seg.strip()
        if not any(t in s for t in _INSTALLERS):
            continue
        try:
            words = shlex.split(s)
        except ValueError:
            continue
        if "." in words or "./" in words:
            return True
    return False


def dockerfile_verdict(text: str, lock_name: str) -> Tuple[str, str]:
    """One Dockerfile: (used | not_used | unknown, why with the line)."""
    installs: Optional[int] = None
    for n, ins in _logical_lines(text):
        op, _, rest = ins.partition(" ")
        if op.upper() != "RUN":
            continue
        if lock_name in rest:
            return USED, f"line {n} reads {lock_name}"
        if _IMPLICIT_READERS.search(rest):
            return USED, f"line {n} runs a tool that reads the lock ({_IMPLICIT_READERS.search(rest).group(0).strip()})"
        if _opaque(rest):
            return UNKNOWN, f"line {n} runs something this check cannot see into ({_opaque(rest)[:80]})"
        if re.search(r"-r\s+\$|\binstall\b[^;&]*\$\{?\w", rest):
            return UNKNOWN, f"line {n} installs from a variable ({rest[:80]})"
        if installs is None and _installs_from_manifest(rest):
            installs = n
    if installs is None:
        return UNKNOWN, "no RUN installs from the manifest (`-e .` / `.`)"
    return NOT_USED, f"line {installs} installs from the manifest and no RUN reads {lock_name}"


def lock_shipped(tree: str, lock_rel: str) -> Dict[str, object]:
    """`{state, why, evidence: [file:line words]}` for the lock at `lock_rel` inside `tree` (the tree's root holds
    the Dockerfiles). `not_used` only when every root Dockerfile says so."""
    lock_name = os.path.basename(lock_rel)
    if os.path.dirname(lock_rel) not in ("", "."):
        return {"state": UNKNOWN, "why": f"{lock_rel} is not at the tree's root", "evidence": []}
    try:
        names = sorted(n for n in os.listdir(tree) if _DOCKERFILE.match(n) and os.path.isfile(os.path.join(tree, n)))
    except OSError:
        return {"state": UNKNOWN, "why": "the tree could not be listed", "evidence": []}
    if not names:
        return {"state": UNKNOWN, "why": "no Dockerfile at the tree's root", "evidence": []}
    ev, verdicts = [], []
    for n in names:
        try:
            with open(os.path.join(tree, n), encoding="utf-8", errors="replace") as fh:
                state, why = dockerfile_verdict(fh.read(), lock_name)
        except OSError:
            state, why = UNKNOWN, "unreadable"
        verdicts.append(state)
        ev.append(f"{n}: {why}")
    if USED in verdicts:
        return {"state": USED, "why": "a Dockerfile reads the lock", "evidence": ev}
    if UNKNOWN in verdicts:
        return {"state": UNKNOWN, "why": "a Dockerfile could not be judged", "evidence": ev}
    return {"state": NOT_USED, "why": f"every Dockerfile ({', '.join(names)}) installs from the manifest and none "
                                      f"reads {lock_name}", "evidence": ev}
