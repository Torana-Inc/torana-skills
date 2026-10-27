#!/usr/bin/env bash
# =============================================================================
# bootstrap.sh — install the bundled torana CLI. ONE implementation.
# =============================================================================
# Run it from anywhere; it is idempotent and a no-op (~0.2s) once the CLI matches
# the wheels shipped next to this script.
#
#   bash bootstrap.sh              # quiet unless it does something or fails
#   bash bootstrap.sh --verbose
#
# ⛔ WHY A SCRIPT AND NOT A BLOCK IN SKILL.md. The bootstrap used to live only as a
#    shell block inside SKILL.md. Three defects hid in it, all found on the first
#    clean plugin install (2026-09-15) and none visible on a dev box:
#
#    1. It looked for the wheel at "$SKILL_DIR/wheels" only. In the PLUGIN layout the
#       wheels sat at the plugin root, two levels up, so it found nothing, fell through
#       to a probe list of ~/.claude/skills paths that do not exist on a customer
#       machine, and died with "cannot bootstrap the torana CLI" — while the wheel it
#       needed was on disk a few directories away.
#    2. It installed ONLY the CLI wheel. `pantheon_shared` ships in every zip and in the
#       plugin, the packager HARD FAILS without it, and nothing ever installed it — so
#       the artifact-intent gate it exists for could not run.
#    3. Its build-skew check called `torana version`, a command that did not exist, so
#       the check silently never fired.
#
#    A block of prose cannot be tested. This can.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
# Whether TORANA_VENV was set by the caller, before the default below fills it in (the dev-laptop rule needs it).
TORANA_VENV_GIVEN="${TORANA_VENV:-}"
TORANA_VENV="${TORANA_VENV:-$HOME/.torana-venv}"
TORANA="$TORANA_VENV/bin/torana"
VERBOSE=0
HOOK_MODE=0
case "${1:-}" in
  --verbose) VERBOSE=1 ;;
  --hook)    HOOK_MODE=1 ;;
esac

# ── Hook mode ───────────────────────────────────────────────────────────────
# ⛔ A SessionStart hook's plain stdout goes into CLAUDE'S CONTEXT, not the user's
#    transcript — so the first version of this script installed a virtualenv, two wheels
#    and five PyPI packages on someone's machine and they SAW NOTHING. Software that
#    installs itself silently is indistinguishable from software that is up to something,
#    and the user's own session flagged it as such.
#
#    `systemMessage` is the one field that reaches the user, and it requires the hook to
#    emit JSON and nothing else. So: re-run ourselves plainly, capture everything, and
#    report it as a single JSON object. Silence stays silent — the no-op path prints
#    nothing, so nothing is shown.
#
#    Always exits 0 here: a CLI that failed to install must not stop the session from
#    starting. The message says what happened; the user decides.
if [ "$HOOK_MODE" -eq 1 ]; then
  out="$(TORANA_BOOTSTRAP_FROM_HOOK=1 bash "${BASH_SOURCE[0]}" 2>&1)"
  mkdir -p "$HOME/.torana" 2>/dev/null || true
  [ -n "$out" ] && printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$out" >> "$HOME/.torana/bootstrap.log" 2>/dev/null
  if [ -n "$out" ]; then
    printf '%s' "$out" | python3 -c 'import json,sys; print(json.dumps({"systemMessage": "Torana plugin: " + " ".join(sys.stdin.read().split())}))'
  fi
  exit 0
fi

say()  { [ "$VERBOSE" -eq 1 ] && echo "$*"; return 0; }
warn() { echo "$*" >&2; }


# ── Find the wheels ─────────────────────────────────────────────────────────
# Every layout we ship in, in preference order. Being layout-AGNOSTIC is deliberate:
# defect 1 above was a packaging change (wheels hoisted to the plugin root to avoid
# copying them 11 times) silently breaking a path this script depended on. It should
# not be possible for that to happen again.
WHEEL_DIR=""
for d in "$SKILL_DIR/wheels" \
         "$SKILL_DIR/../../wheels" \
         "${CLAUDE_PLUGIN_ROOT:-/nonexistent}/wheels" \
         "${CLAUDE_PLUGIN_ROOT:-/nonexistent}/skills/torana-skill/wheels"; do
  if [ -d "$d" ] && ls "$d"/torana_cli-*.whl >/dev/null 2>&1; then
    WHEEL_DIR="$(cd "$d" && pwd)"; break
  fi
done

CLI_WHEEL=""; SHARED_WHEEL=""
if [ -n "$WHEEL_DIR" ]; then
  CLI_WHEEL=$(ls -t "$WHEEL_DIR"/torana_cli-*.whl 2>/dev/null | head -1)
  SHARED_WHEEL=$(ls -t "$WHEEL_DIR"/pantheon_shared-*.whl 2>/dev/null | head -1)
fi

# The commit a build came from — not its version — is what distinguishes two builds:
# version strings get reused across builds, so a version compare passes while the code
# differs (SKILL-1). DIRTY means the commit does NOT fully describe the build, so a dirty
# build never matches anything and always reinstalls.
#
# Read with shell tools, not python: this runs at every session start, and three python
# interpreter launches cost more than the entire rest of the no-op path.
SITE_VERSION=$(ls "$TORANA_VENV"/lib/python*/site-packages/torana_cli/_version.py 2>/dev/null | head -1)
# ⚠️ Match the ASSIGNMENT, not prose that starts with the same word. `_version.py`'s own
# docstring contains the line "DIRTY=True means COMMIT_SHA does not fully describe this
# build", and a loose pattern happily returned that sentence as the value — so the dirty
# check compared a paragraph against "True", never matched, and the guard silently passed.
read_commit() { [ -f "$1" ] || return 0; sed -n 's/^COMMIT_SHA *= *"\([A-Za-z0-9]*\)".*/\1/p' "$1" | head -1; }
# grep -E, not sed: BSD sed (macOS) has no \| alternation in a basic regex, so the
# sed form matched on Linux and returned EMPTY on a Mac — the dirty guard passing on
# one developer's machine and not another's.
read_dirty()  { [ -f "$1" ] || return 0; grep -E '^DIRTY[[:space:]]*=[[:space:]]*(True|False)[[:space:]]*$' "$1" \
                  | head -1 | sed 's/.*=[[:space:]]*//' | tr -d '[:space:]'; }

wheel_version_py() {
  [ -n "$1" ] || return 0
  if command -v unzip >/dev/null 2>&1; then
    unzip -p "$1" "torana_cli/_version.py" 2>/dev/null
  else
    python3 -c "import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);print(z.read('torana_cli/_version.py').decode())" "$1" 2>/dev/null
  fi
}

WHEEL_VERSION_PY="$(mktemp)"; trap 'rm -f "$WHEEL_VERSION_PY"' EXIT
wheel_version_py "$CLI_WHEEL" > "$WHEEL_VERSION_PY" 2>/dev/null

BUNDLED="$(read_commit "$WHEEL_VERSION_PY")"
BUNDLED_DIRTY="$(read_dirty "$WHEEL_VERSION_PY")"
INSTALLED="$(read_commit "$SITE_VERSION")"

# ── Fast path ───────────────────────────────────────────────────────────────
# Same build already installed, and pantheon_shared importable. Exit silently: this runs
# at the start of every session, so a no-op must cost nothing and say nothing.
# Two builds are the same only when BOTH the CLI and the shared library match what is installed:
# the CLI commit (above) and the shared library's commit, stamped next to the wheels when the plugin
# was built and written into the venv when it was installed. A shared library that does not import
# is not "installed", so the last test imports it with the venv's own Python.
BUNDLED_SHARED="$(cat "$WHEEL_DIR/pantheon_shared.commit" 2>/dev/null)"
INSTALLED_SHARED="$(cat "$TORANA_VENV/.shared-commit" 2>/dev/null)"
shared_stamp_ok() { case "$1" in ""|*dirty*|unknown*) return 1;; *) return 0;; esac; }
if [ -x "$TORANA" ] && [ -n "$BUNDLED" ] && [ "$BUNDLED" = "$INSTALLED" ] \
   && [ "$BUNDLED_DIRTY" != "True" ] \
   && shared_stamp_ok "$BUNDLED_SHARED" && [ "$BUNDLED_SHARED" = "$INSTALLED_SHARED" ] \
   && "$TORANA_VENV/bin/python" -c 'import pantheon_shared' >/dev/null 2>&1; then
  say "torana CLI current (commit ${BUNDLED:0:8}) — nothing to do"
  exit 0
fi

if [ -z "$CLI_WHEEL" ]; then
  if command -v torana >/dev/null 2>&1; then
    warn "NOTE: no bundled wheel found near $SKILL_DIR; using the torana already on PATH."
    warn "      It may not match this skill — run '$(command -v torana) version' to check."
    exit 0
  fi
  warn "ERROR: cannot bootstrap the torana CLI — no wheel found near $SKILL_DIR"
  warn "       Looked in: $SKILL_DIR/wheels, the plugin root, \$CLAUDE_PLUGIN_ROOT"
  exit 1
fi

# ── Python version ──────────────────────────────────────────────────────────
# The CLI wheel declares requires-python >=3.12. Common bases ship older Pythons (Debian
# bookworm and node:22-slim have 3.11), and pip then fails with "requires a different
# Python: 3.11.2 not in '>=3.12'". Check first and say what is needed, what was found and
# how to get it. uv needs no system Python: it downloads 3.12 itself.
py_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; }
PY=""
PYS=""   # every usable 3.12+ Python, the tested 3.12 first; the install keeps the first that makes a venv with pip
if ! command -v uv >/dev/null 2>&1; then
  for cand in python3.12 python3.13 python3; do
    if command -v "$cand" >/dev/null 2>&1 && py_ok "$cand"; then
      PYS="$PYS $cand"; [ -z "$PY" ] && PY="$cand"
    fi
  done
  if [ -z "$PY" ]; then
    FOUND="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)"
    if [ -n "$FOUND" ]; then WHAT="found Python $FOUND"; else WHAT="no python3 was found"; fi
    warn "ERROR: the torana CLI needs Python 3.12 or newer, and $WHAT."
    warn "       Fix one of these, then start a new session:"
    warn "         - install uv (https://docs.astral.sh/uv/), which downloads Python 3.12 by itself"
    warn "         - install Python 3.12+ (python.org, your package manager, or pyenv)"
    exit 1
  fi
fi

# ── Install ─────────────────────────────────────────────────────────────────
echo "Installing the torana CLI (commit ${BUNDLED:0:8}) into $TORANA_VENV …"

if command -v uv >/dev/null 2>&1; then
  # Prefer the tested 3.12, then 3.13. A bare ">=3.12" resolves to the NEWEST Python uv knows,
  # which can be a pre-release the dependencies have no wheels for (measured: 3.15).
  uv venv --python 3.12 "$TORANA_VENV" >/dev/null 2>&1 || uv venv --python 3.13 "$TORANA_VENV" >/dev/null 2>&1 || {
    warn "ERROR: uv could not create a Python 3.12+ environment at $TORANA_VENV."
    warn "       uv downloads Python from the internet if none is installed; on a machine that cannot,"
    warn "       install Python 3.12 or newer and start a new session."; exit 1; }
  uv pip install --python "$TORANA_VENV/bin/python" --reinstall --quiet "$CLI_WHEEL" || {
    warn "ERROR: uv could not install $CLI_WHEEL"; warn "  The first install needs access to PyPI, or to a pip mirror you have configured, for click, httpx, rich, pyyaml, pyjwt."; exit 1; }
  [ -n "$SHARED_WHEEL" ] && uv pip install --python "$TORANA_VENV/bin/python" --reinstall --quiet "$SHARED_WHEEL"
elif [ -n "$PY" ]; then
  # A Python can be new enough and still make a venv with no pip: Debian and Ubuntu ship python3.X
  # without its venv module unless python3.X-venv is installed. Try each candidate and keep the
  # first whose venv has pip; never hand pip a venv that has none.
  VENV_PY=""
  for cand in $PYS; do
    rm -rf "$TORANA_VENV"
    if "$cand" -m venv "$TORANA_VENV" >/dev/null 2>&1 && "$TORANA_VENV/bin/python" -m pip --version >/dev/null 2>&1; then
      VENV_PY="$cand"; break
    fi
  done
  if [ -z "$VENV_PY" ]; then
    rm -rf "$TORANA_VENV"
    warn "ERROR: found Python 3.12+ ($(echo $PYS | tr ' ' ',')), but none could create a virtual environment with pip."
    warn "       Fix one of these, then start a new session:"
    warn "         - install uv (https://docs.astral.sh/uv/), which needs no system Python"
    VER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)"
    warn "         - on Debian or Ubuntu, install the venv package for your Python: 'apt install python${VER}-venv'"
    exit 1
  fi
  "$TORANA_VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  "$TORANA_VENV/bin/python" -m pip install --quiet --force-reinstall "$CLI_WHEEL" || {
    warn "ERROR: pip could not install $CLI_WHEEL"; warn "  The first install needs access to PyPI, or to a pip mirror you have configured, for click, httpx, rich, pyyaml, pyjwt."; exit 1; }
  [ -n "$SHARED_WHEEL" ] && "$TORANA_VENV/bin/python" -m pip install --quiet --force-reinstall "$SHARED_WHEEL"
else
  warn "ERROR: need uv or python3 to install the CLI. Install Python 3.12+ or uv, then retry."
  exit 1
fi

# ⛔ pantheon_shared is not on PyPI and cannot be a pyproject dependency, so nothing pulls it
#    in implicitly. Without it the artifact-intent gate does not fail loudly: `check-intent`
#    exits 2 and `artifact add` reports "was NOT checked" and returns 0. A CLI that breaks
#    later is a quiet failure, so a missing or uninstallable pantheon_shared FAILS the
#    bootstrap here (non-zero, plain message). The next session retries, because the fast
#    path above requires it to be installed.
if ! "$TORANA_VENV/bin/python" -c 'import pantheon_shared' >/dev/null 2>&1; then
  if [ -z "$SHARED_WHEEL" ]; then
    warn "ERROR: the torana CLI is installed, but the shared library it needs is missing from this plugin"
    warn "       (no pantheon_shared-*.whl in $WHEEL_DIR). Reinstall or update the plugin."
  else
    warn "ERROR: the torana CLI is installed, but its shared library ($(basename "$SHARED_WHEEL")) did not install."
    warn "       Run this to see why:  $TORANA_VENV/bin/python -c 'import pantheon_shared'"
  fi
  warn "       Without it, artifact checks cannot run. Fix that, then start a new session."
  exit 1
fi

# Remember which shared library this venv now holds, so the next session can tell when it changed.
printf '%s' "$BUNDLED_SHARED" > "$TORANA_VENV/.shared-commit" 2>/dev/null || true
[ -x "$TORANA" ] || { warn "ERROR: install finished but $TORANA is missing"; exit 1; }
echo "  $("$TORANA" --version 2>/dev/null || echo torana) · commit ${BUNDLED:0:8}"

# ── First-run guidance ──────────────────────────────────────────────────────
# The CLI's default base-url is http://localhost, which is right for a developer with the
# stack running and wrong for everyone else — and a wrong base-url surfaces as a confusing
# connection error later, not as "you didn't configure me".
CURRENT_URL="$("$TORANA" config get base-url 2>/dev/null | tr -d '[:space:]')"
case "$CURRENT_URL" in
  *localhost*|"")
    if ! curl -sS -o /dev/null --max-time 2 "http://localhost" 2>/dev/null; then
      echo "  Base URL is the default (http://localhost) and nothing is answering there."
      echo "  Point it at your tenant:  $TORANA config set base-url https://<your-tenant>"
    fi
    ;;
esac
exit 0
