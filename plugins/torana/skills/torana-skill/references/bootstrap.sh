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
  out="$(bash "${BASH_SOURCE[0]}" 2>&1)"
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
SHARED_INSTALLED=$(ls -d "$TORANA_VENV"/lib/python*/site-packages/pantheon_shared 2>/dev/null | head -1)
if [ -x "$TORANA" ] && [ -n "$BUNDLED" ] && [ "$BUNDLED" = "$INSTALLED" ] \
   && [ "$BUNDLED_DIRTY" != "True" ] && [ -n "$SHARED_INSTALLED" ]; then
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

# ── Install ─────────────────────────────────────────────────────────────────
echo "Installing the torana CLI (commit ${BUNDLED:0:8}) into $TORANA_VENV …"

if command -v uv >/dev/null 2>&1; then
  uv venv --python 3.12 "$TORANA_VENV" >/dev/null 2>&1 || uv venv "$TORANA_VENV" >/dev/null 2>&1
  uv pip install --python "$TORANA_VENV/bin/python" --reinstall --quiet "$CLI_WHEEL" || {
    warn "ERROR: uv could not install $CLI_WHEEL"; exit 1; }
  [ -n "$SHARED_WHEEL" ] && uv pip install --python "$TORANA_VENV/bin/python" --reinstall --quiet "$SHARED_WHEEL"
elif command -v python3 >/dev/null 2>&1; then
  python3 -m venv "$TORANA_VENV" >/dev/null 2>&1 || true
  "$TORANA_VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  "$TORANA_VENV/bin/python" -m pip install --quiet --force-reinstall "$CLI_WHEEL" || {
    warn "ERROR: pip could not install $CLI_WHEEL"; exit 1; }
  [ -n "$SHARED_WHEEL" ] && "$TORANA_VENV/bin/python" -m pip install --quiet --force-reinstall "$SHARED_WHEEL"
else
  warn "ERROR: need uv or python3 to install the CLI. Install Python 3.12+ or uv, then retry."
  exit 1
fi

# ⛔ pantheon_shared is not on PyPI and cannot be a pyproject dependency, so nothing
#    pulls it in implicitly. When it is missing the artifact-intent gate does not fail
#    loudly — `check-intent` exits 2 and `artifact add` reports "was NOT checked" and
#    returns 0. Say so here rather than let a silent no-gate look like a pass.
if ! ls -d "$TORANA_VENV"/lib/python*/site-packages/pantheon_shared >/dev/null 2>&1; then
  warn "WARNING: pantheon_shared is not installed — the artifact-intent gate cannot run."
  warn "         (Expected a pantheon_shared-*.whl in $WHEEL_DIR)"
fi

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
