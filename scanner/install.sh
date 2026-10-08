#!/usr/bin/env bash
#
# Torana scanner — headless install for a Linux host.
#
# Scans repositories checked out on THIS machine on a schedule and reports findings
# to your Torana tenant. No GitHub App, no GitHub Actions, no inbound network.
#
# ⛔ THIS IS THE NON-GITHUB PATH. It performs FULL scans only, so it feeds inventory,
# retirement and the staleness board — it does NOT gate pull requests. Gating needs the
# GitHub Action, because only a CI run can prove which commit it is judging.
#
#   curl -fsSL <repo>/scanner/install.sh | bash      # or clone and run it
#
set -euo pipefail

PREFIX="${TORANA_PREFIX:-/opt/torana}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REFS="$SRC/plugins/torana/skills/torana-scan/references"
WHEELS="$SRC/plugins/torana/skills/torana-skill/wheels"

say() { printf '\033[0;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[0;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ -d "$REFS" ]   || die "scan scripts not found at $REFS — run this from a clone of the repo"
[ -d "$WHEELS" ] || die "wheels not found at $WHEELS"
command -v git >/dev/null || die "git is required — the scanner reads each repo's remote"

# ⛔ THE INTERPRETER IS CHOSEN, NOT ASSUMED. This used to run bare `python3`, which is
# wrong on RHEL: MEASURED on rockylinux:9, `python3` is 3.9.18 while the torana_cli wheel
# declares `Requires-Python >=3.12`, so the venv built fine and `pip install` then failed
# on a version constraint — three steps after the real cause, with nothing naming it.
# `python3.12` IS available there (dnf install python3.12); it is simply not `python3`.
PYTHON="${TORANA_PYTHON:-}"
if [ -z "$PYTHON" ]; then
    for c in python3.13 python3.12 python3; do
        command -v "$c" >/dev/null 2>&1 || continue
        "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null \
            && { PYTHON="$c"; break; }
    done
fi
[ -n "$PYTHON" ] || die "no Python 3.12+ found (checked python3.13, python3.12, python3).
       Debian/Ubuntu:  sudo apt-get install -y python3-venv
       RHEL/Rocky 9:   sudo dnf install -y python3.12      (its 'python3' is 3.9, too old)
       Or point at one yourself:  TORANA_PYTHON=/path/to/python3.12 $0"
say "Using $PYTHON ($("$PYTHON" --version 2>&1))"
# ⚠️ Checked, not assumed. MEASURED on a stock Ubuntu 24.04: python3 is present but
# `ensurepip` is not (it ships in the separate python3-venv package), so the venv step
# below fails with Debian's own message about a missing package — several steps after
# the real cause. Fail here instead, naming the package.
"$PYTHON" -c "import ensurepip" 2>/dev/null \
    || die "$PYTHON cannot create virtualenvs — install python3-venv (Debian/Ubuntu).
       On RHEL/Rocky the python3.12 package already includes it."
# ⚠️ The post-install steps below and torana-scan.service both run as this user. Without
# it the install "succeeds" and then every following command fails on an unknown user.
id torana >/dev/null 2>&1 \
    || die "the 'torana' service user does not exist — create it first:
       sudo useradd --system --create-home --shell /usr/sbin/nologin torana"

say "Installing into $PREFIX"
mkdir -p "$PREFIX"
cp -a "$REFS"/. "$PREFIX/"

say "Creating the virtualenv and installing the Torana CLI"
"$PYTHON" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
# ⭐ The wheels are COMMITTED in this repo — no PyPI, no package index needed.
"$PREFIX/venv/bin/pip" install --quiet "$WHEELS"/pantheon_shared-*.whl "$WHEELS"/torana_cli-*.whl
"$PREFIX/venv/bin/torana" --version >/dev/null || die "the torana CLI did not install"

say "Downloading the pinned scan engines (verified against upstream checksums)"
# ⚠️ Engines that cannot be provisioned stay absent and are SKIPPED WITH A MESSAGE,
# never silently — a missing engine must not look like a clean repo.
bash "$PREFIX/install_engines.sh" || say "some engines unavailable — they will be skipped and reported"

install -m 0644 "$SRC/scanner/torana-scan.conf.example" "$PREFIX/torana-scan.conf.example"
install -m 0755 "$SRC/scanner/torana-scan.sh"           "$PREFIX/torana-scan.sh"
[ -f "$PREFIX/torana-scan.conf" ] || install -m 0644 "$SRC/scanner/torana-scan.conf.example" "$PREFIX/torana-scan.conf"

# ⛔ CREATED HERE, not left to the CLI's first login. torana-scan.service lists this
# path in ReadWritePaths, and systemd requires a ReadWritePaths target to EXIST: if it
# does not, the unit fails before the script runs at all, with
#   Failed to set up mount namespacing: /home/torana/.torana: No such file or directory
#   status=226/NAMESPACE
# MEASURED on a fresh 24.04 install. That message names neither credentials nor this
# directory as the fix, and it is doubly misleading because running the script BY HAND
# works and prints the real problem ("not authenticated", exit 5) — so the by-hand step
# the README recommends passes while the scheduled run, the only one that matters, dies.
say "Creating the CLI's state directory for the torana user"
_TORANA_HOME="$(getent passwd torana | cut -d: -f6)"
install -d -o torana -g torana -m 0700 "${_TORANA_HOME:-/home/torana}/.torana"

# ⛔ WITHOUT THIS THE SCANNER SCANS PERFECTLY AND INGESTS NOTHING. git refuses to read
# the config — and therefore the remote — of a repository owned by another user:
#     fatal: detected dubious ownership in repository at '/home/<owner>/<repo>'
# That is the NORMAL case here: a dedicated service account scanning checkouts a
# developer, CI job or deploy process owns. build_sarif.py derives the repository
# identity with `git remote get-url origin`, its git wrapper is crash-proof and turns
# that fatal into None, so the SARIF ships with no versionControlProvenance and the
# server refuses the whole document ("keyless SARIF cannot be linked (D7)") — at the
# very last step, after full scans have run.
# MEASURED on demo 2026-10-08: two repositories, 236 findings computed, every one
# discarded, and the console said "2/2 scanned, 0 failed".
# ⚠️ Scoped to the scanner user's own gitconfig, never --system: this says "trust what
# you were pointed at", which is the operator's decision already expressed in
# torana-scan.conf, and it grants no filesystem access the user did not already have.
say "Trusting the configured repositories for the torana user (git safe.directory)"
_CONF_SRC="$PREFIX/torana-scan.conf"
if [ -r "$_CONF_SRC" ]; then
    # shellcheck disable=SC1090
    . "$_CONF_SRC"
    _paths=""
    [ -n "${TORANA_REPOS:-}" ] && _paths="$(printf '%s' "$TORANA_REPOS" | tr ',' ' ')"
    [ -n "${TORANA_ROOT:-}" ]  && _paths="$_paths $(find "$TORANA_ROOT" -maxdepth 2 -name .git -type d \
                                      -exec dirname {} \; 2>/dev/null)"
    # ⚠️ Both `-H` and `-C /` are load-bearing, and each failed silently when missing:
    #   -H   without it sudo keeps HOME=/root, so `git config --global` tries to write
    #        /root/.gitconfig as the torana user and fails on permissions.
    #   -C / without it git inherits THIS script's cwd — the clone, which normally sits
    #        in the installing admin's home (mode 0750) — and dies with
    #        "fatal: failed to stat '<cwd>': Permission denied" before doing anything,
    #        because it tries to discover a repository from the working directory first.
    # Both produce a step that appears to run and changes nothing.
    for _p in $_paths; do
        [ -d "$_p" ] || continue
        if sudo -u torana -H git -C / config --global --add safe.directory "$_p" 2>/dev/null; then
            say "  trusted $_p"
        else
            say "  ⚠️  could not trust $_p — add it by hand:
      sudo -u torana -H git -C / config --global --add safe.directory $_p"
        fi
    done
    [ -n "$_paths" ] || say "  (no repositories configured yet — re-run this after editing $_CONF_SRC,
      or add each by hand: sudo -u torana git config --global --add safe.directory <path>)"
fi

cat <<NEXT

$(say "Installed.") Three steps left:

  1. Point it at your repositories and tenant:
       sudo \$EDITOR $PREFIX/torana-scan.conf

     ⛔ ASK TORANA for your tenant address — TORANA_BASE_URL ships as a placeholder
        because it differs per customer, and a wrong value fails only at the final
        push, after the whole scan has been paid for.

  2. Point the CLI at that SAME address, then authenticate ONCE.
       sudo -u torana $PREFIX/venv/bin/torana config set base-url https://<your-address>
       sudo -u torana $PREFIX/venv/bin/torana auth login --email <user> --password <pw>

     ⚠️ USE --email/--password, not the browser flow, for a scheduled host. The
        refresh token is bound to an SSO session that idles out in 30 MINUTES (10h
        ceiling), so any schedule slower than that cannot refresh itself. What keeps
        an unattended scan working is the saved password: --save-credentials is ON by
        default and writes ~torana/.torana/credentials.yaml (0600), and the CLI
        re-authenticates from it whenever the refresh token has expired.
        A browser login works for exactly one run, then fails with exit 5.

     ⛔ The 'config set base-url' line is REQUIRED. torana-scan.conf is read by the
        scheduled scan, not by 'auth login', so skipping it makes the login target
        the built-in default and fail with "Cannot reach http://localhost/... :
        Connection refused" — which reads like a broken install, not an unset
        address. Verify with: sudo -u torana $PREFIX/venv/bin/torana config show

     ⛔ Use a DEDICATED account with 'integrations:write' ONLY — not a tenant admin.
        The CLI stores credentials under that user's ~/.torana (0600), and a scanning
        host should not hold an account that can do more than file findings.

  3. Schedule it:
       sudo cp $SRC/scanner/systemd/* /etc/systemd/system/
       sudo systemctl enable --now torana-scan.timer
       systemctl list-timers torana-scan.timer

  Run it once by hand first:
       sudo -u torana $PREFIX/torana-scan.sh

NEXT
