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
command -v python3 >/dev/null || die "python3 is required (3.12+)"
command -v git     >/dev/null || die "git is required — the scanner reads each repo's remote"
# ⚠️ Checked, not assumed. MEASURED on a stock Ubuntu 24.04: python3 is present but
# `ensurepip` is not (it ships in the separate python3-venv package), so the venv step
# below fails with Debian's own message about a missing package — several steps after
# the real cause. Fail here instead, naming the package.
python3 -c "import ensurepip" 2>/dev/null \
    || die "python3 cannot create virtualenvs — install python3-venv (Debian/Ubuntu) or python3-pip (RHEL)"
# ⚠️ The post-install steps below and torana-scan.service both run as this user. Without
# it the install "succeeds" and then every following command fails on an unknown user.
id torana >/dev/null 2>&1 \
    || die "the 'torana' service user does not exist — create it first:
       sudo useradd --system --create-home --shell /usr/sbin/nologin torana"

say "Installing into $PREFIX"
mkdir -p "$PREFIX"
cp -a "$REFS"/. "$PREFIX/"

say "Creating the virtualenv and installing the Torana CLI"
python3 -m venv "$PREFIX/venv"
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

cat <<NEXT

$(say "Installed.") Three steps left:

  1. Point it at your repositories and tenant:
       sudo \$EDITOR $PREFIX/torana-scan.conf

  2. Authenticate ONCE (interactive). The CLI then keeps itself logged in: the
     refresh token lasts 7 days and is renewed on every run, so a daily scan never
     lapses.
       sudo -u torana $PREFIX/venv/bin/torana auth login --email <user> --password <pw>

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
