#!/usr/bin/env bash
#
# One scheduled sweep: scan every configured repository and report to Torana.
#
# ⛔ ALWAYS A FULL SCAN. fleet_scan.py passes `--scan-scope full`, and that is what
# lets the platform retire findings that have stopped appearing. An ingest with no
# declared scope is read as "changed", which retires NOTHING — a nightly scan would
# then accumulate findings forever while reporting success every time.
#
set -euo pipefail

PREFIX="${TORANA_PREFIX:-/opt/torana}"
CONF="${TORANA_CONF:-$PREFIX/torana-scan.conf}"
[ -r "$CONF" ] || { echo "ERROR: no config at $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

export TORANA_BASE_URL TORANA_PROFILE
TORANA_BIN="$PREFIX/venv/bin/torana"
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT

# ⚠️ Checked BEFORE scanning, not after. A scan takes minutes; discovering the
# credentials are gone only at the push step wastes all of it and reports a confusing
# failure. `auth status` also refreshes the access token, so the push below cannot
# expire mid-flight.
if ! "$TORANA_BIN" auth status >/dev/null 2>&1; then
    echo "ERROR: not authenticated for profile '$TORANA_PROFILE'." >&2
    echo "       run: $TORANA_BIN auth login --email <user> --password <pw>" >&2
    exit 5
fi

ARGS=(--out-dir "$OUT" --scan-types "${TORANA_SCAN_TYPES:-all}" --push
      --torana "$TORANA_BIN" --timeout "${TORANA_TIMEOUT:-1800}")
if [ -n "${TORANA_REPOS:-}" ]; then ARGS+=(--repos "$TORANA_REPOS")
elif [ -n "${TORANA_ROOT:-}" ];  then ARGS+=(--root  "$TORANA_ROOT")
else echo "ERROR: set TORANA_ROOT or TORANA_REPOS in $CONF" >&2; exit 1; fi

if [ "${TORANA_GIT_PULL:-true}" = "true" ] && [ -n "${TORANA_ROOT:-}" ]; then
    # ⚠️ Fast-forward only. A scanner must never rewrite or merge someone's working
    # tree; if the branch has diverged, scan what is there and say so.
    for r in "$TORANA_ROOT"/*/; do
        [ -d "$r/.git" ] || continue
        git -C "$r" fetch --quiet --all 2>/dev/null || true
        git -C "$r" merge --ff-only --quiet "@{u}" 2>/dev/null \
            || echo "note: $(basename "$r") could not fast-forward — scanning the checked-out tree"
    done
fi

"$PREFIX/venv/bin/python" "$PREFIX/fleet_scan.py" "${ARGS[@]}"
