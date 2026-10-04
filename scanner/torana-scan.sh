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

if [ "${TORANA_GIT_PULL:-false}" = "true" ] && [ -n "${TORANA_ROOT:-}" ]; then
    # ⚠️ Fast-forward only. A scanner must never rewrite or merge someone's working
    # tree; if the branch has diverged, scan what is there and say so.
    #
    # ⛔ A FAILED FETCH IS REPORTED, never swallowed. This used to end in `|| true`,
    # which hid the most likely failure of all: under torana-scan.service the
    # checkout is on a READ-ONLY filesystem (ProtectSystem=strict, and TORANA_ROOT
    # is not in ReadWritePaths), so every fetch fails and the scan silently runs on
    # a stale tree. The stderr is kept for the same reason — "read-only file system"
    # is the line that tells the operator which fix to apply.
    pull_failed=0
    for r in "$TORANA_ROOT"/*/; do
        [ -d "$r/.git" ] || continue
        if ! err="$(git -C "$r" fetch --quiet --all 2>&1)"; then
            pull_failed=1
            echo "WARNING: $(basename "$r") could not fetch — scanning the tree as checked out." >&2
            [ -n "$err" ] && echo "         git: ${err%%$'\n'*}" >&2
            continue
        fi
        git -C "$r" merge --ff-only --quiet "@{u}" 2>/dev/null \
            || echo "note: $(basename "$r") could not fast-forward — scanning the checked-out tree"
    done
    if [ "$pull_failed" = "1" ]; then
        echo "WARNING: TORANA_GIT_PULL is on but at least one fetch failed. Either grant the" >&2
        echo "         unit write access (systemctl edit torana-scan.service →" >&2
        echo "         ReadWritePaths=$TORANA_ROOT) or set TORANA_GIT_PULL=\"false\" in $CONF" >&2
        echo "         so the scanner stops claiming to refresh checkouts it cannot touch." >&2
    fi
fi

"$PREFIX/venv/bin/python" "$PREFIX/fleet_scan.py" "${ARGS[@]}"
