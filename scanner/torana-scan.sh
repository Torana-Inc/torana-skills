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

# ⚠️ The tenant address is checked FIRST and by name. Left at the shipped placeholder,
# every later step still fails — but as "not authenticated" from the auth check below,
# which sends the operator to re-run `auth login` when the real problem is an unset
# address. Name the actual cause instead, and point at the only place that has it.
case "${TORANA_BASE_URL:-}" in
    ""|*CHANGE-ME*|*example.invalid*)
        echo "ERROR: TORANA_BASE_URL is not set in $CONF (still the placeholder)." >&2
        echo "       Ask Torana for your tenant address — it differs per customer and" >&2
        echo "       per environment, so there is no default to fall back on." >&2
        echo "       Set it in $CONF, and point the CLI at the same address:" >&2
        echo "         $TORANA_BIN config set base-url <that address>" >&2
        exit 4
        ;;
esac

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
# ⚠️ REPO_PATHS is built from the SAME two knobs, so the reachability pass below can
# never walk a different set from the one that was scanned. Deriving it twice is how
# a sweep comes to answer for a repository it never looked at.
REPO_PATHS=()
if [ -n "${TORANA_REPOS:-}" ]; then ARGS+=(--repos "$TORANA_REPOS")
    IFS=',' read -r -a REPO_PATHS <<< "$TORANA_REPOS"
elif [ -n "${TORANA_ROOT:-}" ];  then ARGS+=(--root  "$TORANA_ROOT")
    for d in "$TORANA_ROOT"/*/; do REPO_PATHS+=("${d%/}"); done
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

# ⚠️ `|| scan_rc=$?`, not a bare call: `set -e` is on, so a failing scan would exit
# here and everything below — including the exit status this script reports — would be
# dead code that reads as if it ran.
scan_rc=0
"$PREFIX/venv/bin/python" "$PREFIX/fleet_scan.py" "${ARGS[@]}" || scan_rc=$?

# ── Code reachability ────────────────────────────────────────────────────────────
#
# For each finding Torana cannot judge on its own, read the checkout and record
# whether this repository's code actually imports the package / reaches the function.
# An absence LOWERS the finding's priority; it never closes one and never raises one.
#
# ⛔ AFTER the scan, never before. The queue is built from the findings that are
# already in the platform, so a pass run first would answer an empty list and look
# like it worked.
#
# ⚠️ ONE REPOSITORY AT A TIME, and a failure in one does not stop the rest — the
# sweep's whole point is that it keeps going. The pass itself refuses to answer a
# finding bound to another repository, so the worst a bad checkout can do is answer
# nothing.
if [ "${TORANA_REACHABILITY:-true}" != "false" ]; then
    reach_rc=0
    # ⚠️ `${a[@]+"${a[@]}"}` — an empty array under `set -u` is an unbound variable on
    # bash 4.3 and older, which several LTS distributions still ship.
    for r in ${REPO_PATHS[@]+"${REPO_PATHS[@]}"}; do
        [ -d "$r/.git" ] || continue
        echo "reachability: $(basename "$r")"
        if ! "$PREFIX/venv/bin/python" "$PREFIX/reachability_pass.py" \
                --repo "$r" --apply; then
            reach_rc=1
            echo "WARNING: reachability pass failed or was refused for $(basename "$r")" >&2
            echo "         The scan itself is unaffected; those findings keep the" >&2
            echo "         priority the ranking gave them." >&2
        fi
    done
    [ "$scan_rc" = "0" ] && scan_rc="$reach_rc"
fi

exit "$scan_rc"
