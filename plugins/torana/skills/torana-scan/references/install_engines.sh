#!/usr/bin/env bash
#
# install_engines.sh — provision the pinned Scan Pack engines (Option 2).
#
# Downloads the engine versions pinned in scan_pack.json into scan_pack/bin/,
# VERIFYING each binary against the upstream release's published checksums file.
# scan_pack.py prefers scan_pack/bin/ over PATH, so this gives a reproducible,
# pinned bundle on any full-shell host (dev box, dogfood VM, CI) without relying
# on the user having installed anything. Engines that can't be provisioned here
# (e.g. inside a restricted sandbox) just stay absent and scan_pack.py skips them.
#
# Honest verification model: we verify the downloaded artifact against the
# UPSTREAM checksums.txt for the pinned version (real integrity check). The
# computed sha256 is printed so it can be recorded in the manifest later to hard-
# pin against upstream tampering. No fabricated checksums are shipped.
#
# Usage:
#   ./install_engines.sh                 # install all pinned FAST-TIER engines
#   ./install_engines.sh --engines trivy,gitleaks
#   ./install_engines.sh --engines vvah  # provision ONLY the deep tier (VVAH, source install)
#   ./install_engines.sh --dry-run       # print the resolved plan, download nothing
#   ./install_engines.sh --verify        # HEAD-check every pin (all os/arch) — run BEFORE adding/bumping a pin
#
# Deep tier: the `deep_tier` entries in scan_pack.json (VVAH) install from source
# (git clone a pinned ref + `pip install .`) into the isolated venv. They are opt-in
# — a bare run installs only the fast-tier bundle unless you name a deep tool via
# --engines. The skill provisions the deep tier when the user opts into `--deep`.
#
# Requires: bash, python3, curl, tar, one of sha256sum/shasum, and git (deep tier).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/scan_pack.json"
BIN_DIR="$HERE/scan_pack/bin"
VENV_DIR="$HERE/scan_pack/venv"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

DRY_RUN=0
VERIFY=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --verify)  VERIFY=1 ;;
    --engines) ONLY="$2"; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

command -v python3 >/dev/null || { echo "ERROR: python3 required" >&2; exit 1; }
command -v curl    >/dev/null || { echo "ERROR: curl required" >&2; exit 1; }

# --- verify mode: HEAD-check every pin across the os/arch matrix (no download) --
# Run this BEFORE adding/bumping a version in scan_pack.json — a yanked or typo'd
# pin (e.g. Trivy 0.55.0 was removed from GitHub) is caught here instead of failing
# a customer's install. Exits non-zero if any pinned asset is unavailable.
if [ "$VERIFY" -eq 1 ]; then
  echo "Verifying manifest pins are downloadable (HEAD only, full os/arch matrix)…"
  VPLAN="$TMP/verify.tsv"
  python3 - "$MANIFEST" > "$VPLAN" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
MATRIX = [("darwin", "arm64"), ("darwin", "amd64"), ("linux", "arm64"), ("linux", "amd64")]
seen = set()
for e in data["engines"] + data.get("deep_tier", []):
    inst = e.get("install"); b = e["binary"]
    if not inst or b in seen:
        continue
    seen.add(b); ver = e["version_pin"]; m = inst["method"]
    if m == "github_release":
        base = f"https://github.com/{inst['repo']}/releases/download/v{ver}"
        print(f"{b}\t{ver}\tchecksums\t{base}/{inst['checksums'].format(version=ver)}")
        for osn, arch in MATRIX:
            o = inst["os_map"].get(osn); a = inst["arch_map"].get(arch)
            if not o or not a:
                continue
            print(f"{b}\t{ver}\t{osn}/{arch}\t{base}/{inst['asset'].format(version=ver, os=o, arch=a)}")
    elif m == "pip":
        pkg = inst["package"].format(version=ver).split("==")[0]
        print(f"{b}\t{ver}\tpypi\thttps://pypi.org/pypi/{pkg}/{ver}/json")
    elif m == "source":
        # git ref reachability — checked via `git ls-remote` (tag+HEAD), below.
        print(f"{b}\t{ver[:12]}\tgitref\t{inst['repo']}#{inst['ref']}")
PY
  vrc=0
  while IFS=$'\t' read -r binary ver tag url; do
    if [ "$tag" = "gitref" ]; then
      # Source install: verify the repo is reachable (an exact commit SHA is not
      # listable via ls-remote — full pinning is validated at clone time).
      repo="${url%%#*}"
      if command -v git >/dev/null && git ls-remote "$repo" >/dev/null 2>&1; then
        code=200
      else
        code=000
      fi
    else
      case "$url" in
        *pypi.org*) code=$(curl -o /dev/null -s -w "%{http_code}" -L "$url") ;;
        *)          code=$(curl -o /dev/null -s -w "%{http_code}" -I -L "$url") ;;
      esac
    fi
    if [ "$code" = "200" ]; then ok="OK"; else ok="FAIL"; vrc=1; fi
    printf "  %-10s %-9s %-12s %-4s (HTTP %s)\n" "$binary" "$ver" "$tag" "$ok" "$code"
  done < "$VPLAN"
  if [ "$vrc" -eq 0 ]; then
    echo "All pinned versions are available across the matrix."
  else
    echo "ONE OR MORE PINS UNAVAILABLE — fix the manifest before committing/shipping." >&2
  fi
  exit $vrc
fi

# --- platform detection ---------------------------------------------------
case "$(uname -s)" in
  Darwin) OS=darwin ;;
  Linux)  OS=linux ;;
  *) echo "ERROR: unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64 ;;
  *) echo "ERROR: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# --- resolve the install plan from the manifest (python does the JSON) ------
# Emits one tab-separated line per unique binary:
#   github_release:  binary<TAB>github_release<TAB>url<TAB>checksums_url<TAB>asset<TAB>bin_in_archive
#   pip:             binary<TAB>pip<TAB>package
#   unsupported:     binary<TAB>UNSUPPORTED<TAB>os/arch
PLAN="$TMP/plan.tsv"
python3 - "$MANIFEST" "$OS" "$ARCH" "$ONLY" > "$PLAN" <<'PY'
import json, sys
manifest, osname, arch, only = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
wanted = {x.strip() for x in only.split(",") if x.strip()} if only else None
data = json.load(open(manifest))
seen = set()
# Fast-tier engines install on a bare run; deep-tier tools (VVAH) are OPT-IN — they
# install only when named in --engines (heavy LLM-SDK deps + a git clone).
fast = [(e, False) for e in data["engines"]]
deep = [(e, True) for e in data.get("deep_tier", [])]
for e, is_deep in fast + deep:
    inst = e.get("install")
    b = e["binary"]
    if not inst or b in seen:
        continue
    named = wanted and (b in wanted or e["name"] in wanted)
    if is_deep and not named:
        continue                      # opt-in: skip deep tier unless explicitly named
    if wanted and not named:
        continue
    seen.add(b)
    ver = e["version_pin"]
    m = inst["method"]
    if m == "github_release":
        o = inst["os_map"].get(osname); a = inst["arch_map"].get(arch)
        if not o or not a:
            print(f"{b}\tUNSUPPORTED\t{osname}/{arch}"); continue
        asset = inst["asset"].format(version=ver, os=o, arch=a)
        chk = inst["checksums"].format(version=ver)
        base = f"https://github.com/{inst['repo']}/releases/download/v{ver}"
        print(f"{b}\tgithub_release\t{base}/{asset}\t{base}/{chk}\t{asset}\t{inst['bin_in_archive']}")
    elif m == "pip":
        print(f"{b}\tpip\t{inst['package'].format(version=ver)}")
    elif m == "source":
        # git clone + pip install into the isolated venv (VVAH: not on PyPI).
        print(f"{b}\tsource\t{inst['repo']}\t{inst['ref']}\t{inst.get('python_min','3.10')}")
    else:
        print(f"{b}\tUNSUPPORTED\tmethod={m}")

# Pinned RULESETS (not binaries), emitted AFTER the engines loop closes -- they are a
# separate list in the manifest, not another engine install method. Fetched once here so
# scans stop re-resolving the ruleset through semgrep.dev on every run; see
# scan_pack.json rulesets[]._why_comment.
for rs in data.get("rulesets", []):
    # Same --engines contract as above: a ruleset rides with its engine, so
    # `--engines gitleaks` must not fetch semgrep's 2.4 MB of rules.
    if wanted and rs.get("for_engine") not in wanted:
        continue
    i = rs.get("install") or {}
    if i.get("method") == "http_snapshot":
        print(f"{rs['name']}\thttp_snapshot\t{i['url']}\t{rs['dest']}\t{i.get('min_bytes',0)}\t{i.get('must_contain','')}")
    else:
        print(f"{rs.get('name','?')}\tUNSUPPORTED\tmethod={i.get('method')}")
PY

echo "Platform: $OS/$ARCH   →   $BIN_DIR"
echo "Plan:"
cat "$PLAN" | sed 's/^/  /'
if [ "$DRY_RUN" -eq 1 ]; then echo "(dry-run — nothing downloaded)"; exit 0; fi
mkdir -p "$BIN_DIR"

install_github_release() {
  local binary="$1" url="$2" chk_url="$3" asset="$4" bin_in_archive="$5"
  echo "→ $binary: $url"
  curl -fsSL "$url" -o "$TMP/$asset"
  curl -fsSL "$chk_url" -o "$TMP/checksums.txt"
  local want got
  want="$(grep -E "[[:space:]]\*?${asset}\$" "$TMP/checksums.txt" | awk '{print $1}' | head -1)"
  got="$(sha256 "$TMP/$asset")"
  if [ -z "$want" ]; then
    echo "  WARN: $asset not found in upstream checksums; computed sha256=$got (NOT verified)" >&2
  elif [ "$want" != "$got" ]; then
    echo "  ERROR: checksum mismatch for $asset" >&2
    echo "    upstream=$want  computed=$got" >&2
    return 1
  else
    echo "  ✓ verified against upstream checksums (sha256=$got)"
  fi
  tar -xzf "$TMP/$asset" -C "$TMP"
  local found
  found="$(find "$TMP" -type f -name "$bin_in_archive" -perm -u+x 2>/dev/null | head -1)"
  [ -z "$found" ] && found="$(find "$TMP" -type f -name "$bin_in_archive" | head -1)"
  [ -z "$found" ] && { echo "  ERROR: '$bin_in_archive' not in archive" >&2; return 1; }
  install -m 0755 "$found" "$BIN_DIR/$binary"
  echo "  installed → $BIN_DIR/$binary"
}

install_pip() {
  local binary="$1" package="$2"
  echo "→ $binary: pip $package (isolated venv)"
  [ -d "$VENV_DIR" ] || python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q --upgrade pip >/dev/null
  "$VENV_DIR/bin/pip" install -q "$package"
  ln -sf "$VENV_DIR/bin/$binary" "$BIN_DIR/$binary"
  echo "  installed → $BIN_DIR/$binary (→ venv)"
}

# Source install for the deep tier (VVAH): clone a pinned git ref and `pip install .`
# into the SAME isolated venv the pip engines use. The deep-tier runner (vvah_run.py)
# resolves the console script at scan_pack/venv/bin/<binary>, so no bin/ symlink is
# needed and the tool stays out of the router's PATH. Heavy (LLM SDK deps) by design.
install_source() {
  local binary="$1" repo="$2" ref="$3" pymin="$4"
  echo "→ $binary: source $repo@${ref:0:12} (isolated venv)"
  command -v git >/dev/null || { echo "  ERROR: git required for source install" >&2; return 1; }
  [ -d "$VENV_DIR" ] || python3 -m venv "$VENV_DIR"
  # VVAH needs Python >= its floor; fail clearly rather than mid-pip.
  local pyver
  pyver="$("$VENV_DIR/bin/python" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
  if [ "$(printf '%s\n%s\n' "$pymin" "$pyver" | sort -V | head -1)" != "$pymin" ]; then
    echo "  ERROR: $binary needs Python >= $pymin; venv has $pyver" >&2; return 1
  fi
  local src="$TMP/$binary-src"
  # Shallow clone, then hard-checkout the exact ref (branch OR commit sha).
  git clone --quiet "$repo" "$src" || { echo "  ERROR: git clone failed" >&2; return 1; }
  ( cd "$src" && git checkout --quiet "$ref" ) || { echo "  ERROR: ref $ref not found" >&2; return 1; }
  local sha
  sha="$( cd "$src" && git rev-parse HEAD )"
  "$VENV_DIR/bin/pip" install -q --upgrade pip >/dev/null
  "$VENV_DIR/bin/pip" install -q "$src" || { echo "  ERROR: pip install . failed" >&2; return 1; }
  if [ ! -x "$VENV_DIR/bin/$binary" ]; then
    echo "  ERROR: '$binary' console script not found after install" >&2; return 1
  fi
  echo "  ✓ installed → $VENV_DIR/bin/$binary (commit $sha)"
}

install_http_snapshot() {
  local name="$1" url="$2" dest="$3" min_bytes="$4" must_contain="$5"
  local out="$HERE/scan_pack/$dest"
  echo "→ $name: snapshot $url"
  mkdir -p "$(dirname "$out")"
  local tmp="$TMP/$name.snapshot"
  # -L: /c/auto and /c/p/default both 302. Without it you save a 211-byte HTML stub
  # and every later scan dies on an unparseable config.
  if ! curl -fsSL --max-time 300 "$url" -o "$tmp"; then
    echo "  ERROR: fetch failed ($url)" >&2; return 1
  fi
  local size; size=$(wc -c < "$tmp")
  if [ "$size" -lt "$min_bytes" ]; then
    echo "  ERROR: got $size bytes, expected >= $min_bytes — redirect stub or truncated?" >&2; return 1
  fi
  if [ -n "$must_contain" ] && ! grep -q "$must_contain" "$tmp"; then
    echo "  ERROR: payload lacks '$must_contain' — not a ruleset" >&2; return 1
  fi
  # ⚠️ SMOKE-TEST BEFORE PUBLISHING. semgrep aborts the ENTIRE config load on one
  # malformed rule and reports "1 config was invalid" however many are bad. Catch it
  # here, at install, rather than on every scan from now on.
  local sem="$BIN_DIR/semgrep"
  if [ -x "$sem" ]; then
    local probe="$TMP/$name-probe"; mkdir -p "$probe"
    printf 'x = 1\n' > "$probe/probe.py"
    if ! "$sem" scan --config "$tmp" --metrics off --quiet "$probe" >/dev/null 2>&1; then
      echo "  ERROR: semgrep rejected the snapshot — not installing it" >&2; return 1
    fi
  else
    echo "  NOTE: semgrep not installed yet; skipping smoke test" >&2
  fi
  mv "$tmp" "$out"
  # ⛔ NO CONTENT DIGEST ON PURPOSE. The obvious thing here is a sha256 of the file, used
  # as a version. It does not work: this endpoint returns the SAME rules in a DIFFERENT
  # ORDER on each fetch. Measured 30 minutes apart -- identical 1074 rule ids, identical
  # 2423491 bytes, 3704 lines "changed", two different sha256s; sorting both files gives
  # the same digest, so nothing had actually changed. A raw digest would therefore report
  # drift on every re-provision even when the rules are untouched, and whoever kept seeing
  # it would learn to ignore the one time it was real. Source + fetch time say where the
  # rules came from and when, which is what a human actually needs; "are these the same
  # rules as that other machine?" is deliberately left unanswered rather than answered
  # wrongly.
  printf '{"name":"%s","url":"%s","bytes":%s,"fetched_at":"%s"}\n' \
    "$name" "$url" "$(wc -c < "$out")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out.provenance.json"
  echo "  ✓ pinned → $out  ($(wc -c < "$out") bytes)"
}

rc=0
while IFS=$'\t' read -r binary method a b c d; do
  case "$method" in
    github_release) install_github_release "$binary" "$a" "$b" "$c" "$d" || rc=1 ;;
    pip)            install_pip "$binary" "$a" || rc=1 ;;
    source)         install_source "$binary" "$a" "$b" "$c" || rc=1 ;;
    http_snapshot)  install_http_snapshot "$binary" "$a" "$b" "$c" "$d" || rc=1 ;;
    UNSUPPORTED)    echo "– $binary: unsupported ($a) — skipping" >&2 ;;
  esac
done < "$PLAN"

echo
echo "Done. scan_pack.py will prefer $BIN_DIR over PATH."
[ "$rc" -ne 0 ] && echo "(one or more engines failed — see errors above)" >&2
exit $rc
