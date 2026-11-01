#!/usr/bin/env python3
"""Is the npm codemod engine usable HERE? — node, then ts-morph. Exit 0 = usable, 3 = decline.

FIX_PR_PHASE5_CODEMOD_SPEC § 3.5.4. Grown from the measured prototype at
docs/evidence/fix_pr_phase5_libcst/npm/node_probe.py.

⛔ A DECLINE, NEVER A FALLBACK. When this says no, every npm site is refused with the code it returns
and the codemod block is `unavailable`. There is no Python fallback and no regex rewrite: a rename
applied by text search is exactly the silent half-fix this design exists to prevent.

⛔ `require('ts-morph')` IS THE TEST, not npm's exit code — the same rule as `import libcst` for the
Python engine (§ 3.5.6), and for the same measured reason: an install can succeed and leave a package
that cannot load.
"""
import json
import os
import shutil
import subprocess
import sys

#: minimatch 10 (a ts-morph dependency) declares node "18 || 20 || >=22".
MIN_NODE = (18, 0)
PROBE_TIMEOUT_S = 10

HERE = os.path.dirname(os.path.abspath(__file__))


def node_modules_dirs():
    """Where the engine's `node_modules` may live, in resolution order.

    1. `codemod_js/node_modules`, beside `rename.js` — node resolves this NATIVELY by walking up from
       the script's own directory, so no NODE_PATH is needed. This is where a baked image puts it
       (the Claude sandbox), and it is the more robust of the two.
    2. `$PACK_DIR/node/node_modules` (§ 3.5.4), reached with NODE_PATH — where `install_engines.sh`
       puts it on a laptop, because the shipped `references/` tree may be read-only.

    `TORANA_CODEMOD_NODE_MODULES` overrides both, and is what the sandbox Dockerfile sets when it
    bakes the engine somewhere else.
    """
    override = os.environ.get("TORANA_CODEMOD_NODE_MODULES")
    if override:
        return [override]
    pack = os.environ.get("TORANA_SCAN_PACK_DIR") or os.path.join(
        os.path.expanduser("~"), ".torana", "scan-pack")
    return [os.path.join(HERE, "codemod_js", "node_modules"),
            os.path.join(pack, "node", "node_modules")]


def node_for_codemod():
    """`{"usable": bool, ...}` for the node RUNTIME alone. Decline codes: node_unavailable, node_too_old."""
    exe = shutil.which("node")  # PATH only: never a runner's bundled externals/node20, which is the runner's, not ours
    if not exe:
        return {"usable": False, "decline": "node_unavailable", "detail": "no node on PATH"}
    try:
        out = subprocess.run([exe, "-p", "process.versions.node"], capture_output=True, text=True,
                             timeout=PROBE_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"usable": False, "decline": "node_unavailable", "detail": f"{exe}: {exc}"}
    ver = out.stdout.strip()
    try:
        major_minor = tuple(int(x) for x in ver.split(".")[:2])
    except ValueError:
        return {"usable": False, "decline": "node_unavailable", "detail": f"{exe} printed {ver!r}"}
    if out.returncode != 0 or major_minor < MIN_NODE:
        return {"usable": False, "decline": "node_too_old", "detail": f"{exe} {ver} < {MIN_NODE}"}
    return {"usable": True, "node": exe, "version": ver}


def engine_for_codemod():
    """node AND ts-morph, as one answer: `{"usable", "node", "version", "ts_morph", "node_modules"}`
    or a decline (`node_unavailable` / `node_too_old` / `ts_morph_unavailable`)."""
    base = node_for_codemod()
    if not base["usable"]:
        return base
    tried = []
    for nm in node_modules_dirs():
        tried.append(nm)
        env = {**os.environ, "NODE_PATH": nm}
        try:
            out = subprocess.run(
                [base["node"], "-e", "process.stdout.write(require('ts-morph/package.json').version)"],
                capture_output=True, text=True, timeout=PROBE_TIMEOUT_S, env=env,
                cwd=os.path.dirname(nm) if os.path.isdir(os.path.dirname(nm)) else HERE)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"usable": False, "decline": "ts_morph_unavailable", "detail": f"{nm}: {exc}"}
        if out.returncode == 0 and out.stdout.strip():
            return {**base, "ts_morph": out.stdout.strip(), "node_modules": nm}
    # ⚠️ NAME WHAT WAS TRIED. "ts-morph is unavailable" with no paths reads as a missing capability;
    # naming the resolution order sends the reader to the install, which is where the problem is.
    return {"usable": False, "decline": "ts_morph_unavailable",
            "detail": "require('ts-morph') failed under each of: " + ", ".join(tried)}


if __name__ == "__main__":
    r = engine_for_codemod() if "--engine" in sys.argv else node_for_codemod()
    print(json.dumps(r))
    sys.exit(0 if r["usable"] else 3)
