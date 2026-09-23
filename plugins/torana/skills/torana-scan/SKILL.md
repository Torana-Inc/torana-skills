---
name: torana-scan
description: >
  Scan a code repository for security vulnerabilities (SAST, SCA, IaC,
  secrets, container) and either print the findings locally or push them to
  Torana via the `torana` CLI. Claude is the SAST engine: it reads the source
  files directly. OSV.dev is the SCA engine, and `semgrep --sarif` can be
  merged as an extra engine. Trigger whenever the user wants to: scan a repo,
  scan this repo, scan a repository for vulnerabilities, find vulnerabilities
  in code, run a security scan, run a security review, source-code security
  scan, list vulnerabilities in a project, push scan results to Torana, ingest
  scan results, produce SARIF, check a repo for CVEs, scan dependencies, scan a
  Dockerfile, scan for hardcoded secrets, or any phrasing about "find security
  issues in this code". Produces a standard SARIF 2.1.0 document (Torana
  profile) that drops into the `vulnerabilities` / `repositories` sink tables
  under a source-neutral repository id.
metadata:
  version: "2.8.0"
  last_updated: "2026-07-16"
  platform_version_tested: "2026.1"
---

# Torana Scan — code-level vulnerability scanner (SARIF-native)

## ⛔ Step 0, ALWAYS: load `torana-skill` — it is how the `torana` CLI is learned

**Invoke `torana-skill` (the `Skill` tool) before the first `torana` command this skill runs.**
Its install/auth bootstrap, profile rules and each verb's flags live there, not here — this
file names commands, it does not teach them, and a command used from memory is how a flag
drifts or a wrong verb runs.

- ⛔ **A working CLI is NOT evidence it is loaded.** `torana --version` succeeding only proves a
  binary exists — exactly how a run skipped `torana-skill` while everything "worked".
- ✅ **Loaded by a caller in this same session counts** — confirm it was actually invoked, and
  do not load it twice.
- ⛔ Where this file and `torana-skill` disagree about a command, **`torana-skill` wins**; say so.
- If `torana-skill` is not installed, stop and say so — ⛔ never run CLI commands from memory.


> Claude reads the code and emits findings; OSV handles SCA; `semgrep --sarif`
> can be merged as an extra engine. The skill assembles ONE **SARIF 2.1.0**
> document (one `run[]` per engine, Torana profile) and either prints findings
> or pushes via `torana ingest sarif`. Findings link to a **source-neutral**
> repository row, so they converge with the GitHub integration sync and the
> asset-inventory skill on the same `repositories` row.
> Standalone skill — does not require `torana-vm` or any workspace setup.

---

## Dependencies and Precedence

**`torana-skill` must be loaded alongside this skill.** `torana-scan` does not
bootstrap the CLI or OAuth — it relies on `torana-skill` having installed the
CLI wheel, set `$TORANA`, configured the base URL, and (for push) authenticated.

```bash
"$TORANA" --version 2>/dev/null || echo "ERROR: no torana CLI — torana-skill's bootstrap has not run"   # proves a binary exists, NOT that torana-skill is loaded (Step 0)
```

List-only mode needs no CLI/auth. All CLI calls use `"$TORANA"` (quoted).

**Pairs with `torana-asset-inventory`.** Identity + governance (criticality,
owner, environment, SLA) come from that skill's asset document, NOT from the
scanner — no scanner can know them. This skill ensures an asset exists (reuse or
invoke the asset skill) before/alongside scanning.

---

<!-- ═══════════════════════════════════════════════════════════════
     DOMAIN KNOWLEDGE
     ═══════════════════════════════════════════════════════════════ -->

## Core Concepts

### Two modes — ask which one up front

| Mode | What it does | Auth needed |
|---|---|---|
| **A. List-only** | Walk the repo, print findings, write a local SARIF doc. No network except OSV.dev. Nothing leaves the machine. | No |
| **B. Scan + push** | Same scan, then `"$TORANA" ingest sarif <doc>`. Findings land in the canonical sink tables. | Yes — `torana-skill` already authenticated |

**Default to Mode A** if ambiguous; offer Mode B after showing the table.

### Scan surfaces

Five sub-scans driven by Claude reading files; each finding becomes a SARIF
`result` with a Torana `scan_type ∈ {SAST, SCA, IaC, Secret, Container}`.

| Sub-scan | Inputs | engine (SARIF run) |
|---|---|---|
| **SAST** | Source under `auth/`, `admin/`, `payment/`, `api/`, route handlers | `claude_review` |
| **SCA** | Manifests (`package.json`, `requirements.txt`, `go.mod`, `Gemfile`, `pom.xml`) → OSV | `osv` |
| **IaC** | `Dockerfile`, `terraform/*.tf`, `k8s/*.yaml`, `.github/workflows/*.yml` | `claude_review` |
| **Secrets** | Whole tree; Claude verifies each candidate isn't a placeholder | `claude_review` |
| **Container** | Public base-image manifest (no docker daemon) | `claude_review` |
| **(optional) semgrep** | `semgrep --sarif src` run by the user/CI | merged verbatim |

> **v2.1 (SC0) — the Scan Pack runs REAL engines, replacing Claude-plays-every-role
> where a real tool exists.** Run `references/scan_pack.py` (below): it auto-detects
> domains, runs the pinned engines that are installed (Trivy → IaC + container,
> Gitleaks → secrets, semgrep → SAST), and merges every engine's native SARIF
> through `build_sarif.py`. A missing engine is **skipped with a clear message**, so a
> partial toolchain still scans. Claude review remains a SAST engine and the fallback
> for any domain whose real engine isn't installed.
>
> **v2.2 — scan-type selection.** The user chooses **which scan types run** (one, several,
> or all): `SAST`, `SCA`, `Secret`, `IaC`, `Container`. There is exactly **one engine per
> type**, so this is a *scan-type* menu, not an engine menu — pass the choice with
> `--scan-types SAST,Secret` (default `all`). Within each selected type the engine is still
> chosen automatically (installed pinned engine, else Claude-review fallback for SAST).
> `SCA` runs via OSV in the skill (Step 2), not the Scan Pack; the other four map to
> Scan-Pack engines. List-only vs push is unchanged.
>
> **Provisioning the engines (any full shell — dev box / VM / CI / Claude Code in
> CLI or any IDE).** Run `references/install_engines.sh` once to download the pinned,
> checksum-verified engines into `scan_pack/bin/` (Trivy/Gitleaks binaries; semgrep in
> an isolated venv). `scan_pack.py` prefers that local bin over PATH. Engines are
> **not** Python packages — a venv can't hold Trivy/Gitleaks — so do not try to
> `pip install` them. In a restricted sandbox (no egress / no binaries), skip the
> installer: scan_pack falls through to PATH, then to Claude review. (The skill's
> Procedure step 4 is where the install is offered to the user.)

### Key terminology

| Term | Definition |
|---|---|
| **SARIF** | OASIS-standard findings format (2.1.0). The skill emits one document with one `run[]` per engine. Any SARIF tool (GitHub, CodeQL, Trivy) can target the same `torana ingest sarif` endpoint. |
| **Torana profile** | Standard SARIF + a namespaced `properties.torana.*` bag carrying the ~12 fields with no native SARIF home (`scan_type`, `cve_id`, `package`, exploit intel). Conformant SARIF consumers ignore it. |
| **Source-neutral id** | `torana_repository_id = "repo:" + normalize(host/org/repo)`, derived server-side from the run's `versionControlProvenance.repositoryUri`. The scanner, the asset skill, and VCS sync all converge on this one id. |
| **Fingerprint (vuln PK)** | Computed server-side (`pantheon-integration` `torana_mesh/etl/ingestors/sarif.py::_fingerprint`) and scoped by `asset_key`. **SCA:** `sha256(sca|asset_key|manager|name|version|cve_id|advisory_id-if-no-CVE)` — the client `partialFingerprints` is deliberately ignored so OSV aliases (PYSEC/GHSA) of one CVE collapse, while distinct CVEs on one package version stay distinct. **SAST/other:** `sha256(asset_key|<first usable partialFingerprints value>)`, skipping placeholders (`"requires login"`) and git-blame keys; with none usable, `sha256(sast|asset_key|ruleId|uri|norm_snippet|occurrence)`. No line number is hashed. Stable across re-scans → upsert dedupes. |
| **`partialFingerprints`** | Client-side identity the skill stamps under `toranaSkill/v1`. Claude-review and OSV findings always get it. **SCA** results in engine-native runs merged verbatim (Trivy) get it too — keyed `(ecosystem, package, version, CVE)`, so the same CVE on the same version carries one id whether Trivy or OSV found it. ⛔ **SAST/IaC/secret results in merged native runs are deliberately NOT stamped**: the server prefers a usable client value as the row key for non-SCA results, so stamping them would re-key every existing row and strand what hangs off `torana_vulnerability_id` (controls, pentest verdicts, alerts) — for no gain, since the server's own synthesized key is already line-drift safe. Do not rely on an engine's own `fingerprints`: semgrep OSS emits the literal `"requires login"` for `matchBasedId` on every result (the server skips it as a placeholder). |
| **Pinned ruleset** | The rules `--config auto` would fetch, snapshotted ONCE at install (`install_engines.sh`) into `scan_pack/rules/` and frozen; semgrep then runs `--config <snapshot> --metrics off`. `auto` is **not** repo-aware — semgrep requests the bare URL `<semgrep_url>/c/auto` (`config_resolver.py`; a project URL is accepted but never sent), which 302-redirects to `/c/p/default` and returns the same ~1074 rules to every caller; rule-to-file selection happens locally from each rule's `languages:`. Pinning therefore reproduces `auto` exactly while removing the per-scan network call, the telemetry it forces, and the "which rules ran?" ambiguity. The endpoint is unversioned and **serves the same rules in a different order on each fetch** (measured: identical 1074 rule ids and byte count, 3704 lines of diff, same digest once sorted) — so no content digest is recorded; a raw one would report drift on every re-provision. Coverage records `ruleset_status` (`pinned` / `not-installed`), `ruleset_source` and `ruleset_fetched_at`. The snapshot is never packaged or committed; re-run `install_engines.sh` to move the pin. |
| **Coverage** | `run.properties.torana.coverage` — what the engine actually *looked at*, beside what it found: `files_scanned`, `files_unparsed`, `files_partially_parsed`, `rules_timed_out`, plus capped example lists. Per-run, because each engine covers a different file set. A count without it is not a result: "294 findings" and "294 findings, and 31 files the parser could not read" are different claims. Absent means *not measured*, never zero. |
| **Severity casing** | Datalake stores Title Case: `Critical`/`High`/`Medium`/`Low`/`Info`. (The skill emits SARIF `level`, the scanner's own rating as `scanner_severity`, and `security-severity` only when the finding has a real CVSS score; the platform decides the stored severity.) |

### What this skill does NOT do

- Does not run the application, build containers, or modify the target repo.
- Does not set governance (criticality/owner/SLA) — that's `torana-asset-inventory`.
- Does not triage findings (true/false positive) — that's the triage skill.
- Does not open tickets / push WAF rules / create alerts — downstream playbooks.

---

<!-- ═══════════════════════════════════════════════════════════════
     EXECUTION MECHANICS
     ═══════════════════════════════════════════════════════════════ -->

## Inputs

| Input | Required | Default |
|---|---|---|
| `repo_path` | yes | current working directory |
| `commit_sha` | no | `HEAD` (auto via `git rev-parse HEAD`) |
| `output_path` | no | `./scan.sarif` |

The repo should have a git remote (`origin`) so code and dependency findings auto-link. If
a repo has no remote, pass `--asset-ref <host/org/repo>` at push time (keyless SARIF, see D7).

⛔ **Never pass `--asset-ref` for an image scan.** An image's identity is its digest, which
every image finding already carries (`properties.torana.image`). Naming a repository would
claim the image was built from it. Until the platform accepts image-only SARIF (tracker P9),
`torana ingest sarif` rejects an image scan with a 422 "keyless" error: report that to the
user as a platform limitation, and do not work around it.

---

## Procedure

### Invocation contract — use what you were given; ask only for what's missing

This skill runs in two situations, and the difference is **what information the request
carries**, NOT who is calling. There is no reliable "caller" signal — do not try to detect
one. Instead, read the request for these parameters and act on each independently:

| Parameter | Values | If PRESENT | If ABSENT |
|---|---|---|---|
| `surfaces` / scan-types | `SAST` · `SCA` · `Secret` · `IaC` · `Container` · `all` | run exactly those, don't re-ask | ask (question 2 below) |
| `depth` | `shallow` · `deep` | use it (only relevant when SAST in scope) | ask (question 3 below) — SAST only |
| `mode` | `list-only` (A) · `push` (B) | do that, don't re-ask | ask (question, "Two modes") |
| `base_sha` | a commit sha | **diff-scan** against it (post-fix delta) | full scan of the working tree |
| `image` | image ref | Container scan targets it | ask only if Container is in scope |

**The rule:** for every parameter the request already specifies, use it and do NOT re-ask.
Only interview the user for the ones that are missing. A request that carries all of them
runs silently end-to-end; a bare request (a human typing "scan this repo") is missing all of
them and gets the full interview below — same skill, same code, the questions just fall away
as the answers arrive.

**Why this shape, not "if a skill invoked me":** an orchestrating skill (e.g.
`torana-alert-triage`) asks the human *once* up front ("re-scan deep or shallow?") and then
passes `depth` down on each call so the loop isn't a Q&A gauntlet. It doesn't need to announce
itself — supplying the parameter *is* the signal. Equally, a parent that wants the human
consulted simply omits the parameter, and the interview fires here. The behaviour keys off
information you can actually see in the request, never off a caller identity you can't.

**Common parameterized calls** (all just subsets of the interview, pre-answered):
- SCA/advisory only (what `torana-impact` needs): `surfaces=[SCA], mode=list-only` → run Step 2 (OSV) only, skip the rest.
- SAST before a fix: `surfaces=[SAST], depth=<chosen>, mode=list-only`.
- SAST after a fix: same + `base_sha=<pre-fix sha>` → diff-scan delta.

---

**Ask up front about scope, scan types, depth, engines, and mode** (in that order) — **for
any not already supplied per the contract above**. For the ones you must ask, these are
**required questions**, not hints — ask each one; don't silently pick a default.

**1. Scope — one repo or the whole fleet?** First look at the target path:

```bash
# How many git repos are at/under the target? (1 = single repo; >1 = a fleet)
find "${REPO_PATH:-.}" -maxdepth 2 -name .git -type d | wc -l
```

- If the target is a **single repo** (its own `.git`), scan it directly (Steps 0–6 below).
- If the target is a **directory containing several repos** (or the user says "all" /
  names an org), this is a **fleet scan** — **offer it explicitly** rather than making
  them pick one:

  > *"`<dir>` holds N repos — do you want me to scan (a) one of them, or (b) all N
  > (fleet)?"*

  For the fleet path, use `references/fleet_scan.py` (see "Fleet scanning" below):

  ```bash
  python3 "$SKILL_DIR/references/fleet_scan.py" --root "$REPO_PATH" \
      --out-dir ./fleet-out --concurrency 4   # add --push for Mode B
  ```

  When the target is clearly a set of repos, "scan all" is a first-class option —
  offer it rather than making the user pick one.

**2. Scan types — which to run?** Offer the five scan types and let the user pick one,
several, or all (default **all**):

> *"Which scan types do you want? `SAST`, `SCA` (dependencies), `Secret`, `IaC`,
> `Container` — pick one or more, or `all` (default)."*

There is exactly **one engine per type**, so this is the real selection lever — the user
picks *scan types*, not engines. Map the answer to what runs:

| Scan type | What runs | How it's driven |
|---|---|---|
| **SAST** | Claude review (Step 1) + `semgrep` | Claude-review findings + `--scan-types SAST` on the Scan Pack |
| **SCA** | OSV (Step 2) | run Step 2; OSV is **not** a Scan-Pack engine |
| **Secret** | `gitleaks` | `--scan-types Secret` |
| **IaC** | `trivy-config` | `--scan-types IaC` (only fires if IaC files exist) |
| **Container** | `trivy-image` | `--scan-types Container` **and** pass `--image <ref>` |

Carry the selection as a comma list into `scan_pack.py --scan-types <...>` (Step 4) — omit
it or pass `all` for everything. **Only run the sub-scans the user selected:** skip Step 1's
Claude review if SAST wasn't chosen, and skip Step 2 (OSV) if SCA wasn't chosen. A selected
type with no target in the repo (e.g. IaC but no `.tf`/Dockerfile) is skipped with a clear
message — that's expected, not an error.

**3. Depth — shallow (fast) or deep?** Whenever **SAST is in scope** (selected, or `all`), you
MUST ask which SAST depth to run — do not default silently:

> *"For SAST, do you want (a) a **shallow/fast** scan (semgrep + Claude review — quick, free),
> or (b) an additional **deep** agentic pass (VVAH — threat-model → taint → adversarial verify;
> slower and token-costly)? Deep is off by default."*

- If the user picks **shallow** (or SAST isn't in scope), skip the deep tier — nothing to do.
- If the user picks **deep**, the deep tier is VVAH (the Visa harness) — a stronger agentic SAST
  engine that layers on SAST (it is *not* a new scan type).

  > **⚠ The skill NEVER runs VVAH itself. You (the model) do NOT launch `vvaharness scan`.** VVAH
  > is LLM-driven: its `cli` backend shells out to `claude`, and running that from inside this
  > Claude session nests `claude` in `claude` with `stdin</dev/null` → it hangs forever; its `sdk`
  > backend needs an API key, which you must **never** ask the user to paste into the chat. So the
  > skill's job for the deep tier is only: **provision → estimate → hand the user a command they
  > run themselves → ingest the file they produce.** `vvah_run.py` guards the run path and will
  > refuse a `cli` run inside Claude Code, so don't try.

  Do these in order:

  1. **Provision VVAH** (self-install, safe — just pip, no LLM). If `vvah_run.py` reports it's
     absent: `bash "$SKILL_DIR/references/install_engines.sh" --engines vvah` (git clone a pinned
     ref + `pip install .` into the isolated venv). Never ask the user to install it.
  2. **Show the cost scope** (safe — no LLM spend):
     `python3 "$SKILL_DIR/references/vvah_run.py" --repo "$REPO_PATH" --estimate-only`
  3. **Ask the user how THEY will run it** (they run it, not you) — present exactly this:

     > *"You'll run VVAH's deep pass yourself in a separate terminal (it can't run inside this
     > session). How do you want to authenticate it?*
     > *(a) **Claude Code login** — no API key; uses your Claude subscription, or*
     > *(b) **API key** — you set `ANTHROPIC_SDK_API_KEY` in your terminal / a `.env` file (never
     > here)."*

  4. **Give them the ready-to-run command** for their choice (`--backend cli` for (a),
     `--backend sdk` for (b)) — relay its output **verbatim**:
     ```bash
     python3 "$SKILL_DIR/references/vvah_run.py" --repo "$REPO_PATH" --print-command --backend cli
     # or: --backend sdk
     ```
     It prints the exact `vvaharness scan … --stop-after s9` command (pointing at the installed
     venv, nothing else to install), the terminal-side auth step, and where the SARIF lands
     (`<repo>/security-scan/*_report.sarif`). Tell them it takes a few minutes.
  5. **When the user says it's done, locate the output file and show them the link:**
     ```bash
     ls -t "$REPO_PATH"/security-scan/*_report.sarif 2>/dev/null | head -1
     ```
     Print that absolute path back as the clickable output file. If none found, the run didn't
     finish — have them re-check the other terminal.
  6. **Ingest it** — fold that file into the scan as the `vvah` run (this is the skill's job):
     `scan_pack.py --repo . --scan-types SAST --deep-sarif <that_report>.sarif` (add `--findings`
     for the Claude review + `--osv` as usual), then list (or push) as in Step 5/6.

  Invariants:
  - **Never paste an API key into the chat.** For the key path, auth happens only in the user's
    terminal (`export ANTHROPIC_SDK_API_KEY=…` or a `.env` VVAH auto-loads).
  - **Detection-only** — the handoff command always carries `--stop-after s9`; a plain VVAH scan
    edits source (S10 fix mode), which must never happen.
  - **You never launch or background `vvaharness scan`.** Provision, estimate, hand off, ingest.
    It merges as a `vvah` run (scan_type SAST) into the same document/scan_id.

**4. Engines — offer to install missing ones.** Run the preflight — it reports exactly
which engines resolve (the scanner's own local-bin → PATH order) and which are missing,
so the offer is driven by a command result, not a guess:

```bash
python3 "$SKILL_DIR/references/scan_pack.py" --preflight
```

If its output ends with an `ACTION:` line, engines are missing — follow it.

**If any engine is missing, you MUST offer to install it before scanning.** The only
two reasons to skip silently: every engine is already present, or you're in the
no-shell Claude **Desktop** sandbox (can't run binaries). Anywhere you can run the
check above and download a file — including **Claude Code (CLI or any IDE)** — counts
as a full shell, so the offer applies. Repo contents are never a reason to skip: the
user may want the engines for the next scan, and that's their call.

Make it a real choice, not just a mention of the script:

> *"Trivy and Gitleaks aren't installed, so IaC / secret / container scanning would
> fall back to Claude review. Install the pinned engines now (`install_engines.sh`,
> ~1 min, checksum-verified) for real-engine results, or proceed with the fallback?"*

- On install: run `bash "$SKILL_DIR/references/install_engines.sh"` (optionally
  `--engines trivy,gitleaks`), confirm they resolve, then continue.
- Otherwise: proceed; Claude review covers the uninstalled domains.

**5. Mode — list-only or push?**

> *"Do you want me to (a) scan and just list findings locally, or (b) scan and
> push the results to Torana?"*

If unspecified, default to **(a) list-only** and offer (b) at the end. Mode applies
to both single and fleet scans (fleet honors it via `--push`).

---

### Step 0 (both modes). Ensure an asset record exists — create one if missing

Identity + governance come from the asset path, not the scanner. **Before
scanning, always check for an asset record; if none exists, create one by
invoking the `torana-asset-inventory` skill** — do not fabricate governance here
and do not skip this step.

```bash
ls asset-inventory.json 2>/dev/null   # local asset file?
```

- **If `asset-inventory.json` is present**, reuse it (passed to
  `build_sarif.py --asset`).
- **If it is absent**, **invoke the `torana-asset-inventory` skill** to create it
  (the skill derives identity from the git remote + `gh`, asks the user for
  governance, writes `asset-inventory.json`, and — in Mode B — pushes it via
  `torana ingest assets` so criticality/owner/SLA land on the repository row).
  Only then continue to the scan.
  - In **Mode B (push)** this is **mandatory** — never push findings for a repo
    that has no asset record.
  - In **Mode A (list-only)** still offer to create it; it costs nothing and
    makes the later push one step.

The asset path and the scan path converge on the same source-neutral
`repo:<host>/<org>/<repo>` row — order does not matter, but the scan skill is
responsible for making sure the asset exists.

### Step 1. Walk the repo and build findings

Claude reads the relevant files directly. For each finding, build a dict (these
are normalized into SARIF `results` by `build_sarif.py`):

- `rule_id` — stable rule slug, e.g. `claude.xss.reflected`
- `title`, `description`
- `severity` — Title Case: `Critical`/`High`/`Medium`/`Low`/`Info`
- `scan_type` — `SAST` / `IaC` / `Secret` / `Container` (`SCA` for OSV)
- `cwe` — e.g. `CWE-79` (when known)
- `cve_id` — (when known; usually SCA)
- `file`, `line`, `code_snippet`
- `remediation` — one sentence (optional)
- `package` — SCA only: `{name, version, fixed_in, manager, dependency_type}`

Collect into `/tmp/findings.json` (a JSON list).

### Step 2 (optional). SCA via OSV

```bash
echo '[{"name":"lodash","version":"4.17.20","ecosystem":"npm",
        "manifest":"package.json","manifest_line":15,"dependency_type":"direct"}]' \
  | python3 "$SKILL_DIR/references/osv_lookup.py" > /tmp/sca.json
```

`osv_lookup.py` emits finding dicts (same shape as Step 1, `scan_type=SCA`,
carrying `cve_id` + `package`). Saved separately and passed via `--osv`.

### Step 3 (optional). Merge a semgrep run

If the user/CI ran `semgrep --sarif src --output semgrep.sarif`, pass it via
`--semgrep-sarif` — `build_sarif.py` merges that run verbatim and enriches it
with the repo link + scan id so it is no longer keyless.

### Step 4. Assemble the SARIF document

**Preferred (v2.1) — run the Scan Pack, which runs real engines AND merges for you:**

```bash
python3 "$SKILL_DIR/references/scan_pack.py" \
    --repo "$REPO_PATH" \
    --findings /tmp/findings.json \
    --osv /tmp/sca.json \
    --asset ./asset-inventory.json \
    --output "${OUTPUT_PATH:-./scan.sarif}" \
    --scan-types "${SCAN_TYPES:-all}"      # user's Step-2 choice: SAST,SCA,Secret,IaC,Container | all
    # --deep                             # add when the user chose DEEP in Step 3 (VVAH agentic SAST)
    # --deep-config sdk.yaml             #   optional: backend/budget config (default cli backend, no key)
    # --max-input-tokens 2000000         #   optional: cheap deep-tier cost pre-gate
    # --image registry/repo@sha256:...   # required when Container is selected (Trivy image)
    # --engines semgrep,gitleaks         # optional: finer ENGINE subset (below scan-types)
```

Only pass `--findings` (Claude review) when **SAST** was selected, and only pass `--osv`
when **SCA** was selected — `--scan-types` gates the binary engines, but OSV and Claude
review are separate inputs the skill controls.

`scan_pack.py` auto-detects domains, runs every installed pinned engine
(Trivy IaC/container, Gitleaks secrets, semgrep SAST), prints a per-engine
ran/skipped/failed summary, then calls `build_sarif.py` to merge all engine SARIF
**plus** the passed-through Claude `--findings` and OSV `--osv` into one document.
Secret-engine output is redacted at the write boundary. A missing engine is skipped
with a clear message — Claude review still covers SAST and any uninstalled domain.

Each engine line also reports its **coverage** when the engine can measure it:

```
✓ semgrep        293 finding(s)  [1500 files, 31 unparsed, 11 partial, 3 rule timeouts]
```

The same numbers land in `run.properties.torana.coverage`, so what the scan *missed*
travels with what it found instead of being reconstructable only by hand afterwards.

> ⚠️ **`rules_timed_out` is not stable across runs.** Semgrep's per-rule limit is
> wall-clock, so the same repo, ruleset and engine yield different counts under
> different machine load (observed: 3 on one run, 1 on the next, with
> `files_scanned` / `unparsed` / `partial` identical). Read it as *"at least this
> much was skipped on this run"* — never diff it between scans as though a code
> change caused the difference. A timeout means one RULE was abandoned on one file;
> every other rule still ran, so the file is covered and that rule is not.

> ⚠️ **Counts vary ±2 between identical runs, and pinning does not fix that.** Measured on
> one repo with the SAME frozen ruleset and the same commit: 292 then 294 findings, the
> difference being two `avoid-sqlalchemy-text` hits in one 4,900-line file. semgrep-core
> runs with `--timeout 5 --timeout-threshold 3` (its defaults, which this skill does not
> override): a rule near the 5s boundary finishes or doesn't depending on machine load, and
> once 3 rules time out on a file semgrep skips *the remaining rules on that file entirely*.
> Neither shows up in `rules_timed_out`. So a small count delta is not evidence of a code
> change — check `ruleset_status` first (an unpinned run used whatever the registry served
> that day), then expect engine noise. `--timeout 0 --timeout-threshold 0` would remove it,
> at unbounded wall-clock cost.

> ⚠️ **If the ruleset snapshot is missing, semgrep falls back to `--config auto`** and the
> console says `ruleset UNPINNED (auto)`. `--metrics off` is dropped with it — semgrep exits
> 2 on `auto` + `--metrics off`, because the registry call IS the metrics call — so an
> unpinned scan still runs, but it contacts semgrep.dev and sends telemetry.

> ⚠️ **Trivy picks its dependency parser by FILENAME.** Only `requirements.txt` matches pip,
> so a lock file named anything else (`requirements/requirements_lock.txt`) is never opened —
> not even when trivy is pointed straight at it. `trivy-fs` therefore declares
> `--file-patterns 'pip:.*requirements_lock\.txt'`, which reads those files in place.
> Measured: a repo whose only real dependency description was a 38-pin
> `requirements_lock.txt` stored 0 SCA findings — a zero indistinguishable from "we did not
> look". Widen the pattern when a new naming convention appears; the durable fix is to
> discover manifests in the repo and declare them.

> ⚠️ **`dependency_type` (`direct` / `transitive`) comes from Trivy's `Packages[]`, not its
> vulnerabilities.** Trivy puts `Relationship` on the package record (populated by
> `--list-all-pkgs`); `trivy_to_sarif.py` joins it per Result by `PkgID`, falling back to
> `name@version` (one package can be direct in one lock file and indirect in another). It
> stays **empty for pip `requirements*.txt` targets by design** — Trivy reports no
> relationship for them at all. Only true lock files (`uv.lock`, `poetry.lock`,
> `package-lock.json`, …) populate it. Do not chase those NULLs as a bug.

> ⚠️ **`--out-dir` is per-user (`/tmp/scanpack-<uid>`) and is cleared per engine
> before each run.** It used to be a fixed shared `/tmp/scanpack`: on a multi-user
> host the first account to scan owned it, later accounts could not write, their
> engines failed silently, and the leftover SARIF was reported as their result. An
> engine that cannot clear its own output (report or sidecar) now FAILS rather than
> inheriting someone else's answer. If you see `cannot clear stale output ... Pick a
> writable --out-dir`, that guard is doing its job.

**Manual fallback — call `build_sarif.py` directly** (e.g. you ran engines yourself):

```bash
python3 "$SKILL_DIR/references/build_sarif.py" \
    --findings /tmp/findings.json \
    --osv /tmp/sca.json \
    --merge-sarif semgrep=./semgrep.sarif \
    --merge-sarif trivy-config=./trivy-iac.sarif \
    --merge-sarif gitleaks=./gitleaks.sarif \
    --asset ./asset-inventory.json \
    --repo "$REPO_PATH" \
    --output "${OUTPUT_PATH:-./scan.sarif}"
```

(`--merge-sarif ENGINE=PATH` is repeatable for any native-SARIF engine;
`--semgrep-sarif <path>` remains a back-compat alias. `--osv` / `--asset` are
optional; at least one of `--findings` / `--osv` / `--merge-sarif` is required.
`--coverage ENGINE=PATH` is repeatable too — it attaches that engine's coverage
JSON to its run; `scan_pack.py` passes it automatically, so you only need it when
driving `build_sarif.py` by hand.)
The script derives the repo
URI + commit from git, stamps `versionControlProvenance` + `automationDetails`
(scan id) + `invocations` on every run, and prints the scan id. The document
carries **no tenant_id** — the server takes it from the caller's JWT.

If the script warns the SARIF is **keyless** (no git remote / asset_ref), push
with `--asset-ref <host/org/repo>` in Step 6. ⛔ **Not for an image scan:** its NOTE says the
image digest is the identity. Do not add `--asset-ref` (see Inputs above).

### Step 5. Show the findings (Mode A stop point)

```bash
python3 -c "
import json
doc = json.load(open('${OUTPUT_PATH:-./scan.sarif}'))
rows = []
for run in doc['runs']:
    eng = run['tool']['driver']['name']
    # Semgrep states its rating once per rule, not per result.
    rule_level = {x['id']: (x.get('defaultConfiguration') or {}).get('level') for x in run['tool']['driver'].get('rules', [])}
    for r in run.get('results', []):
        loc = (r.get('locations') or [{}])[0].get('physicalLocation', {})
        where = f\"{loc.get('artifactLocation',{}).get('uri','-')}:{loc.get('region',{}).get('startLine','-')}\"
        props = r.get('properties') or {}
        # The scanner's own rating; SARIF level as the fallback. Score only when a real one exists.
        sev = (props.get('torana') or {}).get('scanner_severity') or r.get('level') or rule_level.get(r['ruleId']) or '?'
        score = props.get('security-severity', '-')
        rows.append((eng, r['ruleId'], sev, score, where, r['message']['text'][:60]))
print(f'{len(rows)} finding(s):')
for eng, rid, sev, score, where, msg in rows:
    print(f'  [{eng:<13}] {sev:>8} {score:>4}  {where:<40}  {msg}')
"
```

Then ask: *"Want me to push these to Torana?"* If no → stop; the SARIF is at
`./scan.sarif`.

---

### Fleet scanning — many repos at once (v2.1, SC1)

To scan a whole set of repos (e.g. the `pantheon-*` org) instead of one, use
`references/fleet_scan.py`. It runs the Scan Pack per repo (real binary engines —
Claude review is single-repo only, not run at fleet scale), writes one
asset-tagged SARIF per repo, and a `batch_summary.json` roll-up.

```bash
python3 "$SKILL_DIR/references/fleet_scan.py" \
    --github-org torana-security \        # or: --root <dir> | --repos a,b,@file
    --out-dir ./fleet-out \
    --concurrency 4 --timeout 1800 --max-repos 100 \
    --scan-types "${SCAN_TYPES:-all}" \    # same choice as single-repo; per-repo binary engines
    --push                                 # omit to just produce SARIFs locally
```

One bad repo is skipped, not fatal; `batch_summary.json` records per-repo status,
engines, finding counts, and push receipts. Group-by-service rollup and scheduled
sweeps are deferred (need the asset graph / scheduler).

---

### Diff-scan — `--base <sha>` (post-fix delta, v2.4)

When a developer has just fixed a vulnerability and wants to know **before
merge** — *did my change close the target finding, and did it introduce a new
one?* — run a **surgical diff-scan** instead of a full re-scan:

```bash
python3 "$SKILL_DIR/references/scan_pack.py" \
    --repo "$REPO_PATH" \
    --base <base_sha> \                    # e.g. the branch point: git merge-base origin/main HEAD
    --findings /tmp/findings.json \        # Claude SAST review of HEAD (as usual)
    --osv /tmp/sca.json \                  # OSV/SCA of HEAD (as usual)
    --output "${OUTPUT_PATH:-./scan.sarif}" \
    --delta-output ./scan-delta.json \     # optional; defaults to scan-delta.json next to --output
    --scan-types "${SCAN_TYPES:-all}"
    # --base-findings /tmp/base-findings.json   # optional: Claude SAST re-run against the base worktree
    # --base-osv /tmp/base-sca.json             #           (so Claude/OSV findings participate in the delta)
```

What it does:

1. Computes the **changed-file set** `git diff --name-only <base>..HEAD` (+ changed manifests for SCA).
2. Scans **HEAD** restricted to that set (each engine's SARIF is post-filtered by URI; `--findings`/`--osv` are filtered too).
3. Scans **`<base>`** restricted to the **identical** set **in an isolated `git worktree`** — the developer's in-progress fix is **never** checked out, stashed, or disturbed.
4. Emits a **fixed / new / unchanged delta** by set operations on `partialFingerprints` (no new fingerprint scheme) to `scan-delta.json`:

   ```json
   { "base_scanned": true,
     "fixed":     [ { "ruleId": "...", "uri": "auth/login.py", "message": "..." } ],
     "new":       [],
     "unchanged": [],
     "counts": { "fixed": 1, "new": 0, "unchanged": 0 } }
   ```

   The target finding moving to `fixed[]` is the machine-checkable proof the fix
   worked; an empty `new[]` is the "introduced nothing" answer.
5. Stamps `run.properties.torana.base_revision = <base>` (run-level) into the HEAD SARIF, so a
   later `"$TORANA" ingest sarif` carries the base marker.

**Why both scans are restricted to the *same* changed set:** a finding in an
**unchanged** file must never falsely appear as `fixed`. Restricting both sides
means only changed-file findings enter the delta; everything else is never
evaluated.

**base Claude/OSV findings:** `--findings`/`--osv` are HEAD-only inputs the skill
supplies. To let Claude-SAST / OSV findings participate in the delta (not just
the binary engines), re-run Claude review / OSV against the base worktree and
pass them via `--base-findings` / `--base-osv`. Without them, the base delta is
computed from the binary engines only, so a HEAD Claude finding in a changed
file classifies as `new`.

> **Local artifact only (T3 scope).** The diff-scan produces a correct local
> `scan-delta.json` and stamps the SARIF `base_revision`. **Server-side
> persistence of the delta, the PR Check-Run gate, and the rendered Fix-Impact
> delta panel are owned by a downstream task (T6)** — the ingestor does not read
> `run.properties.torana.base_revision` yet. T3 ships the client-side stamp + the
> local delta; the server read is deliberately not part of this skill.

### Mode B — Push to Torana

`torana-skill` already established `$TORANA` and an authenticated session. **Do
not re-run install or `auth login`.**

#### Step 6. Push the SARIF

```bash
"$TORANA" ingest sarif "${OUTPUT_PATH:-./scan.sarif}" --format json --raw
# keyless fallback, code or dependency scan with no git remote: add --asset-ref github.com/<org>/<repo>
# never for an image scan: it is rejected until the platform accepts image-only SARIF (tracker P9)
```

Expected receipt:

```json
{
  "scan_id": "sarif:01HXY...",
  "source": "sarif",
  "received_at": "2026-06-16T...Z",
  "counts": { "repositories": 1, "vulnerabilities": 5 }
}
```

Push requires `integrations:write`. Re-POSTing the same scan is idempotent
(returns the existing receipt). Verify with:

```bash
"$TORANA" ingest receipts "<scan_id>" --format json --raw
```

---

## OAuth scopes this skill needs

| Action | Scope |
|---|---|
| Push SARIF | `integrations:write` |
| Look up receipts | `integrations:read` |

`integrations:*` covers both.

---

## Error handling

| Symptom | Root cause | Fix |
|---|---|---|
| `build_sarif.py` warns "KEYLESS" | A code or dependency scan with no git remote, no `--asset-ref` and no asset `asset_ref` | Push with `--asset-ref <host/org/repo>` (D7) |
| `ingest sarif` returns 422 "keyless" on an image scan | The platform does not yet accept image-only SARIF (tracker P9) | Report it to the user as a platform limitation. Never add `--asset-ref` for an image |
| `ingest sarif` returns 422 "keyless" on a code or dependency scan | SARIF had no `versionControlProvenance` and no `asset_ref` | Add `--asset-ref` |
| `ingest sarif` returns 422 schema error | A finding produced an out-of-profile value | Read the JSON pointer; fix the offending field |
| `ingest sarif` returns 401 | OAuth scope missing `integrations:write` | Re-auth with the right scope |
| Findings land but no governance (criticality/owner) | Asset record not created | Run the `torana-asset-inventory` skill (Step 0) |
| Receipt arrives but `vulnerabilities` empty | Server in dark-write mode (no `datalake_client` wired) | Dev-stack config; confirm the service booted with a datalake client |

---

## Files in this skill bundle

| File | Purpose |
|---|---|
| `SKILL.md` | This file. |
| `INSTALL.md` | Build + install instructions. |
| `references/osv_lookup.py` | OSV.dev SCA helper (emits SARIF-ready finding dicts) |
| `references/build_sarif.py` | Multi-run Torana-profile SARIF assembly + native-SARIF merge + secret redaction |
| `references/scan_pack.py` | Scan Pack router — runs pinned OSS engines, merges via `build_sarif.py` |
| `references/scan_pack.json` | Pinned engine manifest (Trivy, Gitleaks, semgrep) + install metadata |
| `references/install_engines.sh` | Bootstrap the pinned engines into `scan_pack/bin/` (checksum-verified) |
| `references/fleet_scan.py` | Fleet scanner — runs the Scan Pack across many repos → per-repo SARIF + `batch_summary.json` |
| `references/vvah_run.py` | Deep-tier runner (SC2) — runs VVAH agentic SAST detection-only (`--stop-after s9`), cost-gated, returns SARIF for merge as the `vvah` run |
| `references/tests/test_diff_scan.py` | Offline unit tests for the `--base` diff-scan + fixed/new/unchanged delta (fixture git repo; no live platform) |
| `references/trivy_to_sarif.py` | Converts Trivy's native JSON (`trivy-fs`, `trivy-image`) to Torana-profile SARIF, including the scanner's rating and each CVSS score with its vector and source |
| `references/semgrep_enrich.py` | Semgrep `post_process`: copies each rule's confidence, impact, likelihood and subcategory from Semgrep's JSON output onto its SARIF results |
| `wheels/torana_cli-*.whl` | Bundled CLI (added at build time by `make claude-skills`) |

---

## Changelog

- **v2.8.0 (2026-09-22)** — **Lock files Trivy skipped are read; direct/transitive no
  longer dropped.** (CF-1) Trivy selects its parser by filename and only `requirements.txt`
  matches pip, so `requirements/requirements_lock.txt` was never opened: one repo stored 0
  dependency findings while its only real dependency description (38 pins) went unread.
  `trivy-fs` now passes `--file-patterns 'pip:.*requirements_lock\.txt'` (in place, no
  staged copies). Measured: 7 → 45 packages evaluated on that repo; 18 → 24 findings on
  another. (CF-6) `dependency_type` was empty on every row: `trivy_to_sarif.py` read
  `Relationship` off the vulnerability record, but Trivy puts it on the package in
  `Results[].Packages[]` — the data was one array over. Now joined per Result by `PkgID`,
  falling back to `name@version`. Measured on a `uv.lock` repo: 119 findings went from
  all-NULL to 30 `direct` / 89 `transitive`. pip `requirements*.txt` targets stay NULL by
  design (Trivy reports no relationship for them).
- **v2.7.0 (2026-09-22)** — **Pinned semgrep ruleset; no per-scan registry call.**
  `--config auto` re-resolved the ruleset through semgrep.dev on every scan. It is not
  repo-aware: `config_resolver.py` requests the bare `<semgrep_url>/c/auto` (no project
  parameter), which 302-redirects to `/c/p/default` — the same ~1074 rules for everyone,
  with rule-to-file selection done locally from `languages:`. So `auto` bought no per-repo
  curation, only a network round trip per scan, forced telemetry, and no record of which
  ruleset produced a document. `install_engines.sh` gains an `http_snapshot` method: fetch
  `/c/p/default` once (`curl -L` — both URLs 302), check size and content, smoke-test it
  through semgrep BEFORE publishing it (semgrep aborts the whole config load on one malformed
  rule, so that must fail the install, not every later scan), and record source + fetch time
  in `<snapshot>.provenance.json`. Rulesets follow `--engines`. semgrep now runs
  `--config {rules} --metrics off`; `scan_pack.py` substitutes `{rules}` and stamps
  `ruleset_status` / `ruleset_source` / `ruleset_fetched_at` into the coverage block.
  **Deliberately no content digest**: the endpoint reorders the same rules on every fetch, so
  a raw hash reports drift that did not happen. A missing snapshot is not fatal — it falls
  back to `auto`, drops `--metrics off` with it, and prints `ruleset UNPINNED (auto)`.
  `scan_pack/rules/` is git-ignored and never packaged. **Not fixed:** reproducible counts —
  that is semgrep's `--timeout 5 --timeout-threshold 3` on large files, not the ruleset (same
  frozen ruleset and commit gave 292/294/293/292). *(Requires `make claude-skills` +
  reinstall, then re-run `install_engines.sh`.)*
- **v2.6.0 (2026-09-22)** — **Result identity on merged runs, coverage in the document,
  and a stale-output guard.** Found auditing a live scan whose numbers could not be
  reproduced. (1) **Merged SCA runs had no identity.** `_enrich_run` gave merged native runs
  provenance, a scan id and a `scan_type` but never a fingerprint, so only Claude-review
  and OSV findings were keyed (measured `osv 14/14`, Trivy `0`).
  `build_sarif._stamp_fingerprints` now stamps `toranaSkill/v1` on every merged **SCA**
  result with the same key as `_result_from_finding`. It is inert server-side (the
  ingestor ignores client fingerprints for SCA) and does not change any row id. Merged
  SAST/IaC/secret results are intentionally left unstamped — see the `partialFingerprints`
  row: the server already keys them line-drift-safe, and a client stamp would re-key every
  existing row. (2) **Coverage now ships**: `run.properties.torana.coverage`
  via the new repeatable `--coverage ENGINE=PATH`, fed from semgrep's native sidecar, with
  per-engine counts on the console. Parse errors already survived in
  `invocations[].toolExecutionNotifications`; *scope* (`paths.scanned`) did not, so a
  finding count could not be interpreted without re-deriving it by hand. Rule timeouts,
  previously invisible because semgrep exits 0 and the run stays `executionSuccessful`,
  are now reported. (3) **Stale output is no longer accepted as a result**: `--out-dir`
  defaulted to a fixed shared `/tmp/scanpack` and success meant "a parseable SARIF exists",
  with no check that this run wrote it — three consecutive scans reported
  `✓ semgrep 293 finding(s)` while semgrep was exiting non-zero and failing to write,
  each re-serving another user's day-old SARIF with a byte-identical finding set. The
  runner now clears the report AND its sidecars first (a stale `.semgrep.json` sidecar
  would otherwise feed `semgrep_enrich.py` and the coverage block) and fails loudly if it
  cannot, and `--out-dir` is `/tmp/scanpack-<uid>`. (4) `_SCA_MANIFESTS` gains `uv.lock`,
  `pdm.lock`, `requirements_lock.txt` and the `requirements*.txt` family — a uv-managed
  repo carries only `uv.lock` files, so the SCA domain never switched on and was skipped
  with no finding to be wrong about. (5) `trivy-image` gains `--list-all-pkgs`, so
  `dependency_type` resolves instead of being `None` on every container finding.
  **Not done:** `--metrics off` on semgrep — it cannot ship while `--config auto` is in
  place (semgrep hard-fails: the registry call IS the metrics call), so silencing
  telemetry requires pinning the ruleset first; a `_metrics_comment` in `scan_pack.json`
  records this. *(Requires `make claude-skills` + reinstall.)*
- **v2.5.0 (2026-09-15)** — **Severity/CVSS contract, release 1, and Semgrep false-positive
  signals.** Implements the skill side of tracker issues P10, P3 and P9
  (pantheon-tests `docs/classie-m2-platform-bugs-2026-09-14.md`) against the contract
  `docs/sarif_severity_cvss_contract_2026-09-15.md`.
  - **Trivy** (`trivy_to_sarif.py`): each finding carries Trivy's raw rating and its source,
    and each CVSS score with the vector and source from the same Trivy entry: v3 and v4
    separately, and v2 only when there is neither (so a v2-only CVE keeps its score).
  - **OSV** (`osv_lookup.py`): sends the advisory's own rating word, never the band computed
    from the score, and each published vector with its source.
  - **Claude review** (`build_sarif.py`): its rating travels as `scanner_severity` with source
    `claude_review`. The new fields pass through into `properties.torana`.
  - **Semgrep** (`scan_pack.json`, new `semgrep_enrich.py`): one run writes SARIF and JSON;
    confidence, impact, likelihood and subcategory are copied onto each result. No severity,
    score or CVSS field is added to Semgrep results.
  - **Image scans** (`SKILL.md`): never add `--asset-ref`; a keyless 422 on an image scan is
    a platform limitation until P9 is fixed.
  - **No placeholder scores** (release 2, shipped only after the platform's ingest change was
    deployed): `build_sarif.py` writes `security-severity` only from a real v3 or v4 score.
    A finding with no real score carries none, instead of a band constant (9.5/8.0/5.5/3.0/0.0)
    that ingest used to store as Medium and as a CVSS score. *(Requires reinstall.)*

- **v2.4.0 (2026-07-16)** — **Diff-scan (`--base <sha>`) + fixed/new/unchanged delta (T3).**
  `scan_pack.py` gains `--base`: it computes the changed-file set (`git diff <base>..HEAD`),
  scans HEAD and `<base>` restricted to the *identical* set (the base scan runs in an isolated
  `git worktree` — the dev's working tree is never touched), and writes a `scan-delta.json` with
  `fixed[]`/`new[]`/`unchanged[]` computed by set-ops on `partialFingerprints` (no new fingerprint
  scheme). `build_sarif.py` gains `--base` and stamps `run.properties.torana.base_revision`
  (run-level, beside `scan_id`) so a later ingest carries the base marker. Optional
  `--base-findings`/`--base-osv` let Claude/OSV findings participate in the delta. **Local artifact
  only** — server-side delta persistence + the PR Check-Run gate + the Fix-Impact panel are a
  downstream task (T6); the ingestor does not read `base_revision` yet, and this skill ships no
  server code. Offline unit tests in `references/tests/test_diff_scan.py`. *(Requires reinstall.)*
- **v2.3.2 (2026-07-08)** — **Deep tier is handoff-only: the skill never runs VVAH.** Following the
  `cli`-hang and the fact that an API key must never be taken in chat, the deep-tier flow is now
  **provision → estimate → hand the user a command they run themselves → ingest their output file**.
  Step 3 asks how the user will auth *their* run — **(a) Claude Code login** (no key) or **(b) API
  key** (set in their terminal / a `.env` VVAH auto-loads, **never in chat**) — then
  `vvah_run.py --print-command --backend cli|sdk` emits the exact `vvaharness scan … --stop-after s9`
  (pointing at the installed venv, with backend-appropriate terminal-side auth) and the SARIF output
  path; `scan_pack.py --deep-sarif <file>` ingests it. The skill does **not** launch `vvaharness scan`
  (guard still refuses a nested `cli` run). *(Requires reinstall.)*
- **v2.3.1 (2026-07-08)** — **Deep-tier `cli`-backend hang fixed (guard + run-outside path).**
  Live dogfood on juice-shop-extensions: a `--deep` run **hung at stage 1** — VVAH's `cli` backend
  shells to `claude`, and running it from inside the skill nests `claude` in `claude` with
  `stdin=/dev/null`, so the nested `claude -p` never gets input and wedges. **Fix:** `vvah_run.py`
  now **guards** — if the backend is `cli` and we're inside a Claude Code session, it refuses fast
  with an actionable message instead of hanging (`--allow-nested-cli` overrides). Added the
  **run-outside workflow**: `vvah_run.py --print-command` emits the exact `vvaharness scan …
  --stop-after s9` to run in a separate plain terminal, and `scan_pack.py --deep-sarif <path>` folds
  the produced SARIF back in as the `vvah` run. SKILL.md Step 3 rewritten: the reliable paths are
  **(A) `sdk` backend + API key** (runs in-skill) or **(B) run-outside + ingest** (no key, uses the
  subscription); the `cli` backend is never run from inside the skill. *(Requires reinstall.)*
- **v2.3 (2026-07-07)** — **VVAH deep tier (SC2), opt-in.** Adds an optional deep SAST pass
  via the Visa harness (VVAH), off by default. New `references/vvah_run.py` runs VVAH
  **detection-only** (`--stop-after s9` — never edits source), cost-gated (shows
  `vvaharness estimate` scope + a `--max-input-tokens` pre-gate; dollar caps via the config's
  per-stage `max_budget_usd`), default `cli` backend (Claude Code login, **no API key**), and
  returns SARIF that merges as a `vvah` run (SAST) into the same scan_id. `scan_pack.py --deep`
  invokes it (only when SAST is in scope); `fleet_scan.py --deep` threads it per repo.
  Depth is a **first-class up-front question** (Procedure Step 3, "shallow/fast vs deep") —
  the skill asks it whenever SAST is in scope, not a buried note; engines→4, mode→5.
  **Self-provisioned** like every engine: `install_engines.sh --engines vvah` source-installs a
  pinned commit into the isolated venv (VVAH isn't on PyPI). `build_sarif._NATIVE_ENGINES` gains
  `vvah→SAST`. Live-validated against vvaharness 1.1.0 (source install, estimate, corrected
  `--config`/`--repo-name` flags, all `--deep` gate paths). *(Requires `make claude-skills` + reinstall.)*
- **v2.2 (2026-07-07)** — **Scan-type selection.** The user now picks **which scan types
  run** (one, several, or all): `SAST`, `SCA`, `Secret`, `IaC`, `Container`. Since there is
  one engine per type, this is a scan-type menu, not an engine menu. `scan_pack.py` gains
  `--scan-types` (gates the binary engines by their manifest `scan_types`; `all`/omitted =
  every domain, i.e. prior behavior); `fleet_scan.py` passes it through per repo. `SCA` (OSV)
  and Claude-review SAST are gated by the skill, not the Scan Pack. Procedure adds a Step 2
  "Scan types" question (engines→3, mode→4). Engine *selection within* a chosen type stays
  automatic (pinned engine, else Claude-review fallback for SAST).
- **v2.1.1 (2026-06-27)** — **Deterministic engine preflight.** `scan_pack.py --preflight`
  (+ `--json`) reports engine availability via the scanner's own local-bin→PATH
  resolution and prints an `ACTION:` line when engines are missing; Procedure step 2
  runs it as the engine check, so the install offer is driven by a command result.
- **v2.1 (2026-06-26)** — **Scan Pack (SC0) + fleet scanning (SC1) + engine
  provisioning.** Adds `scan_pack.py` (domain auto-detect + pinned-engine router,
  graceful skip of uninstalled engines, local-bin→PATH resolution) and
  `scan_pack.json` (pinned Trivy/Gitleaks/semgrep + install metadata).
  `build_sarif.py` generalizes the semgrep merge into repeatable
  `--merge-sarif ENGINE=PATH` (any native-SARIF engine), stamps each engine's
  `scan_type`, and **redacts secret-engine values at the write boundary**.
  `install_engines.sh` provisions the pinned engines into `scan_pack/bin/`
  (verified against upstream checksums; semgrep via an isolated venv).
  `fleet_scan.py` runs the Scan Pack across many repos (org/root/list) →
  per-repo SARIF + `batch_summary.json`, with concurrency + cost caps.
  Engine selection is automatic by domain (no per-run menu); list-only vs push
  unchanged. Claude review stays a SAST engine and the fallback for any
  uninstalled domain. See `pantheon-docs/EM/Torana_Scanner_Implementation.md`.
- **v2.0 (2026-06-16)** — **SARIF-native rewrite.** Emits standard SARIF 2.1.0
  (Torana profile) via `build_sarif.py` and pushes with `torana ingest sarif`,
  replacing the proprietary scan envelope + `build_envelope.py` +
  `ingest scan-results`. Findings link to a source-neutral repository id and
  converge with the asset-inventory skill and VCS sync. Adds optional
  `semgrep --sarif` merge. Governance moved entirely to `torana-asset-inventory`
  (no more `vm-assets.yaml` requirement here).
- **v1.0 (2026-05-24)** — Initial standalone release (proprietary envelope).
