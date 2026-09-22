---
name: torana-impact
description: >
  For a specific security finding (a SAST vulnerability or an SCA/CVE), answer the
  two questions around a fix decision and record the answer in Torana: (1)
  REACHABILITY — does this finding actually matter? Is the vulnerable code/package
  DEPLOYED, INTERNET-FACING, next to CUSTOMER DATA, and how CRITICAL is what it runs
  on? (2) FIX-IMPACT — what does the fix move? Which running services/owners does the
  change ripple to; for a package bump the affected service set; for a repo/secret fix
  the deployment blast radius plus the semantic blast radius the graph can't see.
  (3) UPGRADE DELTA — for a package version move (upgrade OR downgrade), what
  vulnerabilities does the target version ADD, REMOVE, or leave UNCHANGED versus the
  one you run? (the platform only scans deployed versions, so this uses OSV via
  torana-scan). Given an alert or vulnerability id, a PR, OR a "bump package X to
  version Y" question, the skill reads the finding, walks the entity graph
  (reachability), computes the fix blast-radius and/or the upgrade delta, synthesizes a
  brief, gets human confirmation, and optionally persists the report onto the
  remediation. Trigger whenever the user wants to: assess a finding's reachability or
  exposure, decide if a vuln matters, find the blast radius of a fix, see which services
  a change affects, check if something is deployed / internet-facing / near customer
  data, prioritize a finding, "what happens if I fix this", OR — for a version move —
  "what vulnerabilities would I add/remove by upgrading X to Y", "is it safe to bump
  X to Y", "compare the CVEs in version A vs B", "what's in the new version", or "should
  we upgrade/downgrade this package". Read-only analysis; human-in-the-loop before any
  write. Standalone skill — requires `torana-skill` for the CLI (and `torana-scan` for
  the upgrade delta's OSV advisory lookup).
metadata:
  version: "0.1.1"
  last_updated: "2026-07-20"
  platform_version_tested: "2026.1"
---

# Torana Impact — reachability + fix-impact per finding

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


> Given a finding, YOU (the agent) drive the `torana` CLI to answer **"does it
> matter?"** (reachability) and **"what does the fix move?"** (fix-impact), then
> record it. Every analysis step is a **read** — the only write is the optional
> final "record the report" step, which is **human-approved**. You are an analyst,
> not an actor. For the sibling question *"is it actually exploitable?"* use
> `torana-pentest`. Standalone skill — requires `torana-skill` for the CLI.

---

## Dependencies and Precedence

**`torana-skill` must be loaded first.** This skill does **not** bootstrap the CLI
or authenticate.

**`torana-scan` is required for the upgrade-delta** (Step 2b — "what's in the new version").
Torana only stores CVEs for *deployed* versions, so the target version of an upgrade has no
rows here; the advisory lookup that answers "is the version I'm moving to safer?" is OSV,
which `torana-scan` owns. When you need it, **invoke `torana-scan` with the advisory-only
parameters** (`surfaces=[SCA], mode=list-only`) so it runs just the OSV lookup and skips the
repo flow — see its "Invocation contract". Do not reimplement OSV here; scan is the single
SCA owner. (`torana-scan` also needs `torana-skill`, so this adds no new baseline.)

**Which CLI invocation to use — read this before the preflight.** There are two
shapes, and they do NOT mix:
- **Sandbox / Claude Desktop** (base `torana-skill` only): the CLI lives in a venv
  exported as **`$TORANA`** — call it as `"$TORANA" …`.
- **Local dev stack** (`torana-dev-skill` is loaded, or you were told to use a
  profile): call **bare `torana`** on `PATH`, prefixed with the profile, e.g.
  `TORANA_PROFILE=T1 torana …`. **`torana-dev-skill` precedence wins** — if it's
  loaded, ignore `$TORANA` and use the profile form for every command in this skill.

Pick one and use it consistently. Every `"$TORANA" …` command below is written in the
sandbox form; on the dev stack, substitute `TORANA_PROFILE=<profile> torana …`.

Preflight (sandbox form shown; dev-stack form in the comment):
```bash
"$TORANA" --version 2>/dev/null || echo "ERROR: no torana CLI — torana-skill's bootstrap has not run"   # proves a binary exists, NOT that torana-skill is loaded (Step 0)
"$TORANA" auth me 2>&1 | grep -q "^EMAIL" || echo "ERROR: not authenticated — run torana-skill's auth login"
# dev stack instead:  TORANA_PROFILE=<profile> torana auth me   (verify the right tenant is active)

# references/*.md live next to this SKILL.md. In an agent shell there is no $0, so resolve
# from the known skill roots rather than dirname "$0":
for d in "$HOME/.claude/skills/torana-impact" "$SKILL_DIR" ./skills/torana-impact; do
  [ -f "$d/references/reachability-rubric.md" ] && SKILL_DIR="$d" && break
done
```

**No harness, no external tools** — this skill only drives the `torana` CLI. It is
read-mostly; nothing is fired at any target (that is `torana-pentest`).

**Reads:** the finding (via the CLI). For the **fix-impact of a PR** and for the
**shared-secret semantic note**, run in a checkout of the finding's repository (so
`--base-sha/--head-sha` can diff it and you can read the code).

---

## What this skill does NOT do
- It does **not** fire anything at a target or prove exploitability — that is `torana-pentest`.
- It does **not** write anything without human confirmation (only the final record step writes).
- It does **not** present a graph blast-radius as complete for a **secret/config** finding — see Step 2's semantic note.

---

## Procedure

Full rubrics: `references/reachability-rubric.md` and `references/fix-impact-rubric.md`.
Command reference: `references/torana-cli.md`.

### Step 0 — Load & classify the finding
```bash
"$TORANA" vulnerability "<vuln-id>" get --json    # → repo, cwe_id, package?, source_file_path?, severity
```
Classify:
- **SAST** — has `source_file_path`, repo-scoped, **no package** → repo-based reachability + `--repo` fix-impact.
- **SCA / CVE** — has a **package** (`pkg:<type>/<name>@<ver>`) → package-based (mixed-direction) reachability + `--changed-pkgs` fix-impact.

### Step 1 — Reachability analysis — "does it matter?" (read-only)
Four clauses; compose them into a verdict (rubric has the tiers).

**a. Runs? (where is it deployed)**
```bash
# SAST — repo → image → service:
"$TORANA" entity-graph reachable "repo:<repo>" --via builds_image,deployed_as,exposed_via --direction forward --json
# SCA/CVE — package → services (MIXED direction; do NOT use --direction reverse, it false-negatives):
"$TORANA" entity-graph reachable "pkg:<type>/<name>@<ver>" \
  --via contains:reverse,deployed_as:forward,exposed_via:forward --json
```
No reached `service:` node → **not deployed → low urgency**. Report the finding, stop the escalation (do not error).

> **Two gotchas on the mixed-direction JSON:**
> - The top-level `"direction": "forward"` in the response is misleading — with mixed edges the *real* per-edge direction is in `edge_dirs` and each path's own `direction`. Read `edge_dirs`, not the top-level field.
> - A **broadly-deployed shared package** (e.g. a common lib in every image) returns a **large** result — 100 KB+, often auto-saved to a file — because `contains:reverse` fans out to every image carrying it. Don't try to eyeball it: the answer you want is the **distinct set of reached `service:` nodes** (dedupe `to_key` where it starts `service:`), which is small even when the raw path list is huge. (This is why Step 2's fix-impact leads with `affected.service`/`affected_counts` — the rollup, not the raw edges.)

**b. Internet-facing?** For each reached `service:`, read its exposure:
```bash
"$TORANA" datalake query --sql "SELECT torana_entity_id, public_access, criticality_name, has_customer_data FROM assets WHERE torana_entity_id IN ('service:...') AND is_deleted IS NOT TRUE"
```
`public_access=true` (per-service, discriminating) or an `exposed_via` edge ⇒ internet-facing.

> **`exposed_via` may be absent for the WHOLE tenant** (not just this service) — many clusters have only one internet-facing edge, or none. When there is no `exposed_via` anywhere, `public_access` is your *only* exposure signal; say so, and don't read "no exposed_via edge" as "internet-facing = confirmed no." (Contrast with the `accesses` sparsity note below — same shape: absence of an edge is not evidence of absence.)

> **Code-vs-graph exposure conflict — the finding's text wins for the caveat, the graph wins for the count.** If the finding's own description says the vulnerable code is a *public* endpoint (e.g. "public GET `/oauth/consent`") but the graph says the hosting service is `public_access=false`, do NOT silently pick one. The graph models *service* exposure (is the service fronted by a LB/Ingress); the finding describes a *route*. A route can be "public" in the app sense while its service sits behind the edge (nginx/api-gw). **Report both, and flag the tension:** "the service is graph-internal, but the finding describes a public route — reachable only through the edge; a human should confirm whether the edge exposes this path." Never present "internal-only" as final when the finding itself claims a public route.

**c. Data-adjacent?** The service's own `has_customer_data`, plus any `accesses` edge to a `customer-data` datastore:
```bash
"$TORANA" entity-graph neighbors "service:<env>/<name>" --type accesses --direction forward --json   # → datastore: nodes (may be sparse)
"$TORANA" datalake query --sql "SELECT datastore_id, engine, data_classification FROM datastores WHERE is_deleted IS NOT TRUE"
```
> `accesses` edges are sparse on secret-wired clusters — if none, fall back to the service's `has_customer_data` (the documented workaround). Do NOT claim "not data-adjacent" just because the edge is absent.

**d. Critical?** `criticality_name` on the service (from `assets`, or `"$TORANA" govern show "service:<env>/<name>"`).

**Verdict:** compose `deployed × exposed × data-adjacent × criticality`. The headline: *"running, internet-facing, next to customer data, high-criticality"*.

### Step 2 — Fix-impact analysis — "what does the fix move?"
```bash
# SCA / package fix → lead with the AFFECTED SERVICE SET (the rollup), not the raw edges:
"$TORANA" fix-impact analyze --changed-pkgs "pkg:<type>/<name>@<ver>" --direction both --json
#   read: affected.service[], affected_counts, truncated_reason
# SAST / repo fix → the deployment chain:
"$TORANA" fix-impact analyze --repo "repo:<repo>" --direction both --json
# Given a PR/branch → derive the changed packages from the local diff:
"$TORANA" fix-impact analyze --repo "repo:<repo>" --base-sha "<b>" --head-sha "<h>" --repo-path "<dir>" --direction both --json
```
Report: `affected.service` (or the repo→service chain) + `owners` + `upstream` (dependents). If `truncated_reason="size"`, say the set is a shallowest-first sample.

**SEMANTIC BLAST-RADIUS NOTE (mandatory — trigger by CATEGORY, not a CWE list).** For any finding in the **credential / secret / token-semantics / shared-config** category, the graph blast-radius is the *deployment* only — it does NOT capture the semantic reach. You MUST flag this, read the code (or hand to `torana-alert-triage`), and NEVER present the graph blast-radius as complete.

The trigger is the **class of finding, not a hardcoded CWE number.** It fires when a fix means *rotating a shared secret* or *changing what a shared token/credential/config carries or trusts*. Concretely, treat these as in-category (non-exhaustive — judge by the shape, not the list):
- hardcoded / shared **secrets & credentials** — CWE-321 (hardcoded crypto key), CWE-798 (hardcoded creds), CWE-259, CWE-256, CWE-522 (insufficiently-protected creds, incl. sensitive data in a JWT payload);
- **token semantics** — anything about what a JWT/session token carries, signs, or is trusted for (payload contents, signing key, verification);
- **shared config** a fleaked/changed value ripples through (a signing key, an API key, a connection secret consumed by many services).

The semantic reach to describe:
- **shared signing secret** → *every service that verifies tokens signed with it* (grep the callers of the shared verifier, e.g. `pantheon_shared.jwt`).
- **token payload / trust** (like CWE-522) → *every service that decodes and trusts these tokens* — they consume the exposed data even though no edge connects them.
- **shared credential/API key** → *every service configured with it*.

If you are unsure whether a finding is in-category, **err on the side of flagging** — a false "this is semantically broader than the graph shows" is cheap; a missed one ships a wrong "1 service" blast radius for a secret.

### Step 2b — Upgrade delta — "what's in the version I'm moving TO?" (package upgrades/downgrades only)

Run this **only when the change is a dependency version move** — an upgrade or downgrade of a
`pkg:` — i.e. the question is *"is the version I'm moving to any safer?"* Fix-impact (Step 2)
answers *what the change disturbs* (keyed on the deployed **base**); this answers *what the
change introduces or clears* (the **target**). They are different questions — do both for an
upgrade.

**Why a separate step:** Torana only scans **deployed** versions, so the target version has
**zero** rows in `vulnerabilities`. The graph and the datalake can say nothing about it. The
answer comes from **OSV**, which `torana-scan` owns — invoke it advisory-only and diff the two
version's advisories. See the full procedure (the two OSV calls, the fixed/introduced/unchanged
framing, severity enrichment via `vm_cve_metadata`, and the honesty guard) in
**`references/fix-impact-rubric.md` → "Upgrade delta"**. In short:

```
advisories(base)  vs  advisories(target)  →  { fixed[], introduced[], unchanged[] }
```

- **fixed** — CVEs the upgrade clears (the win). **introduced** — CVEs the target has that you
  don't (the guardrail — this is what catches an upgrade that trades one bug for a worse one).
  **unchanged** — present in both; the bump doesn't help these.
- **"0 introduced" means "none *disclosed* yet," not "safe."** State it as *none known*; a fresh
  release can simply be too new to have findings. The **fixed** count is the trustworthy signal.
- If a version is absent from every advisory DB, the honest escalation is a **real scan of an
  image built on the target** — that is `torana-scan`'s job, not something to fake here.
- Cross with reachability: *"clears 13 CVEs, but you only import this as an SDK, so most never
  mattered"* is the fusion only this skill can state — the CLI cannot.

The `derive_changed_pkgs` output already hands you `base` and `target` (its `head`) for a PR;
for a bare "upgrade X to Y" question, base = the deployed cohort, target = Y.

### Step 3 — Synthesize the brief

**The brief MUST open with an explicit tier label. This is not optional.** A brief without a tier has not
finished the job — the tier *is* the prioritization product, the thing that makes thousands of findings
survivable. Accurate prose that stops short of a label is a **failed run**.

```
TIER: <P0|P1|P2|P3> — <the one clause that decided it>
```

Then the statement:
> *"This finding matters because <reachability verdict>. Fixing it moves <affected services + owners>. <semantic caveat if secret / shared-config / shared-code>."*

**Required elements — state each, or state that you can't:**

| Element | Rule |
|---|---|
| **TIER** | always. Derive from the reachability rubric's table. If a clause is unknown, pick the tier the *known* clauses support and say which clause was unavailable — never silently omit the tier |
| **Reachability verdict** | deployed? internet-facing (and *via what*)? data-adjacent? criticality? |
| **Blast radius** | the number **and which question it answers** — one pin's cohort, or the CVE's full exposure (fix-impact rubric §A) |
| **Semantic caveat** | whenever the fix touches a secret, shared config, or **shared code** — say the graph number is a floor and give the widened one |
| **Empty vs absent** | `owners`/`upstream`/`accesses` empty ⇒ *not onboarded*, never *"no owners exist"* |

Deep-link the FE: the entity-graph (`/entity-graph`) for the reachability, the alert's fix-impact-panel for the recorded report.

> **Known tier caveat:** on an ingress-fronted tenant no app service is directly `public_access=true`, so
> under the current rubric nothing reaches **P0** and P1 is the ceiling. Note it when you emit P1 for
> something that is internet-reachable *through* an ingress — the tier table doesn't yet model that path.

### Step 4 — Human-in-the-loop (mandatory before any write)
Present the brief. Wait for explicit confirmation. The reachability + fix-impact **reads** above are safe to run unattended; **recording is not** — do not proceed to Step 5 without a yes.

### Step 5 — Record the report (optional, on confirm)

**Look the remediation id up yourself — never ask the human for it:**
```bash
"$TORANA" remediations list --vulnerability-id "<finding-id>" --json   # plural group; also --alert-id, --repo/--pr-number
```
```bash
"$TORANA" remediation "<remediation-id>" impact --compute --json   # persists → renders in the fix-impact-panel
```
`[]` ⇒ no remediation exists yet: report the analysis and stop — persistence follows a remediation.

> Collections are **plural** in this CLI, instance verbs singular. `remediation list` does not exist;
> `remediations list` does. A failed `<noun> list` is not proof the capability is missing — try `<noun>s`.

---

## Error handling & edge cases
- **Not deployed** (no reached service) → low-urgency; skip exposure/data-adjacency escalation, don't error.
- **Un-onboarded tenant** (`deployments exposure-intelligence` empty, `depends_on`=0) → `reachable` still works; fix-impact `upstream` will be empty — say so, don't imply "no dependents."
- **Secret/config finding** → never present the graph blast-radius as complete (Step 2 note).
- **`truncated_reason="size"`** → the affected set is a shallowest-first sample; suggest narrowing.

## Safety
Read-only analysis; the single write (`remediation impact --compute`) is human-gated and idempotent. No secrets read, nothing fired. If the user asks to prove exploitability, hand to `torana-pentest`; to author the fix/PR, hand to `torana-alert-triage`.

## Troubleshooting
- `reachable ... --direction reverse` returns only `contains` and no `deployed_as` → you used the old syntax; use the **mixed-direction** `--via contains:reverse,deployed_as:forward,exposed_via:forward`.
- `fix-impact --repo` returns empty → confirm the repo key form (`repo:github.com/org/name`) and that the repo has `builds_image` edges (a container build).
- `public_access` reads `true` for everything → the k8s workloads sync predates the per-service fix, or hasn't re-run; trigger `"$TORANA" deployments sync <id>`.
