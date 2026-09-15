# Fix-impact rubric — "what does the fix move?"

The blast radius of a fix: the running things it ripples to, the owners to notify, and — for
config/secret findings — the part the graph **cannot** see. Lead with the small distinct
answer, not the raw edge dump.

## The three input shapes

### A. Package fix (SCA/CVE) → the affected service set
```bash
fix-impact analyze --changed-pkgs "pkg:<type>/<name>@<ver>" --direction both --json
```
- **Lead with `affected.service`** and `affected_counts` — the distinct running blast radius (e.g. `{service: 2, image: 28}`), NOT the raw `downstream` edge list.
- `upstream` = repos/services that *declare a dependency on* this package (the notify list). Empty on tenants with no SCA `depends_on` — say so.
- `owners` = the `team:` set to notify.

#### ⚠️ A pin answers "what did I disturb?" — a CVE asks "who is exposed?"
`--changed-pkgs pkg:x/y@1.2.3` returns **only that exact version's cohort.** A CVE affects a version
**range**, so seeding one pin under-scopes it — often badly. Measured on acme: `litellm@1.82.6` → **12
services**, `@1.74.15.post2` → **2**, `@1.81.13` → **1**. Same library, same CVE class, 6× spread decided by
which pin you typed.

**Never trust a version handed to you in the question.** A user pasting *"CVE-1234 (libfoo 1.2.3)"* is quoting
whichever row they happened to see — often the minority one. Resolve it from the data first:
```bash
torana datalake query --sql "SELECT package_installed_version, count(*) AS rows FROM vulnerabilities \
  WHERE cve_id='<CVE>' AND package_name='<name>' GROUP BY package_installed_version ORDER BY rows DESC"
```
A real example on acme: `CVE-2026-49468` is quoted as litellm `1.74.15.post2` (30 rows → **2 services**), but
the platform records it mostly on `1.82.6` (128 rows → **12 services**). Answering the quoted pin under-scopes
that CVE **6×**.

**Then enumerate the package's cohorts in the graph:**
```bash
torana datalake query --sql "SELECT to_key, count(distinct from_key) AS images FROM entity_edges \
  WHERE to_key LIKE 'pkg:<type>/<name>@%' AND edge_type='contains' GROUP BY to_key ORDER BY images DESC"
```
Then run fix-impact per cohort **whose version falls in the CVE's affected range**, and report the union.

| The question | Right seed |
|---|---|
| "I bumped this exact version — what do I disturb?" (fix-impact) | the **one pin** (its base version — see C) |
| "Who is exposed to this CVE?" (reachability / prioritization) | **every cohort in the affected range** |

Never present a single pin's cohort as a CVE's exposure. Say which you answered.
*(Automatic name-level widening is not built yet — do this enumeration by hand.)*

### B. Repo/SAST fix → the deployment chain
```bash
fix-impact analyze --repo "repo:<repo>" --direction both --json
```
- Returns the `repo → builds_image → image → deployed_as → service` chain (the services the fixed code ships to). `affected.service` rolls it up.
- If empty: check the repo key form (`repo:github.com/org/name`) and that the repo actually builds a container (`builds_image` edge).

### C. A PR / branch → derive the changed packages, then A
```bash
fix-impact analyze --repo "repo:<repo>" --base-sha "<b>" --head-sha "<h>" --repo-path "<checkout>" --direction both --json
```
- The CLI runs `git diff base..head` on the checkout's dependency manifests (requirements*.txt / go.mod / poetry.lock / package-lock.json) and derives the changed `pkg:` keys — you don't hand-list them. Read its stderr notes to see what it derived.

#### The radius keys on the BASE version — read the stderr line
The derivation splits what it found by **role**, and the stderr line tells you all three:
```
[fix-impact] derived from 17e11a84..ab912060: 1 base pkg(s) → blast radius; 2 head pkg(s) → target; names: pypi/litellm, ...
```
| role | meaning | used for |
|---|---|---|
| **base** | the version **currently deployed** — what this change disturbs | **seeds the blast radius** |
| **head** | the version you're moving *to* — not deployed yet, matches nothing | the target: check *it* for its own CVEs; verify after deploy |
| **names** | `<eco>/<name>` | name-level widening (see A) and range-pinned manifests that resolve no version |

**Why it matters:** seeding the head version matches **zero** images (nothing runs it yet), which is why this
path used to report "affects nothing" for every version bump. If you ever hand-seed a bump with
`--changed-pkgs`, pass the **base** version, not the fixed one.

**A newly-added dependency has no base version** → it contributes head+name only, and the radius comes from
`--repo`. That is correct, not a gap: adding a dependency disturbs nothing already running. Say exactly that
— do **not** claim other services already ship it.

**Range pins derive nothing.** Only exact `==` pins and lockfiles resolve a version; `litellm>=1.74.7,<1.75.0`
yields no key. If the stderr notes show 0 derived from a manifest you know changed, check for a range pin and
fall back to the name-level enumeration in A.

## The truncation flag
`truncated_reason="size"` ⇒ the node budget was hit; `affected`/`downstream` are a **shallowest-first sample**, not the complete set. Say so and suggest narrowing (`--max-depth`, or a specific repo/service).
> Do **not** narrow a CVE question by picking a more specific package version — that shrinks the number by
> changing the question (see A). Narrow the traversal, never the exposure.

## THE ONE RULE THE GRAPH CANNOT EXPRESS — semantic blast radius (trigger by CATEGORY, not a CWE list)
For any finding in the **credential / secret / token-semantics / shared-config** category, the
graph fix-impact is the **deployment only** — it does NOT capture the semantic reach. The trigger
is the **class of finding, not a hardcoded CWE number**: it fires whenever the fix means *rotating a
shared secret* or *changing what a shared token / credential / config carries or is trusted for*.

**In-category shapes (judge by the shape — this list is illustrative, NOT exhaustive):**

| Finding shape | Example CWEs | The semantic reach the graph misses |
|---|---|---|
| hardcoded / shared **secret or key** | CWE-321, CWE-259, CWE-547 | every service configured with / verifying it |
| hardcoded **credentials** | CWE-798, CWE-256 | every service that authenticates with them |
| **insufficiently-protected creds / token payload** | **CWE-522** | every service that **decodes and trusts** these tokens (they consume the exposed payload — no edge connects them) |
| **JWT signing / verification** | (any JWT-semantics finding) | every token **verifier** — grep the callers of the shared verifier (e.g. `pantheon_shared.jwt`) |
| shared **config / API key** a leak ripples through | (varies) | every service configured with the value |
| **fix lands in SHARED CODE** — a library, client, or middleware other services import | (any CWE — the trigger is *where the fix goes*, not what the bug is) | every service that **imports the changed symbol**, not just the repo that hosts it |

**The shared-code trigger is the one that looks least like "a secret."** Shape B (`--repo`) returns the
*hosting repo's* deployment chain — if the fix actually lands in shared surface, that number is the wrong
denominator. Measured on acme: a pantheon-auth finding whose fix site was `PantheonClient`
(`pantheon-shared/src/pantheon_shared/http/client.py:154`) shows **1 service** from the graph and
**12** in reality:
```bash
grep -rl "PantheonClient" --include=*.py pantheon-*/ | cut -d/ -f1 | sort -u
```
**So: before reporting a Shape-B number, check where the fix actually goes.** If the changed file lives in a
shared package (`pantheon-shared`, a `*-framework`, any lib the repo publishes), enumerate the importers and
lead with that count — the repo's own deployment chain is a floor, not the answer.

**Do NOT gate this on the CWE number matching a list** — that was the bug. CWE-522 (sensitive data
in a JWT payload) is squarely in-category even though it isn't "a hardcoded secret." When unsure,
**flag it** — a false "this is broader than the graph shows" costs a sentence; a missed one ships a
wrong "1 service" blast radius for a secret rotation.

**You MUST:**
1. Flag it explicitly in the brief: *"graph blast-radius = the hosting service's deployment; the REAL blast-radius is every {token verifier / secret consumer / token decoder} — not modeled by the graph."*
2. Read the code (or hand to `torana-alert-triage`) to enumerate the actual consumers.
3. NEVER present the graph blast-radius as complete for these findings.

This is the single case where fix-impact's honest answer is *"the graph shows X, but the true impact is larger and lives in the code."* Getting it wrong under-scopes a platform-wide rotation.

## Upgrade delta — "what's in the version I'm moving TO?" (SKILL.md Step 2b)

Fix-impact (§A) keys on the **base** (deployed) version and answers *what the change disturbs*.
This answers the opposite half of an upgrade: *what the target version introduces or clears*.
Do both for any upgrade/downgrade.

### Why the platform can't answer it — and who can

Torana scans **deployed** images, so `vulnerabilities` has rows only for versions that are
running. The target of an upgrade isn't deployed → **zero rows** → the graph and datalake are
silent. The answer lives in **OSV** (advisory-by-`name@version`), which **`torana-scan` owns**
(it is the SCA engine — CLAUDE.md GAP-A6). Do **not** reimplement OSV here.

**Invoke `torana-scan` advisory-only** (its Invocation contract: `surfaces=[SCA],
mode=list-only`) once per version — base and target — and diff the two advisory sets:

```
advisories(base)  vs  advisories(target)   →
   fixed[]       = in base, NOT in target   (the upgrade clears these — the win)
   introduced[]  = in target, NOT in base   (the upgrade ADDS these — the guardrail)
   unchanged[]   = in both                  (the bump doesn't help these)
```

### Enrich, then judge

- Severity/urgency of each CVE comes from the **local** `vm_cve_metadata` cache (KEV, EPSS,
  CVSS), keyed by `cve_id` — no deployment needed:
  ```bash
  "$TORANA" datalake query --sql "SELECT cve_id, cvss3_base_score, epss_score, kev_listed \
    FROM public.vm_cve_metadata WHERE cve_id = ANY(ARRAY['CVE-…','CVE-…'])" --json
  ```
- **Lead with the verdict, not the raw lists:** *"safe upgrade — clears 13 (incl. 2 KEV-listed),
  introduces 0 known"* or *"caution — clears 5 but introduces 1 High (CVE-…)."*

### The honesty guards (do not skip — these are the traps)

- **"0 introduced" ≠ "safe."** It means *none disclosed yet*. A just-released version is often
  too fresh to have findings, which looks identical to clean. Say **"none known,"** never "none."
  The **fixed** count is the trustworthy number; `introduced=0` is a soft signal.
- **OSV coverage varies by ecosystem** — strong for PyPI/npm/Go/crates, thinner for OS packages
  (deb/apk/rpm), where distro advisories are better. State per-ecosystem confidence.
- **Version absent from every advisory DB** → don't infer "clean." The honest escalation is a
  **real scan of an image built on the target** — hand that to `torana-scan` (full flow), it is
  not something to fabricate from advisory silence.
- **Fuse with reachability (the part only this skill can do):** *"the upgrade clears 13, but you
  import this only as an SDK and never touch the vulnerable component, so most never mattered —
  the real win is the 2 KEV CVEs in code you do call."* The CLI cannot make this judgement; you can.

For a PR, `derive_changed_pkgs` already returns `base` and `head` (the target). For a bare
"upgrade X to Y" question: base = the deployed cohort(s) of X, target = Y.

## Recording (Step 5, HITL only)
```bash
remediation "<remediation-id>" impact --compute --json   # persists → fix-impact-panel badge
```
Idempotent (re-compute overwrites the same report row). Needs a remediation id; without one, report the analysis and stop.
