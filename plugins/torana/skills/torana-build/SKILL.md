---
name: torana-build
description: >
  Build and deploy a Torana program end-to-end from the command line. This is the
  domain-AGNOSTIC platform BUILD engine: given an intent ("build me a program that …"), it
  grounds against the workspace's real data, authors the program, and stops for you to
  confirm deployment. From YOUR perspective there are exactly two actions — BUILD a program,
  then DEPLOY it. Everything in between (planning, generating artifacts, validating them) is
  internal machinery shown only as progress. Trigger whenever the user wants to build, create,
  generate, or deploy a program / app / workspace on Torana — "build me a program", "create a
  dashboard program for X", "deploy this proposal", "build and deploy Y". This skill carries NO
  domain knowledge (no vulnerability-management specifics); DOMAIN skills like `torana-vm` drive
  this engine by supplying the user's intent (verbatim) + their own domain grounding. Requires `torana-skill` for CLI/auth
  bootstrap. Drives the `torana build` CLI (the finalized build path).
metadata:
  version: "0.1"
  last_updated: "2026-07-16"
  status: "authoring"
  spec: "pantheon-agent-builder/docs/TORANA_BUILD_V2_SKILL_CONVERGENCE.md"
---

# torana-build — build & deploy a Torana program

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


You drive Torana's program-build state machine to turn an **intent** into a **deployed program**.
You author the plan and each artifact yourself, and step the machine through the `torana build`
CLI. The platform's data layer is your safety net — it will refuse to let you produce anything
incorrect, so build confidently and let its validation guide you.

## Harness rule — YOU author; the platform's agents don't

The `torana build` CLI exposes TWO harnesses over the same state machine:

| | Claude harness (THIS skill — the default) | Torana harness (platform agents) |
|---|---|---|
| Blueprint | `blueprint start` → **`blueprint save`** → `approve` | `blueprint run` |
| Cook | `cook start` → **`artifact add`** → **`artifact validate`** → `cook finalize` | `cook run` / `cook step` |

From a Claude session you ALWAYS use the author-and-submit verbs — you are the authoring
intelligence, grounded by this skill; the platform validates, gates, and deploys. **Never call
`blueprint run` or `cook run|step`** — those launch the platform's own authoring agents and are
reserved for the case where the user EXPLICITLY asks to exercise the platform build path (e.g.
dogfooding it). In that case say so in your reply and prefix the command with
`TORANA_HARNESS=platform ` — a PreToolUse guard hook blocks the bare form. Both harnesses land
in the same state machine, provenance, and deploy gates, so nothing is lost by authoring
yourself — and everything (grounding, keyspace checks, literal fidelity) is gained.

## The ONE principle: the user sees TWO verbs — BUILD, then DEPLOY

From the user's perspective there are exactly two actions:

1. **Build a program** — they give you an intent ("build me a program that tracks X and shows Y on
   a dashboard"); you produce a *deployable* program.
2. **Deploy it** — on their explicit confirmation, you make it live.

**Everything between is invisible machinery.** Internally the platform has a state machine
(intent → blueprint → cook → deployable → deployed), but **you must NEVER make the user drive those
phases.** Do not ask them to "create an intent," then "approve a blueprint," then "cook it." You run
the whole thing autonomously and surface the phases only as **progress narration** — "grounding
against your schema… planning the program… building the SLA transformer… validating…". The user
issues *one* build request and, later, *one* deploy confirmation. That's the entire contract.

If a domain skill (e.g. `torana-vm`) invokes you, it hands you the intent + domain grounding; the
same rule holds — you build autonomously and stop at deploy. **Keep the two separate:** the
**intent** is the user's business context (their words — a short promise) and goes to `--intent`
untouched; the **grounding** is the domain skill's analysis and goes into the **blueprint
`grounding`**, never into `--intent`.

## First, always: bootstrap + gate

1. **Auth/context** (via `torana-skill`): run `torana auth me` — confirm the logged-in identity and
   that you are operating as the **correct tenant** (the workspace owner). Never build as the wrong
   tenant.
2. **Capability gate** — run `torana build capabilities --json` BEFORE building. This returns the
   platform's `definition_schema_version`, `fsm_contract_version`, the artifact-type list, and the
   **artifact-definition JSON schema** you author against. Two rules:
   - **Version check (MAJOR only).** This skill supports **definition-schema major `1`** and
     **fsm-contract major `1`**. Parse `major = int(version.split(".")[0])` for both. If either major
     is **not 1**, or the `capabilities` call **404s** (endpoint absent = you cannot verify
     compatibility), **REFUSE to build** and tell the user plainly: *"This platform serves build
     schema v{X}/FSM v{Y}; I support major 1 of each. A breaking change means I might author
     artifacts the platform would reject. Update the skill (or use the platform's own builder) to
     build here."* A **minor** difference (e.g. platform `1.4`, you know `1.0`) is fine — proceed;
     the schema grows by adding optional fields.
   - **NEVER bundle or hard-code the schema.** Always author each artifact's `definition` against the
     schema you just fetched. If you carry a stale copy, you will drift and produce rejects.

See `references/authoring.md` for the exact build loop, the blueprint shape, and every authoring rule.

## BUILD (verb 1) — autonomous, narrated as progress

On a build request, run this whole loop yourself (details in `references/authoring.md`):

1. **Ground** — read the workspace's REAL schema (tables/columns), entity graph, and policy via
   `torana` reads. Never author SQL against imagined columns. Narrate: "grounding against your data…".
2. **Create the proposal** — `torana build proposals create --workspace-id <WS> --intent "…"
   --title "…" --built-via claude_skill`. (Always pass `--built-via claude_skill` so the card shows
   "Built with Claude".) This is internal — the user just said "build X".
   **`--intent` is the user's business context — their words, a short promise (one or two
   sentences), rendered verbatim on the proposal card.** Pass the user's actual request through
   (at most lightly cleaned into a sentence that preserves their meaning). Do **NOT** stuff your
   grounded analysis — the funnel logic, KEV/EPSS/reachability, thresholds, SQL rationale — into
   `--intent`; that belongs in the blueprint `grounding` (step 3) and is not shown on the card. A
   card whose intent is a wall of technical prose has overwritten the user's intent — that is the
   bug this rule prevents. (The platform's C2 floor is a trivial 20 chars / 2 words — it never asks
   for a verbose intent; a short, honest promise is correct.)
3. **Plan (blueprint)** — author an ordered, grounded set of steps and approve it:
   `blueprint start` → `blueprint save --blueprint-file bp.json` → **`proposal <id> validate --phase
   blueprint`** → `blueprint approve`. **No user gate here** — show it as progress ("planning the
   program…"), not an approval request.
4. **READ THE CATALOG BEFORE YOU AUTHOR ANY SQL.** The platform ships **reviewed, validated SQL definitions** (`vm.tf.*`) — a flaw on an asset, an asset's posture, SLA
   clocks, exploited findings. Each was authored once, reviewed, and validated against the
   real schema. Authoring a fifth variant of "open finding on one asset" is how a platform
   ends up with five subtly different answers to the same question.

   Read the whole catalog **once**, at the start of the build:

   ```bash
   TORANA_PROFILE=<P> torana vm transformers catalog list
   ```

   The whole catalog — id, what each answers, and its grain — is ~5k tokens. Small enough to
   read whole, which means there is no query to phrase, no ranking to trust, and no cut-off
   that can hide the right entry. Hold the list for the build and adjudicate every relation
   against it. (`catalog search` exists but is **not** for this: it ranks by resemblance to
   words you choose, and the words for a *need* rarely match the words for a *shape*.)

   **Narrate every decision.** The user is watching; the reuse decision must be visible
   as it happens. Per relation print: what you are looking for, the entries you
   considered (quote each one's `one row` grain — you have it in the list), the
   decision, and the AXIS on which you rejected the closest. "No good match" is an
   assertion; "em_012 is finding-grain, I need action-grain" is checkable.

   * **An entry that SATISFIES the need** (your judgement — the platform neither ranks nor
     filters) → reference the entry by id. **Do not copy its SQL into your artifact.**
     Copying forks the definition, and the fork drifts — that is the exact failure the
     catalog exists to prevent.
   * **None that fits** → record the miss, then author. The record is not paperwork; it is what turns
     your gap into the next catalog entry:

   ```bash
   TORANA_PROFILE=<P> torana vm transformers catalog record-miss "<need>" \
     --gap-category <category> --near-miss <closest entry id> \
     --rationale "<why no entry fits — be specific: wrong grain? missing column? different population?>"
   ```

   Then set the decision id on the artifact definition and deposit as usual:

   ```jsonc
   // REUSE — an entry satisfies the need. NO `sql` key at all.
   { "name": "...", "destination_table": "...",
     "catalog_entry_id": "vm.tf.open_finding_base" }

   // AUTHOR — no entry fits, and you recorded why.
   { "name": "...", "destination_table": "...", "sql": "SELECT ...",
     "catalog_decision_id": "<the id record-miss returned>" }
   ```

   **Set exactly one of `catalog_entry_id` / `sql`.** Both → rejected: deploy reads
   `sql` first, so the entry id would sit in the definition looking authoritative while
   being ignored — a silent fork wearing the catalog's name. Neither → rejected: a
   transformer that produces nothing.

   **The API rejects an authored deposit without a decision id** — a 400 from the
   platform, not a lint you can talk past, and it verifies the row exists rather than
   trusting the id you send. (`catalog_eligible=true` is the equivalent opt-in on the
   *direct* `POST /transformers` backstop — a different surface, for callers that skip
   the build path entirely. On an artifact definition you set the two fields above.)

   **If the entry is not yet materialized for this tenant, that is NORMAL — not a
   blocker.** Materialization is an INSTALL side-effect, not a user action and not
   something you call: `materialize`/`release` are service-to-service writes invoked by
   the install path with a service JWT, deliberately not exposed on the CLI (exposing
   them would let a caller mutate refcounts out of band). Check status with:

   ```bash
   TORANA_PROFILE=<P> torana vm transformers materialized     # what THIS tenant has built
   ```

   A materialization is **refcounted**: N programs needing the same shape point at ONE
   physical table, and it is torn down when the last one releases. So your job is to
   DECLARE the dependency by entry id and let install resolve it — never to build the
   relation yourself because it is not there yet.

   ⚠️ **Never inline a catalog entry's SQL because the table does not exist yet.** That
   converts a shared, refcounted relation into a private copy that will drift — the exact
   failure the catalog exists to prevent, wearing the disguise of progress.

5. **Build the artifacts (cook)** — `cook start`, then per blueprint step: author the typed
   `definition`, `artifact add … --source-step <step_id>`, `artifact validate <id>`. Validation is
   the platform's hard gate (real SQL EXPLAIN). On a `rejected` artifact, read the reason, repair,
   `artifact edit` + re-validate — **at most 3 attempts per artifact**, then `cook fail --reason …`
   and stop (never loop). Finish with `cook finalize` → the program is **deployable**.

   ⛔ **`artifact add` carries three CALLER-OWNED fields. New SQL without one is REFUSED.**

   ```
   --catalog-entry-id <id>        REUSING a catalog entry (and then carry NO sql)
   --catalog-decision-id <id>     you authored new SQL after recording a miss
   --required-integrations a,b    what must be CONNECTED for this to return data
   ```

   The domain skill decides *which* — it adjudicated the catalog. You **pass it through**.
   Until these existed the values could only be smuggled inside `definition`, which is why the
   catalog gate was unsatisfiable from this path: the gate demanded a decision the deposit
   contract had no way to carry.

   `--required-integrations` is **reconciled, not trusted**: the server independently derives
   the set from what the SQL reads and records any disagreement as evidence. Both values are
   kept — a declaration that does not match what the SQL actually reads is a defect worth
   surfacing, not a value to overwrite. A mismatch does **not** block the deposit.

6. **Read the build back before you report it.** After `deploy`, run
   `torana admin build trace <proposal-id>` and show the user its SUMMARY line. A build that
   cannot explain itself is not finished being built — and the trace is where a silent
   problem (a gate refused twice before passing, a step that hardcoded a policy value)
   becomes visible instead of shipping quietly.
   *(`admin build trace` is SA-only; from a tenant profile it 403s. Do the exercise below
   regardless — it is the half that catches what the trace cannot.)*

   ⛔ **6b. EXERCISE THE PROGRAM. `deployed` is not `working`.** The deploy result reports
   whether artifacts were WRITTEN, never whether they DO anything. Measured 2026-08-28: a
   build deployed 22/22 green with a KEV→Slack route that could never fire — its
   `source_rule_ids` held an artifact key instead of a rule UUID, so every alert fell through
   to the catch-all queue and **nothing reached `#security-alerts`**, the build's headline
   requirement. Every gate passed. Only running it exposed this.

   For anything that ALERTS or ACTS, before you report success:

   ```bash
   TORANA_PROFILE=<p> torana rule <id> execute          # does it match rows at all?
   TORANA_PROFILE=<p> torana alerts list --workspace-id <ws>
   TORANA_PROFILE=<p> torana alert <alert-id> provenance   # WHICH route + playbook claimed it
   TORANA_PROFILE=<p> torana alert <alert-id> activities   # what actually ran
   ```

   Check the alert was claimed by the route you INTENDED, not merely by *a* route. Then verify
   at the external system itself — read the Slack channel, check the ticket — never from the
   execution record: playbook executions report `agent_actions: []` and `tool_calls: null` even
   when a message was demonstrably posted.

   ⚠️ **Do NOT resolve or delete an alert to "re-run it clean".** Detection-signal dedup is
   durable and survives both — the rule returns `Results: 0` forever after, while the same SQL
   still returns the rows, and there is no CLI verb to clear it. Two CVEs were made permanently
   unalertable this way. Inspect alerts; never recycle them.
7. **STOP at deployable.** Narrate what was built, present the concrete validated artifacts, and
   **ask the user to confirm deployment.** Do not auto-deploy.

### Always validate completeness BEFORE you deposit (self-check, then correct)

The platform enforces deterministic **completeness** rules (C1–C6) at the write boundary — a
proposal whose intent merely echoes the title, whose blueprint has no grounding, whose step
`produces` is a placeholder, or that names no policy is REFUSED. Don't discover that by eating a
4xx: **run `torana build proposal <id> validate` yourself before each deposit and fix what it
flags first.** The verb is read-only, returns `{valid, failures[]}`, and exits non-zero on
failure. Two checkpoints:

- **After `blueprint save`, before `blueprint approve`:** `validate --phase blueprint`. If it
  reports C3 (no grounding) / C4 (placeholder `produces`) / C5 (empty `policy_basis`), RE-AUTHOR the
  blueprint (`blueprint save` again with the fix) and re-validate — same disciplined loop as a
  rejected artifact, **at most 3 attempts**, then stop. Only approve a clean blueprint.
- **Before `cook finalize`:** `validate --phase program` (and a full `validate`). Fix any C1/C2
  (C1 = intent is a verbatim copy of the title; C2 = intent under the trivial 20-char/2-word floor —
  a real user request clears this easily) or C6 (a declared artifact type you didn't build) before
  finalizing. **C2 is a floor, not a target: never pad the intent with technical detail to "pass" it.
  If C2 trips, the user's promise was genuinely empty — write their actual ask, not your analysis.**

Beyond the deterministic rules, apply your OWN judgment: does the built manifest actually *realize
the intent*? The platform can't judge that — you can. A program that validates C1–C6 but doesn't do
what the user asked is still wrong; don't present it. (When a DOMAIN skill drives you, it owns this
substance judgment — see its always-validate rule.)

## DEPLOY (verb 2) — only on explicit confirmation

When the user confirms (a clear, on-topic "yes, deploy it" — not an ambiguous "looks good"):

- `torana build proposal <id> deploy`. The platform applies the whole manifest atomically and rolls
  back on any failure. Report the result (`deploy-status`). If it rolls back, report the reason —
  never leave a half-applied program.

## Stale proposals — REBASE, then stop at the deploy gate (never force)

A workspace can hold several deployable proposals. When one deploys, the app version advances, and
the others become **stale** — they were built against an older base of the app. A stale candidate is
one whose `anchored_on_version` is behind the workspace's current live version (visible in
`proposal show` / version data), a candidate in state `superseded`, **or** any `deploy` that returns
HTTP 409 `stale_anchor`.

**Do NOT deploy a stale candidate as-is, and do NOT `reanchor` it.** Deploying stale can silently
duplicate transformers already live, collide on names, or break the ordering of live rules.
`reanchor` only re-validates and re-pins — it is blind to duplication and does not re-plan, so it is
NOT the fix.

**The fix is `rebase`.** Rebase re-derives the program's HOW against the current live system while
holding the frozen intent fixed — you re-author the blueprint against what's now live, the platform
diffs it against the old one, and ONLY the steps that actually changed are rebuilt (everything still
valid is reused). It lands the candidate back at **deployable** (or **superseded**, if the intent is
already fully delivered by what's live). It is BUILD-SIDE — it **never deploys**; the deploy gate is
unchanged.

**You (Claude) drive the rebase yourself** — the same way you drive a fresh build, just against the
live base. (There is also a platform-driven one-shot, `rebase run`, which the Torana UI button uses;
you don't need it — you self-drive with the deterministic `diff` + `apply` verbs so you see and
narrate exactly what's reused vs rebuilt.) When the user asks to deploy a stale candidate (or a
deploy 409s `stale_anchor`):

1. **Explain, then re-blueprint.** Tell the user: *"This program was built when the app was on
   v{anchored}, but it's now on v{live}. Deploying as-is could duplicate or conflict with what's
   already live, so I'll **rebase** it — re-evaluate against the current system and rebuild only what
   changed."* Then **re-author the blueprint** for the same frozen intent, grounded on the CURRENT
   live schema — exactly your normal Blueprinter job (fetch the intent from `proposal show`; ground
   with your usual reads). Write it to a file, e.g. `bp.json`. You do NOT need to preserve step ids;
   the diff matches by content.
2. **Diff (deterministic, no LLM):** `torana build proposal <id> rebase diff --blueprint-file bp.json`
   → `{reuse[], recook[], drop[], diff_token, outcome_preview}`. This tells you which steps are
   unchanged (reused, no re-cook), changed/new (recook), or gone (drop). Narrate the split.
3. **Apply:** `torana build proposal <id> rebase apply --blueprint-file bp.json --diff-token <token>`
   (use the `diff_token` from step 2 — if it 409s `rebase_stale_diff`, a deploy raced in; re-run the
   diff). Apply saves the fresh blueprint, drops absent steps, re-pins the anchor, and either marks
   **superseded** (nothing to build) or seeds the changed steps → **cooking**.
4. **Re-cook only the changed steps — yourself, same as a normal build:** if apply returned
   `cooking` (recook set non-empty), author each seeded step exactly like the normal build loop —
   per changed step: author the typed `definition`, `artifact add … --source-step <step_id>`,
   `artifact validate <id>` — then `cook finalize` → **deployable**. (If `superseded`, skip —
   there's nothing to build.) Do NOT reach for `cook run` here — that launches the platform's
   authoring agents (see **Harness rule** below); the seeded steps are yours to author.
5. **Two outcomes, then STOP:**
   - **superseded** — the intent is already fully delivered by live artifacts. Tell the user their
     program is already satisfied by what's live; there is nothing to deploy.
   - **deployable** — rebuilt against the live base, now safe to deploy. **STOP at the deploy gate**
     and ask for the user's explicit "yes, deploy" — same single human gate as any build. Do NOT
     auto-deploy after a rebase.

Never `reanchor` a stale candidate — it only re-validates and re-pins, blind to duplication and
re-planning. Rebase (re-blueprint → diff → apply → cook) is the fix. The platform also enforces the
stale gate (a stale deploy is rejected), so you cannot accidentally force one through.

## What you never do

- Never make the user drive the FSM phases (create/blueprint/cook as separate asks). Two verbs only.
- Never bundle the artifact schema — always fetch it (`build capabilities`).
- Never loop past 3 validate attempts on one artifact — `cook fail` and stop.
- Never deposit a hollow phase — `validate` before `blueprint approve` and before `cook finalize`;
  fix the completeness failures (grounding, real `produces`, policy) first. (Intent stays the user's
  short promise — never padded to pass C2; the substance lives in the blueprint grounding.)
- Never auto-deploy — the deploy gate is a real human confirmation.
- Never force-deploy a stale proposal — refuse and explain (rebase is coming).
- Never author domain-specific content on your own initiative — you're the engine; a domain skill (or
  the user's intent) supplies the *what*.
- **Never author SQL without searching the catalog first.** a library of reviewed definitions exists; a
  fifth variant of "open finding on one asset" is five subtly different answers to one question.
- **Never copy a catalog entry's SQL into an artifact.** Reference it by id. A copy is a fork,
  and a fork drifts.
- **Never inline a catalog entry's SQL because the table does not exist yet.** Declare the
  entry id; materialization is a refcounted INSTALL side-effect, not your call to make.
  Inlining turns a shared relation into a private copy that drifts.
- **Never call `materialize`/`release` yourself.** They are service-to-service writes with a
  service JWT, deliberately absent from the CLI. `torana vm transformers materialized` is
  the read you are allowed.
- **Never invent a `catalog_decision_id`.** The API verifies the row exists; a fabricated UUID
  is a 400, and the gate is there to make the gap visible rather than to be satisfied.

## Reference

- `references/authoring.md` — the exact build loop, the blueprint shape, per-step authoring rules,
  and how the platform validates (base transformers vs dependent SQL), plus the CLI verb map.
