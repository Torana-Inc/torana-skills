# Authoring reference — how to build a program (the internal loop)

This is the mechanism behind the user's "build a program" request. The user never sees these steps
as commands — they are your internal progress. **This file contains NO artifact schema** — you fetch
that at runtime from `torana build capabilities --json`. It documents the *process* and the fixed
shapes the platform enforces.

## The CLI verb map (what you drive internally)

All under `torana build` (the finalized build path). The proposal id resolves the workspace, so most
verbs don't need `--workspace-id`.

| Purpose | Command |
|---|---|
| Fetch schema + versions (GATE) | `torana build capabilities --json` |
| Create proposal | `torana build proposals create --workspace-id <WS> --intent "…" --title "…" --built-via claude_skill` |
| Start blueprint | `torana build proposal <id> blueprint start` |
| Save blueprint | `torana build proposal <id> blueprint save --blueprint-file bp.json` |
| Approve blueprint | `torana build proposal <id> blueprint approve` |
| Start cook | `torana build proposal <id> cook start` |
| Add an artifact | `torana build proposal <id> artifact add --type <t> --key <k> --source-step <step_id> --definition-file d.json` |
| Validate an artifact | `torana build proposal <id> artifact validate <artifact_id>` |
| Check proposal COMPLETENESS (C1–C6) | `torana build proposal <id> validate [--phase intent\|blueprint\|program]` |
| Edit an artifact (to repair) | `torana build proposal <id> artifact edit <artifact_id> --definition-file d.json` |
| List artifacts + states | `torana build proposal <id> artifact list` |
| Finalize (→ deployable) | `torana build proposal <id> cook finalize` |
| Record a clean cook abort | `torana build proposal <id> cook fail --reason "…" --stage cook` |
| Inspect progress | `torana build proposal <id> show --json` (state, blueprint, cook_state, artifacts) |
| Deploy (verb 2, on confirm) | `torana build proposal <id> deploy` |
| **Read the build back** | `torana admin build trace <id>` — intent → steps → decisions → gates → deploy |
| Gate detail only | `torana admin build trace <id> --gates-only` / `--failed-only` / `--step 1.2` |
| Raw gate rows | `torana admin build gate-evidence <id>` |
| Every version of this app | `torana admin build versions <workspace-id>` |
| Deploy result | `torana build proposal <id> deploy-status` |

## The blueprint shape (what `blueprint save` accepts)

```jsonc
{
  "plan_id": "<slug>",                 // optional
  "grounding": { ... },                // optional — the schema/entity/policy facts you grounded on
  "steps": [                           // REQUIRED, non-empty, each step_id UNIQUE
    {
      "step_id": "1.1",                // REQUIRED, stable, unique — artifacts reference this
      "artifact_type": "transformer",  // REQUIRED — one of the fetched artifact_types
      "produces": "<output_name>",     // REQUIRED — what this step yields
      "consumes": ["<source_table>"],  // upstream tables/steps it reads
      "policy_basis": "<policy honored, or ''>",
      "depends_on": [],                // step_ids this step depends on (author in topo order)

      // ⛔ REQUIRED IN PRACTICE — the artifact PROVENANCE GATE rejects any artifact whose
      // `semantic_description` shares no significant terms with its step's narrative, and
      // that narrative is built from THESE two fields. Omit them and every
      // `artifact add … --semantic-description-file` on this step fails with HTTP 400:
      //   "semantic_description does not trace to blueprint step '1.1' — it shares no
      //    substance with what that step says it is for. The step's own words are —
      //    intent: '(none)'; why_it_matters: '(none)'."
      //
      // ⚠️ UNRECOVERABLE ONCE COOKING STARTS. `blueprint save` is only legal while
      // blueprinting; after `cook start` it returns HTTP 409, so you cannot add these
      // retroactively — the whole proposal has to be abandoned and rebuilt. Author them up
      // front, always.
      "title": "<short human label for the step>",
      "intent": "<the outcome THIS step delivers, in a sentence>",
      "why_it_matters": "<what breaks without it>"
    }
  ]
}
```

**On the provenance gate.** The bar is deliberately low — the artifact's rationale need only
share a couple of significant terms with the step's narrative, so you stay free to rephrase,
expand, or write for a different audience. What it catches is a rationale that is about
something else entirely (drift). Leaving `intent`/`why_it_matters` empty does NOT lower the
bar; it makes the gate unsatisfiable, because there is no narrative to share terms with.

You may instead omit `semantic_description` on the artifact and let the server DERIVE it from
these two fields — but see the artifact-intent rule below for why an author-written,
regeneration-grade intent is worth far more than a derived one.

The `produces`/`consumes`/`policy_basis` VALUES come from the **grounding** — your (or a domain
skill's) analysis of what the program should contain — NOT from the user's `intent` text. The
`intent` stays the user's short business promise (rendered on the card); the technical detail lives
here in the blueprint. The engine enforces only the SHAPE, never the domain meaning.

## ⛔ SQL arrives from `torana-text-to-sql` — it is not hand-written at deposit time

Any step whose `definition` carries datalake SQL (transformer, rule, widget query, catalog
entry) gets that SQL from the **`torana-text-to-sql`** skill, **with its evidence block**.

⚠️ **`artifact validate` is a real EXPLAIN, and EXPLAIN cannot see the failures that matter
here.** Three classes pass it and still ship a wrong answer:

| Failure | Why EXPLAIN passes it |
|---|---|
| **unreachable column** | the column is declared, so it parses — it is simply written by nothing and returns silence |
| **hardcoded policy** | `severity IN ('Critical','High')` is valid SQL; it bakes one tenant's risk appetite in as fact |
| ⛔ **fan-out** | measured: a wrong `edge_type` returned **19,450** rows where **24** were correct. Real columns, real edge type, correct casing, EXPLAIN clean |

⭐ So the order is: **author via `torana-text-to-sql` → paste its evidence record → deposit**.
Depositing first and repairing against `rejection_reason` only fixes what EXPLAIN can see.

⚠️ **`repair()` in the loop below is for SQL ERRORS, not for wrong answers.** If a step's SQL is
valid but the numbers look wrong, do not repair-loop on it — go back to `torana-text-to-sql`
with the grain restated. Three repair attempts against a semantically wrong query produce three
semantically wrong queries.

## The per-step build loop (cook)

```
for step in approved_blueprint.steps:            # topo order — upstream transformers first
    definition = author(step)                    # a dict matching the FETCHED schema for step.artifact_type
                                                 # ⛔ SQL comes FROM `torana-text-to-sql` — see below
    write definition → d.json
    artifact add --type <step.artifact_type> --key <k> --source-step <step.step_id> --definition-file d.json
    result = artifact validate <artifact_id>     # THE hard gate — real EXPLAIN on the platform
    if result.state == "rejected":               # rejection_reason carries the real SQL error
        for attempt in 1..3:                     # HARD CAP — never loop past 3
            definition = repair(definition, result.rejection_reason)
            artifact edit <artifact_id> --definition-file d.json
            result = artifact validate <artifact_id>
            if result.state == "validated": break
        else:
            cook fail --reason "step <step_id>: <last_error>" --stage cook   # clean abort, then STOP
validate --phase program                         # COMPLETENESS self-check BEFORE finalize (C6 etc.)
# fix any completeness failure, then:
cook finalize                                    # → deployable (platform re-checks step-completeness)
```

## Completeness self-check (`validate`) — deposit clean, don't eat a 4xx

Alongside per-artifact SQL validation, the platform enforces deterministic **completeness** rules
(C1–C6) at the write boundary: C1 intent ≠ title, C2 intent not too thin, C3 blueprint `grounding`
present, C4 step `produces` not a placeholder echo, C5 `policy_basis` explicit, C6 every declared
artifact type actually built. A proposal that fails these is REFUSED on `blueprint save/approve` or
`cook finalize`. Run `validate` yourself and fix first, rather than discovering it via a 4xx:

```
blueprint save  →  validate --phase blueprint  →  (fix + re-save, ≤3 tries)  →  blueprint approve
… cook loop …   →  validate --phase program    →  (fix)                      →  cook finalize
```

`validate` is read-only (`{valid, failures[]}`, exits non-zero on failure). Each failure names the
rule + field, so the fix is mechanical: add real grounding, give `produces` a meaningful name, fill
`policy_basis` (or the literal `"none"`), or build the missing artifact type. **For a C2 failure, do
NOT pad the intent with technical detail — write the user's actual ask as a short promise; the floor
is trivial (20 chars / 2 words) and a genuine request clears it.**

## Authoring rules the platform ENFORCES (author to satisfy them, don't fight them)

- **Every artifact MUST carry `--source-step`** matching an approved-blueprint `step_id`, or `add`
  returns HTTP 400. One step may produce several artifacts (all citing the same `step_id`). You cannot
  create an orphan artifact — this is provenance by construction.
- **Author against the FETCHED schema's exact field names.** Unknown/misspelled fields are rejected
  (`extra="forbid"`), not silently dropped. E.g. `destination_table`, not `destinaton_table`.
- **`depends_on` is derived from the blueprint** — the platform heals it from the step's `depends_on`
  on validate. Author it consistently; expect the platform to be authoritative.
- **Base transformers EXPLAIN at cook; dependent SQL validates via ephemeral views.** A base
  transformer (no `depends_on`) has its SQL compiled against live base tables at cook. A dependent
  artifact (rule/kpi/widget, or a transformer that reads a sibling) is validated against its upstream
  transformers materialized as ephemeral temp views — so it validates correctly at cook even though
  the upstream isn't live yet. **Author upstream transformers before their dependents** (topo order)
  so this chain resolves.
- **Terminal completeness.** `cook finalize` refuses unless EVERY blueprint step produced at least one
  validated artifact. Don't leave a step uncovered — if a step is genuinely unbuildable, drop it from
  the blueprint (re-save) rather than leaving it dangling.

## Validation ≠ deploy — some artifacts only fail at DEPLOY

`artifact validate` proves an artifact's SQL compiles (real EXPLAIN) and its definition matches the
fetched schema. It does **NOT** exercise the cross-service create calls the deploy makes, so a few
artifact types can pass validate and still fail — or silently under-deliver — at `deploy`. Know these
before you present a program at the deploy gate:

- ⛔ **`destination_table` is TENANT-scoped, not app-scoped — a collision is DESTRUCTIVE.** Two apps
  naming the same table share one dbt model file. Your deploy overwrites it; if that deploy then
  fails for any reason, the rollback **deletes** it — taking the other app's model with it and
  leaving every dependent `ref()` dangling. dbt compiles the project as a unit, so this bricks
  **every** transformer deploy in the tenant, for every app, until a human restores the file. The
  rollback reports a clean `0/N deployed` and says nothing about the collateral. Worse, the failure
  names YOUR artifact, so it reads as a defect in SQL you just validated.
  **Rule: prefix every `destination_table` so it is unique to this app, and confirm the name is
  unused before cook** (`torana transformer-tables list`). A name that already exists is a
  collision, never reuse — reuse is `catalog_entry_id`.
- **Schedulers resolve their target at DEPLOY, not validate.** A scheduler's `target_ref` is the
  NAME of the transformer/rule it runs. The deploy resolves that name → the just-deployed real UUID
  and sends it to workflow-framework (which requires `transformer_id`/`rule_id`, a UUID). So a
  scheduler validates fine even if its `target_ref` names a transformer/rule that **isn't in the same
  proposal** — then the deploy can't resolve it and fails. **Rule: a scheduler's `target_ref` MUST
  name a transformer/rule built in THIS proposal** (same blueprint), so it's in the deploy's
  name→id map. (This resolution is a platform fix as of the deploy executor's name index; if you hit
  `Invalid transformer_id type: NoneType`, the platform you're on predates it — omit schedulers and
  refresh manually, and file the gap.)
- **Dashboards must carry their widgets in a shape the deploy understands.** The deploy attaches a
  dashboard's widgets two ways: (a) **reference** entries carrying a sibling widget's `artifact_id`/
  `artifact_key` (that widget is a separate step, deployed first), or (b) **inline** widget specs
  (a full `{name, widget_type, sql|query_id, display_config, description, semantic_description}`
  object). Anything that is neither — an entry with no ref and no widget spec — is dropped and the
  dashboard deploys with fewer widgets than intended (historically ALL inline widgets were dropped,
  leaving `widgets: []`). **Rule: after deploy, VERIFY the dashboard's widget list is non-empty**
  (`torana dashboard <id> widgets list`); if it's short, the manifest's widget entries weren't in a
  supported shape — fix the shape, don't hand-attach and move on.
- **EVERY widget MUST carry `description` AND `semantic_description` — this is mandatory content, not
  optional.** Both are read straight through to the deployed widget row by the deploy executor
  (`_create_widget`), so whatever you author lands on the widget:
    - `description` — the one-line info-icon tooltip: *what the widget shows* (e.g. "Open
      vulnerabilities by severity tier").
    - `semantic_description` — the rich *how-to-read-this / what-to-do-about-it* body. It surfaces in
      the FE's expandable row under the widget title, in `torana widget <id> get`, and — critically —
      is **injected into every anchored-chat LLM turn** via the `workspace_widget` anchor, so a user
      asking the agent about a widget gets your authored interpretation. A blank
      `semantic_description` means the FE box silently doesn't render and the chat agent has no
      context — the widget ships mute.
  **Do NOT emit a widget with either field empty.** The one-line `description` alone is not enough;
  the semantic body is what makes the widget self-explanatory. Author it as you build the step,
  the same way you write a transformer's or KPI's description — a widget is shipped content and is
  held to the same completeness bar. When you author a dashboard step, treat "every inline widget
  has a non-empty `description` and `semantic_description`" as part of the step's definition of done,
  and VERIFY it after deploy: `torana widget <id> get` must show a populated SEMANTIC DESCRIPTION
  field (empty = you left the default; go back and author it).
- **⛔ An ARTIFACT's `semantic_description` is its regeneration-grade INTENT — AUTHOR IT.**
  Distinct from the widget guidance above (which is about a widget's user-facing "how to read this").
  An app is the result of **intent → blueprint step → cooked artifact**, and the artifact's
  `semantic_description` is where the *why* survives that chain.

  ⛔ **Do NOT leave it empty.** The server will then derive a rationale from the step's `intent` +
  `why_it_matters`. That derived text is not an intent and can never be five-part — a blueprint
  step has no grain, scope or fallback to derive them from — so the artifact ships **looking
  healthy while being unregenerable**. It is **unbackfillable**: an artifact's source of truth is
  its intent, not its SQL, and SQL → English is lossy, so nobody can recover later what you knew
  at the moment you authored it.

  Write 1–3 sentences of prose, leave a blank line, then **all five keys**, each at the start of
  its own line, lowercase, in this order:

  ```
  question:  the ask in the user's own words
  grain:     one row per WHAT
  semantics: every domain term a generator would otherwise guess
  scope:     time window, soft-delete handling, row limits
  fallback:  what to do when a concept cannot bind
  ```

    - **`grain`** is the highest-value field and the cheapest to check — it is what a regeneration
      is compared on, so a changed grain means a **different artifact**, not a better one.
    - **`semantics` names CONCEPTS, never columns.** *"critical = the tenant's top severity band"*
      is right; *"critical = `vulnerabilities.severity` IN (...)"* is wrong — the binding must stay
      free to change when a better column appears, which is the entire point of regenerating.
    - ⛔ **The intent block goes LAST.** Anything after the final key is absorbed into `fallback`.
    - It must still **restate its step's why**. A rationale sharing no substance with its step is
      **rejected** by `add_artifact` with the step's own words quoted back. Describing what the
      artifact renders is `description`, not this.

  ⛔ **THE TEST:** *could two competent generators, given only this text and the current schema,
  produce queries that disagree on a row count?* If yes, it is a description, not an intent.

  ⭐ **VERIFY it — do not eyeball it.** This skill cannot import platform code, so the CLI is the
  only way to check your own output against the real rule:

  ```bash
  torana datalake check-intent --file <intent.txt> --artifact-type <transformer|widget|rule|…>
  # exit 0 = conforming · 1 = still a description · 2 = bad input
  ```

  Pass it on the CLI with `--semantic-description-file` (a conforming intent is multi-line and
  ~1,400 chars, so the file form is the practical one):

  ```bash
### ⛔ `artifact add` — the COMPLETE flag list. Do not invent one.

These are ALL of them, verified against `--help`. Measured across two test sessions: an
author invented `--name`, `--sql-file` and `--workspace-id`, corrected them via `--help`,
and then **invented `--name` again in the next session** — because the lesson lived in a
transcript instead of here.

```
--type            transformer|rule|dashboard|widget|kpi|attention_card|route|playbook|scheduler
--key             stable key, unique within the proposal          ← the IDENTITY. There is no --name.
--definition      definition JSON, e.g. '{"sql":"SELECT …"}'      ← the SQL goes HERE
--definition-file path to a JSON file with the definition          ← there is no --sql-file
--depends-on      comma-separated artifact_key dependencies
--source-step     the blueprint step_id this came from             ← REQUIRED once the blueprint is approved
--description     short human-facing blurb (NOT the intent)
--semantic-description[-file]   the five-part regeneration-grade INTENT
--catalog-entry-id      the entry this REUSES (then carry NO sql)
--catalog-decision-id   the recorded miss id when no entry fit
--required-integrations comma-separated integrations
--validate        validate immediately after adding
```

⚠️ **Three flags authors keep inventing, and none exists:**

| Invented | Reality |
|---|---|
| `--name` | the identity is `--key` |
| `--sql-file` | SQL goes in `--definition` / `--definition-file` as JSON |
| `--workspace-id` | the workspace is carried by the PROPOSAL, bound at create |

⚠️ `--question-id` is **not** on this command either — it belongs to
`catalog record-miss`, which is the miss path.

⭐ **When unsure, run `artifact add --help` rather than guessing.** A wrong flag fails the
whole deposit, and the error names the flag, not the fix.

### The three CALLER-OWNED fields on `artifact add`

⛔ **A transformer carrying its OWN new SQL is REFUSED without one of the first two.** The
gate's message names the remedy, but by then you have already burned an attempt — pass the
field with the deposit.

| Flag | When | What it means |
|---|---|---|
| `--catalog-entry-id <id>` | an entry SATISFIES the need | REUSE. Carry **no** `sql` — setting both is rejected, because deploy reads `sql` first and the entry id would look authoritative while being ignored |
| `--catalog-decision-id <id>` | no entry fit | you recorded WHY on a named axis via `catalog record-miss`, and this is the id it returned |
| `--required-integrations a,b` | always, when known | what must be CONNECTED for this artifact to return data |

⚠️ **You do not decide which.** The domain skill adjudicated the catalog and hands you the
answer; this engine carries no domain knowledge and must not start guessing here.

⚠️ **`--required-integrations` is reconciled, never trusted.** The server derives the same
set from the tables the SQL reads and records any disagreement as gate evidence. Both are
kept — a declaration that does not match what the SQL reads is a defect worth surfacing, not
a value to silently overwrite. It does **not** block the deposit.

  torana build proposal <pid> artifact add --type transformer --key <k> \
    --definition-file def.json --semantic-description-file intent.txt
  ```

  ⚠️ **Putting it inside `--definition` does NOT work** — that writes
  `definition.semantic_description`, a different field that no gate or reader looks at. Measured:
  1,395 chars sat there while the column held 265.
- **General rule:** treat `deploy` as the real gate for anything that crosses into another service
  (scheduler → workflow-framework, dashboard→widget attach, route → alert-routing). Always run the
  VERIFY step (query the materialized tables, list the dashboard's widgets, list the schedulers) after
  a deploy — a green `deployed` status is necessary but not sufficient.

## Never bundle a schema OR a recipe's field names — always reconcile against the FETCHED schema

The engine fetches the artifact-definition schema from `torana build capabilities` for a reason:
schemas grow. A domain skill's **recipe** (e.g. `torana-vm`'s `vuln-prioritization.yaml`) shows the
SHAPE of a program but may predate schema changes — its field names are illustrative, not
authoritative. Before authoring any artifact from a recipe, diff the recipe's fields against the
fetched schema for that type and drop/rename anything the live schema doesn't declare (`extra="forbid"`
rejects unknown fields at `add`). Observed example: a recipe using `summary_template`/`action_template`
on an `attention_card` whose live schema only has `title/description/severity/icon/query/trigger_when`.

## Grounding (before any SQL)

Read the workspace's REAL schema, the entity graph, and the active policy docs **only through the
`torana` CLI** — never a raw DB dump or source read. Author SQL only against columns that actually
exist: deploy pre-flight re-validates against the live schema and aborts the whole deploy on drift,
so imagined columns waste the entire build.

**The exact grounding reads (use these — do not guess):**

| To learn… | Command |
|---|---|
| Which tables exist (names + descriptions) | `torana datalake tables list` |
| One table's columns + types + primary key | `torana datalake schema table <table> --scope platform` (or `torana datalake tables get <table>`) |
| ALL tables' columns + types in one call (bulk) | `torana datalake all-columns --scope platform` |
| Column synonyms, enum values, join hints | `torana datalake query-hints` |
| A table's row count + freshness | `torana datalake table-summary <table>` |

Prefer `datalake schema table <table> --scope platform` for the specific base table(s) you're building over; use
`all-columns` when you need the whole workspace at once. **Do NOT** ground by dumping rows
(`table-data`) and inferring columns — read the schema directly. When a domain skill drives you, use
the grounding rules it supplies (e.g. which columns mean severity/SLA) on top of these real reads.

## Fast lane (optional): import an artifacts.yaml

If you already have a complete `artifacts.yaml` (e.g. an export), you can import it in one shot:
`torana build proposals import --workspace-id <WS> --file artifacts.yaml --built-via claude_skill`.
This creates the proposal with a synthesized blueprint (saved **ready, NOT approved**) + draft
artifacts. To reach deployable you then drive the native tail of the loop:

1. `torana build proposal <id> blueprint approve` — import leaves the blueprint `ready`; cooking
   requires it `approved`, so this step is **required** (not optional).
2. `torana build proposal <id> cook start`
3. `artifact validate` each imported draft (repair on reject, same 3-attempt cap as above).
4. `torana build proposal <id> cook finalize` → **deployable**.

Always pass `--built-via claude_skill` on import so the card shows "Built with Claude" (an import
without it stamps `unknown` and shows no badge). Prefer the native step-by-step loop above (per-step
provenance + per-artifact validation) as the primary path; use import only as a shortcut when a full
yaml already exists.

## Reading progress

`torana build proposal <id> show --json` returns `state`, the `blueprint`, `cook_state` (per-step
status), and the `artifacts` with their states — everything you need to narrate progress and decide
the next step. `artifact list` is a cheaper read for just the artifact states during the cook loop.

## Multi-part apps → App Bundles (Spec E)

A real app is often a **chain** of proposals: v1 lays a foundation transformer, v2 adds a capability
that reads it, v3 another, and so on — each deploy accumulating onto the last. When you build such a
chain, package it as an **App Bundle** so it ships as a reviewed, re-installable unit.

**Producing a bundle (after you've built the chain in a scratch workspace):**

```
torana build bundles export --workspace-id <WS> --bundle-id <id> --out bundle.json
torana build bundles validate --file bundle.json      # B1–B6 + B7 must pass
torana build bundles import  --file bundle.json        # store it (tenant bundle)
```

Export captures each version faithfully — its real intent, real blueprint, and cooked artifacts —
so a re-install reproduces N real proposals + N versions, indistinguishable from a hand-built app
(never the lossy `artifacts.yaml` synthesized-blueprint form).

**Authoring a chain so it captures + re-installs cleanly:**

1. **Foundation once.** Author the shared foundation transformer (e.g. `prioritized_vulnerabilities`)
   in the FIRST link. Later links read it with ordinary SQL `FROM prioritized_vulnerabilities` — it
   resolves at deploy because the foundation already materialized (no cross-proposal ref machinery).
2. **Blueprint steps MUST encode dependencies as step-level `depends_on` (step_ids), not just
   `consumes`.** This is load-bearing: the cook path derives an artifact's upstream views from its
   blueprint step's `depends_on` (step_ids). A dependent step that reads a sibling's output but omits
   the producing step from its `depends_on` gets NO upstream view built → its EXPLAIN fails at cook
   with `relation "<view>" does not exist`. The bundle validator's **B7** check catches this at author
   time (`torana build bundles validate` names the artifact + missing step) — so validate before you
   ship. E.g. a KPI reading `prioritized_vulnerabilities` (produced by step `s_foundation`) must have
   its own step declare `depends_on: ["s_foundation"]`.
3. **Blueprint substance stays required** — every step needs `grounding` (a dict), a real `produces`
   name, and an explicit `policy_basis` (or the literal `"none"`). These survive capture because they
   were required when the link was built live; a hand-authored bundle that omits them fails validator
   B1.
4. **Vocabulary, not hardcoded values** — the same `{{vocab:…}}` placeholder rule as single apps
   applies inside every link's artifact SQL (it resolves per-tenant at install).

**Installing a bundle** (yours or a system one like `ciso_posture`):
`torana build bundles install <id> --workspace-id <WS>` — serial fail-fast; on a link failure it
stops, names the link + stage, and leaves prior links as valid versions. Or in one step at creation:
`torana workspaces create --type <t> --bundle <id>`.

---

## Catalog-first authoring (Domain Primitives spec § 4.21)

**The platform ships a catalog of reviewed SQL definitions. Search before you write.**

### Why this rule exists

The catalog is not a convenience library. Each entry was authored once against the real
schema, validated, and reviewed — which is precisely what an LLM authoring SQL against a
1,385-column schema cannot guarantee. The first catalog entry exists because a shipped rule
carried a hallucinated `edge_type` and a wrong join key.

Duplication is the specific harm. When four programs each author "open findings on an
asset", you get four populations that disagree at the edges — one includes `Deferred`, one
forgets `is_suppressed`, one uses `= false` on a nullable boolean and silently drops 99.5%
of rows. That last one is not hypothetical; it shipped.

⭐ **The difference between the catalog and the transformer graveyard is DESCRIPTION, not
quality.** Catalog entries carry `answers_questions`, `grain` and `output_shape`, so you can
adjudicate them without reading SQL — which is why they get reused. Transformers carry none:
`torana transformer-tables list` returns **names only**, and platform-wide **0 of ~976
transformer-output columns** carry a description. So every app re-authors what the last app
already built, and the duplication above is the result. **You are one of those authors.**
Describe what you emit — the artifact's `description`/`semantic_description`, and above all
what **ONE ROW** represents — or your table joins the graveyard the moment you deploy it.

### The loop

```bash
# 1. Read the whole catalog ONCE per build — free, fast, no side effects, nothing ranked
TORANA_PROFILE=<P> torana vm transformers catalog list

# 2a. AN ENTRY SATISFIES IT → reference the entry by id. Do NOT copy its SQL.
# 2b. NONE DOES → record the miss, THEN author
TORANA_PROFILE=<P> torana vm transformers catalog record-miss "<need>" \
  --gap-category wrong_grain --near-miss vm.tf.em_012 \
  --rationale "Entries cover finding-grain; this step needs one row per REMEDIATION ACTION."
```

Step 1 is a full read, not a query. The list is small enough to hold, so no
ranking stands between you and the right entry — and judging is your job, not the
platform's. Re-listing per relation pays the same tokens repeatedly for what you have.

The miss record is what makes the catalog improve. `gap_category` and `near_miss_entry_id`
are the queue for the next entries — an unrecorded miss is a gap nobody can act on, and
`--near-miss` is what tells the next author where to start.

### What a good rationale looks like

The rationale is read by whoever decides the next catalog entry. Be specific about *why*
the near-miss did not fit:

| Weak | Strong |
|---|---|
| "no entry matched" | "vm.tf.finding_enriched is finding-grain; this needs one row per remediation action, so counts would double" |
| "needed custom SQL" | "entries filter is_deleted; this audit must include soft-deleted rows to prove retention" |
| "different data" | "no entry joins `identities`; this step needs certificate expiry, which only lives there" |

A rationale that does not name the axis (grain / population / columns / time semantics) is
not usable evidence, and the catalog will not improve from it.

### The gate is enforced by the API, not by this document

An artifact that carries its own `sql` **requires** a real `catalog_decision_id`; the
deposit is rejected without one. The platform verifies the row exists — a fabricated UUID
returns 400. This is deliberate: a skill instruction is a suggestion, and this needed to
hold for callers that never load a skill.

Two surfaces, same rule, different field:

| Surface | How you satisfy it |
|---|---|
| Build artifact definition (`artifact add`) | set `catalog_entry_id` (reuse, no `sql`) **or** `sql` + `catalog_decision_id` |
| Direct `POST /api/v1/transformers` (backstop) | `catalog_eligible=true` + `catalog_decision_id` |

Setting both `catalog_entry_id` and `sql` is rejected, not merged — deploy reads `sql`
first, so the entry id would look authoritative while being silently ignored.

### When the entry fits but the table does not exist yet

**That is normal, and it is not your problem to solve by authoring SQL.**

Materialization is an **install side-effect**, not a user action. `materialize` / `release`
are service-to-service writes invoked by the install path with a service JWT, and they are
deliberately absent from the CLI — exposing them would let a caller mutate refcounts out of
band. What you get is the status read:

```bash
TORANA_PROFILE=<P> torana vm transformers materialized
```

The mechanism is **refcounted and proven**: N programs needing the same shape point at ONE
physical table; the last release tears it down. Verified end to end —

```
materialize  -> status=ready, refcount=3, physical_table=vm_tf_finding_enriched
release x3   -> refcount 2 -> 1 -> 0, torn_down=true
```

So: **declare the dependency by entry id.** Install resolves it. Never author the relation
yourself because it happens not to be built in this tenant right now — that converts a
shared, refcounted table into a private copy that will drift, which is the failure the
catalog exists to prevent.

⚠️ A materialized table can legitimately be EMPTY. `vm.tf.finding_enriched` builds with 0
rows today because its LEFT JOINs depend on FKs nothing populates (`torana_issue_id` is
empty on every row; the `image:`/`cloud:` entity-namespace gap). Empty means *the data is
not there yet*, not *the definition is wrong* — do not "fix" it by rewriting the SQL.
