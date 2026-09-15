# Datalake — schema discovery and authoring SQL

The datalake is the canonical store: 11 sink tables that every integration writes into and
every rule, transformer, widget and catalog entry reads from.

---

## ⚠️ Read this before writing any SQL

**The datalake declares far more columns than any pipeline fills.** A column existing in the
schema is NOT evidence it will ever hold a value. Ask the CLI for the current split rather
than trusting any number written down — it moves whenever a pipeline lands.

⚠️ **This is not theoretical, and it is why the check exists.** The shipped `vm.tf.*` catalog
and the question corpus were authored by reading the schema column list, before any
reachability check existed. Their SQL returned nothing. Tracing back found the columns were
valid, declared and documented — and **written by nothing**. **74% of that SQL can never run on
any tenant.**

```bash
"$TORANA" datalake tables list                       # the 11 sink tables
"$TORANA" datalake schema table <t> --scope platform      # one table's columns
"$TORANA" datalake all-columns --table <t> --scope platform   # same, bulk payload shape
"$TORANA" datalake all-columns --reachable --scope platform   # every table, one call
"$TORANA" datalake reachable-columns --scope platform
"$TORANA" datalake reachable-columns --scope platform --explain   # + WHO writes each column
"$TORANA" datalake all-columns --value-domains --scope platform  # WHAT each column can HOLD
"$TORANA" datalake schema audit                      # is the schema DESCRIBED accurately?
```

### ⛔ Two schemas, and only one of them is the platform's

| command | what you get | same for every tenant? |
|---|---|---|
| `all-columns` *(default)* | the **13 canonical sink tables** — the platform schema | **yes** |
| `all-columns --include-transformers` | those **plus** this tenant's derived tables | **no** |
| `schema transformers` | the derived tables **alone** | **no** |

⚠️ **Measured: SA has 18 transformer tables, T1 has 1.** They are outputs one tenant's own
dbt models built, so SQL written against them is not portable — a tenant that never built
that program has no such table. ⭐ **Author against the SINK tables.**

⚠️ The default changed: `all-columns` used to INCLUDE transformers, so older notes may show
`--no-include-transformers`. The flag still works; it is simply the default now.

### ⛔ Which command answers which question

Three surfaces, and they are NOT interchangeable. Picking the wrong one is how a
"column missing" conclusion gets reached about a column that exists.

| You want | Command | Universe |
|---|---|---|
| types, descriptions, value domains | `schema table <t>` · `all-columns` | **489** cols / 13 tables — includes non-sink `vm_cve_*` and system fields |
| WHO can write a column | `reachable-columns --explain` | **446** business cols over the 11 SINK tables |
| both, joined, for one table | `schema table <t> --writers` | the schema set, annotated from the writer map |

⚠️ **Neither is a subset view of the other.** `schema` declares 43 columns that
`reachable-columns` does not report — non-sink tables carry no reachability claim, and
system fields are returned separately as `system_columns`. So "absent from
`reachable-columns`" does NOT mean "not in the schema".

⭐ **`--writers` is a VIEW of `reachable-columns`**, not a second answer — one fetch backs
both, so they cannot drift. Verified: 0 disagreements across every shared column of
`repositories`.

### `--explain` — same columns, plus WHO writes each one

⚠️ **`--explain` changes NOTHING about which columns come back.** Measured on T1: 275 columns
either way, byte-identical apart from one added field. It only adds `writers[]` to each row —
the mechanism (`mapping` / `declared` / `system` / …), the source file, and the integration.

```
# without            artifacts   container_image_id
# with --explain     artifacts   container_image_id   operator:etl/manifest_interpret.py
```

⭐ **Ask for it whenever you care WHY a column is reachable**, not merely that it is. It roughly
doubles the payload (148 KB → 315 KB on T1), which is the only cost.

⛔ **A consumer that reads `writers[]` MUST pass it.** Without `--explain` the key is absent on
every row — and absent is indistinguishable from "no writers", which reads as a build defect
across the whole schema. `torana-text-to-sql`'s gate passes it for exactly this reason.

### Does every column have a writer? — `schema table <t> --writers`

⭐ **One command for types AND how each column is written.** `/tables/{t}/columns` carries
`data_type` and no writers; `reachable-columns` carries writers and no `data_type` — this
joins them, so "is this column writable, and by what" is one call:

```bash
"$TORANA" datalake schema table repositories --writers --scope platform

# ⭐ Tenant lens: the profile IS the tenant — no id needed.
TORANA_PROFILE=T1 "$TORANA" datalake schema table repositories --writers --scope tenant

# SUPER-ADMIN reading a tenant it is not. Rarely needed.
TORANA_PROFILE=SA "$TORANA" datalake schema table repositories --scope tenant --tenant-id <uuid>
```

```
advanced_security_enabled  ETL mapping   via github
created_by                 ETL mapping+Platform stamp   via github, gitlab
created_via                API seam
criticality_level          ⚠️ nothing writes this
```

⛔ Unlike `--reachable` (which **filters**), `--writers` **hides nothing** — an unwritten
column is listed and counted. That is the point: the footer names the count and says what it
means. At **platform** scope no writer is a **build defect**; at **tenant** scope it is
usually a **connection to make**.

⚠️ **Reconciles with `supply` exactly**, once two by-design exclusions are applied —
verified on this platform: declared 489 − 32 `vm_cve_*` (not sink tables, so they carry no
reachability claim) − 11 `is_deleted` (a system field) = **446**, the same set `supply`
declares. Platform: 441 written + 5 unwritten. T2: 314 written + 132 unwritten.

⚠️ **It is `schema table <TABLE>`, not `schema <TABLE>`.** `schema` is a command group;
the per-table form lives under it. (`all-columns --table <t>` returns the same columns in
the bulk payload shape — use whichever fits.)

```bash
"$TORANA" datalake schema table vulnerabilities --scope platform --detail terse
"$TORANA" datalake schema table vulnerabilities --reachable --scope platform  # only writable
```

⭐ **`--value-domains` — the flag that stops you guessing a value.** A type of `TEXT` does
not tell you whether severity is `Critical` or `CRITICAL`, or that `Unknown` exists.

```
severity   TEXT  [closed] Critical, High, Medium, Low, Info, Unknown
                   declared by: normalize.py::CANONICAL_SEVERITIES
scan_type  TEXT  [open]   container_image_scan, cspm, gitlab_vulnerability_findings
cve_id     TEXT  - not yet described
```

| Reads | Means | So |
|---|---|---|
| `[closed]` | the vocabulary is complete | an `IN` list may enumerate it |
| `[open]` | more spellings can appear | ⛔ do NOT write an exhaustive `IN` |
| `not yet described` | ⚠️ **nobody has described it** — NOT "any value allowed" | check the data before assuming |

⚠️ 855 of 859 columns are `not yet described` today, so that is the common answer.

⭐ **`datalake schema audit`** reconciles every surface that DESCRIBES the schema (the
reachability map, the semantic overlay, the removed-column archive, `information_schema`)
and exits non-zero on drift. ⛔ Run it after ANY schema change — a column removed from the
schema does not remove the SQL that reads it.

**Always run both forms and compare** — the gap is large on every table, and it is the whole
reason this page exists:

```bash
"$TORANA" datalake all-columns --table vulnerabilities --scope platform   # every declared column
"$TORANA" datalake all-columns --table vulnerabilities --reachable --scope platform  # only writable
```

⚠️ **`schema` prints one single-line JSON blob**, so `wc -l` and `grep` mislead — both forms
return the same line count while the real column counts differ substantially. Count the keys
(e.g. pipe through `jq`), never the lines.

## ⚠️ Two scopes, two owners — do not merge them

| Scope | Question | Empty means | Owner |
|---|---|---|---|
| `platform` | could **any** integration Torana ships write it? | **no pipeline exists anywhere** | platform engineering |
| `tenant` | can **this** customer's connected tools write it? | integration not connected | customer success |

**Use `--scope platform` when authoring.** Tenant scope also hides columns that are fine once a
customer connects an integration — a deployment question, not an authoring one.

## ⚠️ `reachable` ≠ `populated`

**Reachable** = a pipeline exists that writes the column.
**Populated** = data has actually landed.

⚠️ **An empty query result is a fact about THIS TENANT — never a reason to change the SQL.**
The pipeline may exist and simply not have run, or the customer has not connected that source.
Rewriting SQL because one tenant returned no rows is overfitting to that tenant, and it is how
a query comes to answer a different question everywhere else.

⚠️ **The inverse is equally wrong**: rows coming back is not validation. A query joining the
wrong way returns plenty of rows and answers the wrong question.

## Verify column names — never pattern-match them

Column names do not follow a guessable convention across tables. On `vulnerabilities` the
identity column is `torana_entity_id` (not `asset_id`), first-seen is
`scan_first_detected_date` (not `first_seen_at`), and state is `vulnerability_status` (not
`status`). **A plausible-looking name that does not exist fails outright; one that exists but
is unreachable fails silently.** Always confirm against `schema --reachable`.


## What a column MEANS — the semantic model (required, not optional)

`schema` and `reachable-columns` tell you a column exists and can hold data. Neither tells
you what it *means*, what it is called elsewhere, what values it holds, or how to join it.
That is the semantic model:

```bash
torana datalake query-hints                 # synonyms + enum values + join hints, per table/field
torana datalake query-hints --format json   # machine-readable; read .tables.<T>.field_hints
```

**Run it before authoring SQL, as a step — not as a command you know exists.** Measured
across 22 local sessions, `query-hints` appeared in 13 transcripts and was **executed in 3**,
zero times during a build window: it gets loaded into context and never run. Meanwhile three
sessions resolved *asset criticality* by guesswork and disagreed with each other, though the
model answers it directly.

It carries, per field: `synonyms` (what the same concept is called in other tables),
`enum` + `enum_closed` (the value domain), `enum_source` (which mapping/writer produces
those values), and join hints.

### ⚠️ Confirm enum values against the data — the model is a strong hint, not a guarantee

An `enum` here is derived from the mappings that write the column, so it can drift from
what a given tenant actually holds. **`enum_closed: false` says so explicitly — treat that
as "these are examples, not the set."**

```bash
torana datalake query --format json --sql "SELECT <col>, COUNT(*) n FROM <t> GROUP BY 1 ORDER BY 2 DESC"
```

⭐ **Casing is the expensive failure.** `WHERE severity = 'critical'` against data holding
`'Critical'` returns zero rows and looks like a correct query over an empty result — no
error, nothing to debug. Confirm the casing before you filter on it.

> **Measured 2026-08-24 (T2):** on this build the declared enums were accurate —
> `VULNERABILITIES.SEVERITY` declares `Critical/High/Medium/Low/Info/Unknown`
> (`enum_closed: true`) and the data holds `Critical/High/Medium/Low/Unknown`;
> `SCAN_TYPE` declares six values (`enum_closed: false`) and the data holds a subset
> (`SCA`, `Posture`, `Unknown`). ⚠️ An earlier report of widespread enum disagreement
> (8 of 14 declarations wrong, `scan_type` with no overlap at all) did **not** reproduce
> here. Both readings point the same way: **verify against the tenant in front of you
> rather than trusting either the model or a previous measurement.**


## ⚠️ None of this is CI-enforced

**The reachability discipline on this page is a convention, not a guard.** Nothing fails a
build when it is violated. Assume it has been violated somewhere and verify rather than trust:

| Check | Where it lives | CI-enforced? |
|---|---|---|
| `torana-text-to-sql`'s reachability gate | `skills/torana-text-to-sql/scripts/test_gate.py` | ❌ **No** — a standalone script in the skill's `scripts/`, not under `pantheon-cli/tests/`, so pytest never collects it |
| Whether shipped SQL uses reachable columns | — | ❌ **No such check exists** |
| Whether a mapping conforms to its category model | `torana-integration-model` skill | ❌ Run on demand only |
| Mapping conformance **at generation** | `validate_bundle.py` (`/generate-integration`) | ✅ **Yes** — the one enforced gate |

⚠️ **The one thing that IS enforced is generation-time**: a new integration cannot be
generated writing to the wrong table. Everything already shipped was authored before these
checks existed and has never been gated.

⚠️ **This matters most for the gate's own correctness.** The session that built
`torana-text-to-sql` found its regression suite caught **four real bugs in the gate it had
just written — three of which passed ad-hoc testing first**, including one where
`SELECT cve_id` verified zero columns and reported a false ✅. An unwired suite catches
nothing on the next change.

**Practical consequence:** re-run the gate yourself on any SQL you author or inherit. Do not
assume existing SQL passed it — most of it predates the gate entirely (**74% of the shipped
catalog cannot run on any tenant**).

```bash
"$TORANA" datalake check-sql --file /tmp/candidate.sql
"$TORANA" datalake check-sql --sql "SELECT cve_id FROM vulnerabilities" --verbose
```

⚠️ **Use the CLI verb, not a skill script.** `datalake check-sql` diagnoses every column the
SQL reads by calling the supply API — so it works on a machine with no platform checkout.
`torana-skill` ships **no `scripts/` directory**; any instruction to run
`python "$SKILL_DIR/scripts/…"` from here cannot resolve.

## Where a column's data comes from

Whether a column *should* be filled is answered by the integration **category model** — what a
tool of a given kind owes. See `integrations.md` § Integration categories and their contracts.

⚠️ **A category model covers only a small fraction of declared columns.** It answers *"is this
mapping faithful to its contract?"*, never *"should this column exist?"*.

**Per-column supply/demand verdicts come from the CLI** — ask it, rather than reading a file
out of a checkout you may not have:

```bash
"$TORANA" datalake supply --help          # why a column is empty; what to connect
"$TORANA" datalake schema-coverage        # how many columns carry a written meaning
```

## Has this question been asked before? — semantic resolution

```bash
"$TORANA" admin question-resolve "which teams have the largest unresolved exposure?"
```

Resolves any phrasing to a canonical corpus `question_id`. **Run it on the user's own words
BEFORE authoring SQL**: the corpus curates a fixed set of questions, and the same question
asked five ways should reach the same answer rather than producing five definitions that
disagree.

⭐ **UNRESOLVED is a RESULT, not an error.** It is recorded as demand, and demand is what
tells curators which question to add next. Never treat it as a reason to stop or apologise —
a real user's ask will frequently sit outside the curated corpus.

⚠️ **Ambiguous asks return `alternatives` with `ambiguous: true`.** Pick deliberately and say
which you picked; taking the first of two near-equal candidates silently is how you answer a
question the user did not ask.

⚠️ `method` reports `lexical`, never `embedding` — no model is involved. Treat the confidence
as token-overlap evidence, not a semantic guarantee.

## What the platform intends to answer, and what blocks it — the corpus (SA)

⛔ **SUPER-ADMIN ONLY.** The corpus is PLATFORM CURATION — which questions the platform
intends to answer — not a fact about any tenant's data. A tenant token gets 403. Run these
under `TORANA_PROFILE=SA`; a tenant cannot add a question, so showing them a partial catalog
reads as their gap when it is ours.

```bash
"$TORANA" admin corpus summary              # coverage: validated, by use case, limb states
"$TORANA" admin corpus questions            # EVERY question — the ledger
"$TORANA" admin corpus roadmap              # what blocks them, ranked by questions unblocked
"$TORANA" admin corpus show <question-id>   # ONE question, including WHY it is blocked
```

⭐ **`show` is the one that answers "why can't the platform answer this?"** It prints the
question's grain and tables, the one sentence explaining why no amount of data helps, and
each blocked limb with its measured evidence and the capability that would unblock it.

### ⚠️ VALIDATED is not the same as "has SQL"

A question can carry SQL text that was never proved to run. `corpus summary` counts
`validated`; `question-coverage` counts `with SQL`. **They differ, and the gap is the point** —
reporting "has SQL" as answered overstates coverage. When you need "can the platform actually
answer this today", read `validation_status == validated`.

### ⚠️ Three states that look alike and are not

| Field | Says |
|---|---|
| `validation_status` | was this SQL ever proved to run? (`validated` / `not_validated`) |
| `outcome` | what the regeneration concluded — `sql`, `retired` (withdrawn), `no_sql_authored` (never written) |
| `answerable_by_schema` | could the SCHEMA answer it at all, independent of today's data |

⛔ `retired` and `not_validated` are different facts. Collapsing them reports a withdrawn
question as a failure.

### The roadmap groups by WORK, not by question

`roadmap` returns two groups, and the split is the actionable part:

- **schema additions** — the limb names *no column at all*; the concept has nowhere to live.
  ⛔ No ETL and no incoming data can help until the schema carries it. The expensive kind.
- **blocked columns** — the column exists but is empty, constant, or at the wrong grain.
  The fix is a writer, an ETL mapping, or a join path.

⚠️ **A row is a blocked COLUMN, never a "capability" count.** Two columns can be one project,
so the row count is an UPPER BOUND on distinct work. Do not report it as a project total.

⚠️ **`reachable_constant` is NOT a gap.** The column works; this tenant simply has no
instances. It is excluded from the roadmap deliberately — counting it would fill the plan with
work nobody will ever do.

### ⛔ Never re-derive these numbers yourself

Every count is computed server-side so the CLI, the FE and the API cannot disagree about what
"answered" or "blocked" means. Read them from `corpus summary`; do not recount from
`corpus questions` and do not cache them — the corpus is actively authored and every count
moves.

⚠️ **`corpus questions` and `corpus roadmap` are two VIEWS of the same questions**, not two
datasets. The first lists them; the second groups them by what blocks them. Neither
truncates — if you ever see a "more not shown" line, the API was asked for a limit.

Where the demand lands, for curators (SA):

```bash
"$TORANA" vm transformers catalog by-question       # misses grouped by what was ASKED
```

Cross-tenant and ranked by DISTINCT TENANT count first: three tenants asking once is a
coverage gap; one tenant asking three times is a preference. Rows with no `question_id` are
reported as `unresolved` and never merged — an empty list is not evidence of absence.
