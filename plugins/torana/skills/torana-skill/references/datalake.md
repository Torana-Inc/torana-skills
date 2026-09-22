# Datalake — schema discovery and authoring SQL

The datalake is the canonical store. `schema-ddl --index` labels every table as one of three
kinds, and the difference decides how much you can trust what is in it: **sinks** hold rows
integrations wrote as they synced; **transformers** are computed tables, the output of a saved
query someone scheduled; **reference** tables are cross-tenant data. Rules, widgets and catalog
entries read from all three.

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

⭐ **Start with `schema-ddl`, not the individual verbs.** It renders every fact about a column
on or above that column's line, reading each one from the surface that owns it — so the DDL
cannot disagree with them. The verbs below still work and are the reference when you want one
fact on its own; `schema-ddl` is the authoring path.

```bash
"$TORANA" datalake schema-ddl --index                # every table: kind, grain, what it is for
"$TORANA" datalake schema-ddl --tables <a,b> --with preset:answer
#   preset:answer = meaning, domains, reach, trust, measures — metadata only, so it is free.
#   Add --with values (or preset:data) only when a question needs this tenant's actual rows.
"$TORANA" datalake sql-reachability --sql "<the SQL>"  # judge SQL BEFORE anyone runs it
"$TORANA" datalake policy-template --sql "<the SQL>"   # does it hardcode one tenant's policy?
"$TORANA" datalake schema audit                      # is the schema DESCRIBED accurately?
```

### What `schema-ddl` is, and what each layer adds

It renders the schema as annotated DDL — one `CREATE TABLE` per table, with every fact about
a column on or above that column's line. It **owns no data**: each layer is read in-process
from the surface that already owns it (the semantic model, the writer map, the value-domain
registry, live `pg_stats`), so the DDL cannot disagree with them.

⛔ **Bare DDL is the default.** Nothing is included unless you name it, and the output header
lists what was included AND what was not — so an absent tag reads "not requested", never
"no data".

| layer | adds | source |
|---|---|---|
| *(bare)* | columns, types, keys, `JOIN KEY` lines | live schema |
| `meaning` | what a column IS, and the traps a type cannot show | semantic model |
| `domains` | the values a column may hold, `[closed]` or `[open]` | value-domain registry |
| `reach` | UNREACHABLE / POLICY / caller-only verdicts | writer map |
| `writers` | which pipeline writes each column | writer map |
| `trust` | measured reliability of each JOIN KEY — RELY / DEGRADED / NORELY / UNMEASURED | measured per tenant |
| `graph` | `entity_edges` contract: edge types, direction, key namespaces, live counts | entity graph |
| `measures` | what ONE ROW of an answer means — the named ALTERNATIVE readings of a question | semantic model |
| `rows` | live row counts | ⚠️ scans rows |
| `shape` | constant / enum / key / high-cardinality | ⚠️ scans rows (cheap, `pg_stats`) |
| `fill` | how many rows carry a value | ⚠️ scans rows |
| `values` | the values THIS tenant actually holds, with counts | ⚠️ scans rows |

**Presets:** `preset:answer` = `meaning,domains,reach,trust,measures` — metadata only, so it
is free to fetch and is the right default for answering a question. `preset:data` =
`rows,shape,fill,values`. `preset:all` = everything.

⚠️ **`domains` and `values` answer different questions and mislead in opposite directions.**
Declared says what the column MAY hold and holds for every tenant; observed says what THIS
tenant has, with counts. Filter on a declared value this tenant never held and you match
nothing, with no error. Treat the observed set as the whole truth and your predicate silently
excludes whatever arrives tomorrow.

⚠️ **The five measured layers scan live rows** (`graph`, `rows`, `shape`, `fill`, `values`).
They carry a `measured_at` stamp, are cached per tenant, and `--fresh` re-measures. Their
findings describe one tenant at one moment and do not travel to another.

⭐ **Fetching every layer is not thoroughness.** Nothing marks the four or five facts that
decide a query, so they arrive with the same weight as the thousands that do not. Ask for the
index, pick the tables the question reaches, then add a measured layer only when a specific
doubt calls for it.

<details><summary>The individual verbs — one fact at a time</summary>

```bash
"$TORANA" datalake schema table <t> --scope platform      # one table's columns
"$TORANA" datalake all-columns --table <t> --scope platform   # same, bulk payload shape
"$TORANA" datalake all-columns --reachable --scope platform   # every table, one call
"$TORANA" datalake reachable-columns --scope platform
"$TORANA" datalake reachable-columns --scope platform --explain   # + WHO writes each column
"$TORANA" datalake all-columns --value-domains --scope platform  # WHAT each column can HOLD
```

⚠️ Grounding SQL from these means joining four payloads yourself, which is the cost
`schema-ddl` removes — and the value-domain and reachability facts are easy to omit by
accident when they arrive separately.

</details>

### Is this SQL carrying one tenant's policy? — `policy-template`

A literal in a WHERE clause can be a fact about the world or a setting that differs per
customer. `severity IN ('Critical','High','Medium')` is not a fact about vulnerabilities —
it is **that tenant's severity floor**. Saved as a widget, rule or catalog entry, such SQL
is **correct where it was written and wrong at the next customer**: it runs, returns rows,
and quietly answers a different question. Nothing fails.

```bash
"$TORANA" datalake policy-template --sql "<the SQL>"   # which literals are tenant policy?
```

The platform stores these settings as a **policy vocabulary** — named keys such as
`severity_floor`, each holding one tenant's value. This verb names the key behind each
literal and prints the `{{vocab:…}}` placeholder to bind instead of the hardcoded value.

⭐ **The match is exact, not a guess.** It replays the platform's own renderer over every
candidate value and keeps the one that reproduces the literal set — so it cannot drift from
the shipped software, because it *is* the shipped software run backwards. Only one value of
`severity_floor` produces `('Critical','High','Medium')`, and that value is `Medium`.

| verdict | means | what to do |
|---|---|---|
| ⚠️ `REVIEW` | a key is declared on that column and the literal matches it — **including an exact match** | the SQL is left as written; you decide, because only the asker knows whether the question named the value |
| ◻ `WAIVED` | carries `-- policy-literal-ok: <reason>` | already justified by the author |

⭐ **`torana-text-to-sql` calls this verb automatically.** There it is an input named
**`vocabulary`**, on by default, turned off with *"no vocabulary"*. It reports the findings
and leaves the SQL alone either way.

### Running SQL that carries `{{vocab:…}}`

⭐ **Templated SQL executes normally.** `query`, `query-execute` and `playground-execute` each
bind every `{{vocab:…}}` to this tenant's policy value before running, so SQL written to be
portable is still testable here — no flag, no editing.

```bash
"$TORANA" datalake query --sql "SELECT count(*) FROM vulnerabilities
                                WHERE severity IN {{vocab:…severity_floor.at_or_above}}"
```

The response carries `bound_vocabulary`: the key, the value it resolved to, the origin
(*the tenant's own decision* or *platform default*), and the SQL fragment it rendered. There is
no opt-in flag because binding is **reported** — an executed query is never a mystery, and a
template pasted by accident is visible in the output rather than silently answered.

⚠️ **A bound query can return a different number than the literal form.** That is the point —
it uses the tenant's current policy. On a tenant whose `severity_floor` is `Medium`,
`{{vocab:…severity_floor.at_or_above}}` renders `('Critical','High','Medium')`, not the
`('Critical','High')` someone may have started from.

⛔ **Unresolvable placeholders refuse by name and nothing runs** — an unknown key, or one this
tenant has no value for. It never falls back to a default: a default is a value nobody chose,
and a number computed from one answers a different question.

⚠️ **A `{{vocab:…}}` inside a string literal is left alone** — `SELECT '{{vocab:x}}'` returns
the text, because that is data rather than a reference.

⛔ **It reports; it never rewrites your SQL.** Every verdict is `REVIEW`, even when the
literal set identifies one key uniquely — identifying a value is not knowing the author meant
it as policy. An earlier version did auto-substitute exact matches: a caller asked for
"critical and high", the match was exact, the literal was replaced, and at execution that
tenant's floor resolved to `Medium` — widening the filter and answering a different question.

*"How many critical vulns"* and
*"how many vulns above our floor"* compile to **byte-identical SQL** with opposite correct
treatments: the first must keep its literal, the second must bind the key. The question is
not recoverable from the SQL, so a verb reading only SQL must report and let you choose.

⚠️ **A literal only counts where it DECIDES the result.** Severity names in `ORDER BY CASE`
set sort order and filter nothing, so they are correctly ignored — as is a `SELECT` echo of
a policy value. Verified: the shipped severity-breakdown report returns CLEAN although it
contains six severity literals.

⚠️ **A clean result is reported with the number of keys that COULD have matched** ("12
vocabulary keys are SQL-substitutable"), so "nothing found" is never confused with "nothing
is mappable". ⛔ Most vocabulary keys are deliberately not SQL-substitutable — they toggle
behaviour or route notifications and never appear as literals — so a key you expected may
be absent by design rather than by omission.

⚠️ **This does not replace `sql-reachability`'s `hardcoded_policy` field.** That one asks
*"is this literal policy-SHAPED?"* using a word list, and still catches policy-looking
literals on columns no vocabulary key maps to. This one asks *"WHICH key, and what value?"*
and is exact. Run both; neither is a superset of the other.

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
across the whole schema.

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
| The `sql-reachability` verdicts | `pantheon-datalake/tests/test_sql_reachability_verdicts.py` | ✅ **Yes** — a collected suite, so a regression fails the run |
| Whether shipped SQL uses reachable columns | — | ❌ **No such check exists** |
| Whether a mapping conforms to its category model | `torana-integration-model` skill | ❌ Run on demand only |
| Mapping conformance **at generation** | `validate_bundle.py` (`/generate-integration`) | ✅ **Yes** — the one enforced gate |

⭐ The first row used to read ❌. The check lived as a standalone script inside a skill's
`scripts/`, where pytest never collected it; moving the logic into the platform put it under
a suite that runs.

⚠️ **The one thing that IS enforced is generation-time**: a new integration cannot be
generated writing to the wrong table. Everything already shipped was authored before these
checks existed and has never been gated.

⚠️ **This matters most for a checker's own correctness.** A regression suite written
alongside one of these checks caught **four real bugs in it — three of which passed ad-hoc
testing first**, including one where `SELECT cve_id` verified zero columns and reported a
false ✅. A checker that is wrong is worse than no checker: it answers confidently, and
nobody investigates a ✅. An unwired suite catches nothing on the next change.

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
