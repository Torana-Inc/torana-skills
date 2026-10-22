# Datalake — schema discovery and authoring SQL

> A customer's open question about their data ("which repositories have the most critical findings") is answered by the `torana-data-analyst` skill, which gets its SQL from `torana-text-to-sql`. This file is the command reference they build on.

The datalake is the canonical store, and **`schema-ddl` is the one place to learn its schema.**
`schema-ddl --index` labels every table: **sinks** hold rows integrations wrote as they synced;
**transformers** are computed tables, the output of a saved query someone scheduled (an app's own
relations, such as `posture_*`, are transformers); **derived** tables are platform-computed lookups;
**reference** tables are cross-tenant data. Rules, widgets and other transformers read from all of them.

---

## ⚠️ Read this before writing any SQL

**The datalake declares far more columns than any pipeline fills.** A column existing in the
schema is NOT evidence it will ever hold a value. Ask the CLI for the current split rather
than trusting any number written down — it moves whenever a pipeline lands.

⚠️ **This is not theoretical, and it is why the check exists.** A shipped library of reviewed
SQL definitions (since retired) was authored by reading the schema
column list, before any
reachability check existed. Their SQL returned nothing. Tracing back found the columns were
valid, declared and documented — and **written by nothing**. **74% of that SQL can never run on
any tenant.**

⭐ **Start with `schema-ddl`, not the individual verbs.** It renders every fact about a column
on or above that column's line, reading each one from the surface that owns it — so the DDL
cannot disagree with them. The verbs below still work and are the reference when you want one
fact on its own; `schema-ddl` is the authoring path.

```bash
"$TORANA" datalake schema-ddl --index --stable        # every table: kind, grain, what it is for
"$TORANA" datalake schema-ddl --tables <a,b> --with preset:answer --stable
#   preset:answer = meaning, domains, reach, trust, measures: metadata only, so it is free.
#   --stable leaves tenant-measured facts (join trust, transformers not healthy here) out of the
#   DDL and prints them after it as LIVE STATE. Read both.
#   Add --with values (or preset:data) only when a question needs this tenant's actual rows.
"$TORANA" datalake sql-reachability-and-policy --sql "<the SQL>"  # judge the SQL BEFORE anyone runs it, in one call
"$TORANA" datalake supply sql-columns --sql "<the SQL>"  # why would each column it reads be EMPTY here?
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


### Is this SQL carrying one tenant's policy? — `policy-template`

A literal in a WHERE clause can be a fact about the world or a setting that differs per
customer. `severity IN ('Critical','High','Medium')` is not a fact about vulnerabilities —
it is **that tenant's severity floor**. Saved as a widget, rule or transformer, such SQL
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

**Hand-written placeholders are validated, not created.** Some keys have no column to anchor
on: day and hour counts (`sla_warning_lead_days`, `kev_remediation_window_hours`,
`scan_frequency`), counts and targets (`min_group_size`, `scan_coverage_target_pct`). The verb
never templates a literal such as `INTERVAL '7 days'` for them. When the SQL already carries
such a placeholder, the report (with and without `--bind`) adds one line per placeholder:

```bash
"$TORANA" datalake policy-template --sql "SELECT 1 FROM vulnerabilities v WHERE NOW() + ({{vocab:vm.remediation.sla_escalation.sla_warning_lead_days}})::int * INTERVAL '1 day' > v.scan_first_detected_date"
#   ✅ Hand-written, validated  sla_warning_lead_days  line 1  (interval arithmetic)
```

`⛔ Hand-written, INVALID` names what is wrong: `UNKNOWN_KEY` (no such key), `WRONG_PATH` (not
the qualified path), `NOT_BARE` (a scalar is written bare with your own operator, or with a comparison verb and no
operator: `col {{vocab:….gte}}`; no other verb),
`QUOTED_PLACEHOLDER` (inside a string literal, never bound), `NOT_NUMERIC_CONTEXT` (not in a
numeric comparison, interval arithmetic, a `LIMIT` or the SELECT list, for example a function
argument). Echoing the value in the SELECT list (`({{vocab:…}})::int AS cadence_days`) is valid. In JSON it is the
`hand_written` list (`key`, `placeholder`, `line`, `status`, `context`, `code`, `detail`).

⭐ **`torana-text-to-sql` calls this verb automatically.** There it is an input named
**`vocabulary`**, on by default, turned off with *"no vocabulary"*. On, it runs the report and
then `policy-template --bind`, and hands back the templated SQL the binder printed; off, it
hands back literal SQL. Without `--bind` this verb itself never rewrites the SQL.

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

### Running LITERAL SQL with declared policy keys

⚠️ The skill path does not need this: with vocabulary on (the default), `torana-text-to-sql`
hands back SQL already templated by `policy-template --bind`, and you run it as above. This is
for a caller that holds literal SQL plus the keys it judged policy.

`query` and `query-execute` take `--question "<the user's words, verbatim>"` and
`--policy-keys k1,k2`. Code templates
each declared key's literal into `{{vocab:…}}` — **unless the question names that value** —
then binds this tenant's value as above, and runs it:

```bash
"$TORANA" datalake query-execute --sql-query "<literal SQL>" \
    --question "<the user's question>" --policy-keys severity_floor
```

Text output prints `Policy bound: <key> ← <value> (<origin>)` or
`Policy left literal: <key> (<reason>)` before the rows; `--json` carries `policy_bind` and
`bound_vocabulary`. Without `--policy-keys` the SQL runs exactly as written.

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

## Column facts come from the DDL

Everything you need to know about a column is in `schema-ddl`, on or above its line. Use the DDL
and nothing else for the schema.

- **Does the column exist?** Only a name you have seen in the DDL output is real. Names do not follow
  a guessable convention across tables: on `vulnerabilities` the identity column is
  `torana_entity_id` (not `asset_id`) and first-seen is `scan_first_detected_date` (not
  `first_seen_at`). A plausible name that does not exist fails; one that exists but is unreachable
  returns NULL on every row, silently.
- **What does it mean, what does it hold, can anything fill it, does the join connect?** The
  `meaning`, `domains`, `reach` and `trust` layers of `preset:answer`. A column tagged
  `UNREACHABLE` is declared and permanently empty here: never put it in a SELECT, WHERE or JOIN.
- **Who writes it?** `--with writers`.
- **Does this tenant hold the values the DDL declares?** Declared and observed domains answer different
  questions. Write against the declared set; check the observed one before you filter on it:
  `"$TORANA" datalake schema-ddl --tables <t> --columns <c> --with values`. Casing is the expensive failure:
  `WHERE severity = 'critical'` against data holding `'Critical'` returns zero rows with no error.
- **What does one row of the answer mean?** The `measures` layer.
- **Do not fetch everything.** Ask for the index, pick the tables the question reaches, name the
  columns you will use, and add a measured layer (`rows`, `shape`, `fill`, `values`, `graph`) only for a
  specific doubt.
- **`--stable` and LIVE STATE.** With `--stable` the DDL text carries no measured facts, so it stays the same
  from one call to the next; the join-trust verdicts and the transformers that are not healthy here
  come back in the LIVE STATE block after it. A join marked `NORELY` or `UNMEASURED` there is a join not to trust.

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

## Is a saved proof still true? — `proof verify` / `proof replay`

`torana alert <id> proof --save FILE` (detection.md) records an item's claims and every value behind them. Two
read-only checks take that FILE back:

```bash
"$TORANA" datalake proof verify /tmp/proof.json                        # rebuild it NOW, compare claim by claim
"$TORANA" datalake proof verify /tmp/proof.json --save /tmp/now.json   # …and keep the fresh record
"$TORANA" datalake proof replay /tmp/proof.json                        # recompute from its OWN captured values
```

- **verify** answers "is it still true?". Each claim comes back `unchanged`, `aged` (only the clock moved, e.g.
  "22 hours ago"), `inputs_moved` (same text, an input changed underneath), `changed`, or `evidence_gone` (a row it
  read is gone), with one reason per input that differs: `value_changed` (then → now), `membership_changed`,
  `row_gone`, `rule_changed`, `meaning_changed`. The file must belong to the profile's tenant (else 400).
- **replay** answers "was it computed from what it says?". It reads no tenant data and exits 1 when the record
  does not reproduce: the rule code changed (`NotCaptured`), or the record was edited.
  - A record from an older proof framework still replays. The output adds `framework changed: 0.2.0 → 0.4.0` and
    one `rule changed: <rule> vN → vM` line per rule that moved (JSON: `framework_changed`, `rules_changed`).
  - Only a different MAJOR framework (a record-format change) is refused with 400 "…rebuild it": re-save the record
    with `torana alert <id> proof --save FILE`.
- Any tenant user (`datalake:read`; verify also needs `alert:read`). A record over 1 MiB is refused (413).

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

