---
name: torana-text-to-sql
description: >-
  Turn a question about a security estate into PostgreSQL against the Torana datalake, and
  say plainly when the data cannot answer it. The datalake declares far more than it holds:
  a column can exist, be correctly named, and hold nothing until a named caller runs — so SQL
  over it parses, runs, and returns a confident empty answer. This skill grounds every query
  in the schema as annotated DDL, then judges the SQL before anyone runs it. Use it whenever
  someone wants SQL for a datalake question, asks how many vulnerabilities / which assets /
  show me findings by X, asks whether a question is answerable from the data, or asks why a
  query returns nothing. It produces one of three answers: SQL, SQL plus what it does not
  answer, or no SQL plus what is missing — a column the schema does not have, or a subject the
  datalake does not cover at all. Every answer ends with a grounding note naming what the
  SQL was checked against and what was not. It does not run the SQL — `torana-data-analyst`
  does that.
compatibility: Requires the torana CLI (loaded via torana-skill)
metadata:
  version: "2.0"
---

# Writing SQL against the Torana datalake

Requires `torana-skill`, which owns the CLI.

⛔ **Write the SQL yourself, with this skill.** Do not hand the question to a Torana assistant or agent to
write it. Your own difficulty writing a query is not a reason to; ground it better (the index, the DDL, the
layers below) and check it.

## Overview

The datalake's schema is a declaration of what *could* be collected, not a description of what
is there. Some columns fill only when a named caller runs, and hold nothing until then; a
declared join can connect every row, some of them, or none, and which one holds is measured per
tenant rather than promised by the schema; a column can be correctly named and empty here. None
of it raises an error — the SQL parses, executes, and returns a number that looks like an
answer.

So there are two acceptable outputs, and the second matters as much as the first: SQL when the
data supports the question, and a precise gap when it does not. A precise gap names a column
and says what the platform reports about it, or names a subject and says the datalake does not
cover it. "I could not find that" is not an answer.

### Why the joins are soft

Each table is filled by integrations syncing on their own schedules — a scanner, a cloud
provider, a ticketing system, each arriving separately and knowing nothing of the others. No
step assigns shared identifiers, so rows are keyed by a **value each source computes
independently**: a container image digest, a package URL (`purl`), a namespaced cloud resource
path.

```
torana_entity_id    image:us-west1-docker.pkg.dev/…/service-a@sha256:64806e…
torana_package_id   pkg:deb/debian/openssh@1:9.2p1-2+deb12u10
```

Two sources land on the same row only when they compute the identical string, and nothing
enforces that they will. The DDL marks these relationships `JOIN KEY` rather than the SQL
`FOREIGN KEY` for exactly this reason: it tells you which columns to join on, and promises
nothing about a partner existing. A row can point at a partner that was never ingested, and
nothing objects.

Three consequences follow. **Read a join's measured trust before counting through it** — the
`trust` layer is narrower than the word suggests: it is not a quality score for the data, it is
the measured share of rows on this tenant that actually find a partner. **Join keys whole,
never sliced** — the prefix is part of the value, not a namespace to strip. And **a missing
partner is a real finding**, worth reporting as a number rather than dropping.

### What grounding a query consists of

**Thirteen inputs, each named and each requested separately**, so you pay only for what the
question reaches. Knowing they are distinct is the point: a query can be correct against the
schema and wrong against every one of the others. **These names are the vocabulary of the note
you end with**, so a reader can tell what was checked from what was not.

`Stage` says *when* an input acts — **before** you write the SQL (grounding: it describes the
schema) or **after** it is written (checking: it judges the SQL). That is also which line of
the note reports it.

| Input | Stage | Ask for | Default | What it settles |
|---|---|---|---|---|
| tables, columns, types, keys | before | (bare) | **always** | what exists and what a row is |
| the table index | before | `--index` | **always** | which tables exist, their kind and grain |
| `meaning` | before | `--with meaning` | **on** | what a column *is*, and the traps in it |
| `domains` | before | `--with domains` | **on** | the values the column is allowed to hold, `[closed]` or `[open]` |
| `reach` | before | `--with reach` | **on** | whether anything can ever fill it |
| `trust` | before | `--with trust` | **on** | whether each declared join actually connects, measured here |
| `measures` | before | `--with measures` | **on** | what ONE ROW of the answer means — the named alternative readings |
| `writers` | before | `--with writers` | off | which pipeline writes it |
| `graph` | before | `--with graph` | off ⚠ | edge types, their direction, how keys resolve, with live counts |
| `rows` | before | `--with rows` | off ⚠ | live row counts |
| `shape` | before | `--with shape` | off ⚠ | constant / enum / key / high-cardinality |
| `fill` | before | `--with fill` | off ⚠ | how many rows carry a value |
| `values` | before | `--with values` | off ⚠ | what **this tenant** actually holds, with counts |
| `validity` | after | (cannot be turned off) | **on** | will this SQL run, and does anything fill what it reads |
| `vocabulary` | after | *"no vocabulary"* turns it off | **on** | which literals in the SQL are *this* tenant's settings rather than facts about the world. **On** (the default): `policy-template --bind` templates them into `{{vocab:…}}` **in code** — never you — and you hand back **the SQL it prints**, for a question asked once and for saved SQL alike. **Off**: literal SQL, exactly as written. See § vocabulary |

The eleven `before` layers are served by `schema-ddl`. `preset:answer` =
`meaning domains reach trust measures`; it is metadata only, so it is free to fetch and is the
right default. ⚠ marks the five that scan live rows: they describe one tenant at one moment and
do not travel to another.

The two `after` inputs act on the finished SQL, so they are not part of `Grounded:` — each
reports on its own line of the note. `validity` is the only input with no off switch: handing
over SQL that cannot execute is never a wanted outcome. `vocabulary` has one, because it
changes what the SQL is *for* rather than whether it is right — see below.

Declared and observed domains answer different questions, and the gap between them is usually
wide — a column commonly *allows* a handful of values while a given tenant holds two or three
of them. **Write against the declared set.** It is what makes a literal correct, and it is the
same for every tenant. The observed set describes what one tenant holds today; a predicate
built from it silently excludes whatever arrives tomorrow, and it belongs to whoever is
reading the rows, not to whoever is writing the query.

### Which examples to read

`references/` holds worked examples graded by how much of the above a question needs. Each
level adds a way to be wrong that the level below cannot produce, so read up to the level your
question reaches and stop.

- **`L1-single-table/`** — one table. A wrong answer is usually visible.
- **`L2-declared-joins/`** — joined tables. A wrong answer is plausible: fewer rows, correctly
  shaped, silently.
- **`L3-entity-graph/`** — what runs where, what contains what. A wrong answer is confident and
  large.
- **`L4-cannot-answer/`** — the fact may not be recorded anywhere, and a neighbouring column
  looks right while answering something else.

## Quick start

```
torana datalake schema-ddl --index --stable
torana datalake schema-ddl --tables vulnerabilities,assets --with preset:answer --stable
torana datalake sql-reachability-and-policy --sql "SELECT …"
```

If the index lists `inbox_items`, start Inbox questions from `inbox_items`, `inbox_entries` and `inbox_activities`; take facts about the finding from the `JOIN KEY` target, never from the item.

Read the index and decide which tables answer the question (`## Choosing tables`). Fetch those
tables annotated — `preset:answer` is the free metadata set, and the output header prints its
expansion so you always know what you got. **Write the SQL yourself from what came back**: the
calls fetch context and check the result, but none of them writes anything. Then judge it
before anyone runs it.

It is a loop, not a pipeline. Discovering in the DDL that a column you wanted does not exist, or
that a join you assumed does not connect, sends you back to table choice — that is the check
working, not a setback.

**You can stop at any step, and stopping is an answer.** If the index shows no table holds what
is being asked, say so there: you do not need the DDL to report a gap you have already found.

## Choosing tables

Read the index first. It labels every table as one of four kinds, and the difference decides
how much you can trust what is in it.

**Sinks** are where ingestion lands. `vulnerabilities`, `assets`, `packages`, `entity_edges`
and the rest hold rows written by integrations as they sync — raw facts, one row per thing
observed, no interpretation applied.

**Transformers** are computed tables: a saved SQL query that someone wrote, reviewed and
scheduled, whose output is materialised as its own table. `mttr_monthly_trend` is not collected
from anywhere — it is computed from the sinks on a schedule, and the computation embodies
decisions the sinks do not record: which statuses count as "resolved", where a bucket boundary
falls, what "overdue" means for this tenant. The index states each one's **grain** — what a
single row represents — and a sentence saying what the table is for.

The word names both halves — the scheduled job and the table it writes — and which is meant is
usually clear from the sentence. Where it is not, this file says "transformer table" for the
table.

**Reference** tables (`vm_cve_*`) are cross-tenant data, so always join them to a tenant table
rather than scanning them alone.

**Derived** tables (`[derived]` in the index) are rebuilt by a platform job from sink data, and
each exists to answer one kind of lookup that no hand-written join answers on every tenant. The
index line says which lookup. They are not optional context: when the question touches what a
derived table is the lookup for, fetch its DDL and use it.

⛔ **Who owns a finding, and how much its place matters, is read from the derived governance
table, never from `assets` alone and never by walking `entity_edges`.** Team, owner, environment,
criticality, internet exposure and the customer-data flag are declared on a deployment, while
findings sit on images and repositories, so a direct `vulnerabilities` to `assets` join finds a
partner for few of them or none (its trust tag says so). The moment a question names any of
those six things for a finding, add the governance table to the fetch and write both joins, the
second for findings on hosts and cloud resources, whose governance is on their own asset row:

```sql
LEFT JOIN entity_properties_resolved g
       ON g.entity_key = COALESCE(v.torana_entity_id, v.torana_repository_id)
      AND g.is_deleted IS NOT TRUE
LEFT JOIN assets a
       ON a.torana_entity_id = v.torana_entity_id AND a.is_deleted IS NOT TRUE
...
COALESCE(g.asset_team, a.asset_team) AS asset_team   -- the same shape for each of the six
```

**"Who owns it" has two answers, and the SQL returns both.** `asset_team` is a team somebody
declared. `g.repository_owner` is the owner or organisation login of the repository the code
lives in: an observed fact, not a team, and on a tenant that has declared no teams the only
answer there is. Wherever the SQL returns the team, return `g.repository_owner` beside it. When
the question groups or ranks BY owner, the key is
`COALESCE(g.asset_team, a.asset_team, g.repository_owner) AS owning_team` with a second key
column saying which supplied it (`'declared_team'` / `'repository_owner'`), grouped by both. When
the question is about MISSING ownership ("which have no owner"), test the declared team alone
(`COALESCE(g.asset_team, a.asset_team)`, never the asset's own column by itself) and show the
repository owner as a column. Never write `'unassigned'` for a NULL, and never put
the repository owner under a column called `asset_team`.

A finding neither join reaches is unowned or undeclared: keep it and let the NULL show. Measured:
a blind run that joined `assets` directly returned no owner for any image finding and reported
internet exposure as false where the resolved value was true.

### Which to use

A transformer that genuinely answers the question is the better choice, because recomputing its
logic from the sinks means guessing the decisions it encodes, and a guessed threshold gives a
confident, plausible, wrong number.

A transformer is a scheduled job, and jobs stop: the table survives holding whatever rows it
last produced. The index flags every table no healthy transformer currently maintains.

**That flag does not change the SQL, and it is not a reason to reject a table.** The query
against a stale transformer is identical to the query against a maintained one, and the
staleness is not durable — someone rematerialises the table and the same SQL returns current
rows. A caveat written into the answer today is wrong tomorrow, and it does not travel with the
SQL when the SQL is saved to a widget or a transformer.

So choose on **grain and fit** — does one row of this table mean what the question asks about.
Report staleness only where it survives the moment: when the SQL will be saved or shipped, a
transformer that nothing maintains is a dependency worth naming, which `## When the SQL will be
saved or shipped` covers.

Whatever you pick, match the grain the question asks for, take the fewest joins that get there,
and never force a fit. A table that nearly answers the question answers a different one.

**An index line with no grain is not a reason to skip the table — fetch its DDL.** The index line
is the first sentence of a table's description, and a table whose description opens with something
else simply has no grain printed there. That says nothing about whether it fits. Measured: the
table that correctly answered a deduplication question was passed over because its index line
showed no grain, and a worse table was used instead. If a table's name or subject is plausible,
ask for its DDL and read the real grain before ruling it out.

**Preferring a transformer is not a reason to prefer a particular one.** When none sits at the
question's grain, go to the sink and compute — a transformer bent to fit (grouped away from its
grain, or with the population its definition restricts it to ignored) returns an authoritative
number for a question nobody asked. Cross-check a transformer total against the sink before
handing it over; a disagreement is a finding worth quoting, not a rounding error.

⛔ **When a transformer carries its own decision, return that decision; do not regroup its codes
into classes of your own.** A ranking table records where each finding was put: a tier, a state, a
route, a reason, or a flag that names a class. Use that column before any vocabulary key (§
vocabulary): group by it, show its own labels, and let the reader see every value. If the
question's word ("urgent") is not one of the table's values, return the table's classes and say in
one sentence which of them you read as that word and why; never fold them into a `CASE` that hides
the original. Measured: two sessions asked a near-identical question of one ranking table an hour
apart; one grouped reason codes and called 273 findings urgent, the other grouped tiers and called
5,824 urgent.

## Which layers to ask for

`schema-ddl --help` lists all eleven layers and what each one shows. Five scan live rows —
`graph`, `rows`, `shape`, `fill`, `values` — and the help text tags only four of them, so take
the ⚠ marks in the table above as the list.

**`--with preset:answer` is the default fetch**, and it is enough unless the caller asks for
more. It answers the four questions that most often make a query wrong without making it
fail: what does this column actually mean, how are its values spelled, does anything write it
at all, and does this join connect here.

⛔ **Do not add a measured layer on your own initiative** — `rows`, `shape`, `fill`, `values`,
`graph` counts, `preset:data`. They describe what comes back, not what to write, and fetching
them to see the answer in advance is the caller's job, not this skill's. Saying a table is
empty or that a filter will match nothing is a claim about this tenant at this moment that
expires the next time an integration syncs; `torana-data-analyst` runs the query and sees it
directly.

⚠️ **One narrow exception: a column you are about to BUILD A CLASSIFIER ON.** When the answer's
shape depends on one column's contents — bucketing rows by it, calling rows stale or active or
unowned by it, deriving a status from it — fetch `fill` for that column before writing the
classifier. This is not fetching the answer in advance; it is checking that the column the whole
output is organised around holds values at all. A classifier over an empty column returns tidy
buckets that are an artefact of the emptiness, and nothing downstream reveals that. Measured: a
staleness classifier was built on a column no integration writes, so every asset came back in one
bucket and the answer read as a finding about the fleet. Fetch the one column, not the table, and
if it is unfilled say so and use a column that is filled (or return the third answer).

### When the caller names layers, use exactly those

The layers are an input. If the request says *"…and include values"*, or *"with shape"*, or
names any layer, add it to the fetch and say so in the grounding note:

```
torana datalake schema-ddl --tables vulnerabilities --with preset:answer,values
```

A caller asking for a measured layer knows their situation — an operator questioning a live
system may want the data shape, and this skill cannot tell from the question alone. Take the
instruction; do not second-guess it, and do not substitute a different layer for the one named.

⛔ **Never silently drop a layer the caller named.** If it cannot be fetched, say which and
why — that is the `requested, but empty` or `⚠ DEGRADED` line in the DDL header, relayed.

The same applies to `vocabulary`: on by default (the SQL you hand back is templated by
`policy-template --bind`), off on *"no vocabulary"* (§ vocabulary). Whichever way, the `Vocabulary:` line says
what happened — literals left in place are reported as left, with the reason, never omitted.

Fetching every layer for every table is not thoroughness. Nothing marks the four or five facts
that decide the query, so they arrive with the same weight as the thousands that do not, and
finding them again becomes its own search.

## Facts recorded in more than one form

When a question hinges on a fact the platform records in more than one form (membership of a catalogue, recorded
evidence, a prediction score), keep the forms apart: the SQL returns each one the question touches, and the
answer says which form each statement rests on. Exploitation is the usual case: catalogue membership (which covers
every CVE), recorded exploitation evidence and the EPSS score are three separate facts. A prediction is never
evidence, "likely to be exploited" is not "known exploited", and an empty field usually means nobody checked: say
"nothing recorded", not "no".

## Writing the SQL

**Name the measure in a comment on the first line**, because the English question rarely fixes
the unit. "How many vulnerabilities" means either findings or distinct CVEs, and the two differ
by an order of magnitude.

```sql
-- MEASURE: one row per distinct CVE, excluding findings that carry no cve_id.
SELECT count(DISTINCT cve_id) FROM vulnerabilities WHERE is_deleted IS NOT TRUE
```

That comment is what a reviewer reads to check you counted the thing that was asked for.

**When the question asks for one figure (a share, a rate, a ratio), return it as a column of its
own**, on a total row or beside the breakdown: the reader never adds rows up to get it. A ratio
near 1, or a share near 0 or 100, keeps enough precision to show it is not exactly that: return
both counts and a percentage with two decimals, never a ratio rounded to two. A share names
what it is a share of, in the column name or the MEASURE line; when the question is about work
still to do, the denominator is the open population, not every row the table keeps.

**The column list decides the `is_deleted` filter — not whether the table is a sink or a
transformer.** If the table's DDL lists `is_deleted`, filter it: `is_deleted IS NOT TRUE`. If the
DDL does not list it, add no filter; the clause would fail the whole query with `column
"is_deleted" does not exist`.

Rows are marked deleted rather than removed, so an unfiltered read counts rows that no longer
exist. That applies to transformer tables too: a transformer updated in place keeps a departed
row as a tombstone, so it can carry both live rows and tombstones at once. Only a table rebuilt
whole has no tombstones — a row that should not be there is simply not produced — and those
tables do not have the column, which is why the column list is the reliable test. Do not reason
from how you think the table is built; read its DDL.

Filtering a column that happens to be `false` on every row costs nothing and is still correct.
So when the column is in the list there is no judgement to make: filter it.

**The filter must constrain every row the statement returns — give it its own top-level `AND`,
never a branch of an `OR`.** A question asking for two classes ("already breached, and about to
breach") invites `WHERE breached IS TRUE OR (breached IS NOT TRUE AND is_deleted IS NOT TRUE)`,
where the first branch has no deletion test and returns every deleted breached row. Measured on
an agent run carrying this rule: it returned the right total only because no deleted row
happened to be breached that day, so the query was wrong and read as correct. Write eligibility
once, outside the class logic: `WHERE is_deleted IS NOT TRUE AND (<class A> OR <class B>)`.
Deletion decides whether a row exists at all, never which class it belongs to.

**In a LEFT JOIN, put the filter in the `ON` clause, never in `WHERE`.** In `WHERE` it turns the
LEFT JOIN into an inner join and silently drops rows whose partner is missing, which defeats the
reason you chose a LEFT JOIN.

⛔ **Exception — a question about history keeps the deleted rows.** For closures, retirements,
remediation flow, MTTR, backlog over time, or "what was fixed/retired/decommissioned", a
soft-deleted finding IS the closure; filtering it erases the event the question asks about. A
retired finding can still carry an open-looking status, so a status test cannot find those
closures either. For these questions do not filter `is_deleted` — read the closure counts the
history table publishes as its own columns (its remediated / retired / disappeared measures) and
say which closure kind each number covers.

**Join along the `JOIN KEY` lines, and read the trust tag on each one.** The tag is one of four
values, measured on this tenant's rows:

| Tag | Means | What to do |
|---|---|---|
| `RELY` | orphan rate at or below 1% | join normally |
| `DEGRADED` | works for most rows, silently drops the rest | quote the orphan rate |
| `NORELY` | rows name partners that do not exist | an empty result is **not** evidence of absence — say so |
| `UNMEASURED` | nobody has checked | never read this as "fine"; say the join is unverified |

On anything but `RELY` the join silently drops rows, so quote the orphan rate in the answer
rather than presenting the count as complete — and consider a LEFT JOIN that counts the
unmatched rows, which `references/L2-declared-joins/` works through.

⚠️ `UNMEASURED` has several causes and they are not interchangeable — the tag says which. Every
key NULL means the join is **unused** here, not broken. A missing column means the semantic
model declares a join the live schema does not have, which is a declaration defect worth
reporting rather than working around. An empty table means it cannot be measured yet.

`entity_edges` is the exception: it carries no `JOIN KEY` lines because the graph is traversed
through `from_key` and `to_key`, always with an `edge_type` filter. That is a different shape
with its own traps, covered in `references/L3-entity-graph/`.

**Some columns hold a vocabulary; most just hold data.** `severity`, `scan_type` and
`vulnerability_status` take one of a small set of agreed values, and the annotations list them:
`--with domains` gives the declared set, which holds for every tenant. That is the set to
write against — a literal it allows is correct here and everywhere.

**Take the literal from the annotation, never from memory.** A value the column does not hold
matches nothing and nothing reports it: the query succeeds, returns zero rows, and reads as a
real answer.

Two different ways to get that wrong, and the second is easy to miss.

The domain is marked `[closed]` or `[open]`, and the marker is the point. **Closed** means the
platform normalises the column on ingest, so the declared list is exhaustive and a misspelling
or wrong case cannot be a real value. **Open** means the list is the values described so far and
another may appear, so an unexpected one is not proof of a mistake.

Either way, a correctly-spelled declared value may simply be absent on this tenant — one that
runs no SAST scanner holds no `scan_type = 'SAST'` row, and filtering on it returns zero as
quietly as a typo would. ⚠️ That is not a reason to change the SQL. `scan_type = 'SAST'` is the
correct query for the question; zero rows is the correct answer, and it means *nothing ran a
SAST scanner here*. Whoever runs the query reports that. Rewriting the predicate to match what
this tenant happens to hold would answer a different question everywhere else.

⚠️ **The same holds for a whole limb of the question.** A tier, a join or a condition whose table
or column holds nothing on this tenant yet (a pentest-proven tier with no pentest run, a
compensating-control test with no control recorded) stays in the SQL and returns nothing here.
Removing it makes the SQL right for this tenant today and wrong on the next one. When an empty
input would make a test pass for every row ("no control recorded" is not "no control in the
way"), return it as a column that shows NULL and count the rows it is unknown for: never a
filter, never dropped. This is not the unusable column of `## The three answers`, which nothing
can fill on any tenant.

A `cve_id` or a `package_name` is not that kind of column and has no vocabulary to check: those
values arrive from scanners, so the only sensible literal is one the question itself supplied.

⛔ **When the question points at a thing it does not name ("this vulnerability", "a new CVE",
"the affected product"), never invent a value to filter on.** A stand-in such as
`'CVE-0000-00000'` returns nothing until someone edits it, and an empty result reads as "we are
not affected". Write the answer at the grain of the unnamed thing (one row per CVE, or per
package), ordered so the likeliest candidates come first, with the filter on a commented line
the caller can switch on: `-- AND v.cve_id = '<the CVE>'`. Say in the first line of the answer
that the question named none. The SQL must run, and return rows, as handed over.

Mind the NULL rules throughout: `!=` and `NOT IN` never match NULL, so excluding a value that
way also drops every row where the column is NULL. `IS DISTINCT FROM` is usually what was meant.

### The nullable-boolean rule

**On a nullable boolean, write `IS TRUE` / `IS NOT TRUE`. Never `= true`, `= false`,
`!= true`, `<> true`.**

`IS NOT TRUE` is *total* — it returns true or false for every input including NULL, so it
needs no second branch:

```
x IS NOT TRUE  ≡  (x = false OR x IS NULL)  ≡  COALESCE(x, false) = false
```

Why it matters, on the only case that convinces anyone. Over `{true, false, NULL, NULL}`:

```sql
COUNT(*) FILTER (WHERE fp != true)   -- returns 1
COUNT(*) FILTER (WHERE fp IS NOT TRUE)  -- returns 3   ← the answer expected
```

Two rows vanish. No error, no warning, and nothing in the output says a row was dropped.
`NULL != true` is NULL, not TRUE, and a predicate that is NULL does not match.

**Which columns this applies to — read it, do not guess.** A column is nullable when the
schema does *not* mark it `not_null`. `schema-ddl` renders `NOT NULL` on the column line
where it applies. ⚠️ The
absence of `not_null` is the nullable signal — there is no positive `nullable: true` key.

On a NOT NULL boolean, `= false` and `IS NOT TRUE` are exactly equivalent and either is
fine. The rule costs nothing to apply everywhere, so prefer `IS NOT TRUE` by default rather
than looking each column up.

**What a NULL MEANS is declared — read it before you write the sentence around the number.**
The `domains` layer (in `--with preset:answer`) prints a `NULL means …` tag after
`values[closed]: true, false` on every nullable boolean. ⛔ `values[closed]` alone reads as
"these two values cover every row"; the `NULL means` tag is what says they do not. It also
tells you what the NULL rows ARE, which changes the answer's wording: *"not reported by the
provider"* (say the count includes unknowns) versus *"no decision recorded"* (they are the
backlog).

⛔ **The `NULL means` tag binds a filter that SELECTS rows too.** `col IS TRUE` keeps only rows
a source vouched for, so a NULL there is "not reported", never "no". For **every** boolean the
WHERE clause depends on whose `NULL means` says it was not reported, not only the one the
question is about: return its unreported rows as a column of the same statement
(`count(*) FILTER (WHERE col IS NULL) AS <col>_not_reported`). ⛔ That count must see the rows
the flag removes, so a selecting flag goes in each count's `FILTER`, never in `WHERE`:
`count(*) FILTER (WHERE a IS TRUE AND b IS NOT TRUE)` beside `count(*) FILTER (WHERE a IS
NULL) AS a_not_reported`. Under `WHERE a IS TRUE` the unreported count is always 0.
Name each such column in the answer. When that column equals the population, the answer
is unknown: a 0 is never a clean result. *"Admins without MFA: 0"* over an estate where no
source reports admin roles is the failure this prevents.

⛔ **On the triage flags (`is_triaged`, `is_false_positive`, `is_risk_accepted`,
`is_verified`, `is_suppressed`), `false` is ALSO undecided.** Most ingest paths stamp these
`false` on insert, others leave them NULL, and only `true` records a human decision. So
`IS NULL` is as wrong as `= false` here: *"how many are untriaged?"* written `is_triaged IS
NULL` returns zero on a tenant whose scanners stamp `false`. `IS NOT TRUE` is the only form
that selects the untriaged rows under both conventions. ⚠️ Untriaged is not the backlog: a
fixed finding nobody triaged is untriaged too (see *A "still" question* below). The `NULL means` tag on these columns says
so; `sql-reachability` does **not** flag `IS NULL`, so this one is on you.

⛔ **This is the same argument as the anti-default rule below** ("paper over it with a
default"), one layer down. There, `COALESCE(col, 0)` turns *never measured* into *measured
zero* in the OUTPUT. Here, `col = false` turns *nobody has triaged this* into *triaged and
found negative* in the PREDICATE — and then drops the row, so the reader never sees even the
wrong value. Both convert an absence into a confident claim; this one also hides the
evidence.

⭐ `sql-reachability` now checks this mechanically and reports `nullable_boolean` findings,
naming the column, the required form and (as `null_means`) what the dropped rows are.
Relay those findings rather than re-deriving them.
It is a warning, never a refusal: `= false` can be deliberate when you genuinely mean
"explicitly false, excluding unknown" — say so when you mean it.

### A "still" question takes the standard open population, then only what it names

Words such as *still*, *currently*, *outstanding*, *pending*, *waiting* or *backlog* ask what is
waiting **now**.

⚠️ **The trigger is wider than that word list.** A question phrased as presence, exposure or risk
asks the same thing without any of those words: *"do we run X anywhere"*, *"what is exposed"*,
*"which assets carry the most risk"*, *"who is affected"*. A fixed finding is not exposure and a
resolved one is not risk, so these take the open population too. Ask what the question means
rather than matching its vocabulary: if a resolved row would be wrong in the answer, filter the
state.

**The open population is one fixed set of four lines, the same on every such question:**

```sql
WHERE v.is_deleted IS NOT TRUE
  AND v.vulnerability_status IN (<the open states>)
  AND v.is_false_positive IS NOT TRUE
  AND (NOT {{vocab:vm.prioritization.scope_gates.exclude_risk_accepted}} OR v.is_risk_accepted IS NOT TRUE)
```

1. **Status is one of the open states**: `IN` exactly the set the tenant's vocabulary declares
   as open work, or, with no declaration, the open states in the status column's domain
   annotation. Write it as `IN (…)` even when the set holds one value: `--bind` templates an
   `IN` list into the tenant's set and refuses an `=` (`OPERATOR_SHAPE`), leaving the literal.
   Never assemble an exclusion list yourself.
2. **Not a false positive.** A finding somebody ruled a false positive is not open work on any
   tenant, whatever its status still says.
3. **Risk-accepted findings leave only when this tenant's policy says they do.** That is a
   setting, not a fact, so the line is written with its vocabulary placeholder exactly as shown
   (see *Placeholders you write yourself* under `vocabulary`). Never write a bare
   `is_risk_accepted IS NOT TRUE`: it decides the tenant's policy for them.
4. **The condition the question names**, only when it names one: "waiting for *triage*" is the
   triage flag `IS NOT TRUE`, added to the four lines, never in place of one.

⛔ Add no other decision flag (`is_suppressed`, `is_triaged`, `is_verified`, `is_confirmed`)
unless the question names it. Suppression is a display decision: a suppressed finding is still
present. The set is fixed so that one question always returns the same SQL; a flag chosen per
run breaks that. Say in the grounding note which open states the filter kept. No such meaning
in the question → no state filter.

⛔ **A question about history, exceptions or everything ever seen does not take this
population.** What was fixed, time to remediate, backlog over time, what was dismissed or
accepted, what came back: these need the closed rows, and each names its own filter. Two rules
for them:

- **Fixed is a status, not a date.** A finding is remediated when its status is in the tenant's
  remediated set (a vocabulary key on the status column; `--bind` templates the `IN` list).
  The resolution date is filled by any closure, a dismissal included, so the date says when and
  never whether.
- **Read each date's meaning before using it as evidence.** A column whose name says "last
  detected" or "last seen" can record when the source last changed its record, not when
  anything last looked: never infer "stale", "not seen since" or "the scanner stopped reporting
  it" from a date without reading its annotation. A finding the source stopped reporting is
  recorded as a retirement (soft-deleted, with a closure reason), and a finding that came back
  carries its reopen on its own row. The annotations name those columns; use them instead of
  comparing dates or matching one row to another.

⚠️ Measured on an agent run that carries the same rule: one run of *"how many
vulnerabilities are still waiting for triage?"* in four filtered on the triage flag alone and
counted fixed and suppressed findings as waiting.

### "Is it running?" has three answers

Whether a finding's place is running is a fact read from the inventory, and for a container
image it is not "the image has an asset row":

- **An image** runs when a live workload carries it, and does not when none does:
  `EXISTS (SELECT 1 FROM assets w WHERE w.container_image_id = v.torana_artifact_id AND
  w.is_deleted IS NOT TRUE)`. For an image, no workload is the answer: FALSE.
- **A host or cloud resource** with a live asset row is running: TRUE.
- **A service** runs when something runs behind it: a current link to a running image or workload. A service
  record on its own, or an exposure route to it, does not make it running: a service can be exposed with nothing
  deployed to it. When the question says running, count only the services that pass this test, and list the
  exposed-but-not-running ones apart with their own count.
- **A workload** (a deployment, job or pod in an inventory) runs when a running image or pod is recorded behind
  it. An inventory row with no running image or pod is recorded, not running. When the question says running,
  count only the workloads that pass this test and list the recorded-only ones apart with their own count; the
  two counts add up to the inventory total.
- **A repository, or an entity with no asset row,** was not observed: NULL, never FALSE.

An image can run as several workloads: count them or return them all, never pick one. When the
answer counts running things, return the not-observed count beside it.

**"On which asset?" uses the same bridge.** When the question puts a condition on the asset a
finding is on ("on Windows servers", "on production hosts"), an image finding's assets are every
live workload running the image, plus the finding's own asset row where it has one:

```sql
LEFT JOIN assets t
       ON t.is_deleted IS NOT TRUE
      AND (t.torana_entity_id = v.torana_entity_id
           OR t.container_image_id = v.torana_artifact_id)
```

The grain becomes one row per (finding, asset): say so in the MEASURE line and count findings
with `count(DISTINCT …)`. Keep the LEFT JOIN: a finding with no asset (a repository, an image
nothing runs) is a row with no asset, which an asset condition cannot match; return how many
there are. ⛔ An inner join on `torana_entity_id` alone tests the condition on the image's own
inventory row and silently drops the rest. An asset property the finding also records takes
both sources: the operating system is `COALESCE(t.compute_operating_system, v.os_release)`.
Governance (team, criticality, exposure) still comes from the governance table, keyed on
`COALESCE(t.torana_entity_id, v.torana_entity_id, v.torana_repository_id)`. ⚠️ A trust tag is
measured over the whole table, not over the rows your `WHERE` kept: never quote it as the share
your query dropped.

**Cap unbounded result sets with `LIMIT 100`, unless the SQL will be saved or shipped** (a saved
definition carries no cap: whoever runs it decides how many rows to take, see `## When the SQL will
be saved or shipped`). An explicit N in the question ("top 200") wins. Aggregates need no cap — they already return
few rows — but a bare `SELECT` over a sink table can return millions. ⚠️ A `GROUP BY` that
returns one row per entity (per package, per asset) is a list, not an aggregate: cap it.

**A `LIMIT` needs an `ORDER BY` that puts the asked-for rows first.** The cap decides which rows
the caller sees, so the sort is part of the answer. Take the direction from the column's own
definition, not from its name: a rank-sounding column can be a score where higher means more
urgent, so `ASC` would return the bottom of the queue under a heading promising the worst.
⛔ Never sort by a date because nothing better came to mind: a question about exploitation puts
exploited rows first, a question about urgency the most urgent. If no column expresses the
asked-for order, the list has no "first 100": return counts per class instead. Measured: an "is
it being exploited" list sorted by detection date and capped at 100 put the first
known-exploited CVE at row 774.

**Add a deterministic tie-break** — a final `ORDER BY` key that is unique, such as the finding or
entity id. Without one, the same question re-run returns a different 100 rows, and two columns
holding the same number are not a tie-break at all. A question naming two classes gets a cap per
class (`row_number() OVER (PARTITION BY …)`), never one shared cap that fills up with the larger
class.

**Every capped statement returns its own total as a column**: `count(*) OVER () AS
<things>_total`, which counts the rows before the cap (after a `GROUP BY`, the groups), and
`PARTITION BY` the class when the cap is per class. You do not run the SQL, so you cannot state
the total in prose; the column is what says "the 100 worst of 4,812". A bare 100 rows reads as
the whole population. **When the filter keeps every row** (the classifier-column check showed
the column it tests is unfilled), a capped list answers nothing: return the count per state.

**Build a label with `concat_ws`, not `||`, when any part can be NULL.** `a || ' / ' || b` is NULL
whenever one side is NULL, so a row with a missing package name loses its whole label and reads as
an empty row rather than a partly-known one. `concat_ws(' / ', a, b)` skips the NULL parts and
keeps the row legible.

## The three answers

Whichever of the three you give, **end it with a short note saying what the SQL was grounded
against, what was checked, and what the vocabulary check did.** Copy the names from the tool
output rather than recalling them — `schema-ddl`'s header prints `included:` and
`not included:`, `sql-reachability` prints its verdict, how many columns it checked, and a
`NOT MEASURED` list, and `policy-template` prints its counts and how many keys it could have
matched.

```
Grounded: meaning, domains, reach, trust, measures (default) · not fetched: writers, graph, rows, shape, fill, values
Checked:  sql-reachability ✅ ok, 7 columns · not measured: shape, fanout
Vocabulary: ✅ clean — no tenant setting found, 12 keys checked
```

When the caller named layers, say which came from them — so a reader can tell the skill's own
default from what was asked for:

```
Grounded: meaning, domains, reach, trust, measures (default) + values, shape (you asked) · not fetched: writers, graph, rows, fill
Checked:  sql-reachability ✅ ok, 7 columns · not measured: fanout
Vocabulary: templated 2 (severity_floor, epss_escalate_threshold; tier 3) · 12 keys checked
```


All three lines matter, and none can be reconstructed from the SQL. A reader looking at SQL
cannot tell a column whose meaning was read from one taken on the name alone, or a join whose
trust was measured from one assumed to connect, or a literal that is this tenant's policy from
one that is a fact about the world — every pair produces identical-looking SQL. Naming what
you did not fetch is what stops the absent check reading as a clean one, and marking what was
requested is what stops a caller assuming their instruction was honoured.

Give the counts on the `Vocabulary:` line too, for the same reason: `✅ clean` alone cannot be
told from a check that never ran, so say how many keys could have matched. When the caller
turned it off, say what was found and left alone — never leave the line out:

```
Vocabulary: not run (you asked)
```

With vocabulary on, the line lists what code templated and what it left, with the reason
`policy-template --bind` printed:

```
Vocabulary: templated 1 (severity_floor, tier 3) · left 1 (NAMED_IN_QUESTION: vulnerability_status 'Open') · 12 keys checked
```

⚠️ **Give the column count, not just the verdict.** `sql-reachability` reports `✅ ok` after
checking zero columns when the SQL reads a transformer table, because its writer map covers
sink tables only. The verdict alone would read as validation of a query it never looked at.

**SQL** — the data supports the question.

**SQL plus what it does not answer** — a column you wanted is unusable, and you dropped it
from the projection. Say which column and what the answer is therefore missing.

⭐ **This is the right answer for a compound question whose clauses do not all resolve.** A
question with several parts ("which are overdue, who owns them, and was anyone told") rarely has
a column for every part. Map each clause either to a column in the `SELECT` list or to a named
"cannot answer" sentence — the clause in the caller's own words, then what the datalake lacks for
it — and hand back the SQL for the clauses that do resolve. Refusing the whole question over one
missing clause throws away the answer the caller can act on. The third answer is for when **no**
clause resolves, not one in three.

⛔ **The caveats must not claim more than the SQL does.** Read them against the SQL clause by
clause before handing over, and delete anything the SQL does not support: a filter that is not in
the `WHERE`, a column that is not in the `SELECT`, a population described as narrower or wider
than the one queried, a caveat about rows the SQL already excluded. The caller checks the caveats
rather than re-reading the SQL, so a caveat that disagrees with its own query makes a wrong answer
look verified. A fact about the table that the SQL already handles is not a caveat — saying it
implies the opposite was done.

**No SQL, plus what is missing** — the question turns on a fact the datalake does not hold.
That is a useful result: it tells whoever asked that the data would have to be collected before
this question can be answered at all. Never substitute a neighbouring column to produce
something, because a populated field answering a different question is worse than an
acknowledged gap — nobody checks a number that looks fine.

Which of the three applies is decided by **where** the unusable column sits, and it is
mechanical rather than a judgement call. In the SELECT list, dropping it narrows the answer. In
WHERE / JOIN / GROUP BY / HAVING, dropping it returns a different set of rows, silently.

### When there is no table at all

When the question is about a **subject the datalake does not cover**, there is no column to
name and inventing one is a false statement. *"How many employees are in the organization"* is
the shape of it: no employee table, no headcount column, nothing to point at. The answer is
that the datalake holds security telemetry from connected tools and no HR system feeds it.

The check is the table list, not a layer — a subject with no table has nothing to request
layers about:

```
torana datalake schema-ddl --index
```

⚠️ **A plausible table is usually sitting right next to the subject.** `identities` carries
`first_name`, `last_name`, `email`, `department` and `title`, so `count(*)` over it returns a
confident number. Its writers are the GitHub, Slack, Jira and GCP IAM mappings — it is a roster
of **accounts across connected tools**, not of people. That count double-counts anyone with
four accounts, includes service accounts (`is_service_account` and `is_machine_identity` are
columns on it), and omits every employee who uses none of those tools. It answers a different
question and looks like an answer to this one. Check a table's writers before treating it as
the subject it resembles — `schema-ddl --tables <t> --with writers` shows which pipeline writes each column.

⚠️ Before giving the third answer, check that you actually asked. **An absent annotation means
you did not request that layer. It never means there is no data.** The two look identical on
the page, which is why the output header lists what was included *and* what was not. Calling a
column unusable when you never requested `reach` is the confident-wrong failure this skill
exists to prevent, committed by the skill itself.

There is a fourth thing you can do with an unusable column, and it is the one to avoid: paper
over it with a default. Read plainly, the column yields NULL, and a NULL is visible — a reader
sees the hole. Wrapped in `COALESCE(col, 0)` or a `CASE … ELSE`, the same absence becomes a
confident `0` on every row, and "never measured" is rendered as "measured zero". Those are
opposite claims, and the second cannot be spotted in the output by anyone. Let the NULL show,
or drop the column and say what the answer therefore excludes.

⭐ The same argument applies inside a predicate, where it is harder to see: see **the
nullable-boolean rule** above. `COALESCE` fakes an absent value in the OUTPUT; `col = false`
fakes one in the WHERE clause and then drops the row, so not even the faked value appears.

## After `sql-reachability`

One call does the check: `torana datalake sql-reachability-and-policy --sql "…"` returns the
`sql-reachability` verdict (copied, not re-derived) with the `policy-template` findings beside it.
Everywhere this skill says to run `sql-reachability` or read its verdict, that is this call, and the
`Checked:` line names it. `--no-policy` skips the vocabulary half (*"no vocabulary"*). Templating is
still its own step: `policy-template --bind`, below.

⛔ **Check the finished statement, once.** The check never returns rows or values, so it is not a way to peek
at data: do not send it `SELECT *`, a one-row peek or a bare count to see what is there. To see data, run a
query. A clean verdict means return the SQL now. Ask `schema-ddl` for the tables and columns you need in one call
(the platform's own Text-to-SQL agent is capped at 4 DDL fetches and 4 checks a turn; take that as the budget).

Run `sql-reachability` on the SQL before anyone runs the SQL itself. Each finding it prints
carries its own explanation, so relay those to whoever asked rather than restating them in your
own words, and fix the SQL for anything it flags.

**Never hand over SQL that cannot execute.** Every table and column name must come from the
DDL you fetched, never from memory or from what a name ought to be. `❌ BLOCKED` and
`⚠️ PARSE FAILED` both mean the query would fail against the database — fix the SQL and run
the check again rather than passing it on with a caveat. There is no version of the three
answers that ends in SQL the platform will refuse: if the name you wanted does not exist, that
is the third answer, not a query to hand over. The same holds for the text you print: every SQL
block is complete and is the exact text that was checked. No ellipsis, no "same as above", no
CTE left out because an earlier block had it.

Read the findings below the verdict line, not only the verdict. Each one says what it found and
what to do about it.

Most of what it reports is a property of the SQL and holds anywhere. Two optional checks are
not, and both are off unless you ask:

- `--shape` warns when a column you filter on holds only one value, or none, on this tenant —
  a predicate that cannot discriminate.
- `--fanout` runs the query and compares its row count to the table it iterates, catching a
  join that multiplies rows.

Those two measure one tenant at one moment. Their findings are worth acting on here and are not
worth repeating anywhere else.

It also lists the checks that did *not* run. An empty finding list for a check that did not run
means nothing looked, not that nothing is wrong.

**An empty result is a fact about this tenant, not a reason to change the question.** When a
column fills only after someone runs a workflow, zero rows means nobody has run it, which is
the opposite of "there are none". `sql-reachability` says which case applies; report that
rather than quietly rewriting the query until it returns something.

## `vocabulary` — this tenant's settings become `{{vocab:…}}`, templated by code

Once the SQL is valid, run the report:

```
torana datalake policy-template --sql "<the SQL>"
```

It answers a question validity does not: **is a literal in this query one tenant's setting
rather than a fact about the world?** `severity IN ('Critical','High','Medium')` is not a fact
about vulnerabilities — it is that tenant's severity floor. The platform stores such settings
as a **vocabulary**: named keys, each holding one tenant's value, written `{{vocab:…}}`.

⭐ **You cannot see this tenant's settings; the report can.** Each finding carries `sql_encodes`
(what your literals encode), `tenant_value` (what this tenant actually resolves the key to) and
`mismatch`. `mismatch: true` means **your literal is not this tenant's value**. ⛔ Never describe a
literal as the tenant's setting; only `tenant_value` is.

**Vocabulary is on by default, and then the SQL you hand back is TEMPLATED — by code.** Decide
which findings are this tenant's policy **and were not named by the question** (a `mismatch` on
such a literal is the cue), then run the platform's binder:

```
torana datalake policy-template --bind \
    --question "<the caller's question, verbatim — without the delivery instruction>" \
    --policy-keys <every finding's key whose literal you did NOT take from the question> \
    --file <the SQL>
```

`--question` is the user's question **word for word, minus the delivery instruction** (drop
*"write SQL I'll save as a transformer:"*, keep *"count open vulnerabilities at or above our
severity floor"*) — never a paraphrase: the guard matches the values the user actually typed.

⛔ **Never pass `--bind-keys`.** It is the tier for a key a human approved for this SQL, and it
binds even a value the question names. When `--bind` leaves a literal as `NAMED_IN_QUESTION`
that you believe the question did not name, keep the literal, copy the line into `Vocabulary:`
and say why you think the guard misread it. Never override it.

Hand back **the SQL it prints** (`SQL (templated):` or `SQL (unchanged):`) — for a question asked
once and for SQL that will be saved alike — and copy its `Templated` / `Left literal` lines into
the `Vocabulary:` line. Code decides the rest, the same way every time: a value the question
**names** is never templated, even if you list its key; an ambiguous or oddly-shaped literal is
left with a named reason (`AMBIGUOUS_KEYS`, `OPERATOR_SHAPE`, …).

⭐ **Templated SQL runs through the platform.** `torana datalake query` and `query-execute` fill in
this tenant's value for every `{{vocab:…}}` before executing, and report `bound_vocabulary`: the
key, the value, and whether it was the tenant's own decision or a platform default. Say that once
when you hand the SQL over. For a tool **outside** Torana (a psql shell, another database client),
the caller asks for *"no vocabulary"* and gets literal SQL.

| verdict | what it means | what to do |
|---|---|---|
| ⚠️ `REVIEW` | a vocabulary key is declared on that column, and the literal matches it | if the question did not name the value, pass the key to `--bind` (`mismatch: true` says the literal is not this tenant's value); if it did, leave it — it is the question |
| ◻ `WAIVED` | the SQL carries `-- policy-literal-ok: <reason>` | leave it — already justified |

⛔ **A business term with no column is matched against the key list before any literal is chosen.**
"Crown jewel", "high-value", "stalled": none is a column, and each can be a setting this tenant
owns. **First look for a column:** when the table you read already carries a flag or class for the
term (a transformer computed it from these keys), use that column, as *Which to use* says,
provided the table holds the rows the question needs: a flag on a table of open findings cannot
answer what was met, fixed or missed in the past, which takes the closed rows from the sink. The
key list is for a term nothing in the table expresses. Then run `torana --json vm policy
vocabulary` and read the `meaning` of every key in the category the term belongs to (the table and
`--keys` forms print no meanings). When a key covers the term, write the predicate on the column
the key's `columns` names, in the shape `--bind` templates, and list the key in `--policy-keys`; a
key with no `columns` is written by hand in one of the shapes below. Only when no key covers the
term is the reading yours, and the caveat then names the keys you read and set aside. ⛔ Never
write "no vocabulary key defines X" unless the meanings were read in this session. Measured: a
session shown `criticality_escalation_floor` wrote `criticality_level = 4` for "crown jewel" and
told the caller no key defined it.

⛔ **A key the answer names as "not applied" is a defect, not a caveat.** If a setting covers the
rows the question is about, apply it. If you cannot tell which of two settings governs, return
both results as columns and say which one the state column uses.

⛔ **Before templating a list key, read its value; a list this tenant has left empty is not
templated.** The vocabulary listing shows it as `[]`, and the `policy-template` report (without
`--bind`) as `tenant <key> = []`. The platform refuses to bind an empty list and the whole
statement fails at execution, though `--bind` and `sql-reachability` both pass it. An unset
scope or exclusion list is no restriction: leave that predicate out, do not list the key in
`--policy-keys`, and say in the answer which key is unset and that the SQL covers every row
(for saved SQL: the predicate comes back once the key has a value). This is not the empty limb
of *Writing the SQL*: there the data is empty and the limb stays; here a policy list is unset
and cannot be bound. Never hand back SQL you have reason to believe will be refused.

⛔ **Never substitute a placeholder for a literal yourself (the shapes under *Placeholders
you write yourself* below are the only ones written by hand), and never describe the SQL you hand
back as templated when it is not.** Without `--bind` the verb reports and does not rewrite; with
`--bind`, `policy-template` does it deterministically. You hand back the SQL the verb printed —
never one you edited by hand, and never the literal SQL with keys "on the side".

### Placeholders you write yourself

One class of setting has no literal for the binder to find, so "never by hand" cannot apply to
it. Write these placeholders directly, in exactly these shapes, and nowhere else:

- **A policy switch**: the risk-accepted gate of the open population,
  `(NOT {{vocab:vm.prioritization.scope_gates.exclude_risk_accepted}} OR v.is_risk_accepted IS NOT TRUE)`.
- **A number of days or hours the tenant sets** and the question refers to without stating
  ("about to breach", "overdue for review", "stalled"): the bare placeholder inside interval
  arithmetic, `({{vocab:<key>}})::int * INTERVAL '1 day'`. ⛔ Do not write `INTERVAL '7 days'` and
  describe it as an assumption: `torana vm policy vocabulary --keys` lists every key, and a
  lead time, review period or expiry limit that has a key is this tenant's setting. Only when no
  key covers it is the number yours to choose; then say so in the caveats.
- **A deadline** is computed, never read from a stored due date: first detection plus the
  tenant's window for the finding's severity (the lookup form of the SLA-window key, which
  `--bind` produces from a severity-to-days `CASE`). A severity with no window has no deadline:
  report those rows as their own class, never as on time and never as late.
  **A question about known-exploited (KEV) findings takes the tenant's KEV window instead:**
  first detection plus `({{vocab:vm.remediation.sla_windows.kev_remediation_window_hours}})::int
  * INTERVAL '1 hour'`. Measured: a KEV question answered with the severity window reported 42
  of 58 findings within SLA; under the tenant's KEV window all 58 were overdue.
  ⛔ **A question about all findings does not switch its KEV rows to that window.** Which window
  governs a KEV row there is not settled, so it is the two-settings case above: the state
  (overdue, about to breach) is computed on the severity window for every row, and KEV-listed
  rows carry their KEV-window deadline as a second column with a flag saying it is earlier.
  Return the count of rows overdue only under the KEV window as its own column, and say in one
  sentence that KEV findings may have a shorter deadline under the tenant's KEV setting.
- **Any other per-severity number the tenant sets** (a key whose shape is `key-map`, such as the
  days without an update before work counts as stalled): the lookup form,
  `({{vocab:<key>.lookup[v.severity]}})::int * INTERVAL '1 day'`. `--bind` builds this form only
  for the SLA window; for any other key-map it reports "Declared but no literal found" and
  leaves a `CASE` in place. ⛔ Never hand back a severity `CASE` whose numbers were copied from
  the vocabulary list: they are this tenant's values today.
- **A criticality floor** ("crown jewel", "business-critical"): the name column, case-folded,
  against the floor key, `INITCAP(COALESCE(g.criticality_name, a.criticality_name)) IN
  ({{vocab:vm.escalation.asset_criticality.criticality_escalation_floor.at_or_above}})`. The
  column holds both `critical` and `Critical`, the key renders `'Critical', 'High'`, and
  `--bind` does not see through `INITCAP`; without the fold the filter matches nothing. A
  literal on `criticality_level` is invisible to the binder: never use it for a floor.

Then run `policy-template` (with or without `--bind`) on the SQL: for a placeholder in interval
arithmetic it prints `✅ Hand-written, validated` or `⛔ Hand-written, INVALID` with a named
reason; for a switch, a lookup or a floor, `--bind` prints `◻ Already a placeholder: <key>`.
An invalid one is fixed before the SQL is handed over. Copy those lines into the
`Vocabulary:` line beside what the binder templated. A value the question itself states ("in
the next 30 days") stays a literal: it is the question.

**Why**, because this is the decision the whole check turns on: *"how many critical vulns"*
and *"how many vulns above our floor"* produce **byte-identical SQL** with opposite correct
treatments. The literals alone can never say which was meant — and **you were told which**.
If the question named the values, they are the question, not policy. If the question asked
for "our floor" or "what we treat as actionable", pass the key to `--bind`. Never by hand.

⚠️ **This was learned the hard way.** An earlier version substituted automatically when the
match was exact. A caller asked for "critical and high", the SQL said
`severity IN ('Critical','High')` — which identifies `severity_floor = High` uniquely — so it
was replaced. At execution that tenant's floor resolved to `Medium`, the filter widened to
include Medium, and the query answered a different question. **The identification was right
and the outcome was still wrong.** The question guard in `--bind` is what prevents it now.

⚠️ **A bound value may differ from the literal it replaced** — that is the point of binding,
and also its risk. `severity_floor` resolving to `Medium` turns `('Critical','High')` into
`('Critical','High','Medium')`.

⛔ **Anything the platform cannot resolve refuses by name, and nothing runs.** An unknown key,
or one this tenant has no value for, returns an error naming the placeholder rather than
falling back to a default — a default is a value nobody chose.

**Report a clean result too, with the number of keys that could have matched** — the verb
prints it. "No policy literal found" alone cannot be told from a check that never looked.

### When the caller says `no vocabulary`

Skip the check and `--bind` both, hand back the literal SQL exactly as written, and say so on
the `Vocabulary:` line — an unrun check must never read as a clean one. This is the mode for
running the SQL outside Torana.

## When the SQL will be saved or shipped

SQL that gets saved — as a transformer, a widget, a detection rule — runs for
every tenant, not only this one. So a literal that encodes what *this* tenant decided has to be
replaced by a reference that each tenant resolves for itself.

Which literals those are is not obvious, because they look like ordinary values. `severity =
'Critical'` names a remediation window that differs per customer; a 30-day SLA is one tenant's
policy. `scan_type = 'SCA'` is not — it describes the world, and it means the same everywhere.

The `vocabulary` input (above) already handles this: with vocabulary on, the SQL you hand over
is the one `policy-template --bind` printed. That substitution — done by code, only
where the question did not name the value — is the difference between an artifact that travels
and one that silently answers a different question at the next customer.

⛔ **If the SQL is going to be saved and it was NOT templated (the caller said `no vocabulary`, or `--bind` left a policy literal in place), say so plainly.**
That is the one case where the literals left in place matter more than the answer itself: the
artifact will carry this tenant's settings to every other tenant.

`sql-reachability` reports an overlapping set in its own `hardcoded_policy` field, found a
different way — by word list rather than by vocabulary key. It catches policy-shaped literals
on columns no key maps to, so read both. Neither includes the other.

A hardcoded policy value does not make the query wrong here, only wrong elsewhere, which is
why neither check changes the verdict. To see every key and its current value for this tenant:

```
torana vm policy vocabulary
```

**Saved SQL carries no `LIMIT` and ends in a strict order.** A saved definition is run by many
callers who each want a different number of rows, so the cap belongs to the caller. Leave it
out unless the number is the question ("top 10"), and end with an `ORDER BY` that puts the rows
the question cares about first and finishes on a unique key. For the same reason expose an age
as a column rather than cutting on a reporting window the question did not fix.

**Name any transformer the SQL reads that nothing currently maintains.** Reading a stale
transformer once is fine — someone may rematerialise it, and the same SQL then returns current
rows. Depending on one permanently is different: the saved artifact keeps returning whatever
that table last held, for as long as no job runs, and nothing in the artifact says so. The
index flags which tables those are; say which ones the SQL depends on, so whoever owns it can
decide whether to schedule the job or read the sinks directly.

## Important rules

### Do not build a transformer on top of another transformer

Build on sink tables.

Each transformer table is refreshed by a scheduled job. Chain two and the jobs must run in
dependency order — machinery that does not exist yet, so a chain has no defined behaviour when
a job in the middle fails.

A chain also hides its own mistakes. A wrong grain or threshold in a base table is silently
wrong in everything built on it, and nothing exposes the lineage: neither the table index nor
nor the DDL says what a transformer reads from, so a chained table cannot be told from one
built directly on sinks by looking at it.

