---
name: torana-data-analyst
description: >-
  Answer questions about a tenant's security data WITH THE DATA — not just the SQL. ⛔ It never
  writes SQL itself: EVERY query is produced by the `torana-text-to-sql` skill (grounded,
  reachability-checked, tenant-neutral), which this skill MUST invoke; it then RUNS that SQL (its
  `{{vocab:…}}` policy references are filled with this tenant's values by the platform) against the Torana datalake via the `torana` CLI, asks
  `torana-text-to-sql` for the follow-up queries the first result demands (breakdowns, join
  coverage, value checks), and presents the finding first, then the rows (table or chart), then
  the SQL. Every number comes from a query run in this session — never from memory. Trigger
  whenever the user wants to LOOK AT their data: "show me …", "how many …", "break down … by …",
  "top N …", "what does the data say about …", "list the critical vulns on …", "which
  repos/assets/packages have the most …", "trend of … over time", "explore the vulnerabilities
  table", "is there anything odd in …", or pastes SQL and asks what it returns. NOT for a specific item, entry, finding, CVE, CWE, verdict, fix, overdue state, owner or history, or for "what needs attention": those are answered by the Inbox views (`alerts list`, `alert <id> view`, `alerts cve`/`cwe`, `alerts boxes`) in `torana-skill`, read FIRST; this skill is for what those views cannot answer (ad-hoc aggregation across the estate). NOT for saving a query
  as a widget, rule or transformer, and NOT for building or changing programs (those are done in the
  Torana app).
  ⛔ Step 0 ALWAYS loads `torana-skill` (how the `torana` CLI is learned) and then
  `torana-text-to-sql` (the only SQL producer) — both before any `torana` command.
version: "1.3"
last_updated: "2026-09-18"
platform_version_tested: "2026.1"
---

# torana-data-analyst — answer with the data

> The user asked a question about **their** data. The deliverable is the **answer** — a
> number, a ranking, a pattern, a "yes, and here is why" — backed by rows you actually
> fetched. The SQL is a receipt, shown last.

It scopes, executes, reads and presents — and ⛔ **it does not author SQL**: that is
`torana-text-to-sql`'s job, and this skill must invoke it for every query (§ 1). Two things
are yours alone: ⛔ **presentation** — nothing renders tables or charts for you (§ 4,
`references/presentation.md`) — and ⛔ **the query budget** in § 3, which nothing enforces for you.

⛔ **You answer, with `torana-text-to-sql` and the CLI.** Never send the question to a Torana assistant or agent
to answer or to write the SQL, even when the customer asks for Ask AI by name. See `torana-skill`, "You answer;
you never drive Torana's agents".
## ⛔ The second rule: YOU NEVER WRITE OR EDIT SQL

Every query this skill runs — the main answer, every follow-up, every coverage or value check —
comes from `torana-text-to-sql`. Not "consult it", not "draft and let it check": **it produces
the SQL; you run and read it.**

Why this is a rule and not a preference: SQL written straight from a schema looks right and
routinely is not — a column nothing writes returns an empty or wrong answer; a join the model
marks orphaned drops every row; a transformer table that already answers the question gets
re-invented with a different grain. `torana-text-to-sql` owns the discipline that prevents
each of those (the reachable schema, the measured joins, the choice of a fitting transformer
over the raw sinks, the measure/grain choice, the value-domain check) and records what it
checked. An analyst that
writes its own SQL skips all of it and answers confidently anyway.

⛔ If a result shows the SQL is wrong, **do not patch it** — send the defect back to
`torana-text-to-sql` in words and run what it returns (§ 3).

---

## ⛔ The one rule that outranks everything: NEVER INVENT A NUMBER

**Every figure in your answer must come from the result of a query you ran in this session.**
Counts, totals, percentages, rankings, "most", "none" — all of them.

A table of plausible numbers is the worst thing this skill can produce: it is
indistinguishable from a real answer and people act on it. A missing answer is recoverable;
a fabricated one is not.

⚠️ **The multi-part trap.** Asked for two things ("find X *and* break it down by Y"), it is
easy to query the first, and narrate the second. **Every part needs its own query.** If you
did not run a query for a figure, you do not have it — run it or say "I haven't pulled that".

**Self-check before responding:** for each number, point at the result row it came from. If
you can't, delete it or go run the query.

---

## Prerequisites — do not duplicate them here

### ⛔ Step 0, ALWAYS: load BOTH skills — `torana-skill`, then `torana-text-to-sql` — BEFORE ANY `torana` COMMAND

⛔ **Both loads come first — before `auth status`, before `datalake summary`, before anything
touches the datalake.** Reading the datalake with only one of the two loaded is how a run goes
wrong. The order is fixed:

1. **`torana-skill`** — how the CLI is learned (below).
2. **`torana-text-to-sql`** — the only producer of SQL, and the owner of grounding: it reads the
   annotated schema (sinks AND transformer tables) before any SQL exists. ⛔ Nothing of the
   datalake is read by this skill until it is loaded.
3. **Then** scope (`summary`) and the question (§ 1).

**Invoke `torana-skill` (the `Skill` tool) before any `torana` command — every time, even when
`torana` is already on PATH and authenticated.** A working CLI is not the reason to load it:
`torana-skill` is the ONE place this chain learns how the CLI is used — its install/auth
bootstrap, how to sign in, and the verbs and their flags (`references/datalake.md` for
`summary`, `schema-ddl`, `query-execute`). This skill names a few commands; it
does not teach them, and a command used from memory is how a flag drifts or a wrong verb runs.

- Read `torana-skill`'s **`references/datalake.md`** before the first datalake command.
  `torana-text-to-sql` requires the same file before it writes SQL — pass on that it is loaded.
- ⛔ Where this file and `torana-skill` disagree about a command, **`torana-skill` wins**; say so.
- ⛔ Never skip it because "the CLI already works" — that is exactly when it gets skipped.

**Then invoke `torana-text-to-sql` (the `Skill` tool)** — still before any datalake command; pass
on that `torana-skill` is loaded. This skill cannot produce an answer without it (§ 1). If
either skill is missing, stop and say so; ⛔ do not fall back to writing SQL, or to guessing CLI
usage, yourself.

```bash
torana --version && torana auth status
```

Commands here use **bare `torana`** — each Bash call is a fresh shell, so a variable set in
an earlier call is gone, and an expansion can trip a permission prompt. If `torana` is not on
PATH (e.g. the Claude Desktop sandbox), run `torana-skill`'s bootstrap (already loaded in
step 0) and prefix each command with the path it prints.

⛔ **No shell variables in commands at all** — not `S=$(…); … "$S"`. Expansions need a
permission approval (and are denied outright headless). `auth status` already prints the
tenant you are signed in to; inline values instead of capturing them.

⚠️ **The signed-in tenant decides the data.** The same question returns different data on
every tenant. Always know which one you are answering for, and say it in the answer.

```bash
torana --json datalake summary        # row count + freshness per sink table
```

Run `summary` at the start. If the tables the question needs are empty,
say so **before** writing SQL — *"this tenant has no rows in `vulnerabilities`; nothing is
synced yet"* is the answer, not a query returning 0.

⚠️ **Data can move while you work** — a sync landing mid-analysis changes the totals between
two queries, and the parts of your answer stop adding up. So compute each share's
denominator **in the same query** (`SUM(COUNT(*)) OVER ()`), not in a separate count; and if
two of your queries disagree on a total, re-run `summary` — if `latest_update` moved, say the
data changed during the analysis and which figures come from which snapshot.

---

## The workflow

```
0. load       → torana-skill, THEN torana-text-to-sql (ALWAYS, both, before any torana
                 command); then scope: which tenant, which tables, is there data (summary)
1. get SQL    → INVOKE torana-text-to-sql with the question; take its outcome (✅ / 🟡 / ❌)
2. run        → execute it as handed over (the platform fills `{{vocab:…}}` with this tenant's value)
3. look       → READ the result; every follow-up query ALSO comes from torana-text-to-sql
4. present    → finding first, then the data, then the SQL + text-to-sql's grounding note
```

### 1. Get the SQL — invoke `torana-text-to-sql`, every time

**How:** invoke the skill (the `Skill` tool, skill `torana-text-to-sql`). Pass it:

- the **question VERBATIM** (its intent lookup is on the user's words, not a tidied version),
  or, for a follow-up, the precise follow-up question (*"of the rows above, how many have a
  NULL `torana_artifact_id`?"*);
- that the run is **non-interactive** (its default — it must never stop to ask);
- the **tenant** you are answering for — it needs one for its gate, and you run against the same one in § 2;

If the `Skill` tool is not available in this harness, load `torana-text-to-sql`'s `SKILL.md`
and follow its pipeline in full. ⛔ Either way, the SQL you run is the SQL it emits.

**What comes back is one of three outcomes — act on it, don't second-guess it:**

| Outcome | You |
|---|---|
| ✅ **SQL** | go to § 2 |
| 🟡 **SQL + gap** | go to § 2, and carry its gap sentence into the answer verbatim — it names what the rows do NOT answer |
| ❌ **No SQL + missing column** | ⛔ run nothing. **That is the answer**: name the column and that nothing writes it (*Data gaps*) |

Keep what it hands back beside the SQL — the outcome, the gap sentence, the `Vocabulary:`
line and the grounding note (§ 2) — for your *details* (§ 4). They are how a reader audits what
the SQL was checked against, and whether it read a transformer table or the raw sinks.

### 2. Run it as it stands

`torana-text-to-sql` hands over SQL whose policy literals (a severity floor, a status set) were
already templated **by code** into `{{vocab:…}}` references — except values the question itself
named, which stay literal. Run it exactly as handed over: `query-execute` fills each reference with
**this tenant's** value before executing and reports it in `bound_vocabulary`. Its `Vocabulary:`
line says what was templated and what was left literal, with the reason. **You never template,
edit or un-template anything.**

⛔ **Read the grounding note the skill ends with** — one line naming what the SQL was grounded
against and what was not:

```
Grounded: meaning domains reach trust measures values(severity) · not fetched: writers graph rows shape fill
Checked:  sql-reachability ✅ OK, 3 columns · not measured: shape fanout empty_means
```

| The note says | What it means for the number you are about to report |
|---|---|
| a layer under `not fetched` | it was never requested — absent is NOT evidence of "no data" |
| `values(...)` naming a column | that column's literals were checked against THIS tenant's rows, not just the declared domain |
| no `values(...)` | a literal in the SQL may be spelled correctly and held by no row here — the query returns zero and reads like an answer |
| `Checked: … 0 columns` | ⛔ `sql-reachability` covers sink tables only. On a transformer table it reports ✅ having checked nothing |
| a layer under `not measured` | that check did not run. An empty finding list means nothing looked |

⭐ Carry the relevant half into your own caveats. A reader of your answer cannot see the note.

```bash
torana --json datalake query-execute --sql-query "<the SQL, exactly as handed over>" --limit <n>
```

Returns `data`, `columns`, `row_count`, `total_rows`, `limited` — and, when the SQL carried
`{{vocab:…}}`, `bound_vocabulary` (each key's value and whether it is the tenant's own or a
platform default). (`datalake query` fills the references the same way but has no row limit.) The server rejects anything
that is not `SELECT`/`WITH`. The JSON is verbose; extract what you need:

```bash
torana --json datalake query-execute --sql-query "<the SQL>" --limit <n> \
  | jq -c '{limited, total_rows}, .data[]'
```

⛔ **Never template, edit or strip a `{{vocab:…}}` reference, and never fill one in by hand.** The
platform fills it at run time with this tenant's value; a hand-filled value is a guess. If a
reference fails to resolve, the run refuses by name — report that rather than editing the SQL.

⛔ **If the engine rejects the SQL** (syntax, a missing column, a type): go back to `torana-text-to-sql`
once, with the question, the failed SQL and the exact error, and run what it returns. **A second failure:
stop.** Report the failing SQL and the error; do not try a third time.

⛔ **`relation "X" does not exist` — STOP.** The SQL named a table this tenant does not have. Do not
retry and do not rename it: say that the data it needs has not been built or synced.

### 3. Look at what came back — follow-ups come from `torana-text-to-sql` too

**Reading the result is the job, not a formality.** Before presenting, decide what the result
demands — then **ask `torana-text-to-sql` for that query** (§ 1), and run it (§ 2):

| You see | Ask `torana-text-to-sql` for |
|---|---|
| a join-based breakdown | the coverage: how many rows joined vs not — say it in the answer |
| a big `Unknown` / `NULL` bucket | what it is — a missing enrichment, or a real category? |
| one bucket holding almost everything | ⛔ likely a defect in the SQL (`CASE` order, join direction): **describe the defect to it** and run its revision |
| a surprising spike or outlier | the one drill-down that explains it (by source, by date, by entity) |
| **0 rows** | whether the filter values exist; if the SQL is right, report it — 0 rows is a fact about this tenant; name the source or sync that would fill the table |
| `limited: true` | an aggregate instead of the slice — or say it is truncated |

⛔ **Rows coming back is not validation.** A join the wrong way returns plenty of rows and
answers a different question. [`references/sql-rules.md`](references/sql-rules.md) is the
checklist for READING the SQL you were given (dialect, grain, joins, math) — use it to spot a
defect and describe it back, never to rewrite the query yourself.

**Budget:** aim for ≤ 8 executed queries **per part of the question** — value checks,
drill-downs and gap diagnosis all count (each is a `torana-text-to-sql` round-trip plus a run);
`summary` doesn't. At the limit and still hunting: stop, report what you have and name the next
query you would ask for.

**Top N with ties:** if rank N ties with rank N+1, show every tied row and say so — don't
pick one silently.

⛔ **A capped list carries its own total.** The SQL `torana-text-to-sql` hands over returns a total column
(`count(*) OVER () AS <things>_total`, the rows before the cap). Quote that column for "how many exist": "the top N of M". If the statement has no such column, ask `torana-text-to-sql` for the same statement with one; never
edit the SQL yourself, and never give the number of rows you received as the total. Until you have the total,
say "at least N".

**A fact the platform records in more than one form** (membership of a catalogue, recorded evidence, a prediction
score) is reported in each form it was asked about, and each statement says which form it rests on. A
prediction is never evidence, "likely" is not "known", and an empty field usually means nobody checked: say
"nothing recorded", not "no". See `torana-text-to-sql`, "Facts recorded in more than one form".

### 4. Present — finding first

Full rules: [`references/presentation.md`](references/presentation.md).

```
<the answer in one or two sentences — the number, the ranking, the yes/no + why>

<the data: markdown table, or a chart for trends/distributions>

<caveats: measure used, join coverage, truncation, assumptions — one line each>

<follow-ups worth asking, if the data raised any>

<details: per query — the SQL as run, a one-line "why", which tables it read
 (a transformer table or the raw sinks), and text-to-sql's grounding note>
```

- ⛔ No reasoning narration ("let's break this down", "first I queried…"). The reader gets a
  finished analyst answer.
- **Name the tenant** when more than one is configured or it isn't obvious.
- **State the measure** ("counting findings, not distinct CVEs").
- **Say how far the answer reaches** (rule: `torana-skill`, "Every answer says how far it reaches"): what the data
  does not cover, how fresh it is from the platform's own freshness field, and which figures were derived. On an
  estate with more than one provider or code host, group the inventory by provider first, cover every one the
  question spans, and say which you looked at.
- **Show every query** whose numbers appear in the answer, last — with its grounding note.
- **Say which policy values the numbers used** — from `bound_vocabulary` (e.g. the floor filled with this tenant's value, and whether that is its own choice or a platform default) and any literal `torana-text-to-sql`'s `Vocabulary:` line says was left in place, with its reason — so the reader knows what "our floor" meant here.

---

## When to ask vs assume — at most ONE question

Answer directly by default. Ask one question, with 2–3 concrete options, **only** when a term
has readings that give materially different answers:

- **"recent"** → last 7 days, 30 days, or this quarter?
- **"critical assets" / "important"** → by finding severity, by asset criticality, or by exposure?
- **"our" / "my team's"** → by owner, environment, or repository group?
- **"at risk" / "compliant"** → against which threshold? You carry no built-in cutoff.

Otherwise assume the common reading, answer, and add a one-line scope note naming the
alternative. Never ask twice.

---

## Data gaps — say exactly what is missing

If the data can't answer the question, name the gap precisely instead of approximating:

| Gap | Say |
|---|---|
| column does not exist | *"`assets` has no `owner` column; the closest are `…`"* |
| column exists, nothing writes it | *"`<t>.<c>` is declared but no integration writes it"* |
| tables not joinable | *"`identities` has no join to `vulnerabilities` in the model — they can't be combined"* |
| table empty on this tenant | *"this tenant has no rows in `<t>` — the source isn't connected or synced"* |
| derived table not built | *"there's no MTTR table here; I computed it from `vulnerabilities` instead"* — or say it can't be |

⛔ Never fabricate a column, table or join key to make a plausible-looking answer.

---

## Beyond the answer

For anything beyond answering a data question — keeping a query as a widget or rule, building or changing a program — say what the user would do in the Torana app. Offer it in one line at the end; don't start it unasked.

---

## Anti-patterns

| ⛔ Don't | Because |
|---|---|
| touch the datalake (even `summary`) before BOTH `torana-skill` and `torana-text-to-sql` are loaded | the datalake is read through the discipline of both skills or not at all (step 0) |
| run any `torana` command without loading `torana-skill` first — even when the CLI "already works" | `torana-skill` is how the CLI is learned; commands from memory drift (step 0) |
| write, draft or "fix up" SQL yourself — even a one-line value check | it skips reuse, reachability and grain; every query comes from `torana-text-to-sql` (§ 1) |
| report a number without reading the grounding note, or edit the SQL to "fix" a literal | the note says what was and was NOT checked; a literal the skill grounded in this tenant's observed values is not yours to change (§ 2) |
| stop after getting the SQL to ask "shall I run it?" | the user asked for data; run it (read-only, server-enforced) |
| answer from what a security dataset "usually" looks like | every number must come from a query in this session |
| retry a missing table under neighbouring names | one missing table becomes a dozen failed calls |
| count through `entity_edges` without checking fan-out | one package sits in many images; the count becomes the fan-out |
| treat `workspace_id`, `program_id` as columns | they are routing context, not datalake columns |
| paste 500 rows into the chat | aggregate in SQL; show the top slice and say it's a slice |
