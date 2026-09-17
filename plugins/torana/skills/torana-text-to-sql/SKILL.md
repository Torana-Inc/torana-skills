---
name: torana-text-to-sql
version: "1.0"
description: >
  Turn a question about security data into SQL against the Torana datalake — grounded in the
  REACHABLE schema, so the SQL can actually return data. REUSE-FIRST: consults the platform's
  reviewed transformer definitions before authoring, reuses one when it fits, and records a
  curation gap when none does — then authors anyway, because a gap in the store must never
  block an answer. Emits one of THREE outcomes, never
  just SQL: (1) SQL, (2) SQL plus an explicit statement of what it does NOT answer, or (3) NO
  SQL plus the name of the column that is missing and the note that nothing writes it. Outcome
  3 is a first-class result — it is an entry in the owed-an-ETL queue, not a failure. Every
  answer states what it did: the intent, the reuse decision with the candidates it rejected and
  the axis each failed on, what was recorded, the sources, and the SQL. Use when
  the user wants to: query the datalake, write SQL for a security question, ask "how many
  vulnerabilities…", "which assets…", "show me findings by…", convert a question to SQL, check
  whether a question is answerable from the data, or find out why a query returns nothing.
  SQL it emits is TENANT-NEUTRAL: every value encoding a tenant's policy is a vocabulary
  placeholder, so one SQL serves every tenant.
  ALSO use before authoring SQL for a detection rule, transformer, widget or catalog entry —
  the same reachability discipline applies. Requires `torana-skill` for CLI/auth bootstrap.
  NOT for authoring a reusable catalog entry (that is `torana-domain-corpus`); NOT for
  auditing an integration mapping (that is `torana-integration-model`).
---

# torana-text-to-sql — a question, honestly answered or honestly refused

## What this skill is for

A text-to-SQL tool that **always** emits SQL is worse than useless on this platform. The
datalake **declares far more columns than any pipeline fills** — the reachable set is a
fraction of the declared schema, and most declared columns are written by nothing. SQL against
one of those shadow columns parses, runs, and returns nothing — or worse, returns a plausible
number that answers a different question.

⚠️ **No count appears in this file, deliberately.** The reachable set changes as writers are
registered, so any figure here would be stale — and worse, would install a prior ("only a small
share is reachable, so most things will fail") that substitutes for looking. The rule is
invariant even though the number is not:

> **Fetch the reachable set. Use only what it returns. Never assume from a count.**

The live figure comes from one command, which is the only authority:

```bash
python "$SKILL_DIR/scripts/reachability_gate.py" fetch --scope platform
```

So this skill's job is not "produce SQL." It is **"produce SQL when the data supports it, say
precisely what is missing when it does not, and never bake one tenant's policy into it."**

Two independent failure modes, both of which produce SQL that looks correct:

| Failure | Looks like | Caught by |
|---|---|---|
| **unreachable** — the column is written by nothing | empty or wrong result | the reachability rules below |
| **tenant-specific** — a policy value is hardcoded | correct *here*, wrong at the next tenant | the vocabulary rules below |

## Prerequisites — do not duplicate them here

**`torana-skill` must be loaded alongside this skill.** It owns CLI mechanics and auth.

```bash
"$TORANA" --version 2>/dev/null || echo "ERROR: torana-skill not loaded — load it first"
```

⚠️ **Read `torana-skill`'s `references/datalake.md` before writing any SQL.** It owns the
reachability rules this skill depends on and does not restate: the two scopes and why
`--scope platform` is the authoring scope, `reachable ≠ populated`, the verify-column-names
rule, and the schema-discovery commands. Everything below assumes you have read it.

---

## The three outcomes

Every response is exactly one of these. Decide from the **schema**, never from a query result.

| | Outcome | When | What you MUST include |
|---|---|---|---|
| ✅ | **SQL** | every column the intent needs is reachable **AND** every policy value is a placeholder | the SQL |
| 🟡 | **SQL + gap** | the core question is answerable but a facet is not | the SQL **and** an explicit sentence naming what it does *not* answer |
| ❌ | **No SQL** | the fact is produced by no pipeline | the **column name(s)** and *"nothing writes this — it needs an ETL"* |

⚠️ **✅ has TWO preconditions, not one.** Reachable-but-hardcoded is **not** ✅. A query with
`severity IN ('Critical','High')` embeds one customer's risk appetite as though it were a fact
about the world; it passes reachability, it parses, and it fails at *deployment*, when the
policy layer has nothing to bind. See **Tenant-neutrality** below.

⚠️ **Outcome 3 is a first-class result.** Naming the missing column is directly actionable —
it is an entry in the owed-an-ETL queue. Guessing instead produces SQL that answers a
different question, which is far harder to catch than an empty result.

### ⛔ The SUMMARY CONTRACT — five things, in every answer, whichever outcome

Whatever the outcome, the answer states these five, in this order. ⛔ **The reuse decision is
part of the answer, not a working note** — an answer that shows only SQL hides whether the
platform's reviewed definitions were consulted at all.

| # | State | ⛔ Not this |
|---|---|---|
| 1 | **Intent** — the need you looked up on, VERBATIM | a tidied-up restatement |
| 2 | **Reuse decision** — reused `<name>`, or not — **naming the candidates considered and the AXIS each failed on** | *"no reuse"* |
| 3 | **Provenance** — what the platform RECORDED (the decision id from `catalog.submission`), or why nothing was | *"recorded"* with nothing to check |
| 4 | **Sources** — which definition, which canonical tables, and any join key used | *"the datalake"* |
| 5 | **The SQL** | |

⭐ **Item 2 must name the near-misses, not just the verdict.** *"Considered `kev_watchlist`
(finding-grain, I need one row per team-month) and `threat_gap` (no `owning_team`)"* is
auditable; *"no reuse"* is an assertion nobody can check. It is also what makes the record
useful — near-misses tell a curator whether to **widen** an existing definition or **write** a
new one.

⚠️ **If the lookup did not run** (§ 0b), item 2 says exactly that and item 3 says **no record
was written**. ⛔ Never report an unavailable store as "nothing matched" — that is the false
gap this skill must not file.

### 🔥 MASKED — worse than blocked, and it outranks it

An unreachable column inside `CASE WHEN … ELSE 'none'` or `COALESCE(unreachable, 0)` makes
every row report `'none'` / `0` **as a fact**. A blocked query fails visibly; a masked one
ships confident wrong numbers that nobody questions.

The gate emits `MASKED` and ranks it **above** `BLOCKED` for exactly this reason. When you hit
one, the fix is never to keep the confident negative: drop the unreachable input, return an
explicit `'unknown'` branch where you can no longer tell, and **name the column** in the report.

⚠️ **Binding can CREATE a masking risk.** `COALESCE(unreachable_col, <conservative default>)`
returns the platform's assumption as though it were measured. Bind policy; never paper over an
unreachable column with a default.

### Choosing between 🟡 and ❌ — the clause decides

This is the whole distinction, and it is mechanical:

- An unreachable column in the **SELECT list** can be dropped. The query still runs and the
  answer merely **narrows** → 🟡, and you say what was lost.
- An unreachable column in **WHERE / JOIN / GROUP BY / HAVING** cannot be dropped. Deleting it
  does not narrow the answer — it returns a **DIFFERENT ROW SET, silently** → ❌ unless a
  genuine semantic substitute exists.

`reachability_gate.py` labels every offending column `STRUCTURAL` or `projection` for exactly
this reason. Do not make this judgement by eye.

---

## The workflow

### 0. ⭐ Resolve the question against the CORPUS — before any schema fetch

```bash
TORANA_PROFILE=<profile> torana admin question-resolve "<the question, VERBATIM>"
```

⛔ **Run it even when you expect a miss, and pass the question VERBATIM.** The phrasing IS the
demand signal: an UNRESOLVED question is an entry in the owed-a-corpus-entry queue, which is
what tells curators what to add next. Paraphrasing destroys exactly the text that queue reads.

⚠️ **A resolve is a HINT, not an answer.** It returns a confidence and a match — measured on a
real question: `EM-100` at **39% via lexical**. That is worth reading for the grain and the
wording the corpus already uses; it is **not** permission to skip steps 1–5. ⛔ A low-confidence
lexical match on a question about a different grain will actively mislead you.

⛔ **`RESOLVED (WEAK)` is a CANDIDATE, not an answer — CONFIRM the grain before using the id.**
The response now carries `resolve_strength` (`strong` | `weak` | `none`). Measured 2026-08-26:

| ask | score | verdict |
|---|---|---|
| a corpus question, verbatim | 0.80-0.87 | `strong` — act on it |
| ⛔ a worklist ask landing on **EM-038, a MONTHLY TREND question** | **0.35** | `weak` |
| a REAL paraphrase ("is our vulnerability backlog growing" = EM-038) | 0.29 | `none` |

⭐ **The false match scores ABOVE two real paraphrases, so no threshold separates them** —
the score is a bag-of-words cosine with no notion of GRAIN, which is exactly what
distinguishes "how many per month" from "one row per fix". Raising the cutoff would break
real paraphrases instead. ⛔ Tagging an artifact from a `weak` resolve writes a wrong
`question_id` into the curation queue that decides what gets authored next.

⭐ Record the outcome in step 5c: `--question-id` on a hit, omit it on a miss (the record then
carries `recorded_as_demand: true`).

### 0b. ⭐ REUSE-FIRST — probe the definition store before you author

⛔ **This step is not optional and it is not a formality.** The platform ships pre-built apps
whose SQL is authored through this skill. A question this skill re-authors from scratch, when a
reviewed definition already answers it, is how two definitions of "open vulnerability" end up in
one platform — disagreeing at the edges, both defensible, neither retractable.

#### ⭐ Probe TWICE — the user's words, then a schema-register rewrite

⛔ **A single probe on the user's own phrasing misses transformers that exist.** The index is
built from `description`, `semantic_description`, `grain`, source tables and vocabulary keys —
**all of it schema register**. A user's question is not, so the two frequently share too few
tokens to match.

Measured: *"Who is carrying the most security debt and who is furthest behind?"* returns
**nothing**, while *"open vulnerability counts by owning team"* — the same need — returns
`vulnerabilities_by_team` **ranked first**. The transformer was there the whole time.

⚠️ **And it is NOT a clean business-vs-technical split, so you cannot phrase around it by
sounding technical.** Four business phrasings of that one need: two found it, one returned
**the wrong transformer ranked first**, one returned nothing. It turns on whether the phrasing
happens to contain a token the index anchors on. ⇒ **Always probe twice.**

```bash
# 1. the user's need, verbatim — this is what gets RECORDED on a miss
TORANA_PROFILE=<profile> torana vm transformers catalog search "<the need, in the user's words>"

# 2. the same need, restated in schema register — grain-shaped, naming tables and measures
TORANA_PROFILE=<profile> torana vm transformers catalog search "<one row per X with Y and Z>"
```

**Write the rewrite as a GRAIN**: *"one row per owning team with open counts and overdue
counts"*, *"one row per remediation task with days since last update"*, *"one row per system
with counts of scans and criticality levels"*. Judge candidates from **both** probes together.

⛔ **REWRITE THE USER'S SUBJECT — never append a fixed block of security vocabulary.** This is
the trap, and it is measured: a canned hint appended to every query recovers the same 5 of 5
transformers **and destroys the ability to MISS**. With it, *"quarterly office supply spend by
department and vendor"* returns **10 confident candidates** from the security store, and
*"headcount by department and hiring manager"* returns 8.

⭐ **A rewrite that stays about the user's actual subject still correctly misses** — *"one row
per vendor with sum of spend"* matches nothing here, as it should. **The rewrite is not buying
you recall; it is buying you the ability to still say no.** A probe that matches everything
records false demand and destroys the curation signal.

⚠️ **Report the rewrite in your answer.** A probe run against text the user did not write,
presented as if they had, is not auditable. State both the verbatim need and the rewrite you
searched with.

⛔ **On a MISS, record the user's VERBATIM need — never the rewrite.** The curation queue is a
demand signal; recording your own paraphrase inflates a need nobody expressed and makes the
queue un-auditable against what was actually asked.

⭐ **`catalog search` is the reuse probe. `catalog list` is NOT** — that serves the old catalog
surface, which is being retired and carries only part of the store, so a reuse check run against
it silently cannot see the rest. To read the whole store rather than search it, that is
`definitions list`. ⛔ Both are `torana-skill`'s to document, not this file's.

Per candidate the probe returns `answers`, `one row` (the grain), `reads`, and — where the
platform could resolve it — `projects`.

⛔ **Leave `--top-k` and `--threshold` at their defaults.** Raising the bar hides candidates,
and a hidden candidate becomes a duplicate definition forever. ⚠️ **Lowering it is worse, not
safer**: below the default an unrelated need stops reporting a miss at all — so the gap is never
recorded, which is the one signal a curator needs.

#### ⛔ Did the lookup RUN? Answer that FIRST, before reading the result

**A lookup that never ran and a lookup that found nothing are indistinguishable from the result
alone** — by construction. ⛔ **So never infer "no candidates" from an empty-looking result.**
This has already filed a false `genuinely_novel` gap against a well-populated store, because
`pantheon-data-transformers` restarted mid-run and the search returned nothing.

Decide from the **call's outcome**, never the result's shape:

| what you observe | what it means | what to do |
|---|---|---|
| exit **0** with a JSON body | ⭐ the lookup RAN | read the candidates; `is_miss` tells you whether any cleared the threshold |
| non-zero exit, or **empty stdout** | ⛔ the lookup DID NOT RUN | ⛔ **record nothing.** Say the store could not be consulted, then author — do not file a gap you did not measure |

⚠️ A 502 here is `pantheon-data-transformers` being down — it is the upstream nginx proxies
`/api/v1/vm/transformers` to, NOT program-framework. Say so; do not treat the store as empty.

#### Adjudicate on GRAIN — the score classifies nothing

⛔ **A HIT IS NOT PROOF OF COVERAGE — adjudicate on `one row` (the grain), never the score.**
The threshold is deliberately LOW: its job is cheap recall, handing you plausible candidates to
judge. It is not a verdict. Measured 2026-08-26:

| query | top score | truth |
|---|---|---|
| `em_040`, its own description verbatim | 0.765 | real hit |
| **"One row per repository with its open finding counts by severity"** | **0.755** | ⛔ **real GAP — asked 9×, top recorded repository-axis miss** |
| "quarterly office supply spend by department and vendor" | 0.626 | nonsense |
| "average rainfall in Bangalore in July" | 0.446 | absurd, and *only just* a miss |

⭐ **0.010 separates the worst true hit from a genuine gap**, so no threshold can classify
both correctly, and the response's `confidence_band` reports `ambiguous` for everything in
0.60–0.80. ⛔ In that band the score tells you NOTHING — read each candidate's `one row`
line and decide whether it is YOUR grain. `EM-100` returns a confident `em_034`; taking that
at face value is how a real gap stays invisible for nine askings.

#### ⚠️ A missing `projects:` line means UNKNOWN, never "projects nothing"

A candidate's `projects:` line lists the columns it actually SELECTs. **It is absent when the
platform could not resolve them** (a `SELECT <alias>.*` form), not when there are none.

⛔ **Reading an absent projection as "it lacks the column I need" is a false rejection**, and
it has already happened: a judge rejected a fitting candidate for "not projecting
`days_open` and `threat_score`" — **both of which it projects**. It was shown no columns and
guessed from the description.

⇒ **No `projects:` line ⇒ judge that candidate on GRAIN alone.** Never reject it for a missing
column you cannot see. When a projection *is* shown and the column you need is genuinely absent,
that is a real `missing_column` axis — and you can now say so with evidence.

#### 0b-i. ⛔ RECORD AND PROCEED — a miss must never block the answer

⭐ **On a miss you record the gap, then you author anyway.** You are on the live path and
**nobody is standing by.** Blocking an analyst because the store has a gap is a worse failure
than authoring fresh SQL.

⚠️ **This is deliberately the opposite of the BUILD path, which fails closed on a miss.** Both
paths record; only the consequence to the caller differs — a build can wait for a human to add
a definition and re-run, a question cannot. ⛔ **Do not "fix" this inconsistency.**

⛔ **Do NOT call `record-miss` here by hand.** ⭐ **Step 5c's evidence record is this skill's
wire** — it calls `record-miss` for you with the arguments `torana-skill` specifies (verbatim
need, named axis, near-miss anchor), and reports back what the platform actually stored. Carry
the verdict forward instead: `--catalog-verdict miss`, `--catalog-axis`, `--catalog-entry-id`,
`--catalog-gap-category`, `--submit`.

⛔ **Recording it twice is not belt-and-braces — it is FALSE DEMAND.** Two rows for one gap
inflate that need's rank in the queue deciding what a curator authors next, and it is invisible
from your side: the answer still looks right. **One gap, one row.**

⭐ **A failure to record does NOT block the answer — by contract.** The wire is best-effort and
never raises. ⚠️ But it **reports**: read `catalog.submission` and say in your summary if it did
not land. Silence about an unrecorded miss is the failure that wire exists to end.

⭐ **A reuse is recorded too**, as its own decision kind — pass `--catalog-verdict reuse`. ⛔
What must never happen is a **miss** recorded for a question you reused.

⛔ **Running a test, probe or verification lane? `export TORANA_DECISION_ORIGIN=test` first.**
An unlabelled probe is recorded as real demand and inverts the curation ranking.

#### 0b-ii. ⭐ Definitions and canonical tables are judged TOGETHER, never in sequence

⛔ **Do not treat this as "check the store, and if that fails, go to the schema."** A sequential
lookup stops at the first *good enough* hit — and "good enough" is exactly the failure this skill
exists to prevent. A definition that is CLOSE, reused because nothing better was in view, yields
a confidently wrong number. **Seeing both at once is what distinguishes "this fits" from "this
nearly fits."**

So: fetch the reachable schema (step 1) **and** the semantic model (step 1b) even when a
candidate looks promising, and judge across both. A definition is rich but never exhaustive —
it projects a curated subset where the canonical table carries everything — so the common
shape is not *either/or*:

⭐ **Prefer a definition as the BASE, and JOIN a canonical table for what it does not carry.**
That reuses the reviewed logic *and* answers the whole question, instead of abandoning the
definition over one missing column or re-deriving what it already computes.

⛔ **That join is subject to the SAME trust rules as any other — step 1b, no exemption.**
Verify the key in `query-hints` before joining. ⚠️ A definition-to-canonical join on an
unverified key is **worse** than authoring from canonical alone, because the definition's
reviewed provenance makes the whole query look vouched-for. If the key does not hold, say so
and build from canonical tables instead.

#### 0b-iii. ⛔ EXISTS is not MATERIALIZED — three facts, not one

⛔ **A definition existing in the store does NOT mean you can `SELECT` from it in this tenant.**
The store is platform-wide; materialization is per-tenant. Many definitions are seeded and
never built for a given tenant — they have no relation behind them.

⛔ **Putting such a name in a `FROM` clause produces SQL that fails at runtime — which is worse
than not offering it**, because the caller reads reviewed-looking SQL and only finds out when
they run it.

Three distinct facts, and you must not collapse them:

| fact | what it answers | how to establish it |
|---|---|---|
| **EXISTS** | is there a reviewed definition for this shape? | the reuse probe (`catalog search`) |
| **MATERIALIZED** | is there a relation to SELECT from, *in this tenant*? | is the name in the reachable-table listing you fetched in step 1a |
| **HEALTHY** | is what it returns CURRENT? | ⛔ see the health-honesty warning in step 1a — you very likely **cannot** establish this |

⇒ **Offer them differently, and say which you are doing:**

- **Exists + materialized** → reuse it: `FROM <name>`, normally.
- **Exists, NOT materialized** → ⛔ **never** a `FROM` target. Report it as *"a reviewed
  definition covers this need but is not built in this tenant — ask for it to be materialized"*,
  and author against canonical tables meanwhile. That is a useful answer; a broken query is not.
- **Materialized but health unverifiable** → say the freshness is unverified (step 1a), or
  prefer canonical tables, which cannot be quarantined.

### 1. Fetch the reachable schema — never embed one

```bash
python "$SKILL_DIR/scripts/reachability_gate.py" fetch --scope platform --table vulnerabilities
```

⚠️ **Fetch it every time.** `pantheon-shared/.../datalake/text_to_sql.py` froze a schema
listing into a prompt template and drifted: it advertises *"ASSETS Table (197 fields)"* when the
live table has 145, and *"VULNERABILITIES (213 fields)"* against a live 181. **A schema listing
pasted into a prompt is a bug with a delay on it.**

⚠️ **That module is DEAD CODE — measured 2026-08-09, zero importers anywhere in the tree, and
it is not exported from `datalake/__init__.py`.** It is kept here only as the cautionary
example. ⛔ **The LIVE platform text-to-SQL path is
`pantheon-agent-builder/src/utils/schema_context_injector.py`**, which fetches
`/tables/schema` per turn and (since S6) passes `reachable=true&scope=platform`. If you are
reasoning about "what the other harness does", read that file — not this one.

### 1a. ⭐ Fetch the TENANT'S TRANSFORMER TABLES — step 1 does not return them

```bash
TORANA_PROFILE=<profile> torana datalake all-columns --scope platform --include-transformers
```

⛔ **Step 1's reachable fetch returns CANONICAL TABLES ONLY.** Reachability asks *"does an
ingest pipeline write this column?"*, which is meaningless for a table whose columns are
produced by SQL — so the datalake drops transformer/aggregator tables from a reachable
response by design. Measured on T2 2026-09-15: **11 tables reachable, 32 in the tenant** —
21 tables invisible to a step-1-only fetch. On T1: **13 canonical, 15 with the flag.**

The output labels them for you:

```
TABLES SHOWN  15  (declared)
CANONICAL     13   platform schema — identical for every tenant
TRANSFORMER   2   ⚠️ PER-TENANT — derived tables this tenant's own models built
```

⭐ **PREFER A TRANSFORMER WHEN ONE ANSWERS THE QUESTION.** It is a maintained, pre-computed
answer: fewer joins, fewer grain mistakes, and it encodes decisions someone already made.

⛔ **But do NOT read that as "check transformers first, canonical second."** Judge both
together — step 0b-ii says why, and this listing is one of the two halves it means. What this
listing adds to the reuse probe is **MATERIALIZED**: a name here has a relation behind it in
this tenant; a definition absent from here does not, whatever the probe said (step 0b-iii).

⚠️ **Do NOT force a fit.** A transformer at the wrong grain gives a confidently wrong number —
the §1c failure mode, with an authoritative-looking table name attached. When none matches,
build from canonical tables and say so.

⛔ **This rule gets HARDER to follow as the candidate pool grows, not easier.** More candidates
means more that are nearly right, and "nearly right" is what produces a confident wrong number.
A wider probe is there to stop you MISSING a fit — never to help you find one where there is
none.

⛔ **These columns are NOT reachability-vetted, and that changes how you read an empty result.**
Nothing vets them because no pipeline writes them. So:

- The column names **are real** — use them exactly as returned. Never infer one from the
  table's name or from the wording of the question. (A "new findings per week" table spells
  its columns `arrivals` and `closures`.)
- An empty result means **no rows matched**, NOT that a column is unwritable — the opposite of
  what an empty result means for an unreachable canonical column.
- ⛔ **A transformer table can be STALE or QUARANTINED and still serve rows.** Measured on T2:
  **24 of 34** transformers had `last_status='failed'` while their tables kept returning data.
  If the number matters, check status before trusting it — or use the canonical tables, which
  cannot be quarantined:

  ```bash
  TORANA_PROFILE=<profile> torana vm transformers materialized --verify     # status + does the relation still exist
  TORANA_PROFILE=<profile> torana vm transformers materialized --status failed
  ```

  ⛔ **`No results.` is NOT "all healthy" — and on a real tenant it is actively misleading.**
  `materialized` covers only the **VM convenience tables**, not every transformer. Re-measured
  on T2 2026-09-16: it returns **empty** while **34 of 37** transformers are
  `last_status='failed'` (2 success, 1 never run). A tenant where the overwhelming majority of
  transformers are failing looks perfectly clean through this command.

  ⚠️ **Re-measured, still true, and the gap WIDENED** — it was 24-of-34 on 2026-09-15. Do not
  assume a later platform change has quietly fixed this; it had not.

  ⛔ **Do NOT substitute `GET /api/v1/transformers` for it.** That route is answered from the
  **calling service's own tenant**, not the tenant you are authoring for — on T2 it returns the
  `Torana` service tenant's 18 rows (`17 success + 1 NULL`) instead of T2's real
  `24 failed + 10 success`. You would read another tenant's health and conclude everything is
  fine. (Root cause and the fix are in
  `pantheon-agent-builder/docs/TEXT2SQL_TRANSFORMER_REDESIGN.md` § 3.2a.)

  ⇒ **There is currently NO reliable per-tenant transformer health check from the skill.** So:
  **state that the freshness is unverified** whenever the number matters, or prefer the
  canonical tables, which cannot be quarantined. Never imply a transformer is current because a
  health command returned nothing.

⚠️ **INTERIM — this step goes away.** The platform is moving to inject healthy transformer
tables directly, annotated `vetted: false`, with a real health gate
(`pantheon-agent-builder/docs/TEXT2SQL_TRANSFORMER_REDESIGN.md` § 2.1a / Phase 3). Until then
this fetch is the skill's only route, and `--include-transformers` is **off by default**, so
omitting it silently authors against two-thirds of the tenant's tables.

### 1b. ⭐ Fetch the SEMANTIC MODEL too — the schema does not carry joins

```bash
TORANA_PROFILE=<profile> torana datalake query-hints
```

⚠️ **`/tables/schema` answers "what columns exist". It cannot answer "how do these tables
relate".** Those are different facts, and the second is a property of a table PAIR, so no
column list can carry it. Fetching only the schema is how a query joins correctly and still
returns the wrong number.

Six things this returns that the schema does not:

| | What it gives you | Why the SQL is wrong without it |
|---|---|---|
| ⭐ **MEASURES** | what ONE ROW of the answer represents — grain, SQL hint, and the plausible WRONG reading | ⛔ **the largest single source of wrong answers.** On a live tenant *"how many vulnerable packages?"* spans **2,271×** across three honest readings and *"how many vulnerabilities?"* spans **317×**. See § 1c — pick one and name it in a comment |
| **join keys** | the exact `ON` clause | a guessed join is a different question |
| ⛔ **measured trust** | `RELY` / `DEGRADED` / `NORELY` / `UNMEASURED` + an orphan rate per join | **a declared join is not a working join.** On a live tenant most declared joins did NOT connect cleanly — some orphaned the overwhelming majority of rows that asked for a partner, and one could not be executed at all — yet **before trust was measured they all rendered identically**. ⛔ So never infer a join's health from the fact that it is declared: **read the verdict** (below) for the tenant you are authoring against |
| ⭐ **cardinality** | `[many_to_one]` / `[one_to_many]` per edge | the **fan-out** signal — joining along `one_to_many` MULTIPLIES rows, so a `COUNT(*)` after it counts the child, not the parent. Use `COUNT(DISTINCT <parent key>)` or pre-aggregate in a CTE |
| ⭐ **the entity graph** | every `edge_type` on `entity_edges` with the namespace on each side (`contains  image: → pkg:`), **plus `key RESOLUTION` — which column each namespace's keys can be joined to** | ⛔ `entity_edges` is an adjacency list and `many_to_many` **in both directions** — an unfiltered join fans out. **ALWAYS filter `edge_type`**, and pick the type whose namespaces match the two things you are connecting |
| ⭐ **column MEANING** | `tables.<T>.field_hints.<COL>` — `description` (what the column actually holds, hand-authored) and `aggregation` (how a metric rolls up) | ⛔ **READ THE DESCRIPTIONS. They carry the NULL traps a type cannot.** `vulnerabilities.created_via` is NULL on all 114,151 rows of a live tenant, so `WHERE created_via != 'sdg_replay'` drops **every real row** — `!=` never matches NULL. `is_false_positive = false` means *never triaged*, not *confirmed real*. `priority_score` is UNBOUNDED (measured 0–273), not a 0–100 scale. ⚠️ `aggregation` names the correct roll-up (`AVG` on a score) — **SUM over a score is silently wrong and raises no error** |

⚠️ **`field_hints` is the surface the platform's own harness renders as `COLUMN MEANING`**
(`pantheon-agent-builder/src/utils/schema_context_injector.py::_format_query_hints`). Both
paths read the same payload, so a column's meaning is identical whichever authors the SQL.
⛔ Do **not** re-derive a column's meaning from its name when a `description` exists — the
name is what the description is there to correct.

⚠️ **Enums are NOT in `field_hints` for your purposes** — take value domains from
`reachable-columns` / the schema's `value_domains`, which carry `closed`. `field_hints` also
carries `enum`, but reading it from two places is how the two copies drift.

#### ⛔ A `NORELY` join — never emit it silently

Trust is **measured per tenant**, after each sync, by running the declared join and counting
rows that name a partner which does not exist. It is served on every join in `query-hints`,
and on its own surface:

```bash
TORANA_PROFILE=<profile> torana datalake join-health
```

| Verdict | What it means | What you do |
|---|---|---|
| `RELY` | the join connects (≤1% orphaned) | use it normally |
| ⚠️ `DEGRADED` | works for most rows, **silently drops the rest** | use it, and **state the rate in the answer** — a count built on it is low, with no error. ⭐ **This is the most dangerous verdict, not the least:** a low single-digit orphan rate can still drop thousands of rows while returning a number that looks entirely plausible |
| ⛔ `NORELY` | rows name partners that **do not exist** | ⛔ **do not emit SQL that depends on it without saying so.** Either find another path, or answer in this shape, with **the rate the command reported**: *"vulnerabilities and assets cannot be reliably joined on this tenant — N% of vulnerabilities name an asset that does not exist"* |
| `UNMEASURED` | **nobody has checked** | ⚠️ **never read this as "fine".** Say the join is unvouched-for if the answer rests on it |

⚠️ **An empty result over a `NORELY` join is NOT an answer.** "There are no vulnerabilities on
that asset" and "this join has never matched a single row" are opposite conclusions, and
without the trust flag they arrive looking identical. **Reporting the first when the second is
true is the single most expensive thing this skill can do** — it is a confident zero.

⛔ **QUOTE THE RATE THE COMMAND REPORTED, NEVER A RATE FROM THIS FILE OR FROM MEMORY.**
Trust is re-measured **per tenant, after every sync**, so a rate is true of one tenant at one
moment. The same join has been seen at wholly different rates on different tenants and on the
same tenant days apart. ⚠️ A number carried over from a previous answer, another tenant, or this
document is a **fabricated measurement** — it will read as authoritative and be wrong. Run
`join-health` (or read the join's trust in `query-hints`) for the tenant you are answering about,
and quote *that*.

⚠️ **The orphan rate's denominator is JOINABLE rows (non-NULL keys), not all rows.** A NULL key
is not an orphan — the row never claimed a partner. A join reported `UNMEASURED /
no_joinable_keys` is **UNUSED on this tenant**, which is a different report from broken: no row
is orphaned because no row asked for anything.

⚠️ **`UNMEASURED` carries a reason — read it, they mean different things.**
`no_joinable_keys` = every key is NULL (the join is unused); `no_rows` = a side is empty, so
there was nothing to measure; `column_missing` = the declared join **cannot be executed** because
a column does not exist — a DECLARATION defect, not a data one, and the one case where the fix is
in the semantic model rather than the pipeline.

#### ⛔ Getting from the GRAPH back to the ROWS — use `key RESOLUTION`, never string surgery

`edge_type values` tells you a `deployed_as` edge runs `image: → service:`. **`key RESOLUTION`
tells you which column an `image:` key can be joined to** — so you never have to manufacture
the join yourself:

```
  key RESOLUTION — where each namespace's keys can be joined (measured on this tenant, best first):
    image:      vulnerabilities.torana_entity_id (100%)  assets.torana_entity_id (39%)  artifacts.torana_entity_id (7%)
    team:       ⛔ resolves NOWHERE — these keys exist only in `entity_edges`
```

```sql
-- ✅ join the graph key to the declared column, whole and unmodified
JOIN vulnerabilities v ON v.torana_entity_id = e.from_key

-- ⛔ NEVER do prefix surgery
JOIN vulnerabilities v ON v.torana_entity_id = substring(e.from_key from 7)
```

⚠️ **That second form is not a hypothetical — it is a measured silent zero.** On a live tenant
it returns **0 rows** where the correct join returns 13. The reason is worth internalising,
because it is not the one you would guess: the sink columns **store the prefix too**
(`vulnerabilities.torana_entity_id` = `image:us-west1-docker.pkg.dev/…`). Stripping it
guarantees nothing matches. ⛔ **Join entity keys whole. Never slice, pad, or re-case them.**

**Three rules for reading the block:**

| What you see | What it means |
|---|---|
| several columns listed | ⭐ **a namespace can live in more than one table.** They are ordered best-first with coverage — take the first unless you specifically need another table's columns |
| a low percentage (e.g. `7%`) | a real join target for a **slice** of that namespace, NOT where those keys live. Joining it silently drops the other 93% |
| ⛔ `resolves NOWHERE` | these keys exist **only** inside `entity_edges`. Stay in the graph — do not invent a join to a sink table |

⚠️ **This is measured per tenant, not declared.** The same namespace resolves to three columns
on one tenant and to nothing at all on another. ⛔ Never carry a resolution you saw once into
another tenant's SQL — re-read the block.

⛔ **Do NOT probe the data to tell edge types apart.** `contains` (image→pkg) and `deployed_as`
(image→service) are distinguishable from this payload alone. Reading tenant rows to learn a
join's shape is a tenant answering a schema question — and it is what `joins.probed: true` in
the step 5c evidence record reports as a regression.

### 1c. ⭐ PICK THE MEASURE — what ONE ROW of the answer represents

⛔ **Do this BEFORE choosing columns.** The wrong grain makes every join and column decision
below irrelevant — the SQL will be valid, run clean, and answer a different question.

`query-hints` opens with a `MEASURES:` block. Each entry gives a **grain** (what one row is),
a **SQL hint**, and a **trap** (the plausible wrong reading).

⚠️ **This is the single largest source of wrong answers, measured twice.** Nine of thirteen
misses in a controlled batch had the right table and a defensible choice, then **counted a
different thing**. The spread is not marginal — on a live tenant:

| The question | Honest readings | Spread |
|---|---|---|
| *"how many vulnerable packages do we have?"* | 92 packages · 741 package-CVE pairs · 208,920 rows | ⛔ **2,271×** |
| *"how many vulnerabilities do we have?"* | 659 distinct CVEs · 208,958 findings | ⛔ **317×** |

**Every one of those SQL statements is correct.** The question never said what to count.

#### The three rules

1. ⭐ **NAME the measure in a SQL comment, always.** This is not decoration — it is how a
   reader discovers you answered a different question than they meant, without re-deriving
   your SQL.

   ```sql
   -- MEASURE: distinct_cve (one row per CVE, however many times it occurs)
   SELECT count(DISTINCT cve_id) AS exposed_cves
   FROM vulnerabilities WHERE is_deleted IS NOT TRUE;
   ```

2. ⛔ **If no declared measure fits, SAY SO AND ASK.** Do not invent a grain silently. An
   invented grain is indistinguishable from a declared one in the output, which is precisely
   what makes it expensive.

3. ⚠️ **Re-check the grain after every join you add.** A join can silently change what a row
   represents. Joining `entity_edges` on `contains` to reach packages fans out **~306×** (one
   package sits in 306 images on average), so `count(*)` after that join counts the fan-out,
   not the packages.

4. ⛔ **READ THE `empty:` LINE AND CARRY IT INTO THE ANSWER.** Each measure declares what
   happens to a row with **no value / no match** — which rows the SQL silently drops. This is
   a different question from the `trap:` line: the trap is the plausible wrong *reading*, the
   empty case is what the *right* reading throws away.

   ```
   distinct_cve
       SQL:   count(DISTINCT cve_id) FROM vulnerabilities WHERE cve_id IS NOT NULL ...
       empty: ⛔ Rows with a NULL cve_id VANISH from this count — measured on a live
              tenant, 1,105 of 208,958 rows (0.5%). They are real findings that no
              source gave a CVE identifier.
   ```

   ⚠️ **The exclusion is usually CORRECT, and still worth saying.** A finding with no package
   is not a vulnerable package. But *"92 packages"* and *"92 packages, excluding 38 findings
   that name none"* are different answers, and only the second lets a reader tell a real zero
   from a filtered one.

   ⭐ **When a measure's `empty:` line says rows are dropped, state the exclusion beside the
   number** — one clause, not a caveat paragraph. ⛔ Never present a filtered count as a
   total. `vulnerability_finding` is the one measure here that drops nothing; its `empty:`
   line says so, which is exactly why it returns the largest number.

⚠️ **A measure is a PRODUCT decision, not a data fact.** It is declared once, deliberately, and
is not derivable by inspecting a tenant. ⛔ **Never "verify" a grain by checking whether two
readings happen to agree on the tenant in front of you** — `externally_reachable_service` gives
the same number under both readings on tenants where every service has one image, and diverges
badly where they do not.

### 2. Map the intent to columns, and check each one

Confirm each column against the fetched set. Two things that are NOT unreachable and must not
be treated as such:

- **System fields** — there are **seven**: `tenant_id`, `namespace_id`, `is_deleted`,
  `created_at`, `created_by`, `updated_at`, `updated_by`. They are written by the platform on
  every insert, are **absent from both the reachability classification and the declared-schema
  response**, and are always available. `is_deleted` appears in nearly every real WHERE clause.
  ⚠️ **Do not retype this list — ask for it.** The gate reads it from the API
  (`reachable-columns` → `system_columns`) and **nowhere else**: the old `pantheon-shared`
  fallback was DELETED, because off-repo it degraded rather than failed and then condemned
  `is_deleted` with a confident verdict. A new system field is picked up with no edit here. This line previously listed
  nine, adding `trace_id` and `contributing_sources`, which are **not** system fields — take
  the set from the source, never from prose.
- **Projection aliases** — `ORDER BY critical_open` refers to a SELECT alias, not a column.

⛔ **Two columns pass this check and are still forbidden:** `vulnerabilities.vulnerability_due_date`
and `vulnerabilities.vulnerability_sla_breach_date`. They are reachable AND populated, so
step 2 gives them a clean pass — but they are the tenant's SLA policy *already materialised*,
and reading one applies whatever policy was in force when the decoration last ran. **Compute
the deadline instead** — see the deny-list in step 3.

#### Finding the column you must NAME for outcome 3

⚠️ **The fetch in step 1 returns the REACHABLE set — which by definition cannot contain the
column outcome 3 asks you to name.** To name what is missing you need the **declared** set,
and the honest report needs both:

```bash
TORANA_PROFILE=<profile> torana datalake schema table <table> --scope platform   # DECLARED — every column
TORANA_PROFILE=<profile> torana datalake all-columns --table <t> --value-domains --scope platform  # what it can HOLD
TORANA_PROFILE=<profile> torana datalake schema audit                             # is the schema described accurately?
TORANA_PROFILE=<profile> torana datalake all-columns --scope platform      # DECLARED, all tables
python "$SKILL_DIR/scripts/reachability_gate.py" fetch --table <t>   # REACHABLE — the subset
```

⛔ **Do NOT reach for `datalake supply columns --scope tenant --tenant-id <uuid>` here.** That command
answers a genuinely different question — *what can THIS tenant get today* (on T2: 314 of 441)
— and it exists for operating an estate, not for authoring SQL. SQL is written once for every
tenant, so a tenant lens would condemn columns that are correct the moment a customer
connects an integration. Measured on `vulnerabilities`: platform 99 reachable, tenant 7.
⭐ **The gate is pinned to `--scope platform` on purpose; leave it there.**

Diff them. Three outcomes, and they are **different findings** worth stating differently:

| What the sweep shows | Report it as |
|---|---|
| declared, not reachable | *"`<col>` is declared but nothing writes it — it needs an ETL."* |
| not declared anywhere, in any sink table | *"**no column in any sink table records X**"* — a stronger and more actionable finding |
| reachable after all | not outcome 3 — go back to step 2 |

⚠️ **Sweep all tables before claiming a concept is absent.** *"I could not find an approver
column"* is a guess; *"no column in any of the 11 sink tables records who approved an
exception"* is a finding, and it is the one that belongs in the owed-an-ETL queue.

### 3. Template the POLICY — tenant-neutrality

⚠️ **Required reading before writing any SQL: [`references/vocabulary-contract.md`](references/vocabulary-contract.md)** —
one row per key: meaning, value domain, conservative default, **legal render verbs**, the exact
binder form to emit, and the deny-list. It is **generated** from the two live registries by
`scripts/generate_vocabulary_contract.py`; never hand-type a key or a verb from memory.

**The bare binder form is the one to emit.** Two syntaxes exist over the same 48 keys:

| | catalog / corpus SQL ← **you are here** | app-template artifacts |
|---|---|---|
| Syntax | `{{key}}` `{{key.at_or_above}}` `{{key[expr]}}` `{{#toggle key}}` | `{{vocab:vm.<cat>.<sub>.<key>}}` |
| Renderer | `vm_catalog/binder.py` → `bind_entry()` | `vm_content/vocab_render.py` |

⚠️ A `{{vocab:…}}` placeholder in corpus SQL is **not** resolved by the binder, survives
binding, and reaches EXPLAIN as a syntax error. This has already shipped once.

**Verbs are legal PER KEY — check the contract, do not infer.** `severity_floor` takes
`.at_or_above`; **`sla_window_by_severity` takes NO verb at all** — it is a dict and uses the
key-map form `{{sla_window_by_severity[v.severity]}}`. Emitting
`{{sla_window_by_severity.at_or_above}}` is plausible-looking and wrong. **15 of the 48 keys
accept no verb.**

#### The three-way literal test — do NOT template everything

| Kind | Example | Action |
|---|---|---|
| **tenant policy** | `severity IN ('Critical','High')` | **bind** it |
| **definitional** | "12-month trend" — the window IS the question | **keep** the literal |
| **reporting window** | caller wants 7 vs 90 days | **expose** it, don't bind |

Ask: *would two reasonable tenants disagree about this value, and does the question stay the
same question if they do?* Both yes → bind. If changing it changes the question → definitional.

⚠️ **Over-templating is its own failure.** A query where everything is a variable answers
nothing specific and forces every caller to supply 20 values. A **synthesized output label**
(`'missing_team'`, `'verified'`) is never a policy literal — it is the query's own vocabulary.
Declare a deliberate literal with `-- policy-literal-ok: <reason>`; the reason is required.

#### ⛔ Deny-list — never read these two columns

`vulnerability_due_date` and `vulnerability_sla_breach_date` are written by the `policy`
decoration (`kind=DERIVE, mode=FILL`, from `scan_first_detected_date`). **They ARE the SLA
policy, already materialised** — carrying whatever windows were in force when the decoration
last ran, with per-row provenance because `mode=FILL`. The vocabulary key is applied at bind
time and always wins.

```sql
-- ⛔ WRONG. Reachable, populated, passes every gate check, silently stale policy.
WHERE v.vulnerability_due_date < NOW()

-- ✅ RIGHT. Compute the deadline from the key + the row's own anchor.
WHERE v.scan_first_detected_date
        + ({{sla_window_by_severity[v.severity]}})::int * INTERVAL '1 day' < NOW()
```

⚠️ **The single most likely trap here.** *"Which vulnerabilities are overdue?"* has an obvious
wrong answer that looks completely correct.

**The gate enforces this** — a read in a *deciding* position (WHERE/JOIN/HAVING/GROUP BY, a
CASE inside one, or a `COUNT(*) FILTER (WHERE …)`) is verdict `STALE_POLICY`. A plain SELECT
echo is not flagged: it shows what the platform currently thinks and decides nothing. The
deny-list is derived from the decoration registry, so a newly-registered policy column is
covered automatically. Waive a deliberate read with `-- policy-literal-ok: <reason>`.

#### Three constraints that silently break bound SQL

1. **The key must be declared on the entry** — `bind_entry` only resolves keys in
   `entry.vocabulary_keys`; an undeclared key's placeholder survives binding.
2. **Never emit a `NOT_APPLICABLE_KEYS` key** (today: `asset_type_scope`). `bind_entry`
   **raises** rather than binding, because binding would silently return zero rows.
3. **The SQL must be correct with conservative defaults applied** — that is the unconfigured
   tenant's experience, and it is what the gate checks.

### 4. Consider a substitution — but only if it means the SAME thing

This is where the skill earns its keep over a mechanical rewrite, and it is also its single
biggest risk.

> **RULE: a substitution must be SHOWN to the user with its semantic difference stated,
> never applied silently. If you are unsure, that is outcome 3.**

Two worked candidates, both of which look easy and are **both rejected** — the reasoning is
the template to follow:

**`vulnerabilities.torana_issue_id` — REJECTED.**
The tempting move is to reach the vuln↔ticket link from the other side, since
`issues.torana_issue_id` *is* reachable. It does not work: that column is the issue's **own
primary key** (`jira/issues.yaml` derives `'jira_issue_' + record.id`), not a pointer to a
vulnerability. The real bridge is `issues.torana_vulnerability_id`, which is **declared and
written by nothing** — the only mention in the mapping is a comment calling it "the documented
bridge." **The link is unreachable from both directions.** → outcome 3.

**`assets.vm_last_scan_time` → `vulnerabilities.scan_last_detected_date`
— REJECTED.**
Reachable and adjacent, but **not equivalent**: one is when an asset was last *scanned*, the
other when a *finding* was last seen. An asset scanned clean has the first and no row at all
for the second. Substituting silently would invert the answer to any scan-coverage question —
the assets you most want to find (scanned, nothing found) vanish. → outcome 3.

A substitution is acceptable only when you can state the difference and it does not change
the answer to *this* question. Offer it; let the user accept it.

#### Synthesis is not substitution — and it is never ✅

**Substitution** swaps one column for another. **Synthesis** constructs a concept the schema
does not name — an "exposure level", a "risk tier", a "health score" — from several reachable
inputs. They are different moves and the second is not covered by the rule above.

⚠️ **Synthesis is PERMITTED, but it is 🟡, never ✅.** The constructed value is the query's
*opinion*, not a measurement: two tenants applying the same question would tier differently,
and no column anywhere records the answer. Treating it as ✅ hides that.

When you synthesize, you MUST:

- **State that the schema records no such value**, and that the tiering is the query's own
  construction — in the 🟡 gap sentence, not only in a comment.
- **Never name the output after an unreachable column.** A projection aliased `risk_score`
  when `assets.risk_score` is written by nothing is indistinguishable from the real thing to
  every downstream consumer. Name it for what it is (`exposure_tier`, `computed_pressure`).
- **Show the inputs in the query**, so a reader can disagree with the construction. A `CASE`
  a reviewer can argue with is honest; a magic number is not.
- ⚠️ **Order the branches so the "cannot tell" case cannot swallow real signal.** A `CASE`
  whose `unknown` branch is tested first will classify assets that DO have findings as
  unknown. Put the decisive branches first and the `unknown` branch last — and see step 7:
  a distribution piled into one bucket is how you catch this.

If you cannot state the construction honestly, or the concept's whole value was that it was
*measured*, that is outcome 3 — say nothing records it.

### 5. Re-verify the SQL you wrote — do not predict

```bash
python "$SKILL_DIR/scripts/reachability_gate.py" check --file /tmp/candidate.sql
```

⚠️ **Re-parse the FINAL text.** Do not reason that a rewrite is clean. The corpus generator
leaked unreachable columns **twice** by predicting; the version that worked re-parsed its own
output. A column can be a plain projection *and* a reference inside a `CASE` in the same
SELECT — remove the projection and the CASE still refers to it.

Exit code is `0` only when the SQL parses and every column reference is reachable.

⚠️ **`checked: N` counts DISTINCT table-qualified columns, not references.** A 90-line query
legitimately reports `checked: 19`. A low number is not evidence of a false pass — but if you
want to prove the gate is really looking, plant a known-unreachable column (`assets.risk_score`)
and confirm it is caught. It sees inside CTEs, `CASE`, and aggregate `FILTER`.

### 5a. ⭐ Check the DATA SHAPE of every column the SQL decides on

⚠️ **Reachability and shape are different questions, and a query passes the first while
being permanently broken by the second.** Measured on T1: `vulnerabilities.is_false_positive`
is `SUPPLIED`, self-filling, **100% populated** — and holds only `False`. It passes step 5
cleanly, and `WHERE is_false_positive = true` returns **zero rows forever**.

```bash
python "$SKILL_DIR/scripts/reachability_gate.py" shape --file /tmp/candidate.sql
# or fold it into step 5:
python "$SKILL_DIR/scripts/reachability_gate.py" check --file /tmp/candidate.sql --shapes
```

#### ⛔ The routing rule — pick the depth from HOW the column is used

The value axis ships three depths at three costs. The gate chooses per column; you need to
know the rule so you can tell when it is wrong:

| the column is used for… | depth | why |
|---|---|---|
| an **equality / IN / comparison against a literal** — `severity = 'Critical'` | `--values` | you need the **actual values**. A predicate on a value that does not exist returns zero rows forever, and no cardinality figure reveals that. |
| a **`COUNT` / `GROUP BY` / `ORDER BY`** — no literal | `--shape` | cardinality is enough. **Free** — one `pg_stats` read per *table*, no scan. |
| **existence only** | `--fill` | one aggregate; the value list is not needed. |

⛔ **`--values` implies `--shape` and `--fill`, and that is resolved SERVER-SIDE.** The gate
makes ONE call at the deepest depth any column needs. **Do not re-implement the implication** —
two harnesses consume this surface and a local resolution is exactly the drift the one-resolver
rule prevents.

⛔ **The classifier is shared, not local.** `route_sql` / `constant_warnings` live in
`pantheon_shared.datalake.shape_routing` because the **platform text-to-SQL agent runs the same
rule**. If this skill classified usage locally, a Claude skill and a platform agent would
produce different SQL for the same question — and neither would be obviously wrong.

#### Three rules that prevent a false alarm

1. ⛔ **`ENUM` is not `CONSTANT`.** `vulnerability_status` is `Open` 6274 / `Resolved` 1 on T1 —
   and `CONSTANT` on another copy of the same data, **one row apart**. A skewed enum returns
   *few* rows, not zero. Never treat "heavily skewed" as "constant".
2. ⛔ **A CONSTANT column that is only SELECTed is fine.** Warn only when the query
   **predicates, joins or groups** on it. ⚠️ And a filter with **no literal** —
   `WHERE is_deleted IS NOT TRUE` — is correct on a False-only column: it matches every live
   row. The gate exempts it, because a warning that fires on idiomatic SQL teaches you to
   ignore the one that matters.
3. ⛔ **Name the value.** *"only ever `False`"* is actionable; *"low cardinality"* is not.

#### ⚠️ Never cache a shape verdict, and never let it block

A shape is a property of a **dataset at a moment**, not of the schema — it flips between
`CONSTANT` and `ENUM` on one row. So the gate **re-measures every run** and **exits 0 even with
warnings**: a non-zero exit would let one tenant's data fail another tenant's SQL, which is the
tenant-decides-a-platform-question failure this whole discipline removes. Reachability gates;
shape informs.

#### What to do with a warning

⛔ **It is a fact about the data, not a column error — do NOT invent a column.** Either:

- drop the predicate and **say in the 🟡 gap sentence** that the filter is a no-op on this
  tenant's data, or
- state plainly that the question cannot be answered as asked, because the column has never
  held the value being asked for.

### 5a-bis. ⭐ Check the SHAPE OF THE RESULT — is a join multiplying rows?

```bash
python "$SKILL_DIR/scripts/reachability_gate.py" fanout --file /tmp/candidate.sql
```

⛔ **Reachability and shape both pass on the query this catches.** Measured 2026-08-18: SQL
joining `entity_edges` on `edge_type = 'contains'` (image→**package**) where the intent needed
`'deployed_as'` (image→**service**). Every token legitimate — real columns, a real edge type,
correct casing, passed EXPLAIN. It reported **19,450** KEV exposures where there are **24**,
and populated a column named `deployed_image` with Debian package names.

⭐ **No gate can catch that by reading the SQL.** But the SHAPE gives it away: a relation over
a 6,063-row table returning 19,450 rows has fanned out, whatever the reason. Verified live:

| SQL | verdict |
|---|---|
| `edge_type = 'contains'` (the bug) | ⚠️ **8.25x over `vulnerabilities`** — flagged |
| `edge_type = 'deployed_as'` (correct) | ✅ 0.98x — silent |

⚠️ **The denominator is the `FROM` table, not the biggest table.** Neither `min` nor `max` over
all sources separates these: the bug is 3.21x over `vulnerabilities` but 0.14x over
`entity_edges`, while a legitimately edge-driven query is 23.26x over `vulnerabilities`. Only
the relation the query **iterates** gives the right answer.

⚠️ **WARNING, never a refusal.** Some relations legitimately multiply — one finding across N
deployed services is a documented grain. If the fan-out is intended, **say so in the 🟡 gap
sentence**; if not, check the join keys and the `edge_type` filter. Results under 100 rows are
not judged: a ratio off a handful of rows is noise.

⛔ **Same rule as the platform** (threshold 3.0, 100-row floor, `FROM`-table denominator), so
the harness and this skill flag the same SQL. `test_gate.py` pins the constants against the
platform's copy when a checkout is present.

### 5b. ⭐ Emit the INTENT — this skill is a PRODUCER, not only a consumer

⚠️ **This skill turns an ask into a query and currently discards the ask.** SQL → English is
lossy: it cannot recover the choice that made the SQL *a choice among alternatives*
([`ARTIFACT_INTENT_SPEC.md`](../../../pantheon-datalake/docs/ARTIFACT_INTENT_SPEC.md) § 3).
⛔ **Unbackfillable** — every query emitted without one is permanent hand-work later.

So emit the five-part intent **alongside** the SQL, every time:

| part | what it pins |
|---|---|
| `question` | the ask in the user's own words |
| `grain` | ⛔ **one row per WHAT** — the highest-value field and the cheapest to check |
| `semantics` | every domain term a generator would otherwise guess (*what is "critical"?*) — ⚠️ name the **concept and its rule**, never a column |
| `scope` | time window, soft-delete handling, row limits |
| `fallback` | what to do when a concept cannot bind — ⛔ without it a degraded regeneration is indistinguishable from a healthy one |

⛔ **The test** (§ 2 of that spec): *could two competent generators, given only this text and
the current schema, produce queries that disagree on a row count?* If yes, it is a
**description**, not an intent.

✅ **Follow the corpus, do not invent a format** — `grain` is **49/49** populated there and
`intent_description` **41/49**, averaging ~470 chars. That is the proven shape.

⛔ **CHECK IT — do not self-assess.** Documenting this contract without enforcing it is exactly
how it stayed unmet: it was written here on 2026-08-09 and nothing verified a single intent.
Write the five parts, each key at the start of its own line, **after** the prose, then run:

```bash
TORANA_PROFILE=<profile> torana datalake check-intent --file intent.txt --artifact-type widget
```

Exit `0` = conforming · `1` = still a description, with the missing parts named · `2` = the
check could not run (⛔ **not** a pass — say so rather than proceeding).

⚠️ The rule lives in `pantheon_shared.datalake.artifact_intent`, reached over the CLI, because
**a skill may not import platform code** (`skills/CLAUDE.md`) and a vendored copy would drift
from the validator every other producer uses. One rule, four producers.

⛔ **Two failures the checker catches that self-review does not:** `semantics` that names a
COLUMN rather than a concept (the binding must stay free to change — that is the point of
regenerating), and an intent block placed **above** the prose, which silently donates the whole
paragraph to `fallback`. The block goes **last**.

Store `generated_against` with it — the gate emits it under that key. It is the **shape
signature** the SQL was written against, and it covers ⛔ **candidate columns, not only
referenced ones**: a column the SQL did *not* use because it was empty is exactly the one whose
becoming populated should trigger a regeneration.

### 5c. ⛔ Emit the EVIDENCE RECORD — a script says what happened, not you

```bash
python "$SKILL_DIR/scripts/reachability_gate.py" evidence \
  --question "<the question, VERBATIM>" \
  --file /tmp/candidate.sql \
  --question-id "<from step 0; omit when UNRESOLVED>" \
  --catalog-verdict reuse|miss --catalog-axis "<axis, on a miss>" \
  --catalog-entry-id "<the entry REUSED, or the near-miss anchor on a miss>" \
  --catalog-gap-category "<wrong_grain|missing_column|... on a miss>" \
  --submit \
  --edge-type "<if you joined entity_edges>"
```

⭐ **`--submit` is what makes the verdict COUNT.** Without it the record is printed and
nothing else — the platform's curation queue never learns the catalog was consulted.
Measured 2026-08-26: running `evidence --catalog-verdict reuse` without it left the
platform's decision count unchanged at 225, which is why the reuse counter read **0** while
callers were reusing entries. ⚠️ The record now carries a `catalog.submission` block; if it
says `"server_agreed": false`, the platform did **not** record your reuse — report that,
do not assume it landed.

⛔ **Paste the JSON it prints. Do not write your own.** A model writing `✅ corpus checked` is
a CLAIM, not evidence — that is the whole reason this is a script. The record has **no
free-text field** to narrate into, deliberately.

⚠️ **Two fields carry the weight:**

| Field | Why |
|---|---|
| `joins.probed` | must be **`false`** — edge direction is served by `query-hints` now, so a `true` means something read tenant rows to learn a join's shape |
| `corpus.recorded_as_demand` | an UNRESOLVED question is still recorded. A miss is an entry in the owed-a-corpus-entry queue, **not a failure** |

⚠️ Layers you could not substantiate print `# unrecorded layers: …` to stderr. That is honest:
a record with four of six layers is evidence for four and **silence** for two — never "67%".

⚠️ **`scripts/authoring_evidence.py` is a deliberate duplicate** of the build harness's copy.
A skill may not import platform code ([`../CLAUDE.md`](../CLAUDE.md)), and both paths must emit
the same keys — so the shape is bundled and `test_gate.py` pins the two against each other.
⛔ Change one and you must change both; the test fails if they drift.

### 6. Attach provenance — and report the two things it tells you

```bash
python "$SKILL_DIR/scripts/reachability_gate.py" check --file /tmp/candidate.sql --json
```

Take **`sql_provenance` verbatim** and store it with the query.

⛔ **Do not author any of its fields yourself.** If you find yourself typing a `bridge_id`,
stop — you are inventing provenance, and an invented `bridge_id` that names no registry entry
makes the whole record unfalsifiable.

The block answers a question the ✅/🟡/❌ verdict cannot: *if this returns nothing, is that a
data state or a missing actor?*

#### ⛔ The two things you MUST report to the user

**1. Caller-dependent columns — but ONLY the `caller_only` ones.**

Read `summary.caller_dependent` (and the per-column `caller_only` flag). If it is non-zero:

> *"This query is answerable, but `vulnerabilities.is_confirmed` fills only when an analyst
> records a triage decision — an empty result means nobody has run it, not that there is
> nothing to find."*

⛔ **Say this ONLY for columns where `caller_only` is true** — i.e. **ALL** of the column's
writers are `declared`. A column that *also* has a mapping writer is filled by a sync too, and
telling the user it "fills only when X runs" is **simply false**. It is the kind of false that
sends someone to configure a thing that was never the problem.

⚠️ `self_filling` and `caller_only` are **not** opposites of one convenient flag — they are
computed differently on purpose: `self_filling` = **ANY** writer fills itself; `caller_only` =
**ALL** writers are `declared`. `cve_id` has seven writers, one of them declared; it is
self-filling and must never be described as caller-dependent.

**2. `execution.ok: false` means the query is NOT deliverable — whatever the verdict says.**

A ✅ CLEAN query that does not run is still broken. § 1.1 exists because a clean verdict was
mistaken for a working query.

⚠️ **But `ok: true` with `row_count: 0` is NOT a defect.** Cross-reference
`summary.caller_dependent` first: if any column is caller-dependent, an empty result is
*expected* and the provenance already says why. Do not report it as a failure, and do not
reroute the question.

⭐ **Say WHICH KIND of empty it is — read `fill_mode`, and quote `empty_result_means`.**
`caller_dependent` says only *that* a caller is involved; `fill_mode` says whether anything
will ever run it without a human, which is the difference the user actually acts on:

| `fill_mode` | tell the user |
|---|---|
| `self_filling` | ✅ the pipeline fills this unattended — **empty is a real answer** |
| `wired` | an automated caller exists — empty means "not exercised yet" |
| ⚠️ `manual` | ⛔ **"nobody has recorded one"** — a person must run the verb first. **Never** let this read as "there are none" |
| ⛔ `none` | permanently empty until someone builds the caller |

⛔ **Do NOT use `has_caller` (or `no_caller` alone) for this.** It answers "can this fill at
all?" — it is `true` for `manual` and `wired` alike, so on a corpus where every bridge is
built it separates nothing. Measured 2026-08-10: 47 of 49 answerable corpus rows were
caller-dependent with `no_caller` = 0, of which **36 needed a person**.

#### Two more fields worth reading

| field | what a non-zero value means |
|---|---|
| `summary.load_bearing_unreachable` | ⛔ the query **computes an answer** from a column nothing writes — not a missing display field, but a filter or `CASE` arm silently changing which rows come back |
| `summary.no_caller` | ⚠️ a caller-dependent column whose caller **does not exist yet**. The column answers with silence, forever, until someone builds one. |

⛔ **For an arbitrary column, a whole SQL file, or an integration's blast radius, use
`torana-supply-graph`** — that skill owns diagnosis. This one reports provenance for **SQL it
authors** and points there rather than explaining it. One resolver, two entry points.

### 7. Optionally run it — as a smoke test, never as the authority

⚠️ **Templated SQL will not execute as written** — `{{…}}` is not SQL. To run it, take the
BOUND text the gate already produced: `check --json` returns it as the `rendered` field, with
conservative defaults applied. That is also exactly what an unconfigured tenant would get.

⚠️ **The schema decides what is answerable. A query result never overrides it.**

| Signal | Proves | Does **NOT** prove |
|---|---|---|
| **0 rows** | this tenant has no such data **today** | ⛔ nothing about reachability — the pipeline may exist and not have run, or the integration is not connected |
| **rows returned** | the column holds data **here** | ⛔ that the SQL answers the intended question |
| **a result that contradicts the query's own stated logic** | ✅ **a defect in YOUR SQL** — join direction, `CASE` ordering, NULL handling | ⛔ nothing about reachability — **fix the SQL, never reroute the question** |

⚠️ **An empty result must NEVER cause you to reroute, substitute a column, or downgrade to
outcome 3.** That is tenant data deciding a platform question — the exact overfitting this
discipline exists to eliminate. One tenant's empty table is not evidence about the schema.

⚠️ **The inverse is equally wrong**: rows coming back is not validation. A query joining the
wrong way returns plenty of rows and answers the wrong question.

✅ **But the third row is a reason TO run it.** The gate checks columns, not logic — it will
pass a query whose `CASE` branches are ordered wrong or whose join drops half the fleet. **A
distribution piled into one bucket is a smell worth reading**: a real case put 97% of assets
in `unknown`, including assets with four actionable findings, because the `unknown` branch was
tested first. The gate passed it; only running it exposed the bug. **The fix is always in your
SQL, never in the question.**

**Report an empty result as a fact about the tenant** — *"reachable, but this tenant has no
rows; the integration may not be connected or synced"* — and leave the SQL alone. Keep that
separation and run it: the tenant-vs-schema discipline is about *not rerouting the question*,
not about avoiding the check.

---

⭐ **The gate now checks this FOR you.** `value_domain` rides on the same
`reachable-columns` payload the gate already fetches, so `check` reports a guessed literal
without a second command:

```
🔤 VALUE DOMAIN — a literal this column may never hold:
   ⛔ vulnerabilities.severity IN ['critical','high','medium','low','info'] OMITS ['Unknown']
      from a CLOSED domain — those rows are dropped SILENTLY.
```

⚠️ A **bound** policy set (`severity = ANY({{severity_floor.at_or_above}})`) is exempt — the
binder's omission is a tenant decision, not a guess. Only unbound literals are judged.
⭐ The platform harness runs the same check off the same payload, so a skill-authored and a
harness-authored query get the same verdict.

⛔ **REACHABLE IS NOT ENOUGH — CHECK THE VALUES.** A column can be perfectly reachable and
still make your SQL return nothing, because you guessed its values. `severity` is
Title-Case and `Unknown` is real; a filter naming `('Critical','High','Medium','Low','Info')`
looks exhaustive and silently drops 4,104 rows. Measured: `required_scan_types` offered
`container` while ingest wrote `container_image_scan` — **0 of 86,696** rows matched, and it
deployed green.

| `--value-domains` reads | Means | So |
|---|---|---|
| `[closed]` | the vocabulary is complete | an `IN` list may enumerate it |
| `[open]` | more spellings can appear | ⛔ do NOT write an exhaustive `IN` |
| `not yet described` | ⚠️ nobody described it — NOT "anything allowed" | verify before assuming |

## ⚠️ Cost — what this discipline actually charges you

Delegating every VM build step to this skill multiplies its per-call fetches by the step count,
so the per-step figure matters. Measured 2026-08-20 against a live stack:

| Step | Cost |
|---|---:|
| `check` (reachability + policy + provenance) | **<1s** — ⭐ ONE `reachable-columns` round-trip supplies system columns, policy-derived and writers |
| `shape` | ~1s |
| `evidence` | <1s |
| `fanout` | ~1s (two bounded `COUNT`s, capped) |
| **all four** | **~3s per authored artifact** |

⭐ **Against a build step that takes 60–240s, that is noise.** The fan-out probe alone was
measured at ~1.4s to catch a 19,450-row defect that would otherwise have deployed green.

⚠️ **The one thing that would make it expensive is re-fetching per column.**
`establish_ground_truth` makes exactly **one** reachability call and derives four inputs from
it. ⛔ If you find yourself calling `fetch` in a loop, stop — fetch once and reuse the map.

## Calibration — check yourself against the corpus

`pantheon-datalake/torana_datalake/corpus/question_reachable_sql.csv` is a 93-row test set with an answer
key. Replay the gate against it:

```bash
python "$SKILL_DIR/scripts/corpus_check.py" \
  --csv $TORANA_ROOT/pantheon-datalake/torana_datalake/corpus/question_reachable_sql.csv \
  --column original_sql
```

⚠️ **If the skill starts "answering" most of the blocked questions, be suspicious and audit the
substitutions.** A high answer rate is the failure mode here, not the success. The honest
result on the current schema is that most of the blocked set stays blocked, because the facts
they need are written by nothing.

The corpus run also reports the tenant-neutrality counters — `templated rows`,
`hardcoded-policy`, `vocabulary keys used`.

⚠️ **The bar is not "move the numbers."** Run `check-corpus`: `hardcoded-policy` findings should
be **zero, or each one waived with a stated reason**. A regeneration that leaves policy literals
unexplained has ignored this section — however much the counters moved.

⚠️ **Policy-literal confidence is the signal.** The checker is heuristic and its author puts
`medium`/`low` at roughly 30–50% false positive. Treat `high` as probably real and
`medium`/`low` as **candidates needing judgement** — a synthesized output label and a
definitional window both trip it. Waive with `-- policy-literal-ok: <reason>`, never silently.

### Scope note — `{{vocab:` is reported as an error, and that is correct *here*

`reachability_gate.py` flags any `{{vocab:…}}` placeholder unconditionally. **That is right for
this skill**, whose entire scope is catalog/corpus SQL bound by `vm_catalog/binder.py`, where
the prefix is genuinely unresolvable and would reach EXPLAIN.

It would be **wrong** if this gate were ever pointed at app-template artifacts, which are
rendered by `vm_content/vocab_render.py` and for which `{{vocab:…}}` is the *only* correct
form. The gate has no mode for that today. **Do not "fix" this by relaxing the check** — if
artifact SQL ever needs gating, it needs a distinct renderer path, not a weakened rule here.

---

## Anti-patterns

| ⛔ Don't | ✅ Do |
|---|---|
| Paste a schema listing into a prompt or this file | Fetch it every run |
| Author against `--scope tenant` | Author against `--scope platform` |
| Treat `is_deleted` / `tenant_id` as unreachable | Take the system-field list from the API |
| Let a checker keep answering when ground truth is missing | Refuse with exit 2 and a named cause — a confident wrong verdict is worse than a crash |
| Drop an unreachable WHERE predicate to make SQL run | Refuse (outcome 3) — dropping it changes the row set silently |
| Swap in an adjacent column that "looks close" | State the semantic difference and let the user choose |
| Predict that a rewrite is clean | Re-parse the final text |
| Rewrite SQL because it returned 0 rows | Report the empty result as a tenant fact |
| Trust `SUPPLIED` + 100% populated as "usable in a predicate" | Run step 5a — a CONSTANT column passes both |
| Treat a heavily-skewed ENUM as CONSTANT | Warn only on `shape == constant`; a skewed enum returns few rows, not zero |
| Cache a shape verdict, or let one block the SQL | Re-measure every run; reachability gates, shape informs |
| Re-implement `values ⊃ shape ⊃ fill` locally | Ask for the deepest depth; the server resolves it |
| Emit SQL and discard the ask | Emit the five-part intent (step 5b) — it is unbackfillable |
| Emit SQL for an unanswerable question | Name the missing column and say nothing writes it |
| Hardcode `severity IN ('Critical','High')` | Bind `{{severity_floor.at_or_above}}` |
| Read `vulnerability_due_date` / `_sla_breach_date` | Compute from `{{sla_window_by_severity[…]}}` + the row's anchor |
| Emit `{{vocab:…}}` in corpus SQL | Emit the bare binder form |
| Guess a render verb | Look it up in the contract — 15 of 48 keys take none |
| Template every literal | Apply the three-way test; keep definitional ones |
| Let `CASE … ELSE 'none'` hide an unreachable column | Return `'unknown'` and name the column |
| Author SQL without probing the definition store, or probe the retiring `catalog list` | Probe `catalog search` first — reuse beats authoring (step 0b) |
| Probe ONCE, on the user's phrasing alone | Probe twice — verbatim, then a schema-register grain rewrite. A transformer that exists is regularly invisible to the user's own words (step 0b) |
| Append a fixed block of security vocabulary to the query to "improve recall" | Rewrite the user's SUBJECT. A canned hint matches on recall and destroys the ability to MISS — "office supply spend" then returns 10 confident security candidates (step 0b) |
| Record your rewrite as the miss | Record the user's VERBATIM need — the queue is demand, not paraphrase (step 0b) |
| Retune `--top-k` / `--threshold` | Leave the defaults — raising hides candidates, lowering stops a real gap being recorded |
| Infer "nothing matched" from an empty result, and file a gap | Decide from the CALL's exit code; if it did not run, record **nothing** |
| Read a missing `projects:` line as "projects nothing" | Judge on grain — the list is UNKNOWN, not empty |
| Block the answer because the store has a gap | Record the miss, then author anyway |
| Record a **miss** for a question you reused, or record one twice | One gap, one row — carry the verdict to 5c and let its wire record it |
| Assume a submitted verdict landed | Read `catalog.submission`; report `server_agreed: false` |
| Check the store, then fall back to the schema | Judge both TOGETHER — sequence reuses what is merely *close* |
| `FROM` a definition that is not materialized here | Offer it as *"covered but not built — ask for it"* |
| Answer with only the SQL | State all five summary items, near-misses named with axes |

---

## Maintaining this file

**Rules and fetch commands, not measurements.** A number earns its place only if it is a fact
about a contract (48 keys), an instruction to act (15 keys take no verb), a description of a
file (93-row corpus), or the historical evidence for a rule (197 vs 145). **A snapshot of
current state does not** — however well labelled. The moment a number here needs a disclaimer,
delete it rather than hedge it, and point at the command that fetches the live value.
