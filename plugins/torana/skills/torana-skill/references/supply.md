# Supply — why a column is empty, and whose problem it is

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap first.**

---

## ⛔ Never trust a 0-row result until supply says why

An empty query result is **not** an answer, and it is **not** a reason to change the SQL.
"No rows" has several causes with completely different owners and completely different
customer-facing messages:

| Verdict | What it means | Who fixes it |
|---|---|---|
| Torana never collects it | no pipeline exists anywhere | platform engineering |
| A caller must run | the collector exists but nothing invoked it | operations |
| Connect a category of tool | no tool of that kind is integrated | the customer |
| Your tool does not report this field | the tool is connected but does not supply it | the customer's vendor |
| A collector is off / a sync is failing | connected, but broken right now | operations |
| Supplied — and the result is still empty | **our bug** | us |

Rewriting a query because one tenant returned nothing is overfitting to that tenant. It is
how a query comes to answer a different question everywhere else.

⚠️ **The inverse is equally wrong:** rows coming back is not validation. A query joining the
wrong way returns plenty of rows and answers the wrong question.

## Commands

```bash
"$TORANA" datalake supply --help                 # the reference standard for CLI help — read it
"$TORANA" datalake supply integrations           # what can I ask about?
"$TORANA" datalake supply columns --scope platform   # what columns exist, and are they lit?
"$TORANA" datalake supply verdicts               # what does each answer MEAN, and who fixes it?
"$TORANA" datalake supply column vulnerabilities.cvss4_base_score
"$TORANA" datalake supply integration tenable    # what breaks if this goes away?
"$TORANA" datalake supply questions              # which questions can't be answered, and why?
```

Bare `datalake supply` prints help and exits 0 — deliberately, so a reader with no column
name in hand gets the map instead of a rejection.

### One command for a tenant's whole supply picture

`supply columns` answers all of it in one shot — how many columns that tenant can reach, the
verdict breakdown, and **which mechanism writes them**:

⭐ **`--scope tenant` resolves the tenant from `TORANA_PROFILE`** — no id needed, and this
is the form to reach for. `--tenant-id` is for a SUPER-ADMIN reading a tenant it is not; a
tenant profile that passes it gets a 403 naming its own tenant.

```bash
# ⭐ THE USUAL FORM — the profile IS the tenant.
TORANA_PROFILE=T1 "$TORANA" datalake supply columns --scope tenant

# SUPER-ADMIN reading someone else's estate. Rarely needed — set the profile instead
# where you can.
TORANA_PROFILE=SA "$TORANA" datalake supply columns --scope tenant --tenant-id <uuid>

"$TORANA" datalake supply columns --scope platform --group-by writer_kind   # mechanism table
"$TORANA" datalake supply columns --scope platform --table vulnerabilities  # per-column rows
"$TORANA" datalake supply columns --scope platform --writer-kind extractor  # one mechanism
"$TORANA" datalake supply columns --scope platform --dark   # reachable but unlit
"$TORANA" datalake supply columns --scope platform --unreachable  # nothing writes these
```

⭐ **`--export` SHOWS *and* exports** — it adds the two-sheet `.xlsx`, it never replaces the
terminal output. `supply export` is the export-only form.

```bash
"$TORANA" datalake supply columns --scope tenant --tenant-id <uuid> --export   # server's name
"$TORANA" datalake supply columns --scope tenant --tenant-id <uuid> --export t2.xlsx
"$TORANA" datalake supply export --scope tenant --tenant-id <uuid>   # export only
```

The workbook has two sheets with **different grains, deliberately**: `Columns` (one row per
column, ~446) and `Writers` (one row per column × writer, ~1,636), joined on Table+Column.
⚠️ Writers fan out hard — `assets.torana_entity_id` has 38 writers across 19 integrations —
so one flattened sheet would inflate every count ~4×.

### ⛔ Two numbers, and they are not the same number

`supply columns` under a tenant lens prints **both**, because reading either as the other is
the mistake this whole surface exists to prevent:

```
314 of 441 columns are reachable for THIS tenant; 251 are lit, 63 are dark.
(441 is the PLATFORM figure — what Torana ships a writer for.)
```

| figure | question | changes per tenant? |
|---|---|---|
| **441** | could ANY Torana pipeline write it? | no — platform fact |
| **314** | can THIS tenant actually get it? | **yes** — depends what is connected |

The mechanism table splits on the same axis, `EXISTS` vs `HERE`:

```
                   EXISTS   HERE
ETL mapping           380    235    arrives when that integration syncs
API seam               96     96    ⚠️ fills only on an external call — no sync ever will
Ingestor               24     13    filled by a bulk ingest path
Decoration             17     17    joined at read time — not stored on the row
Platform stamp         11     11    stamped by the platform on every row
Push route              3      3    filled when an operator or service pushes to the API
Extractor               2      0    filled by an extractor pipeline
```

⚠️ Only **ETL mapping / ingestor / extractor** are gated on what the tenant connected. The
other four are platform paths that are always on — which is why their two columns match. A
gap in `HERE` is a **connection to make**, never a build defect.

⛔ **THE MECHANISM ROWS DO NOT SUM TO THE TOTAL, and the command says so.** On T2 they add to
533 against 441, because a column with several mechanisms appears under each — measured, 55
T2 columns have more than one writer kind (`assets.asset_owner` has three). Never quote the
sum as coverage; the distinct count is the coverage figure.

## Can a deployed artifact return anything? — the FOUR answers

Diagnoses a **deployed** rule / transformer / widget, or a whole app, by id. The SQL is
fetched server-side, so the answer is about what is RUNNING, not about a pasted copy.

```bash
# One artifact — kind is rule | transformer | widget
TORANA_PROFILE=T1 "$TORANA" datalake supply artifact widget <ARTIFACT-ID>

# Every artifact in an app, in one pass — the acceptance check BEFORE deploying
TORANA_PROFILE=T1 "$TORANA" datalake supply workspace <WORKSPACE-ID>
TORANA_PROFILE=T1 "$TORANA" datalake supply workspace <WORKSPACE-ID> --only-broken
```

⛔ **Four `answerable` states, and two of them produce zero rows for OPPOSITE reasons.**
Telling those apart is most of what this is for: a rule that can never fire looks exactly
like a well-configured rule on a quiet week.

| `answerable` | CLI mark | Means | Who fixes it |
|---|:--:|---|---|
| `quiet_estate` | `✓` | everything supplied; nothing matches today | nobody — healthy |
| `degraded_fields` | `~` | an unsupplied column is READ but does not filter rows, so it **still returns its rows** — only those fields read empty or zero | same owner as a block; only the consequence differs |
| `permanently_unanswerable` | `✗` | an unsupplied column sits in a WHERE — it returns **nothing**, permanently | whoever `owner` names |
| `undetermined` | `?` | we could not read the query or trace its columns | never a green light we did not earn |

⚠️ **`--only-broken` lists `permanently_unanswerable` ONLY.** A `degraded_fields` artifact
is degraded, not broken, and is deliberately excluded — it is working.

⚠️ **The `summary` carries a key for EVERY state and always sums to `artifact_count`.** If
the text output prints a "state this CLI does not know how to name" line, the server has a
newer state than the CLI: read `summary` from `--format json` for the full breakdown.

⛔ **`degraded_fields` is not a softer `permanently_unanswerable`.** Reporting a widget that
returns rows as "cannot return anything on this account" is a confidently wrong answer about
something visibly working, and a reader who sees a full table under that sentence stops
trusting every other verdict on the page. Measured on a live estate 2026-10-02: two widgets
that returned 1 and 2 rows were reported as returning nothing.

## Related

- **Before authoring SQL** — `references/datalake.md` (`reachable` ≠ `populated`, two scopes)
- **Checking SQL you already have** — `"$TORANA" datalake supply sql-columns --file <f>` diagnoses
  every column the SQL reads, without needing a repo checkout

## Fastest path for a WIDGET — ask the platform

```bash
"$TORANA" widgets verdict <WIDGET-ID>     # tenant-scoped: why is THIS widget empty
"$TORANA" admin verdicts                  # SA fleet: which tenants are blocked, and on what
```

The platform resolves an empty widget to one of four verdicts server-side, each naming a
**different owner** — which a silent zero cannot:

| verdict | means | owner |
|---|---|---|
| `blocked` | a shipped integration can write this; none the tenant connected does | tenant connects a tool |
| `empty` | connected, sync healthy, genuinely 0 rows | nobody — a true zero |
| `stale` | connected, but the sync is failing | tenant, or our bug |
| `live` | rows returned | — |

⚠️ **`unknown` is a real answer.** The endpoint never claims `live` without a measured row
count — an honest "could not tell" beats a confident wrong verdict.

⛔ **Read `admin verdicts` carefully.** When it reports `NOT MEASURED`, the zeros are
placeholders, not findings. "0 blocked" read as good news, when nothing was measured, is
exactly the misdirection that line exists to prevent.

## Naming the gap — `NEEDS_CALLER` is not "no data"

When you report why something cannot be built or returns nothing, name the gap the verdict
actually shows:

| `supply column` verdict | What is missing | Who acts |
|---|---|---|
| `UNREACHABLE` / `PEER_GAP` | a writer — nothing can EVER fill the column | platform (a mapping or a schema change) |
| ⭐ `NEEDS_CALLER` | nothing: the writer exists and is wired, **it has never been invoked** | whoever runs the tool |

⚠️ Reporting a caller gap as "no data" or as a join problem sends someone to build a mapping
or fix a join when the real work item is "run the tool".
