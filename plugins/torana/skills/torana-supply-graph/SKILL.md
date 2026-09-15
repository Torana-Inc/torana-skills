---
name: torana-supply-graph
description: >-
  Answer "why is this column/panel/query empty for this tenant?" and "what breaks if we
  disconnect this integration?" by walking the Torana Supply Graph. Diagnoses a column, a
  whole SQL file, or an integration, and turns "no data" into ONE of a fixed set of
  verdicts, each with a different owner and a different customer-facing message — Torana
  never collects it, a caller must run, connect a category of tool, your tool does not
  report this field, a collector is off, a sync is failing, or it is supplied and an empty
  result is OUR bug. Trigger whenever the user asks why a widget/dashboard/panel is empty,
  why a column has no data, why a query returns nothing, what they need to connect to see
  something, what connecting a given tool would be worth, whether a gap is ours or the
  customer's, what breaks if they lose an integration, what their blast radius is, which
  integration is a single point of failure, or whether a tool is earning its keep. ALSO use
  before trusting a zero-row result from any datalake query — a 0-row answer whose cause is
  unknown is not an answer.
version: "2.0"
last_updated: "2026-08-07"
platform_version_tested: "2026.1"
---

# Supply Graph — why is this empty, and what breaks if it goes away

> *"No data"* is not one condition. It is at least seven, each with a **different owner** and
> a **different correct thing to say**. This skill tells them apart.

---

## ⛔ Read this before changing anything here — the traversal is NOT in this skill

`SUPPLY_GRAPH_SPEC.md` § 3.4.0 decides the traversal is implemented **once, server-side**, in
`pantheon-datalake`:

```
GET /api/v1/datalake/supply/diagnosis?columns=t.c,t.c
GET /api/v1/datalake/supply/forward?integration=<name>
```

✅ **That API is live, and this skill CALLS it.** Every verdict here is resolved
server-side; the skill computes none. [`scripts/supply_graph.py`](scripts/supply_graph.py)
is a thin client behind a two-method interface (`diagnose()` / `forward()`).

⚠️ **It was not always.** This skill shipped first as a validation prototype holding a full
second copy of the § 3.4.1 verdict table — the cheapest place to prove the verdicts were
right, because an engineer sees a bad verdict in a terminal and a customer sees it in a
widget. ⛔ The two copies never disagreed, but **nothing would have failed when they did**:
both kept answering, confidently, and a divergence reaches a customer as two different
answers about the same column. The migration the module always specified is now done and
`LocalTraversal` is deleted.

⛔ **Do not re-add a decision tree, a mapping-path parser, or a category lookup here.**
Shipping a second copy of the verdict logic is the exact drift disease the spec exists to
prevent — and it has already been removed from this file once.

---

## Core concept — the graph, and why it is derived rather than stored

The edge is **"supplies"**. Read backward it answers *what fills this*; forward, *what
depends on this*.

```
category ◀──belongs_to── data_source
integration ──enables──▶ data_source ──rendered_by──▶ mapping ──writes──▶ column
     caller ──calls──▶ endpoint ──declared_writes──▶ column
   decoration/operator/ingestor/extractor/system ──writes──▶ column
     column ──read_by──▶ query ──renders──▶ widget
```

⛔ **Derived on read, never materialized.** Every edge already exists in code that is
authoritative by construction — the mapping tree, the write-seam registry, the bridge
registry, live integration state. Copying them into a table creates a fourth artifact that
drifts from three.

⚠️ **`category` hangs off `data_source`, not off `integration`.** This is not a detail. An
integration carries a category *set* — GCP is a `cloud_provider` that also ships a scanner.
Rolled up per integration, `cve_id` resolves to 7 categories including `identity_provider`,
which produces *"connect an identity provider to see CVEs"*. Per data source it is
`security_scanner` + `code_scanner`.

---

## ✅ The profile trap — RESOLVED

✅ **The two-profile trap is GONE — one tenant profile is now enough.**

| call | profile | why |
|---|---|---|
| `torana datalake supply …` | **`T1`** (tenant) | resolves BOTH halves server-side |

⚠️ **What used to be true, and why it mattered.** The skill fetched the category map itself,
and that endpoint is ⛔ **super-admin only** — a tenant profile is refused outright. So an
operator holding only a tenant profile lost `CATEGORY_MISSING` and `PEER_GAP` entirely and
had to opt into a degraded run.

⛔ The server resolves the category half with a tenant-scoped **service** JWT (§ 3.4.0), so
a caller who could never resolve it alone now gets it. ⚠️ That is a *substantive* reason for
the resolver to be server-side, not merely a tidier one — verified by running these scripts
with a deliberately bogus `--sa-profile` and getting a correct `CATEGORY_MISSING`.

`--sa-profile` and `--allow-degraded` are still accepted so existing invocations keep
working; they no longer do anything.

**Degraded mode is now the SERVER's call, and it is still loud.** If the server cannot
reach the category layer it reports `category_layer: "unavailable"`, the
category-dependent verdicts collapse to `UNRESOLVED` (rank-less, non-customer-facing), and
the scripts print a warning.

⛔ **It never emits a vendor name because a category lookup failed.** That would be the
§ 3.4.6 error with extra confidence behind it.

---

## The verdicts

⛔ **`SUPPLY_GRAPH_SPEC.md` § 3.4.1 is the ONE canonical table** — verdict name,
customer-facing?, rank, and message template. **Do not restate it here or anywhere else.**
It was previously restated in five places with three different counts and drifted within a
single review round.

What you need to know operationally:

- The **decision tree** (§ 3.4.1.1) is **ordered and total** — first match wins, every column
  reaches exactly one verdict. It evaluates over the writer **set**, not one writer, because
  a column commonly has several writers in different states (`cve_id` has 7).
- **`SUPPLIED` outranks everything.** If any path is live and healthy the data should be
  arriving and the other paths are irrelevant.
- Two verdicts — `UNRESOLVED` and `LINEAGE_AMBIGUOUS` — are **deliberately not
  customer-facing**. They mean *we could not trace this*, which is our problem. Render the
  neutral empty state and emit telemetry; **never** an incident message.
- **Per-query aggregation** is worst-wins by `rank`, naming at most 3 columns, load-bearing
  first, and **never more than one verdict class** — a panel showing three different
  explanations teaches the reader nothing.

⛔ **`rank` and customer-facing-ness are CARRIED ON EACH VERDICT from the server** — this
skill holds no copy of the table. Adding a verdict is a one-place edit, in the resolver.
`supply_graph.verdict_vocabulary()` fetches the whole table on demand
(`torana datalake supply verdicts`) for the rare caller that needs to reason about a
verdict it has not been handed.

---

## ⛔ A 0-row result is NOT evidence of a supply problem

The single most dangerous assumption in this area. A query returns 0 rows for a completely
healthy reason: **the filters matched nothing.** *"Critical vulns opened today: 0"* is good
news.

| per-query verdict | what to render on 0 rows |
|---|---|
| `SUPPLIED` (all columns) | ⛔ **nothing**, or a neutral *"No matching records."* **Never** an incident message. |
| any non-`SUPPLIED` verdict | the aggregated message |

⚠️ And when a genuinely `SUPPLIED` column is empty, that is **our bug** — escalate it. Telling
a customer to check their scanner when the defect is ours is the trust loss, inverted.

---

## Phrasing — category vs vendor, and it is not cosmetic

⚠️ **"Always use categories" is the WRONG rule.** Category language is right only when we are
**guessing** what the customer owns. When their own configuration tells us, naming the vendor
is more useful — refusing to is evasive.

| situation | phrasing | example |
|---|---|---|
| nothing relevant connected | ⛔ **category** | *"To populate this, connect a source-code scanner."* |
| peer tool present, doesn't emit this field | **both** | *"Your vulnerability scanner does not report this; tools such as Tenable do."* |
| writer connected but misconfigured / failing | ✅ **vendor by name** | *"Tenable is connected, but its host-detections collector is off."* |

**The five hard rules** (§ 3.4.5), enforced in [`scripts/render.py`](scripts/render.py):

1. ⛔ **Never emit an internal term** — no *"bridge"*, no `BRIDGE-*` id, no *"declared
   writer"*, no *"write seam"*, no *"reachability"*. Say what to do.
2. Never blame the customer for a `SUPPLIED` verdict.
3. ⛔ **Never guess a trigger.** Say *who* fills a `NEEDS_CALLER` column, never *when* — the
   `trigger` field does not exist yet. An invented *"this fills after each scan"* that turns
   out false costs more trust than the empty panel did.
4. Choose category vs vendor by what we already know (above).
5. Distinguish *"no data yet"* from *"cannot ever"* — different verdicts, different owners.

⚠️ When naming peer examples, cap at 2–3 and never imply they are the only options: the
writer list is what Torana supports today, not the market.

---

## How to use it

⚠️ Activate the venv first — the scripts call the `torana` CLI, and the SQL mode needs
`sqlglot`: `source $TORANA_ROOT/.venv/bin/activate`

### Fastest path for a WIDGET — ask the platform, do not re-derive

```bash
TORANA_PROFILE=T2 torana widgets verdict <widget-id>
```

⭐ **Start here when the subject is a widget.** The platform now resolves an empty widget to
one of four verdicts server-side, each naming a DIFFERENT owner:

| verdict | means | owner |
|---|---|---|
| `blocked` | a shipped integration can write this; none the tenant connected does | tenant connects a tool |
| `empty` | everything connected, sync healthy, genuinely 0 rows | nobody — a true zero |
| `stale` | connected, but the sync is failing | tenant, or our bug |
| `live` | rows returned | — |

⚠️ **`unknown` is a real answer, not a failure.** The endpoint never claims `live` without a
measured row count — an honest "I could not tell" beats a confident wrong verdict.

Use the column-level diagnosis below when you need to know **WHICH column** is at fault, or
when the subject is a SQL file rather than a widget. The two agree by construction: the
verdict reads the same reachability report `diagnose_column.py` does.

### Backward — "why is this column empty?"

```bash
python scripts/diagnose_column.py vulnerabilities.cve_id assets.vm_scan_enabled
python scripts/diagnose_column.py --format json vulnerabilities.is_confirmed
```

Prints, per column: the verdict, **what to say to the user**, and an internal note that is
⛔ **for engineers only** (it names bridges and callers).

### Whole SQL file — "why is this panel empty?"

```bash
python scripts/diagnose_sql.py widget.sql
cat widget.sql | python scripts/diagnose_sql.py -
```

Parses every column reference, diagnoses each, and aggregates per § 3.4.2. `load_bearing`
comes from **sqlglot's parse tree**, never a guess: a reference is load-bearing when an
ancestor is a filter (`WHERE`/`JOIN`/`HAVING`/`QUALIFY`), sets the grain (`GROUP BY` /
`PARTITION BY`), or computes a value acted upon (`CASE`/`FILTER`/func). A bare
`ORDER BY t.x` is presentation-only and falls out as `false` naturally.

⚠️ Bind vocabulary placeholders (`{{actionable_status_set}}`) before parsing.

### Forward — "what breaks if we lose this?"

```bash
python scripts/forward_walk.py gcp          # blast radius of a connected integration
python scripts/forward_walk.py tenable      # what connecting it would light up
python scripts/forward_walk.py --all        # rank every integration
```

⛔ **Read the SOLE-writer number, not the total.** `cve_id` has seven writers; losing one
changes nothing. Reporting *"Tenable writes 115 columns"* overstates its blast radius by more
than 2×. **Sole-written is what actually goes dark.**

### Acceptance

```bash
python scripts/acceptance.py
```

Reproduces every § 3.13 / § 3.14 row measured on T1. Verdicts and sole-writer counts are
**asserted**; total-write counts are **drift-reported**, because the mapping tree moves (the
reachable column count moved 384→389→395→397 within one day — which is why every result
stamps the count it was resolved against).

---

## Interpreting a result

| verdict | who owns it | what to do |
|---|---|---|
| `UNREACHABLE` | ⛔ **us** | Say so plainly. No customer action helps. |
| `NEEDS_CALLER` | the named caller | Name **who**, never **when**. Check `status`: `none` means no caller exists *and never will until one is built*. |
| `DOCUMENT_ONLY` | the customer | An upload, not a connectable tool. *"Connect a []"* must never render. |
| `CATEGORY_MISSING` | the customer | Name the **category**, never a vendor. |
| `PEER_GAP` | the customer | Category **plus** 2–3 examples. The most actionable verdict. |
| `SOURCE_DISABLED` / `SYNC_FAILING` | the customer | Name the **vendor** — reading their own config back. Minutes to fix. |
| `SUPPLIED` | ⛔ **us**, if empty | Render nothing. If the column really is empty, escalate. |
| `UNRESOLVED` / `LINEAGE_AMBIGUOUS` | ⛔ **us** | Neutral empty state + telemetry. Never a customer message. |

---

## Known limits — report them, do not work around them

- ⛔ **Transformer-backed tables return `UNRESOLVED`.** Flagship widgets read
  `reachable_exploitable_risk`, `account_hygiene_summary` and friends — **not** the 11 sink
  tables. The writer map makes no claim about those, so the honest verdict is *"we cannot
  trace this"*, which is rank-less and non-customer-facing. The transformer hop (**P8**)
  fixes it by resolving widget columns through author-time lineage back to sink columns.
  ⚠️ Reporting this is correct behaviour; do not paper over it.
- **`SOURCE_DISABLED` and `SYNC_FAILING` have no T1 instance today** — every connected
  integration has all its data sources enabled and reports `last_sync_status: success`.
  That is a healthy state, not a broken walk. `acceptance.py` asserts their *absence*, so
  the day one appears it is visible rather than silent.
- **No trigger hop.** For a `NEEDS_CALLER` column the walk stops at *"an external caller
  must run"*. It cannot say which agent, fired by what event.
- **Out of scope here:** the transformer hop (P8) and the runtime widget diagnosis (P9)
  are the server's, not this skill's. ✅ The server-side API (P6) is live and is what this
  skill now calls.

---

## ⛔ Portability

Per [`skills/CLAUDE.md`](../CLAUDE.md): **no `pantheon-*` checkout, no imports of platform
code.** Everything arrives over the `torana` CLI. A skill that reads the mapping tree off
disk works for its author and fails — *confidently, on stdout* — for an operator against
production.

Corollaries honoured here:

- `sys.path` inserts are **self-relative** (`__file__`-based), which is a skill bundling its
  own code, not reaching outward.
- `--format json` emits **only JSON on stdout**; every diagnostic goes to stderr.
- The scripts run **directly** (`python scripts/<name>.py`) so the skill works before
  registration.
- Constants that the platform owns — the 7 system columns, the 11 sink tables, which
  categories have a model — are read **from the payload**, never hand-listed here, because a
  restated list drifts.

<!-- CHANGELOG
v1.0 (2026-08-06) - Phase 0 validation prototype. Client-side traversal behind the
                    diagnose()/forward() interface, to be swapped for the § 3.4.0
                    server-side API at P6.
v2.0 (2026-08-07) - MIGRATED to the server-side resolver (§ 4.5 "one resolver" bar).
                    LocalTraversal, _parse_mapping and the local VERDICT_RANK deleted;
                    ApiTraversal wired to `torana datalake supply`. The SA-profile
                    requirement is gone — the server resolves the category half with a
                    service JWT, so one tenant profile now suffices.
-->
