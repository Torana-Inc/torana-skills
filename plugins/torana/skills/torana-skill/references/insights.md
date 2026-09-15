---
name: insights
description: >
  Skill for working with the Torana Insights platform — covering data transformers
  (SQL metric pipelines via dbt), visualization (widget and dashboard rendering,
  entity relationship graphs), and RAG (document ingestion and semantic search).
  Supports create/read/execute/delete workflows across all three sub-services.
version: "2.0"
last_updated: "2026-04-16"
platform_version_tested: "2026.1"
---

# Insights — Torana Platform (CLI)

The Insights capability spans three microservices that together take raw security data through
to actionable knowledge:

- **Data Transformers** — SQL transformation pipelines powered by dbt. Turn raw datalake tables into pre-computed metric tables.
- **Visualization** — Widget and dashboard rendering. Execute detection-framework queries and format results for charts, tables, and graphs. Includes entity relationship graph visualization.
- **RAG** — Document ingestion and semantic search. Upload documents, parse and embed them into Qdrant, then query with natural language.

All operations go through the `torana` CLI — no curl, no raw API calls.

---

## Bootstrap — Install & Authenticate

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap — the canonical
one.** It is not repeated here on purpose: a copied block drifts from the original, and a
stale bootstrap makes real commands look missing (the exact wrong conclusion the surface
check exists to prevent). Every command on this page assumes `"$TORANA"` is set by it.

---

## Core Concepts

### The Three Pillars

**Transform** — Raw security data (assets, vulnerabilities, findings, identities, repositories) lives in the datalake (DuckDB in dev, Snowflake in prod). Transformers apply SQL logic via dbt to produce persistent destination tables containing derived metrics — MTTR, SLA compliance percentages, coverage ratios, etc.

**Visualize** — Widgets are configuration objects managed by the detection-framework service. Each widget references a query ID and a widget type. The viz service executes the query against the datalake and formats the result rows for the specified visualization type. Dashboards are collections of widgets rendered in parallel.

**Query** — Documents (PDFs, Word docs, Markdown, text files) are uploaded to the RAG service. The service parses, chunks, embeds, and stores vectors in Qdrant. Users then issue natural language queries; the service embeds the query and retrieves semantically similar chunks ranked by score.

---

## States and Lifecycle

### Transformer States

| Field | Values | Meaning |
|-------|--------|---------|
| `is_active` | `true` / `false` | Whether the transformer is enabled for scheduled runs |
| Execution `status` | `running` | dbt is executing right now |
| Execution `status` | `success` | dbt completed successfully; destination table is up to date |
| Execution `status` | `failed` | dbt failed; check `error_message` and `dbt_output` fields |

A transformer always exists independently of its executions. Deleting a transformer drops its dbt model file, its destination table, and all execution history.

### Before you edit or delete one: who uses it?

`torana datalake transformers list` carries two columns that answer this.

| Column | Source | Reads |
|---|---|---|
| `USED BY (APPS)` | program-framework `build_v2_artifacts` | The app(s) whose deploy created it |
| `REFS` | data-transformers `vm_transformer_materialization` | Reference count, **shared catalog relations only** |

⛔ **`—` is not `0`.** `REFS` shows `—` when the transformer is not a refcounted shared
relation at all — the common case. A `0` would assert "nothing references this", which for a
private transformer is false and is exactly the claim someone would act on before deleting it.

⚠️ **The two columns can legitimately DISAGREE, and neither is derived from the other.** A
shared relation's own `workspace_id` is the sentinel `vm-catalog`, so data-transformers can
only COUNT its consumers, never name them. The refcount also drifts (it has climbed across
repeated deploys without a matching release). **`REFS 5` beside one named app is a leaked
reference — that gap is the finding, not a rendering bug.**

### Document States (RAG)

| `status` | Meaning |
|----------|---------|
| `pending` | Queued for processing |
| `processing` | Currently being parsed, chunked, and embedded |
| `indexed` | Fully available for semantic search in Qdrant |
| `failed` | Processing failed; check `error_message` |

Documents cannot be queried until they reach `indexed` state.

### Collection States (RAG)

| `status` | Meaning |
|----------|---------|
| `active` | Accepting documents and queryable |
| `archived` | Read-only; no new documents |
| `deprecated` | Marked for removal |

---

## How It Works

### Transformer Flow

1. Choose a **template** (pre-built SQL for common metrics) or write **custom SQL**.
2. Create the transformer with `sql_template` or `custom_sql` and a `destination_table` name.
3. The service stores the transformer definition in PostgreSQL and generates a dbt `.sql` model file.
4. Execute the transformer (returns immediately, runs async by default).
5. In the background: dbt attaches the tenant's DuckDB file via the `attach_source_database()` macro, creates source views via `create_source_views()`, then compiles and runs the SQL.
6. The execution record is updated to `success` or `failed`.
7. The destination table is now queryable by visualization widgets or detection-framework rules.

**Async vs sync execution**: By default, execute returns immediately. Add `--sync` to block until completion and receive final status in the response.

### Widget Rendering Flow

1. Widgets are defined in the detection-framework service (not in viz). Each widget has a `widget_type` and references a query.
2. Rendering retrieves the widget configuration from detection-framework, executes the underlying SQL query against the datalake, and formats the result.
3. Widget types and their data shapes:
   - `table` — `columns: [str]`, `rows: [[any]]`, `total_rows: int`
   - `pie` — `labels: [str]`, `datasets: [{label, data: [num]}]`
   - `bar` — `labels: [str]`, `datasets: [{label, data: [num]}]`
   - `line` — `labels: [str]`, `datasets: [{label, data: [num]}]`
   - `scalar` — `value`, `formatted_value`, `label`, optional `trend_direction`, `trend_percent`, `color`
4. Dashboard rendering runs all widgets in parallel. Individual widget failures do not fail the whole dashboard — failed widgets carry `status: error` with an `error_message`.

### Graph Visualization Flow

1. **Overview** — queries all entity tables and returns the full entity relationship graph as `nodes` and `edges`.
2. **Entity-centered** — starts from a specific entity and expands outward for N hops (1-3). Use `hops=1` for immediate relationships, `hops=2` or `hops=3` for blast radius analysis.
3. **Search** — full-text search across entity names and properties, returns matching nodes.
4. **Alert graph** — fetches an alert from the detection-framework, extracts referenced entity IDs from the alert results, and builds a graph of those entities and their relationships.

Valid entity types: `assets`, `identities`, `vulnerabilities`, `findings`, `datastores`, `repositories`, `artifacts`.

### RAG Flow

1. Create a **collection** to group related documents.
2. Upload a document (multipart form with file, title, collection_name, etc.).
3. The service saves the file, parses it (PDF, DOCX, MD, TXT, HTML are supported), splits into chunks (~512 tokens with 100-token overlap), generates embeddings via the configured model, and stores vectors in Qdrant.
4. Poll document status until `status == "indexed"`.
5. Query with a natural language query string. The service embeds the query, searches Qdrant for similar vectors, applies tenant/namespace isolation, and returns ranked `SearchResult` objects with `score`, `text`, `document_title`, `section_title`, and optional `highlight`.

---

## Multi-Tenant Considerations

All three services enforce IAM isolation. Resources are scoped by `tenant_id` and `namespace_id` derived from the JWT. You cannot see or operate on another tenant's data.

**Data Transformers**: Each tenant has their own DuckDB file. Transformer executions set `TENANT_ID` in the dbt subprocess environment so macros attach the correct file.

**Visualization**: The datalake client receives `iam_context` on every query. Queries automatically filter by the tenant's data scope.

**RAG (Collections)**: Qdrant collection names are namespaced as `{tenant_id[:8]}_{namespace_id[:6]}_{name}`. All Qdrant searches include a `tenant_id` + `namespace_id` payload filter.

---

## Troubleshooting Guide

### Transformer execution fails immediately

Check the execution record and look at `error_message` and `dbt_output`. Common causes:

- **Invalid SQL syntax**: The SQL passed custom validation but dbt found a compile error. Review the `dbt_output.result` field for the dbt error message.
- **Source table does not exist**: The macro `create_source_views()` only creates views for tables that exist in the tenant's DuckDB. If you reference `{{ source('torana', 'vulnerabilities') }}` but the tenant has no vulnerabilities data, the view won't exist and dbt will fail with a missing relation error.
- **Tenant DuckDB file missing**: The tenant has never ingested data. Check that datalake ingest has run for this tenant.
- **Template parameter missing**: Use sql-templates get to see the required parameters schema before creating.

### Widget renders with status NO_DATA

The query returned zero rows. This is not an error — it means the underlying detection-framework query produced no results from the datalake. Verify that:

1. The transformer that populates the widget's source table has run successfully.
2. The transformer's destination table actually has rows.
3. The detection-framework query is using the correct table name.

### Document stuck in "processing" status

Processing is synchronous within the upload request — if it fails mid-way, the document may be left in `processing`. Check the `error_message` field on the document. Common causes:

- **Unsupported file format**: Only `.pdf`, `.docx`, `.md`, `.txt`, `.html` are supported.
- **File too large**: Max file size is 50 MB by default. Split large documents.
- **Qdrant unreachable**: The embedding store is unavailable. Check Qdrant service health.
- **Embedding model error**: The configured embedding model returned an error (e.g., API key issues). Check service logs.

### RAG search returns irrelevant results

- **Score too low**: Results with `score < 0.5` are typically not semantically relevant. Set `min_score: 0.6` or higher in the query.
- **Wrong collection**: Specify `collection_name` in the query to restrict search to the intended collection.
- **Documents not indexed**: If documents were recently uploaded, check that all have `status == "indexed"` before querying.
- **Query too vague**: Short or ambiguous queries produce poor embeddings. Use 10+ word, specific queries.

### Graph shows entities but no relationships (edges)

Edges are derived from foreign key relationships between entity tables. If the entities were ingested independently without matching IDs, no edges will form. Verify that the datalake ingest process populated cross-reference fields correctly. Use `hops=1` to start.

---

## Best Practices

1. **Use templates when available.** Templates like `mttr_calculator` and `sla_compliance` encode correct percentile math and time window logic.

2. **Always materialize transformer outputs for downstream consumption.** Set `materialized: true` (the default). Non-materialized transformers produce ephemeral views that are not stored.

3. **Organize RAG documents into collections by topic or program.** Collections let you restrict searches to a relevant subset.

4. **Limit graph hops to 2 for interactive queries.** `hops=3` can return thousands of nodes for highly connected entities and is slow.

5. **Monitor transformer execution times.** Long-running transformers (>60s) indicate the underlying SQL is scanning too much data.

6. **Set `min_score` in RAG queries.** Without a minimum score threshold, Qdrant returns the top-k results regardless of relevance.

7. **Use `--sync` for agent workflows.** When an agent needs the transformer result immediately, the synchronous variant blocks until dbt finishes and returns the final status.

8. **Check the template search before writing custom SQL.** The template search performs semantic search over template descriptions.

---

## Discovering Commands

Use plural to list, then singular + `--help` to discover instance commands:

```bash
"$TORANA" dashboards list               # get IDs
"$TORANA" dashboard <id> --help         # see all commands for that dashboard
"$TORANA" widgets list                  # get IDs
"$TORANA" widget <id> --help            # see all commands for that widget
"$TORANA" sql-templates --help
"$TORANA" transformer-executions --help
"$TORANA" transformer-tables --help
"$TORANA" entity-graph security --help  # the entity/alert security graph
"$TORANA" rag --help
"$TORANA" rag collections --help
"$TORANA" rag collection <id> --help    # documents live under the single collection
```

> ⚠️ **There is no top-level `transformers` group.** Transformer *output tables* are
> `transformer-tables`, execution history is `transformer-executions`, tables inside the
> datalake are `datalake transformers`, and the VM catalog is `vm transformers catalog`.
> Run `--help` on the one you mean rather than guessing a plural.

## Typical Workflows

### Create and execute a transformer

```bash
# Search for an appropriate template
"$TORANA" sql-templates search --query "mean time to resolve vulnerabilities"

# Preview the SQL with your parameters
"$TORANA" sql-templates preview mttr_calculator \
  --param source_table=vulnerabilities \
  --param severity_field=severity \
  --param days=90

# Create the transformer, then execute it. Discover the exact flags first —
# there is no `create-and-execute` verb.
"$TORANA" datalake transformers --help
"$TORANA" datalake transformer <id> --help

# Check the destination table
"$TORANA" transformer-tables summary vuln_mttr_by_severity
"$TORANA" transformer-executions list          # execution history
```

### Upload a document and perform semantic search

```bash
# Create a collection
"$TORANA" rag collections create \
  --name incident_runbooks \
  --description "Security incident response runbooks"

# Upload a document (the file path is a positional argument)
"$TORANA" rag upload /path/to/ransomware_runbook.pdf \
  --title "Ransomware Response Runbook" \
  --collection incident_runbooks \
  --document-type policy

# Confirm it landed
"$TORANA" rag collection <collection-id> documents

# Search
"$TORANA" rag search \
  --collection incident_runbooks \
  --query "How do we isolate infected systems during a ransomware attack?" \
  --top-k 5
```

### Drill into a number — the rows behind one cell

```bash
"$TORANA" widget <widget-id> decompose --key team=platform-security --limit 50
"$TORANA" widget <widget-id> decompose --key severity=Critical -o json   # scriptable
"$TORANA" widget <widget-id> decompose --key team=X --cursor "<next_cursor>"
"$TORANA" widget <widget-id> decompose --key team=X --all                # walk it all
"$TORANA" widget <widget-id> decompose --key team=X --show-sql           # don't run it
"$TORANA" widget <widget-id> decompose                                   # the WHOLE widget
"$TORANA" widget <widget-id> decompose --key team=X --total              # exact row count
```

⭐ **`--key` or no `--key` are two different questions.** With a key you get the rows
behind ONE cell, reconciled against what that cell displayed. With **no key at all**
you get every record the widget covers — there is no single cell to reconcile
against, so the metrics are recomputed but not compared (`·`, never `✓`/`✗`). A
partial key set is an error, not a shortcut: it would answer a question nobody asked.

⭐ **The rows usually come from a DIFFERENT relation than the widget names.** Most
widgets read a transformer output, which is already aggregated; the `GROUP BY` lives
in the transformer's own SQL. `decompose` crosses that one hop and reports where it
landed in `decomposed_via.source_relation`. Use the **displayed** column name in
`--key` — the alias is translated for you.

⛔ **Read the RECONCILIATION block before the rows.** It recomputes every metric over
the constituent rows and compares it to what the cell showed:

| mark | meaning |
|---|---|
| `✓` | the rows explain the number |
| `✗` | they explain a DIFFERENT number — the materialized table is STALE, not the drill-down wrong |
| `·` | nothing to compare against — the column is not drawn on this widget, or you drilled the whole widget rather than one cell |

⚠️ **Row count and metric value are different numbers.** A cell reading 218 can have
45,993 rows behind it (218 distinct CVEs across 45,993 findings). A row count alone
next to that cell reads as a bug.

⚠️ **A metric is ONE OUTPUT COLUMN, not one aggregate.** A column can wrap several
(`ROUND(100.0 * COUNT(*) FILTER (…) / NULLIF(COUNT(*), 0), 1)`); it is recomputed
whole. If you ever see the same column listed twice, that is a bug — report it.

**`--total` is opt-in** because the exact count is the expensive half of a large
drill. Without it you get the rows and `has_more`, which is enough to page.

**Paging is cursor-based.** The server ALWAYS paginates — an omitted `--limit` uses
the server default, never "all rows" (one bar click can be 27,000+ records). Take
`next_cursor` from `-o json` and pass it back as `--cursor`.

**Three honest outcomes**, all HTTP 200: rows + reconciliation; `not_aggregate`
("each row it shows is already a single record" — a real answer for a row-level
widget); or `unsupported` with a reason. A 400 means a clicked value was missing or
not valid for its column.

### Render a dashboard

```bash
"$TORANA" dashboards list
"$TORANA" dashboard <dashboard-id> render     # every widget on it, as the UI draws them
"$TORANA" widget <widget-id> render           # one widget's rows
```

### Graph visualization

```bash
"$TORANA" entity-graph security stats
"$TORANA" entity-graph security entity assets <asset-id> --hops 2
"$TORANA" entity-graph security search --query "prod-server"
"$TORANA" alert <alert-id> graph              # alert context graph
"$TORANA" alert <alert-id> entities           # just the entity summary
```

---

## Error Reference

| CLI output | Meaning | Fix |
|---|---|---|
| `Not authenticated` | No cached token | Run OAuth login (see bootstrap) |
| `Session expired` | Refresh token invalid | Re-run OAuth login |
| `403 Forbidden` | Token missing scope | Re-auth with correct account |
| `Cannot reach <url>` | Wrong base-url or network | `"$TORANA" config get base-url`; verify tunnel |

<!-- CHANGELOG
v1.0 (2026-02-28) - Initial skill creation covering data-transformers, pantheon-viz, and pantheon-rag.
v2.0 (2026-04-16) - Migrated execution mechanics to torana CLI; removed curl/tg/tp/td
-->
