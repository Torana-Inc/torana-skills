# SQL rules for analysis — PostgreSQL datalake — a READING checklist

⛔ **This skill does not write SQL** — `torana-text-to-sql` does (SKILL.md § 1). These rules are
the checklist for READING the SQL it returns: use them to spot a defect (wrong grain, a join
the wrong way, an unguarded denominator) and describe that defect back to `torana-text-to-sql`.
Never to rewrite the query yourself.

Folded from the platform's Security Data Analyst V2 prompt.

---

## Columns and tables

- **Use only columns you fetched** with `datalake schema-ddl --tables <t> [--columns …]`. ⛔ Never pattern-match a name from another table or from memory.
- If a needed column does not exist, **say so** and list the closest real ones. A false
  "not found" is fixable; a fabricated column is a silent wrong answer.
- **Transformer tables** (MTTR, SLA, priority scores …) live in the same tenant schema — use
  the bare name. ⛔ Never assume one exists; only `schema transformers` proves it.
- ⛔ `workspace_id`, `program_id`, `program_name`, `workspace_name` are routing context, not
  datalake columns. Never put them in a `WHERE`.

## Joins

- **Join only on the `JOIN KEY` lines the DDL declares.** A table with none has no join —
  query it alone; never invent a foreign key.
- **Read `join-health` before trusting a join-based number:**

  | Verdict | Means for your answer |
  |---|---|
  | `RELY` | fine |
  | `DEGRADED` | some rows silently drop — report the coverage |
  | `NORELY` | an empty/low result is **not** evidence of absence — say so |
  | `UNMEASURED` | unknown — never read as "fine"; measure coverage yourself |

- **Enrichment joins are `LEFT JOIN` + `COALESCE(dim, 'Unknown')`**, and report coverage:
  `COUNT(*) AS total, COUNT(a.<pk>) AS joined`.
- **Fan-out:** a join to a many-side (`entity_edges`, packages → images) multiplies rows. If
  the count after a join exceeds the count before, you are counting the join, not the thing.
  Use `COUNT(DISTINCT <key>)` or aggregate before joining.

## Grain and measures

- Read the table's primary key from the DDL. Single-column key → one row per entity. Composite
  pk → several rows per entity; aggregate if the question wants fewer dimensions.
- The DDL's `measures` layer lists **measures** — named ways to count a table, each with a grain and an
  `empty:` note saying which rows it drops. Pick one deliberately; put `-- measure: <name>`
  in the SQL; say it in the answer.
- Transformer tables are usually pre-aggregated — check the grain before adding `GROUP BY`.

## Strings and values

- `'single quotes'` are strings, `"double quotes"` are identifiers. `col = "High"` looks for
  a column named `High`.
- **Casing is not guessable.** Either confirm it (`SELECT DISTINCT` / `--value-domains`) and
  match exactly, or match case-insensitively: `LOWER(severity) = 'critical'`,
  `GROUP BY LOWER(severity)`.
- `[closed]` domain → an `IN` list may enumerate it. `[open]` or `not yet described` → don't
  write an "exhaustive" `IN`; look at the data.
- Fuzzy topic search: `ILIKE '%<topic>%'` on the text columns. There is no semantic search
  in this path.

## Filtering and soft deletes

- Sink tables keep soft-deleted rows: add `is_deleted IS NOT TRUE` (not `= false` — NULL).
- `WHERE` for row filters; `HAVING` only for aggregate filters.

## Math

- `x / NULLIF(y, 0)` — always.
- `ROUND(<expr>::numeric, 2)` on every computed value.
- Percentages: `ROUND(100.0 * a / NULLIF(b, 0), 1)`.
- Median: `PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY col)` — cast to `numeric` before `ROUND`.

## PostgreSQL dialect

| ✅ Use | ⛔ Never (other dialects — syntax error here) |
|---|---|
| `NOW() - INTERVAL '7 days'` | `DATEADD()`, `DATEDIFF()`, `GETDATE()` |
| `CURRENT_TIMESTAMP`, `CURRENT_DATE` (no parens) | `CURRENT_TIMESTAMP()` |
| `DATE_TRUNC('week', ts)` | `strftime()` |
| `EXTRACT(EPOCH FROM (b - a)) / 86400` for days | `MEDIAN()` |
| `IS TRUE` / `IS NOT TRUE`, `\|\|` for concat | |

## Question → shape

Starting shapes, **not** SQL. Confirm every column against the schema you fetched.

| The user asks | Shape |
|---|---|
| "X by severity" | `GROUP BY severity` on `vulnerabilities`, `ORDER BY count DESC` |
| "open vs resolved" | `GROUP BY vulnerability_status` — check its values first |
| "criticals by environment / criticality" | `vulnerabilities v LEFT JOIN assets a` on the declared key, `GROUP BY COALESCE(a.<dim>,'Unknown')`, report joined count. ⚠️ First check `<dim>` is filled for the entity kinds the vulns sit on (images often carry no environment); else route via repository or `entity_edges` |
| "top N repos / packages / assets" | `GROUP BY` the entity, `ORDER BY count DESC LIMIT N` |
| "trend / over time" | `DATE_TRUNC('<period>', <ts>)` + `GROUP BY 1 ORDER BY 1` — pick the timestamp that means "when it happened", say which |
| "what changed recently" | filter an `updated`/`detected` timestamp by a window; ask the window only if "recent" is ambiguous |
| "MTTR / SLA / average age" | an existing transformer table if one holds it (check grain); else compute with `AVG(EXTRACT(EPOCH …))`, `ROUND`, `NULLIF` |
| "find X about <topic>" | `WHERE title ILIKE '%topic%' OR description ILIKE '%topic%'` |
| "anything odd in <table>?" | profile it: row count, NULL share of key columns, top values of categorical columns, min/max of timestamps — then drill into what stands out |
