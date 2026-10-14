# Presenting results

In the platform chat UI, returned rows become charts automatically. In Claude Code nothing
does — the presentation is part of your answer.

---

## Order — always

1. **The finding.** First sentence is the answer: the number, the ranking, the yes/no + why.
2. **The data** that supports it.
3. **Caveats** — one line each: measure used, join coverage, truncation, assumed scope.
4. **Follow-ups** the data raised (optional, 1–3).
5. **The SQL** — every query whose numbers appear above, each with a one-line purpose.

⛔ Never open with the SQL or with "I queried the X table…".

## Choosing the form

| Result shape | Show as |
|---|---|
| a single number or yes/no | a sentence — no table |
| ≤ ~20 rows, categorical | markdown table, sorted by the measure, with a share-% column when parts sum to a whole |
| > ~20 rows | aggregate further or show the top slice + "N more"; never dump |
| a time series, or a distribution worth seeing | a chart — load the `dataviz` skill first; for anything the user will share or revisit, publish it as an Artifact |
| a comparison across two dimensions | a pivot table (rows × columns) rather than a long list |

⭐ **A chart is worth it when the SHAPE is the answer** (a trend, a spike, a long tail). When
the answer is one number, a chart is decoration.

## Tables

- Right-align numbers; thousands separators (`15,149`); round percentages to 1 dp.
- Label the measure in the header (`findings`, `distinct CVEs`), not `count`.
- Include the `Unknown` / `NULL` bucket — hiding it overstates coverage.
- If `limited: true`, say "showing N of `total_rows`".

## Caveats worth a line

- **Tenant:** name the tenant when more than one is configured.
- **Measure:** "counting findings — 1 CVE on 50 images counts 50 times".
- **Join coverage:** "<joined> of <total> criticals matched an asset; the rest are in *Unknown*".
- **Freshness:** the table's `latest_update` from `datalake summary` if the question is about "now".
- **Assumption:** "'recent' = last 30 days; say if you meant 7".

## Numbers

Quote only numbers a query returned or the platform printed. Never add, subtract or count rows yourself: a
count is a `COUNT(*)` query (ask `torana-text-to-sql` for it) or the platform's own total. A figure you must
derive (a difference, a share) is labelled **derived**, with its inputs beside it. A percentage no query or
platform line produced is not yours to give.

## SQL block

````markdown
<details><summary>Queries</summary>

```sql
-- why: criticals by asset environment (measure: vulnerability_finding)
SELECT …
```
</details>
````

Use `<details>` only where it renders; in a terminal, a plain fenced block at the end is fine.
