# Worked examples — what they are for, and the one rule for writing them

These teach what the schema cannot say. A column's type, its value domain and its writer are
all served by `torana datalake schema-ddl`; what no schema can tell you is that a question has
two honest answers, that a declared join does not connect, that `!=` never matches NULL, or
that an empty column means nobody ran a workflow rather than that nothing happened.

Each file is one example: a question, why the obvious SQL is wrong, the SQL, and what to say
when giving the answer.

## The rule: teach a trap, never restate a measurement

A **trap** is structural. It is true next year, on every tenant, at every deployment:

- `!=` never matches NULL, so excluding a value with `!=` drops every NULL row.
- A declared JOIN KEY is a declaration, not a working join — read its measured trust.
- A column only a workflow fills is empty until someone runs the workflow.
- A materialised policy date was computed under whatever policy was in force at the time.
- "How many vulnerabilities" can mean findings or distinct CVEs.

A **measurement** is a number from one tenant at one moment:

- "9,426 rows are Unknown"
- "this join is NORELY at 100%"
- "reading the column reports 445 breached, computing reports 0"

Measurements go stale silently. The example keeps parsing, keeps passing every reference
check, keeps running — and teaches something that stopped being true. That is the exact
failure this whole skill exists to prevent, so reintroducing it in the teaching material is
worse than leaving the lesson out.

**Write the instruction to measure, not the measurement.** `norely-join-say-so` is the model:
it says *"quote the join's trust verdict and orphan rate from the DDL"* rather than naming a
rate. It was written before the trust on that join changed, and it is still correct today
because it never asserted the value.

When a number genuinely helps, give the reader the query that produces it rather than the
answer — `compute-sla-dont-read-it` says to compare `min(vulnerability_due_date)` against
`min(scan_first_detected_date)`, which demonstrates the drift on any tenant without baking in
a figure from one.

## Front matter

```yaml
---
id: matches-the-file-name
title: 'One line — the lesson, not the question'
shape: count | breakdown | ranking | trend | graph | partial | cannot-answer
outcome: sql | sql_with_gap | no_sql
tables: [the tables the SQL actually reads]
illustrates: [field:TABLE.COLUMN, measure:name, namespace:image]
needs: [the schema-ddl layers this example assumes were fetched]
---
```

`needs:` is a contract with the reader: fetch those layers and the example's reasoning is
visible in the DDL. Keep it honest — if the lesson turns on a value domain, say `domains`.

YAML gotchas: quote a `title` that starts with a quote, and write `namespace:image`, never
`namespace:image:` (a trailing colon makes it a mapping, not a string).

## Adding or replacing one

Drop the file in, rebuild the skill zip, reinstall. There is no service to restart and no
wheel to rebuild — that is deliberate. These are the highest-churn artefact in the skill,
replaced whenever a new data pattern turns up, so the change path is the lightest one
available.

⚠️ There is no automated validation. Nothing checks that `illustrates:` still resolves or that
the SQL still runs, so the rule above is the whole defence. Before adding one, ask whether it
teaches something structural — if the lesson is a number, it does not belong here.
