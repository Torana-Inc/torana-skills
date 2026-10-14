---
id: compute-sla-dont-read-it
title: 'A materialised deadline is frozen policy — compute the SLA, never filter on it'
shape: count
outcome: sql
tables: [vulnerabilities]
illustrates: [field:VULNERABILITIES.VULNERABILITY_DUE_DATE, field:VULNERABILITIES.VULNERABILITY_SLA_BREACH_DATE]
needs: [meaning, reach]
---
**Question:** How many critical findings are past their remediation deadline?

**Why it isn't obvious:** `vulnerability_due_date` looks like exactly the column for this, and
it is real, populated and reachable — so nothing about it reads as a trap. But it is not an
observation: the `policy` decoration WROTE it, by applying whatever SLA window was configured
when the decoration last ran. Filtering on it answers "what did the platform think the deadline
was the last time policy was materialised", which is a different question and silently goes
stale the moment the tenant changes its policy — or the moment the decoration stops running.

Nothing errors when it drifts. The count stays plausible, which is what makes it dangerous.

**Tables:** `vulnerabilities`, computing the deadline from the row's own anchor
(`scan_first_detected_date`) and the tenant's SLA window.

```sql
-- MEASURE: one row per critical finding whose remediation window has elapsed,
-- computed from the row's own first-detected date — NOT read from the
-- materialised vulnerability_due_date, which is frozen policy.
-- The window differs per tenant AND per severity, so write the map plainly and
-- let `policy-template --bind` template it (see below) — do not write {{vocab:…}}.
SELECT count(*) AS overdue_critical
FROM vulnerabilities
WHERE is_deleted IS NOT TRUE
  AND severity = 'Critical'
  AND vulnerability_status NOT IN ('Fixed', 'Resolved', 'Closed', 'Suppressed')
  AND scan_first_detected_date
      + (CASE severity WHEN 'Critical' THEN 7 WHEN 'High' THEN 30
                       WHEN 'Medium' THEN 90 WHEN 'Low' THEN 180 END)
        * INTERVAL '1 day' < NOW()
```

⛔ **WRITE THE MAP, THEN LET THE BINDER TEMPLATE IT — you never type `{{vocab:…}}` yourself.**
That is the same rule as everywhere else in this skill (SKILL.md § vocabulary: templating happens
*in code*), and this page used to break it by showing a hand-written placeholder. `policy-template
--bind` recognises a severity→days map — both the `CASE` above and an inline
`'{"Critical": 7, …}'::jsonb ->> severity` — and rewrites the whole construct to
`{{vocab:vm.remediation.sla_windows.sla_window_by_severity.lookup[severity]}}`. Hand back the SQL
it prints. ⭐ Round-trip proven: the placeholder renders back to exactly this `CASE`, with the
tenant's own numbers.

⚠️ **Write the map COMPLETE — every severity the key covers (Critical, High, Medium, Low).** The
binder refuses a partial map on purpose: `CASE severity WHEN 'Critical' THEN 7 END` yields NULL
for the other bands, while the bound key yields their real windows, so templating it would change
which rows get a value.

⛔ **And never substitute a bare number for the window.** A hardcoded single window silently stops
tracking policy and nothing detects it. The map form above is not a hardcode — it is the shape the
binder reads; a lone `+ 7 * INTERVAL '1 day'` is, and the binder cannot rescue it (a loose integer
is never matched, deliberately: it would fire on any query that happens to use the same number).
The warning lead time is the key `sla_warning_lead_days`; list every key you used in the handover
so `--bind` can confirm them.

⛔ **"About to breach" is a different question from "breached", and its threshold is that key.** A
transformer's precomputed breach flag answers only the second. Measured on an agent run: a
run bucketed every non-breached open finding as "approaching breach" and said the question had
supplied no threshold — while the key held it. Never write "not available" for a value a
vocabulary key holds; the keys are the tenant's settings, not the caller's to supply.

⚠️ A severity the tenant's map does not cover renders `NULL`, so the comparison is NULL and the
row is neither in nor out. Count that band separately rather than letting it vanish.

**Answer:** Give the computed count and say which window you applied, because the number means
nothing without it. Expect it to differ from any dashboard built on `vulnerability_due_date` —
the two disagree by construction, and the gap widens the longer it is since the decoration last
ran. A quick way to show the drift without arguing about it: compare
`min(vulnerability_due_date)` against `min(scan_first_detected_date)`. If the earliest deadline
predates the earliest finding, the column is carrying a window the current data never saw.

The key renders `(CASE severity WHEN 'Critical' THEN 7 … ELSE NULL END)` from the tenant's policy.
`torana vm transformers definitions render --sql …` shows the bound text; `torana datalake query`
binds it when it runs.

⚠️ `vulnerability_sla_breach_date` is not an escape: the same decoration writes it from the same
window, so substituting it relocates the trap rather than avoiding it. Reading either column in
SELECT to *show* the materialised value is fine — it is filtering, grouping, joining or sorting
on one that makes the answer turn on stale policy.
