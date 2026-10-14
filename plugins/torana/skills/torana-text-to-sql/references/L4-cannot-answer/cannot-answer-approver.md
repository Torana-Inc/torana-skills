---
id: cannot-answer-approver
title: 'When no column records the fact, say so — never substitute a neighbouring column'
shape: cannot-answer
outcome: no_sql
tables: [vulnerabilities]
illustrates: [field:VULNERABILITIES.IS_RISK_ACCEPTED, field:VULNERABILITIES.BUSINESS_JUSTIFICATION]
needs: [meaning, reach]
---
**Question:** Who approved the risk acceptance on our open findings?

**Why it isn't obvious:** The schema records THAT a finding was risk-accepted
(`is_risk_accepted`), WHY (`business_justification`) and until when
(`risk_acceptance_expires_at`) — but no column records WHO approved it. `assigned_to` is the
owner of the work and `updated_by` is whoever last wrote the row; either one would produce a
confident list of names that answers a different question.

**Tables:** none can answer it. `vulnerabilities` carries the acceptance, not the approver.

**Answer:** No SQL. Say: "No column records who approved a risk acceptance —
`vulnerabilities` holds the acceptance flag and its justification, not the approver. It would
need a new field on the triage workflow." Then offer the answerable neighbour as a separate
question: the risk-accepted findings with their justification and expiry.

⚠️ Note what the neighbour costs. `business_justification` and `risk_acceptance_expires_at`
both come back `NEEDS_CALLER` — *"filled when `torana vulnerability triage` runs. We do not
track when it last ran."* So the fallback query can return zero rows, and zero means nobody has
triaged rather than nothing is risk-accepted. Say which, using the verdict `supply sql-columns` prints.
