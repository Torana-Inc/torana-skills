---
id: name-the-measure
level: L1
title: 'A count needs a stated unit — "how many" usually has two honest answers'
shape: count
outcome: sql
tables: [vulnerabilities]
illustrates: [field:VULNERABILITIES.CVE_ID]
needs: [meaning]
---
**Question:** How many vulnerabilities do we have?

**The trap:** there is no column called "vulnerability count", and the two obvious readings
differ by an order of magnitude. One finding is one scanner result on one asset; one CVE may
appear as hundreds of findings. Both are correct answers to the English question, and a bare
number does not say which one was given.

No annotation can resolve this, because the ambiguity is in the question rather than in the
schema.

```sql
-- MEASURE: both readings, so the answer can state which one it means.
SELECT count(*)                                  AS findings,
       count(DISTINCT cve_id)                    AS distinct_cves,
       count(*) FILTER (WHERE cve_id IS NULL)     AS findings_with_no_cve
FROM vulnerabilities
WHERE is_deleted IS NOT TRUE
```

**Answer:** lead with the number that matches the intent, name the unit, and give the other
one. *"622 distinct CVEs across 15,449 findings"* answers the question; *"15,449"* invites the
reader to assume whichever they had in mind.

The third column is not decoration: findings with no `cve_id` are counted in `findings` and
invisible in `distinct_cves`, so the two numbers do not reconcile without it.

**The habit, beyond this column:** any aggregate whose unit is not obvious from the question
gets its measure named in a comment on the first line. That comment is what a reviewer reads
to check you counted the thing that was asked for.
