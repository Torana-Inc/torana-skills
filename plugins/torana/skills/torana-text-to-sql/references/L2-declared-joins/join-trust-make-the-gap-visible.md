---
id: join-trust-make-the-gap-visible
title: 'A declared join is not a working join — count what it drops'
level: L2
shape: count
outcome: sql
tables: [vulnerabilities, packages]
illustrates: [field:VULNERABILITIES.TORANA_PACKAGE_ID]
needs: [trust]
---
**Question:** How many findings are on a package we know about?

**The trap:** every `JOIN KEY` line in the DDL is a *declaration*. Whether the rows
actually match is measured per tenant, and the `trust` layer prints the rate:

```
JOIN KEY (torana_package_id) -> packages (torana_package_id)
  -- [many_to_one] ⚠ DEGRADED 2.8% orphaned
```

An inner join here silently discards those orphans. The result is smaller, correctly shaped,
and wrong — with no error anywhere.

**The move:** LEFT JOIN, then count the unmatched rows as their own column. The gap becomes a
number in the answer instead of an absence from it.

```sql
-- MEASURE: one row per SCA finding; the unmatched ones are reported, not dropped.
SELECT count(*)                                        AS findings,
       count(*) FILTER (WHERE p.torana_package_id IS NULL) AS no_package_record
FROM vulnerabilities v
LEFT JOIN packages p
       ON p.torana_package_id = v.torana_package_id
      AND p.is_deleted IS NOT TRUE
WHERE v.is_deleted IS NOT TRUE
  AND v.torana_package_id IS NOT NULL
```

**Answer:** give both numbers and the trust verdict from the DDL. "14,985 of 15,410, because
2.8% of findings reference a package with no record" is an answer; "14,985" alone is a claim
the data does not support.

⚠️ **Every predicate on the right-hand table belongs in `ON`, never in `WHERE`.** A `WHERE`
condition on a LEFT-joined table is false for the unmatched rows — their columns are NULL —
so it discards exactly the rows the LEFT JOIN was there to keep. The join silently becomes an
inner join and the gap disappears rather than being reported.

Measured on one tenant, the same query with one predicate moved:

| predicate in | rows | unmatched reported |
|---|---:|---:|
| `ON` | 15,410 | 13,819 |
| `WHERE` | 1,591 | **0** |

Neither form errors. The second looks like a clean result.
