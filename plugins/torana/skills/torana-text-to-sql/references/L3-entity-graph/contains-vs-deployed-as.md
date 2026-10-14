---
id: contains-vs-deployed-as
title: 'Two edge types from the same image — pick the right one, and count what you mean'
shape: graph
outcome: sql
tables: [entity_edges]
illustrates: [edge:contains, edge:deployed_as, namespace:pkg]
needs: [graph]
---
**Question:** How many distinct packages are running in deployed services?

**Why it isn't obvious:** Both `contains` (`image: → pkg:`) and `deployed_as`
(`image: → service:`) start at an image. Joining the wrong one gives real-looking rows about
the wrong thing, and joining through `contains` multiplies rows — one package sits in many
images, and one image can back many services — so `count(*)` after the join counts pairs,
not packages. Filter `edge_type` on every edge alias and count the distinct key you mean.

**Tables:** `entity_edges`, twice: `contains` for the packages, `deployed_as` to keep only
images that are running.

```sql
-- MEASURE: one row per package (distinct pkg: key), not per image-package pair.
SELECT count(DISTINCT c.to_key) AS running_packages
FROM entity_edges c
WHERE c.edge_type = 'contains'
  AND c.is_deleted IS NOT TRUE
  AND EXISTS (
        SELECT 1
        FROM entity_edges d
        WHERE d.edge_type = 'deployed_as'
          AND d.is_deleted IS NOT TRUE
          AND d.from_key = c.from_key)
```

**Answer:** Give the distinct package count and say it counts packages, not package copies.
If the caller wants copies, that is `count(*)` over the same filter — a different number.
