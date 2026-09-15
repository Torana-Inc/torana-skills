-- EM-025  Ownership verdict per asset + its open finding count.
-- POLICY BOUND: the staleness window is the tenant's SLA window keyed by the
-- asset's own criticality (key-map form — this key has NO legal verbs), and the
-- open-work status set.
-- 'missing_team'/'stale_mapping'/'verified' are SYNTHESIZED OUTPUT LABELS, not
-- status filters — deliberately left literal.
SELECT a.torana_entity_id, a.asset_name, a.asset_type, a.asset_environment,
       a.asset_owner, a.asset_owner_email, a.asset_team, a.governance_source,
       a.asset_last_seen_at,
       CASE
         WHEN a.asset_team IS NULL OR a.asset_team = '' THEN 'missing_team'
         WHEN a.asset_owner IS NULL OR a.asset_owner = '' THEN 'missing_owner'
         WHEN a.asset_status = 'Decommissioned'
           OR a.asset_last_seen_at < NOW() - ({{sla_window_by_severity[a.criticality_name]}})::int * INTERVAL '1 day'
           THEN 'stale_mapping'
         WHEN a.governance_source IS NULL OR a.governance_source = '' THEN 'unattributed'
         ELSE 'verified'
       END AS ownership_status,
       v.open_findings
FROM assets a
LEFT JOIN (
  SELECT vv.torana_entity_id, COUNT(*) AS open_findings
  FROM vulnerabilities vv
  WHERE vv.is_deleted IS NOT TRUE AND vv.is_false_positive IS NOT TRUE
    AND vv.is_suppressed IS NOT TRUE
    AND vv.vulnerability_status = ANY({{actionable_status_set}})
  GROUP BY 1
) v ON v.torana_entity_id = a.torana_entity_id
WHERE a.is_deleted IS NOT TRUE
ORDER BY (ownership_status = 'verified'), v.open_findings DESC NULLS LAST
