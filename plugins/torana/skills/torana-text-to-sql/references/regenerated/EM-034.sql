-- EM-034  SLA miss cross-cut by team x environment x severity.
-- NO VOCABULARY. Every literal here is definitional or an output label:
--   '(unassigned)'/'(unknown)' are synthesized labels for NULL grouping keys.
-- The deadline is computed from the tenant's SLA key + each row's own anchor —
-- NOT read from vulnerability_due_date / vulnerability_sla_breach_date, which
-- are the deny-listed materialised copies of a possibly-stale policy.
WITH scoped AS (
  SELECT v.torana_vulnerability_id, v.severity, v.vulnerability_resolution_date,
         v.torana_entity_id,
         v.scan_first_detected_date
           + ({{sla_window_by_severity[v.severity]}})::int * INTERVAL '1 day' AS due_at
  FROM vulnerabilities v
  WHERE v.is_deleted IS NOT TRUE AND v.is_false_positive IS NOT TRUE
    AND v.is_suppressed IS NOT TRUE
)
SELECT COALESCE(a.asset_team, '(unassigned)') AS team,
       COALESCE(a.asset_environment, '(unknown)') AS environment,
       s.severity AS risk_level,
       COUNT(*) AS total_findings,
       COUNT(*) FILTER (WHERE s.due_at IS NOT NULL
             AND (s.vulnerability_resolution_date IS NOT NULL AND s.vulnerability_resolution_date <= s.due_at
                  OR s.vulnerability_resolution_date IS NULL AND s.due_at >= NOW())) AS sla_compliant,
       COUNT(*) FILTER (WHERE s.due_at IS NOT NULL
             AND (s.vulnerability_resolution_date IS NOT NULL AND s.vulnerability_resolution_date > s.due_at
                  OR s.vulnerability_resolution_date IS NULL AND s.due_at < NOW())) AS sla_exceeded,
       COUNT(*) FILTER (WHERE s.due_at IS NULL) AS no_sla_set,
       ROUND(100.0 * COUNT(*) FILTER (WHERE s.due_at IS NOT NULL
             AND (s.vulnerability_resolution_date IS NOT NULL AND s.vulnerability_resolution_date > s.due_at
                  OR s.vulnerability_resolution_date IS NULL AND s.due_at < NOW()))
             / NULLIF(COUNT(*) FILTER (WHERE s.due_at IS NOT NULL), 0), 1) AS pct_exceeded
FROM scoped s
LEFT JOIN assets a ON a.torana_entity_id = s.torana_entity_id AND a.is_deleted IS NOT TRUE
GROUP BY 1, 2, 3
HAVING COUNT(*) FILTER (WHERE s.due_at IS NOT NULL) > 0
ORDER BY pct_exceeded DESC NULLS LAST, total_findings DESC
