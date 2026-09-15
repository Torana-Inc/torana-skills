-- EM-086  Weekly threat digest: what landed in the last 7 days, per event type/day.
-- POLICY BOUND: the "high-severity" cut in the headline counter is risk appetite.
-- The 7-day window is DEFINITIONAL — it IS the question ("weekly digest").
WITH scoped AS (
  SELECT v.* FROM vulnerabilities v
  WHERE v.is_deleted IS NOT TRUE AND v.is_false_positive IS NOT TRUE
    AND v.is_suppressed IS NOT TRUE
), new_vulns AS (
  SELECT 'new_vulnerability_detected' AS event_type,
         DATE_TRUNC('day', s.scan_first_detected_date) AS event_day,
         COUNT(*) AS event_count,
         COUNT(DISTINCT s.torana_entity_id) FILTER (WHERE s.torana_entity_id IS NOT NULL AND s.torana_entity_id <> '') AS impacted_asset_count,
         COUNT(DISTINCT s.cve_id) FILTER (WHERE s.cve_id IS NOT NULL AND s.cve_id <> '') AS distinct_cve_count,
         COUNT(*) FILTER (WHERE s.severity = ANY({{severity_floor.at_or_above}})) AS at_or_above_floor_count
  FROM scoped s WHERE s.scan_first_detected_date >= NOW() - INTERVAL '7 days' GROUP BY 2
  UNION ALL
  SELECT 'newly_exploitable_vulnerability', DATE_TRUNC('day', s.cve_last_modified_date), COUNT(*),
         COUNT(DISTINCT s.torana_entity_id) FILTER (WHERE s.torana_entity_id IS NOT NULL AND s.torana_entity_id <> ''),
         COUNT(DISTINCT s.cve_id) FILTER (WHERE s.cve_id IS NOT NULL AND s.cve_id <> ''),
         COUNT(*) FILTER (WHERE s.severity = ANY({{severity_floor.at_or_above}}))
  FROM scoped s WHERE s.cve_last_modified_date >= NOW() - INTERVAL '7 days'
    AND (s.is_exploit_available IS TRUE OR (s.cisa_kev_data IS NOT NULL AND s.cisa_kev_data <> '')) GROUP BY 2
  UNION ALL
  SELECT 'new_public_disclosure', DATE_TRUNC('day', s.public_disclosure_date), COUNT(*),
         COUNT(DISTINCT s.torana_entity_id) FILTER (WHERE s.torana_entity_id IS NOT NULL AND s.torana_entity_id <> ''),
         COUNT(DISTINCT s.cve_id) FILTER (WHERE s.cve_id IS NOT NULL AND s.cve_id <> ''),
         COUNT(*) FILTER (WHERE s.severity = ANY({{severity_floor.at_or_above}}))
  FROM scoped s WHERE s.public_disclosure_date >= NOW() - INTERVAL '7 days' GROUP BY 2
  UNION ALL
  SELECT 'new_vendor_advisory', DATE_TRUNC('day', s.patch_publication_date), COUNT(*),
         COUNT(DISTINCT s.torana_entity_id) FILTER (WHERE s.torana_entity_id IS NOT NULL AND s.torana_entity_id <> ''),
         COUNT(DISTINCT s.cve_id) FILTER (WHERE s.cve_id IS NOT NULL AND s.cve_id <> ''),
         COUNT(*) FILTER (WHERE s.severity = ANY({{severity_floor.at_or_above}}))
  FROM scoped s WHERE s.patch_publication_date >= NOW() - INTERVAL '7 days'
    AND s.vendor_advisory IS NOT NULL AND s.vendor_advisory <> '' GROUP BY 2
)
SELECT event_type, event_day, event_count, impacted_asset_count, distinct_cve_count, at_or_above_floor_count
FROM new_vulns WHERE event_day IS NOT NULL ORDER BY event_day DESC, event_type
