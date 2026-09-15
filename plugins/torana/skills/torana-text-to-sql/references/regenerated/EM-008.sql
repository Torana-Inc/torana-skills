-- EM-008  Where to draw the remediation cut-line, per severity band.
-- POLICY BOUND: the open-work status set, and the EPSS escalation threshold
--   (both tenant risk appetite). The severity BANDS are the question's own
--   axis — the query enumerates every band by design, so a floor filter would
--   destroy the question. `case_order` is legal on severity_floor but wrong
--   here: the CASE is the full ordering, not a floor.
-- 🟡 GAP: `is_weaponized` is UNREACHABLE (nothing writes it). It is DROPPED
--   from the exploitation signal rather than silently substituted. Consequence
--   stated in the report: a vulnerability that is weaponized but has neither an
--   EPSS score at/above the threshold, nor a KEV entry, nor exploitability_status
--   = 'exploited' is NOT counted as likely-exploited. This narrows the signal;
--   it does not change the row set.
WITH scoped AS (
  SELECT v.torana_vulnerability_id, v.severity, v.epss_score, v.cvss3_base_score,
         v.cisa_kev_data, v.is_exploit_available, v.exploitability_status,
         CASE WHEN COALESCE(v.epss_score, 0) >= {{epss_monitor_threshold}}
                   OR (v.cisa_kev_data IS NOT NULL AND v.cisa_kev_data <> '')
                   OR v.exploitability_status = 'exploited'  -- policy-literal-ok: an exploitability_status enum VALUE, not a vulnerability_status policy set
              THEN 1 ELSE 0 END AS is_likely_exploited
  FROM vulnerabilities v
  WHERE v.is_deleted IS NOT TRUE AND v.is_false_positive IS NOT TRUE
    AND v.is_suppressed IS NOT TRUE
    AND v.vulnerability_status = ANY({{actionable_status_set}})
), totals AS (
  SELECT COUNT(*) AS all_open, SUM(is_likely_exploited) AS all_likely_exploited FROM scoped
), banded AS (
  SELECT COALESCE(s.severity, 'Unrated') AS severity_band,
         CASE COALESCE(s.severity, 'Unrated')
           WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3
           WHEN 'Low' THEN 4 WHEN 'None' THEN 5 ELSE 6 END AS band_order,
         COUNT(*) AS findings_in_band,
         SUM(s.is_likely_exploited) AS likely_exploited_in_band
  FROM scoped s GROUP BY 1, 2
)
SELECT b.severity_band, b.band_order, b.findings_in_band, b.likely_exploited_in_band,
       SUM(b.findings_in_band) OVER (ORDER BY b.band_order) AS cumulative_work_if_line_drawn_here,
       SUM(b.likely_exploited_in_band) OVER (ORDER BY b.band_order) AS cumulative_likely_exploited_covered,
       t.all_likely_exploited - SUM(b.likely_exploited_in_band) OVER (ORDER BY b.band_order) AS likely_exploited_still_missed,
       ROUND(100.0 * SUM(b.likely_exploited_in_band) OVER (ORDER BY b.band_order) / NULLIF(t.all_likely_exploited, 0), 2) AS pct_likely_exploited_covered,
       t.all_open AS total_open_findings
FROM banded b CROSS JOIN totals t ORDER BY b.band_order
