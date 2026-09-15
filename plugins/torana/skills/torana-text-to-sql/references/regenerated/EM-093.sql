-- EM-093  Cross-scheme score disagreement per CVE.
-- NO VOCABULARY, deliberately. Every literal is DEFINITIONAL:
--   `>= 1.0` is a CVSS-scale fact (one whole point on a 0-10 scale), not a
--   tenant risk appetite; `> 1` counts distinct values. The dispositions are
--   synthesized output labels. Templating any of these would be over-
--   templating: it would force every caller to supply values to ask a question
--   that is about measurement consistency, not about policy.
SELECT v.cve_id, COUNT(*) AS finding_rows,
       COUNT(DISTINCT v.scanner_name) AS distinct_scanners,
       COUNT(DISTINCT v.severity) AS distinct_severity_bands,
       STRING_AGG(DISTINCT v.severity, ' | ' ORDER BY v.severity) AS severity_bands_seen,
       STRING_AGG(DISTINCT v.scanner_name, ' | ' ORDER BY v.scanner_name) AS scanners_seen,
       STRING_AGG(DISTINCT v.cvss_version_primary, ' | ' ORDER BY v.cvss_version_primary) AS cvss_versions_seen,
       MIN(v.cvss3_base_score) AS min_cvss3, MAX(v.cvss3_base_score) AS max_cvss3,
       MIN(v.cvss4_base_score) AS min_cvss4, MAX(v.cvss4_base_score) AS max_cvss4,
       MIN(v.cvss_base_score) AS min_cvss_primary, MAX(v.cvss_base_score) AS max_cvss_primary,
       MAX(v.cvss3_base_score) - MIN(v.cvss3_base_score) AS cvss3_spread,
       MAX(v.cvss4_base_score) - MIN(v.cvss4_base_score) AS cvss4_spread,
       COUNT(*) FILTER (WHERE v.cvss3_base_score IS NULL AND v.cvss4_base_score IS NULL AND v.cvss_base_score IS NULL) AS rows_with_no_score,
       MAX(v.cna_severity) AS a_cna_severity,
       CASE
         WHEN COUNT(DISTINCT v.severity) > 1 THEN 'severity_band_disagreement'
         WHEN COALESCE(MAX(v.cvss3_base_score) - MIN(v.cvss3_base_score), 0) >= 1.0 THEN 'cvss3_score_disagreement'
         WHEN COUNT(DISTINCT v.cvss_version_primary) > 1 THEN 'scored_under_different_cvss_versions'
         WHEN COUNT(*) FILTER (WHERE v.cvss3_base_score IS NULL AND v.cvss4_base_score IS NULL AND v.cvss_base_score IS NULL) = COUNT(*) THEN 'unscored'
         ELSE 'consistent'
       END AS consistency_disposition
FROM vulnerabilities v
WHERE v.is_deleted IS NOT TRUE AND v.cve_id IS NOT NULL AND v.cve_id <> ''
GROUP BY v.cve_id HAVING COUNT(*) > 1
ORDER BY consistency_disposition, finding_rows DESC
