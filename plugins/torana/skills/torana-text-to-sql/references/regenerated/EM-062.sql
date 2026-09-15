-- EM-062  Scanner signature/plugin currency per scan run.
-- ⛔ DELIBERATELY does NOT read vulnerability_due_date / _sla_breach_date: this
--    question is about SCANNER currency, not remediation SLA. Those columns are
--    the SLA policy already materialised and are irrelevant here.
-- THREE-WAY TEST on '30 days': DEFINITIONAL, kept literal. It is the analyst's
--    evidence threshold for "this run happened long enough after the newest CVE
--    it reported that its feed was probably stale" — a property of the scan
--    evidence, not of the tenant's risk appetite. Binding it to
--    sla_window_by_severity would be a category error: a REMEDIATION deadline
--    per severity has nothing to do with a scan run's feed age, and the run is
--    not keyed by severity at all.
SELECT v.scan_id, v.scanner_name, v.scan_type,
       MIN(v.scan_first_detected_date) AS scan_run_at,
       COUNT(*) AS findings_in_run,
       COUNT(DISTINCT v.plugin_version) AS distinct_plugin_versions,
       MAX(v.plugin_version) AS max_plugin_version,
       COUNT(*) FILTER (WHERE v.plugin_version IS NULL OR v.plugin_version = '') AS findings_without_plugin_version,
       MAX(v.cve_last_modified_date) AS newest_cve_record_seen,
       MAX(v.cve_published_date) AS newest_cve_published_seen,
       FLOOR(EXTRACT(EPOCH FROM (MIN(v.scan_first_detected_date) - MAX(v.cve_published_date))) / 86400.0)::int AS days_scan_after_newest_cve_seen,
       CASE
         WHEN COUNT(*) FILTER (WHERE v.plugin_version IS NOT NULL AND v.plugin_version <> '') = 0
           THEN 'signature_version_not_recorded'
         WHEN MIN(v.scan_first_detected_date) IS NULL THEN 'scan_date_not_recorded'
         WHEN MIN(v.scan_first_detected_date) - MAX(v.cve_published_date) > INTERVAL '30 days'  -- policy-literal-ok: definitional evidence threshold for feed staleness, not a tenant SLA
           THEN 'signatures_possibly_stale'
         ELSE 'signatures_current_by_available_evidence'
       END AS signature_freshness_verdict
FROM vulnerabilities v
WHERE v.is_deleted IS NOT TRUE AND v.scan_id IS NOT NULL AND v.scan_id <> ''
GROUP BY v.scan_id, v.scanner_name, v.scan_type
ORDER BY scan_run_at DESC NULLS LAST
