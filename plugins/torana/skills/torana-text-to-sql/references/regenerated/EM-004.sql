-- EM-004  Headline-CVE blast radius + ownership. One row per (asset, finding).
-- POLICY BOUND: severity floor (risk appetite) and the open-work status set.
-- 'Won''t Fix' is kept alongside the bound set: see notes.
SELECT a.torana_entity_id, a.asset_name, a.asset_type, a.asset_environment,
       a.asset_status, a.public_access, a.criticality_name, a.asset_team,
       a.asset_owner, a.asset_owner_email, a.has_customer_data,
       v.torana_vulnerability_id, v.cve_id, v.severity,
       v.software_name, v.software_vendor, v.software_product, v.software_version,
       v.package_name, v.package_installed_version, v.package_fixed_version,
       v.package_manager, v.is_fix_available, v.vulnerability_status,
       v.scan_first_detected_date
FROM vulnerabilities v
JOIN assets a ON a.torana_entity_id = v.torana_entity_id
WHERE v.is_deleted IS NOT TRUE
  AND a.is_deleted IS NOT TRUE
  AND v.is_false_positive IS NOT TRUE
  AND v.severity = ANY({{severity_floor.at_or_above}})
  AND v.vulnerability_status = ANY({{actionable_status_set}})
  AND a.asset_status IS DISTINCT FROM 'Decommissioned'  -- policy-literal-ok: lifecycle state of the asset record, not a tenant risk setting
ORDER BY CASE a.criticality_name
           WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
           WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
         a.public_access DESC NULLS LAST, a.asset_name
