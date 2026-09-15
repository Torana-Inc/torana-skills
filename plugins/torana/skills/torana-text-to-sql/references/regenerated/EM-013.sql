-- EM-013  SSVC-style triage: four decision points + a resulting decision.
--
-- 🔥 MASKING FIXED. The original wrote:
--       CASE WHEN ... v.active_threats ... THEN 'active'
--            WHEN ... v.is_weaponized ... THEN 'poc'
--            ELSE 'none' END
--    Both columns are UNREACHABLE (nothing writes them), so the ELSE branch
--    fired for the entire estate and every row reported ssvc_exploitation =
--    'none' — "no known exploitation anywhere" — AS A FACT. That is a confident
--    wrong answer, not an empty one.
--
--    ssvc_automatable was worse: its ONLY inputs were is_weaponized (unreachable)
--    and exploit_code_maturity, so it reported 'no' for the whole estate.
--
-- FIX: the unreachable inputs are DROPPED, the surviving branches are computed
--    from reachable columns only, and every branch that can no longer be
--    distinguished returns an explicit 'unknown' rather than a confident
--    negative. 'unknown' is honest; 'none'/'no' was not.
--
-- POLICY BOUND: the open-work status set, the EPSS escalation threshold, and
--    the criticality escalation floor (all tenant risk appetite).
--
-- 🟡 GAP, stated: `is_weaponized` and `active_threats` are unreachable, so this
--    query CANNOT distinguish 'active exploitation' from 'proof-of-concept
--    available' on the evidence those columns carry. It reports 'unknown'
--    where it cannot tell. Naming them is the actionable result.
SELECT v.torana_vulnerability_id, v.cve_id, v.vulnerability_name, v.severity,
       v.cvss3_base_score, v.epss_score, v.scan_first_detected_date,
       v.cve_published_date, v.torana_entity_id,
       a.asset_name, a.asset_environment, a.criticality_name, a.public_access,
       a.has_customer_data, a.asset_team,
       CASE
         WHEN v.exploitability_status = 'exploited'
              OR (v.cisa_kev_data IS NOT NULL AND v.cisa_kev_data <> '') THEN 'active'
         WHEN v.is_exploit_available IS TRUE
              OR (v.exploit_framework_metasploit_data IS NOT NULL
                  AND v.exploit_framework_metasploit_data <> '') THEN 'poc'
         WHEN v.exploitability_status IS NULL AND v.cisa_kev_data IS NULL
              AND v.is_exploit_available IS NULL THEN 'unknown'
         ELSE 'none'
       END AS ssvc_exploitation,
       CASE
         WHEN v.exploit_code_maturity IN ('weaponized', 'functional', 'high') THEN 'yes'
         WHEN v.exploit_code_maturity IS NULL THEN 'unknown'
         ELSE 'no'
       END AS ssvc_automatable,
       CASE
         WHEN a.public_access IS TRUE AND v.vulnerability_attack_vector = 'network' THEN 'open'
         WHEN a.public_access IS TRUE THEN 'controlled'
         WHEN a.public_access IS NULL THEN 'unknown'
         ELSE 'small'
       END AS ssvc_exposure,
       CASE
         WHEN a.criticality_name = ANY({{criticality_escalation_floor.at_or_above}})
              OR a.has_customer_data IS TRUE THEN 'very_high'
         WHEN a.criticality_name = 'Medium' THEN 'medium'
         WHEN a.criticality_name IS NULL THEN 'unknown'
         ELSE 'low'
       END AS ssvc_mission_wellbeing,
       CASE
         WHEN (v.exploitability_status = 'exploited'
               OR (v.cisa_kev_data IS NOT NULL AND v.cisa_kev_data <> ''))
              AND (a.public_access IS TRUE
                   OR a.criticality_name = ANY({{criticality_escalation_floor.at_or_above}})) THEN 'Act'
         WHEN v.exploitability_status = 'exploited'
              OR (v.cisa_kev_data IS NOT NULL AND v.cisa_kev_data <> '') THEN 'Attend'
         WHEN v.is_exploit_available IS TRUE
              AND (a.public_access IS TRUE
                   OR a.criticality_name = ANY({{criticality_escalation_floor.at_or_above}})
                   OR a.has_customer_data IS TRUE) THEN 'Attend'
         WHEN COALESCE(v.epss_score, 0) >= {{epss_escalate_threshold}}
              AND a.public_access IS TRUE THEN 'Attend'
         ELSE 'Track'
       END AS ssvc_decision
FROM vulnerabilities v
LEFT JOIN assets a ON a.torana_entity_id = v.torana_entity_id AND a.is_deleted IS NOT TRUE
WHERE v.is_deleted IS NOT TRUE AND v.is_false_positive IS NOT TRUE
  AND v.is_suppressed IS NOT TRUE
  AND v.vulnerability_status = ANY({{actionable_status_set}})
ORDER BY CASE WHEN v.scan_first_detected_date IS NULL THEN 1 ELSE 0 END,
         v.scan_first_detected_date DESC
