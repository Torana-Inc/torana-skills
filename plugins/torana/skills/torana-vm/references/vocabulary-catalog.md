<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Source of truth: pantheon-agent-builder/src/services/vm_policy/vocabulary_registry.py
     Regenerate:      pantheon-agent-builder/scripts/generate_vocabulary_catalog.py
     Any edit here is overwritten on the next regeneration. -->

# VM domain vocabulary — authoring catalog

The platform's canonical, closed set of tunable VM domain settings you may reference from
artifact SQL and fields via `{{vocab:...}}` placeholders (the platform resolves each to its
per-tenant value at install). Generated from the platform's vocabulary registry —
**56 active keys (10 security-critical)** across categories: prioritization, escalation, remediation, exceptions, ownership, automation, coverage, notifications, asset_governance.

## How to use these keys

These keys are the platform's closed set of tunable VM domain SETTINGS (severity floors, EPSS
thresholds, SLA windows, asset exclusions, reachability gates, coverage targets, …). Each has a
platform default; a tenant's value is resolved at install (from the org's policy docs if found,
else the default, overridable). When an artifact needs one of these settings, emit a
`{{vocab:...}}` placeholder from the key table below — **never** a hard-coded literal — and the
platform resolves it per-tenant. A literal freezes one org's value into a portable artifact and
is wrong. (You don't pick the value or care where it comes from; just use a valid key.)

**Two placeholder forms:**

- **Scalar substitution** — `{{vocab:vm.<category>.<subcategory>.<key>}}` (no verb). The raw
  resolved value is substituted (a number, a JSON map, a string). Used in non-SQL fields.
- **Typed SQL render** — `{{vocab:...<key>.<verb>}}`. The verb decides the SQL fragment it
  renders to, so it decides the SQL you must write AROUND it:

  | Verb | Legal for shapes | Renders to | Correct SQL idiom |
  |------|------------------|------------|-------------------|
  | `at_or_above` / `in` | ordered-enum, selector-list | `'Critical','High'` — **quotes included** | `WHERE severity IN ({{…in}})` — ⛔ never `IN ('{{…in}}')` |
  | `not_in` | ordered-enum, selector-list | `'lab','sandbox'` — **quotes included** | `WHERE tag NOT IN ({{…not_in}})` — ⛔ never `NOT IN ('{{…not_in}}')` |
  | `case_order` | ordered-enum | `WHEN 'Critical' THEN 1 …` | `CASE severity {{…case_order}} END` |
  | `gte`/`lte`/`gt`/`lt`/`eq` | scalar | `>= 0.5` (operator+literal) | put AFTER the column: `WHERE epss_score {{…gte}}`. For the OPPOSITE, wrap: `WHERE NOT (coverage_pct {{…gte}})` — **never** `WHERE coverage_pct < {{…gte}}` (renders `< >= 90`, a syntax error). |
  | `flag` | bool | `AND TRUE` when on, empty when off | drop in as a standalone WHERE fragment |
  | *(no verb)* — **key-map** | key-map | raw JSON: `{"Critical": 7, …}` | **quote it and cast**: `'{{…}}'::jsonb ->> severity` — see below |

### Who supplies the quotes — the one thing to get right

Both of the rules below are about quotes, and they point OPPOSITE ways. Read the verb first:

| Verb class | Renders | You write |
|---|---|---|
| `in` / `at_or_above` / `not_in` | `'Critical','High'` — **already quoted** | bare: `IN ({{…}})` |
| `(bare)` key-map | `{"Critical": 7}` — **raw JSON, unquoted** | quoted: `'{{…}}'::jsonb` |

⛔ **Quoting a member-list verb is the more common error, and its symptom does not
point at you.** `IN ('{{…in}}')` renders `IN (''Critical', 'High'')` and Postgres reports
`syntax error at or near "Critical"` — against FULLY-RENDERED SQL, where the placeholder is
gone and nothing names the quotes. Measured 2026-09-06: the authoring agent made this exact
mistake, and repeated it after being told not to. The renderer now refuses it by name.

**A `(bare)` key-map: quote the placeholder, cast to `jsonb`, then index it.**
This is the one form with no obvious SQL idiom, and getting it wrong is the most expensive
mistake here: a build that hardcoded `WHEN 'critical' THEN 14` against a governed
`Critical: 7` put 96 critical fixes live reporting time remaining that policy said was
already spent. Three separate builds made that exact mistake.

```sql
-- sla_window_by_severity is a key-map: {"Critical": 7, "High": 30, "Medium": 90, …}
SELECT v.cve_id,
       v.scan_first_detected_date
         + ((('{{vocab:vm.remediation.sla_windows.sla_window_by_severity}}'::jsonb
              ->> v.severity)::int) * INTERVAL '1 day') AS due_date
FROM vulnerabilities v
```

⛔ **The quotes are load-bearing.** The placeholder renders raw JSON, so an UNQUOTED
`{{vocab:…}}` reaches Postgres literally and validation fails with
`EXPLAIN failed: syntax error at or near "{"` — measured 2026-08-28. Write
`'{{…}}'::jsonb`, never a bare `{{…}}`, anywhere the value lands in SQL.

⚠️ A severity missing from the map yields NULL. That is the CORRECT answer ("no deadline
set") — do not `COALESCE` it into an invented default.

⛔ **Do not read a column that is the policy ALREADY MATERIALISED** (e.g.
`vulnerabilities.vulnerability_due_date`) in a deciding clause — the platform refuses it
and tells you to compute from the row's own anchor plus the vocabulary key, as above.

**Rules:**

1. **Never invent a key.** Only the keys in the table above exist. A placeholder referencing an
   unknown key is not caught offline — it fails at install when resolve-and-gate can't bind it.
2. **Match the verb to the shape.** The "Render verbs" column lists the ONLY legal verbs for
   each key. A key marked `(bare scalar)` takes no `.verb` suffix.
3. **Security-critical keys** (`Sec-crit = yes`) pause an install until the org confirms a
   value — expected, not an error. The build proceeds; the human confirms during install.
4. **Live source of truth:** `torana vm policy vocabulary` (the platform-neutral definitions,
   this same catalog) and `torana vm policy vocabulary-browse` (a specific tenant's RESOLVED
   values + provenance). This file is a generated snapshot for offline authoring.

## The keys

| Key | Qualified path (`{{vocab:<path>[.<verb>]}}`) | Shape | Render verbs | Default | Sec-crit |
|-----|----------------------------------------------|-------|--------------|---------|----------|
| `severity_floor` | `vm.prioritization.severity_thresholds.severity_floor` | ordered-enum | at_or_above/case_order/in/not_in | `"Medium"` | **yes** |
| `severity_floor_by_environment` | `vm.prioritization.severity_thresholds.severity_floor_by_environment` | scope-map | (bare scalar — no .verb suffix) | `null` | **yes** |
| `reachability_required` | `vm.prioritization.scope_gates.reachability_required` | bool | flag | `true` | **yes** |
| `asset_exclusions` | `vm.prioritization.exclusions.asset_exclusions` | selector-list | in/not_in | `[]` | **yes** |
| `kev_auto_escalate` | `vm.escalation.threat_intel.kev_auto_escalate` | bool | flag | `true` |  |
| `epss_escalate_threshold` | `vm.escalation.threat_intel.epss_escalate_threshold` | scalar | gte/lte/gt/lt/eq | `0.5` |  |
| `weight_epss` | `vm.escalation.priority_weights.weight_epss` | scalar | gte/lte/gt/lt/eq | `100` |  |
| `weight_cvss` | `vm.escalation.priority_weights.weight_cvss` | scalar | gte/lte/gt/lt/eq | `5` |  |
| `weight_kev` | `vm.escalation.priority_weights.weight_kev` | scalar | gte/lte/gt/lt/eq | `30` |  |
| `weight_exposure` | `vm.escalation.priority_weights.weight_exposure` | scalar | gte/lte/gt/lt/eq | `25` |  |
| `weight_criticality` | `vm.escalation.priority_weights.weight_criticality` | scalar | gte/lte/gt/lt/eq | `10` |  |
| `internet_facing_escalates` | `vm.escalation.exposure.internet_facing_escalates` | bool | flag | `true` |  |
| `customer_data_escalates` | `vm.escalation.data_sensitivity.customer_data_escalates` | bool | flag | `true` |  |
| `require_fix_available` | `vm.remediation.fix_requirements.require_fix_available` | bool | flag | `false` |  |
| `sla_window_by_severity` | `vm.remediation.sla_windows.sla_window_by_severity` | key-map | (bare scalar — no .verb suffix) | `{"Critical": 7, "High": 30, "Me…` |  |
| `ownership_routing` | `vm.ownership.assignment.ownership_routing` | routing-map | (bare scalar — no .verb suffix) | `{"_fallback": "graph:owns", "_e…` |  |
| `auto_remediation_allowed` | `vm.automation.autonomous_remediation.auto_remediation_allowed` | module-toggle | (bare scalar — no .verb suffix) | `false` | **yes** |
| `risk_acceptance_required` | `vm.automation.workflow_gates.risk_acceptance_required` | module-toggle | (bare scalar — no .verb suffix) | `true` |  |
| `notify_quiet_hours` | `vm.notifications.quiet_hours.notify_quiet_hours` | time-range | (bare scalar — no .verb suffix) | `null` |  |
| `actionable_status_set` | `vm.prioritization.scope_gates.actionable_status_set` | selector-list | in/not_in | `["Open"]` | **yes** |
| `asset_type_scope` | `vm.prioritization.scope_gates.asset_type_scope` | selector-list | in/not_in | `[]` | **yes** |
| `exclude_risk_accepted` | `vm.prioritization.scope_gates.exclude_risk_accepted` | bool | flag | `true` |  |
| `dedup_grouping_keys` | `vm.prioritization.deduplication.dedup_grouping_keys` | selector-list | in/not_in | `["cve_id", "torana_entity_id"]` |  |
| `min_group_size` | `vm.prioritization.deduplication.min_group_size` | scalar | gte/lte/gt/lt/eq | `3` |  |
| `selector_max_rows` | `vm.prioritization.deduplication.selector_max_rows` | scalar | gte/lte/gt/lt/eq | `1000` |  |
| `epss_monitor_threshold` | `vm.escalation.threat_intel.epss_monitor_threshold` | scalar | gte/lte/gt/lt/eq | `0.1` |  |
| `exploit_available_escalates` | `vm.escalation.threat_intel.exploit_available_escalates` | bool | flag | `true` |  |
| `zero_day_escalates` | `vm.escalation.threat_intel.zero_day_escalates` | bool | flag | `true` |  |
| `ransomware_use_escalates` | `vm.escalation.threat_intel.ransomware_use_escalates` | bool | flag | `true` |  |
| `criticality_escalation_floor` | `vm.escalation.asset_criticality.criticality_escalation_floor` | ordered-enum | at_or_above/case_order/in/not_in | `"High"` |  |
| `kev_remediation_window_hours` | `vm.remediation.sla_windows.kev_remediation_window_hours` | scalar | gte/lte/gt/lt/eq | `24` |  |
| `compliance_sla_override` | `vm.remediation.compliance_overrides.compliance_sla_override` | bool | flag | `true` |  |
| `sla_warning_lead_days` | `vm.remediation.sla_escalation.sla_warning_lead_days` | scalar | gte/lte/gt/lt/eq | `7` |  |
| `sla_breach_escalation_target` | `vm.remediation.sla_escalation.sla_breach_escalation_target` | routing-map | (bare scalar — no .verb suffix) | `{"_default": "security_team"}` |  |
| `risk_accept_approval_role_by_severity` | `vm.exceptions.acceptance_authority.risk_accept_approval_role_by_severity` | key-map | (bare scalar — no .verb suffix) | `{"Critical": "security_director…` | **yes** |
| `risk_accept_requires_compensating_control` | `vm.exceptions.acceptance_evidence.risk_accept_requires_compensating_control` | bool | flag | `true` |  |
| `risk_accept_review_max_days` | `vm.exceptions.expiry.risk_accept_review_max_days` | scalar | gte/lte/gt/lt/eq | `90` |  |
| `suppression_expiry_max_days` | `vm.exceptions.expiry.suppression_expiry_max_days` | scalar | gte/lte/gt/lt/eq | `90` |  |
| `reopen_on_redetection` | `vm.exceptions.reopening.reopen_on_redetection` | bool | flag | `true` |  |
| `routing_fallback_chain` | `vm.ownership.fallback.routing_fallback_chain` | selector-list | in/not_in | `["on_call", "team_lead", "engin…` |  |
| `stalled_no_update_days` | `vm.ownership.stalled_work.stalled_no_update_days` | key-map | (bare scalar — no .verb suffix) | `{"Critical": 2, "High": 5, "Med…` |  |
| `triage_autonomy_level` | `vm.automation.autonomous_remediation.triage_autonomy_level` | ordered-enum | at_or_above/case_order/in/not_in | `"Manual"` | **yes** |
| `deploy_block_on_critical` | `vm.automation.pipeline_gates.deploy_block_on_critical` | module-toggle | (bare scalar — no .verb suffix) | `true` |  |
| `build_block_requires_security_review` | `vm.automation.pipeline_gates.build_block_requires_security_review` | bool | flag | `true` |  |
| `auto_ticket_severity_set` | `vm.automation.workflow_gates.auto_ticket_severity_set` | selector-list | in/not_in | `[]` |  |
| `scan_coverage_target_pct` | `vm.coverage.coverage_targets.scan_coverage_target_pct` | scalar | gte/lte/gt/lt/eq | `95` |  |
| `scan_frequency` | `vm.coverage.scan_cadence.scan_frequency` | scalar | gte/lte/gt/lt/eq | `1` |  |
| `required_scan_types` | `vm.coverage.required_scanners.required_scan_types` | selector-list | in/not_in | `["SAST", "SCA", "Secrets", "IaC…` | **yes** |
| `image_age_thresholds` | `vm.coverage.artifact_hygiene.image_age_thresholds` | key-map | (bare scalar — no .verb suffix) | `{"warn_days": 90, "block_days":…` |  |
| `unscanned_deployed_is_finding` | `vm.coverage.coverage_targets.unscanned_deployed_is_finding` | module-toggle | (bare scalar — no .verb suffix) | `true` |  |
| `digest_schedule` | `vm.notifications.digests.digest_schedule` | time-range | (bare scalar — no .verb suffix) | `null` |  |
| `notification_urgency_tiers` | `vm.notifications.urgency_tiers.notification_urgency_tiers` | routing-map | (bare scalar — no .verb suffix) | `{"_default": "digest"}` |  |
| `production_criticality_floor` | `vm.asset_governance.criticality_floors.production_criticality_floor` | ordered-enum | at_or_above/case_order/in/not_in | `"Medium"` |  |
| `criticality_floor_by_data_class` | `vm.asset_governance.criticality_floors.criticality_floor_by_data_class` | scope-map | (bare scalar — no .verb suffix) | `null` |  |
| `asset_required_attributes` | `vm.asset_governance.required_attributes.asset_required_attributes` | selector-list | in/not_in | `["asset_owner", "asset_environm…` |  |
| `data_sensitivity_taxonomy` | `vm.asset_governance.data_classification.data_sensitivity_taxonomy` | selector-list | in/not_in | `["customer-data", "pii", "pci",…` |  |
