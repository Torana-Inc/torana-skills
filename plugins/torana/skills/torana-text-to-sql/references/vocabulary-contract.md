<!-- GENERATED FILE — DO NOT EDIT BY HAND. -->
<!-- Regenerate: python3 scripts/generate_vocabulary_contract.py -->

# Vocabulary contract — the generator's reference before writing any SQL

**Generated** from the two live registries. Hand-edits are discarded.

| Source | What it supplies |
|---|---|
| `pantheon-data-transformers/.../vm_catalog/_vocabulary_snapshot.py` | conservative defaults, shapes |
| `pantheon-program-framework/.../vm_content/vocabulary_keys.py` | legal render verbs, meanings |
| `pantheon-data-transformers/.../vm_catalog/binder.py` | substitution order, `NOT_APPLICABLE_KEYS` |

**48 keys.** Both registries verified identical at generation time — this script refuses to emit if they diverge.

---

## 1. Tenant-neutrality — the precondition, not a nice-to-have

Every value encoding a tenant's **policy** — risk appetite, SLA windows, which statuses count as open — is a **placeholder**, bound per tenant at deployment. One SQL serves every tenant.

`severity IN ('Critical','High')` embeds one customer's risk appetite as though it were a fact about the world. It passes reachability, it parses, and it is **wrong** — and the defect surfaces only at deployment, when the policy layer has nothing to bind.

## 2. TWO syntaxes over ONE key set — getting this wrong fails at EXPLAIN

| | catalog / corpus SQL ← **this skill** | app-template artifacts |
|---|---|---|
| Syntax | `{{key}}` `{{key.at_or_above}}` `{{key[expr]}}` `{{#toggle key}}` | `{{vocab:vm.<cat>.<sub>.<key>[.<verb>]}}` |
| Renderer | `vm_catalog/binder.py` → `bind_entry()` | `vm_content/vocab_render.py` |

⚠️ The **key sets are identical**; the **syntaxes are not.** Corpus SQL uses the **bare binder form**. A `{{vocab:…}}` placeholder in corpus SQL is not resolved by the binder, survives binding, and reaches EXPLAIN as a syntax error. This has shipped once already.

### Binder substitution order (`bind_entry`)

1. blocks — `{{#toggle key}}…{{/toggle}}`, `{{#unless}}`, `{{#if}}`
2. ordered-enum — `{{key.at_or_above}}` → `SELECT unnest(ARRAY['Critical','High',…])`
3. key-map — `{{key[t.col]}}` → `CASE t.col WHEN … END`
4. scalar / selector-list — `{{key}}`; a SET renders as `SELECT unnest(ARRAY[…])`
5. `{{ tenant_id }}` / `{{tenant_id}}`

Blocks are stripped **first** so placeholders inside a dropped block do not survive.

⚠️ **A set renders as a set-returning SUBQUERY, not a bare `ARRAY[…]`** (SUPPLY_GRAPH_SPEC § 3.12 G-d). A bare array is valid only after `= ANY`/`<> ALL`; after `IN` Postgres rejects it (`operator does not exist: character varying = text[]`). The subquery form is valid after **all three**, so a set-valued key is executable wherever an author puts it. ⛔ An EMPTY set has no executable rendering at all — the binder REFUSES it; guard the clause with `{{#if key}}…{{/if}}`.

## 3. Three constraints that silently break generated SQL

1. **The key must be declared on the entry.** `bind_entry` only resolves keys listed in `entry.vocabulary_keys`. An undeclared key's placeholder survives binding.
2. **`NOT_APPLICABLE_KEYS` must never be emitted** (`asset_type_scope`). `bind_entry` **raises** rather than binding, because binding would silently return zero rows.
3. **Every key has a conservative default** (48/48, enforced by a startup assertion). Generated SQL must be correct **with defaults applied** — that is the unconfigured tenant's experience.

## 4. ⛔ DENY-LIST — policy-derived columns that must NEVER be read

| Column | Why |
|---|---|
| `vulnerability_due_date` | written by the `policy` decoration as `scan_first_detected_date + (sla_window_days * INTERVAL '1 day')` (and FILLed by cve_intel from CISA's kev_due_date). Reading it applies whatever policy was in force when the decoration last ran. |
| `vulnerability_sla_breach_date` | same `policy` decoration, expr `COALESCE(vulnerability_due_date, scan_first_detected_date + window)`. Mode=FILL means provenance varies PER ROW — some rows carry an ETL-written value, others a decoration-written one. |

**The vocabulary key always wins** — it is applied at bind time, while the column carries whatever policy was in force when the decoration last ran.

```sql
-- ⛔ WRONG. Reachable, populated, passes every gate check, and silently
--    applies a stale policy.
WHERE v.vulnerability_due_date < NOW()

-- ✅ RIGHT. Compute the deadline from the key + the row's own anchor.
WHERE v.scan_first_detected_date
        + ({{sla_window_by_severity[v.severity]}})::int * INTERVAL '1 day' < NOW()
```

⚠️ *"Which vulnerabilities are overdue?"* has an obvious wrong answer that looks completely correct. This is the single most likely trap.

## 5. The three-way literal test — do NOT template everything

Before templating any literal, decide which of three it is:

| Kind | Example | Action |
|---|---|---|
| **tenant policy** | `severity IN ('Critical','High')` | **bind** it |
| **definitional** | "12-month trend" — the window IS the question | **keep** the literal |
| **reporting window** | caller wants 7 vs 90 days | **expose** it, do not bind |

⚠️ **Over-templating is its own failure.** A query where everything is a variable answers nothing specific and forces every caller to supply 20 values. A synthesized OUTPUT label (`'missing_team'`, `'verified'`) is never a policy literal — it is the query's own vocabulary.

**Decision aid** — ask: *would two reasonable tenants disagree about this value, AND does the question stay the same question if they do?* Both yes → bind. If changing it changes the question → definitional, keep it.

## 6. The key table

`verbs` is the **closed** legal set for that key — a verb not listed is rejected. An **empty** verb list means the key is only ever a bare form (scalar, block toggle, or key-map); appending a verb to it produces an unbound hole.

| key | meaning | value domain | conservative default | legal verbs | emit this form | use in |
|---|---|---|---|---|---|---|
| `actionable_status_set` | Which vulnerability statuses are still considered open work. | selector-list | `Open` | `in`, `not_in` | `{{actionable_status_set}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `asset_exclusions` | Assets or tags excluded from vulnerability prioritization. | selector-list | `[]` *(empty — widest scope)* | `in`, `not_in` | `{{asset_exclusions}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `asset_required_attributes` | Attributes every asset must carry to be governable. | selector-list | `asset_owner, asset_environment, criticality_name` | `in`, `not_in` | `{{asset_required_attributes}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `asset_type_scope` | Asset types in scope for vulnerability prioritization. | selector-list | `[]` *(empty — widest scope)* | `in`, `not_in` | ⛔ **never emit** | ⛔ **NOT APPLICABLE — never emit** |
| `auto_remediation_allowed` | May the platform auto-open fix PRs without human approval? | module-toggle | `FALSE` | — *(none)* | `{{#toggle auto_remediation_allowed}}…{{/toggle}}` | include/exclude a whole module block |
| `auto_ticket_severity_set` | Severities that automatically open a tracking ticket. | selector-list | `[]` *(empty — widest scope)* | `in`, `not_in` | `{{auto_ticket_severity_set}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `build_block_requires_security_review` | A build-blocking rule needs security sign-off before it is enforced. | bool | `TRUE` | `flag` | `{{#toggle build_block_requires_security_review}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `compliance_sla_override` | A stricter compliance deadline overrides the internal SLA. | bool | `TRUE` | `flag` | `{{#toggle compliance_sla_override}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `criticality_escalation_floor` | Asset business-criticality at/above which findings escalate. | ordered-enum | `High` | `at_or_above`, `case_order`, `in`, `not_in` | `{{criticality_escalation_floor.at_or_above}}` | severity/criticality filters in WHERE, and CASE ordering |
| `criticality_floor_by_data_class` | Minimum criticality per data classification (e.g. PCI, PHI). | scope-map | `null` *(canonically unset)* | — *(none)* | `{{criticality_floor_by_data_class[t.column]}}` | per-scope override; renders its ABSENT branch when unset |
| `customer_data_escalates` | A service handling customer data escalates the priority of its findings. | bool | `TRUE` | `flag` | `{{#toggle customer_data_escalates}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `data_sensitivity_taxonomy` | The vocabulary used to mark data sensitivity. | selector-list | `customer-data, pii, pci, phi, none` | `in`, `not_in` | `{{data_sensitivity_taxonomy}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `dedup_grouping_keys` | The fields that identify one finding across multiple scanners. | selector-list | `cve_id, torana_entity_id` | `in`, `not_in` | `{{dedup_grouping_keys}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `deploy_block_on_critical` | Whether an unresolved Critical blocks deployment. | module-toggle | `TRUE` | — *(none)* | `{{#toggle deploy_block_on_critical}}…{{/toggle}}` | include/exclude a whole module block |
| `digest_schedule` | Cadence of the scheduled summary report. | time-range | `null` *(canonically unset)* | — *(none)* | `{{digest_schedule}}` | schedule/quiet-window; almost never in corpus SQL |
| `epss_escalate_threshold` | EPSS exploit-probability score at/above which a CVE escalates. | scalar | `0.5` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{epss_escalate_threshold}}` | a numeric/string comparison in WHERE |
| `epss_monitor_threshold` | EPSS score at/above which a CVE is watched, below the escalation bar. | scalar | `0.1` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{epss_monitor_threshold}}` | a numeric/string comparison in WHERE |
| `exclude_risk_accepted` | Whether formally risk-accepted findings leave the active queue. | bool | `TRUE` | `flag` | `{{#toggle exclude_risk_accepted}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `exploit_available_escalates` | A known public exploit escalates a finding's priority. | bool | `TRUE` | `flag` | `{{#toggle exploit_available_escalates}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `image_age_thresholds` | Container-image age (days) at which to warn and to block. | key-map | `warn_days=90, block_days=180` | — *(none)* | `{{image_age_thresholds[t.column]}}` | per-severity windows/thresholds — arithmetic in WHERE or SELECT |
| `internet_facing_escalates` | An internet-facing service escalates the priority of its findings. | bool | `TRUE` | `flag` | `{{#toggle internet_facing_escalates}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `kev_auto_escalate` | Auto-escalate CVEs on the CISA KEV (Known Exploited Vulnerabilities) list. | bool | `TRUE` | `flag` | `{{#toggle kev_auto_escalate}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `kev_remediation_window_hours` | Accelerated remediation window (hours) for actively exploited CVEs. | scalar | `24` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{kev_remediation_window_hours}}` | a numeric/string comparison in WHERE |
| `notification_urgency_tiers` | Which conditions page immediately rather than wait for a digest. | routing-map | `_default=digest` | — *(none)* | `{{notification_urgency_tiers[t.column]}}` | routing/notification targets in SELECT — rarely in corpus SQL |
| `notify_quiet_hours` | Org-default quiet window during which proactive notifications are suppressed. | time-range | `null` *(canonically unset)* | — *(none)* | `{{notify_quiet_hours}}` | schedule/quiet-window; almost never in corpus SQL |
| `ownership_routing` | Which team/queue an alert routes to, per selector. | routing-map | `_fallback=graph:owns, _else=unassigned` | — *(none)* | `{{ownership_routing[t.column]}}` | routing/notification targets in SELECT — rarely in corpus SQL |
| `production_criticality_floor` | Minimum business-criticality a production asset may carry. | ordered-enum | `Medium` | `at_or_above`, `case_order`, `in`, `not_in` | `{{production_criticality_floor.at_or_above}}` | severity/criticality filters in WHERE, and CASE ordering |
| `reachability_required` | Must a finding be on a deployed service to be prioritized? | bool | `TRUE` | `flag` | `{{#toggle reachability_required}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `reopen_on_redetection` | A closed finding reopens if detected again. | bool | `TRUE` | `flag` | `{{#toggle reopen_on_redetection}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `require_fix_available` | Require a fix to exist for a finding to be classed 'fix-now'. | bool | `FALSE` | `flag` | `{{#toggle require_fix_available}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `required_scan_types` | Scan types that must be enabled on in-scope assets. | selector-list | `sast, sca, container, secrets, iac` | `in`, `not_in` | `{{required_scan_types}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `risk_accept_approval_role_by_severity` | Which role may accept risk at each severity. | key-map | `Critical=security_director, High=security_director, Medium=security_manager, Low=security_manager` | — *(none)* | `{{risk_accept_approval_role_by_severity[t.column]}}` | per-severity windows/thresholds — arithmetic in WHERE or SELECT |
| `risk_accept_requires_compensating_control` | An accepted risk must name a compensating control. | bool | `TRUE` | `flag` | `{{#toggle risk_accept_requires_compensating_control}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |
| `risk_accept_review_max_days` | Maximum lifetime (days) of a risk acceptance before re-review. | scalar | `90` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{risk_accept_review_max_days}}` | a numeric/string comparison in WHERE |
| `risk_acceptance_required` | Closing a finding as 'accepted risk' requires an approval step. | module-toggle | `TRUE` | — *(none)* | `{{#toggle risk_acceptance_required}}…{{/toggle}}` | include/exclude a whole module block |
| `routing_fallback_chain` | Where a finding goes when no owner can be determined. | selector-list | `on_call, team_lead, engineering_manager` | `in`, `not_in` | `{{routing_fallback_chain}}` | set membership: `= ANY(...)` / `<> ALL(...)` |
| `scan_coverage_target_pct` | Percentage of the estate required to be under scan. | scalar | `95` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{scan_coverage_target_pct}}` | a numeric/string comparison in WHERE |
| `scan_frequency` | How often assets are rescanned. | scalar | `1` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{scan_frequency}}` | a numeric/string comparison in WHERE |
| `severity_floor` | Minimum vulnerability severity that is 'actionable' for prioritization. | ordered-enum | `Medium` | `at_or_above`, `case_order`, `in`, `not_in` | `{{severity_floor.at_or_above}}` | severity/criticality filters in WHERE, and CASE ordering |
| `severity_floor_by_environment` | Per-environment override of the severity floor (e.g. 'Medium+ in prod, High+ in dev'). | scope-map | `null` *(canonically unset)* | — *(none)* | `{{severity_floor_by_environment[t.column]}}` | per-scope override; renders its ABSENT branch when unset |
| `sla_breach_escalation_target` | Who an SLA breach escalates to. | routing-map | `_default=security_team` | — *(none)* | `{{sla_breach_escalation_target[t.column]}}` | routing/notification targets in SELECT — rarely in corpus SQL |
| `sla_warning_lead_days` | How many days before an SLA breach a warning fires. | scalar | `7` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{sla_warning_lead_days}}` | a numeric/string comparison in WHERE |
| `sla_window_by_severity` | Remediation SLA window (days) per severity. | key-map | `Critical=7, High=30, Medium=90, Low=180` | — *(none)* | `{{sla_window_by_severity[t.column]}}` | per-severity windows/thresholds — arithmetic in WHERE or SELECT |
| `stalled_no_update_days` | Days without progress before a finding is chased, per severity. | key-map | `Critical=2, High=5, Medium=10, Low=30` | — *(none)* | `{{stalled_no_update_days[t.column]}}` | per-severity windows/thresholds — arithmetic in WHERE or SELECT |
| `suppression_expiry_max_days` | Maximum lifetime (days) of a suppression before it lapses. | scalar | `90` | `gte`, `lte`, `gt`, `lt`, `eq` | `{{suppression_expiry_max_days}}` | a numeric/string comparison in WHERE |
| `triage_autonomy_level` | How far the platform may triage without a human. | ordered-enum | `Manual` | `at_or_above`, `case_order`, `in`, `not_in` | `{{triage_autonomy_level.at_or_above}}` | severity/criticality filters in WHERE, and CASE ordering |
| `unscanned_deployed_is_finding` | A deployed asset with no scan results is itself a finding. | module-toggle | `TRUE` | — *(none)* | `{{#toggle unscanned_deployed_is_finding}}…{{/toggle}}` | include/exclude a whole module block |
| `zero_day_escalates` | A zero-day escalates regardless of its base severity. | bool | `TRUE` | `flag` | `{{#toggle zero_day_escalates}}…{{/toggle}}` | include/exclude a pre-authored block — never a bare literal |

## 7. Named traps

- **`sla_window_by_severity` has NO legal verbs.** It is a dict and takes the **key-map form** `{{sla_window_by_severity[t.severity]}}`. Emitting `{{sla_window_by_severity.at_or_above}}` is plausible-looking and wrong — the binder leaves the hole unbound and it reaches EXPLAIN.
- **15 of 48 keys accept NO verb at all**: `auto_remediation_allowed`, `criticality_floor_by_data_class`, `deploy_block_on_critical`, `digest_schedule`, `image_age_thresholds`, `notification_urgency_tiers`, `notify_quiet_hours`, `ownership_routing`, `risk_accept_approval_role_by_severity`, `risk_acceptance_required`, `severity_floor_by_environment`, `sla_breach_escalation_target`, `sla_window_by_severity`, `stalled_no_update_days`, `unscanned_deployed_is_finding`. Check the table before suffixing anything.
- **Binding can CREATE a masking risk.** `COALESCE(unreachable_col, <conservative default>)` returns the platform's assumption as though it were measured. Bind the policy; do not paper over an unreachable column with its default.
- **A default must render correct SQL.** Generated SQL is judged with defaults applied — that is what an unconfigured tenant runs.
- **The renderer does not skip comments.** A `{{vocab:...}}` inside `--` or `/* */` is parsed like any other placeholder, so a comment written to *explain* a placeholder — or to document a workaround — can itself fail the artifact on an unknown key. Describe the binding in prose; never paste the syntax into a comment.

## 8. Verify, do not predict

```bash
python3 scripts/reachability_gate.py check --file /tmp/candidate.sql \
    --scope platform
```

The gate binds with the platform's **own** binder and conservative defaults, then re-parses. `BIND_ERROR` / `UNRESOLVED_PLACEHOLDER` means the placeholder is wrong — an authoring defect, not a SQL defect.

