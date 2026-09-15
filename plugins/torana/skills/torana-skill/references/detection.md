---
name: detection
description: >
  Manage Torana detection — create, update, execute, and troubleshoot detection rules, alert
  suites, and alert management. Use this skill when users want to write detection logic, organize
  rules into suites, triage or acknowledge alerts, set up alert routing, manage detection
  workflows, run ad-hoc queries, or view execution logs and dashboards.
version: "1.0"
last_updated: "2026-04-16"
platform_version_tested: "2026.1"
---

# Detection — Torana Platform (CLI)

The Torana Detection Framework manages the full lifecycle of security detection: writing rules,
organizing them into suites, executing them on a schedule, routing the resulting alerts, and
visualizing outcomes via dashboards. All operations go through the `torana` CLI — no curl, no
raw API calls.

---

## Bootstrap — Install & Authenticate

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap — the canonical
one.** It is not repeated here on purpose: a copied block drifts from the original, and a
stale bootstrap makes real commands look missing (the exact wrong conclusion the surface
check exists to prevent). Every command on this page assumes `"$TORANA"` is set by it.

---

## Core Concepts

### What Is a Detection Rule?

A detection rule is a named SQL query that runs against the Torana datalake on a schedule. When
the query returns rows, those rows become **alerts**. Rules have:

- **Name and description** — human-readable identification
- **SQL query** — the detection logic (runs against datalake tables via DuckDB)
- **Severity** — `critical`, `high`, `medium`, `low`, `informational`
- **Category** — grouping label (e.g., `vulnerability`, `access`, `compliance`)
- **Schedule** — cron expression or interval controlling how often the rule runs
- **Workspace** — the workspace this rule is associated with
- **Suite membership** — rules are grouped into suites for bulk execution

### Suites

A suite is a named collection of rules. Suites allow:
- Bulk execution of all member rules in one API call
- Shared scheduling (schedule the suite rather than individual rules)
- Workspace-level organization of detection capabilities

### Alerts

When a rule executes and its SQL query returns rows, each row becomes an alert. Alerts have:
- `severity` — inherited from the rule
- `status` — `open`, `acknowledged`, `resolved`, `false_positive`
- `rule_id`, `suite_id` — traceability back to the detection logic
- `result_data` — the actual row(s) returned by the SQL query
- `workspace_id` — the workspace context

### Alert Routing

Alert routes define where alerts go after they fire:
- **Destinations**: email, Slack, JIRA, webhook
- **Filters**: route only specific severities, categories, or rule tags
- **Conditions**: route based on alert field values

### Queries

Queries are reusable SQL fragments that can be referenced by rules and widgets. Running a
query directly (ad-hoc execution) lets you test SQL logic before embedding it in a rule.

### Detection Workflows

Detection workflows are rule-scoped automation that fires automatically when an alert is
created. They are distinct from the general-purpose workflow framework — they are tightly
coupled to the alert lifecycle.

---

## States & Lifecycle

### Rule States

| State | Meaning |
|---|---|
| `active` | Rule runs on its schedule; alerts are generated |
| `inactive` | Rule exists but is not scheduled |
| `draft` | Rule is being authored; not yet executable |

### Suite States

| State | Meaning |
|---|---|
| `active` | Suite can be executed; member rules run |
| `inactive` | Suite exists but is not scheduled |

### Alert States

| State | Meaning | Action |
|---|---|---|
| `open` | Alert fired; not yet triaged | Investigate and acknowledge or resolve |
| `acknowledged` | Analyst has seen and is working the alert | Continue investigation |
| `resolved` | Alert has been remediated | No further action |
| `false_positive` | Alert was not a real threat | Tune the rule to reduce noise |

### Rule Execution States

| State | Meaning |
|---|---|
| `pending` | Execution queued |
| `running` | SQL query executing against datalake |
| `completed` | Query ran; alerts created (if any rows returned) |
| `failed` | Query failed; check `error_message` |

---

## How It Works

### Rule Execution Flow

1. Scheduler fires the rule at the configured time (or `rule <id> execute` is called manually)
2. The detection framework creates a `RuleExecutionLog` with status `running`
3. The SQL query runs against the tenant's datalake (DuckDB)
4. If the query returns rows, each row becomes an alert record
5. Alert routes are evaluated; matching routes dispatch notifications
6. `RuleExecutionLog` is updated to `completed` or `failed`

### SQL Query Format

Detection rules use DuckDB SQL. Source tables from the datalake are referenced as plain table
names (unqualified). The execution framework attaches the correct DuckDB file automatically.

```sql
-- Example: find critical unpatched vulnerabilities open for > 30 days
SELECT
    asset_id,
    cve_id,
    severity,
    first_seen_at,
    DATEDIFF('day', first_seen_at, CURRENT_DATE) AS days_open
FROM vulnerabilities
WHERE severity = 'critical'
  AND status = 'open'
  AND DATEDIFF('day', first_seen_at, CURRENT_DATE) > 30
ORDER BY days_open DESC
```

### Alert Routing Flow

1. Alert is created
2. Detection framework evaluates all active alert routes for the workspace
3. Routes whose filter conditions match the alert are triggered
4. Dispatch adapters send notifications (email, Slack, JIRA ticket, webhook)

---

## Multi-Tenant Considerations

All detection entities are scoped by `tenant_id` and `namespace_id`. A tenant's rules, suites,
alerts, and alert routes are never visible to other tenants.

- Tenant admin and tenant users can manage detection within their tenant
- The datalake queries automatically filter to the tenant's data scope
- Alert routes dispatch to destinations configured by the tenant admin

---

## Troubleshooting Guide

| Symptom | Likely Cause | Fix |
|---|---|---|
| Rule execution fails with "table not found" | Source table doesn't exist in tenant's datalake | Verify the data has been ingested and the table name is correct; use `datalake tables` to list available tables |
| Rule returns 0 rows but alerts expected | SQL logic incorrect, or data not yet available | Test the SQL with `datalake query` first; check datalake table contents |
| Rule never executes | Rule is `inactive`, or schedule expression is invalid | Check rule state; verify cron expression (5-part format required) |
| Alert routing not dispatching | Route filter not matching alert, or destination misconfigured | Check `alert-routes list`, verify filter conditions and destination credentials |
| Suite execution partially fails | One or more member rules failed | Check `suite-execution-logs get <execution-id>` for per-rule status |
| Alerts keep firing for known false positive | Rule SQL too broad | Refine the SQL WHERE clause; mark existing alerts as `false_positive` |

---

## Best Practices

1. **Test SQL before creating a rule** — Use `datalake query` to validate the SQL logic against real datalake data before embedding it in a rule.

2. **Start with low severity** — Set new rules to `low` or `informational` while tuning. Promote to `high`/`critical` only after validating precision.

3. **Use suites for logical grouping** — Group related rules into a suite (e.g., "Vulnerability Management Suite") and schedule the suite rather than individual rules.

4. **Set up alert routing before activating rules** — Configure routes first so alerts are dispatched immediately when rules fire.

5. **Use rule tags for routing granularity** — Tag rules (e.g., `compliance:soc2`, `asset-type:cloud`) and use those tags as routing filters to send alerts to the right team.

6. **Review execution logs after every schedule change** — `rule-execution-logs` show whether the rule is running and how many alerts it generates per run.

7. **Acknowledge alerts promptly** — Open alerts represent active findings. Use `alerts acknowledge` to track which alerts are being worked.

---

## Discovering Commands

The CLI is the source of truth. Use plural to list, then singular + `--help` to discover instance commands:

```bash
"$TORANA" rules list                    # get IDs
"$TORANA" rule <id> --help              # see all commands for that rule
"$TORANA" alerts list                   # get IDs
"$TORANA" alert <id> --help             # see all commands for that alert
"$TORANA" suites list                   # get IDs
"$TORANA" suite <id> --help             # see all commands for that suite
"$TORANA" alert-routes list             # get IDs
"$TORANA" alert-route <id> --help       # see all commands for that route
"$TORANA" rules --help
"$TORANA" alerts --help
"$TORANA" queries --help
"$TORANA" detection-workflows --help
"$TORANA" rule-execution-logs --help
"$TORANA" suite-execution-logs --help
"$TORANA" active-dashboards --help
```

## Typical Workflows

### Create and activate a detection rule

```bash
# Discover tables, then the columns that can actually HOLD DATA.
# ⚠️ --reachable is not optional — see the warning below.
"$TORANA" datalake tables list
"$TORANA" datalake schema table vulnerabilities --reachable --scope platform

# Test SQL ad-hoc before embedding in a rule
"$TORANA" datalake query --sql "SELECT * FROM vulnerabilities WHERE severity = 'critical' LIMIT 5"

# Create a rule
"$TORANA" rules create \
  --name "Critical Unpatched Vulnerabilities > 30 Days" \
  --severity critical \
  --category vulnerability \
  --sql "SELECT torana_entity_id, cve_id, severity, scan_first_detected_date FROM vulnerabilities WHERE severity='Critical' AND vulnerability_status='Open' AND scan_first_detected_date < CURRENT_DATE - INTERVAL '30 days'" \
  --schedule "0 */6 * * *"

# Execute the rule manually to test
"$TORANA" rule <rule-id> execute

# Check execution result
"$TORANA" rule-execution-logs list --rule-id <rule-id>
```

### Manage suites

```bash
# Create a suite
"$TORANA" suites create --name "Vulnerability Management Suite"

# Add rules to the suite
"$TORANA" suite <suite-id> add-rule --rule-id <rule-id>

# Execute the entire suite
"$TORANA" suite <suite-id> execute

# Check suite execution logs
"$TORANA" suite-execution-logs list --suite-id <suite-id>
```

### Triage alerts

```bash
# List open alerts
"$TORANA" alerts list --status open

# Filter by severity
"$TORANA" alerts list --severity critical --format table

# Get alert details
"$TORANA" alert <alert-id> get

# Acknowledge an alert
"$TORANA" alert <alert-id> acknowledge

# Resolve an alert
"$TORANA" alert <alert-id> resolve

# Mark as false positive
"$TORANA" alert <alert-id> false-positive
```

### Set up alert routing

```bash
# List existing routes
"$TORANA" alert-routes list

# Create a route (Slack destination, critical alerts only)
"$TORANA" alert-routes create \
  --name "Critical Alerts → Slack" \
  --destination-type slack \
  --destination-config '{"webhook_url": "https://hooks.slack.com/..."}' \
  --filter-severity critical

# Test the route
"$TORANA" alert-route <route-id> test
```

### View active dashboards

```bash
"$TORANA" active-dashboards list      # list/create/delete only — there is no `get`
```

---


## ⚠️ Authoring SQL: `tables list` is NOT enough

**The datalake declares far more columns than any pipeline fills.** On every table a large
share is declared, documented, and written by nothing. Run `--reachable` and compare — never
assume from the schema listing.

⚠️ **"It appeared in the schema" is exactly the rule that produced the problem.** The shipped
`vm.tf.*` catalog and the question corpus were authored that way, before this check existed:
**74% of that SQL can never run on any tenant** — not because the columns were misspelled, but
because nothing writes them. A rule built on one returns no alerts, forever, and reads as a
quiet tenant rather than a broken rule.

```bash
"$TORANA" datalake schema table <table> --reachable --scope platform   # columns a pipeline can write
"$TORANA" datalake all-columns --reachable --scope platform   # every table, one call
```

⚠️ **`reachable` ≠ `populated`.** Reachable means a pipeline EXISTS. Populated means data has
landed. **An empty result is a fact about this tenant, never a reason to change the SQL** — the
customer may simply not have connected that integration yet.

⚠️ **The example above previously used `asset_id`, `first_seen_at` and `status` — none of
which exist on `vulnerabilities`.** The real columns are `torana_entity_id`,
`scan_first_detected_date` and `vulnerability_status`. Verify names against
`schema --reachable`; never pattern-match from memory or from another table.

## Error Reference

| CLI output | Meaning | Fix |
|---|---|---|
| `Not authenticated` | No cached token | Run OAuth login (see bootstrap) |
| `Session expired` | Refresh token invalid | Re-run OAuth login |
| `403 Forbidden` | Token missing scope | Re-auth with correct account |
| `Cannot reach <url>` | Wrong base-url or network | `"$TORANA" config get base-url`; verify tunnel |

<!-- CHANGELOG
v1.0 (2026-04-16) - Initial CLI-based detection skill
-->
