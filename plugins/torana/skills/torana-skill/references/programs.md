---
name: programs
description: Security Programs — highest-level orchestration layer. Coordinates data transformers, detection rules, alert routing, dashboards, playbooks, and schedules through a 3-phase AI-driven planning and execution workflow. Covers Programs, Plans, and Templates.
version: "2.0"
last_updated: "2026-04-16"
platform_version_tested: "2026.1"
---

# Programs — Torana Platform (CLI)

Programs are the highest-level orchestration construct in Torana. A Program encodes a security
automation goal as a structured requirement and then uses AI agents to plan and create all the
artifacts needed to achieve it — transformers, rules, suites, playbooks, alert routing, dashboards,
and schedules — across multiple services. Programs are backed by Plans, optionally bootstrapped
from Templates. All operations go through the `torana` CLI — no curl, no raw API calls.

---

## Bootstrap — Install & Authenticate

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap — the canonical
one.** It is not repeated here on purpose: a copied block drifts from the original, and a
stale bootstrap makes real commands look missing (the exact wrong conclusion the surface
check exists to prevent). Every command on this page assumes `"$TORANA"` is set by it.

---

## Core Concepts

### Program

A Program is a named security automation goal. It contains a **requirement** — a structured JSON object with exactly 8 fields describing what the program should do and how it should behave.

**The 8-field requirement structure:**

| Field | Type | Description |
|-------|------|-------------|
| `goal` | string | What security capability to automate |
| `business_value` | string | Why this matters to the business |
| `tools` | list[string] | Security tools involved (e.g., Qualys, Tenable, ServiceNow) |
| `data_sources` | list[string] | Supplemental data sources beyond the tools |
| `instructions` | string | Numbered step-by-step instructions for the program |
| `governance` | string | Constraints and rules the program must follow |
| `reporting` | string | What dashboards, charts, and reports to generate |
| `actions` | list[object] | Alert/notification triggers with recipients |

**Required fields:** `goal`, `business_value`, and `instructions`. All others are optional but recommended for richer AI-generated plans.

**The `actions` sub-structure:**
```json
{
  "trigger": "When a new critical vulnerability is discovered",
  "action": "Create a JIRA ticket and assign to engineering team",
  "recipients": ["engineering-team@example.com"]
}
```

**Program states:**
- `draft` — being defined; requirement can still be edited
- `planning` — AI agents are generating the plan (background task running)
- `plan_review` — plan generated and ready for human review
- `active` — plan approved and assigned; ready to execute
- `in_progress` — execution is running
- `paused` — execution paused
- `completed` — all phases executed successfully
- `partially_completed` — some artifacts failed during execution
- `failed` — execution failed

**Other program fields:**
- `name` — human-readable name
- `description` — optional longer description
- `owner` — user ID or email of the program owner
- `priority` — integer 1–5 (1 = highest)
- `tags` — list of strings for categorization
- `plan_id` — reference to the assigned Plan (nullable)
- `template_id` — reference to the Template used to create it (nullable, for tracking)

---

### Plan

A Plan is a standalone entity that holds the AI-generated structured execution blueprint for a program. Plans are separate from Programs so the same plan can be reused across multiple programs.

A Plan has three phase fields, each storing a JSON structure:

| Field | Phase | Contains |
|-------|-------|----------|
| `phase1` | Data Foundation | Transformers |
| `phase2` | Detection & Alerting | Rules, Suites, Playbooks, Alert Routing, Schedules |
| `phase3` | Visibility & Reporting | Dashboards (with widgets), Schedules |

Plans can be created manually (via API) or generated automatically by AI planning agents. They are assigned to a Program via the `assign-plan` endpoint, which also moves the program to `active` state.

---

### Template

A Template is a reusable starting point for creating programs. It pre-fills the 8-field requirement with sensible defaults for a particular security use case, using `{{placeholder}}` syntax in fields that users should customize.

**Template structure:**
- `name` — template name (e.g., "Vulnerability Risk Assessment")
- `category` — grouping category (e.g., "Vulnerability Management", "Incident Response", "Compliance")
- `requirement_template` — pre-filled 8-field requirement with `{{placeholders}}`
- `variable_fields` — list of field paths users can customize (e.g., `["goal", "actions.0.recipients"]`)
- `required_user_fields` — subset of variable_fields that users MUST provide
- `example_values` — example values shown in UI for placeholder fields
- `version`, `author`, `tags` — metadata
- `is_public` — if true, visible across all tenants; if false, only visible to creator's tenant
- `is_active` — whether the template is currently available
- `usage_count` — how many programs have been created from this template

**Placeholder substitution:** When `use` or `preview` is called, `{{placeholder_key}}` strings in the `requirement_template` are replaced with user-supplied values.

---

## States & Lifecycle

### Program Lifecycle

```
DRAFT
  │
  ├── (trigger planning) programs plan <id>
  │
  ▼
PLANNING  (background AI agents running)
  │
  ▼
PLAN_REVIEW  (AI done; human reviews plan artifacts)
  │
  ├── (assign plan) programs assign-plan <id>
  │
  ▼
ACTIVE  (ready to execute)
  │
  ├── programs execute phase1 <id>   → Creates transformers
  ├── programs execute phase2 <id>   → Creates detection artifacts
  ├── programs execute phase3 <id>   → Creates dashboards
  │
  ▼
COMPLETED | PARTIALLY_COMPLETED | FAILED
```

### Planning Phases

Planning uses AI agents (invoked asynchronously in background tasks) for each phase:

| Step | Agent Role | Output Artifacts |
|------|-----------|-----------------|
| PLANNING_PHASE1 | Data Planner | Transformers |
| PLANNING_PHASE2 | Detection Planner | Rules, Suites, Playbooks, Alert Routing, Schedules |
| PLANNING_PHASE3 | Visibility Planner | Dashboards (with widgets), Schedules |

Each step progresses: `PENDING` → `IN_PROGRESS` → `COMPLETED` / `FAILED`

### Execution Phases

Each execution phase reads the corresponding plan phase data and creates real artifacts in the target services:

| Step | Creates In |
|------|-----------|
| EXECUTING_PHASE1 | Data Transformers service |
| EXECUTING_PHASE2 | Detection Framework + Workflow Framework |
| EXECUTING_PHASE3 | Visualization service |

---

## How It Works

### 3-Phase Architecture

**Phase 1 — Data Foundation (Transformers)**
- Creates SQL-based data transformers that enrich raw data into analysis-ready tables
- These tables become the data sources for Phase 2 detection rules and Phase 3 dashboards

**Phase 2 — Detection & Alerting**
- Creates detection rules that query Phase 1 transformer tables
- Groups rules into suites
- Creates playbooks for response actions
- Sets up alert routing for notifications (email, Slack, JIRA)
- Creates schedules to run rules on a cron basis

**Phase 3 — Visibility & Reporting**
- Creates dashboards with widgets that visualize Phase 1 data
- Creates scheduled reports and summary dashboards
- Widgets use SQL queries targeting the same transformer tables as Phase 2 rules

### Artifact Types

The following artifact types can appear in a plan:

| Type | Phase | Service |
|------|-------|---------|
| `transformer` | 1 | pantheon-data-transformers |
| `rule` | 2 | pantheon-detection-framework |
| `suite` | 2 | pantheon-detection-framework |
| `playbook` | 2 | pantheon-workflow-framework |
| `alert_routing` | 2 | pantheon-detection-framework |
| `schedule` | 2 & 3 | pantheon-workflow-framework |
| `dashboard` | 3 | pantheon-viz |
| `widget` | 3 (nested in dashboard) | pantheon-viz |

### Creating a Program from Scratch

1. Create with the 8-field requirement → state: `draft`
2. Trigger planning → state moves to `planning` then `plan_review`
3. Review plan artifacts via plan get + plan artifact commands
4. Edit plan artifacts as needed
5. Execute Phase 1 → creates transformers
6. Execute Phase 2 → creates detection artifacts
7. Execute Phase 3 → creates dashboards
8. Monitor progress via execution-status

### Creating a Program from a Template

1. Browse templates by category
2. Preview with your values
3. Create program from template → returns a full Program in `draft` state
4. Continue with planning and execution as above

### Plan Artifact CRUD

Individual artifacts within a Plan can be managed via plan artifact commands. Each artifact type supports list, get, create, update/upsert, and delete.

Supported types: `transformers`, `rules`, `suites`, `playbooks`, `alert-routing`, `dashboards`, `schedules`

---

## Multi-Tenant Considerations

- Programs are strictly tenant-isolated: all queries filter by `tenant_id` from the IAM context
- Plans are also tenant-isolated by `tenant_id`
- Templates have special visibility rules: `is_public=True` templates are visible across all tenants; private templates are scoped to the creator's tenant
- When triggering planning, the IAM context must include a valid `namespace_id` — the user must have a namespace assigned
- All created execution step records carry `tenant_id` and `namespace_id` for IAM compliance

---

## Troubleshooting Guide

**1. Planning fails with "Agent did not return execution_plan"**

The AI planning agent did not produce a valid JSON plan. This usually means:
- The agent timed out (default timeout is 300 seconds per phase)
- The agent's response did not contain parseable JSON
- The program requirement is too vague for the agent to work with

Resolution: Check the program's `progress_notes` field for details. Provide more specific `goal` and `instructions` in the requirement. Retry planning. Check agent logs in `pantheon-agent-builder`.

**2. Execution partially completes (state = partially_completed)**

Some artifacts failed to create during execution. This can happen when:
- A transformer SQL query is invalid
- A referenced table doesn't exist yet (Phase 2/3 before Phase 1 is done)
- Rate limits or timeouts from target services

Resolution: Check failed counts and `execution_progress_details` for error messages. Fix the plan artifacts that failed. You can re-run individual execution phases — they skip artifacts that already exist.

**3. Artifact creation fails with "cross-database reference"**

Dashboard widget SQL queries must use unqualified table names. A query referencing `transformers.my_table` will fail. Use `my_table` directly.

**4. Template "use" returns 400 with missing_fields**

The `required_user_fields` list specifies which placeholder values must be provided. Check the template to inspect `required_user_fields`, then include all of them in `user_values`.

**5. Template created but still shows raw `{{placeholders}}` in requirement**

Use `preview` first with the same `user_values` to see the substitution result before committing. The placeholder name in `user_values` must exactly match the `{{name}}` in the template.

**6. Planning stuck in "planning" state**

The background planning task may have crashed without updating the program state. Check the program framework logs for exceptions in the `run_3phase_planning_task` coroutine. The `latest_execution_id` can be used to look up program_executions rows and see the step-level status.

---

## Best Practices

**1. Write detailed requirements to get better AI plans**

The quality of the AI-generated plan is directly proportional to the quality of the `instructions` field. Include: specific tool names, algorithm details (e.g., risk scoring formulas), explicit enumeration of what to measure, and clear governance constraints.

**2. Review the plan before executing**

After planning completes (state = `plan_review`), always inspect the generated plan artifacts before running execution. Incorrect SQL in a transformer will only surface as an error during Phase 1 execution.

**3. Execute incrementally, phase by phase**

Do not trigger all phases at once without verifying Phase 1 results. Phase 2 rules must reference transformer tables created in Phase 1. Run Phase 1, verify the transformer tables exist, then run Phase 2.

**4. Use Templates for common program types**

If your organization runs the same type of program repeatedly, create a Template with `{{org_name}}` and `{{alert_recipient}}` placeholders. Each new instance takes 3 clicks with consistent structure.

**5. Pass explicit priority to critical programs**

Use `priority: 1` for programs tied to compliance deadlines or critical business risk.

**6. Tag programs consistently**

Use consistent tags like `["vulnerability-management", "compliance", "q1-2026"]` across programs and workspaces.

---

## Discovering Commands

Use plural to list, then singular + `--help` to discover instance commands:

```bash
"$TORANA" plans list                    # get plan IDs
"$TORANA" plan <id> --help              # see all commands for that plan
"$TORANA" templates list                # get template IDs
"$TORANA" template <id> --help          # see all commands for that template
"$TORANA" programs --help
"$TORANA" plans --help
"$TORANA" templates --help
```

Note: `programs` does not yet have a `program <id>` singular form — instance operations
(`plan`, `execute`, `artifacts`, etc.) are still on the plural `programs` group for now.
Run `"$TORANA" programs --help` to see available subcommands.

## Typical Workflows

### Create a program from a template, plan, and execute

```bash
# Find an appropriate template
"$TORANA" templates list --category "Vulnerability Management"

# Preview the template with your values
"$TORANA" template <template-id> preview \
  --value org_name="ACME Corp" \
  --value alert_recipients="security-team@acme.com"

# Create program from template
"$TORANA" template <template-id> use \
  --program-name "ACME VM Program Q1 2026" \
  --value org_name="ACME Corp" \
  --value alert_recipients="security-team@acme.com"

# Trigger AI planning (async)
"$TORANA" programs plan <program-id>

# Poll planning status
"$TORANA" programs planning-status <program-id>

# Get the program to find plan_id
"$TORANA" programs get <program-id>

# Review Phase 1 transformers
"$TORANA" plan <plan-id> transformers

# Execute Phase 1
"$TORANA" programs execute phase1 <program-id>

# Monitor execution
"$TORANA" programs execution-status <program-id>

# Execute Phase 2 after Phase 1 completes
"$TORANA" programs execute phase2 <program-id>

# Execute Phase 3
"$TORANA" programs execute phase3 <program-id>

# List all artifacts created by the program
"$TORANA" programs artifacts <program-id>
```

### Manage plan artifacts

```bash
# List transformers in phase 1
"$TORANA" plan <plan-id> transformers

# Update a transformer by name
"$TORANA" plan <plan-id> transformers update <transformer-name> --file updated.yaml

# List rules in phase 2
"$TORANA" plan <plan-id> rules

# Delete a rule from the plan
"$TORANA" plan <plan-id> rules delete <rule-name>
```

---

## Error Reference

| CLI output | Meaning | Fix |
|---|---|---|
| `Not authenticated` | No cached token | Run OAuth login (see bootstrap) |
| `Session expired` | Refresh token invalid | Re-run OAuth login |
| `403 Forbidden` | Token missing scope | Re-auth with correct account |
| `Cannot reach <url>` | Wrong base-url or network | `"$TORANA" config get base-url`; verify tunnel |

<!-- CHANGELOG
v1.0 (2026-02-28) - Initial skill creation
v2.0 (2026-04-16) - Migrated execution mechanics to torana CLI; removed curl/tg/tp/td
-->
