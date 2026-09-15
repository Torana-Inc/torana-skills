---
name: workflows
description: >
  Invoke this skill when the user asks about workflows, playbooks, schedulers, or automation
  on the Torana platform. Trigger phrases include: "create a workflow", "build a playbook",
  "schedule a detection suite", "automate", "set up a workflow", "workflow execution",
  "schedule a task", "cron schedule", "run workflow", "workflow steps", "playbook execution",
  "list workflows", "API catalogue", "workflow builder", "enhanced workflow".
version: "2.0"
last_updated: "2026-04-16"
platform_version_tested: "2026.1"
---

# Workflows — Torana Platform (CLI)

The Torana Workflow Framework provides three complementary automation tools: Enhanced Workflows
for deterministic step-by-step automation, Playbooks for AI-driven adaptive processes, and a
Scheduler for time-based execution of any task type. All operations go through the `torana`
CLI — no curl, no raw API calls.

---

## Bootstrap — Install & Authenticate

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap — the canonical
one.** It is not repeated here on purpose: a copied block drifts from the original, and a
stale bootstrap makes real commands look missing (the exact wrong conclusion the surface
check exists to prevent). Every command on this page assumes `"$TORANA"` is set by it.

---

## Core Concepts

### Three Automation Tools

The Workflow Framework offers three distinct tools, each suited to different automation needs:

| Tool | What it does | Best for |
|---|---|---|
| Enhanced Workflow | Step-based DAG (directed acyclic graph) with explicit data flow and JSONPath mapping | Deterministic, repeatable processes where every step and data path is known upfront |
| Playbook | Natural language instructions sent to an AI agent for execution | Adaptive, exploratory processes where reasoning and judgment are needed |
| Scheduler | Cron or interval triggers for any task type | Time-based automation of workflows, detection suites, rules, or transformers |

### When to Use Enhanced Workflows

Use Enhanced Workflows when:
- The exact sequence of steps is known in advance
- You need reliable, auditable automation with step-by-step execution logs
- Data must be transformed and passed between steps with precision
- You want to combine API calls, data transforms, conditional branches, and loops in a single flow
- The process must run identically every time

### When to Use Playbooks

Use Playbooks when:
- The process requires judgment, interpretation, or contextual decisions
- Instructions are more naturally expressed in English than as a rigid sequence of steps
- The exact steps may vary depending on what the agent discovers during execution
- You are automating incident response, investigation, or analysis tasks

### When to Use Scheduler

Use the Scheduler when:
- You want to run any task (workflow, suite, rule, transformer) on a recurring basis
- You need cron-based schedules (e.g., "every 6 hours", "every Monday at 9am UTC")
- You need interval-based triggers (e.g., "every 30 minutes")
- You want a single place to manage all time-based automation

### Key Terminology

| Term | Definition |
|---|---|
| Enhanced Flow | The database entity representing a workflow definition (steps + config) |
| Step | A single node in a workflow DAG. Has a type (START, ACTION, CHECK, END) and optional action type |
| Action Type | The specific operation an ACTION step performs: api_call, data_transform, rest_api, parallel, loop, conditional, wait, webhook |
| JSONPath | Syntax for navigating JSON data structures (e.g., `$.step_outputs.fetch_data.results[*].id`) |
| Input Mapping | Defines how a step's inputs are sourced from the workflow context using JSONPath |
| Output Mapping | Defines which fields from a step's raw output are written back to the workflow context |
| Workflow Context | The shared data store during execution containing global_variables, constants, and step_outputs |
| START Step Config | Contains the workflow's global_variables, constants, input_schema, and output_schema |
| Playbook | A template with natural language instructions and typed input parameters |
| Template Variables | Placeholders in playbook instructions (e.g., `{{alert_id}}`) replaced with actual values at execution time |
| Scheduled Task | A persistent entity linking a task (workflow/suite/rule/transformer) to a schedule |
| API Catalogue | A 4-level hierarchy (ServiceType → Provider → APIGroup → API) used by api_call steps to reference integration endpoints |

### API Catalogue Hierarchy

The API Catalogue allows workflows to call any registered API without hardcoding URLs:

```
ServiceType  (e.g., "Security Automation", "SIEM", "Vulnerability Management")
  └── Provider  (e.g., "Torana Platform", "Splunk", "CrowdStrike")
        └── APIGroup  (e.g., "Detection", "DataLake", "Integration")
              └── API  (specific endpoint with OpenAPI spec, auth, rate limits)
```

An `api_call` step references an API by its `api_id` from the catalogue. The engine resolves the base URL, authentication, and endpoint automatically.

---

## States & Lifecycle

### Enhanced Workflow States

| State | Meaning | Customer action required? |
|---|---|---|
| `draft` | Workflow is editable; cannot be executed | No — continue editing |
| `published` | Workflow is live and executable; locked for editing | No — ready to run |
| `archived` | Workflow is retired; read-only, not executable | No — historical record only |

**Key constraint:** Only `published` workflows can be executed.

### State Transitions (Enhanced Workflow)

```
draft --> published  (via publish — validates first, blocks if errors exist)
published --> draft  (via unpublish)
draft|published --> archived  (via archive)
```

Cloning always creates a new `draft` regardless of the source workflow's state.

### Playbook States

| State | Meaning | Customer action required? |
|---|---|---|
| `draft` | Playbook is editable; cannot be executed | No — continue editing |
| `active` | Playbook is live and executable | No — ready to run |
| `archived` | Playbook is retired; read-only, not executable | No — historical record only |

### Execution States

Both workflows and playbooks produce executions that follow this lifecycle:

| State | Meaning |
|---|---|
| `pending` | Execution created, not yet started |
| `running` | Actively executing steps |
| `completed` | All steps finished successfully |
| `failed` | One or more steps failed and flow did not recover |
| `cancelled` | Execution was stopped by user request |
| `paused` | Execution halted mid-flow (workflow only) |

Step-level execution states (workflow only): `pending`, `running`, `success`, `failure`, `skipped`, `cancelled`, `retrying`.

### Scheduler States

| State | Meaning | Customer action required? |
|---|---|---|
| `active` | Schedule is firing at the configured time | No |
| `paused` | Schedule is temporarily suspended | Resume when ready |
| `disabled` | Schedule was disabled (by `on_failure=disable` or manually) | Re-enable if desired |
| `expired` | `end_date` has passed or `max_executions` reached | Create a new schedule |
| `error` | Scheduler internal error | Check configuration |

---

## How It Works

### Enhanced Workflow Execution Flow

1. **Validate** — Engine validates the flow definition (checks for START/END steps, dependency cycles, step config)
2. **Create execution record** — An execution is created with status `pending`; inputs and global variables from the START step config are loaded into the workflow context
3. **Initialize context** — `WorkflowContext` is built with `global_variables`, `constants` (from START step config), and initial `flow_inputs`
4. **Execute steps in dependency order** — Steps are resolved topologically; a step runs only after all its `depends_on` steps are complete
5. **Resolve inputs via JSONPath** — Before each step executes, its `input_mapping` is applied to pull data from the context using JSONPath expressions
6. **Execute action** — The action type determines what happens: API call, data transform, REST call, etc.
7. **Map outputs** — After the step completes, its `output_mapping` extracts specific fields from the raw output and writes them into `context.step_outputs[step_id]`

**JSONPath context paths available to every step:**
- `$.global_variables.<name>` — global variables defined in START step
- `$.constants.<name>` — constants defined in START step
- `$.step_outputs.<step_id>.<field>` — output of a previously completed step
- `$.inputs.<name>` — original flow inputs

### Playbook Execution Flow

1. **Render template** — Input values are substituted into the natural language instructions (replacing `{{variable}}` placeholders)
2. **Create execution record** — A PlaybookExecution is created storing the rendered instructions
3. **Send to AI agent** — The rendered instructions are dispatched to the configured agent
4. **Agent executes** — The AI agent reads the instructions and takes actions (API calls, data queries, tool invocations) as it sees fit
5. **Track actions** — Each action the agent takes is logged in `agent_actions` on the execution record
6. **Complete** — When the agent returns a response, the execution is marked `completed` or `failed`

### Scheduler Operation

1. **Create task** — A ScheduledTask is created linking a `task_type` (workflow/suite/rule/transformer) to a `task_id` and a schedule expression
2. **Calculate next execution** — The scheduler computes `next_execution_at` from the cron or interval expression
3. **Fire at schedule time** — The scheduler service fires the task by calling the appropriate downstream API
4. **Log result** — A ScheduledTaskExecutionLog is written with status (success/failure/error/timeout) and duration
5. **Handle failure** — If `on_failure=pause`, the schedule pauses after failure; if `on_failure=disable`, the schedule disables after `max_failures` consecutive failures

**Schedule types:**
- `cron` — Standard 5-part cron expression (`minute hour day month day_of_week`)
- `interval` — Short notation like `30m`, `6h`, `1d`
- `once` — Single execution at `start_date`

**Schedulable task types:** `workflow`, `suite`, `rule`, `transformer`

---

## Multi-Tenant Considerations

- All workflow, playbook, and scheduler entities are scoped to `tenant_id` and `namespace_id`
- The API Catalogue is populated per-tenant (providers and APIs are scoped)
- Tenant users see only their namespace's resources
- The `GET /available-tasks` endpoint only returns workflows from the same database and queries detection/transformers services for suites, rules, and transformers — it will return partial results if those services are unreachable
- Playbook execution passes `IAMContext` to the agent builder to preserve tenant context during AI-driven execution

---

## Troubleshooting Guide

### Common Issues

| Issue | Symptoms | Root Cause | Fix |
|---|---|---|---|
| Workflow validation failure on publish | Error with `errors` array when publishing | Missing START or END step, dependency cycle, invalid step config, or required fields absent | Use validate command with the flow definition to see full error list; fix each error before publishing |
| Step fails mid-execution with null data | Step shows `failure` status; `error_message` mentions `NoneType` or `KeyError` | JSONPath in `input_mapping` resolves to null because the previous step's output didn't contain the expected field | Check the previous step's raw output in `step_executions.raw_outputs`; adjust the JSONPath or add `default_value` in the `DataMapping` |
| Playbook not responding / execution stuck in `running` | `PlaybookExecution.status` stays `running` indefinitely | Agent builder is unreachable or the agent timed out | Check `pantheon-agent-builder` logs; verify `PANTHEON_AGENTS_URL` is correctly set; cancel the execution and retry |
| Scheduler not firing | `next_execution_at` keeps advancing but no ScheduledTaskExecutionLog entries appear | `is_enabled=false` or `status=paused/disabled` on the task | Inspect the task's `is_enabled` and `status`; resume or update to enable |
| Workflow executes draft flow | Error: "Cannot execute draft flow - publish first" | The flow was never published | Publish the flow first; fix any validation errors that block publishing |
| Cron expression rejected | Error: "Cron expression must have 5 parts" | Expression has wrong number of parts (common: using 6-part quartz format) | Use standard 5-part cron: `minute hour day month day_of_week` (e.g., `0 */6 * * *` for every 6 hours) |

### Diagnostic Approach

1. **Check execution status** — look at `status`, `failed_step_id`, `error_message`, and `steps_completed`
2. **Read execution logs** — gives timestamped step-by-step log entries with categories (`execution`, `step`, `mapping`, `condition`, `error`)
3. **Inspect step outputs** — the `step_outputs` field in the execution detail contains what each completed step produced
4. **Validate before executing** — use validate command to catch configuration issues before they cause runtime failures
5. **Check scheduler task state** — inspect `failure_count`, `last_error`, `last_execution_status`, and `next_execution_at`

---

## Best Practices

1. **Choose the right tool** — Use Enhanced Workflows for multi-step API orchestration where data must be precisely passed between steps. Use Playbooks for incident response, investigation, or any task where the agent needs to reason about what to do next. Use the Scheduler for any recurring automation rather than building cron logic into individual services.

2. **Validate before publishing** — Always validate before publishing. The publish endpoint itself re-validates, but calling validate separately lets you iterate without repeated state changes.

3. **Set per-step timeouts** — Every ACTION step has a `timeout_seconds` field (default 30 seconds). Long-running API calls or data transforms should have their timeout explicitly set to avoid silent hangs.

4. **Use output mapping to reduce noise** — Define `output_mapping` on every step to extract only the fields downstream steps need.

5. **Design scheduler failure policy** — For critical schedules (e.g., daily detection runs), set `on_failure=pause` and `notify_on_failure=true` so a human reviews before the schedule resumes.

6. **Clone, don't recreate** — When iterating on a published workflow, clone it to get a draft copy, make changes, validate, then publish.

7. **Structure playbook instructions for auditability** — Playbook instructions should include clear numbered steps so the agent's `agent_actions` log maps cleanly to intent.

---

## CLI Shape — Plural vs Singular

| Form | When to use | Examples |
|---|---|---|
| `torana workflows <verb>` | **Collection** operations (list, create, import) | `workflows list`, `workflows create` |
| `torana workflow <UUID> <verb>` | **Instance** operations on a known workflow ID | `workflow <id> get`, `workflow <id> execute` |

---

## Discovering Commands

The CLI is the source of truth. Use plural to list, then singular + `--help` to discover instance commands:

```bash
"$TORANA" workflows list                # get IDs
"$TORANA" workflow <id> --help          # see all commands for that workflow
"$TORANA" playbooks list                # get IDs
"$TORANA" playbook <id> --help          # see all commands for that playbook
"$TORANA" workflows --help
"$TORANA" playbooks --help
"$TORANA" schedulers --help
"$TORANA" schedulers tasks --help
```

## Typical Workflows

### Create, publish, and execute a workflow

```bash
# Create from a JSON/YAML file defining steps
"$TORANA" workflows create --file workflow-definition.yaml

# Publish (makes it executable)
"$TORANA" workflow <workflow-id> publish

# Execute with inputs
"$TORANA" workflow <workflow-id> execute --input '{"tenant_id": "abc"}'

# Monitor execution
"$TORANA" workflows executions-by-execution-id <execution-id>
"$TORANA" workflows logs <execution-id>
```

### Create and execute a playbook

```bash
"$TORANA" playbooks create --file playbook.yaml
"$TORANA" playbook <playbook-id> publish
"$TORANA" playbook <playbook-id> execute \
  --input '{"alert_id": "ALT-001", "severity": "high"}'
"$TORANA" playbook <playbook-id> executions             # this playbook's runs
"$TORANA" playbooks executions-by-execution-id <execution-id>   # one run, by its id
```

### Schedule a detection suite

```bash
# Find schedulable tasks
"$TORANA" schedulers tasks available

# Create a scheduled task
"$TORANA" schedulers tasks create \
  --name "Detection Suite — Every 6 Hours" \
  --task-type suite \
  --task-id <suite-id> \
  --schedule-type cron \
  --schedule-expression "0 */6 * * *"

# Pause / resume / trigger immediately
"$TORANA" schedulers tasks pause <task-id>
"$TORANA" schedulers tasks resume <task-id>
"$TORANA" schedulers tasks execute <task-id>
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
v1.0 (2026-02-28) - Initial skill creation from pantheon-workflow-framework source analysis
v2.0 (2026-04-16) - Migrated execution mechanics to torana CLI; removed curl/tg/tp/td
-->
