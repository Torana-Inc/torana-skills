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
- `sla_due_at` — the deadline, set when the alert is raised (see **SLA deadlines** below)
- `verdict_source` — where the verdict came from, stated by the platform: `ranking_rules` (a rule's declared
  verdict), `triage_agent`, `person` or `platform`. `verdict_source_label` is short (`Ranking rules`, `Triage agent`,
  the person's name, `Platform`); `verdict_source_detail` is long (`Ranking rules: <rule name>`). An entry also carries
  `members_by_source` and `members_source_summary`. Read these; never infer the source from `verdict_actor_id`.
  `torana alerts list` shows the label in its decider column; `torana alert <id> get` shows the detail.
  Every alert row also carries `tenant_id` and `rule_name`; `torana alerts list` shows the rule's name in its RULE
  column (add `--wide` for the rule id too; `--format json` always has both), and `rule-execution-logs list` fills
  its RULE NAME column from the same field.
  `torana alert <entry id> members` returns EVERY member (it pages the server's 100-row pages itself, up to 50
  pages); `--limit` / `--offset` return one page and print "showing X-Y; more may exist" to stderr when it is full.
  `torana alert <id> cve-intel` shows what the platform holds about the CVEs on an item, one row per CVE (CVSS,
  EPSS, CISA KEV and ransomware use, CWE, description, dates). A finding shows its own CVE; an entry shows its
  members' distinct CVEs, worst CVSS first, at most 50 (`--format json` has `total` and `truncated`). A CVE the
  threat-intel table does not hold is listed with `known: false`, not an error; an unreadable datalake is a 503.
  `torana alert <id> proof` is the item's deep-dive **with proof**: each claim ("Is this item still true?", "How
  severe is it, really?", "Where does it run?", …) and the datalake rows, selections, column meanings and rule
  outputs behind every value. `--claim <id>` traces one claim down to the rows and queries (an unknown id exits 2
  and lists the ids); `--save FILE` keeps the record for `torana datalake proof verify|replay` (datalake.md);
  `--format json` is the record itself. Read-only, any tenant user (`datalake:read` + `alert:read`). The header
  line names the item type. Modelled: `vuln_in_image` (a CVE finding on a container image), `fix_entry` and
  `mitigation_entry` (also an Inbox entry "Upgrade X" / "Mitigate X" for one package), `threat_signal`,
  `posture_summary`, `code_finding` (a SAST, IaC or secrets finding in one file of a repository: state, flagged
  lines, rule, whether the code ships to running services, owner); each also carries the alert's own facts. A code
  scanner never reports a finding as closed: it is gone only when a later scan stops listing it, and the claim says
  so. Any other item prints "No proof model for this item type yet (…)". That means not modelled, not "no
  evidence". Cite a claim's text rather than re-deriving it, and say "not recorded" when the claim says so.

```bash
"$TORANA" alert <alert-id> proof                          # every claim, by section
"$TORANA" alert <alert-id> proof --claim stale            # what "Is this item still true?" was read from
"$TORANA" alert <alert-id> proof --save /tmp/proof.json   # keep it to verify or replay later
```

  `torana alert <id> brief` shows the item's **AI brief**: the proven claims in prose ("In one breath",
  "Remediation", "Suggested plan", …), every sentence with the claim ids it cites, written by one AI call over that
  item's claims only and checked by code (every number, id and name must be in a cited claim; the footer says
  `validated: N/N`). It is checked against the item's proof as it is NOW: "◇ claims changed since written" marks a
  sentence whose claims changed (rewrite it), "as of <time>:" dates one whose claim only aged. Read-only, any tenant
  user with `alert:read`; "No brief yet" (exit 3) when none was written. `--write --wait` writes a new one (one LLM
  call, about a minute; a person's action, ⛔ refused in the agent sandbox). Unmodelled items get no brief ("no
  proof model"). `--workspace` defaults to the alert's own workspace; `--format json` is the stored brief plus the
  staleness result. Quote a brief's sentence only with its cites, and prefer the claim itself (`proof --claim`).

```bash
"$TORANA" alert <alert-id> brief                          # the brief, with staleness against the proof now
"$TORANA" alert <alert-id> brief --format json            # stored brief + validation + staleness
```

### `inbox` vs `get` — two views of one item, and which to use

⭐ **`torana alert <id> inbox` is the item EXACTLY as the Inbox shows it** — the same sections, same order, same
wording as the product's detail pane: Description, Verdict, Proposed Fix, Reported By, Activity. A section with
nothing to say is omitted, as it is hidden there. Use it to answer "what does the user see for this item?", to
read an item the way an operator reads it, or to quote the product's own words back to someone.

```bash
"$TORANA" alert <alert-id> inbox                 # the Inbox view, with Activity
"$TORANA" alert <alert-id> inbox --no-activity   # sections only
"$TORANA" alert <alert-id> inbox --format json   # the same sections as data
```

⭐ **Handed an Inbox URL?** `…/workspaces/<workspace-id>/inbox?box=<box>&alert=<alert-id>` maps to
`alert <alert-id> inbox` — the `alert` query parameter IS the id to pass. The workspace is implied by the alert
and needs no flag, and `box` shows in the header line. To list the box instead of opening one item,
`alerts list`. ⚠️ An item belongs to ONE tenant: run the profile that owns it, or the id 404s even for SA
(a cross-tenant read is refused, not empty). `alerts boxes` shows how many items each box holds.

⛔ **Do not re-derive these sections from `get --format json`.** The platform builds them once
(`GET /alerts/{id}/view`) and pantheon-fe and this CLI both only PRINT them, so the two surfaces can never word
the same item differently. Anything you compose yourself will drift from what the user is looking at.

**`get` is the other view: the operator/debug one.** It carries lines the Inbox deliberately leaves out — the
`RUNTIME` line and its ⚠ stale marker, the `TRIAGE` failure line (attempts, error kind), `CLOSED BECAUSE` and the
lifecycle evidence, `GROUP` progress, and the full raw key dump. Reach for `get` when debugging why an item is in
a strange state; reach for `inbox` when you care what the item says.

⚠️ `inbox` reads the FINDING's severity (`finding_severity`) in its header line, as the pane does; an item's
alert-level `severity` can differ (`high` where the pane says `critical`). Both are in `--format json` under
`header`. Dates inside CVE rows arrive as a `template` plus ISO `dates` so each surface formats them locally —
`--format json` shows both, and the text output has already rendered them.

### SLA deadlines

Every rule-raised alert gets `sla_due_at = raised + hours`, where the hours come from, in order:
1. the rule's own override (`sla_hours`), when set;
2. the tenant's SLA policy for the alert's severity;
3. the platform defaults: Critical 24 h, High 72 h, Medium 168 h, Low 720 h.

When an alert's severity rises, its deadline is recomputed for the new severity and the
**tightest** one wins. An item reopened by a new detection after it was closed restarts its clock. ⚠️ Changing the policy or an override
affects **new alerts only**; existing deadlines never move, so don't promise a user that their
open alerts will change.

```bash
"$TORANA" alerts sla-policy get                           # hours per severity + rule overrides
"$TORANA" alerts sla-policy set --critical-hours 12 --high-hours 48   # tenant admin (alert:update)
"$TORANA" alerts sla-policy set --reset                   # back to the platform defaults
"$TORANA" rule <rule-id> update --sla-hours 8             # this rule's alerts due 8 h after raise
"$TORANA" rule <rule-id> update --clear sla_hours         # back to the tenant policy
```

Who: any tenant user can `get`; `set` and rule overrides need `alert:update` / `rule:update`.
Overdue open alerts: `sla_due_at < now()` and status not resolved/closed (the Alerts dashboard's
"Past SLA" panel counts exactly that).

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

# True positives whose relied-on deployment is NO LONGER RUNNING (F-o01-2)
# ⛔ The VERDICT IS UNCHANGED and nothing is re-triaged: the platform recorded what the
# verdict relied on (an image or repository), then found that place stopped running. It
# is an observation for the decider, not a reversal.
"$TORANA" alerts list --runtime-stale
# The RUNTIME column reads "stale since <date>" for those, and "—" otherwise. ⚠️ "—"
# covers BOTH "still running" AND "no record": alerts whose finding names no place
# (posture_service, upgrade) never carry one, so an empty column is not "it is running".
# Full detail, including what was observed and when it was last seen:
"$TORANA" alert <id> get        # adds a RUNTIME line, and a ⚠ line when stale
# JSON carries every field: verdict_runtime_key, _facts, _seen_at, _confirmed_at,
# _stale_at, plus the derived _last_seen_at (later of confirmed/seen) and _stale (bool,
# already gated on the alert being a true positive — prefer it over _stale_at).
"$TORANA" alerts list --runtime-stale --format json

# Complex filtering — one expression, several fields. `--filters` is a JSON OBJECT:
#   field -> value                                     (a bare value means equals)
#   field -> [v1, v2]                                  (a list means in_list)
#   field -> {"operation": <op>, "value": <v>}         (the explicit form)
"$TORANA" alerts filter --filters '{"severity": "critical"}'
"$TORANA" alerts filter --filters '{"status": {"operation": "in_list", "value": ["open", "pending_remediation"]}}'
# ⚠️ VALUES ARE CASE-EXACT and the two severity vocabularies DIFFER. The rule's
# `severity` is lower-case (critical/high/medium/low); the finding's own
# `finding_severity` is Title-Case (Critical/High/…). `{"severity": "CRITICAL"}` is
# refused, naming the allowed set and pointing at the other field — it does NOT return 0
# rows silently, and (since 2026-10-04) no longer 500s.
# ⚠️ An unknown FIELD or OPERATION is refused the same way, so a filter that cannot be
# applied never runs as an unfiltered list.

# Get alert details
"$TORANA" alert <alert-id> get

# Acknowledge an alert
"$TORANA" alert <alert-id> acknowledge

# Resolve an alert
"$TORANA" alert <alert-id> resolve

# Mark as false positive
"$TORANA" alert <alert-id> false-positive
```

### Record a human triage verdict on a vulnerability

An alert's verdict stays on the ALERT; it is not copied onto the finding. To record an
analyst's judgement on the finding itself, use `vulnerability <ID> triage` (tenant):

```bash
"$TORANA" vulnerability <torana_vulnerability_id> triage --confirmed --notes "reachable from the edge"
"$TORANA" vulnerability <torana_vulnerability_id> triage --business-justification "deferred to Q3" \
    --compensating-controls "WAF rule 941100" --risk-acceptance-expires-at 2026-12-31
"$TORANA" vulnerability <torana_vulnerability_id> triage --no-patch-available --workaround-available
```

Every call also stamps `decided_by_actor_type=user` and `decided_at=now` on the row, so a human
verdict is distinguishable from a scanner-reported flag. You do not pass them.
`--risk-acceptance-expires-at` takes `YYYY-MM-DD` (UTC) and refuses a date in the past (exit 6).
⚠️ `decided_via_alert_id` is never written by anything (its caller was removed), so do not filter
on it to find "decisions made via an alert". An empty triage column means "nobody has triaged
this finding", not "this finding is fine".

### Sort and filter the Inbox list by last activity

`alerts list` can order by, and be limited to, the time of an item's last activity: the newest meaningful change
(raised, decided, assigned, moved between states, re-rated, a member joined or left, a comment, facts that really
changed). A rule pass that only re-saw the item is not one, and neither is a reinstall carry-over, so this is not
`updated_at`. For an entry it includes its members' activity. The default order is unchanged.

```bash
"$TORANA" alerts list --sort newest --since 2d                    # changed in the last two days, newest first
"$TORANA" alerts list --sort oldest --since 30d --box needs_attention
"$TORANA" alerts list --from 2026-10-01T00:00:00Z --to 2026-10-03T00:00:00Z
"$TORANA" alerts list --sort priority                             # the ranking's order
```

`alerts boxes` takes the same `--cve` / `--cwe` / `--since` / `--from` / `--to`, so a count and its list ask the same question.
`--cve CVE-…` / `--cwe CWE-…` list only the entries holding a live finding for that CVE (or with that CWE), plus
ungrouped findings that match directly; the counts take the same filters. `--since` takes 24h, 2d, 7d or 30d and cannot be combined with `--from`. The LAST ACTIVITY column and the
`last_activity_at` / `last_activity_label` JSON fields carry the value. `workspace <id> alerts list` takes the same options.

### Code findings: links to GitHub, and switching code reading off

`alert <id> get` on a code finding prints `CODE IN GITHUB`: the file, its flagged lines and the scanned commit
(`src/api/v1/admin.py L148, L370 at 7acd0a2`, or "on the default branch (not pinned to the scanned commit)" when no commit
is known), then the file's URL. No command prints customer code; the link is where to read it. The triage agent may read the
code around the flagged lines through a GitHub integration, on by default, nothing kept. To stop that for one integration:

```bash
"$TORANA" integration <INTEGRATION_ID> patch --code-context off     # on to allow it again
"$TORANA" integration <INTEGRATION_ID> get                          # shows "Code reading by triage: on|off" (GitHub only)
```

### Drill into a CVE or a CWE across an app's ranked findings

`alerts drill-down` answers "what does the platform hold about this CVE (or CWE) here?" from the datalake
`posture_findings` population. The path is `alerts drill-down` (the collection group), not `alert drill-down`
(the singular `<ID>` group). `--workspace-id` is required.

```bash
"$TORANA" alerts drill-down cve CVE-2026-33845 --workspace-id <ws>        # counts, intel, breakdowns, look-here, top instances
"$TORANA" alerts drill-down cve CVE-2026-59822 --workspace-id <ws> --blast-radius --ecosystem pypi --package litellm --version 1.82.6
"$TORANA" alerts drill-down cve CVE-2026-59822 --workspace-id <ws> --upgrade-delta --ecosystem pypi --package litellm \
    --installed 1.82.6 --target 1.84.0
"$TORANA" alerts drill-down cwe CWE-89 --workspace-id <ws>                 # code hotspots, rules, earlier decisions, package CVEs
```

The default view is LIVE: open findings whose item state is not `no longer deployed` or `fixed at source`; the rest
appears as one line of counts. Read `drill_down_available` on an alert/entry to know whether a drill-down exists.
`--blast-radius` works for pypi, golang, npm and maven only; "the entity graph has no node for this package version"
means the graph has no such node, not that nothing is affected. `--upgrade-delta` compares OSV records; "none known
introduced" is never a guarantee. `--format json` returns the API response untouched.

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

### Find dead-lettered triage jobs (SA only)

A triage job that exhausts its retries goes `dead` and never runs again on its own.

```bash
"$TORANA" pipeline overview agent_invocation        # DEAD RECOVERABLE / DEAD PERMANENT counts
# every dead row; or split with dead-recoverable / dead-permanent
"$TORANA" pipeline queue agent_invocation entries list --bucket dead --tenant-id <TENANT_UUID>
"$TORANA" pipeline queue agent_invocation entries list --bucket dead-recoverable --tenant-id <TENANT_UUID>
"$TORANA" pipeline requeue agent_invocation --tenant-id <TENANT_UUID> --dry-run   # what a requeue would revive
```

**Recoverable** means the job's LAST error was `transient` or `rate_limit`; everything else dead
is **permanent** (fix the cause, don't requeue). Each row's `dead_class` column holds this verdict.
Overview, the buckets, `requeue --recoverable-only`, `entry <id> get` and the alert's
`triage_failure.recoverable` all read it, so they always agree. A job that used up every attempt
is **not** recoverable for that reason alone: look at its kind.

⚠️ Each row carries `workspace_id`: check it before attributing a dead job to an app.

### Find alerts whose triage FAILED (tenant)

`verdict: null` + `triage_running: false` reads the same for an alert never triaged and one
whose triage crashed. `triage_failure` (on `alert get` and every list row) tells them apart:
`failed` = dead-lettered, will not retry on its own; `retrying` = the platform will try again.
A later successful attempt clears it.

```bash
"$TORANA" alerts list --workspace-id <UUID> --inbox-rows --triage-failure failed   # needs a person
"$TORANA" alerts list --workspace-id <UUID> --triage-failure any                   # failed or retrying
"$TORANA" alerts boxes --workspace-id <UUID> --inbox-rows   # last line: triage failed / retrying counts
"$TORANA" alert <ALERT_ID> get                              # TRIAGE line: attempts, when, error
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

⚠️ **"It appeared in the schema" is exactly the rule that produced the problem.** A shipped
library of reviewed SQL definitions (since retired) and the question corpus were authored that way, before this check existed:
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
