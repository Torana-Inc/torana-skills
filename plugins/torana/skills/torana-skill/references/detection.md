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
- `status` — `open`, `triaging`, `awaiting_input`, `pending_remediation`, `escalated`, `resolved`, `closed`
  (`false_positive` is a verdict and a closing reason, never a status; the list is what `alerts list --status` accepts)
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
  Its GRAPH NODE column is the entity-graph node a member is about (e.g. a group check's server,
  `host:servicenow/<id>`), filled ONLY when that node is on a live edge, so `torana entity-graph neighbors <key>`
  (or the UI `/entity-graph/explore?seed=<key>`) opens it; text mode ends with "K of N member(s) have a node". Empty
  means no node, not a failure: IP and account members (shadow IPs, no-2FA accounts) have none today.
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
  lines, rule, whether the code ships to running services, owner), `group_check` (an alert that stands for a group
  its rule declared, e.g. a CMDB check: section "The check", "N open of M rows this check groups", read from the
  alert's own `members_open` / `member_count`), `group_member` (ONE row of such a check: section "row" names the check,
  and "── Row path" draws the row's own path, e.g. `Internet —flagged by SOC-EXP-002 · RDP (3389)→ crd-db-p02 —owned
  by→ infra-windows`: the evidence its check returned plus the entity graph around its node; each edge is reported
  unless marked `(derived)`, the check's own conclusion, or `(heuristic ?)`, a host matched to the CMDB by name;
  `torana alert <check id> members` lists the row ids); each also carries the alert's own facts. A code
  scanner never reports a finding as closed: it is gone only when a later scan stops listing it, and the claim says
  so. Any other item prints "No proof model for this item type yet (…)". That means not modelled, not "no
  evidence". Cite a claim's text rather than re-deriving it, and say "not recorded" when the claim says so.

```bash
"$TORANA" alert <alert-id> proof                          # every claim, by section
"$TORANA" alert <alert-id> proof --claim stale            # what "Is this item still true?" was read from
"$TORANA" alert <alert-id> proof --save /tmp/proof.json   # keep it to verify or replay later
```

  `torana alert <id> assessment` answers a question no row states. Today the question is **effort**: how big the fix
  is, as a range of days, for an upgrade (`fix_entry`) or a code finding (`code_finding`). The platform computes it
  from rows it already holds (versions in use and the target, the number of images or services). It is marked
  `◈ assessed`: an estimate, a different kind from `measured` and `derived`, and never a proven fact. In
  `alert <id> proof` the same claims are section "Effort", with the estimate tagged `[assessed]`.
  ⛔ The estimate is the platform's. Quote the line as printed ("Medium · 1.75 to 3.5 days"); never restate it in
  other units, round it, add to it, or compute your own. An argument does not move the number; only evidence does.
  What it prints, top to bottom: the line; "Based on N checks. K more are not available yet." (how strong the
  estimate is: the checks that are in, and how many that could strengthen it cannot be run yet); "How we got this", one row per part (Edit, Review, Test,
  Rollout) with its reason and its days, then "Estimate" (their sum, the low end) and one sentence saying why the
  answer is a range and what its high end is; "What it rests
  on", the checks that are in (`✓`); "Not checked yet:", the missing checks (`○`), each with a STATEMENT of what is
  not known; `*` marks the ones that matter most to the accuracy of the estimate. ⛔ A missing check is not something
  the user can switch on: the platform cannot run it yet. An instruction (connect, allow, define, run) is printed
  only under "What you can do now", which appears only when the platform can act on it (`ask_ready`); today it never
  appears. When you report an estimate, say how many checks it is based on and what is not checked yet; never tell
  the user to enable, connect or allow something this command did not print under "What you can do now".
  "Not estimated: …" means there is nothing left to change (the checks are still printed). An item type with no
  assessment yet (a mitigation, a vulnerability in an image) prints "No assessment for this kind of item yet (…)" and
  exits 3. `--format json` is the route's body: per assessment `line` (with the evidence count), `short`, `estimate`
  (with `parts` and `range_note`), `claims`, `rests_on` and `coverage` (`not_available`, and `passes`, each with `gap`, `ask` and `ask_ready`).
  Read-only, any tenant user (`datalake:read` + `alert:read`).

```bash
"$TORANA" alert <alert-id> assessment                     # the estimate, its split, and each pass in or missing
"$TORANA" alert <alert-id> assessment --format json       # the same, as data
```

  The item's **AI brief** (`torana alert <id> brief`, and `brief write` to write one) is described in [inbox.md](inbox.md).

### The Inbox view of an item

⭐ `torana alert <id> view [--section ...]` is the item exactly as the Inbox shows it, and `torana alerts cve|cwe` is a CVE or
CWE across an app. Everything about reading and deciding Inbox items is in [inbox.md](inbox.md). This file stays about rules,
alerts as the engine raises them, and alert routing.

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

1. **Use rule tags to understand routing** — Rules carry tags (e.g., `compliance:soc2`, `asset-type:cloud`) that routes filter on; read them to see where an alert was sent.

2. **Review execution logs** — `rule-execution-logs` show whether a rule is running and how many alerts it generates per run.

3. **Acknowledge alerts promptly** — Open alerts represent active findings. Use `alerts acknowledge` to track which alerts are being worked.

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

### Triage alerts

```bash
# List open alerts
"$TORANA" alerts list --status open

# Filter by severity
"$TORANA" alerts list --severity critical --format table

# True positives whose relied-on deployment is NO LONGER RUNNING
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

# Record a verdict (the full set of decision commands is in "Decide an item" above)
"$TORANA" alert <alert-id> verdict --triage-verdict true_positive --reason-code <code> --proposed-fix "<one sentence>"

# Close it, with the reason
"$TORANA" alert <alert-id> close --reason accepted_risk --message "<why>"

# Mark as a false positive: a verdict, then (if you are closing it) a closing reason
"$TORANA" alert <alert-id> verdict --triage-verdict false_positive --reason-code <code>
"$TORANA" alert <alert-id> close --reason false_positive
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

### Search the Inbox (`--search`, the Inbox's search box)

Which command answers which Inbox question (one item, text, a property, counts and joins) is the route rule in [inbox.md](inbox.md), "Choosing the route"; this section is the `--search` detail.

⭐ **To find Inbox items that mention a package, image, service, host, file, CVE or phrase, use `--search`** rather
than paging the list and grepping it. An entry matches when the text is in its own title, matched row, summaries or
finding key, OR in ANY finding grouped inside it.
A row titled "Upgrade <package> to <version>: clears <N> findings" is listed for a search on <service> when some of the
findings it clears are on <service>.
Grepping the list's names
misses exactly those.

```bash
"$TORANA" alerts list --workspace-id <UUID> --search <service> --box needs_attention      # MATCHED column says where
"$TORANA" alerts list --workspace-id <UUID> --search '<package> <service>'                # every word must appear
"$TORANA" alerts list --workspace-id <UUID> --search '"<phrase>" -<word>' --all           # phrase, minus a word
"$TORANA" alerts boxes --workspace-id <UUID> --search <package>                           # the tab counts for it
"$TORANA" workspace <UUID> alerts list --search <text> --format json \
  | jq '.items[] | {name, m: .search_match}'                                                # where each row matched
```

- Rules: case-insensitive substring; words AND; `"quoted phrase"` is one term; `-word` excludes entries that mention
  it anywhere. At most 200 characters and 8 terms (more is a 422 naming the limit).
- It combines with every other filter (`--severity`, `--verdict`, `--category`, `--box`, `--cve`, `--since`, …). Those
  stay flags: the CLI searches a `key:value` word as literal text, because finding keys hold colons. The screen's search box may read some `key:value` words (such as `severity:high`) as filters, so the same text can give a different list there; use the flag for a filter.
- `alerts boxes` takes the same `--search`, so a count and its list agree.
- Each searched row carries `search_match`: `where` (`findings` | `title` | `fact` | `text` | `finding_key`),
  `field`, `snippet`, `findings_matched` of `findings_total`, and `matched_findings` (up to 50 lines). In text
  output this is the MATCHED column. A `findings` hit is a grouped finding; open the entry with
  `alert <id> members` or `alert <id> view` to see it in context.
- API: `GET /api/v2/alerts?q=…` and `GET /api/v2/alerts/facet-counts?q=…`.

### Code findings: links to GitHub, and switching code reading off

`alert <id> get` on a code finding prints `CODE IN GITHUB`: the file, its flagged lines and the scanned commit
(`src/api/v1/admin.py L148, L370 at 7acd0a2`, or "on the default branch (not pinned to the scanned commit)" when no commit
is known), then the file's URL. No command prints customer code; the link is where to read it. The triage agent may read the
code around the flagged lines through a GitHub integration, on by default, nothing kept. To stop that for one integration:

```bash
"$TORANA" integration <INTEGRATION_ID> patch --code-context off     # on to allow it again
"$TORANA" integration <INTEGRATION_ID> get                          # shows "Code reading by triage: on|off" (GitHub only)
```

### Look at a CVE or a CWE across an app's ranked findings

See [inbox.md § A CVE or a CWE across an app](inbox.md#a-cve-or-a-cwe-across-an-app).

### Operator commands

These still run, with the same behaviour, but are not listed by `--help` because a customer's Claude should meet the
Inbox commands first: `alerts reconcile-owners`, `alerts reconcile-sla`, `alerts regroup`, `alerts create`,
`alerts triage-agents`, `alerts by-rule-by-rule-id`, `alerts by-suite-by-suite-id`, `alerts suite-rule`,
`alert <id> compress-context`, `alert <id> invoke`, `alert <id> cancel`. Use them only when an operator asks.

### Set up alert routing

```bash
# List existing routes
"$TORANA" alert-routes list

# Create a route with flags (Slack destination, critical alerts only)
"$TORANA" alert-routes rules \
  --workspace-id <WS_UUID> \
  --name "Critical alerts to Slack" \
  --severity-levels critical \
  --destination-type slack \
  --destination-config '{"webhook_url": "https://hooks.slack.com/..."}'
# or from a file: alert-routes create --name "Critical alerts" --file route.yaml
# Read an existing route as a model for the file: alert-route <route-id> get --format yaml

# Try the routing rules against a sample alert (a JSON/YAML file of alert data)
"$TORANA" alert-routes routing-test --input sample-alert.yaml
```

`alert-route <id> test` is listed in `--help` but does not work yet (it calls a route the platform does not serve): use
`alert-routes routing-test`. `alert-route <id> enable|disable|update|patch|move|delete` are the other per-route verbs.

### Find alerts whose triage FAILED (tenant)

`verdict: null` + `triage_running: false` reads the same for an alert never triaged and one
whose triage crashed. `triage_failure` (on `alert get` and every list row) tells them apart:
`failed` = dead-lettered, will not retry on its own; `retrying` = the platform will try again.
A later successful attempt clears it.

```bash
"$TORANA" alerts list --workspace-id <UUID> --entries --triage-failure failed   # needs a person
"$TORANA" alerts list --workspace-id <UUID> --triage-failure any                   # failed or retrying
"$TORANA" alerts boxes --workspace-id <UUID> --entries   # last line: triage failed / retrying counts
"$TORANA" alert <ALERT_ID> get                              # TRIAGE line: attempts, when, error
```

### View active dashboards

```bash
"$TORANA" active-dashboards list      # list/create/delete only — there is no `get`
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
v1.0 (2026-04-16) - Initial CLI-based detection skill
-->
