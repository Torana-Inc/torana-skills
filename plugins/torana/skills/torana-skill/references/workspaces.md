# Workspaces — Torana Platform

> **UI vs CLI terminology:** The platform UI shows these as **Apps**. The CLI and API call them **Workspaces**. They are the same thing. When a user says "app" or "my app", use `workspaces`/`workspace` in all CLI commands.

Workspaces are the primary organizational unit in Torana — tenant-scoped containers
that group security rules, dashboards, plans, playbooks, and workflows into a coherent
operational context.

---

## Core Concepts

### What a Workspace Contains

| Resource | Description |
|---|---|
| **Rules** | Detection rules assigned to this workspace |
| **Dashboards** | Security dashboards pinned or assigned |
| **Plans** | Remediation plans linked to the workspace |
| **Playbooks** | Response playbooks configured for this context |
| **Workflows** | Automation workflows scoped to this workspace |
| **Transformers** | Data transformers running in workspace context |
| **Alert routes** | How alerts generated in this workspace are routed |

### States

| State | Meaning |
|---|---|
| `active` | Workspace is running; rules evaluate, alerts fire |
| `inactive` | Created but not yet activated |
| `archived` | Soft-deleted; preserved for audit, not operational |

---

## CLI Hierarchy — Plural/Singular Split

The CLI follows a **plural/singular split**:
- `torana workspaces <verb>` — collection operations (list, create, summary)
- `torana workspace <UUID> <verb>` — instance operations on a specific workspace

Resolve the workspace ID before instance operations:
```bash
WS_ID=$("$TORANA" workspaces list --search "<name>" --state active --json --raw | jq -r '.[0].id')
```

---

## Typical Workflows

### List workspaces

```bash
"$TORANA" workspaces list
"$TORANA" workspaces list --format table
"$TORANA" workspaces list --state active
"$TORANA" workspaces list --search "prod"
"$TORANA" workspaces list --all --format json
```

### Get workspace details

```bash
"$TORANA" workspace "$WS_ID" get
```

### Create a workspace

```bash
"$TORANA" workspaces create \
  --name "Production Security" \
  --description "Production environment monitoring" \
  --icon fa-shield

# Idempotent — returns existing if name already taken:
"$TORANA" workspaces create --name "Production Security" --if-not-exists

# From a file:
"$TORANA" workspaces create --file workspace.yaml
```

### Install an APP BUNDLE at creation (starter apps)

An **app bundle** is a frozen, multi-link starter app (dashboards, transformers, KPIs,
attention cards, rules) that installs into a workspace as a whole. `--bundle` replays the
bundle's recorded links into N real proposals + deployed artifacts at creation time.

⚠️ **`--bundle` and `--app-template` are mutually exclusive.** `--app-template` starts from
a bundled starter app for the type; `--bundle` installs a chained-proposal use-case app.

```bash
# 1. DISCOVER — the bundle ids, their versions, link counts, and the workspace TYPE
#    each one targets. ⛔ Note the group is `build bundles`, NOT `workspaces bundles`.
"$TORANA" build bundles list

# 2. INSTALL — --type must match the TYPE column from step 1, or the bundle is rejected.
"$TORANA" workspaces create \
  --name "CISO Posture" \
  --type vulnerability_management_v2 \
  --bundle ciso_posture

# 3. STATUS — install is ASYNCHRONOUS. `create` returns a workspace id immediately,
#    while INSTALL STATUS is still `installing`. Poll it to a terminal value.
WS_ID=<id printed by create>
"$TORANA" workspace "$WS_ID" get | grep -i "INSTALL STATUS"   # installing -> installed
```

⚠️ **`create` returning an id is NOT proof the app installed.** The bundle deploys in the
background; a workspace can sit at `installing` for minutes (measured: ~3 min for a 7-link
bundle, ~70s for a 4-link one) and can end at `failed`. Always poll to a terminal status
before reporting success:

```bash
for i in $(seq 1 60); do
  S=$("$TORANA" workspace "$WS_ID" get 2>/dev/null | grep -i 'INSTALL STATUS' | awk '{print $3}')
  echo "[$i] $S"; case "$S" in installed|failed) break;; esac; sleep 10
done
```

**Verify the install actually materialized artifacts** — a green status is necessary, not
sufficient:

```bash
"$TORANA" workspace "$WS_ID" home config dump --format json   # zones + pinned widgets
"$TORANA" rules list --workspace-id "$WS_ID"                  # the operational loop
```

⚠️ **Rules take `--workspace-id`; routes and schedulers do NOT** — those use the
workspace-scoped form (`"$TORANA" workspace "$WS_ID" alert-routes list`). Passing
`--workspace-id` to them errors.

#### Install `failed`? Just re-run `install`

An install is serial and fail-fast with **no rollback**: the links before the failure are
real, valid app-versions. So `install` is idempotent by state — it resumes a failed try
(re-running ONLY the links that did not deploy), watches an in-flight one, and no-ops when
already installed. There is no separate recovery verb to remember, and nothing is deleted:
the failed job is kept as the audit record.

```bash
"$TORANA" workspace "$WS_ID" build bundles install ciso_posture   # install OR resume
"$TORANA" workspace "$WS_ID" build bundles install-detail         # why it failed
```

⚠️ **Never reach for `workspaces create --bundle` to retry** — that builds a NEW workspace.
Re-running `install` on the EXISTING one is the retry.

The workspace-scoped form (`workspace <id> build bundles …`) needs no ids and is the natural
path; the top-level `build bundles <verb> "$WS_ID"` takes the workspace explicitly, for
scripting. The job id is only ever something you READ (`install-detail` prints it).

> **Authoring or changing a bundle is a different job.** These commands INSTALL an
> existing bundle. Bundles are platform source (`app_bundles/<id>.py`) authored via the
> **`torana-app-bundle`** skill, which owns the validator gates and the regeneration path.

### Update a workspace

```bash
"$TORANA" workspace "$WS_ID" update --file workspace-update.yaml
```

### Lifecycle operations

```bash
"$TORANA" workspace "$WS_ID" activate    # inactive → active
"$TORANA" workspace "$WS_ID" archive     # soft-delete; preserves data
"$TORANA" workspace "$WS_ID" delete      # permanent removal
"$TORANA" workspace "$WS_ID" set-default
```

---

## Inspecting Workspace Contents

### Rules

```bash
"$TORANA" workspace "$WS_ID" rules
```

### Dashboards

```bash
"$TORANA" workspace "$WS_ID" dashboards
```

### Plans

```bash
"$TORANA" workspace "$WS_ID" plans
"$TORANA" workspace "$WS_ID" plans --status open
```

### Playbooks

```bash
"$TORANA" workspace "$WS_ID" playbooks
```

### Workflows

```bash
"$TORANA" workspace "$WS_ID" workflows
```

### Transformers

```bash
"$TORANA" workspace "$WS_ID" transformers
```

### Alert routes

```bash
"$TORANA" workspace "$WS_ID" alert-routes
```

---

## AI Home — the generated operator home page

A per-workspace page that is **generated by a run and served from storage**, not derived on
load. It answers, in one fixed order: what needs you · what is wrong · what you cannot see.

⭐ **The governing rule: a number never appears without its coverage.** Every measure is
`measured`, `partial` or `blind`, and a blind measure states what it cannot see rather than
rendering a zero. Coverage is resolved SERVER-SIDE — never re-derive it.

```bash
# Read the current page
"$TORANA" workspace "$WS_ID" ai-home get
"$TORANA" workspace "$WS_ID" ai-home get --format json

# Generate a new one (Torana harness: collect facts -> narrate -> critique -> persist).
# ⚠️ SYNCHRONOUS — the request waits ~20-40s for the LLM. Not yet a 202 + poll.
"$TORANA" workspace "$WS_ID" ai-home run

# What this app CANNOT answer yet, and who can fix it
"$TORANA" workspace "$WS_ID" ai-home gaps

# Run history — shows which harness produced each page
"$TORANA" workspace "$WS_ID" ai-home runs

# Inspect ONE run — stages, critique rounds, findings, and the config
# fingerprint that produced it.
# ⛔ Nested under the workspace, NOT `torana admin`: a run belongs to the app
# whose page it produced (same shape as `workspace <id> sweeps get`).
"$TORANA" workspace "$WS_ID" ai-home run-detail "$RUN_ID"

# Per-ZONE feedback (Z0..Z6, or 'page')
"$TORANA" workspace "$WS_ID" ai-home feedback --run-id "$RUN" --zone Z5 --rating -1 \
  --comment "the questions read as filler"
```

### Authoring a page yourself (the `torana-ai-home` skill's loop)

Two commands make this possible: `facts` returns the assembled data **un-narrated**, and
`deposit` posts a finished page back. Same tables, same schema, same page as the Torana
agents write to.

```bash
"$TORANA" workspace "$WS_ID" ai-home facts --output facts.json
# ... write the narration, self-critique it, assemble run.json ...
"$TORANA" workspace "$WS_ID" ai-home deposit -f run.json
```

⛔ **Deposit is mechanically validated and a 422 persists NOTHING.** It rejects a citation
naming anything absent from the facts payload, a coverage state that contradicts the
server's, a blind question carrying a number, and an empty-but-present blind block. The
error names the offending claim so it can be corrected and re-deposited.

⚠️ `get` returns **404 when the page has never been generated** — a state, not an error.

### Reading the STATUS of a run — `success` is not the only good outcome

`runs` and `run-detail` report one of four terminal statuses. Two are servable pages:

| status | meaning |
|---|---|
| `success` | narrated, and every collector read cleanly |
| `partial` | narrated, but at least one source could not be read — the facts are incomplete |
| `data_only` | facts collected, **NO narration** — the page renders numbers without prose |
| `failed` | nothing servable |

⛔ **`data_only` is a REAL page, not a failure.** When narration is unavailable the page
degrades to the numbers rather than to a blank screen — the numbers are already in hand.

⭐ **But it is NOT a success, and the distinction is the point.** Until 2026-09-04 an
un-narrated run was recorded as `success`, so a page reading "(no narration — showing
measured data only)" looked green in every status column and metric while the narration
half of the feature was entirely unwired. Status is now DERIVED from what was actually
produced, never claimed by the caller.

⚠️ **`data_only` and `partial` are orthogonal, not a severity ladder.** A run can be
data-only with clean collectors, or narrated with a failed one. If you see `data_only`,
the narration agent is the thing to investigate — `run-detail` shows the attempted rounds
even when none produced a draft.

## Health and Observability

### Summary statistics (all workspaces)

```bash
"$TORANA" workspaces summary
"$TORANA" workspaces summary --format json
```

### Runtime stats (per workspace)

```bash
"$TORANA" workspace "$WS_ID" runtime-stats
```

### Activity log

```bash
"$TORANA" workspace "$WS_ID" activities
"$TORANA" workspace "$WS_ID" activities --page-size 50
```

### Landing page

```bash
"$TORANA" workspace "$WS_ID" config     # get landing page config
"$TORANA" workspace "$WS_ID" state      # get landing page state
"$TORANA" workspace "$WS_ID" sweep      # trigger widget rebuild
"$TORANA" workspace "$WS_ID" graph      # app-graph (nodes + edges)
"$TORANA" workspace "$WS_ID" graph --mermaid
```

---

## KPI Cards, Attention Cards, Pinned Widgets

```bash
# KPI cards
"$TORANA" workspace "$WS_ID" kpi list
"$TORANA" workspace "$WS_ID" kpi add --title "..." --sql "SELECT ..." --format number
"$TORANA" workspace "$WS_ID" kpi remove --kpi-id <UUID>

# Attention cards
"$TORANA" workspace "$WS_ID" attention list
"$TORANA" workspace "$WS_ID" attention add --title "..." --condition "..." --severity critical
"$TORANA" workspace "$WS_ID" attention remove --attention-id <UUID>

# Pinned widgets
"$TORANA" workspace "$WS_ID" pinned list
"$TORANA" workspace "$WS_ID" pinned add --widget-id "$WIDGET_ID" --dashboard-id "$DASHBOARD_ID"
"$TORANA" workspace "$WS_ID" pinned remove --widget-id "$WIDGET_ID"
```

---

## Program Advisor and Proposals (workspace-scoped)

### How proposals are generated

**Bootstrap and refresh are the same operation.** Bootstrap runs automatically when a
workspace is first created. Refresh re-runs the same sweep when new data arrives. Both
produce proposals — security program recommendations tailored to the workspace's data.
There is no separate "setup" step: every sweep is expected to produce proposals.

A user can trigger a fresh sweep at any time by clicking **Refresh** on the Build page
(or running `advisor refresh` in the CLI).

### The `advisor` group is the single entry point

All proposal and sweep operations live under `workspace <id> advisor`. There is no separate `build` group.

### Correct workflow when proposals are empty

If `proposals list` returns 0 items:

1. **Run `advisor status` first.** Check the `running` field.
   - If `running=True`: a sweep is already in progress — **do not trigger another one.**
     Wait for it to finish, then re-check proposals.
   - If `running=False`: go to step 2.

2. **Check when the sweep completed.** The `advisor status` output includes a completion
   timestamp (`LAST RUN` / `COMPLETED AT`). Compare it to the current time.
   - If completed **less than 30 seconds ago**: wait and re-check — there can be a brief
     lag between sweep completion and proposals appearing in the list.
   - If completed **more than 30 seconds ago** and proposals are still 0: **ask the user**
     whether to trigger another advisor sweep. Never trigger it autonomously.

3. **If you already see some proposals and `running=True`**: those are partial results.
   More may appear when the sweep completes. Wait before drawing conclusions.

### Proposal generation time — when to flag a problem

Proposal generation normally completes within **5 minutes**, measured from the sweep's
own `STARTED AT` timestamp in `advisor status` output. If `running=True` and more than
5 minutes have elapsed since `STARTED AT`, the sweep may be stuck.

When that happens:
1. Wait another minute and re-check — transient slowness is possible
2. Ask the user if they want to trigger a fresh refresh: `workspace "$WS_ID" advisor refresh`
3. If that also hangs, escalate to a platform admin — the advisor background task
   may need to be restarted

Never trigger a new sweep autonomously to "fix" a stuck one — always ask first.

### Working with proposals

```bash
# Trigger proposal generation
"$TORANA" workspace "$WS_ID" advisor refresh             # re-run sweep and regenerate proposals

# Check status
"$TORANA" workspace "$WS_ID" advisor status              # see if sweep is running + proposal count

# List proposals
"$TORANA" workspace "$WS_ID" proposals list --all --json --raw

# Suppressed proposals
"$TORANA" workspace "$WS_ID" proposals suppressed

# Act on a specific proposal
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" --help    # discover available actions
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" build
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" status
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" approve
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" reject
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" mark-committed

# Advisor advanced lifecycle
"$TORANA" workspace "$WS_ID" advisor bootstrap           # initial sweep (runs automatically on create)
"$TORANA" workspace "$WS_ID" advisor status              # check sweep state + proposal count
"$TORANA" workspace "$WS_ID" advisor artifacts
"$TORANA" workspace "$WS_ID" advisor environment-snapshot
"$TORANA" workspace "$WS_ID" advisor invalidate-cache
"$TORANA" workspace "$WS_ID" advisor reset-all-sessions  # SA only
```

### Building a proposal

`proposal build` creates an agent chat session, fires the first turn with the proposal
as context, and returns immediately with the session and agent IDs. The build is a
multi-turn HITL conversation — you drive it entirely from the CLI.

**Correct flow:**

```bash
# 1. Kick off the build — prints session, agent, turn IDs + CLI commands
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" build

# Example output:
# Session:        agent_5cae3885-..._ws_743af014_bfd89a37b3d5
# Agent:          5cae3885-cfcd-4eb5-beb4-9bf2b5263ebf
# Turn ID:        <turn_id>
#
# Monitor:        torana agent 5cae3885-... session agent_5cae3885-..._ws_743af014_... chat get
# Continue:       torana agent 5cae3885-... session agent_5cae3885-..._ws_743af014_... chat -m "your message"
# Detail:         torana workspace <WS_ID> proposal <PID> status

# 2. Watch what the agent said in its first turn
"$TORANA" agent "$AGENT_ID" session "$SESSION_ID" chat get

# 3. Respond to the agent (drives the HITL conversation)
"$TORANA" agent "$AGENT_ID" session "$SESSION_ID" chat -m "Yes, proceed with the KEV watchlist rule"

# 4. Check proposal + browser URL at any time
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" status
```

**Session ID is always explicit** — there is no local session cache. Every `chat` command
requires `--session-id`. Get it from `proposal build` output or `proposal status`.

**`proposal status`** shows the proposal's current claim state (which session owns it,
which agent), CLI monitoring commands with the session ID already embedded, and the browser URL.

Do not construct browser URLs manually — always get them from `proposal status`.

---

## Sweeps (workspace-scoped)

```bash
"$TORANA" workspace "$WS_ID" sweeps list
"$TORANA" workspace "$WS_ID" sweeps list --mode bootstrap --status success
"$TORANA" workspace "$WS_ID" sweeps get <SWEEP_ID>
"$TORANA" workspace "$WS_ID" sweeps diff --a <SWEEP_A> --b <SWEEP_B>
"$TORANA" workspace "$WS_ID" sweeps retire <SWEEP_ID> --reason "stale"
```

Cross-workspace sweep inspection (SA only):
```bash
"$TORANA" advisor sweeps list
"$TORANA" advisor sweeps list --tenant-id <UUID>
"$TORANA" advisor sweeps get <SWEEP_ID>
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Workspace shows no rules | Rules not yet assigned | Check `workspace "$WS_ID" rules` |
| `state: inactive` after create | Needs explicit activation | `workspace "$WS_ID" activate` |
| Landing page widgets empty | Sweep hasn't run | `workspace "$WS_ID" sweep` then check `state` |
| 409 on create | Name already taken | Use `--if-not-exists` or update the existing one |
| `activities` returns empty | No actions recorded yet | Normal for newly created workspaces |
| No advisor proposals | Workspace never swept | `workspace "$WS_ID" advisor bootstrap` |
| Proposals still generating after 5+ minutes | Advisor sweep may be stuck | Check `advisor status`; try `advisor refresh`; escalate to admin if still stuck |

---

## Frontend URL Patterns

The base URL for all FE links is the same `base_url` the CLI uses (configured in
`$SKILL_DIR/config/base-url.yml`). When presenting results to the user, always include
direct links so they can click through without searching.

### Workspace pages

| Destination | URL pattern |
|---|---|
| Workspace home (landing page) | `{base_url}/workspaces/{ws_id}` |
| Rules tab | `{base_url}/workspaces/{ws_id}?view=rules` |
| Dashboards tab | `{base_url}/workspaces/{ws_id}?view=dashboards` |
| Playbooks tab | `{base_url}/workspaces/{ws_id}?view=playbooks` |
| Transformers tab | `{base_url}/workspaces/{ws_id}?view=transformers` |
| Alert routing tab | `{base_url}/workspaces/{ws_id}?view=alert-routing` |
| Alerts tab | `{base_url}/workspaces/{ws_id}?view=alerts` |
| Workflows tab | `{base_url}/workspaces/{ws_id}?view=workflows` |
| Scheduler tab | `{base_url}/workspaces/{ws_id}?view=scheduler` |
| Documents tab | `{base_url}/workspaces/{ws_id}?view=documents` |
| Data tab | `{base_url}/workspaces/{ws_id}?view=data` |

### Deep links to specific artifacts

| Artifact type | URL pattern |
|---|---|
| Specific rule (opens detail modal) | `{base_url}/workspaces/{ws_id}?view=rules&ruleId={rule_id}` |
| Specific dashboard (opens it selected) | `{base_url}/workspaces/{ws_id}?view=dashboards&dashboard_id={dashboard_id}` |

> **Note:** Playbooks, transformers, and alert routes have tab-level links only — the FE
> does not yet support deep-linking to a specific item within those tabs.

### Global pages (not workspace-scoped)

| Destination | URL pattern |
|---|---|
| Alerts list (all workspaces) | `{base_url}/alerts` |
| Specific alert | `{base_url}/alerts/{alert_id}` |
| All dashboards | `{base_url}/analytics/dashboards` |
| Integrations | `{base_url}/integrations` |
| Workflows | `{base_url}/workflows` |
| Playbooks | `{base_url}/playbooks` |

### Resolving base_url at runtime

```bash
BASE_URL=$("$TORANA" config get base-url 2>/dev/null)
```

Always use `{BASE_URL}/workspaces/{WS_ID}` — never hardcode a hostname.

---

## Best Practices

1. **Use `--if-not-exists`** for idempotent creation in scripts.
2. **Archive instead of delete** — archived workspaces retain audit history.
3. **Inspect contents before archiving** — check `rules`, `plans`, and `alert-routes` are handled.
4. **`sweep` after bulk changes** — landing page state is not updated in real-time.
5. **Always run `--help` first** — flags evolve with CLI releases.

---

## Command Reference

Use plural to list, then singular + `--help` to discover instance commands:

```bash
"$TORANA" workspaces list               # get workspace IDs
"$TORANA" workspace <UUID> --help       # see all commands for that workspace
"$TORANA" workspaces --help
"$TORANA" workspaces create --help
"$TORANA" workspace <UUID> kpi --help
"$TORANA" workspace <UUID> advisor --help
"$TORANA" workspace <UUID> proposals --help
```
