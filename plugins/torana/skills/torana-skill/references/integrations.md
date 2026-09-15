# Integrations — Torana Platform

Torana integrations connect the platform to external tools and pull security,
development, and operational data into the Torana datalake via scheduled or
on-demand sync.

---


## Integration categories and their contracts (SUPER-ADMIN)

Every integration source declares what KIND of tool it is — 102 sources, 28 families,
12 categories. Snyk and Qualys are `security_scanner`; Jira is `project_management`;
GitHub is `vcs`; GitLab is four things at once.

```bash
TORANA_PROFILE=SA torana integrations categories               # the 12, and which have a model
TORANA_PROFILE=SA torana integrations category-map             # every family -> its categories
TORANA_PROFILE=SA torana integrations family-categories jira   # one family, per data source
TORANA_PROFILE=SA torana integrations category security_scanner  # the CONTRACT for that kind
```

**10 of 12 categories carry a MODEL** — what a tool of that kind must produce, and which table
it writes to. A `security_scanner` owes `cve_id`, `severity`, a readable description, and
targets `vulnerabilities`; a `project_management` tool targets `issues`.

⚠️ **SA-only, deliberately.** Category models are platform curation, not tenant data. A tenant
profile is refused with a clear message.

⚠️ **Labels are SETS, and they come from what the tool IS — never from what its mapping
writes.** Deriving a label from destination tables is circular and ratifies bugs: `jira`'s
largest table by volume was `findings` **because its tickets landed in the wrong table**, so
table-derived labelling would have called Jira a scanner.

**To audit a mapping against its contract**, use the `torana-integration-model` skill —
missing required fields, written-but-empty, wrong table. Full detail:
`pantheon-integration/CLAUDE.md` § Category labels and category models.

---

## Core Concepts

### What Is an Integration?

A persistent, tenant-scoped configuration that tells Torana how to connect to an
external service and what data to collect. Every integration has four building blocks:

| Building Block | Description |
|---|---|
| **Provider** | The external system (e.g., `github`, `jira`, `wiz`) |
| **Credentials** | Secrets required to authenticate — API tokens, client IDs/secrets, etc. |
| **Data Sources** | The specific types of data the provider can supply |
| **Sync Config** | How often to sync, batch size, rate limits, incremental vs full |

### Known Providers

| Provider | Type | Auth |
|---|---|---|
| GitHub | `vcs` | Personal Access Token |
| GitLab | `vcs` | Personal Access Token |
| Jira | `project_management` | Email + API Token + URL |
| Slack | `communication` | Bot OAuth Token |
| Wiz | `security_scanner` | Client ID + Secret |
| Snyk | `code_scanner` | API Token |
| AWS Security Hub | `cloud_provider` | Access Key + Secret Key |
| Azure | `cloud_provider` | Client ID + Secret + Tenant ID |
| GCP | `cloud_provider` | Service Account JSON |
| Okta | `identity_provider` | API Token + Domain |
| CrowdStrike | `security_scanner` | Client ID + Secret |

Discover all providers and their exact required fields:

```bash
"$TORANA" integrations providers
"$TORANA" integrations providers-by-provider-name github
```

### States

| Field | Values | Meaning |
|---|---|---|
| `status` | `active`, `inactive`, `error`, `configuring` | Overall lifecycle |
| `is_active` | true/false | User intent: running or paused |
| `auth_success` | true/false/null | Last credential test (`null` = never tested). ⛔ **Never self-updates** — see "Re-checking authentication" below |
| `health_status` | `healthy`, `degraded`, `unhealthy` | Computed from sync performance |
| `last_sync_status` | `completed`, `failed`, `started` | Most recent sync result |

**Combined state interpretation:**

| is_active | auth_success | Meaning | Action |
|---|---|---|---|
| true | true | Healthy | Monitor |
| true | false | Running but creds broken | Fix access, then `integration <id> test-auth` |
| false | true | Paused, creds valid | Activate when ready |
| false | false | Paused + creds broken | Fix access, `test-auth` to confirm, then activate |

⚠️ **A `false` here may be STALE.** It reflects the last *explicit* test, not current
reality — so an integration whose access was fixed hours ago still reads `false`. Confirm
with `test-auth` before telling anyone their credentials are broken.

---

## Discovering Commands

Use plural to list, then singular + `--help` to discover instance commands:

```bash
"$TORANA" integrations list             # get IDs
"$TORANA" integration <id> --help       # see all commands for that integration
"$TORANA" integrations --help
```

## Typical Workflows

### Discover what's available

```bash
"$TORANA" integrations providers
"$TORANA" integrations providers-by-provider-name github
"$TORANA" integrations types
"$TORANA" integrations semantic --query "vulnerability scanner"
```

### List existing integrations

```bash
"$TORANA" integrations list
"$TORANA" integrations list --format json
```

#### ⛔ `STATE` and `HEALTH` answer DIFFERENT questions

`STATE` is the lifecycle — `active` / `paused`. `HEALTH` is whether the last sync
actually collected everything. **An integration can be `active` and `degraded` at
the same time**, and that combination is the one worth acting on.

| HEALTH | Means | What the customer does |
|---|---|---|
| *(blank)* | Last sync collected everything | nothing |
| `degraded` | Credential works, but some scope units could not be read | grant the missing permission on that project/account |
| `failed` | Last sync failed outright | check `last_sync_error` |
| `auth-fail` | The credential itself is rejected | re-authenticate |

⚠️ **Never read `active` as "healthy".** Until 2026-09-08 the API mapped a
`partial` sync to `completed`, so a GCP integration whose service account was
denied on 7 of its 18 data sources reported a clean success on every surface —
the reason existed only in the logs. If a user asks "why is this column/widget
empty?", check `HEALTH` before assuming the data is genuinely absent.

`--format json` keeps the raw `last_sync_status` (`partial` / `completed` /
`failed` / …) rather than the derived label, so scripts test the real value.

**Then get the per-source detail** — which sources were skipped, on which
project, and why:

```bash
"$TORANA" integration <ID> runs        # PROJECT / STATUS / REASON per scope unit
"$TORANA" integration <ID> scope       # what it is scoped to read, + dormant sources
"$TORANA" integration <ID> etl-health  # success rate, partial count, last failure
```

### Create an integration

Always check provider requirements first:

```bash
# 1. See what fields the provider needs
"$TORANA" integrations providers-by-provider-name github

# 2. Create
"$TORANA" integrations create \
  --name "Acme Corp GitHub" \
  --provider github \
  --config '{"access_token": "ghp_...", "organization": "acme-corp"}' \
  --data-sources repositories,pull_requests

# Or from a file:
"$TORANA" integrations create --file github-integration.yaml
```

### Activate an integration

```bash
"$TORANA" integration <integration-id> activate
```

### Re-checking authentication (after access is fixed OUTSIDE Torana)

```bash
"$TORANA" integration <integration-id> test-auth
```

**Use this whenever an access problem was fixed somewhere other than Torana** — a cloud
IAM grant landed, a token was re-issued, a firewall opened, a scope was added.

⛔ **`auth_success` has NO background writer.** There is no cron job, and the ETL sync
never touches the field. So after the customer fixes access, syncs quietly start
returning data while the integration still reports `auth_success: false` — two surfaces
disagreeing about the same integration, indefinitely, until someone runs this command.

`test-auth` re-runs the provider's live probe and writes **only** the auth flag (plus the
connection timestamp). It never touches config, status, or `is_active`, so it is safe to
run at any time, on any integration, in any state. It prints the provider's real reason:

```
Authentication: FAIL  [X]
  403 Forbidden — identity lacks resourcemanager.projects.get
  auth_success is now: False
```

**Why not the alternatives:**

| Instead of… | Why not |
|---|---|
| `integration <id> activate` | Also re-probes, but raises **400** when the probe fails, so it cannot record a negative verdict — and on success it also flips `status`/`is_active`. |
| `integration <id> update` | Only re-probes when the request carries a `config` block, and **re-sending config can destroy stored secrets** — clients read them back redacted (`"****ROBE"`) and the API persists config exactly as submitted. Use `update` only when the secret itself genuinely changed. |

⚠️ **Do not report "your credentials are broken" from a stored `auth_success: false`.**
Run `test-auth` first — the stored value may simply be stale.

### Trigger a sync

```bash
# Incremental sync (routine)
"$TORANA" integration <integration-id> sync

# Full sync (initial setup or recovery)
"$TORANA" integration <integration-id> sync --full

# Specific data source
"$TORANA" integration <integration-id> sync --data-source repositories
```

### Monitor health and sync history

⚠️ `sync-stats` and `sync-logs` NO LONGER EXIST (verified 2026-09-02 — both return
"No such command"). Use these:

```bash
"$TORANA" integration <integration-id> health           # auth/connection health
"$TORANA" integration <integration-id> etl-health       # run counts, success rate
"$TORANA" integration <integration-id> sync latest      # last sync, per data source
"$TORANA" integration <integration-id> runs             # run history
```

⛔ **`Partial:` in `etl-health` is NOT a failure.** It means the run collected real data
but did not read every scope unit — e.g. one GCP project denied while others succeeded.
It needs a different response from `Failed:` (fix that project's IAM binding vs.
investigate a broken sync), which is why the two are counted separately.

### The sync ran, so why is the column empty? — ETL raw capture

⭐ **This answers a question nothing else can: what the vendor ACTUALLY sent, and where each
record landed.** `etl-health` says a run succeeded; capture shows the records that run
received and which datalake columns each one wrote. A field the vendor never sent and a
field the mapping silently dropped look identical everywhere else.

⚠️ **Top-level `etl`, NOT under `integrations`** — `"$TORANA" integrations etl capture` is
*No such command*.

```bash
"$TORANA" etl capture status             # is capture on? how many runs, how much on disk
"$TORANA" etl capture runs               # captured runs, newest first
"$TORANA" etl capture records <run-id>   # the raw records that run received
"$TORANA" etl capture lineage <rec-id>   # ⭐ what ONE raw record became in the datalake
"$TORANA" etl capture schema <rec-id>    # that record rendered against its declared schema
"$TORANA" etl capture sweep              # apply retention + size limits now
```

⛔ **`status` tells you whether payloads are MASKED.** Unmasked capture puts raw vendor PII
on disk. Read that line before quoting anything from `records`, and never paste captured
payloads into a ticket without checking it.

⚠️ It is **capped and retained** (per-run record cap, days + MB ceiling) precisely so the
scan stays affordable — so an old run may legitimately hold nothing. `runs` shows what is
still on disk; absence there is not evidence the sync received nothing.

⛔ **This is the DLQ's sibling, not its replacement.** The DLQ holds records that FAILED;
capture holds every record that ARRIVED, including the ones that mapped to nothing. A
column empty with zero DLQ entries is exactly the case capture exists for.

### Multi-container scope — a provider that reads N projects/accounts

Some providers read **several independent containers** under one integration: GCP
projects, AWS accounts, Azure subscriptions. One integration, one credential, N scope
units.

```bash
"$TORANA" integration <integration-id> scope           # what it reads, and what it collects per unit
"$TORANA" integration <integration-id> gcp-projects    # which projects the credential CAN see
```

`scope` shows each project plus its data-source selection. **Three states, and they mean
different things:**

| Shown | Means |
|---|---|
| `data sources: all (17)  (no per-project selection set)` | default — every syncable source |
| `data sources: 2 selected — …` | deliberately narrowed for this project |
| `data sources: NONE — nothing is collected from this project` | deliberately parked |

⛔ **"all" and "NONE" are different configs, not two spellings of empty.** An absent
selection means *sync everything*; an empty one means *sync nothing*. Never "helpfully"
normalise one into the other.

#### Reading a multi-project sync

`sync latest` and `runs` print **one row per (data source × project)** when the
integration is scoped:

```
DATA SOURCE       PROJECT              STATUS   RECORDS  REASON
storage_buckets   pantheon-dev-496317  skipped  0        permission denied — …
storage_buckets   pantheon-468400      success  4
cloud_assets      —                    success  1484
```

- Every column belongs to **exactly one project** — the records are that project's, not
  a run total.
- `—` in PROJECT means the source is **org-scoped** (GCP `cloud_assets`, `scc_findings`
  read the whole organisation in one call) or the run predates per-project attribution.
  It does **not** mean the project is unknown-because-broken.
- `partial` at the run level means *some* units were read. Look at the per-project rows
  to see which.

#### ⚠️ Two GCP 403s that look identical and are not

```
permission denied — the service account has no access to this project
    -> grant read access ON THAT PROJECT

billing project not usable — needs roles/serviceusage.serviceUsageConsumer on <X>
    -> a DIFFERENT project (the billing/quota project) and a DIFFERENT role
```

⛔ The second is **not** fixed by granting read access on the project in the error. Every
call carries `x-goog-user-project`; the caller must be able to *use* that billing
project. Read the reason text, not just the status.

### Update credentials

```bash
"$TORANA" integration <integration-id> update \
  --config '{"access_token": "ghp_NEWTOKEN"}'
```

### Enable / disable a data source

⚠️ The source is a POSITIONAL argument — there is no `--data-source` flag.

```bash
"$TORANA" integration <integration-id> disable cloud_sql_instances
"$TORANA" integration <integration-id> enable  cloud_sql_instances
"$TORANA" integration <integration-id> scope          # see the resulting selection
```

These write `scope_data_sources` — the per-scope-unit selection the ETL
enforces. It NARROWS the code capability and can never widen it: a source with
no backend mapping is not syncable, and naming it is rejected with the valid
list.

⭐ **A disabled source is EXCLUDED, not degraded.** Future syncs record the unit
as `excluded` with its reason, which — unlike a permission failure — does **not**
mark the integration degraded. This distinction is why a customer who deselects
sources they do not use no longer sees their integration reported DEGRADED for
exactly the sources they asked us to drop.

⛔ **DISABLING DOES NOT DELETE WHAT WAS ALREADY COLLECTED.** Rows stay attributed
to the integration and simply stop being refreshed, so `last_seen` freezes while
the estate moves on — and a stale row that still LOOKS current is worse than a
missing one. **Check what the source holds before disabling it:**

```bash
"$TORANA" integrations data <integration-id>     # rows per data source
```

There is no per-data-source purge yet; `integrations purge-data` is
whole-integration only (its `--source` flag disambiguates a PROVIDER, not a data
source). Disabling a source that holds rows is therefore safe only when you
accept that those rows go stale in place.

### Reset a stuck sync

⚠️ `reset --sync-id` NO LONGER EXISTS. Cursors are reset per data source:

```bash
"$TORANA" integration <integration-id> cursor list                       # where each resumes
"$TORANA" integration <integration-id> cursor reset                      # ALL data sources
"$TORANA" integration <integration-id> cursor reset --data-source users  # just one
```

### Deactivate or delete

```bash
"$TORANA" integration <integration-id> deactivate   # preserves config, keeps data
"$TORANA" integration <integration-id> delete       # removes the integration AND its data
```

⛔ **`delete` removes the data too, and it is ASYNCHRONOUS.** The integration disappears
from every list immediately, but the datalake rows, graph nodes and edges it produced are
removed by a background job that takes roughly 20-40s (longer on a large estate). The
command returns 202 and tells you the cleanup was queued — it is *not* finished when the
command returns.

⚠️ **Do not tell a user their data is gone the moment `delete` returns.** Say the cleanup is
running, and check it:

```bash
"$TORANA" integration <integration-id> cleanup-status
```

⭐ **A 404 from `cleanup-status` is the SUCCESS case for a deleted integration.** The record
is removed only once its data has actually gone, so "no cleanup pending" means the cleanup
completed.

### Deletion cleanup — checking and retrying

```bash
"$TORANA" integration <integration-id> cleanup-status   # one integration
"$TORANA" integrations cleanup-status                   # everything still running/failed
"$TORANA" integrations cleanup-status --failed-only     # only what needs attention
"$TORANA" integration <integration-id> cleanup          # queue / retry
"$TORANA" integration <integration-id> cleanup --wait   # …and poll until it finishes
```

| `purge_state` | Meaning | What to tell the user |
|---|---|---|
| `pending` | queued, not started | Cleanup is queued; it runs shortly. |
| `purging` | running now | Cleanup is running. |
| `failed` | ⛔ gave up after `PURGE_MAX_ATTEMPTS` | **The integration is gone but its data is NOT.** Nothing else will remove it — retry with `cleanup`. |
| *(404 / absent)* | finished | Cleanup completed; the data is gone. |

⚠️ **`--wait` waits on the whole TENANT's refresh cycle**, not just this integration, so it
can block behind unrelated work. On timeout it exits 2 and the cleanup is **not** cancelled.

⚠️ **A deployment-managed integration returns 409 on `delete`.** Delete it from its
deployment instead — `torana deployment <id> delete` tears down the bound integration and
enqueues the same cleanup.

### Data left behind by an OLD deletion (before cleanup existed)

Integrations deleted before deletion-cleanup shipped left all of their data behind, and
their record is gone — so there is no per-integration handle left to clean up with. Find and
remove that data from the data itself:

```bash
"$TORANA" integrations data --orphans                 # what is stranded, per integration
"$TORANA" integrations purge-data <id>                # per-integration repair (SA)
TORANA_PROFILE=SA "$TORANA" integrations cleanup-orphaned              # preview, all tenants
TORANA_PROFILE=SA "$TORANA" integrations cleanup-orphaned --no-dry-run --yes
```

⭐ **`orphaned: 0` in `integrations data --orphans` is the number to check** after any
deletion — it is the direct evidence that nothing was stranded.

⚠️ `cleanup-orphaned` is **super-admin only** and crosses tenant boundaries. It previews by
default; `--yes` skips the prompt but never the preview. Rows only the deleted integration
wrote are **deleted**; rows another live integration also wrote are **detached** (its key is
stripped, the row stays) — so a shared asset never disappears because one contributor left.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `auth_success: false` after create | Wrong/expired credentials | Fix the credential/grant, then `integration <id> test-auth`. Only use `update` if the SECRET itself changed |
| `auth_success: false` but syncs return data | **Stale flag** — access was fixed externally and nothing re-checked it | `integration <id> test-auth` |
| Sync logs show `429` errors | Rate limit hit | `integration <id> update --config '{"rate_limit_per_minute": 30}'` |
| Sync stuck in `started` for >15 min | Worker crashed | `integration <id> cursor reset` (⚠️ `reset --sync-id` no longer exists) |
| `records_read_from_source: 0` | Source not selected, or denied | `integration <id> scope` shows the selection AND dormant sources; `integration <id> runs` shows per-unit reasons |
| `health_status: unhealthy` but auth ok | Intermittent failures | `integration <id> runs` — read `REASON` / `error_message` (⚠️ `sync-logs` no longer exists) |
| Run status `partial` | **NOT a failure** — some scope units read, others not | `integration <id> runs` shows one row per project; read that project's `REASON` |
| One project 403s, others fine | Read-permission **or** billing-project permission — two different fixes | Read the REASON text: "no access to this project" vs "needs roles/serviceusage.serviceUsageConsumer on X" |
| 409 "duplicate integration" | Provider limit per tenant | Update existing instead of creating new |
| 409 "managed by deployment" on delete | Deployment-owned integration | Delete the deployment instead: `deployment <id> delete` |
| Deleted an integration but its data is still there | Cleanup is still running, or it **failed** | `integration <id> cleanup-status`; if `failed`, `integration <id> cleanup` |
| `integrations data --orphans` shows orphaned rows | Deleted before cleanup existed, or a cleanup failed | `integrations purge-data <id>`, or SA `integrations cleanup-orphaned` |

---

## Best Practices

1. **Discover before creating** — always run `providers-by-provider-name <provider>` to see exact required fields.
2. **Start with 1-2 data sources** — confirm they sync, then enable more.
3. **Use incremental syncs** for routine operations; full syncs only for initial setup or recovery.
4. **Deactivate instead of deleting** when the user may reconnect — it preserves the
   credentials and the collected data. ⚠️ `delete` now also removes the data the
   integration produced (asynchronously); it is not a reversible pause.
5. **Check `auth_success` after every credential update** — it's in the CLI response.
6. **Treat `auth_success` as a cached verdict, not live truth** — run `test-auth` to refresh
   it. Never re-send `config` just to re-trigger an auth check; that risks destroying stored
   secrets.
7. **Always run `--help` first** — flags evolve with CLI releases.

---

## Command Reference

```bash
"$TORANA" integrations --help
"$TORANA" integration --help
"$TORANA" integrations providers --help
```
