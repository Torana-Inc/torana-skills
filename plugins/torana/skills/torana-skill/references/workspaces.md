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
  --name "Remediation Ops" \
  --type vulnerability_management_v2 \
  --bundle remediation_ops

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
"$TORANA" workspace "$WS_ID" build bundles install remediation_ops   # install OR resume
"$TORANA" workspace "$WS_ID" build bundles install-detail         # why it failed
```

⚠️ **Never reach for `workspaces create --bundle` to retry** — that builds a NEW workspace.
Re-running `install` on the EXISTING one is the retry.

The workspace-scoped form (`workspace <id> build bundles …`) needs no ids and is the natural
path; the top-level `build bundles <verb> "$WS_ID"` takes the workspace explicitly, for
scripting. The job id is only ever something you READ (`install-detail` prints it).

#### Re-import a tenant bundle version

`"$TORANA" build bundles import --file my_app.json` on a version the tenant already stored
UPDATES it, and says so: `created`, `updated`, `unchanged` (same document) or `restored` (the
version had been deleted). It is refused (exit 1, HTTP 409, workspaces named) when the content
differs and a workspace is installed at that version: bump the version instead.

#### Delete a tenant bundle version

A bundle stored by `build bundles import` is the tenant's own and can be deleted one version
at a time (soft delete). System bundles are read-only (exit 4). A version that a live workspace
is installed at is refused (exit 1, HTTP 409): the message names the workspaces, so
upgrade or delete those first. Another tenant's bundle reads as not found (exit 3).

```bash
"$TORANA" build bundles delete my_app --version 3            # asks to confirm; --yes skips
```

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

### Upgrade an installed bundle in place

Tenant admin only. Dry run by default (shows the per-artifact diff and
whether a changed/removed rule affects existing inbox entries); nothing changes until
`--apply`, which asks no further confirmation.

```bash
"$TORANA" workspace "$WS_ID" upgrade-bundle              # dry run, latest version
"$TORANA" workspace "$WS_ID" upgrade-bundle --to 7        # dry run against a specific version
"$TORANA" workspace "$WS_ID" upgrade-bundle --to 7 --apply
"$TORANA" workspace "$WS_ID" upgrade-bundle --partial     # dry run: what applies in place, what is skipped and why
"$TORANA" workspace "$WS_ID" upgrade-bundle --partial --apply
```

A full upgrade is refused when the target adds or removes anything. `--partial` applies every artifact that can be
updated in place and skips the rest, each with its reason, including a change that depends on an artifact the
install does not have yet. The installed version does not move while anything is skipped. A rule whose target
moves its closing to platform-owned Inbox entries (`inbox`) is skipped while the tenant's
`inbox_declaration_enabled` setting is off; the skip reason says so. `torana rules list --validate-sql` adds a
CLOSING column: `invalid` means the query that closes the rule's items no longer compiles, so they stay open.

**Three-way, and a person's edit is never overwritten.** Every changed rule, widget and inline dashboard widget
(a widget defined inside a dashboard; its row is `inline_widget`, key `<dashboard>#<widget name>`) is judged on what
the install recorded, the bundle, and what runs now. Only the fields that changed in the bundle AND still hold the
installed value are written (`FIELDS`). A field a person edited that the bundle also changed is listed under
**Kept** (`change: conflict`) and is never written, `--partial` or not; an edit the bundle did not touch is listed
under **Edited** and kept. A row whose live object cannot be read is refused, not guessed. The first upgrade of an
older install can list inline widget changes earlier upgrades did not detect (a `NOTE:` line, `summary.inline_changed`);
an install already at the latest version can still be upgraded to pick them up. With `--format json`: `conflicts`,
`edited`, `already`, `blocked` per artifact, and `summary.conflict` / `summary.edited`.

**The changed rules run once after `--apply`.** Every rule whose applied change alters what a run produces (its SQL,
`alert_field_map`, severity, grouping, lifecycle or closing) runs once: members first, then group roots. Its open
alerts then carry the new values without waiting for the schedule, so do NOT `torana rule <id> execute` them by hand
after an upgrade. A rule whose change is only its name or description is not re-run. The text output lists them
under "Re-ran" (a dry run: "Would re-run"); JSON has `rules_reexecuted` (`status`: `would_run`, `succeeded`,
`failed`, `running` or `already_queued`) and `summary.reexecuted` / `summary.reexecute_failed`. A failed run never
fails the upgrade. A run still going when the upgrade returns is `running`: check it with
`torana rule <rule_id> status <execution_log_id>`. `--partial` re-runs only the rules it applied.

---

## Inspecting Workspace Contents

### Rules

```bash
"$TORANA" workspace "$WS_ID" rules list
```

### Dashboards

```bash
"$TORANA" workspace "$WS_ID" dashboards list
```

### Plans

```bash
"$TORANA" workspace "$WS_ID" plans list
"$TORANA" workspace "$WS_ID" plans list --search "<name>"
```

### Playbooks

```bash
"$TORANA" workspace "$WS_ID" playbooks list
```

### Workflows

```bash
"$TORANA" workspace "$WS_ID" workflows list
```

### Transformers

```bash
"$TORANA" workspace "$WS_ID" transformers list
```

### Alert routes

```bash
"$TORANA" workspace "$WS_ID" alert-routes list
```

---

## AI Home — the generated operator home page

A per-workspace page that is **generated by a run and served from storage**, not derived on
load. It answers, in one fixed order: what needs you · what is wrong · what you cannot see.

⭐ **The governing rule: a number never appears without its coverage.** Every measure is
`measured`, `partial` or `blind`, and a blind measure states what it cannot see rather than
rendering a zero. Coverage is resolved SERVER-SIDE — never re-derive it.

⭐ **Each measure's detail line states three clocks together:** `viewed now · data as of 2d ago ·
computed 36m ago`. "Computed" is when the page's query ran (`query_ran_at`); "data as of" is when
the slowest SOURCE last observed the rows behind the number (`as_of`). A recent "computed" with an old
"data as of" means the page was refreshed over stale data. Re-sync the integration, don't re-run the
page. The headline number carries only `as_of`.

⭐ **Pushed sources never set "data as of" or fresh/stale** (T-21). A pushed source (a SARIF/trivy
upload, an asset inventory: any mapping with `sync_schedule: on-push`) has no schedule, so its age
is shown BESIDE the data clock: `viewed now · data as of 2d ago · pushed data last push 3d ago ·
computed 36m ago` (`pushed_as_of`; `, oldest sender 9d ago` is added only when the quietest pushed
sender trails the newest by more than a day: `pushed_oldest_as_of`). A measure fed ONLY by pushes has
`freshness: "pushed"` and no data clock: `viewed now · pushed data · last push 3d ago`. That is
not a verdict. To refresh it, push a new scan; there is nothing to re-sync. `torana widget <id>
render` prints the same push age on its freshness line.

⭐ **The page the screen shows is `"$TORANA" app "$APP_ID" ai-home get`: read [home.md](home.md).** The commands
below are the CLASSIC narrated page (deprecated, kept for compatibility). They are hidden from `--help`.

```bash
# Read the current CLASSIC page
"$TORANA" app "$WS_ID" ai-home classic get
"$TORANA" app "$WS_ID" ai-home classic get --format json

# Generate a new classic page (Torana harness: collect facts -> narrate -> critique -> persist).
# ⚠️ SYNCHRONOUS: the request waits ~20-40s for the LLM.
"$TORANA" app "$WS_ID" ai-home classic run

# What this app CANNOT answer yet, and who can fix it
"$TORANA" app "$WS_ID" ai-home gaps

# Classic run history — shows which harness produced each page
"$TORANA" app "$WS_ID" ai-home classic runs

# Inspect ONE run (classic or not) — stages, critique rounds, findings, and the config
# fingerprint that produced it.
"$TORANA" app "$WS_ID" ai-home runs get "$RUN_ID"

# Per-ZONE feedback (Z0..Z6, or 'page')
"$TORANA" app "$WS_ID" ai-home feedback --run-id "$RUN" --zone Z5 --rating -1 \
  --comment "the questions read as filler"
```

### What matters to you: the app's own questions

Questions the app's team chose to track at the top of its Home. Each one is compiled once into SQL and
confirmed by the person who asked it; from then on code answers it on every Home run. They belong to the app
and are shared by everyone in it.

**When to use it:** "add a question to our Home", "what is my team tracking on Home", "why does this question
say can't answer", "move this question to the top", "stop tracking this".

**Two ways to add a question.** ⛔ Try the catalog first.

| Way | Command | Available |
|---|---|---|
| Pick a ready-made question | `questions catalog`, then `questions ask --pick <ID>` | Always |
| Find the ready-made question nearest to what the user asked | `questions catalog --search "<their words>"` | Only where search is on (`search_enabled` in `questions list -o json`); off → 403 `question_search_disabled`, exit 4: read the full `questions catalog` instead |
| Type your own | `questions ask --text "…"` | Only where typed questions are turned on (otherwise 403 `custom_questions_disabled`) |

```bash
Q="$TORANA workspace $WS_ID ai-home"

$Q questions list                      # the app's questions in Home order: state, answer, why
$Q questions list --removed            # removed questions that can still be restored (30 days)
$Q questions catalog                   # ready-made questions this tenant's data can answer (id, use case, added?)
$Q questions catalog --search "are we patching on time"   # the questions closest in meaning, best first; first column = match
$Q questions catalog --use-case sla_management            # one category (repeatable); the footer lists every category with its count
$Q questions ask --pick EM-038 --wait  # start a reading, wait for it, print it with its reading_token
$Q question "$QID" get                 # everything: the written answer + rows, the SQL in force, any unconfirmed reading, what a threshold can be set on
$Q question "$QID" confirm --token "$TOKEN" [--unit months] [--threshold "gt 12" [--threshold-column <name>] [--threshold-match any|all]]   # the asker agrees to the SQL
$Q question "$QID" edit --unit findings --threshold "gte 10"    # also --clear-unit, --clear-threshold, --text (typed only)
$Q question "$QID" edit --threshold "gt 30" --threshold-column median_days_to_remediate   # compare a COLUMN of the rows; add --threshold-match all for "every row"
$Q question "$QID" reread              # read it again (can't answer, stopped after a schema change, failed reading)
$Q question "$QID" discard-reading --token "$TOKEN"   # drop an unconfirmed re-read, keep the confirmed one
$Q question "$QID" refresh             # answer again now with the confirmed SQL (no new reading)
$Q question "$QID" move --top          # or --bottom, --before <QID>, --after <QID>; prints the new order
$Q question "$QID" remove              # stop tracking, for everyone; answers are kept
$Q question "$QID" restore             # bring it back with its history (within 30 days)
$Q question "$QID" answers --limit 10  # past answers, newest first (no rows), each with the sentence written for it
```

**Thresholds: say what is compared.** A threshold is `"<op> <number>"` (`gt gte lt lte eq ne`) on ONE target.
`question <QID> get` lists the targets under "a threshold can be set on" (`threshold_targets` in `-o json`).

| Target | Command | Compares |
|---|---|---|
| The card's own value | `edit --threshold "gt 12"` | a number card's figure; a list card's ROW COUNT ("number of teams above 0") |
| A column of the rows | `edit --threshold "gt 30" --threshold-column median_days_to_remediate` | that numeric column, crossed when ANY row satisfies it |
| A column, every row | `… --threshold-column <name> --threshold-match all` | crossed only when EVERY row with a number satisfies it |

- ⛔ **The row count is not offered on a time series or a fixed breakdown** (one row per month, per severity…):
  13 monthly rows are always 13. Pick a column instead. A user who says "tell me when it takes over 30 days"
  means a column, never the row count.
- Null and non-numeric cells are skipped; a column with no number is never crossed. The card prints
  `N of M rows` (rows that satisfy it, of the rows that hold a number).
- ⛔ **A crossed threshold never sends a message.** It marks the card (`▲ Threshold crossed`) and moves it up on
  Home (`↑ moved up: threshold crossed`). Do not tell the user they will be notified.
- Print the threshold in the API's words (`threshold_text`); never rebuild it from `op` and `value`.

| Refused (422, exit 6; the body lists `targets`) | Why | Do |
|---|---|---|
| `threshold_target_not_offered` | No `--threshold-column`, and this list's row count means nothing | Pick a column from `targets` |
| `threshold_column_unknown` | The column is not a numeric column of the current answer | Pick one from `targets` (`get` lists them) |
| `threshold_match_needs_column` | `--threshold-match` without `--threshold-column` | Add the column, or drop the match |

`--clear-threshold` always works. A threshold set earlier whose target is no longer offered stays in force and is
still shown; only setting it again is refused.

`ask` and `reread` only START a reading. Nothing new is answered on Home until `confirm` runs with that
reading's token. Every command takes `--format json`; `question <QID> get --format json` is the API's own JSON.

**The six states** (`state` on every question; the CLI prints the glyph and the word):

| State | Means | Next command |
|---|---|---|
| `◆ answered` | Code ran the confirmed SQL and the data behind it is supplied | none; `question <QID> get` for the rows |
| `◐ partial` | It ran, but something it reads is incomplete. `reason.text` says what, `what_to_do` says the fix | repeat both lines to the user; `refresh` after the fix |
| `⊘ cannot_answer` | The reading was confirmed as "the data cannot answer this yet". No number | `reread` once the data exists |
| `◌ needs_confirmation` | A reading is ready (or failed) and the asker has not confirmed it | `get`, show it, then the asker runs `confirm`; a failed one: `reread` |
| `◌ reading` | The question is being read right now | wait, then `get` |
| `⚠ stopped` | It used to answer and the last run could not | `get` for the reason; `reread` when the reason is `schema_drift`, otherwise `refresh` |

**Rules:**

- ⛔ Never run `confirm` until you have shown the user the reading: what will be measured, the first answer
  and the SQL. Confirming is the user agreeing that the SQL means what they asked. `ask --wait` prints the
  `confirm` command; it does not run it, and neither do you without the user's yes.
- ⛔ Only the asker can confirm. A 403 `not_the_asker` is not a bug: tell the user who the asker is.
- ⛔ `—` is not `0`. A question that can't answer, has stopped, or returned no value has no number.
- ⛔ `100+` means the list hit the query's own cap, so the true count is 100 or more.
- ⛔ An answer is **measured**, not proven. Do not call it a proven fact.
- ⭐ **Lead with the written answer.** `questions list` and `question <QID> get` print `answer: …`: one or two
  sentences written for THAT answer from its rows (JSON: `answer.narration = {status, text}`). Quote it as the
  answer and offer the rows as the evidence. Every number in it was checked by code against the rows.
  - The phrases a reader must not miss are bold on a terminal (`**…**` in `--format json`); keep that emphasis
    when you quote it. `answer: ▲ needs attention: …` (JSON `narration.attention: true`) means the rows show
    something to act on now: lead with that question when you summarise the Home.
  - `answer: ◌ being written` (`status: pending`): the rows are in, the sentence takes a few seconds. Run `get`
    again; do not write your own sentence in its place.
  - `answer: none written for this result` (`status: unavailable`): the narrator failed or its draft was rejected.
    Read the rows to the user and say there is no written answer for this result. `refresh` produces a new answer,
    which is worded afresh.
  - No `answer:` line at all (`narration: null`): there is nothing to word (the question stopped, or returned no rows).
- ⭐ **Then the figures.** When a question declares headline figures, `questions list` and `question <QID> get`
  print `figures: <value> <label>  ·  <value> <label>  ·  …` under the answer (JSON:
  `answer.display.figures = [{label, value}]`). Code computed each one over the question's FULL result, so quote
  them as totals; the rows printed below are only the first rows kept. A question with no `figures:` line declares
  none: its count is the row count, as before.
  - `get` also prints `what this counts: …` (JSON `answer.display.counts`) when the question says what one row is,
    and the rows with the labelled columns the API chose for a reader (`answer.display.columns`; every column is
    in `answer.display.all_columns` and in `--format json`).
  - ⛔ Never add figures up, subtract them or turn them into a percentage yourself, and never compute a total from
    the printed rows: at most 100 rows are kept, however long the result is.
- ⛔ A sentence belongs to ONE answer. After a `refresh`, the old sentence is gone with the old answer: read the new
  one, never repeat the earlier wording over new rows. Unchanged rows keep the same sentence, by design.
- ⛔ The sentence is not written by the Home page run. A question added between two Home runs gets its sentence
  seconds after `confirm`; do not tell the user to wait for the next Home update.
- ⛔ Questions are read-only: they never create a rule, an alert or a transformer.
- ⛔ A `partial` answer names what is missing (`reason.text`, `what_to_do`). Repeat it; do not present the
  number as complete.
- ⛔ `enabled: false` (the line "What matters to you is turned off in this environment.") or a 404
  `feature_disabled` means the environment has the section turned off (`DISABLE_HOME_WHAT_MATTERS`). A 403
  `custom_questions_disabled` means typed questions are off (`DISABLE_HOME_WHAT_MATTERS_CUSTOM_QUESTIONS`):
  offer the catalog. Say so; do not retry or look for another route.

Other refusals you may meet: 409 `duplicate_question` (already tracked; `existing_id` is it), 409
`stale_reading` (the token is not the current reading's: `get` prints the current one), 409 `use_delete`
(`discard-reading` on a question never confirmed: `remove` it), 422 `catalog_question_text_fixed` (a ready-made
question's wording cannot be edited), 404 `not_in_catalog` (not ready for this tenant), 410
`restore_window_passed`.

**Searching the catalog.** `--search` returns the questions closest in MEANING to the text, best first, so pass
the user's own words: a paraphrase with no word in common still matches. The footer says `(by meaning)`; if it
says `(by words only …)` the embedding model was not reached and only shared words were matched. ⛔ It never picks
for you: show the user the top few and let them choose. Text about something else prints `0 of N … match`; read
the full `questions catalog` before saying nothing fits.

```bash
$Q questions catalog --search "are we patching on time"
# 0.79  EM-080            [sla_management]  How long was each asset exposed between public disclosure … and our patch landing?
# 0.78  EM-041            [executive_reporting]  What share of assets got patched by their deadline, …
# 0.76  EM-032   ✓ added  [sla_management]  Are we fixing vulnerabilities within the response times our own policy defines, …
# 6 of 12 ready-made question(s) match "are we patching on time" (by meaning)
$Q questions catalog --search "pizza recipe"
# 0 of 12 ready-made question(s) match "pizza recipe" (by meaning)  ·  run without --search to see them all
```

**Worked example** (output shortened):

```bash
$Q questions catalog
# EM-038            [trend_analysis]  Are we finding vulnerabilities faster than we fix them — is the backlog growing …
# 12 ready-made question(s)  ·  12 more need data this tenant does not have yet

$Q questions ask --pick EM-038 --wait
# ✓ Question added: 9400e719-b566-4155-8437-c4835bd3354b
#   Unconfirmed reading (ready, by you)
#     what will be measured: Are we finding vulnerabilities faster than we fix them — …
#     outcome: partial  ·  shape: list
#     why: The sync that fills this is failing.
#     what to do: Check the connection — usually expired credentials.
#     first answer: 13 rows  (partial)
#       period_start=2025-10-01T00:00:00Z  ·  new_findings=13  ·  remediated_findings=0  ·  net_change=13
#     SQL:
#       -- MEASURE: one row per calendar MONTH over the last 12 months — new findings first detected …
#     reading_token: 612e5f17-ac5e-4ced-aa40-0e370545ac60
#   Not answered on Home until the asker confirms that this SQL means what was asked:
#     torana workspace <id> ai-home question 9400e719-… confirm --token 612e5f17-…

# ⛔ STOP HERE. Show the user the reading above (and that it is partial, and why). Only after their yes:
$Q question 9400e719-b566-4155-8437-c4835bd3354b confirm --token 612e5f17-ac5e-4ced-aa40-0e370545ac60 \
  --unit months --threshold "lt 1" --threshold-column fix_to_find_ratio
# ✓ Confirmed
# ◐ Partial  ·  13 months
#   threshold: fix to find ratio below 1 in any row  ·  4 of 4 rows  ·  ▲ crossed
#   a threshold can be set on:
#     new findings  (--threshold-column new_findings)
#     fix to find ratio  (--threshold-column fix_to_find_ratio)
#     …
#   why: The sync that fills this is failing.

$Q questions list
#  1  ◐ Partial  ·  13 months  ·  ▲ Threshold crossed (fix to find ratio below 1 in any row  ·  4 of 4 rows)
#     Are we finding vulnerabilities faster than we fix them — …
#     why: The sync that fills this is failing.
#     what to do: Check the connection — usually expired credentials.
```

### The Home page the screen shows

Moved: **[home.md](home.md)** teaches `"$TORANA" app "$APP_ID" ai-home get | status | refresh | runs | events |
item`. The older spellings (`ai-home-v2 get`, `ai-home get --kind proven`, `ai-home run --kind proven`,
`ai-home runs --kind proven`, `ai-home run-detail`) no longer exist.

```bash
# What kind of app this is (its bundle's declared profile: kind, item words, highlight policy), or "declares no
# profile (vulnerability-management defaults)". Read from the CURRENT bundle code (source: bundle_code). Tenant-scoped;
# another tenant's workspace is 404. JSON: {workspace_id, bundle_id, installed_version, profile, source}.
"$TORANA" workspace "$WS_ID" app-profile
"$TORANA" workspace "$WS_ID" app-profile --format json

# The proof behind the page: candidates, items by type, decision groups, home summary, items that failed to prove.
"$TORANA" app "$WS_ID" ai-home proof
```

⚠️ An app with a profile (e.g. CMDB Visibility "Asset inventory") appends ` · <label>` to the page's first line,
uses its own words in the summary's decisions step and the "more decisions" line, and highlights the open decision
with the lowest `alert_priority` when its `highlight` is `priority`. Its group roots are `group_check` items ("N open
of M rows this check groups"); they get no AI brief, and their lines offer no `brief get` command.
⚠️ `torana alert <id> proof` models posture findings, fix entries, mitigation entries, threat signals and
posture summaries (summaries carry the recorded values plus a "Not recomputed" claim). Only an alert none of these
fit says "No proof model for this item type yet", and it still carries its own `alert.*` claims.

### Reading the STATUS of a run — `success` is not the only good outcome

`runs list` and `runs get` report one of four terminal statuses. Two are servable pages:

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
the narration agent is the thing to investigate — `runs get <RUN_ID>` shows the attempted rounds
even when none produced a draft.

## Health and Observability

### Summary statistics (all workspaces)

```bash
"$TORANA" workspaces summary
"$TORANA" workspaces summary --format json
```

### Runtime stats (per workspace)

```bash
"$TORANA" workspace "$WS_ID" runtime-stats                      # last 24h, full
"$TORANA" workspace "$WS_ID" runtime-stats --hours 72 --view compact --format json
```

`--hours` sets the window for run counts only; each rule's `by_rule` row (last run, last
success, `currently_failing`, failure streak with `first_failure_at` / `recovered_at`) reads
the rule's own history and is the same at any window. "Since when has rule X been broken" is
`by_rule[].failing_since` (still failing) or `last_recovered_streak.first_failure_at`, never a
position in `recent_failures`. `--view compact` keeps totals, `by_rule` and up to 10 failures
(errors truncated) and turns `recent_activity` into counts: use it in a script or an agent,
where the full view (about 8k tokens at 72h) is too large.

### Activity log

```bash
"$TORANA" workspace "$WS_ID" activities
"$TORANA" workspace "$WS_ID" activities --page-size 50
```

### Landing page

```bash
"$TORANA" workspace "$WS_ID" config     # get landing page config
"$TORANA" workspace "$WS_ID" home list  # the home page as it renders: zones, pinned widgets, status per widget
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
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" legacy-build
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
```

### Building a proposal

`proposal build` creates an agent chat session, fires the first turn with the proposal
as context, and returns immediately with the session and agent IDs. The build is a
multi-turn HITL conversation — you drive it entirely from the CLI.

**Correct flow:**

```bash
# 1. Kick off the build — prints session, agent, turn IDs + CLI commands
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" legacy-build

# Example output:
# Session:        agent_5cae3885-..._ws_743af014_bfd89a37b3d5
# Agent:          5cae3885-cfcd-4eb5-beb4-9bf2b5263ebf
# Turn ID:        <turn_id>
#
# Monitor:        torana chat agent_5cae3885-..._ws_743af014_... history
# Continue:       torana chat agent_5cae3885-..._ws_743af014_... send -m "your message"
# Detail:         torana workspace <WS_ID> proposal <PID> status

# 2. Watch what the agent said in its first turn
"$TORANA" chat "$SESSION_ID" history

# 3. Respond to the agent (drives the HITL conversation)
"$TORANA" chat "$SESSION_ID" send -m "Yes, proceed with the KEV watchlist rule"
# If the agent stopped on a question instead (send exits 7), answer it:
#   "$TORANA" chat "$SESSION_ID" status
#   "$TORANA" chat "$SESSION_ID" answer --option 1

# 4. Check proposal + browser URL at any time
"$TORANA" workspace "$WS_ID" proposal "$PROPOSAL_ID" status
```

**The chat id is always explicit** — there is no local session cache. Every `chat` command
takes it as its first argument (`torana chat <CHAT_ID> …`); it is the session id printed by
`proposal legacy-build` and `proposal status`. Full chat reference: `references/chat.md`.

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
