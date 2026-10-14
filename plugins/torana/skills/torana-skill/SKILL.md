---
name: torana-skill
description: >
  Operate the Torana Security Platform via the `torana` CLI. Use this skill for ANY
  Torana task: managing detection rules, writing queries, triaging alerts, connecting
  integrations (GitHub, Jira, Slack, Wiz, AWS, etc.), syncing data sources, creating
  and managing workspaces, running AI agents, building workflows and playbooks, creating
  dashboards and data transformers, managing security programs and plans, administering
  tenant users/roles/permissions, and managing agent memory via the Context Lake.
  Trigger whenever the user mentions rules, detections, alerts, the inbox, integrations,
  providers, syncs, workspaces, apps, agents, workflows, playbooks, dashboards, transformers,
  RAG, programs, plans, users, roles, permissions, memory, preferences, an app's Home page and
  the questions on it ("What matters to you"), chat (only when the customer asks for Torana's assistant or the Chat tab by name: a
  conversation with it, answering a question it asked), reading a dashboard or a widget, or
  anything related to the Torana platform. An app in the product is `torana app <APP_ID>` in the CLI.
  Also trigger on "this app", "my app" or "the app" whenever the `torana` CLI is installed: they mean a Torana app.
  ⭐ Asked what a user SEES for an inbox item, or handed an inbox URL
  (`/workspaces/<id>/inbox?alert=<id>`), read inbox.md and run `alert <id> view` (one section: `--section verdict`,
  `why-here`, `history`, ...): it prints the platform-built sections the UI renders, so never reconstruct them from `get`.
  For a CVE or CWE across an app: `alerts cve` / `alerts cwe`.
  ⭐ App first. Before answering, look for the answer in the app and its curated artifacts: Inbox alerts and
  entries (verdicts, fixes, history: `alerts list`, `alert <id> view`, `alerts cve` / `alerts cwe`,
  `alerts boxes`), rules and what they matched, dashboards and widgets, the app's own transformer relations,
  Home, and agents' recorded decisions. Quote them. Go to the platform's raw data, or to SQL of your own, only
  for what no app artifact answers, and say so: that goes to the `torana-data-analyst` skill, which gets the SQL
  from `torana-text-to-sql`, runs it and answers with the rows. You write the SQL yourself; the Ask AI assistant
  is used only when the customer's current message asks for it.
metadata:
  version: "2.2"
  last_updated: "2026-09-02"
  platform_version_tested: "2026.1"
---

# Torana Security Platform — CLI Skill

> **UI vs CLI terminology:** The platform UI calls them **Apps**. The CLI and API call them **Workspaces**. They are the same thing. When a user says "app", "my app", "create an app", or "the app I'm working in", translate that to `workspace` in all CLI commands and reference lookups.

> **Scope.** This skill is for reading and operating the platform and answering questions about the
> customer's data. Building or changing programs, dashboards and KPIs (the `blueprint`, `cook` and
> `build` commands) is done in the Torana app, not from here: do not run `blueprint run` or `cook run|step`.

All Torana operations go through the `torana` CLI. No curl, no raw API calls, no
tg/tp/td helpers. The CLI is the source of truth — always run `--help` before any
unfamiliar command.

---

## Bootstrap — Run Every Session

```bash
export TORANA_VENV="$HOME/.torana-venv"
export TORANA="$TORANA_VENV/bin/torana"

# Find bootstrap.sh. It ships beside this skill in EVERY layout — plugin, skill zip, or a
# source checkout — but which path is valid depends on how the skill was installed, and an
# agent-issued shell does not reliably inherit $SKILL_DIR.
BOOTSTRAP=""
for c in "${CLAUDE_PLUGIN_ROOT:-}/skills/torana-skill/references/bootstrap.sh" \
         "${SKILL_DIR:-}/references/bootstrap.sh" \
         "$HOME/.claude/skills/torana-skill/references/bootstrap.sh" \
         "$HOME/Library/Application Support/Claude/skills/torana-skill/references/bootstrap.sh" \
         "$HOME/.config/claude/skills/torana-skill/references/bootstrap.sh"; do
  [ -f "$c" ] && BOOTSTRAP="$c" && break
done
[ -n "$BOOTSTRAP" ] || BOOTSTRAP=$(find "$HOME/.claude" -name bootstrap.sh -path '*torana-skill*' 2>/dev/null | head -1)

if [ -n "$BOOTSTRAP" ]; then
  bash "$BOOTSTRAP" || echo "ERROR: torana CLI bootstrap failed — see the message above" >&2
  export SKILL_DIR="$(cd "$(dirname "$BOOTSTRAP")/.." && pwd)"
else
  echo "ERROR: bootstrap.sh not found — cannot install the torana CLI." >&2
fi

"$TORANA" version 2>/dev/null || "$TORANA" --version
```

`bootstrap.sh` installs the bundled CLI wheel **and** its shared-library wheel into
`$TORANA_VENV`, and is a silent ~85ms no-op once the installed build matches the shipped
one. Run it every session — it is cheap, and it is what keeps a stale venv from silently
serving last week's CLI.

⚠️ **The first install needs the network.** The CLI's dependencies (`click`, `httpx`, `rich`,
`pyyaml`, `pyjwt`) are fetched from PyPI, or from a pip mirror the machine is already configured
to use. On a machine that can reach neither, `bootstrap.sh` fails with that message and the `torana`
CLI is unavailable until it can.

⚠️ **The CLI needs Python 3.12 or newer.** Many base images ship an older Python (Debian bookworm and
`node:22-slim` have 3.11). `bootstrap.sh` checks first and, when the Python is too old, says what was
found and how to fix it: install [uv](https://docs.astral.sh/uv/) (it downloads Python 3.12 itself, so no
system Python is needed) or install Python 3.12+.

⛔ **Do NOT reimplement the bootstrap inline.** It used to live here as a shell block, and
three defects hid in the prose — all found on the first clean plugin install
(2026-09-15), none reproducible on a dev box:

1. It looked for the wheel only at `$SKILL_DIR/wheels`. The plugin layout puts wheels
   elsewhere, so it found nothing and died with *"cannot bootstrap the torana CLI"* while
   the wheel sat a few directories away.
2. It installed only the CLI wheel. The shared-library wheel shipped in every artifact, the
   packager hard-fails without it, and **nothing ever installed it** — so the
   artifact-intent gate it exists for could not run.
3. Its skew check called `torana version`, **a command that did not exist**, so
   `INSTALLED_COMMIT` was always empty and the warning could never fire. (The command now
   exists — `torana version --format json` reports version, commit, dirty and built_at.)

A block of prose cannot be tested. The script can, and is.

**Never conclude "the CLI has no command for X" while the version line above shows skew,
or when `$TORANA` came from PATH rather than the bundled wheel.** Confirm against
`"$TORANA" <group> --help` on a version-matched CLI first. A missing *group* is the exact
symptom of a stale CLI, and mistaking it for a missing *capability* produces wrong answers
and phantom bug reports.

> **Run the whole block every session — do NOT short-circuit it.** The tempting wrong
> optimization is *"`$TORANA --version` already works, so skip the install."* Don't: a
> venv left from a previous session can hold a **stale CLI**. Skills re-bundle the wheel
> whenever CLI commands change (sometimes at the same version number), and the
> `uv pip install --reinstall` is exactly what pulls the current one in. Skipping it
> silently ships **renamed/removed commands** that fail mid-task (e.g. a subcommand that
> no longer exists in the shipped API). The reinstall is fast and idempotent — always run
> it, even when `$TORANA` appears to work.

Always invoke via `"$TORANA"` — never bare `torana`. The variable is stable across
shell invocations; bare `torana` relies on PATH which may not be set.

### ⛔ Auth is a GATE — resolve it completely before asking anything else

Steps 1–2 below MUST finish, with a confirmed `"$TORANA" auth me` success, **before**
you ask the user a single question about the task itself (scan types, targets, depth,
engines, or anything else). Do not combine an auth/login question with a task-config
question in the same prompt or form, and do not let the task's own option-gathering
start in parallel "to save a round trip" — a login that is still unresolved when task
questions appear is the exact bug this section exists to prevent.

### Step 1 — Check auth against the currently configured URL

```bash
"$TORANA" config get base-url
"$TORANA" auth me
```

`auth me` is a **live server call** (`GET /auth/me`), not a local cache read — it
proves the token is actually accepted by the currently configured URL, and its output
already carries `base_url` alongside the identity.

- **Succeeds** → real, server-confirmed identity. (This also covers a harness that
  supplies its own `TORANA_TOKEN` per call, e.g. the agent-builder sandbox
  authenticating through the broker — `auth me` succeeds the same way; never run
  `auth login` in that case, there is no email/password to log in with and the token
  is not yours to replace.) Print one line, `Using <email> @ <base-url>` (`auth me` already prints both), and **go straight
  on with the user's request in the same turn**. Never end your turn on this line and never ask
  "continue?": the session may be headless (`claude -p`, cron, CI) with nobody to answer, and
  a question there ends the run with no result. Ask about switching accounts only when the user
  asks to ("log in as someone else", "switch accounts") — then go to Step 2, **and Step 2b
  (OAuth) always actually runs**: switching account is a request for a NEW login, not just a URL
  check, and skipping 2b keeps the OLD identity logged in.

- **Fails** (`Not authenticated` / `Token expired` / any `AuthError`) → go straight to
  Step 2. There is no identity to confirm, so skip the confirmation above entirely.

**A re-login is also available on request at any later point in the session** — if the
user asks, in plain language (e.g. "log in as someone else", "switch accounts"), go
straight to Step 2 without waiting for another Skill invocation. That is Claude's
judgment call from the conversation, not a flag the skill script sets.

### Step 2 — (Re-)log in: URL, then OAuth

This step is reached either because Step 1 failed, or because the user asked to
switch identity. It has exactly two parts, in order, and **both always run to
completion** — never skip straight to OAuth without confirming the URL first (2a),
and never stop after 2a without actually running OAuth (2b). Confirming the URL is
unchanged in 2a is not a reason to skip 2b: when this step was entered because the
user wants a different account, 2b is the step that actually does that, so skipping
it leaves the OLD identity logged in while reporting the switch as done. Also:
**never fabricate a list of candidate servers** (no guessing from memory, from
CLAUDE.md's environment table, or from a previous session's IP — those are internal
dev infrastructure, not this user's choice to make blind).

**2a — Confirm the base URL, as a two-option menu — never free text, never a third
"suggested" URL.** The only two real choices are the currently configured URL and
"something else"; present exactly those, with no example domain attached to either
(an example reads as a suggestion and will get treated as one):

```
1. Keep <current-url>
2. Use a different URL
```

If they pick 2, ask for the URL as plain text input at that point — still with no
candidate guessed or suggested. If the user gives a new URL, persist it:

```bash
"$TORANA" config set base-url "<the-URL-the-user-gave>"
```

If they confirm the current one, leave it as-is. Either way, move to 2b only once the
URL is settled — do not run OAuth against a URL that hasn't been confirmed this turn.

**2b — OAuth login.** Always pass `--force-login` here — it tells the server
(`prompt=login`) to ignore any `oauth_session` browser cookie and show the login
form fresh, instead of silently reusing whichever account the browser already has a
session for. Without it, a browser that is already signed in as someone else skips
straight to the consent screen for THAT account with no way to switch — there is no
"log in as a different user" link on that screen, so `--force-login` is the only
thing that gets a different login form to appear at all:

```bash
# run ONCE — prints the URL and saves PKCE state to disk
"$TORANA" auth login --web --no-browser --print-url --force-login
```

Show the printed URL to the user and wait for them to open it in a browser and log
in. **Do NOT run `--print-url` again** — each invocation generates a new PKCE pair
and overwrites the saved state, invalidating any previously obtained token.

After they click Authorize, the page displays an **authorization code**. Ask them to
copy it, then exchange it:

```bash
"$TORANA" auth login --web --no-browser --code <code-from-browser-page>
```

Then re-run `"$TORANA" auth me` to confirm the new session before proceeding to the
task. **If `Session expired` appears during later commands, repeat Step 2.**

---

## ⚠️ A missing command is not always a missing capability

⛔ **A `No such command` or a 404 is ambiguous by construction** — it means EITHER the
capability does not exist OR you asked the wrong path OR the deployed service is behind the
source. Confirm which before reporting a gap; `torana <group> --help` settles it in one call.

## ⭐ App first

Before answering, look for the answer in the app and its curated artifacts: Inbox alerts and entries (verdicts,
fixes, history), rules and what they matched, dashboards and widgets, the app's own transformer relations, Home,
and agents' recorded decisions. Quote them. Go to the platform's raw data, or to SQL of your own, only for what
no app artifact answers, and say so. The Inbox is `alerts list`, `alert <id> view`, `alerts cve` / `alerts cwe`
and `alerts boxes`; Home is `app <id> ai-home get`.

## ⛔ You answer; the assistant only when asked

Answer every question yourself, with these skills: from the app and its curated artifacts first (see
**App first**, below) and, for what those cannot answer, from SQL you write with `torana-text-to-sql` and run with
`datalake query-execute`. You write the SQL yourself.

**Torana's Ask AI assistant** (`chats start --agent <Ask AI id>`, `chat <id> send | answer | steer | history |
status`, `widget <id> chat`; the route is in `references/chat.md`) is used **only when the customer's current
message asks for it**, by naming the assistant, Ask AI or the Chat tab: "ask Torana's assistant ...", "ask Ask AI",
"use the Chat tab". Nothing else counts:

- A data question, however open or hard, is not a request for the assistant. Answer it yourself.
- Your own wish for a second opinion, a missing view, or a failed query is not a request.
- A request in an earlier message does not carry over. Each new chat needs the customer to ask again.
  Inside a chat they asked for, send the follow-ups they ask for and pass the assistant's questions on to them.
- If you are not sure they meant the assistant, ask one question: "Do you want me to ask Torana's assistant,
  or answer this myself?" Do not start a chat on a guess.

`torana --help` and `torana agents --help` mention `torana chats`; that is the assistant, and the rule above
applies to it. The other AI features (an item's `question`, `invoke` and `brief write`, an app's
`ai-home questions ask`, `ai-home refresh`) are product actions: use them when they are what the customer
asked for, never as a way to answer a data question.

## Platform Overview

| Domain | What it manages | Reference |
|---|---|---|
| **Integrations** | External tool connectors, data source syncs | Read `$SKILL_DIR/references/integrations.md` |
| **Workspaces** | Organizational containers, landing pages | Read `$SKILL_DIR/references/workspaces.md` |
| **Inbox** | The work an app has for you: read an item as the screen shows it (`alert <ITEM_ID> view`, one card with `--section`), why it is in its box or closed, decide, close or reopen it, a CVE or CWE across an app (`alerts cve`, `alerts cwe`), search the Inbox for a name or phrase (`alerts list --search`), an item's proof and brief | Read `$SKILL_DIR/references/inbox.md` |
| **Home** | An app's Home page: what needs you, what the app handled, how it is running; one card at a time; is the page current, refresh it; the proof behind an item | Read `$SKILL_DIR/references/home.md` |
| **Data questions** | ⭐ App first: look for the answer in the app and its curated artifacts (the Inbox, rules, dashboards and widgets, the app's own relations, Home, agents' recorded decisions) and quote it. Only for what no app artifact answers (typically an aggregation across the estate) use the data analyst, and say so | Inbox and the other app artifacts first (`$SKILL_DIR/references/inbox.md`); otherwise invoke the **`torana-data-analyst`** skill (it uses `torana-text-to-sql`, then runs the query) |
| **Chat** | ONLY when the customer's current message asks for Torana's assistant or the Chat tab ("ask Torana's assistant", "use the Chat tab"): ask it and wait for its reply; answer the questions it asks. See "You answer" above. For a data question see **Data questions** above | Read `$SKILL_DIR/references/chat.md` |
| **Dashboards and widgets** | Read a dashboard as the screen shows it, find out why a widget is empty or stale, sweep an app for broken widgets, create and edit | Read `$SKILL_DIR/references/dashboards.md` |
| **App and platform health** | Whether the app or the platform is working: read the Home page's own health line. Its first line is the verdict; the lines under it say what is wrong and what to do | `"$TORANA" app "$APP_ID" ai-home get --section health` (`references/home.md`, "How this app is running") |
| **Home questions** | "What matters to you": the questions an app's team tracks on its Home, and their answers | Read `$SKILL_DIR/references/workspaces.md` § "What matters to you" |
| **Agents** | AI agents, sessions, prompts, tools | Read `$SKILL_DIR/references/agents.md` |
| **Datalake** | Sink-table schema, ⚠️ **column reachability** — read BEFORE authoring any SQL | Read `$SKILL_DIR/references/datalake.md` |
| **Supply** | ⛔ **Why a column is empty** — read BEFORE trusting any 0-row result | Read `$SKILL_DIR/references/supply.md` |
| **Entity graph** | Asset graph, ⚠️ **edge direction**, node-key grammar, blast radius | Read `$SKILL_DIR/references/entity-graph.md` |
| **Detection** | Read and inspect rules, their runs and results, and the alerts they raised (the Inbox itself is in the Inbox row) | Read `$SKILL_DIR/references/detection.md` |
| **Proof** | ⭐ **How do we know?** Is this alert still true, which rows and rules every value came from, whether a saved proof still holds or replays, and AI Home V2's page as the platform computed it; how big a fix is (the platform's effort estimate, with how strong its evidence is and what each missing piece takes). Cite a claim, never re-derive it; quote an estimate, never recompute it | Read `$SKILL_DIR/references/detection.md` (`alert <id> proof`, `alert <id> brief`, `alert <id> assessment`), then `references/datalake.md` § "Is a saved proof still true?" (`datalake proof verify\|replay`) and `references/workspaces.md` (`workspace <id> ai-home get`) |
| **Insights** | Data transformers, dashboards, RAG | Read `$SKILL_DIR/references/insights.md` |
| **Tenants** | Users, roles, permissions, tokens, audit logs | Read `$SKILL_DIR/references/tenants.md` |
| **Context Lake** | Agent memory, user preferences, assembly | Read `$SKILL_DIR/references/context-lake.md` |

**When to read a reference file:** As soon as the user's request involves a specific
domain, read the corresponding reference file before executing any commands. It carries
what `--help` cannot: domain concepts, cross-group workflows, and the traps.

---

## Common Patterns (All Domains)

### Numbers: quote, never compute

Quote only numbers the platform printed. Never add, subtract, average or count rows yourself. Take a count
from the platform: `alerts boxes`, a `total` or `count` field, the length of a JSON array, or a `COUNT(*)`
query. If you must derive a figure (a difference, a share), label it **derived** and show the inputs it came from
("derived: <a> of <b> <things>", inputs beside it). A number the platform did not print and you cannot label is not
yours to give: say what you did read.

### Read all of it; never fill in what you did not see

Read the whole output. If you limited it (a page size, `head`, a row cap), say so. Never estimate, extrapolate or invent
what you did not see. Ask the platform for totals (a count, a `total` field, a `COUNT(*)` query). A few rows shown
as a labelled sample are fine.

### Answer exactly what was asked

Match the answer to the question's shape. "Whether": the verdict, and who decided it. "Which" or "what": name every
item, or give the count plus the top ones. "Where" or "what does it affect": the places. Extra context comes after the
direct answer, never instead of it.

### "I could not check" is not "none"

Never turn "I could not check" into "none". Say what you checked, how much of the whole that covered, and what is
unknown. When checking everything takes one call per item, offer a sample or a subset.

### Dates and times: as the product gives them

Quote dates and times exactly as the product prints them, from the field the question is about. Anything relative
("three days ago", "last week") that you work out yourself is labelled derived.

### When what was asked for is off or unavailable

Say so plainly and offer the closest supported route. Do not invent a substitute.

### Output formats

Every list command supports:

```bash
"$TORANA" <resource> list                    # human-readable text (default)
"$TORANA" <resource> list --format table     # bordered table
"$TORANA" <resource> list --format json      # machine-parseable
"$TORANA" <resource> list --all              # auto-paginate all results
```

Use `--format json` when you need to parse results programmatically.

### Plural vs Singular commands

Every resource follows a two-form pattern:

- **Plural** (`torana <resources>`) — collection operations: `list`, `create`. Use this to discover and list items.
- **Singular** (`torana <resource> <UUID>`) — everything for a specific item: `get`, `update`, `delete`, state transitions, sub-groups.

**The rule:** use plural to get an ID, then pass that ID to the singular form and run `--help` to see what you can do with it.

```bash
"$TORANA" rules list                      # find the rule ID
"$TORANA" rule <id> --help                # see all commands for that rule
"$TORANA" rule <id> execute               # act on it
```

This pattern applies to every resource: `rule`, `alert`, `agent`, `workspace`, `integration`,
`suite`, `alert-route`, `workflow`, `playbook`, `plan`, `template`, `transformer`,
`dashboard`, `widget`, `query`, `vulnerability`, `session`, and more.

### Discovering flags

```bash
"$TORANA" <resource> --help
"$TORANA" <resource> <UUID> --help
```

Run this before any operation you haven't used in this session — flags evolve with
CLI releases.

### Error reference

| CLI output | Meaning | Fix |
|---|---|---|
| `Not authenticated` | No cached token | Run OAuth login: `"$TORANA" auth login --web --no-browser --print-url`, open URL, copy code from page, then `"$TORANA" auth login --web --no-browser --code <code>` |
| `Session expired` | Refresh token invalid | Same as above |
| `403 Forbidden` | Token missing scope | Re-auth with correct account |
| `Cannot reach <url>` | Wrong base-url or network | `"$TORANA" config get base-url`; verify tunnel |
| `$TORANA: No such file or directory` | Sandbox venv not created | Re-run the bootstrap block above |

---

## Constructs — what `--help` cannot tell you

**Do not memorise the command list. Ask the CLI.** `--help` resolves at every level and, in
the groups below, carries worked examples. What it cannot give you is the *shape* of a
domain — which order things happen in, which way an edge points, when a zero means nothing.
That is what this table is for. Read the row, then run the entry point.

| Construct | The fact `--help` cannot give | Entry point |
|---|---|---|
| **Entity graph** | The graph is **directed**: forward ≠ reverse. Asking "what does this depend on" and "what depends on this" are different traversals, and node keys have a grammar (`cloud:`, `image:`, `repo:`). | `references/entity-graph.md` |
| **Supply / reachability** | **Never trust a 0-row result until supply says why.** Empty has several causes with different owners — nothing collects it, nobody connected it, or our bug. | `references/supply.md` |
| **Datalake authoring** | `reachable ≠ populated`, and there are two scopes with two owners. | `references/datalake.md` |
| **Drilling into a number** | The rows behind a cell come from the relation the transformer READS, not the table the widget names — `decompose` crosses that boundary and says so in `decomposed_via`. ⚠️ A `matches: false` in the RECONCILIATION means the materialized table is STALE, not that the drill-down is wrong. Paging is cursor-based: feed `next_cursor` back as `--cursor`; an omitted `--limit` still paginates. | `references/insights.md` |
| **Transformer build order** | Transformers read each other; a reader built before its input silently reads OLD data. `datalake transformers graph` shows the waves (from the SQL text — never `source_tables`); `rebuild-all` is ONE server-side build of everything in that order — Ctrl-C stops watching, not the build, and a second one is refused with the running build's id. | `references/insights.md` |
| **Why a widget is empty** | Four verdicts, four DIFFERENT owners (`blocked` / `empty` / `stale` / `live`). `unknown` is a real answer; `live` is never claimed without a measured row count. | `references/supply.md` |
| **Semantic resolution** | The same question asked five ways should reach ONE answer. `admin question-resolve` returns the canonical `question_id` — and **UNRESOLVED is a result recorded as demand**, not an error. | `references/datalake.md` |
| **VM domain** | Policy vocabulary binds *before* transformers render — bind first, or you render against unset values. `vm properties entities|resolve` answer "who owns this": TEAM is a declared team, REPO-OWNER is the code host's owner login, and they are never merged. | `vm --help` · `references/entity-graph.md` |
| **Findings loop** | `vulnerability → remediation → pentest → control` is one chain; each step writes back onto the finding. | `vulnerabilities --help` |
| **Ops diagnostics** | `etl dlq` is what gets you from "the run says partial" to the actual error text — its `PROJECT` column names the scope unit whose record failed. ⚠️ For a multi-container provider (GCP projects, AWS accounts) `partial` may simply mean one project was denied while others collected fine: check `integration <id> scope` and the per-project rows in `sync latest` BEFORE treating it as a failure. | `events --help`, `etl dlq --help`, `references/integrations.md` |
| **Ingestion** | The write-side entry point every scanner skill depends on (`ingest sarif`, `ingest assets`). | `ingest --help` |
| **Plural vs singular** | Plural = collection (`list`, `create`); singular = one instance by ID. | *(taught above)* |
| **Workspace scoping** | `workspace <id> …` delegates to the **same command objects** as the top level — same flags, same output, scoped. | `workspace --help` |
| **Context Lake** | ⚠️ **Discovery is weak here** — most of the group is flat, auto-generated commands. Use the curated sub-groups and the reference file, not `--help` browsing. | `references/context-lake.md` |
| **Discovery habit** | Run `--help` at every level before acting. In the groups above it carries runnable examples. | — |

> ⚠️ **Scope of the "just run `--help`" promise.** It holds for the groups named above and
> the other hand-curated ones (`rules`, `alerts`, `deployments`, `decorations`, `advisor`,
> `etl dlq`, `build proposal`, `vm policy|properties|transformers`, `workspaces schema-check`).
> Elsewhere in the CLI many commands are generated from the API and their help is a
> one-line restatement of the endpoint name. **A thin docstring means "undocumented", not
> "unusable"** — the command still works; you just won't learn its shape from `--help`.
> Fall back to the reference file for that domain.
