---
name: torana-skill
description: >
  Operate the Torana Security Platform via the `torana` CLI. Use this skill for ANY
  Torana task: managing detection rules, writing queries, triaging alerts, connecting
  integrations (GitHub, Jira, Slack, Wiz, AWS, etc.), syncing data sources, creating
  and managing workspaces, running AI agents, building workflows and playbooks, creating
  dashboards and data transformers, managing security programs and plans, administering
  tenant users/roles/permissions, and managing agent memory via the Context Lake.
  Trigger whenever the user mentions rules, detections, alerts, integrations, providers,
  syncs, workspaces, apps, agents, workflows, playbooks, dashboards, transformers, RAG,
  programs, plans, users, roles, permissions, memory, preferences, or anything related to
  the Torana platform. Note: "app" or "apps" in the UI means "workspace" in the CLI/API.
metadata:
  version: "2.2"
  last_updated: "2026-09-02"
  platform_version_tested: "2026.1"
---

# Torana Security Platform — CLI Skill

> **UI vs CLI terminology:** The platform UI calls them **Apps**. The CLI and API call them **Workspaces**. They are the same thing. When a user says "app", "my app", "create an app", or "the app I'm working in", translate that to `workspace` in all CLI commands and reference lookups.

> **⚠ Routing — BUILDING a program is NOT this skill's job.** When the user wants to
> build, create, generate, or deploy a **program** (a workspace app with transformers,
> rules, dashboards, KPIs …), you MUST invoke the **`torana-build`** skill (and the
> domain skill — e.g. **`torana-vm`** for vulnerability-management — on top of it).
> Those skills carry the mandatory grounding discipline; driving the `torana build`
> command family from here produces ungrounded programs that deploy green and return
> nothing. Specifically, NEVER run `blueprint run` or `cook run|step` from this skill's
> context — those launch the platform's own authoring agents (the "Torana harness") and
> are reserved for explicit user requests to exercise that path. A PreToolUse guard hook
> blocks them without the `TORANA_HARNESS=platform` override prefix.

> **Skill precedence:** If `torana-dev-skill` is also loaded, defer to it for:
> - **Auth** — use its direct `--email/--password` login, not the OAuth `--web` flow here
> - **CLI invocation** — use bare `torana` on PATH, not `"$TORANA"` sandbox variable
> - **curl / tg / tp / td** — permitted per `torana-dev-skill` rules, not the "no curl" rule here
>
> For all platform operations (rules, alerts, integrations, agents, etc.), the domain
> reference files in this skill remain authoritative — read them as normal.

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

`bootstrap.sh` installs the bundled `torana_cli` **and** `pantheon_shared` wheels into
`$TORANA_VENV`, and is a silent ~85ms no-op once the installed build matches the shipped
one. Run it every session — it is cheap, and it is what keeps a stale venv from silently
serving last week's CLI.

⛔ **Do NOT reimplement the bootstrap inline.** It used to live here as a shell block, and
three defects hid in the prose — all found on the first clean plugin install
(2026-09-15), none reproducible on a dev box:

1. It looked for the wheel only at `$SKILL_DIR/wheels`. The plugin layout puts wheels
   elsewhere, so it found nothing and died with *"cannot bootstrap the torana CLI"* while
   the wheel sat a few directories away.
2. It installed only the CLI wheel. `pantheon_shared` shipped in every artifact, the
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

### Step 1 — Configure the Torana server URL

Resolve the URL of **the customer's own Torana instance** (e.g.
`https://acme.toranasecurity.ai`) and persist it. **Never hardcode, guess, or fall
back to a demo/sample server.** Precedence:

```bash
# 1. explicit env override (advanced / CI)
# 2. an OPTIONAL pre-baked config — only present for enterprise "managed" installs;
#    NOT shipped in the default bundle
# 3. a URL already saved from a previous session
if [ -n "$TORANA_BASE_URL" ]; then
    "$TORANA" config set base-url "$TORANA_BASE_URL"
elif [ -s "$SKILL_DIR/config/base-url.yml" ]; then
    "$TORANA" config set base-url "$(cat "$SKILL_DIR/config/base-url.yml")"
fi

if URL="$("$TORANA" config get base-url 2>/dev/null)"; then
    echo "Torana URL: $URL"
else
    echo "BASE_URL_NOT_CONFIGURED"
fi
```

If the block prints **`BASE_URL_NOT_CONFIGURED`**, the customer hasn't told us their
instance yet. **Ask them:** *"What's your Torana URL? (e.g.
`https://acme.toranasecurity.ai`)"* — then persist it and continue:

```bash
"$TORANA" config set base-url "<the-URL-the-user-gave>"
```

A returning user who configured it before will see `Torana URL: …` printed — reuse
it, don't ask again. (`config/base-url.yml` is **not** shipped in the bundle; an
enterprise admin may drop one in to pre-configure a managed install, and it then
wins over a previously-saved value.)

### Step 2 — Check auth state

```bash
"$TORANA" auth status
```

- `Authenticated as <email>` → ready, proceed directly to the user's request.
- `Not authenticated` or `Token expired` → continue to Step 3.

### Step 3 — Log in (OAuth only)

```bash
# Step 1: run ONCE — prints the URL and saves PKCE state to disk
"$TORANA" auth login --web --no-browser --print-url
```

Copy the URL from the output above and show it to the user. Wait for them to open it
in their browser and log in.

**Do NOT run `--print-url` again** — each invocation generates a new PKCE pair and
overwrites the saved state, invalidating any previously obtained token.

After the user clicks Authorize in the browser, the page will display an
**authorization code**. Ask the user to copy it, then run:

```bash
# Step 2: exchange the authorization code for tokens
"$TORANA" auth login --web --no-browser --code <code-from-browser-page>
```

**If `Session expired` appears during later commands:** repeat Steps 2–3.

---

## ⚠️ Two CLI shapes that look like missing capabilities

Both cost a full debugging detour when guessed wrong, and both produce an error that reads
like "the platform cannot do this" when in fact only the path was wrong.

1. **There is no `torana build-v2` group.** The build FSM is `torana build proposal <id>
   <verb>`; the SA observability commands live under `torana admin build`. Two groups.
2. **There is no `torana corpus` group.** Corpus commands are `torana admin
   question-coverage` and `torana admin question-resolve`.
3. **There is no `torana bundles` group.** App-bundle discovery is `torana build bundles
   list`; installing one is a FLAG on workspace creation (`workspaces create --bundle <id>`),
   not a verb of its own. Once a workspace EXISTS, its bundle verbs live under
   `torana workspace <id> build bundles …` (install, install-resume, install-status,
   install-detail) — the scoped form needs no ids.

⛔ **A `No such command` or a 404 is ambiguous by construction** — it means EITHER the
capability does not exist OR you asked the wrong path OR the deployed service is behind the
source. Confirm which before reporting a gap; `torana <group> --help` settles it in one call.

## Platform Overview

| Domain | What it manages | Reference |
|---|---|---|
| **Integrations** | External tool connectors, data source syncs | Read `$SKILL_DIR/references/integrations.md` |
| **Workspaces** | Organizational containers, landing pages | Read `$SKILL_DIR/references/workspaces.md` |
| **Agents** | AI agents, sessions, prompts, tools | Read `$SKILL_DIR/references/agents.md` |
| **Datalake** | Sink-table schema, ⚠️ **column reachability** — read BEFORE authoring any SQL | Read `$SKILL_DIR/references/datalake.md` |
| **Supply** | ⛔ **Why a column is empty** — read BEFORE trusting any 0-row result | Read `$SKILL_DIR/references/supply.md` |
| **Entity graph** | Asset graph, ⚠️ **edge direction**, node-key grammar, blast radius | Read `$SKILL_DIR/references/entity-graph.md` |
| **Build** | The `proposal → blueprint → cook → deploy` state machine | Read `$SKILL_DIR/references/build.md` |
| **Detection** | Rules, alerts, suites, queries, alert routing | Read `$SKILL_DIR/references/detection.md` |
| **Workflows** | Workflows, playbooks, schedulers | Read `$SKILL_DIR/references/workflows.md` |
| **Insights** | Data transformers, dashboards, RAG | Read `$SKILL_DIR/references/insights.md` |
| **Programs** | Security programs, plans, templates | Read `$SKILL_DIR/references/programs.md` |
| **Tenants** | Users, roles, permissions, tokens, audit logs | Read `$SKILL_DIR/references/tenants.md` |
| **Context Lake** | Agent memory, user preferences, assembly | Read `$SKILL_DIR/references/context-lake.md` |

**When to read a reference file:** As soon as the user's request involves a specific
domain, read the corresponding reference file before executing any commands. It carries
what `--help` cannot: domain concepts, cross-group workflows, and the traps.

---

## Common Patterns (All Domains)

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
| **Build lifecycle** | `proposal → blueprint → cook → deploy` is a state machine, not four independent verbs. `blueprint run` / `cook run` / `cook step` launch the platform's own authoring agents and are **hook-blocked** — never run them from this skill (see the routing note at the top). | `references/build.md` |
| **Entity graph** | The graph is **directed**: forward ≠ reverse. Asking "what does this depend on" and "what depends on this" are different traversals, and node keys have a grammar (`cloud:`, `image:`, `repo:`). | `references/entity-graph.md` |
| **Supply / reachability** | **Never trust a 0-row result until supply says why.** Empty has several causes with different owners — nothing collects it, nobody connected it, or our bug. | `references/supply.md` |
| **Datalake authoring** | `reachable ≠ populated`, and there are two scopes with two owners. | `references/datalake.md` |
| **Explaining a build** | `lifecycle` says which PHASES ran; `admin build trace` says what each step DECIDED and which gate refused it. A gate repeated with a rising `attempt` is a retry loop. ⚠️ A build with **no** gate rows predates the evidence — read that as *unknown*, never as *passed*. | `references/build.md` |
| **Uninstalling a version** | Deploy is no longer one-way: `build versions uninstall` removes a **contiguous suffix** of the stack, newest first (`11`, `10 11`, …) — an interior or non-adjacent request is refused. ⛔ IRREVERSIBLE: the proposals become `uninstalled`, which is TERMINAL — rebuild from intent, there is no redeploy. Dry-run is the DEFAULT. | `references/build.md` |
| **Drilling into a number** | The rows behind a cell come from the relation the transformer READS, not the table the widget names — `decompose` crosses that boundary and says so in `decomposed_via`. ⚠️ A `matches: false` in the RECONCILIATION means the materialized table is STALE, not that the drill-down is wrong. Paging is cursor-based: feed `next_cursor` back as `--cursor`; an omitted `--limit` still paginates. | `references/insights.md` |
| **Why a widget is empty** | Four verdicts, four DIFFERENT owners (`blocked` / `empty` / `stale` / `live`). `unknown` is a real answer; `live` is never claimed without a measured row count. | `references/supply.md` |
| **Semantic resolution** | The same question asked five ways should reach ONE answer. `admin question-resolve` returns the canonical `question_id` — and **UNRESOLVED is a result recorded as demand**, not an error. | `references/datalake.md` |
| **Question corpus** (SA) | What the platform intends to answer, and what blocks it. ⛔ `validated` ≠ "has SQL" — SQL can exist that was never proved to run. `admin corpus show <id>` gives the MEASURED reason a question is blocked; `roadmap` groups those reasons by the WORK that would fix them, splitting **schema additions** (no column exists, so no ETL can help) from **blocked columns** (a writer or a join path). ⚠️ A roadmap row is a blocked COLUMN, not a project count. | `references/datalake.md` |
| **VM domain** | Policy vocabulary binds *before* transformers render — bind first, or you render against unset values. | `vm --help` |
| **Findings loop** | `vulnerability → remediation → pentest → control` is one chain; each step writes back onto the finding. | `vulnerabilities --help` |
| **Ops diagnostics** | `etl dlq` is what gets you from "the run says partial" to the actual error text — its `PROJECT` column names the scope unit whose record failed. ⚠️ For a multi-container provider (GCP projects, AWS accounts) `partial` may simply mean one project was denied while others collected fine: check `integration <id> scope` and the per-project rows in `sync latest` BEFORE treating it as a failure. | `events --help`, `etl dlq --help`, `references/integrations.md` |
| **Ingestion** | The write-side entry point every scanner skill depends on (`ingest sarif`, `ingest assets`). | `ingest --help` |
| **Plural vs singular** | Plural = collection (`list`, `create`); singular = one instance by ID. | *(taught above)* |
| **Workspace scoping** | `workspace <id> …` delegates to the **same command objects** as the top level — same flags, same output, scoped. | `workspace --help` |
| **App bundles** | A starter app installed whole via `workspaces create --bundle <id>`. ⛔ Discovery lives under **`build bundles list`**, not `workspaces` — and the install is **ASYNCHRONOUS**, so a returned workspace id is not proof it installed; poll `INSTALL STATUS` to `installed`/`failed`. On `failed`, **re-run `install` — never re-create the workspace**: it is idempotent by state (resumes a failed try, watches a running one, no-ops when done). ✅ Scoped form takes no ids: `workspace <id> build bundles install\|install-detail`. | `references/workspaces.md` |
| **Context Lake** | ⚠️ **Discovery is weak here** — most of the group is flat, auto-generated commands. Use the curated sub-groups and the reference file, not `--help` browsing. | `references/context-lake.md` |
| **Discovery habit** | Run `--help` at every level before acting. In the groups above it carries runnable examples. | — |

> ⚠️ **Scope of the "just run `--help`" promise.** It holds for the groups named above and
> the other hand-curated ones (`rules`, `alerts`, `deployments`, `decorations`, `advisor`,
> `etl dlq`, `build proposal`, `vm policy|properties|transformers`, `workspaces schema-check`).
> Elsewhere in the CLI many commands are generated from the API and their help is a
> one-line restatement of the endpoint name. **A thin docstring means "undocumented", not
> "unusable"** — the command still works; you just won't learn its shape from `--help`.
> Fall back to the reference file for that domain.

### Platform transformer definitions — read them before you author SQL

Reviewed, validated definitions. **Reuse beats authoring**: a reviewed definition is more
trustworthy than fresh SQL, and authoring a second query for a solved problem is how two
definitions of "open vulnerability" end up in one platform.

⛔ **`definitions list` is the surface. `catalog list` is NOT** — it serves the OLD
`vm_transformer_catalog_entry` table, which holds **40** of the **77** live definitions and
is being retired. Measured 2026-09-16 on T2: `catalog list` → 40 rows, `definitions list` →
77 (37 bootstrap + 40 ported primitives). Reading the old surface silently hides 37
definitions, and a definition you cannot see is one you will re-author.

```bash
"$TORANA" vm transformers definitions list          # ALL 77, untruncated (~20 KB — read it in one pass)
"$TORANA" vm transformers definitions show <name>   # its SQL, materialization config, semantics
```

**Judge on `one row` (the grain), never on a score or on topic.** The grain is what one row
IS — "one row per open finding" and "one row per team per month" answer different questions
however similar they read.

⚠️ `catalog search` ranks by embedding similarity and **is useful as a recall probe** — it
spans both halves of the store and returns each candidate's `one row` line, plus a `projects:`
line listing the columns it actually SELECTs. Use it to shortlist. ⛔ **Its score is not a
verdict**: measured, 0.010 separates the worst true hit from a genuine gap, and a query with no
relationship to the domain ("quarterly cafeteria menu rotation") scored 0.562 against a genuine
match at 0.616. **Shortlist by search, decide by grain.**

⛔ **Leave `--top-k` and `--threshold` alone** — and note they are NOT symmetric. `top-k`
defaults wide (10) because a wider candidate set costs tokens while a missed entry costs a
duplicate definition forever. The threshold defaults to 0.7 and ⚠️ **must not be lowered**:
measured 2026-09-16 on T2, at 0.45 an unrelated need ("average rainfall in Bangalore in July")
comes back `is_miss=False` with ten cleared candidates, while a genuine need gains only two. ⛔
`is_miss` drives `--record-miss`, so a lower bar means a genuinely novel need records **no gap
at all**, silently.

⚠️ **A missing `projects:` line means the column list could NOT be resolved** (a
`SELECT <alias>.*` form) — **not** that the entry projects nothing. Judge such a candidate on
grain; never reject it for a column you cannot see. A judge shown no columns once rejected a
fitting entry for "not projecting `days_open` and `threat_score`" — both of which it projects.

**When none fits, record the miss.** This is not optional bookkeeping — it is the only
signal that tells curators what to pre-build next, and the transformer API rejects an
authored write without the decision id.

```bash
"$TORANA" vm transformers catalog record-miss "<need, VERBATIM>" \
    --gap-category <missing_column|missing_hole|wrong_grain|different_join|genuinely_novel|platform_defect|needs_caller> \
    --near-miss <closest definition> \
    --rationale "<which axis fails, against which closest entry>" \
    --question-id <EM-NNN>      # ⛔ ONLY on a `strong` resolve — see below
```

⛔ **The need text must be VERBATIM.** The phrasing IS the demand signal; a paraphrase
destroys what the curation queue reads.

#### ⭐ `--question-id` — what makes the same question asked five ways count ONCE

**Free text cannot be grouped.** Without this the queue ranks by phrasing, so one need worded
two ways outranks a need asked twice — and the ranking is what decides which entry a curator
authors next.

**Get the id from the corpus resolver, and read its `resolve_strength`:**

```bash
"$TORANA" --format json admin question-resolve "<the need, VERBATIM>"
# -> {"question_id": "EM-011", "confidence": 0.714, "resolve_strength": "strong", ...}
```

| `resolve_strength` | what to do |
|---|---|
| `strong` | pass `--question-id <id>` |
| `weak` | ⛔ **pass NOTHING.** A weak resolve is a CANDIDATE, not an answer |
| `none` | pass nothing — the need is unresolved, which is itself the demand signal |

⛔ **NEVER tag from a `weak` resolve.** The lexical score has no notion of GRAIN, so the bands
overlap and no threshold separates them: a worklist ask landed on **EM-038 — a *monthly trend*
question — at 0.35, above two real paraphrases at 0.29.** A wrong `question_id` is **worse than
NULL**: NULL is visibly absent and gets fixed, a wrong id is invisibly wrong and silently
merges two unrelated needs into one queue row.

⚠️ **Most needs will not resolve, and that is CORRECT.** The resolver declines rather than
guesses. ⛔ **Do not lower the bar, retry with reworded text, or reach for the nearest
alternative to "get an id"** — an unresolved need is a real finding that tells curators the
corpus is missing a question. Omitting the flag is always safe; inventing an id is not.

⛔ **A resolve failure must NEVER stop the miss being recorded.** Record without the flag.
A fix that makes the skill stop recording misses would be far worse than the untagged rows
it was meant to prevent.

⚠️ **A rationale must name an AXIS, not report failure.** Weak: *"no entry matched"*.
Strong: *"em_012 is finding-grain; this needs one row per (team, month), so the counts would
double"*. The difference decides whether a curator widens an existing definition or writes a
new one — completely different amounts of work.

⛔ **Running a test, probe or verification lane? `export TORANA_DECISION_ORIGIN=test` FIRST.**
An unlabelled probe is recorded as real demand and INVERTS the curation ranking. Measured:
87 of 225 rows (40%) in this queue were unlabelled test probes, and they made
`finding_enriched` look like the #1 gap at 55 misses — 41 of them probes — while the real
#1 was `asset_posture` at 19. Curating on that ranking authors the wrong thing.
