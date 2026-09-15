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

## Bootstrap — Run Every Session (never skip the reinstall)

```bash
export TORANA_VENV="$HOME/.torana-venv"
export TORANA="$TORANA_VENV/bin/torana"

# Resolve SKILL_DIR once — the runtime sets it, but it is NOT reliably exported into an
# agent-issued Bash shell. When it's empty, the bare glob "$SKILL_DIR/wheels/torana_cli-"*.whl
# targets /wheels/ (root), matches nothing, and bash passes the LITERAL unexpanded pattern to
# uv → "invalid wheel filename". Resolve it from the known skill roots and export so every
# downstream $SKILL_DIR use (wheel, config, references) is valid for the whole session.
if [ -z "$SKILL_DIR" ] || [ ! -d "$SKILL_DIR/wheels" ]; then
  for d in "$HOME/.claude/skills/torana-skill" \
           "$HOME/Library/Application Support/Claude/skills/torana-skill" \
           "$HOME/.config/claude/skills/torana-skill"; do
    [ -d "$d/wheels" ] && export SKILL_DIR="$d" && break
  done
fi

# Expand the glob to a real path (newest wheel) so the installer never receives a literal pattern,
# and a stale older wheel left in wheels/ can't get installed over the current one.
WHEEL=$(ls -t "$SKILL_DIR"/wheels/torana_cli-*.whl 2>/dev/null | head -1)

# Install the wheel into $TORANA_VENV. Prefer `uv` (fast), but FALL BACK to stdlib venv + pip when
# uv is not installed — a bare cloud/VM box often has only python3. If NO wheel is bundled AND a
# working `torana` already exists on PATH (a dev-stack / pre-installed box), use that instead of
# failing. The goal: end with a runnable CLI no matter which of the three environments we are in.
if command -v uv >/dev/null 2>&1 && [ -n "$WHEEL" ]; then
  uv venv --python 3.12 "$TORANA_VENV"
  uv pip install --python "$TORANA_VENV/bin/python" --reinstall "$WHEEL"
elif [ -n "$WHEEL" ] && command -v python3 >/dev/null 2>&1; then
  # No uv — stdlib venv + pip. Same end state (a reinstalled current wheel in $TORANA_VENV).
  python3 -m venv "$TORANA_VENV"
  "$TORANA_VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  "$TORANA_VENV/bin/python" -m pip install --quiet --force-reinstall "$WHEEL"
elif command -v torana >/dev/null 2>&1; then
  # No bundled wheel to install, but a torana is already on PATH (dev-stack / pre-installed).
  # Point $TORANA at it and skip the venv build. (Can't guarantee it is current — see warning below.)
  export TORANA="$(command -v torana)"
else
  echo "ERROR: cannot bootstrap the torana CLI — no uv, no bundled wheel + python3, and no torana on PATH." >&2
fi

# Assert the CLI we ended up with actually matches the wheel this skill shipped. Without this
# check a stale CLI is INVISIBLE: platform commands appear "missing" (the group simply isn't
# registered), so the caller concludes a capability does not exist and falls back to raw SQL /
# curl — reaching WRONG conclusions from a tooling artifact.
#
# ⛔ COMPARE THE COMMIT, NOT THE VERSION STRING (SKILL-1). A version compare is blind to
# this defect BY CONSTRUCTION: two builds four days apart, with different bytes and
# different command groups, both call themselves `0.1.2` — measured 2026-08-14,
# dist/ (655,342 B) vs the skill wheel (652,564 B). The version compare passes on both
# and reports "no skew" while the caller runs a build missing whole command groups.
# The commit is the field that can actually tell two builds apart, so it is the field
# this check reads. It is also the SKILL-1 residual made harmless: version REUSE across
# builds no longer defeats the check, because the check no longer looks at the version.
INSTALLED_COMMIT=$("$TORANA" version --format json 2>/dev/null \
  | python3 -c 'import json,sys;print(json.load(sys.stdin).get("commit",""))' 2>/dev/null)
INSTALLED_VER=$("$TORANA" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
# The wheel records its own build commit in torana_cli/_version.py; read it straight out
# of the zip WITHOUT installing, so bundled and installed are compared on the same field.
BUNDLED_COMMIT=$(python3 - "$WHEEL" <<'PY' 2>/dev/null
import re, sys, zipfile
try:
    with zipfile.ZipFile(sys.argv[1]) as z:
        src = z.read("torana_cli/_version.py").decode()
    m = re.search(r'COMMIT_SHA\s*=\s*"([^"]*)"', src)
    print(m.group(1) if m else "")
except Exception:
    print("")
PY
)
echo "torana CLI: installed=${INSTALLED_VER:-unknown} commit=${INSTALLED_COMMIT:0:8}"
if [ -n "$BUNDLED_COMMIT" ] && [ -n "$INSTALLED_COMMIT" ] \
   && [ "$BUNDLED_COMMIT" != "$INSTALLED_COMMIT" ]; then
  echo "WARNING: BUILD skew — running commit ${INSTALLED_COMMIT:0:8} but this skill bundles ${BUNDLED_COMMIT:0:8}." >&2
  echo "         These may report the SAME version string and still differ in which" >&2
  echo "         commands exist. A command reported as 'missing' may simply be absent" >&2
  echo "         from the build you are running." >&2
  echo "         Re-run the install block above before concluding a capability does not exist." >&2
elif [ -z "$INSTALLED_COMMIT" ]; then
  echo "WARNING: the installed CLI reports no build commit — it predates build identity" >&2
  echo "         (CLI-44) and CANNOT be told apart from any other build of the same" >&2
  echo "         version. Reinstall from a current wheel before trusting a 'missing'" >&2
  echo "         verdict on any command." >&2
fi

# SURFACE CHECK — the version string is NOT sufficient on its own.
#
# Two DIFFERENT builds can carry the SAME version. Measured 2026-08-04: the wheel in
# dist/ and the wheel bundled into the skill zips both call themselves 0.1.2, but their
# bytes differ (37b5f5d1… vs f5397aa1…) and only one of them contains the `decorations`
# group. The note below already warns that skills re-bundle "sometimes at the same version
# number" — this is the check that makes that detectable instead of merely documented.
#
# The failure this prevents is not a crash. It is a WRONG CONCLUSION: a missing group makes
# a real capability look nonexistent, the caller falls back to raw SQL or curl, and files a
# phantom bug. That is exactly how CLI-29/CLI-30 were filed as "missing" when the verbs
# existed. So assert on the SURFACE (do the groups resolve?), not just the label.
#
# Add a group here when a skill starts depending on it. Cheap: `--help` is offline.
# Cover the groups most likely to be NEW — those are the ones a stale wheel silently
# lacks, and the ones whose absence gets misread as "the platform can't do that".
MISSING_GROUPS=""
for g in vm entity-graph decorations datalake build ingest events; do
  "$TORANA" "$g" --help >/dev/null 2>&1 || MISSING_GROUPS="$MISSING_GROUPS $g"
done
# `datalake supply` is a SUB-group — a wheel can carry `datalake` and still lack it.
"$TORANA" datalake supply --help >/dev/null 2>&1 \
  || MISSING_GROUPS="$MISSING_GROUPS datalake-supply"
if [ -n "$MISSING_GROUPS" ]; then
  echo "WARNING: the installed CLI is missing expected command group(s):$MISSING_GROUPS" >&2
  echo "         Same version string, DIFFERENT build — a stale or divergent wheel." >&2
  echo "         Do NOT conclude these capabilities are absent from the platform." >&2
  echo "         Reinstall from a current wheel (make claude-skills) before proceeding." >&2
else
  echo "torana CLI surface: OK (vm, entity-graph, decorations, datalake[+supply], build, ingest, events)"
fi
```

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

### VM transformer catalog — read it before you author SQL

Reviewed, validated definitions. Read the list ONCE per build and hold it: nothing is ranked
or filtered, so **you** decide which (if any) entry satisfies the need — judge on each one's
`one row` grain. When one fits, reference its entry id instead of writing SQL. When none
does, record the miss *before* authoring — the transformer API rejects the write without
that decision id.

```bash
"$TORANA" vm transformers catalog list              # the whole catalog, untruncated
"$TORANA" vm transformers catalog show <entry-id>   # its SQL and full provenance
"$TORANA" vm transformers catalog record-miss "<need>" \
    --gap-category <category> --near-miss <closest entry id> \
    --rationale "<which axis fails, against which closest entry>"
```

⚠️ `catalog search` ranks by textual resemblance — human spelunking only, **not** the build
path: the words for a need rarely match the words for a shape.
