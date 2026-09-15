# torana CLI — the verbs the skill relies on

The `torana` CLI is the proprietary surface. It is **self-documenting** — always run
`torana <group> --help` and `torana <group> <verb> --help` before an unfamiliar command;
do not guess flags. This file lists only the verbs the skill leans on and the **non-obvious
output shapes**. Bootstrap/auth conventions come from `torana-skill` (or `torana-dev-skill`
in a dev stack).

`--format json --raw` gives a bare array for lists (no pagination envelope); `--format
json` on a `get` gives the object. Some `get` payloads wrap the object under `data` — read
both (`d.get("data", d)`). The engine already handles all of this; you mostly need the CLI
directly for **discovery** and **VERIFY**.

## Discovery (read-only)  — see `discovery.md` for the ordered protocol
```
"$TORANA" entity-graph edges list | neighbors <KEY> | reachable <FROM> | scopes | health
"$TORANA" datalake query --format json --sql "<SQL>"   # execute SQL — ALWAYS --format json, read .results
"$TORANA" datalake schema table <table> --scope platform | all-columns --scope platform | list-existing | query-hints   # schema + enums (VERIFY casings vs data)
"$TORANA" integrations list | types
"$TORANA" workspaces list                # then workspace <id> get
"$TORANA" admin question-resolve "<text>"   # probe 0: phrasing -> canonical question_id (or UNRESOLVED = demand)
"$TORANA" admin build trace <proposal-id>  # intent -> steps -> DECISIONS -> gates -> deploy
"$TORANA" admin build trace <id> --failed-only --gates-only --step 1.2
"$TORANA" admin build gate-evidence <id>   # raw gate rows: outcome, attempt, reason
"$TORANA" admin build build-health --since 30   # how the build system is operating, per harness
"$TORANA" admin build versions <workspace-id>   # every version of one app
"$TORANA" widgets verdict <widget-id>      # why a widget is empty, and WHO can fix it
"$TORANA" vm transformers catalog by-question   # misses grouped by what was ASKED (SA)
"$TORANA" vm policy vocabulary           # closed policy vocabulary: key, qualified {{vocab:...}} path, shape, render verbs, default
"$TORANA" vm policy vocabulary-browse [--tenant <id>] [--category <c>]   # THIS tenant's RESOLVED values + provenance (origin)
"$TORANA" vm policy vocabulary-show <key>   # full provenance for one key (layer · document · quote · ratifier)
```

**Policy vocabulary (discovery layer 6).** `vm policy vocabulary` is the platform-neutral CLOSED SET of
tunable VM domain settings — the same catalog as `references/vocabulary-catalog.md`. Each row's
`qualified_path` + `valid_render_verbs` is exactly what an artifact SQL `{{vocab:...}}` placeholder must
carry, so the platform resolves the value per-tenant at install. `vm policy vocabulary-browse` returns
THIS tenant's *resolved* values with `origin` (`from_policy` = extracted from a policy doc,
`system_default` = platform default, `manually_set` = override, `conflicted` = sources disagree). Reason
with the resolved values; AUTHOR the placeholders.

## Reading a live program (what the engine reconciles)
| type | list | instance |
|---|---|---|
| transformers | `transformers list --workspace-id <ws>` | `transformer <id> get` → `custom_sql`, `destination_table`, `depends_on` |
| rules | `rules list --workspace-id <ws>` | `rule <id> get` → `sql_command`, `severity` |
| dashboards | `dashboards list --workspace-id <ws>` | `dashboard <id> get` → `widgets[]` (each has `query_id`, `widget_type`, `display_config`) |
| widgets | — | `widget <id> get/render/data` ; SQL is in the linked **query** |
| queries | — | `query <id> get` → `sql_command` (a widget's SQL) ; `query <id> update --sql` |
| KPIs | `workspace <ws> kpi list` | (landing-zone; SQL at `data_source.query`) |
| attention | `workspace <ws> attention list` | (landing-zone; SQL at `condition.query`) |
| home/pins | `workspace <ws> home config dump` | → `zones[type=pinned_widgets].config.pinned_widgets` |
| schedulers | `schedulers tasks --workspace-id <ws>` | `schedulers get <id>` → `schedule_expression`, `task_type`, `<type>_id` |
| routes | `alert-routes routing-rules --workspace-id <ws>` | `alert-route <id> get` → `priority`, `enabled`, filters, `destination_config` |
| playbooks | `playbooks list` | `playbook <id> get/render` |

## Dashboard ↔ widget membership (many-to-many)
```
"$TORANA" dashboard <id> widgets list           # widgets on the dashboard
"$TORANA" dashboard <id> widgets add <widget_id>
"$TORANA" dashboard <id> widgets remove <widget_id> --yes
```
A standalone widget is created as **query → widget → attach**: `queries create` (with
`sql_command`) → `widgets create` (with `query_id`, `widget_type`, and the REQUIRED
per-type `display_config`) → `dashboard <id> widgets add <wid>`. The engine does this for
you on re-apply; you'd only touch it directly when debugging.

## VERIFY signals (ASSESS + post-apply)
```
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) FROM <prefixed_view>"   # materialized non-empty?
"$TORANA" widget <id> render                                       # widget rows + status (dead widget?)
"$TORANA" alerts list --rule-id <id>                               # per-rule alert volume over a window (noisy?)
```

### Rendering an app's widgets — the VERIFY sweep

**A deployed app is not verified until every widget has been RENDERED.** Validate proves the SQL
parses; render proves the app *shows something*. Do this for the whole app, not a sampled widget —
the dead ones are exactly the ones you would not think to sample.

Enumerate, then render each:
```
"$TORANA" dashboards list --workspace-id <WS>            # the app's dashboards
"$TORANA" dashboard <DASH_ID> widgets list               # ← widgets OF a dashboard
"$TORANA" widget <WID> render                            # the rows the UI draws
"$TORANA" dashboard <DASH_ID> render                     # or: every widget of one dashboard at once
```

⚠️ **Enumerate via `dashboard <id> widgets list`, NOT `widgets list --dashboard-id <id>`.** The
top-level filter does not bind — it returns the tenant's whole widget set with a blank
`DASHBOARD_ID` column, so a sweep built on it renders the wrong app's widgets and reports a
confident pass. The per-dashboard form returns the real membership (and its `QUERY` column).

`render` returns a flat envelope — read `status` + `data` (`--format json`):

| `status` | `data` | Verdict |
|---|---|---|
| `success` | `{rows}` / `{labels,datasets}` / `{value}` | **OK** — count the rows/labels; a scalar `value` of 0 still deserves a look |
| `no_data` | `null` | **Dead widget** — SQL ran, returned nothing |
| `error` | `null` (+ `error_message`) | **Broken** — SQL or config failure |

**The fastest whole-app sweep is per-dashboard**: `dashboard <id> render` returns every widget in
one call plus a `total_widgets` / `successful_widgets` / `failed_widgets` rollup, where
`successful_widgets` counts only `status: success` — a `no_data` widget lands in `failed_widgets`.
So the rollup is a good *triage* signal (`successful == total` → the dashboard is fully alive), but
it does not distinguish "SQL returned nothing" from "SQL blew up". Read each widget's own `status`
to tell those apart, since they have completely different fixes.

Render is **cached (~30 min TTL)** — pass `--refresh` when verifying immediately after a deploy or
a transformer run, or you will grade the previous build. The envelope also carries `data_as_of` +
`freshness_detail` (per-source, with `is_bottleneck`) — a widget can be `success` and still be
showing stale numbers.

**A `no_data`/`EMPTY` widget is a finding, not a footnote — diagnose it, don't just count it:**
```
"$TORANA" widget <WID> why           # predicate funnel — WHICH filter collapsed the row set
"$TORANA" widget <WID> provenance    # lineage + "N in → M out" per hop
"$TORANA" widget <WID> explore --show-sql   # the actual SQL behind it
```
`why` is the one that pays: the classic VM failure is a widget reading 0 not because there is no
risk, but because it filters on a column that is NULL for every ingested row (`= false` on a
nullable boolean discards the lot). `provenance`'s row accounting catches the sibling failure —
a widget rendering a *confident, precise, wrong* number off a fraction of its base table.

**Drilling into a widget's number** — `torana widget <id> decompose --key <col>=<value>` returns
the individual records behind one aggregate cell, with a RECONCILIATION block proving they explain
it. ⛔ The full contract (boundary crossing, the ✓/✗/· marks, cursor paging) is documented ONCE in
`torana-skill`'s `references/insights.md` § "Drill into a number" — read it there rather than
restating it here, so the two cannot drift.

**Empty tenant caveat** (see `discovery.md`): on a tenant with no data, `no_data` everywhere is the
expected, correct result — mark the program `pending-grounding` rather than chasing each widget.
The sweep is diagnostic only where the underlying tables actually hold rows.

## Gotchas worth knowing
- **`datalake query`: ALWAYS pass `--format json` and read `.results`.** The default text
  output wraps the result JSON across terminal-width lines, so `grep`/`tail` parsing grabs
  fragments and forces re-queries. `--format json` → clean `{ "results": [...], "count": N }`.
- **Parse CLI JSON with a heredoc, NOT `python3 -c`.** A one-liner
  `python3 -c "…f\"{d[\"k\"]}\"…"` breaks: the backslash-escaped quotes inside a single-quoted
  `-c` string are a syntax error (this bites repeatedly). Pipe into a **`python3 - <<'PY'`
  heredoc** instead — real quotes, no escaping:
  ```bash
  "$TORANA" datalake query --format json --sql "<SQL>" | python3 - <<'PY'
  import sys, json
  d = json.load(sys.stdin)
  for r in d.get("results", []):
      print(r["cve_id"], r["severity"])
  PY
  ```
  The `<<'PY'` (quoted delimiter) stops the shell touching `$` inside the script.
- **Two JSON envelope shapes — know which you're parsing.** *Collections* (list verbs:
  `rules list`, `vm policy vocabulary`, …) return `{ "items": [...], "total": N }` (use
  `--raw` for a bare array). *Details/reports* (a `get`, or `build proposal show`,
  `vm policy vocabulary-browse`) return a **named-key object** (`{proposal, blueprint, …}`,
  `{rollup, categories}`) — read the named facets, there is no `items`. Don't assume `items`
  everywhere.
- **Authoring `{{vocab:…}}`? Use `vm policy vocabulary --keys`.** The flat TAB-separated dump
  (`key⇥qualified_path⇥shape⇥render_verbs⇥default⇥sec-crit`) never truncates — unlike the
  table view, which clips the qualified-path/default columns you author against. And
  `vm policy vocabulary-browse` now carries a **`render_safe`** flag per key: `false` means the
  key resolves to null for this tenant, so authoring it as a **bare** `{{vocab:…}}` literal
  fails render at validate — reference it by policy key instead.
- **Severity casing is NOT guaranteed** — it can be **split by source** (e.g. lowercase
  `critical`/`high` from a GCP container scanner, Title-Case `Critical`/`High` from SARIF).
  **Discover it** (`GROUP BY severity` on the raw column) before writing a predicate; when
  in doubt use `LOWER(severity) = 'critical'`. (The engine's own artifacts normalize to
  Title Case, but *live query data may not be normalized yet* — never assume.)
- **`is_deleted` may be NULL, not `false`** on some ingested rows — a blanket
  `WHERE is_deleted = false` can return 0. Check the column before filtering on it.
- **A widget's SQL is its query**, not a field on the widget — read/update via `query`.
- **`display_config` is required** on widget create per type (bar→x_axis/y_axis,
  table→columns, pie→label/value) — the standalone create path enforces it.
- If a capability is **missing or broken** in the CLI (e.g. a wrong HTTP method, an
  undiffable field), that is a **fix at the CLI/API**, filed and done in the same change —
  never a workaround hidden in the skill. (Precedent this session: `schedulers update-task`
  used POST on a PUT route; `dashboard <id> widgets add/remove` didn't exist. Both fixed at
  the surface.)
```
