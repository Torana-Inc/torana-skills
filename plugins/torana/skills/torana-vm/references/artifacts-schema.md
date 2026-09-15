# artifacts.yaml — the program contract

> **⚠ SCOPE (2026-07-16): BUILD no longer hand-authors `artifacts.yaml`.** The VM BUILD path now
> drives the **`torana-build`** engine, which constructs and validates each artifact from the
> platform's own fetched schema — you do not write this yaml in BUILD. This document is retained
> for **ASSESS**, which reads the **`grounding`** block (§ grounding below — "the refinement
> linchpin — ASSESS reads this") to compute drift and baselines. Use the artifact-section schemas
> here only to *understand* an existing program's shape during ASSESS, not to author one in BUILD.
> (For BUILD authoring rules, see the `torana-build` skill's `references/authoring.md`.)

One `artifacts.yaml` is the whole program: the committed, git-versioned source of truth for
every artifact it deploys. `vm_program.py assess` reads exactly the sections below (they map 1:1
to `spec.get(...)` in the engine). The **whole-object consistency** described here is what makes
a program correct — the `torana-build` engine enforces the equivalent at cook time. Ground every
choice in what `discovery.md` found (real tables, real severity casing, real edges). See
`recipes/` for a complete, working example of a coherent program's shape.

## Top-level shape

```yaml
usecase: vuln-prioritization-torana   # program id → the prefix (vulnprio_) + workspace-name fallback
workspace: { ... }
policy: { file: policy.md }           # optional — a RAG policy doc ingested with the program
transformers: [ ... ]                 # dbt-style materialized views (topologically ordered by depends_on)
rules: [ ... ]                        # SQL detection rules → alerts
dashboards: [ ... ]                   # each with embedded widgets
kpis: [ ... ]                         # landing-page KPI bar
attention_cards: [ ... ]              # landing-page "what needs your attention"
playbooks: [ ... ]                    # multi-step alert handlers (a route can dispatch to one)
routes: [ ... ]                       # alert routing
schedulers: [ ... ]                   # scheduled transformer/rule/suite/workflow runs
grounding: { ... }                    # the facts the program was built against (ASSESS reference)
moved: { }                            # optional rename map (old-name: new-name)
```

`usecase` is load-bearing: it derives the **program prefix** (`re.sub('[^a-z0-9]','',usecase)[:8]`
→ `vulnprio`) that stamps and isolates every artifact. Keep it stable — changing it
re-homes the whole program.

## Every DB-backed artifact carries a `description`

Per Torana convention, transformers/rules/dashboards/widgets/etc. take a **`description`**
(semantic intent, not just identity) — populate it. Ask the user for it when they don't
supply one; it feeds agent reasoning + future semantic search.

## Sections

### workspace
```yaml
workspace:
  name: "Vulnerability Prioritization — Torana"
  description: "..."          # what the program is for
  icon: fa-list-check         # FontAwesome
  type: vulnerability_management
```

### transformers  (materialized views; the data backbone)
```yaml
transformers:
  - key: prioritized_vulnerabilities      # logical name (unique within the program)
    name: prioritized_vulnerabilities
    description: "..."
    destination_table: prioritized_vulnerabilities   # view name (prefix added at apply)
    materialized: true
    depends_on: []                        # sibling transformer keys this SQL reads; engine topo-sorts
    source_tables: [ ... ]                # raw datalake tables it reads (optional, documentary)
    unique_key: torana_vulnerability_id   # optional
    sql: |
      SELECT ... FROM <raw table or sibling view> ...
```
- Reference **sibling views by their logical name** in SQL; the engine rewrites them to the
  prefixed physical name and topologically orders creation by `depends_on`.
- `depends_on` must list every sibling view the SQL reads, or ordering breaks.

### exploitability enrichment (KEV / EPSS / CVSS) — read this before tiering
The **`vulnerabilities` table already carries exploitability + severity intel**, populated by
the platform's global threat-intel feed (CISA KEV, FIRST EPSS, NVD CVSS) at ingest — you do
**not** build or fetch it:
- `cisa_kev_data` — non-null ⇒ the CVE is on CISA's **Known Exploited Vulnerabilities** list
  (actively exploited). `LOWER`-safe: test `cisa_kev_data IS NOT NULL`.
- `epss_score` (`DECIMAL(5,4)`, 0..1) + `epss_percentile` — FIRST **EPSS** exploit probability.
- `cvss3_base_score` — NVD CVSS v3 base score.

**Tiering doctrine — fold these into P0:** the industry-standard top tier is
**`P0 = (KEV-listed OR EPSS-high) AND reachable AND fixable`**. Add `is_kev` /
`epss_score >= <cutoff>` to the P0 `CASE` in your prioritization transformer (see the recipe).
**Always DISCOVER coverage first** (`COUNT(*) FILTER (WHERE cisa_kev_data IS NOT NULL)`,
`COUNT(epss_score)`): if both are 0 the feed hasn't loaded — a super-admin must run
`torana etl-sa threat-intel refresh`; until then ground P0 on reachability+severity and note
it in `grounding.logic_rests_on`.

**The source of truth is `public.vm_cve_metadata`** — one GLOBAL, tenant-independent CVE cache
(SA-controlled via `torana etl-sa threat-intel status|refresh`). Reading the enriched columns
straight off `vulnerabilities` is enough for almost every program. **Optional freshness layer**
— only when a program needs feed updates reflected *between* scans, add an
`enriched_vulnerabilities` transformer that `LEFT JOIN`s the live cache (public is always on
the search_path, so no special scoping):
```sql
SELECT v.*,
       COALESCE(v.epss_score, m.epss_score)             AS epss_effective,
       COALESCE(v.cvss3_base_score, m.cvss3_base_score) AS cvss3_effective,
       (v.cisa_kev_data IS NOT NULL OR m.kev_listed)     AS kev_effective
FROM vulnerabilities v
LEFT JOIN public.vm_cve_metadata m ON v.cve_id = m.cve_id
```
Then point the P0/KEV rules + exploit dashboards at `enriched_vulnerabilities` instead of
`vulnerabilities`. This is a per-program view (transformers are workspace-scoped) — the cache
is global, the view is local. Skip it unless sub-scan freshness matters.

### rules  (SQL detections → alerts)
```yaml
rules:
  - key: new_p0
    name: new_p0
    description: "..."
    severity: critical          # LOWERCASE — the rule API wants critical|high|medium|low|info (see the casing note below)
    alert_enabled: true
    entity_type: vulnerability
    identity_fields: [torana_vulnerability_id]   # dedupe key for alerts
    sql: |
      SELECT ... FROM prioritized_vulnerabilities WHERE ...
```

> ## ⛔ `identity_fields` — the field that decides whether a rule produces alerts AT ALL
>
> `identity_fields` is the dedupe key for alerts. It is **not** a formality, and it is
> **frozen at deploy** — `rule update --file` accepts it and the server discards it, so a
> wrong choice cannot be repaired in place. The rule must be rebuilt. Choose it deliberately:
>
> 1. **SHORT.** The limit is empirically **below ~130 characters**. Over it, alert creation
>    fails **silently** — the rule reports `SUCCESS`, reports the matched row count, reports
>    `alert_generated: true`, and creates nothing.
> 2. **STABLE across runs.** A key that changes between scans re-alerts on the same finding
>    forever.
> 3. **AT THE GRAIN YOU WANT ALERTS AT.** ⭐ This is a design decision, not a detail:
>    keying on the **vulnerability alone** collapses per-system fan-out (one alert for a CVE
>    however many hosts it affects); keying on **(vulnerability, system)** fans out (one
>    alert per affected host). *Neither is wrong — choosing by accident is.*
>
> ⛔ **Never key on `torana_entity_id` for container findings.** Its values are 110–150
> character image digests, over the limit. Measured on two independently-built apps, by two
> different harnesses, on two workspaces: both keyed on it, and yield was **47 alerts from
> 2,615 matched rows = 1.8%**, with three rules at exactly **zero** — including the
> known-exploited rule feeding Slack. Every measurement taken against those apps before the
> defect was found — inbox depth, Slack volume, triage-verdict distribution — was made
> against 1.8% of the intended population.
>
> Where no short, stable column exists at the grain you need, **derive one** (e.g. a hash or
> a composite of short columns) and **say so in the final report**.

> **Severity casing — there are TWO different casings; don't conflate them.**
> 1. **The rule's `severity:` FIELD is lowercase** (`critical`/`high`/`medium`/`low`/`info`) —
>    the detection-rule create API rejects Title Case. This is a fixed API contract, not the data.
> 2. **SQL literals in a WHERE clause match the DATA**, which is a different, discover-it question.
>    The *canonical* data casing is Title Case (`Critical`/…) and the engine's transformers
>    normalize to it (so a program's own prefixed views are Title Case), **but raw source tables
>    may not be** (e.g. `vulnerabilities` from a GCP container scanner can be lowercase, sometimes
>    mixed). So `GROUP BY severity` on the actual table first, and write casing-safe predicates —
>    **`LOWER(severity) = 'critical'`** rather than a bare `severity = 'Critical'` (a hard-cased
>    literal against the wrong-cased table matches **nothing**). Same for `status`.
>
> In short: **`severity:` field → lowercase; SQL `WHERE severity = …` → `LOWER(...)`-safe.**

### dashboards + widgets
```yaml
dashboards:
  - key: prioritize                 # dashboard-level key: OK (program-unique artifact name)
    name: "What To Fix First"
    description: "..."
    widgets:
      # ⚠ INLINE WIDGETS TAKE `name`, NOT `key`. A dashboard's `widgets:` entries validate
      #   against WidgetSpec (additionalProperties: false) — a `key:` on a widget is REJECTED
      #   at import (`widgets.N.key: Extra inputs are not permitted`). Identify each inline
      #   widget by `name`. (`key` is valid only at the artifact top level — transformers,
      #   rules, dashboards, standalone widgets — not on a dashboard's inline widget list.)
      - name: "Prioritization Funnel"
        widget_type: bar          # MUST be one of: bar | line | pie | table | scalar
        description: "..."               # REQUIRED — one-line info-icon tooltip (what it shows)
        semantic_description: "..."      # REQUIRED — rich how-to-read/what-to-do body (see rule below)
        display_config: { x_axis: stage, y_axis: vuln_count }   # REQUIRED, per type (see below)
        sql: |
          SELECT stage, vuln_count FROM prioritized_vulnerabilities ...
```
- **EVERY widget REQUIRES both `description` AND `semantic_description` — mandatory, not optional.**
  The deploy carries both straight to the widget row. `description` is the one-line info-icon
  tooltip (*what it shows*); `semantic_description` is the rich *how-to-read-this / what-to-do*
  body that renders in the FE's expandable row, prints in `torana widget <id> get`, and is
  **injected into every anchored-chat LLM turn** (the `workspace_widget` anchor) so the agent can
  reason about the widget. A blank `semantic_description` ships the widget mute — the FE box
  silently doesn't render and the chat agent has no context. Author it for every widget as you
  build the dashboard; after deploy, `torana widget <id> get` must show a populated SEMANTIC
  DESCRIPTION field.
- ⛔ **`semantic_description` MUST carry a five-part INTENT after the prose — on EVERY artifact
  type you emit (transformer, widget, KPI, rule, dashboard, route, scheduler), not just widgets.**
  Rich prose alone is a *description*, and a description cannot be regenerated from. An
  artifact's source of truth is its **intent**, not its SQL: SQL → English is lossy, so when a
  new integration connects or a column becomes populated, the intent is what a regeneration
  reads. ⚠️ It is **unbackfillable** — anything you ship without one needs its intent
  hand-written later by someone guessing what you meant.

  Write the prose first, leave a blank line, then five keys each at line start:

  ```yaml
  semantic_description: |
    Team accountability view — open vulnerabilities by owning team, with overdue counts.

    question: Which teams carry the most unresolved exposure, and who is furthest past deadline?
    grain: one row per owning team, including an explicit 'unassigned' row for findings no
      ownership path reaches — that row measures how much of the estate has no owner and must
      never be filtered out.
    semantics: owning team = asset team, falling back to repository owner, then 'unassigned';
      overdue = past that finding's SLA deadline, where the window is tenant policy.
    scope: open findings only; live rows only; policy values bind from vocabulary at render
      time, never hardcoded; current-state, not a trend.
    fallback: if no ownership signal is supplied, everything collapses into 'unassigned' — that
      is a true and useful answer, so still render it, but flag the artifact degraded.
  ```

  ⛔ **The test:** *could two competent generators, given only this text and the current schema,
  produce queries that disagree on a row count?* If yes, it is a description, not an intent.
  ⛔ **`semantics` names CONCEPTS, never columns** — `critical = the tenant's top severity band`,
  never `critical = vulnerabilities.severity IN (...)`. The binding must stay free to change
  when a better column appears; that is the whole point of regenerating.
  ⛔ **The intent block goes LAST** — anything after the final key is absorbed into `fallback`.
- **`widget_type` MUST be EXACTLY one of `bar | line | pie | table | scalar`** — the engine
  enum. Do NOT write `bar_chart`/`line_chart`/`pie_chart` (a common wrong guess); those are
  rejected. Same for KPI `format` (`number | percent | currency | duration`). When unsure of
  any enum, fetch it: `torana build capabilities --json` returns the authoritative schema.
- **`display_config` is required and load-bearing**, not cosmetic. The shapes, measured
  from the widgets live on this platform:
  - `table`      → `columns: [col_a, col_b]`
  - `scalar`     → `value_column: n` + `label: "Open criticals"`
  - `bar`/`line` → `x_axis` + `y_axis`
  - `pie`        → `x_axis` + `y_axis` **and** `label_field` + `value_field` (all four;
    every pie widget in production carries the full set — do not emit only two)
  ⚠️ Do NOT use bare `label`/`value` keys — those are rejected. The bulk dashboard-create is
  lenient but standalone widget-add (used on re-apply) enforces it — a widget missing (or
  mis-keying) its `display_config` fails to create.
- ⛔ **`widget_type` DEFAULTS TO `table` if you omit it.** That is the one type whose
  `display_config` is easiest to satisfy, so the path of least resistance silently produces
  an all-table app. Measured: one build shipped **8 of 15 widgets as tables**, one dashboard
  100% table. **Set `widget_type` explicitly on every widget.**
- A widget's SQL becomes a **saved query** linked to the widget; on re-apply, SQL edits go
  to that query, structural edits to the widget.
- ⛔ **Any `LIMIT` in a RULE's SQL silently bounds the inbox.** A rule returns at most
  `LIMIT` rows per run, so it caps how many alerts can ever be raised — independently of
  severity, of the data, and of everything else you tuned. Measured: one build wrote
  `LIMIT 10` into **every** rule. A `LIMIT` in a rule must be **deliberate and stated in the
  final report**; if you want the whole population, omit it. (`LIMIT` in a *widget* query is
  normal — a top-N panel is a display choice.)

### kpis  (landing-page KPI bar)
```yaml
kpis:
  - title: "Open P0"
    description: "..."
    format: number            # number | percent | currency | duration
    icon: fa-fire
    sql: |
      SELECT COUNT(*) FROM prioritized_vulnerabilities WHERE priority_tier = 'P0'
```

### attention_cards  (landing-page "what needs your attention")
```yaml
attention_cards:
  - title: "New P0 this week"
    description: "..."                    # internal note; NOT the rendered body
    summary_template: "{count} new P0 findings this week"   # RENDERS as the card BODY
    action_template: "Triage the {count} P0s and assign owners"  # RENDERS as the card's action bar
    severity: high            # card accent
    trigger_when: "count > 0" # shows the card when the condition holds
    query: |
      SELECT COUNT(*) AS count FROM ... WHERE ...
```
> **The card body comes from `summary_template`, not `description`.** The landing-page sweep
> renders each card's body from `summary_template` and its action line from `action_template`,
> **interpolating `{count}`** (and any other column the `query` returns — the query must alias its
> value `AS count`). Omit them and the body renders blank. Always set `summary_template`; set
> `action_template` to the concrete next step. `description` is an internal note, not shown.

### playbooks  (multi-step alert handlers a route can dispatch to)
A playbook is the orchestration unit for handling an alert (triage + notify + ticket, etc.).
Create one here when a `route` below dispatches to `destination_type: playbook` and the
playbook is program-owned (rather than a pre-existing platform playbook).
```yaml
playbooks:
  - key: notify_slack
    name: "Vuln Prioritization Notify Slack"    # a route's destination_ref resolves to this (prefixed) name
    description: "..."
    instructions: |                              # what the playbook does, in plain language
      Post the alert summary to #vuln-alerts with the top fixable package and its fix.
    tool_dependencies: []                        # tool/api refs it needs (optional)
    input_parameters: []                         # declared inputs (optional; e.g. alert_id)
    tags: []                                      # optional
```
Only build a playbook whose destinations exist (a Slack integration, an agent, …) — omit it
when the estate can't support it rather than shipping an inert dependency.

### routes  (alert routing)
```yaml
routes:
  - key: slack_notify
    name: "Route quick-win alerts to Slack notifier"
    description: "..."
    destination_type: playbook        # playbook | agent | workflow
    destination_ref: "Vuln Prioritization Notify Slack"   # name of the destination (playbook we create, or external)
    enabled: true
    priority: 20                      # lower = evaluated first
    stop_on_match: false
    matching_operator: all
    max_executions_per_hour: 200
    severity_levels: [Critical, High] # a filter — or source_rule_ids / source_suite_ids / required_tags / match_all
```
- A route MUST have at least one filter (`severity_levels`/`source_rule_ids`/
  `source_suite_ids`/`required_tags`) or `match_all: true`, or create is rejected.
- `destination_ref` is resolved to an id at apply time. If the destination doesn't exist
  yet (e.g. an external agent), the route is **deferred** (not a failure) — create the
  destination and re-apply.

#### ⛔ `source_rule_ids` is NOT resolved at deploy — bind it by CLI afterwards

`destination_ref` IS resolved to a real UUID at deploy. **`source_rule_ids` is NOT** — whatever
you author is stored verbatim. Author it as a rule KEY (the only thing that exists at author
time, since rule UUIDs are minted at deploy) and the route ships holding a key that no alert can
ever match:

```
SOURCE RULE IDS   ["em_known_exploited"]     ← the key, not a UUID — matches NOTHING
```

**This fails SILENTLY and the deploy reports success.** Measured 2026-08-28: a KEV→Slack route at
priority 10 never fired; both KEV alerts fell through to the priority-100 catch-all and went to
the analyst queue. Nothing reached `#security-alerts` — the build's headline requirement — while
every artifact showed `deployed`.

**After deploy, bind each route to the real rule id:**

```bash
TORANA_PROFILE=<p> torana rule list          # get the deployed rule's UUID
# ⚠️ --source-rule-ids as a FLAG 422s. Only --file persists.
TORANA_PROFILE=<p> torana alert-route <route-id> update --file rule_binding.json
TORANA_PROFILE=<p> torana alert-route <route-id> get   # confirm it holds a UUID, not a key
```

⚠️ This live edit is **drift from the proposal manifest** — a rebase or redeploy reintroduces the
bug. Re-apply the binding after any redeploy.

#### How a route is actually SELECTED (priority alone does not decide it)

- Evaluation is **first-match-wins by default**: the engine flag `alert_routing_fan_out_enabled`
  defaults to **false**. Its semantics are inverted from the intuitive reading — `true` *enables*
  fan-out to multiple routes; `false` means one alert, one route.
- `priority` orders evaluation (**lower first**) but does not guarantee selection: a
  higher-priority route whose FILTER does not match is skipped, and evaluation falls through to
  the next one. That is exactly how a broken `source_rule_ids` sends everything to the catch-all.
- Set `stop_on_match: true` on a specific route as belt-and-braces — correct in either mode.

⭐ **Verify routing at the external system, never from the deploy result.** Execute the rule, then
read which route and playbook actually claimed the alert (`torana alert <id> provenance` /
`activities`). A route can be perfectly configured, deploy green, and still never fire.

### schedulers  (scheduled runs)
**A VM program that ALERTS needs TWO schedulers, not one** — refreshing the board and firing the
rule are separate executions. Schedule the foundation transformer (re-materialize the prioritized
view) AND every alert-raising rule (evaluate the fresh view → raise alerts). A program that schedules
only the transformer refreshes a board **no one is alerted from**; new P0s appear on the dashboard and
never page anyone. (The platform deploys schedulers enabled — you just have to author them.)

⛔ **Declare cadence AND coverage per artifact — count them before you finalize.** Two
measured failures, both invisible at author time: one build shipped five schedulers on a
**daily** cron (`0 2 * * *`) when hourly was intended, so two rules never executed at all;
another left **six of seven transformers with no scheduler at all**, making the app static
after its first run. State the interval you intend and check that every transformer and
every alert-raising rule has one.
```yaml
schedulers:
  # 1. REFRESH — re-materialize the prioritized view so the board reflects new scan data.
  - name: "Refresh prioritized_vulnerabilities (every 6h)"
    description: "Re-run the prioritization transformer so the board reflects the latest scans."
    task_type: transformer            # transformer | rule | suite | workflow
    target_ref: prioritized_vulnerabilities   # the artifact's logical key
    schedule_type: cron
    schedule_expression: "0 */6 * * *"        # quote cron strings
  # 2. FIRE — evaluate the detection rule against the fresh view so new P0s raise alerts.
  #    WITHOUT this, the board updates but nothing alerts. Schedule it a beat AFTER the
  #    refresh so it reads the just-materialized rows.
  - name: "Fire P0 rule (every 6h)"
    description: "Evaluate the P0 detection rule so freshly-appearing P0s raise alerts."
    task_type: rule
    target_ref: <your P0 rule's key>          # the rule artifact's logical key
    schedule_type: cron
    schedule_expression: "10 */6 * * *"       # slightly after the refresh above
```

### grounding  (the refinement linchpin — ASSESS reads this)
Record the data/graph facts the program rests on, so re-evaluation is principled, not
vibes. Because there's no KPI-history endpoint, **git history of this block IS the trend**.
```yaml
grounding:
  captured_at: "2026-07-10T00:00:00Z"
  graph:  { deployed_as: present, exposed_via: present, builds_image: 13 }
  shape:  { open_vulns: 46682, cvss3_populated_pct: 0, internet_facing_images: 6 }
  baselines: { kpi_p0: 410, rule_new_p0_alert_rate_per_day: 3 }   # ASSESS reference points
  health_defaults:                    # per-program health bar; ASSESS thresholds
    rule_noisy_alerts_per_day: 50
    widget_empty_after_days: 7
    kpi_stale_if_unchanged_days: 30
  policy_vocabulary:                  # DISCOVER 6 — the vocab settings this program consumes
    severity_floor: { resolved: "Medium", origin: from_policy }
    epss_escalate_threshold: { resolved: 0.5, origin: system_default }   # no org value → platform default
    sla_window_by_severity: { resolved: {Critical: 7, High: 30}, origin: from_policy }
  logic_rests_on:
    - "P0 tier assumes reachability (deployed_as) exists"
    - "no CVSS3 tier — cvss3 is 0% populated"
    - "artifacts reference these via {{vocab:...}} placeholders — resolved per-tenant at install"
```

`policy_vocabulary` records which vocab settings the program consumes and their resolved-vs-defaulted
state (from `torana vm policy vocabulary-browse`, discovery layer 6). It is provenance, NOT the values
baked into SQL — the artifacts carry `{{vocab:...}}` placeholders that re-resolve at install, so a
value change (e.g. the org sets a real `epss_escalate_threshold`) reflows without re-authoring.
ASSESS can diff this block to notice a program built on a default the org has since set.
Capture it at build time from DISCOVER. ASSESS recomputes `graph`/`shape`/`baselines` and
diffs vs the recorded values → grounding-drift + operational signals → proposed yaml diffs.

### moved  (optional rename map)
```yaml
moved:
  old_transformer_key: new_transformer_key   # plan treats this as a rename, not destroy+create
```
*(Specced; `plan` does not yet consume it — until then, avoid renames or accept the
recreate. See `plan-apply.md`.)*

## Consistency rules the engine relies on

- Every `depends_on` entry and every sibling view referenced in SQL must be a real
  transformer `key` in this file.
- A rule/KPI/widget/attention SQL may reference transformer views by logical name; the
  engine rewrites them to the prefixed physical name.
- Route `target`/`destination` and scheduler `target_ref` must name artifacts that exist
  (in this file or on the platform), or they defer/fail loudly.
- Write casing-safe severity/status predicates (`LOWER(col) = 'critical'`) — raw tables may
  not be Title-Case (see the severity note above) — and **VALIDATE** by dry-running each
  SELECT with `"$TORANA" datalake query --format json` before plan.
