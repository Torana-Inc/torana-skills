# plan / apply / prune / import — the reconcile engine

> **⚠ SCOPE (2026-07-16): BUILD no longer uses `plan`/`apply`/`prune`/`import`.** The VM BUILD
> path now drives the **`torana-build`** engine (create → blueprint → cook → deploy) — see the
> skill's BUILD operating loop. This document is retained for **ASSESS only**: the `assess` verb
> (§ "assess" below / row in the verb table) gathers a running program's health signals with
> **no platform writes**. Ignore the `plan`/`apply`/`prune`/`import`/`delete` reconcile verbs when
> building — they are legacy for this skill and kept solely because `assess` shares
> `read_live_model`. Do NOT hand-author or reconcile a program in BUILD.

`scripts/vm_program.py` reconciles an `artifacts.yaml` (desired) against a live Torana
workspace (live) with terraform semantics. This file is the operating contract. **For ASSESS**,
read the `assess` verb below; the reconcile verbs are documented for historical/engine context.

## The one core operation

Every verb is a function of **read(live) vs desired(yaml)**. A single routine —
**read the live workspace into a normalized model** (`read_live_model`) — powers plan,
prune, drift, and import. There is no committed state store: the logical-name → live-UUID
mapping is **reconstructed from live every run** by matching artifacts within this program's
workspace by their (clean) name. (A gitignored `.state.json` next to the file is only a
speed cache for `apply`; plan/prune/import never depend on it.)

## The ownership boundary is the program's WORKSPACE (names stay clean)

Each program owns its **own dedicated workspace** — so **the workspace is the ownership
boundary**, and a program's rules, dashboards, widgets, KPIs, attention cards, schedulers,
and routes carry **clean, user-facing names** (no program prefix). Those names are what the
UI shows on KPI cards, dashboard widgets, and attention cards — they MUST read cleanly to an
end user, so the builder never stamps a prefix onto them. plan / prune / drift reconcile
these types by **clean name within the program's workspace** (KPIs/attention additionally by
their `{prefix}_kpi_{i}` / `{prefix}_att_{i}` index id, since the whole landing zone is
rewritten atomically).

**The ONE thing that keeps the prefix: transformer `destination_table`s.** Transformers
compile to views in a **tenant-global** namespace — two programs both defining
`prioritized_vulnerabilities` would collide — so the transformer name/table stays
`{prefix}_…`, and view references in dependent SQL are rewritten to match. That prefix is
never user-facing (it's a table name), so it does no display harm.

**Prune consequence (know this):** because ownership = the whole workspace, `prune`
considers **every** artifact in the program's workspace, not just prefixed ones. That is
correct for a program that owns its workspace as IaC — but do **not** hand-add artifacts to
a program's workspace in the UI and expect `prune` to spare them. `prune` is still gated
behind `plan` + confirmation, so you always see the delete list first.

## The verbs

| verb | reads | writes | gated |
|---|---|---|---|
| `plan` | live (workspace-scoped) vs yaml | nothing | — |
| `apply` | live (fast path: cache) | create + update | prune/replace only |
| `apply --prune` | live | create + update + **delete** | delete confirmed (or `--yes`) |
| `prune` | live | **delete** only (what's not in the yaml) | confirmed (or `--yes`) |
| `import --out X` | live | writes X (a yaml) — **no platform writes** | — |
| `assess --out X` | live + signals | writes X (a JSON health report) — **no platform writes** | — |
| `delete` | state/live | deletes the whole program | confirmed (or `--yes`) |

`plan` on an unchanged program prints **"No changes — live matches artifacts.yaml."** Run
it after every `apply` to confirm convergence.

## What plan diffs, per type (canonical diff)

`plan` compares a **normalized canonical form** so cosmetic differences never show as
spurious diffs. Both sides are already view-ref-rewritten (the applier rewrites on write;
the live record stores that form), so canonicalization is comment-strip + whitespace-
collapse (`_canonical_sql`). Per type:

| type | identity | compared on |
|---|---|---|
| transformer | **namespaced** name (`{prefix}_…` = its table) | canonical SQL (`custom_sql`) |
| rule | clean name (workspace-scoped) | canonical SQL (`sql_command`) |
| KPI | `{prefix}_kpi_{i}` (index) | canonical SQL (`data_source.query`) |
| attention card | `{prefix}_att_{i}` (index) | canonical SQL (`condition.query`) |
| dashboard | clean name (workspace-scoped) | existence (widgets diffed within) |
| widget | `dashboard :: widget` clean name | canonical SQL (its linked query) **+ widget_type** |
| scheduler | clean name (workspace-scoped) | `schedule_expression` (cron) |
| route | clean name (workspace-scoped) | operational signature (priority/enabled/filters/…; **not** the resolved destination id) |

**KPIs/attention are index-keyed** to mirror how the applier assigns their ids, so plan
predicts exactly what apply (a whole-zone landing-page rewrite) would do. **Widget SQL
lives in its linked query**, not the widget — SQL drift is fixed via `query update`,
structural drift via `widget update`. **`display_config` is deliberately not diffed** (the
backend normalizes it → would churn); but it is **load-bearing and required** in the yaml
(bar→x_axis/y_axis, table→columns, pie→label/value).

If a live read **errors** (not empty — errored), plan **skips that type with a loud warning
and does NOT report it as creates.** Fail-loud, never false-positive.

## apply — reconcile behavior

- Create order is dependency-respecting: workspace → policy → transformers(topological) →
  rules → dashboards → kpis → attention → home-pins → playbooks → routes → schedulers.
- **Idempotent + update-on-drift** for every reconciled type: re-running `apply` updates
  in place (transformer/rule/widget SQL via `query update`, scheduler cron via
  `update-task`, route config via `alert-route update`). Structural changes (a scheduler's
  target, a route's destination) are out of scope for update — they are delete+recreate.
- **apply is non-destructive**: it never deletes. Removals (widgets/dashboards/routes/etc.
  dropped from the yaml) show in `plan` as `-delete` but are only performed by `prune`
  (or `apply --prune`). This mirrors terraform's create+update; deletes are opt-in.
- **Home pins are a derived projection** (all of a program's widgets), rebuilt from the
  live widget set on every apply — not authored, not diffed. `prune` refreshes the pin
  zone after deleting widgets so no pin dangles at a deleted id.

## prune — safe deletes

`prune` deletes live (prefixed) artifacts absent from the yaml, in **reverse-dependency
order** (readers before what they read: dashboards/widgets/schedulers/routes before the
transformers whose views they consume; rules before transformers). It prints the deletes
and requires confirmation (or `--yes`). Orphan widgets in a kept dashboard are
detach+deleted; a whole orphan dashboard is deleted (cascading its widgets).

## import — capture live into git (bidirectional)

`import --out X` reads the live workspace (by prefix) and serializes a **re-appliable**
`artifacts.yaml` — the inverse of apply. It de-prefixes names, un-rewrites view refs back
to logical form, and reconstructs transformer `depends_on` by scanning SQL for sibling
views. Use it to capture a UI-built or agent-built app into IaC, or to snapshot drift
before deciding overwrite (`apply`) vs. capture (keep the import).

**import aborts without writing if any section read errored** — a silently-empty section
fed back to `apply --prune` would delete everything that section owns. So a partial/failed
read never produces a prune-unsafe file. Notes: routes import with `destination_ref` = the
resolved id (often an external agent/playbook that can't be reversed to a logical name —
review before re-applying); home pins are not serialized (derived).

## Drift (UI vs YAML)

If someone edits an artifact in the UI, its live canonical form diverges from what the yaml
would produce → `plan` shows it as `~update`. The human chooses: **overwrite** (`apply`
re-imposes the yaml) or **capture** (`import` pulls the UI change into the yaml, then
commit). Never assume the yaml is authoritative after a UI edit — reconcile explicitly.

## rename = destroy + create (and the `moved` block)

Because state is reconstructed from live by name, **renaming an artifact in the yaml reads
as delete-old + create-new** (a transformer rename drops and recreates its materialized
view). To rename without data loss, add a `moved:` map (terraform-style) so `plan` treats
it as a rename, not a destroy. *(Status: the `moved` block is specced but not yet consumed
by `plan` — until it lands, avoid renames or accept the recreate.)*

## Git workflow & rollback (the IaC promise)

The `artifacts.yaml` (+ any `policy.md`) **is** the program — commit it to git. The skill
**generates/edits the file; the human commits it** (the skill never commits). To change a
program: edit the yaml → `plan` → get approval → `apply` → commit. `import` pulls live/UI
drift back into the yaml so git stays the source of truth.

**Rollback** = check out an old version of the yaml and reconcile to it:
```bash
git checkout <old-sha> -- artifacts.yaml
python3 vm_program.py --file artifacts.yaml plan          # preview the rollback
python3 vm_program.py --file artifacts.yaml apply --prune  # reconcile live -> old version
python3 vm_program.py --file artifacts.yaml plan          # confirm: "No changes"
```
**Use `apply --prune`, not plain `apply`.** Plain `apply` is non-destructive (create+update
only) — if the newer version *added* artifacts, a plain apply of the old yaml leaves them,
so live becomes a superset, not an exact match. `--prune` deletes what the old version
doesn't declare, so live == the checked-out version. Deletes are gated (confirmed).

Caveats: renames across versions are destroy+create until `moved` lands; only the program
(logic/artifacts) is versioned, **not** the datalake data; and **`policy.md` is NOT
reconciled** — `_apply_policy` is ingest-once and outside plan/prune, so a changed or
rolled-back policy doc is not re-ingested (see SPEC § 4.8).

## Empty-tenant / grounding

On a tenant with no data, apply still creates every artifact and VERIFY checks SQL validity
+ structure (not row counts); the program is marked `pending-grounding`. When data later
arrives, ASSESS re-grounds it (see `artifacts-schema.md` → `grounding`).
