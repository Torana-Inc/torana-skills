# Recipes — golden programs as SHAPE exemplars

These are complete, working `artifacts.yaml` programs. Use them as **schema/shape
exemplars** — to see how every section fits together into one coherent object — **not** as
domain lessons (you already carry the security domain). Mirror the *structure*; ground the
*content* in what `discovery.md` finds in the actual tenant.

| recipe | what it is |
|---|---|
| `vuln-prioritization.yaml` | Turns a large open-vuln backlog into a reasoned worklist: a **digest-exact reachability funnel** (transformers) → P0–P3 tier rules → "what to fix first" + exposure dashboards → KPI bar + attention cards + a 6-hourly refresh scheduler, with a captured **`grounding`** block. Reads a live GCP/GKE estate; no synthetic data. |

**This recipe is engine-faithful.** It was authored against, and verified live through,
`scripts/vm_program.py` (applied end-to-end, all SQL validated) — so its structure is exactly
what the engine reads: lowercase rule `severity`, `x_axis`/`y_axis` on every chart widget
(incl. pie), no phantom inline `schedule`/`route` on rules, and a real `grounding` block.
Prefer it over the schema examples when in doubt about shape.

Notes:
- It deliberately **omits** `routes:`/`playbooks:` — the source estate had no triage
  agent/Slack connected, so shipping them would be inert. That's the right call, not a gap;
  see `../artifacts-schema.md` for the `routes:`/`playbooks:` contract when an estate supports
  them, and build them only when their destinations exist.
- The `grounding` block carries this estate's real numbers (open_vulns, digest-exact deployed,
  `kev_populated: 0`, tier baselines) — capture the equivalent for every program you build, so
  ASSESS can re-evaluate it later.
