# Discovery — probe before you author

The program's shape is a **function of what the tenant's graph + data actually support**,
not a fixed template. Discover in this order — each layer decides more than the next — and
author only what discovery justifies. This is the step a weaker agent skips; here it is
mandatory. Every command below is read-only.

> Reason about the *security* with your own knowledge. Discovery tells you the **facts of
> this estate** (what edges exist, how values are cased, how big the funnel is) that no
> pretrained model can know.

## The ordered probe

| # | layer | probe | decides |
|---|---|---|---|
| **0** | **resolve** | `torana admin question-resolve "<the user's words>"` | *has this been asked before?* — a canonical `question_id`, or an UNRESOLVED that is itself the answer |
| 1 | **entity graph** | `torana entity-graph edges list` / `neighbors <KEY>` / `reachable <FROM>` / `scopes` | *what intelligence is possible* — reachability, exposure, blast-radius |
| 2 | **data shape** | `torana datalake query --sql "<profiling SQL>"` | *how to tune the logic* — thresholds, which tiers are meaningful, funnel sizes. ⛔ **SHAPES a build, never vetoes one** — see § WHAT COUNTS ARE FOR |
| 3 | **schema** | `torana datalake schema-ddl --index`, then `schema-ddl --tables <a,b> --with preset:answer` | *what columns are addressable, what they MEAN, what they can HOLD, whether anything WRITES them, and whether the joins connect* — one call, annotated DDL. `preset:answer` = meaning, domains, reach, trust, measures |
| 3b | ⛔ **what one ROW of the answer means** | included in `preset:answer` as the `measures` block | ⛔ *"how many vulnerabilities" has two honest readings 317x apart, and both are correct SQL.* Pick the named measure the question asks for and cite it |
| 3c | ⛔ **reachability** | the `reach` layer above, plus `torana datalake sql-reachability --sql "<the SQL>"` before anyone runs it | ⛔ *whether anything ever WRITES the column* — existence is not reachability. A column that exists and nothing fills is a dead artifact that passes every other gate |
| 3e | ⭐ **can this column RANK or FILTER?** | `torana datalake model-conformance` | ⛔ *the model's claims checked against THIS tenant's live rows.* `enum_disjoint` = a declared value the data never uses, so `WHERE col = '<declared>'` returns 0 rows and deploys green. `low_variance` = one distinct value, so the column cannot order anything (a ranking input that ranks nothing). Also `no_data` and `undocumented_column`. Run it before ranking, tiering or equality-filtering on any column you have not measured yourself |
| 3d | ⛔ **governance** | `torana deployments list` · graph path `finding → image → deployed_as → service` | ⛔ *where criticality / exposure / ownership actually LIVE* — an empty `assets` column is NOT evidence the dimension is uncollected |
| 4 | **integrations** | `torana integrations list` · `integrations types` | *what feeds the data* — automation feasibility, freshness |
| 5 | **existing artifacts** | `torana workspaces list` · `workspace <id> get` · `transformers/rules/dashboards list --workspace-id` | *what's already there* — reuse, avoid collisions, or `import` to ASSESS |
| 6 | **policy vocabulary** | `torana vm policy vocabulary` · `torana vm policy vocabulary-browse [--tenant <id>]` | *the tunable domain SETTINGS + their resolved values* — severity floors, EPSS/SLA thresholds, exclusions, reachability gates the program must honour (platform-resolved, not model-guessed) |
| 8 | ⭐ **preflight** | `torana build preflight --workspace-id <WS>` | ⛔ *will a build actually succeed here?* — policy ratification, the BINDABLE vocabulary set, catalog health, integration reachability, schema revision. Read-only; exits non-zero when BLOCKED. Run it LAST in DISCOVER, before any SQL is authored |
| 7 | **catalog** | `torana vm transformers catalog list` (once per build) · `catalog show <id>` | *what SQL already exists, reviewed* — every entry reviewed and validated. Read the whole list **before** specifying any relation; if an entry satisfies a need you name its id instead of authoring SQL. Do **not** use `catalog search` here — ranking can bury the right entry |

### 1 — entity graph (what's *possible*)
The graph gates the program. Relationships (`deployed_as`, `exposed_via`, `builds_image`,
`runs_on`, `owns`, …) determine which intelligence you can express. **No `exposed_via`
edge → no exposure tier. No `deployed_as` → no reachability funnel.** Probe the edge types
and their cardinalities first; let the present edges decide the program's spine.
```bash
"$TORANA" entity-graph edges list --format json          # edge types + counts
"$TORANA" entity-graph scopes                       # scope-filter values present in this tenant
"$TORANA" entity-graph reachable <node-key>         # bounded lineage from a node
```

> **⚠ An edge existing is NOT enough — the edge and the vulnerabilities must share a
> KEYSPACE.** A `deployed_as` edge count > 0 does not mean a reachability tier will
> populate. `deployed_as` keys a `from_key` (image) → `to_key` (service); a vuln joins it
> only if `vulnerabilities.torana_entity_id` **equals** one of those keys. In real estates
> these keyspaces are often **disjoint**: the vulns key first-party built images
> (`image:…/prod/<app>@sha256:…` from `builds_image`), while `deployed_as` keys third-party
> base/sidecar images (`image:docker.io/…`). Result: the join returns **0** and any
> reachability tier is a **dead tier**. **Before committing to a reachability (or exposure)
> spine, prove overlap both directions:**
> ```bash
> # how many open vulns actually sit on a deployed image key (either edge direction)?
> "$TORANA" datalake query --format json --sql "SELECT COUNT(*) FROM vulnerabilities v WHERE v.vulnerability_status='Open' AND (v.torana_entity_id IN (SELECT from_key FROM entity_edges WHERE edge_type='deployed_as') OR v.torana_entity_id IN (SELECT to_key FROM entity_edges WHERE edge_type='deployed_as'))"
> # if that's ~0, eyeball WHY — compare the key namespaces:
> "$TORANA" datalake query --format json --sql "SELECT DISTINCT torana_entity_id FROM vulnerabilities WHERE torana_entity_id IS NOT NULL LIMIT 3"
> "$TORANA" datalake query --format json --sql "SELECT DISTINCT from_key FROM entity_edges WHERE edge_type='deployed_as' LIMIT 3"
> ```
> **Rule: overlap 0 → NO reachability tier.** Drop it and ground fixability-first
> (severity + CVSS3 + fix-availability). Record the mismatch in `grounding.logic_rests_on`
> so ASSESS can lift the tier later if the keyspaces converge.

### 2 — data shape (how to *tune*)
Profile the real distributions before writing any predicate. This catches what schema
never reveals: value casing split by source, null/populated rates, a 46k→410 reachability
funnel, a CVSS3 column that's 0% populated. Examples:
```bash
"$TORANA" datalake query --format json --sql "SELECT severity, COUNT(*) n FROM vulnerabilities GROUP BY 1 ORDER BY 2 DESC"
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) total, COUNT(cvss3_score) cvss3_populated FROM vulnerabilities"
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) FILTER (WHERE cisa_kev_data IS NOT NULL) kev, COUNT(epss_score) epss FROM vulnerabilities"  # exploitability coverage
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) FROM vulnerabilities v JOIN <deployed edge> ..."   # funnel size
"$TORANA" datalake query-hints                       # synonyms + ENUM values + join hints (⚠️ verify — see below)
```

#### ⚠️ ENUM VALUES — confirm against the data, do not trust the declaration

`query-hints` derives each `enum` from the mappings that WRITE the column, so it can drift
from what a tenant actually holds — and `enum_closed: false` says outright that the list is
examples, not the set. **Confirm with `SELECT DISTINCT` before filtering on any value.**

⭐ **Casing is the expensive failure mode:** `WHERE severity = 'critical'` against data
holding `'Critical'` returns zero rows and reads as a correct query over an empty result.
There is no error to debug.

> Measured 2026-08-24 (T2): declared enums were **accurate** on this build —
> `VULNERABILITIES.SEVERITY` declares `Critical/High/Medium/Low/Info/Unknown` and the data
> holds `Critical/High/Medium/Low/Unknown`; `SCAN_TYPE` (`enum_closed: false`) declares six
> and the data holds `SCA`/`Posture`/`Unknown`. An earlier report of widespread disagreement
> did not reproduce. **Verify against your own tenant rather than trusting either.**

#### ⛔ VARIANCE — a column that EXISTS and VARIES are different questions

**For every column a ranking, scoring or grouping will use, run a `GROUP BY` and check
that its distribution can actually order anything.** A dimension that is near-constant is a
**uniform multiplier**: it cannot change any ordering, and it is invisible from inside a
working app because the scores still vary and the model still looks alive.

```bash
"$TORANA" datalake query --format json --sql \
  "SELECT <dim>, COUNT(*) n FROM <t> GROUP BY 1 ORDER BY 2 DESC"
```

> **Measured on a shipped app:** `business_critical`, `internet_facing` and
> `handles_customer_data` were each true on **494 of 495** ranked rows — a constant ×3.36
> applied to essentially every line. The app published a five-dimension risk model and
> **ordered on two.** Nothing errored and nothing reported it. ⭐ **Recurred across four
> builds.**

⛔ **Reject a dimension whose distribution cannot order anything** — drop it from the model,
or replace it. ⭐ **And say so in the final report:** *"three of five dimensions are constant
on this estate"* is a caveat the user must see. It is a seeding/data problem, not a build
problem, and hiding it ships a model that only appears to be multi-dimensional.
> **Always pass `--format json` to `datalake query` and read `.results`.** The default
> text output wraps the result JSON across terminal-width lines — `grep`/`tail` parsing
> grabs fragments and forces re-queries. `--format json` returns clean, structured
> `{ "results": [...], "count": N }`.
>
> **To parse it, pipe into a `python3 - <<'PY'` heredoc — NOT `python3 -c '…'`.** The
> `-c` one-liner breaks the moment your script contains an **f-string with quotes inside
> the `{…}`** (e.g. `f"{d.get(\"key\")}"` or `f"{\"KEY\":42}"`): backslash-escaped quotes
> inside an f-string expression are a Python `SyntaxError` — this bites *repeatedly*. The
> heredoc uses real quotes with zero escaping:
> ```bash
> "$TORANA" datalake query --format json --sql "<SQL>" | python3 - <<'PY'
> import sys, json
> d = json.load(sys.stdin)
> for r in d.get("results", []):
>     print(r["cve_id"], r["severity"])   # real double-quotes, f-strings all fine
> PY
> ```
> The `<<'PY'` (quoted delimiter) also stops the shell touching `$` inside the script.
> If you must inline, keep the `-c` script quote-clean (no `\"` anywhere) — but prefer the heredoc.

**Exploitability (KEV/EPSS) drives the top of the funnel — check it's loaded.** The
platform's threat-intel feed enriches `vulnerabilities` with `cisa_kev_data` (CISA
Known-Exploited), `epss_score` (FIRST EPSS 0..1), and `cvss3_base_score`. If the coverage
query above returns **kev=0 AND epss=0**, the feed hasn't been loaded for this platform — a
super-admin must refresh it (`torana etl-sa threat-intel status` / `torana etl-sa
threat-intel refresh`) before an exploitability-tiered P0 is possible. Until then, ground P0
on **reachability + severity + fixability** and record the gap in `grounding.logic_rests_on`;
fold KEV/EPSS into P0 once the coverage query shows real numbers. Where present,
**P0 = (KEV OR EPSS-high) AND reachable AND fixable** — the industry-standard "fix now."

Let the numbers set the thresholds. A tier nobody's data falls into is noise; a threshold
the estate never crosses is a dead KPI. **Discover, don't assume, the value casing**
(severity/status can be lowercase from one source and Title-Case from another — group by
the raw column first).

#### 2a — the denominator collapse (run BEFORE designing any KPI)

#### ⭐ PROBE 3b — value domains: what a column can actually HOLD

```bash
"$TORANA" datalake schema-ddl --tables vulnerabilities --with domains
```

```
severity   TEXT  [closed] Critical, High, Medium, Low, Info, Unknown
                   declared by: normalize.py::CANONICAL_SEVERITIES
scan_type  TEXT  [open]   SAST, SCA, Secrets, IaC, Posture
cve_id     TEXT  - not yet described
```

| Reads | Means | So |
|---|---|---|
| `[closed]` | the vocabulary is complete | an `IN` list may enumerate it |
| `[open]` | more spellings can appear | ⛔ do NOT write an exhaustive `IN` |
| `not yet described` | ⚠️ **nobody has described it** — NOT "any value allowed" | verify before assuming; 855 of 859 columns |

⛔ **A `TEXT` type tells you nothing about the values, and guessing them is a top cause of a
confidently wrong number.** `severity` is Title-Case and `Unknown` is real, so a filter
naming `('Critical','High','Medium','Low','Info')` looks exhaustive and silently drops
4,104 rows. Measured: `required_scan_types` offered `container` while ingest wrote
`container_image_scan` — the filter matched **0 of 86,696** rows and deployed green.

⚠️ These are DECLARED, not observed — reading them costs no data access and is safe at
build time, unlike row counts (§ WHAT COUNTS ARE FOR, below).

⭐ **After any schema change**, `torana datalake schema audit` reports whether every surface
describing the schema still agrees with it.

#### ⛔ WHAT COUNTS ARE FOR — and the one thing they are NOT for

Probe 2 exists to **SHAPE** a build: pick thresholds, size a funnel, choose which tiers are
meaningful, decide which column actually carries the signal. That is the whole mandate.

⛔ **A row count NEVER decides whether to build.** "Can this be answered truthfully?" is
answerable from schema, reachability and the write seam — **without counting a single row**.
"Is the answer interesting yet?" is a render-time question the platform already answers with
the `empty` verdict, per widget, as data lands.

⚠️ **Measured 2026-08-18** (`b962e9eb`): a session counted 3 resolved issues across 2 teams
and used that as part of its reason to build nothing. Volume is a property of TODAY and an
artifact is durable — a widget refused for 3 rows this quarter does not exist when there are
300. There is also no principled threshold to refuse on (3? 30? per team or overall?), so any
number invented becomes a silent build gate.

⭐ **The rule:** counts SHAPE what you build and belong in `grounding` and in CAVEATS. They
do not veto it. The four structural refusals — unwritable column, uncalled writer, unmatched
join, wrong metric — are in `SKILL.md` § WHEN TO REFUSE, and none of them needs a count.

The raw record count is **never** the workload — it is inflated by scanner duplication,
stale registry digests, and one CVE landing on many images. Establish the honest funnel
first; every KPI and headline you author must be a *stage* of it:

```bash
# raw records → distinct CVEs → distinct (CVE,package) crit/high action pairs → fixable pairs
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) raw_records, COUNT(DISTINCT cve_id) distinct_cves FROM vulnerabilities WHERE vulnerability_status='Open' AND is_deleted IS NOT TRUE"
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) crit_high_pairs FROM (SELECT DISTINCT cve_id, package_name FROM vulnerabilities WHERE vulnerability_status='Open' AND is_deleted IS NOT TRUE AND severity IN ('Critical','High') AND cve_id IS NOT NULL) x"
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) fixable_pairs FROM (SELECT DISTINCT cve_id, package_name FROM vulnerabilities WHERE vulnerability_status='Open' AND is_deleted IS NOT TRUE AND severity IN ('Critical','High') AND cve_id IS NOT NULL AND (is_fix_available IS TRUE OR (package_fixed_version IS NOT NULL AND package_fixed_version<>''))) x"
```

The raw count is the funnel's **anchor** — show it deliberately, labelled as total scan
volume, right next to its distilled actionable counterpart. That pairing IS the platform's
value statement ("you *have* N findings; only M are actions"). What you must never do is
present the raw count **as** the workload ("open vulnerabilities: 61,521") with no funnel
behind it. (Ratios like 76k → 500 CVEs → 60 actions are typical; a program whose top KPI
is the raw number has failed.)

#### 2b — exploitability via the GLOBAL cache, not just per-row columns

The per-row `epss_score` / `cisa_kev_data` columns are ingest-time snapshots and may lag
or be null. The always-fresh global cache `vm_cve_metadata` (KEV + EPSS + CVSS) is directly
joinable and covers far more CVEs — prefer the JOIN for threat tiers:

```bash
"$TORANA" datalake query --format json --sql "SELECT COUNT(DISTINCT v.cve_id) FILTER (WHERE m.kev_listed) kev_cves, COUNT(DISTINCT v.cve_id) FILTER (WHERE m.epss_score >= 0.1) epss_hot FROM vulnerabilities v JOIN vm_cve_metadata m ON m.cve_id=v.cve_id WHERE v.vulnerability_status='Open' AND v.is_deleted IS NOT TRUE"
```

If this returns > 0 while the per-row columns are empty, **ground all threat tiers on the
JOIN** (`... JOIN vm_cve_metadata m ON m.cve_id = v.cve_id`). A KEV-listed CVE on a deployed
image is P0, always — it is the single sharpest signal a VM homepage can carry.

#### 2c — coverage (what the scanner CANNOT see is itself a finding)

```bash
# deployed workloads whose running image has NO scan records at all (incl. images pruned from the registry while still running):
"$TORANA" datalake query --format json --sql "SELECT a.asset_name, a.container_image_id FROM assets a WHERE a.source_system='kubernetes' AND a.container_image_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.torana_entity_id=a.container_image_id AND v.is_deleted IS NOT TRUE)"
# repos with scanning hygiene off:
"$TORANA" datalake query --format json --sql "SELECT name FROM repositories WHERE secret_scanning_enabled IS NOT TRUE OR dependency_security_updates_enabled IS NOT TRUE"
```

Unscanned-deployed images and unscanned repos belong on the homepage as a first-class
attention card — the gap is *actionable* (rescan / redeploy), and a clean coverage panel is
what lets a user trust the counts.

#### 2d — identity hygiene (the `identities` table exists; VM risk includes the access path)

```bash
"$TORANA" datalake query --format json --sql "SELECT COUNT(*) FILTER (WHERE is_admin IS TRUE AND mfa_enabled IS FALSE) admins_no_mfa, COUNT(*) FILTER (WHERE identity_type='service_account_key') static_sa_keys FROM identities"
```

Long-lived service-account keys and no-MFA admins are the access half of vulnerability
risk. When present, surface them — a vuln on a service reachable only via an over-privileged
static key is a different risk than the same vuln behind strong auth.

### 3 — schema (the *floor*)
```bash
"$TORANA" datalake schema-ddl --index                       # every table, one line each
"$TORANA" datalake schema-ddl --tables <a,b> --with preset:answer   # their annotated DDL
```
Author SQL only against columns that exist. Never invent a column a schema didn't show.

⛔ **Existence is the FLOOR, not the bar. Probe 3c is what makes the column real.**

### 3c — reachability (does anything *write* it?)
```bash
"$TORANA" datalake schema-ddl --tables <t> --with reach,writers  # can it be filled, and by what
"$TORANA" datalake sql-reachability --sql "<the SQL>"            # judge the SQL before running it
```

A column can be declared, typed, and present in the DDL while **nothing on the
platform ever writes it**. SQL over such a column is not wrong — it parses, validates,
EXPLAINs, deploys, and returns zero or NULL forever. Every structural gate passes.

⛔ **Run `check-sql` on every authored SQL BEFORE `artifact add`, and treat
`UNREACHABLE` / `PRODUCER_STALE` as a DESIGN INPUT, not a post-mortem.** A verdict of
`UNREACHABLE` means: pick a different column, or drop the tier that rests on it, and
**say so in the final report**. It does not mean carry on and hope.

> **Measured cost of skipping this:** a 53-artifact build passed cook EXPLAIN, C1–C6
> completeness, deploy, and post-deploy verification — then `check-sql` returned
> `Overall: UNREACHABLE` on two of its transformers. Roughly **half the app was
> structurally dead**: 3 of 11 rules could never fire, 2 of 3 KPIs were pinned at
> 0/NULL, 2 of 3 attention cards could never trigger, and the team rollup collapsed to a
> single bucket. Existence had been verified; reachability never was.

⚠️ `check-sql` resolves **table-qualified** references (`v.severity`, not bare `severity`) —
alias your FROM/JOIN tables or it reports *"No table-qualified column references found"*
and you will read that as a pass. A real verdict looks like:

```
2 column reference(s) resolved from the SQL:
  vulnerabilities.severity           SUPPLIED  [ok]
  vulnerabilities.is_false_positive  SUPPLIED  [ok]
```

### 3d — governance (where criticality & exposure actually live)
```bash
"$TORANA" deployments list                            # criticality, env, customer-data, owner, team
"$TORANA" entity-graph neighbors <image-key>          # finding → image → deployed_as → service
```

⛔ **An empty column is not evidence the data is not collected — check the Deployment
before ruling a governance dimension out.**

Business governance (criticality, environment, public exposure, customer-data handling,
ownership) is frequently **sparse or absent on `assets` while fully populated on the
Deployment object**, and it reaches findings through the entity graph. Authors who probe
only the data plane reliably conclude the dimension is unavailable and ship a ranking
without it.

Measured on this platform (T2, the GCP-inventory tenant):

```
assets.criticality_name    734 / 1224 populated   (~60%)
deployments (1 row)        criticality='critical'  env_label='production'
                           has_customer_data=True  owner='torana'  team='platform-security'
```

The Deployment carries the full governance set with nothing missing. ⚠️ The originally
filed figures for this row (`criticality_name` 2.3%, `publicly_accessible` 0 of 1,253)
do **not** reproduce here — re-measure on the tenant in front of you rather than quoting
them. The *conclusion* stands regardless: **probe the Deployment before concluding a
governance dimension is uncollected.**

### 4 — integrations (what *feeds* it)
```bash
"$TORANA" integrations list                           # connected sources (GitHub, Wiz, GCP, …)
```
Tells you which data is live vs. absent, and whether a program's logic can be kept fresh.

### 5 — existing artifacts (reuse / don't collide / re-ground)
```bash
"$TORANA" workspaces list
"$TORANA" workspace <ws> transformers list       # (and rules / dashboards / schedulers / alert-routes)
```
If the user has an existing program, **`import` it first** (`vm_program.py --file … import
--out live.yaml`) and work from the captured yaml — that is the starting point for ASSESS
and for any change.

### 0 — resolve (has this been asked before?)

```bash
"$TORANA" admin question-resolve "<the user's words, verbatim>"
```

**Run this FIRST, on the user's own phrasing, before any other probe.** It answers a question
none of the other probes can: *is this a question the platform already has an answer for?*

Two outcomes, and **both are useful**:

| Outcome | What it means | What you do |
|---|---|---|
| a `question_id` (e.g. `EM-002`) | the corpus already curates this question | carry that id through the build — into `catalog record-miss --question-id` if you end up authoring, so the miss aggregates by INTENT |
| `UNRESOLVED` | nobody has curated this phrasing | **not an error.** It is recorded as demand, and demand is what tells curators which question to add next. Keep building. |

⚠️ **An UNRESOLVED answer is never a reason to stop or to apologise.** The platform's corpus
is 100 questions; a real user's ask will frequently sit outside it. Recording that is the
system working, not failing.

⚠️ **Ambiguous?** When two questions score within the margin the resolver returns
`alternatives` and `ambiguous: true`. **Pick deliberately and say which you picked** — taking
the first of two near-equal candidates silently is how a build answers a question the user
did not ask.

⭐ **Why this is probe 0 and not probe 8.** The resolved id is an INPUT to the catalog
adjudication at probe 7: it is what lets "what should we fix first?" and "show me the stuff
most likely to get us hacked" reach the SAME entry instead of producing two definitions that
disagree at the edges.

### 6 — policy vocabulary (the platform's tunable domain settings)

The estate's data tells you what's *possible*; the **policy vocabulary** is the platform-owned closed
set of VM domain SETTINGS that vary between orgs — the severity floor that counts as "actionable", the
EPSS score that escalates, the SLA windows per severity, the asset exclusions, the reachability/exposure
gates. Each has a platform default; a tenant's value is resolved at install (from that org's policy
docs if found, else the default, overridable). You **never guess or hardcode** these ("P0=24h",
"EPSS > 0.5" from memory) — you author a `{{vocab:...}}` placeholder and the platform resolves it.

```bash
"$TORANA" vm policy vocabulary                          # the closed vocabulary: keys, qualified
                                                        # {{vocab:...}} paths, shapes, render verbs, defaults
"$TORANA" vm policy vocabulary-browse                   # THIS tenant's RESOLVED values + provenance
                                                        #   (origin: from_policy / system_default / conflicted)
"$TORANA" vm policy vocabulary-browse --tenant <id>     # (SA) another tenant's resolved values
```

Two distinct things:

- **The vocabulary** (`vm policy vocabulary`) is the platform-neutral CLOSED SET of tunable settings —
  the same catalog as [vocabulary-catalog.md](vocabulary-catalog.md). It defines the exact
  `{{vocab:vm.<category>.<subcategory>.<key>[.<verb>]}}` placeholders you emit in artifact SQL so the
  values resolve **per-tenant at install** (see the DRIVE step).
- **The resolved values** (`vm policy vocabulary-browse`) are THIS tenant's actual current values,
  with provenance (the `origin`: extracted from a policy doc, a system default, or a manual override).
  Use them to REASON — to size a funnel, pick meaningful tiers, or explain the posture — while still
  authoring `{{vocab:...}}` placeholders (never the literal), so the artifact stays portable and
  re-resolves if the value changes.

If a setting the program needs has **no org value** (browse shows `origin: system_default`), the
program still builds — the placeholder resolves to the platform default. Note it in
`grounding.policy_vocabulary` (see `artifacts-schema.md`).

## Empty data is first-class

With no shape to ground in (a fresh tenant), author from **graph-capability + schema +
intent**, mark assumptions in `grounding.logic_rests_on`, and set the program
`pending-grounding`. VERIFY structure (SQL validity, artifacts created) rather than row
counts. The program is designed to be **re-grounded** when data arrives — that is exactly
what ASSESS does later. Do not refuse to build on an empty tenant; build the structure and
say it's awaiting grounding.

## Record what you found → `grounding`

Everything DISCOVER surfaces that the program's logic rests on goes into the `grounding`
block of `artifacts.yaml` (see `artifacts-schema.md`): the present edges, the shape numbers,
the baseline KPI values, the **resolved policy vocabulary** (`grounding.policy_vocabulary` — which
keys the program consumes and their resolved-vs-defaulted state), and the plain-English assumptions.
That snapshot is what makes later re-evaluation principled — ASSESS diffs current reality against it.


---

## Probe 7 — the catalog (read it whole, once, before you specify anything)

The other six probes tell you what the estate *contains*. This one tells you what the
platform has **already answered**.

The reviewed `vm.tf.*` definitions cover this exact domain: findings on assets, asset
posture, exploited findings, SLA clocks, remediation actions, scan coverage. Each was
authored once against the real schema, validated, and reviewed.

```bash
"$TORANA" vm transformers catalog list
```

**Read it once per build and hold it.** Every entry — id, what each answers, and its
grain — is roughly 5k tokens. That is small enough to read whole, which changes what this
probe is: there is no query to phrase, no ranking to trust, and no cut-off that can hide
the right entry below it. Re-listing per relation is the same tokens paid many times for
information you already have.

There is a `catalog search` command. **Do not use it here.** It ranks by textual
resemblance to a query you write, which is precisely the failure this probe avoids: the
words you would use to describe a *need* are not the words the entry uses to describe its
*shape*, so the right entry can rank below a wrong one, or fall off the list entirely.
Keep `search` for human spelunking over a catalog too large to read; at the catalog's size it can
only lose you information.

**Then adjudicate each relation against what you have read:**

* **An entry SATISFIES the need** → your blueprint step names the **entry id**. You are
  not authoring SQL for this step at all. Judge on `one row` — the grain — not on how
  closely the description echoes your wording.
* **None fits** → record the miss before authoring. The record is what turns your gap into
  the next catalog entry, and the API will reject the transformer write without the
  decision id it returns:

```bash
"$TORANA" vm transformers catalog record-miss "<need>" \
  --gap-category <missing_column|missing_hole|wrong_grain|different_join|genuinely_novel> \
  --near-miss <the entry that came closest> \
  --rationale "<name the axis that fails — wrong grain? a column no entry reads? a join nothing makes?>"
```

`--near-miss` is what makes the record useful to the next author: "nothing fit" tells them
nothing, "em_012 is right except for the grain" tells them what to build.

### NARRATE THE DECISION — the user must see you reason

The lookup is not a private step. The user is watching a build; the reuse decision
is one of the most consequential judgements you make, and it must be visible **as it
happens**, not inferable from the artifacts afterwards.

For **every** relation, print this block. Same shape every time, so it is scannable:

```
🔍 CATALOG — <the relation this step needs, in your words>

   Looking for : one row per remediation ACTION (component + target version),
                 so a "fix this once" list does not double-count findings

   Considered  :
     vm.tf.em_012  one row per candidate remediation action …   ← closest
     vm.tf.em_019  one row per package/root-cause group …
     vm.tf.em_092  one row per disclosed CVE in our estate …

   Decision    : REUSE vm.tf.em_012
   Because     : its grain IS the action grain I need — component + package
                 manager + target fixed version — and it already counts distinct
                 assets/repos per action. Authoring my own would duplicate it.
```

On a miss, the same block ends differently — and the **Because** line must name the
AXIS, not merely report failure:

```
   Decision    : AUTHOR (catalog miss recorded: 84d61be0-…)
   Because     : em_012 comes closest — same subject — but it is finding-grain;
                 this step needs one row per (team, month) so the counts roll up.
                 Wrong grain, not a missing column — recorded as `wrong_grain`.
```

**A Because line that does not name an axis is not a reason.** "No good match" tells
the user nothing they can check. "Wrong grain / a column no entry reads / a join
nothing makes" is a claim they can disagree with — which is the point.

`catalog list` prints `one row` (the grain) and `reads` (the source tables) for every
entry precisely so you can quote them here rather than asserting from memory. Quote the
entry's own words; do not paraphrase a grain you did not read.

### Why this probe is not optional

The cost of a duplicate is not wasted effort — it is **two answers to one question that
disagree at the edges**. One variant includes `Deferred`, another forgets `is_suppressed`,
a third writes `= false` on a nullable boolean and silently drops 99.5% of rows. All three
look correct in isolation. A KPI built on one and a drill-down built on another will not
reconcile, and nobody will know which is wrong.

### When the entry fits but the table is not built yet

**Normal. Declare it anyway.**

Materialization is an install side-effect, not something you invoke: `materialize` /
`release` are service-to-service writes with a service JWT, deliberately absent from the
CLI so a caller cannot mutate refcounts out of band. Your read is:

```bash
"$TORANA" vm transformers materialized     # what THIS tenant has built
```

The mechanism is refcounted and proven end to end — N programs needing the same shape point
at ONE table, and the last release tears it down. Your blueprint step names the entry id;
install builds it once for everyone who asked.

Do **not** author the relation yourself because it is absent right now. That is the
duplication problem wearing the disguise of progress.

⚠️ An entry can materialize EMPTY and still be correct. `vm.tf.finding_enriched` builds
with 0 rows today because its LEFT JOINs depend on FKs nothing populates. Empty means the
DATA is missing, not the definition — do not rewrite the SQL to "fix" it.
