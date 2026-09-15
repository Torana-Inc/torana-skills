---
name: torana-asset-inventory
description: >
  Create (or update) a Torana asset-inventory record for a code repository:
  its IDENTITY (host/org/repo, languages, default branch, visibility) and its
  GOVERNANCE (business criticality, owner, environment, SLA policy, data
  sensitivity) — the facts no scanner can know. Derives what it can from the
  local git remote and the `gh` CLI, then interactively asks the user for the
  governance it cannot infer (never silently guessing), marks every field as
  inferred vs reviewed, writes an asset_inventory.v1.json file, and pushes it
  via `torana ingest assets`. Trigger whenever the user wants to: create an
  asset inventory, register a repo with Torana, set repo criticality / owner /
  environment / SLA, onboard a repository, describe an asset, build an assets
  file, generate vm-assets, or "tell Torana about this repo". The asset record
  lands in the `repositories` sink table under a SOURCE-NEUTRAL id
  (`repo:<host>/<org>/<repo>`) so scanner findings (SARIF) and VCS sync
  converge on the same row.
metadata:
  version: "1.0"
  last_updated: "2026-06-16"
  platform_version_tested: "2026.1"
---

# Torana Asset Inventory — identity + governance for a repository

> Scanners emit findings; they cannot know a repo's business criticality,
> owner, environment, or SLA. This skill produces the **asset record** that
> carries those facts. It derives identity automatically, asks the user for
> governance, and pushes an `asset_inventory.v1.json` to
> `POST /api/v1/ingest/assets`. The record lands in `repositories` under a
> **source-neutral** id so `torana-scan` (SARIF) findings link to it.

---

## Dependencies and Precedence

**`torana-skill` must be loaded alongside this skill.** This skill does not
bootstrap the CLI or OAuth — it relies on `torana-skill` having installed the
CLI wheel, set `$TORANA`, configured the base URL, and authenticated.

Soft check before pushing:

```bash
"$TORANA" --version 2>/dev/null || echo "ERROR: torana-skill not loaded — load it first"
```

All CLI invocations use `"$TORANA"` (quoted) — never bare `torana`.

This skill pairs with **`torana-scan`**: scan checks for an asset file and, if
missing, invokes this skill to create one before scanning.

---

## The source-neutral key (why this matters)

The repository identity Torana stores is **derived from the repo URL, not from
who reported it**:

```
asset_key            = normalize(host/org/repo)   # lowercased, scheme- & .git-stripped
torana_repository_id = "repo:" + asset_key         # e.g. repo:github.com/acme/api
```

Because the scan skill, the GitHub integration sync, and this asset skill all
derive the **same** key, they all upsert the **same** `repositories` row. You do
not need to coordinate ordering: ingest the asset before or after the findings —
they join on the key. **Never invent or hand-edit the id**; always let it derive
from `asset_ref`.

---

## Procedure

### 1. Locate the repo and derive identity

Run from the repo root. Derive identity facts — these are `inferred`:

```bash
# Canonical remote → asset_ref (the server normalizes it to the asset_key)
git remote get-url origin
# Default branch
git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's@^origin/@@' || git branch --show-current
# Languages (rough): top file extensions
git ls-files | sed -n 's/.*\.//p' | sort | uniq -c | sort -rn | head -8
```

If `gh` is available and authenticated, enrich identity (still `inferred`):

```bash
gh repo view --json name,owner,visibility,isPrivate,isFork,licenseInfo,defaultBranchRef 2>/dev/null
```

Map results into the asset doc's `identity` block. `asset_ref` = the
`git remote get-url origin` value (or `host/org/repo` if the user gives it
explicitly). Do **not** normalize it yourself — the server does, idempotently.

### 2. Check whether the asset already exists (idempotency)

```bash
# A local asset file?
ls asset-inventory.json 2>/dev/null
# Already in Torana? (the repo id is derivable, so you can look it up)
"$TORANA" repositories list --raw 2>/dev/null | grep -i "<org>/<repo>" || true
```

If an asset already exists, **reconcile, don't clobber**: load the existing
governance, present it, and only change fields the user wants changed. Re-running
this skill is a sparse update — preserve `reviewed` governance the user previously
confirmed.

### 3. Collect governance interactively (never guess)

Ask the user, one topic at a time. These are `reviewed` once answered; anything
the user cannot/won't specify is recorded as `unknown` — **never a silent
default**:

1. **Business criticality** — Critical / High / Medium / Low (+ a 1–5 level).
2. **Owner** — team or person: name, email, and (optional) GitHub handle.
3. **Environment** — production / staging / development / test.
4. **Data sensitivity** — e.g. PII, PCI, none.
5. **SLA policy** — remediation-days per severity (critical/high/medium/low).
6. **Description (required)** — one sentence on the repo's purpose. Torana table
   convention requires this; prompt until you have a real answer.
7. **Tags** — optional free-form labels.

### 4. Assemble the asset_inventory.v1.json document

Write `asset-inventory.json` in the repo root. Shape (omit fields you genuinely
don't have rather than writing nulls; `field_provenance` records origin):

```json
{
  "schema_version": "asset_inventory.v1",
  "asset_ref": "git@github.com:acme/api.git",
  "description": "Customer-facing billing API.",
  "reviewed": true,
  "identity": {
    "name": "api",
    "full_name": "acme/api",
    "provider": "github",
    "org": "acme",
    "default_branch": "main",
    "languages": ["python", "sql"],
    "visibility": "private",
    "is_private": true,
    "is_fork": false,
    "license": "MIT"
  },
  "governance": {
    "criticality_name": "High",
    "criticality_level": 4,
    "owner_name": "Billing Platform",
    "owner_email": "billing-eng@acme.com",
    "owner_github_user": "acme-billing",
    "environment": "production",
    "data_sensitivity": "PCI",
    "tags": ["revenue", "pci"],
    "sla_critical_days": 7,
    "sla_high_days": 14,
    "sla_medium_days": 30,
    "sla_low_days": 90
  },
  "field_provenance": {
    "languages": "inferred",
    "criticality_name": "reviewed",
    "owner_email": "reviewed",
    "environment": "reviewed"
  }
}
```

### 5. Present for confirmation, then push

Show the assembled document, clearly flagging which fields are `inferred` vs
`reviewed` vs `unknown`. After the user confirms:

```bash
"$TORANA" ingest assets ./asset-inventory.json --format json --raw
```

The receipt confirms the row landed:

```json
{ "scan_id": "asset:git@github.com:acme/api.git", "source": "asset",
  "received_at": "2026-06-16T...Z", "counts": { "repositories": 1 } }
```

`counts.repositories == 1` means the `repositories` row was upserted under
`repo:<host>/<org>/<repo>`. Re-running with edited governance re-runs server-side
(the endpoint is run-always) and updates the row in place.

---

## Guardrails

- **Never silently guess governance.** Criticality, owner, environment, SLA, and
  data sensitivity come from the user. If unknown, mark `unknown` and say so.
- **Never hand-build `torana_repository_id`.** It derives from `asset_ref`
  server-side. Supplying a raw remote is enough.
- **`description` is required** — do not push without a real one-sentence purpose.
- **Reconcile, don't clobber.** On re-run, preserve previously `reviewed`
  governance unless the user explicitly changes it.
- **Identity is inferred, governance is reviewed.** Keep `field_provenance`
  honest — it tells downstream consumers (and auditors) which facts a human
  vetted.

---

## Asset graph — edges (AG0 scaffold)

Beyond the asset record, this skill can emit **entity-graph edges** (the DECLARED
side of the CAASM asset graph): typed, directional relationships like
`repo ──builds──▶ gav ──packaged_in──▶ image`. See
[references/entity-edges.md](references/entity-edges.md) for the `entity_edges.v1`
wire format, the eight key schemes, the legal edge-type→endpoint table, and the
push command `torana ingest entity-edges <file>`.

> **AG0 scope:** the wire format + push path ship now. The build-file parsers
> that *derive* edges from `pom.xml` / `Dockerfile` / CI / Terraform are **AG1**
> and not part of this scaffold.
