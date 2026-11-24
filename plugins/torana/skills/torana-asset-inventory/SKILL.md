---
name: torana-asset-inventory
description: >
  Create (or update) a Torana asset-inventory record for a code repository:
  its IDENTITY (host/org/repo, languages, default branch, visibility), pushed
  via `torana ingest assets`, and the business context no scanner can know
  (criticality, customer data, owning team), set as POLICY ENTRIES with
  `torana vm policy set-entry` after asking the user (never silently guessing).
  Trigger whenever the user wants to: create an asset inventory, register a repo
  with Torana, set repo criticality / owner / customer data, onboard a
  repository, describe an asset, build an assets file, generate vm-assets, or
  "tell Torana about this repo". The asset record
  lands in the `repositories` sink table under a SOURCE-NEUTRAL id
  (`repo:<host>/<org>/<repo>`) so scanner findings (SARIF) and VCS sync
  converge on the same row.
metadata:
  version: "1.0"
  last_updated: "2026-06-16"
  platform_version_tested: "2026.1"
---

# Torana Asset Inventory — identity, and business context as policy

## ⛔ Step 0, ALWAYS: load `torana-skill` — it is how the `torana` CLI is learned

**Invoke `torana-skill` (the `Skill` tool) before the first `torana` command this skill runs.**
Its install/auth bootstrap, how to sign in and each verb's flags live there, not here — this
file names commands, it does not teach them, and a command used from memory is how a flag
drifts or a wrong verb runs.

- ⛔ **A working CLI is NOT evidence it is loaded.** `torana --version` succeeding only proves a
  binary exists — exactly how a run skipped `torana-skill` while everything "worked".
- ✅ **Loaded by a caller in this same session counts** — confirm it was actually invoked, and
  do not load it twice.
- ⛔ Where this file and `torana-skill` disagree about a command, **`torana-skill` wins**; say so.
- If `torana-skill` is not installed, stop and say so — ⛔ never run CLI commands from memory.


> Scanners emit findings; they cannot know a repo's business criticality,
> owning team or whether it handles customer data. This skill pushes an
> identity-only `asset_inventory.v1.json` to `POST /api/v1/ingest/assets` (the
> record lands in `repositories` under a **source-neutral** id so `torana-scan`
> findings link to it), then writes what the user says as **policy entries**. A
> value a person sets is policy, never a source value: the app shows it as "set by
> policy" beside anything the repository's own systems state.

---

## Dependencies and Precedence

**`torana-skill` must be loaded alongside this skill.** This skill does not
bootstrap the CLI or OAuth — it relies on `torana-skill` having installed the
CLI wheel, set `$TORANA`, configured the base URL, and authenticated.

Soft check before pushing:

```bash
"$TORANA" --version 2>/dev/null || echo "ERROR: no torana CLI — torana-skill's bootstrap has not run"   # proves a binary exists, NOT that torana-skill is loaded (Step 0)
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

If an asset already exists, **reconcile, don't clobber**: read the existing policy
entries for its `repo:` selector, present them, and only change what the user wants
changed.

### 3. Ask for business context (never guess)

Ask the user, one topic at a time. Anything the user cannot or will not specify is
left unset — **never a silent default**:

1. **Business criticality** — Critical / High / Medium / Low.
2. **Customer data** — does the repository's software handle customer data? yes / no.
3. **Owning team** — the team that fixes this repository's findings.
4. **Description (required)** — one sentence on the repo's purpose. Torana table
   convention requires this; prompt until you have a real answer.
5. **Tags** — optional free-form labels.

Do NOT ask for an environment or SLA days, and say why if the user offers them: the
environment is read from each deployed resource's own label or tag, and deadlines come
from the app's deadline policy, not from a per-repository value.

### 4. Assemble the identity-only asset_inventory.v1.json document

Write `asset-inventory.json` in the repo root. It carries identity only, so it needs
no `system_of_record`:

```json
{
  "schema_version": "asset_inventory.v1",
  "asset_ref": "git@github.com:acme/api.git",
  "description": "Customer-facing billing API.",
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
  "governance": {"tags": ["revenue"]},
  "field_provenance": {"languages": "inferred"}
}
```

A document carries business context (criticality, owner, sensitivity) only when the
user names an external **system of record** (for example `servicenow`) and supplies its
export: then set `"system_of_record": "<name>"` and the rows are labelled with it. Without
one the push is refused with 422 — set the values as policy instead (step 6).

### 5. Present for confirmation, then push

Show the assembled document, clearly flagging which fields are `inferred`. After the
user confirms:

```bash
"$TORANA" ingest assets ./asset-inventory.json --format json --raw
```

`counts.repositories == 1` means the `repositories` row was upserted under
`repo:<host>/<org>/<repo>`.

### 6. Write the business context as policy entries

For each answer from step 3, with `repo:<host>/<org>/<repo>` as the selector:

```bash
"$TORANA" vm policy set-entry criticality_overrides --selector repo:github.com/acme/api --value High --reason "<user's words>"
"$TORANA" vm policy set-entry customer_data_overrides --selector repo:github.com/acme/api --value true
"$TORANA" vm policy set-entry ownership_routing --selector repo:github.com/acme/api --value billing-platform
```

The response echoes the stored (canonical) selector. A note such as "no effect while no
service runs its images" means the entry is kept and takes effect once a running service
is built from the repository.

---

## Guardrails

- **Never silently guess business context.** Criticality, customer data and the owning
  team come from the user. If unknown, leave them unset and say so.
- **Never hand-build `torana_repository_id`.** It derives from `asset_ref`
  server-side. Supplying a raw remote is enough.
- **`description` is required** — do not push without a real one-sentence purpose.
- **Reconcile, don't clobber.** On re-run, read the existing entries with
  `torana vm policy show <key>` and change only what the user wants changed.
- **A person's value is policy.** Never push criticality, owner or customer data in the
  document without a named system of record.

---

## Asset graph — edges

Beyond the asset record, this skill can emit **entity-graph edges** (the DECLARED
side of the CAASM asset graph): typed, directional relationships like
`repo ──builds──▶ gav ──packaged_in──▶ image`. See
[references/entity-edges.md](references/entity-edges.md) for the `entity_edges.v1`
wire format, the eight key schemes, the legal edge-type→endpoint table, and the
push command `torana ingest entity-edges <file>`.

> The wire format and push path are available. Edges are authored by hand (or by your own tooling);
> nothing derives them from `pom.xml` / `Dockerfile` / CI / Terraform yet.
