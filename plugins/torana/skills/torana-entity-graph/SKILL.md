---
name: torana-entity-graph
description: >
  Map a code repository's DEPLOYMENT topology into Torana's asset graph — the DECLARED
  (code-side) view of what a repo deploys, where, and what's internet-facing. You do NOT
  parse or key anything yourself: you DISCOVER the deployment stacks (docker-compose,
  Kustomize overlays, Helm charts, raw Kubernetes YAML), ask the user which is the
  canonical target and under what environment, ensure a `manifest` Deployment carries its
  governance, then run `torana entity-graph parse-manifests` which RENDERS the manifest with
  its native tool (kustomize build / helm template) and pushes it to the server, which
  interprets it into `service:` nodes + digest-keyed `deployed_as` edges + `exposed_via`.
  These DECLARED edges converge with the cloud connector's OBSERVED edges on identical keys
  (the "lights up later" promise) and stand alone for customers who won't grant cluster
  access. Trigger when the user wants to: map a repo's deployment topology, build the
  declared asset graph, see what a repo deploys and what's exposed, or shift-left check a
  deployment before it runs.
metadata:
  version: "2.0"
  last_updated: "2026-07-01"
  platform_version_tested: "2026.1"
  build_spec: "pantheon-program-framework/docs/EM/Deployment_Object_and_Runtime_Provenance.md § 2.6"
---

# Torana Entity Graph — declared deployment topology from repo manifests

## ⛔ Step 0, ALWAYS: load `torana-skill` — it is how the `torana` CLI is learned

**Invoke `torana-skill` (the `Skill` tool) before the first `torana` command this skill runs.**
Its install/auth bootstrap, profile rules and each verb's flags live there, not here — this
file names commands, it does not teach them, and a command used from memory is how a flag
drifts or a wrong verb runs.

- ⛔ **A working CLI is NOT evidence it is loaded.** `torana --version` succeeding only proves a
  binary exists — exactly how a run skipped `torana-skill` while everything "worked".
- ✅ **Loaded by a caller in this same session counts** — confirm it was actually invoked, and
  do not load it twice.
- ⛔ Where this file and `torana-skill` disagree about a command, **`torana-skill` wins**; say so.
- If `torana-skill` is not installed, stop and say so — ⛔ never run CLI commands from memory.


> The cloud connector sees *what is running* (the **observed** graph); this skill reads the
> repo for *what is declared to run* (the **declared** graph). **You do not parse manifests
> or build node keys** — that is done server-side so the declared edges key **identically**
> to the observed ones and CONVERGE on the same `torana_edge_id`. Your job is to **discover,
> ask, and orchestrate**: pick the canonical deployment stack, attach its governance via a
> `manifest` Deployment, and run one CLI command that renders + pushes.

## The model — RENDER (client) → INTERPRET (server)

- **You render, the server interprets.** Real deployment systems (Kustomize/Helm) only
  yield the truth *after* their native renderer runs (`kustomize build` merges overlays and
  pins image digests; a raw parse of the base gives a placeholder image). So the CLI runs
  the **native tool** locally and POSTs the plain rendered YAML; the server turns it into
  edges using the SAME keying the live-cluster connector uses.
- **Never write a parser.** Do not write Python to parse compose/k8s YAML, do not compute
  `image:`/`service:` keys, do not hand-build edge JSON. If you catch yourself writing a
  parser, stop — `torana entity-graph parse-manifests` does it correctly and deterministically.
- **Convergence + standalone.** Declared `deployed_as` (medium) upgrades to the observed
  `high` on the same key; and when a customer won't grant cluster access, this declared graph
  is the *only* graph — so it must be complete and correctly keyed, which the server guarantees.

---

## Dependencies

**`torana-skill` must be loaded alongside this skill** — it installs the CLI wheel, sets
`$TORANA`, configures the base URL, and authenticates. All CLI calls use `"$TORANA"` (quoted).

```bash
"$TORANA" --version 2>/dev/null || echo "ERROR: no torana CLI — torana-skill's bootstrap has not run"   # proves a binary exists, NOT that torana-skill is loaded (Step 0)
```

Pairs with **`torana-scan`** (same repo, vulnerabilities → SARIF) and
**`torana-asset-inventory`** (the repo's `repo:` node + governance).

---

## Procedure

Use TodoWrite to track the phases. You are an ORCHESTRATOR — the heavy lifting is one CLI call.

### 0. Pre-flight

```bash
"$TORANA" auth me >/dev/null 2>&1 || { echo "not authenticated — load torana-skill"; exit 1; }
```
Confirm the tenant is the intended one (`"$TORANA" auth me` shows profile + tenant) — the push lands in the active token's tenant.

### 1. Discover the deployment stacks

Find every candidate deployment source in the repo (do NOT parse them — just locate them):

```bash
# Kustomize overlays (the cleanest target — pins digests)
find <repo> -maxdepth 4 -name 'kustomization.y*ml' -path '*overlay*' -o -name 'kustomization.y*ml'
# Helm charts
find <repo> -maxdepth 4 -name 'Chart.y*ml'
# docker-compose
find <repo> -maxdepth 3 \( -iname 'docker-compose*.y*ml' -o -iname 'compose*.y*ml' \)
# raw k8s
grep -rlE '^kind:\s*(Deployment|StatefulSet|Service|Ingress)\b' <repo> --include='*.yaml' --include='*.yml'
# Terraform (declares edges — deferred, note only)
find <repo> -maxdepth 3 -name '*.tf'
```

### 2. Choose the canonical stack + env — ASK, don't guess

A repo often has several stacks / overlays (base, staging, prod, multiple clouds). **Which
one represents the deployment to map — and under what environment label — is a fact only the
user knows.** Present what you found and ask:

> "I found these deployment stacks: `k8s/overlays/gke-prod` (Kustomize), `docker-compose.prod.yml`.
> Which is the canonical deployment to map, and what `env` label (e.g. `gke-prod`, `vm-prod`)?
> You can map several as separate environments."

Prefer the **Kustomize/Helm overlay** for the target env when present (it pins image digests →
`deployed_as` converges with the registry with no tag→digest step). Scope each stack under its
own `env` so their nodes don't collide but their image nodes converge.

### 3. Ensure a `manifest` Deployment (governance anchor)

Governance (criticality / owner / customer-data / the env label) is a human fact, not
inferable from the repo. Create (or reuse) a **`manifest`-type Deployment** to hold it:

```bash
# reuse if one already exists for this env:
"$TORANA" deployments list 2>/dev/null | grep -i <env>

# else create a manifest deployment (no cluster, no credentials — it's declared):
"$TORANA" deployments create --name <env> --source-type manifest --env-label <env> \
   --criticality high --owner <team> [--has-customer-data]
```
Capture the returned deployment id.

### 4. Render + push — the one command

```bash
"$TORANA" entity-graph parse-manifests \
   --path <the chosen stack dir/file> \
   --flavor <kustomize|helm|k8s-raw|compose> \
   --deployment <deployment-id>
```
- `--flavor kustomize` → runs `kustomize build` / `kubectl kustomize` (needs one on PATH).
- `--flavor helm` → runs `helm template` (add `--values <f>` per values file).
- `--flavor k8s-raw` → reads plain YAML (already rendered).
- `--flavor compose` → runs `docker compose config` (needs Docker on PATH). Yields
  tag-keyed `deployed_as` + `accesses` (service→datastore) + port-based exposure. Pick this
  only when the *canonical* deployment is compose (single-host / VM), not for a dev compose file.
- Governance + env come from `--deployment`. Without a Deployment, pass `--env <label>` and
  inline `--criticality/--owner/--has-customer-data`.

The response is a receipt with `counts` (`assets`, `entity_edges`, `edges_dlq`, `candidates`).
**Check `edges_dlq` — non-zero means the rendered manifest had type-incorrect edges; report it.**

### 5. Degrade gracefully — never fabricate

- **Renderer missing / render fails** (no `kustomize`/`helm`, external secrets, needs a plan):
  the command errors. Tell the user which tool to install or which values/env files are
  missing; do NOT hand-parse the manifest as a workaround.
- **Terraform / CloudFormation** (the source of `declares` repo→cloud edges): **deferred** —
  note it in the summary, don't attempt it.
- **Unkeyable images / exposures** (a tag-only image, a CD-injected image, a LB with no
  cloud key): the **server** already emits these as **candidates** (visible in the Edge
  Candidates tab) — nothing for you to do; just mention the candidate count.

### 6. Verify + summarize

```bash
"$TORANA" entity-graph edges list --created-via manifest_parse
"$TORANA" entity-graph candidates list
```
Summarize: which stack + env was mapped, the `deployed_as` / service-node / exposure counts,
which services are internet-facing (public), the candidate count, and any flavor **deferred**
(Terraform/CI). Note that these declared edges will **converge** with the cloud connector's
observed edges (or already have, if a cluster Deployment for the same env exists).

---

## What this skill does NOT do

- **Does not parse manifests or compute keys.** The CLI renders; the server interprets and
  keys. Writing a parser is a bug.
- **Does not need cluster access.** It reads the *repo* — the declared side. (The `cluster`
  Deployment + K8s integration is the separate *observed* side.)
- **Does not assert governance from the repo.** Criticality/owner/customer-data are asked and
  stored on the `manifest` Deployment.
- **Does not emit `declares` (repo→cloud) or `runs_on`.** `declares` needs Terraform/CFN
  (deferred); `runs_on` needs a runtime host source (the cloud connector).

See `references/manifest-parsing.md` for the flavor/render reference.
