# Render/interpret reference — flavors, what lands, degradation

> **You do not parse manifests.** `torana entity-graph parse-manifests` renders with the
> native tool and the SERVER interprets the plain YAML into the asset graph
> (Deployment_Object_and_Runtime_Provenance.md § 2.6). This reference is only for choosing
> the flavor and understanding what the server produces — there is no parsing logic here to
> reimplement, and you must not write any.

## Per-flavor render (what the CLI runs, what it yields)

| `--flavor` | Native render the CLI runs | Why it must render | Yields |
|---|---|---|---|
| **kustomize** | `kustomize build <dir>` (or `kubectl kustomize <dir>`) | base+overlay merge + the `images:` transformer that pins **digests** live only in the overlay | **digest-pinned** `deployed_as` (converges with the registry, no tag→digest step); Services/Ingress → exposure |
| **helm** | `helm template <chart> [--values f …]` | Go templates + values hierarchy resolve only via helm | rendered k8s objects (same as above) |
| **k8s-raw** | none — reads the plain YAML file(s) | already literal | `deployed_as` (digest-keyed only if the image is `@sha256`-pinned), exposure |
| **compose** | `docker compose config` (needs Docker on PATH) | resolves `extends`, `env_file`, profiles, `${VAR}` interpolation | **tag-keyed** `deployed_as` (compose rarely digest-pins → medium, won't digest-converge), `accesses` (service→`datastore:self-hosted/<engine>/<target>` from `depends_on`/engine images), exposure from published host ports. One-shot init services (`restart:"no"`, `-init`/`-migration`) get a `service:` node but are never treated **as** a datastore |
| **terraform** | *(deferred — needs `terraform plan`; the only source of `declares` repo→cloud)* | — | note in summary, do not attempt |

Prefer the **overlay for the target env** (Kustomize/Helm) — it pins digests, so the declared
`deployed_as` keys byte-identically to the registry/observed image node.

## What the server produces (per rendered manifest)

- **`service:` asset nodes** — one per workload (`service:<env>/<name>`), governance stamped
  from the referenced `manifest` Deployment (criticality / owner / customer-data).
- **`image ──deployed_as──▶ service`** — from the MAIN container's resolved digest
  (init-containers + sidecars skipped), keyed `image:<registry>/<repo>@sha256:<digest>`.
  Confidence `medium`; converges with the observed `high` on the same `torana_edge_id`.
- **exposure** — a `Service type=LoadBalancer` or an `Ingress` stamps **`public_access=true`
  (declared)** on the fronted `service:` node (the "internet-facing?" signal, no cluster
  needed) and emits an `exposed_via` **candidate** (the specific `cloud:` LB is unkeyable
  from a manifest → it auto-promotes when the cloud connector observes the real LB).

## Degradation — the server handles it; you never fabricate

- **Unkeyable image** (tag-only, or CD-injected/not-digest-pinned) → the server emits a
  `deployed_as` **candidate** (`unresolved image`). It keys for real once the cluster observes
  the running digest.
- **Unkeyable exposure** (no cloud LB key from a manifest) → `exposed_via` **candidate**.
- **Render impossible** (no `kustomize`/`helm` on PATH, external/GitOps secrets, needs a plan)
  → the CLI errors; surface which tool/values are missing. **Do not hand-parse as a fallback.**

## Convergence + standalone (why this matters)

The declared edges use the **same keys** as the cloud connector's observed edges, so where
both run they **converge** (medium → high) and **drift/promote** through the candidate ledger.
And for a customer who won't grant cluster access, this declared graph is the **only** graph —
correctly keyed and complete because the server (not you) produced it.

## Read back

```bash
"$TORANA" entity-graph edges list --created-via manifest_parse
"$TORANA" entity-graph candidates list
```
