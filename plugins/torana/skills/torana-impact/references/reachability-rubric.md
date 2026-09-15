# Reachability rubric — "does this finding matter?"

Four clauses. Each is one cheap read. Compose them into a verdict. The point: separate the
few findings that are *running, exposed, and near data* from the many that are dead code.

## The four clauses

### 1. Runs? (deployed) — the gate
Does the vulnerable code/package execute on any running service?
- **SAST** (repo finding): `entity-graph reachable "repo:<repo>" --via builds_image,deployed_as,exposed_via --direction forward`
- **SCA/CVE** (package finding): `entity-graph reachable "pkg:<type>/<name>@<ver>" --via contains:reverse,deployed_as:forward,exposed_via:forward`
  - **Mixed-direction is mandatory.** A package sits *inside* an image (`contains`, reversed to reach the image) which *deploys to* a service (`deployed_as`, forward). A single `--direction reverse` stops at the image and reports **0 services** — a false negative on the security-critical gate. Always use the `edge:dir` form above.
- **Reached a `service:` node?** → deployed → continue. **None?** → **not deployed → LOW urgency.** Report the finding, stop the escalation. (Dead code is the common case; saying so is the value.)

### 1b. Is the VULNERABLE COMPONENT reachable? (SCA only — the biggest noise-killer)
Clause 1 proves the *package* ships. It does **not** prove the *vulnerable code* runs. Most CVEs in a fat
library affect **one submodule** — a proxy server, a CLI, an optional backend — that a typical consumer never
imports. A package present in the image with its vulnerable component never imported is **dead code**.

1. **Identify the affected component** from the advisory (module path / entry point / feature).
   ⚠️ The platform will **not** tell you this: GCP Container Analysis rows land with
   `vulnerability_description` holding only the CVSS vector, no prose. You must read the advisory
   (GHSA/NVD/vendor) — and **cite it**.
2. **Prove non-use with a positive search**, across *every* surface that could pull it in — not just Python:
   ```bash
   grep -rn "<vuln.module>\|from <vuln.module>\|<pkg>\[<extra>\]" \
     --include=*.py --include=*.toml --include=*.txt --include=Dockerfile* --include=*.yaml --include=*.yml \
     pantheon-*/ | grep -v uv.lock
   ```
   Also check entrypoints/CMD and compose/k8s args — a component can be *run* without being *imported*.
3. **State which surface IS used** ("every import is SDK-shaped: `acompletion`, `embedding`"), so the claim is
   falsifiable rather than an absence hand-wave.

**Guardrails — this clause DOWNGRADES a Critical, so it must not be casual:**
- Downgrade **only** on zero hits across all surfaces **plus** a named component **plus** a cited advisory.
- **Cannot identify the component, or any ambiguity → do NOT downgrade.** Keep the graph tier and say why.
- Never fall below **P2** while the package is deployed — the vulnerable version is still on disk, still
  inherited by anything that later imports it, and one new import re-arms it.
- Frame it as a **recommendation pending confirmation**, and offer `torana-pentest` to prove
  non-exploitability empirically. Do not present a code-reading as proof of safety.

### 2. Internet-facing? (exposed)
For each reached service, read `assets.public_access` and whether it is the `from` of an `exposed_via` edge.
- `public_access=true` is now **per-service** (only LB/Ingress-fronted services), not a blanket flag — trust it.
- Cross-check: a service with an `exposed_via` edge is the one the load balancer fronts.
- Internal-only service (public_access=false, no exposed_via) is reachable from the edge only *through* the fronting service — note the path, don't call it directly internet-facing.
- **`exposed_via` may be absent for the WHOLE tenant** (one edge, or none). When there is no `exposed_via` anywhere, `public_access` is the *only* exposure signal — say so; absence of the edge is not evidence a service is internal. (Same shape as the `accesses` sparsity note in clause 3.)
- **Code-vs-graph conflict — carry both.** The graph models *service* exposure (LB/Ingress-fronted?); a SAST finding often describes a *route* ("public GET `/oauth/consent`"). A route can be app-public while its service is graph-internal (behind nginx/api-gw). If the finding text claims a public route but `public_access=false`, DO NOT resolve it silently — report both and flag: *"service is graph-internal, but the finding describes a public route reachable through the edge; a human should confirm the edge exposes this path."* The graph gives the service count; the finding text gives the exposure caveat.

### 3. Data-adjacent? (near customer data)
Two signals, in order:
1. The service's own `has_customer_data` (governance on the `service:` node).
2. An `accesses` edge to a `datastore:` whose `data_classification='customer-data'`:
   `entity-graph neighbors "service:<env>/<name>" --type accesses --direction forward`
- **`accesses` edges are sparse on secret-wired clusters** (DB connections via k8s secrets are opaque). If there is no `accesses` edge, DO NOT conclude "not data-adjacent" — fall back to signal (1), the service's `has_customer_data` attribute.

### 4. Critical? (blast weight)
`assets.criticality_name` on the service (or `govern show "service:<env>/<name>"`): low / medium / high / critical.

## The verdict
Compose the four into one line and a tier:

| Tier | Shape |
|---|---|
| **P0 — act now** | deployed **AND** internet-facing **AND** (data-adjacent OR criticality ≥ high) |
| **P1 — soon** | deployed **AND** (internet-facing OR data-adjacent) |
| **P2 — backlog** | deployed, internal, no data, low criticality — **or** deployed with the vulnerable component proven unreachable (clause 1b) |
| **P3 — dead code** | **not deployed** (no reached service) |

**Clause 1b caps, it does not zero.** A package that ships but whose vulnerable component is never imported
is **P2**, not P3 — P3 means the artifact isn't running at all. The version is still on disk and one new
import re-arms it, so it stays on the backlog rather than leaving the queue.

State the clauses explicitly: *"Deployed on service:prod/pantheon-auth (high-criticality, holds customer data), reached from the edge via pantheon-nginx → P0."* Never give a bare tier without the clauses that produced it.

**When the graph tier and the component tier disagree, report BOTH and lead with the gap** — it is the most
useful sentence in the brief: *"Graph-only this is P1 (deployed, high-criticality, customer data); the
vulnerable component is the proxy server, which this codebase never imports → recommend P2, pending
confirmation."* Never silently emit only the downgraded tier: the reader must see what you overrode.

## Honest caveats to always carry
- **Un-onboarded tenant** (`deployments exposure-intelligence` returns nothing, `depends_on`=0): `reachable` still works, but the ranked cross-finding view and dependents are empty — say so, don't imply the finding is isolated.
- **`accesses` sparsity** — the "data-adjacent" clause leans on the node attribute when the edge is missing (clause 3).
- **`exposed_via` absence** — when the tenant has no `exposed_via` edges, exposure rests on `public_access` alone (clause 2).
- **Edge absence is never evidence of absence** — for BOTH `accesses` and `exposed_via`, a missing edge means "the graph didn't derive it," not "it isn't there." Fall back to the node attribute and say which signal you used.
- **No CVE prose in the platform** — GCP Container Analysis rows carry `vulnerability_description` = the CVSS vector only. Clause 1b therefore *always* needs an external advisory; cite it, and if you cannot get one, say the component could not be determined and skip the downgrade.
- **A CVE spans versions, not one pin** — resolve the CVE to every affected version cohort before answering "who is exposed" (see the fix-impact rubric §A). Answering the version quoted in the question is the classic under-scope.
