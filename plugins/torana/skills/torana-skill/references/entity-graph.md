# Entity graph — the asset graph, and which way its edges point

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap first.**

The graph answers reachability and blast-radius questions: what is deployed, what is
internet-facing, what sits next to customer data, and what a change ripples into.

---

## ⚠️ The graph is DIRECTED — forward ≠ reverse

Edges point a natural way:

```
image ──contains──▶ pkg
image ──deployed_as──▶ service
service ──exposed_via──▶ cloud LB
```

So the two questions below are **different traversals** and return different sets:

| Question | Direction |
|---|---|
| "What does this run / depend on?" | **forward** — follow the arrows |
| "What is affected if I change this?" | **reverse** — walk AGAINST the arrows |

Asking the wrong direction returns a confident, plausible, wrong answer. When a
blast-radius query comes back suspiciously small, check the direction first.

## Node keys have a grammar

```
pkg:pypi/libexample@1.2.3                                   an SBOM package (a leaf)
image:us-west1-docker.pkg.dev/.../svc@sha256:…  a built container image
service:cluster-a/team-a/service-a  a Kubernetes workload: service:<cluster>/<namespace>/<name>
service:production/service-b        a non-Kubernetes service: service:<env>/<name>
cloud:gcp/resource/136.66.136.36                a public cloud endpoint
repo:github.com/acme/billing-api                a source repo
```

⚠️ **A Kubernetes key carries its CLUSTER NAME.** Two clusters running the same
`<namespace>/<name>` are two nodes. A cluster name shared by 2+ clusters is refused (never
merged): `entity-graph health` lists it under `cluster_name_collisions`. Pushing a rendered
manifest needs `entity-graph parse-manifests --cluster <name>` unless the tenant has one cluster.

⚠️ **Which kind of compute a service runs on is read from its asset record, not from a runtime-context table.**
A table that links a service to its image or package says what it runs, not where. For "is it a function, a container
service, a virtual machine?", read the service's cloud asset: the service segment of its ARN (`lambda`, `ecs`, `ec2`,
...) and the kind-specific attributes beside it (a function's package type, a container service's launch type). Quote
what the asset says. Say "not recorded" only after you have read that record.

⚠️ **Different namespaces do not join.** A vulnerability keyed `image:` and an asset keyed
`cloud:` describe different things; joining them yields zero rows and *looks* like "no
exposure". A zero-row join is a finding about the keys, not about the risk.

## Commands

```bash
"$TORANA" entity-graph --help                    # richest examples in the CLI — read it
"$TORANA" entity-graph neighbors <NODE_KEY> --direction both
"$TORANA" entity-graph nodes --help
"$TORANA" entity-graph nodes resolve <NODE_KEY> ...    # NAME = the row's own name (a host's hostname), STATE, HOME_TABLE
"$TORANA" entity-graph edges --help
"$TORANA" entity-graph contract show             # which edges each (category, table) OWES
"$TORANA" entity-graph contract violations       # the outstanding debt

# One edge type across a SET of nodes — ONE call, not one per node:
"$TORANA" entity-graph edges list --type deployed_as --compact --limit 50
"$TORANA" entity-graph edges list --type contains --all --compact
"$TORANA" entity-graph neighbors <NODE_KEY> --direction both --compact
```

### Graph-health invariants (the Expectation Registry)

```bash
"$TORANA" entity-graph expectations run                         # evaluate now: value vs threshold per invariant
"$TORANA" entity-graph expectations seed                        # restore/update the platform-canonical set
```

- `run` needs `asset:read` (every standard tenant role). `seed` needs `asset:manage`
  (tenant_admin, via `asset:*`). `--tenant-id` needs super admin;
  any other caller gets a 403 (exit 4).
- Every reconcile sweep already applies a changed canonical definition. Run `seed` only
  to get back an invariant the tenant soft-deleted: the sweep never restores one.

⭐ **`--compact` narrows the REQUEST** to `from_key, to_key, edge_type, confidence,
created_via` — unlike `--fields`, which fetches full rows and trims the DISPLAY. A full
edge row is ~1,150 bytes against ~170 for the relationship, so `--compact` is what makes
`--all` over a large edge type affordable.

⚠️ **Pair it with `--limit 50`, not 100.** Measured 2026-10-04: a 100-row compact page of
long `image@sha256` keys reaches ~8,175 tokens and overruns the 8,000-token result budget
an agent reading the same route lives inside; 50 fits with ~47% margin at any key length.
Page with `--offset` while the reported total exceeds one page.

⚠️ **Check an edge type's TOTAL before planning to page it.** Most types here are tens to
hundreds of edges (one or two pages), but `contains` is ~28,870 — 289 pages at 100. And an
edge count is never a count of the things on either end: two versions sharing a package are
two connections and one package.

## Who owns an entity: `vm properties`

Business context (environment, owner, team, criticality, customer data) is taken, in this order, from the resource itself
(its Kubernetes labels or AWS tags), then from the declaration that covers its whole source (the Kubernetes Deployment's
config, or the AWS integration's settings), then nothing. It is never guessed: a value nobody stated stays empty. The
context is carried from a deployment to its images and repositories over graph edges. These two verbs read the resolved result:

```bash
"$TORANA" vm properties entities                    # every governed entity: KIND, ENTITY, TEAM, REPO-OWNER, ENV
"$TORANA" vm properties entities --kind image --limit 50      # --kind is service | image
"$TORANA" vm properties entities --ungoverned       # the remainder governance has not reached
"$TORANA" vm properties resolve <NODE_KEY>          # one entity: its values and where each came from
"$TORANA" --format json vm properties resolve <NODE_KEY>      # same, as the API returns it
```

- Any tenant role with `deployment:read` may run them.
- `resolve` exits 3 when the key has no resolved row. `entities --kind` refuses any other
  value with a 422 (exit 6).

⛔ **TEAM and REPO-OWNER are two different facts. Report them as two.**
`asset_team` (TEAM) is a team somebody DECLARED, and nothing else. `repository_owner`
(REPO-OWNER) is the owner or organisation login of the repository the code lives in, or
that builds the image: an observed fact about the code host. When you answer "who owns
this":

1. A declared team exists: give the team.
2. No team, but a repository owner: give the owner and SAY it is the repository owner,
   e.g. "no team is declared; the repository owner is `acme-org`". Never call it the team.
3. Neither: say nobody is recorded. Do not invent `unassigned`.

In `resolve`, the two are adjacent lines (`asset_team`, then `repository_owner`), and the
`repository_owner` receipt under PROVENANCE names the repository it was read from.

## Traps

⚠️ **Graph data is per-TENANT.** An empty result may mean you are on the wrong tenant, not
that the relationship is absent. Check which tenant you are logged in to with `auth me`.

⚠️ **"Running" narrows the set before you count.** The graph holds a link for everything that has ever been exposed,
including services with no workload behind them now. When a question says running (or "now", or "live"), keep only
the services that have something running behind them (a current service link to a running artifact: an image, a
function package or any other runtime artifact the platform records) and count those: that
is the number. List the others apart, labelled "exposed, nothing running", with their count. The same holds for
workloads: an inventory row with no running artifact (image, function package, other) or pod behind it is recorded, not
running. An empty image column alone does not mean nothing runs: look for a `deployed_as` edge from an artifact to it
(`entity-graph edges list --type deployed_as`) before calling it recorded-only. Never report the
all-exposed total as the running one, and make the two counts add up to the all-exposed total. Count services, not
the lines of a table: when the same service name appears in several environments, each is one service.

⚠️ **A row with no edge is ABSENT, not reported.** The graph has no node table, so an
unconnected asset does not show up as "unconnected" — it does not show up at all. Exposure is
computed *from* the graph, so the platform can answer "not exposed" with total confidence
about an asset it has never seen. Exposure is exposed or not exposed. Reachable from the internet counts as exposed even when a visitor must sign in; the sign-in method is shown as a detail beside it ("no sign-in", "AWS IAM sign-in", "sign-in not recorded"), never a reason to call the asset not exposed. `contract violations` is what surfaces that debt.
