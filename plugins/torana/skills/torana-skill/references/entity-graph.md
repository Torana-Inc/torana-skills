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
pkg:pypi/litellm@1.74.15.post2                  an SBOM package (a leaf)
image:us-west1-docker.pkg.dev/.../svc@sha256:…  a built container image
service:prod/pantheon-agent-builder             a running service (env IS in the key)
cloud:gcp/resource/136.66.136.36                a public cloud endpoint
repo:github.com/acme/billing-api                a source repo
```

⚠️ **Different namespaces do not join.** A vulnerability keyed `image:` and an asset keyed
`cloud:` describe different things; joining them yields zero rows and *looks* like "no
exposure". A zero-row join is a finding about the keys, not about the risk.

## Commands

```bash
"$TORANA" entity-graph --help                    # richest examples in the CLI — read it
"$TORANA" entity-graph neighbors <NODE_KEY> --direction both
"$TORANA" entity-graph nodes --help
"$TORANA" entity-graph edges --help
"$TORANA" entity-graph contract show             # which edges each (category, table) OWES
"$TORANA" entity-graph contract violations       # the outstanding debt
```

## Traps

⚠️ **Graph data is per-TENANT.** An empty result may mean you are on the wrong tenant, not
that the relationship is absent. Check with `TORANA_PROFILE`, or `--tenant-id` as SA.

⚠️ **A row with no edge is ABSENT, not reported.** The graph has no node table, so an
unconnected asset does not show up as "unconnected" — it does not show up at all. Exposure is
computed *from* the graph, so the platform can answer "not exposed" with total confidence
about an asset it has never seen. `contract violations` is what surfaces that debt.
