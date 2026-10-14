# Asset-graph edges

This skill also emits **entity-graph edges** — typed, directional relationships
between entity-graph nodes — alongside the asset-inventory record. The edge
producer is the DECLARED side of the asset graph.

> This page pins the wire format and the push command. Edges are authored by hand or by your own tooling;
> nothing derives them from `pom.xml` / `package.json` / `Dockerfile` / CI configs / Terraform yet.

## Wire format — `entity_edges.v1`

```json
{
  "schema_version": "entity_edges.v1",
  "source": "entity-graph-skill",
  "edges": [
    {
      "from": "repo:github.com/acme/billing-api",
      "to": "gav:com.acme:billing:1.4.2",
      "type": "builds",
      "evidence": { "file": "pom.xml", "field": "artifactId" },
      "confidence": "high"
    },
    {
      "from": "gav:com.acme:billing:1.4.2",
      "to": "image:registry/billing@sha256:ab…",
      "type": "packaged_in",
      "evidence": { "file": "Dockerfile" },
      "confidence": "medium"
    }
  ]
}
```

### The eight polymorphic key schemes

`repo:<host/org/repo>` · `cloud:<provider>/<type>/<id>` · `service:<env>/<name>` ·
`host:<provider>/<id>` · `image:<registry/repo@sha256:digest>` ·
`gav:<group:artifact:version>` · `pkg:<purl>` · `team:<org/name>`

### Legal edge types and endpoints

| `type` | from → to |
|---|---|
| `builds` | `repo:` → `gav:` |
| `packaged_in` | `gav:` → `image:` |
| `contains` | `image:` → `pkg:` |
| `deployed_as` | `image:` → `service:` |
| `declares` | `repo:` → `cloud:` |
| `exposed_via` | `service:` → `cloud:` |
| `runs_on` | `service:` → `host:` |
| `owns` | any → `team:` |

A type-incorrect edge is rejected server-side (routed to the DLQ) without
failing the rest of the batch — but author them correctly.

### Confidence

`authoritative` > `high` > `medium` > `low`. The server keeps the **max**
confidence ever asserted for an edge (a later low-confidence re-derivation never
downgrades an authoritative one), and **accumulates** evidence per `source`.

## Push command

```bash
torana ingest entity-edges ./entity-edges.json
```

Re-running is safe: the edge id is deterministic (`sha256(tenant:from:to:type)`),
so re-pushes are idempotent and re-observed edges are un-tombstoned.
