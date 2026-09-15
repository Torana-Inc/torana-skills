# torana CLI — impact & reachability command reference

All commands come from `torana-skill` (the `$TORANA` CLI). This skill adds no commands; it
orchestrates these. `--json` on every read for machine-parseable output.

## Load the finding
```bash
"$TORANA" vulnerability <VULN_ID> get --json          # repo, cwe_id, package?, source_file_path?, severity
```

## Reachability (entity graph)
```bash
# repo/pkg → running services (does it run, and where):
"$TORANA" entity-graph reachable <FROM_KEY> --via <edges> [--direction forward|reverse|both] --json

#   FROM_KEY forms:  repo:github.com/org/name   |   pkg:pypi/<name>@<ver>   |   image:...   |   service:<env>/<name>
#   --via entries may carry a per-edge direction:  edge:forward | edge:reverse
#     SAST:  --via builds_image,deployed_as,exposed_via --direction forward
#     CVE :  --via contains:reverse,deployed_as:forward,exposed_via:forward     ← mixed, do NOT use plain --direction reverse

"$TORANA" entity-graph neighbors <KEY> --type <edge_type> --direction forward|reverse|both --json
"$TORANA" entity-graph overlay --node-kind service --json          # per-node risk overlay rollup
"$TORANA" deployments exposure-intelligence --json                 # ranked "which few matter" (needs onboarded tenant)
"$TORANA" govern show "service:<env>/<name>"                       # governance (criticality/owner/data)
```

## Governance / attribute reads (datalake)
```bash
"$TORANA" datalake query --sql "SELECT torana_entity_id, public_access, criticality_name, has_customer_data FROM assets WHERE torana_entity_id IN ('service:...') AND is_deleted IS NOT TRUE"
"$TORANA" datalake query --sql "SELECT datastore_id, engine, data_classification FROM datastores WHERE is_deleted IS NOT TRUE"
```

## Fix-impact (blast radius)
```bash
# package fix → lead with affected.service / affected_counts:
"$TORANA" fix-impact analyze --changed-pkgs "pkg:<type>/<name>@<ver>" --direction both --json
# repo/SAST fix → deployment chain:
"$TORANA" fix-impact analyze --repo "repo:<repo>" --direction both --json
# PR/branch → derive changed pkgs from a local checkout diff:
"$TORANA" fix-impact analyze --repo "repo:<repo>" --base-sha <B> --head-sha <H> --repo-path <DIR> --direction both --json
#   returns: { downstream[], upstream[], owners[], truncated, truncated_reason, affected{service,image,cloud,host,datastore}, affected_counts }
```

## Record (HITL only)

**First find the remediation id — do NOT ask the human for it.** The collection lives on the **plural**
group (`remediations`); the singular `remediation <ID>` group is instance-only, so `remediation list` does
not exist and its absence is **not** evidence that you can't look one up:
```bash
"$TORANA" remediations list --vulnerability-id <FINDING_ID> --json   # ← the usual path from a finding
"$TORANA" remediations list --alert-id <ALERT_ID> --json
"$TORANA" remediations list --repo "repo:<repo>" --pr-number <N> --json
"$TORANA" remediations list --json                                   # all (empty [] ⇒ none exist yet)
```
An empty `[]` means **no remediation exists yet** — report the analysis and stop; it does not mean the
lookup is unsupported.

```bash
"$TORANA" remediation <REMEDIATION_ID> impact --compute --json     # persist the report → fix-impact-panel
```

> **General rule for this CLI:** collections are plural (`remediations list`), instance verbs are singular
> (`remediation <ID> get`). If a `<noun> list` fails, try `<noun>s list` before concluding the capability
> is missing.

## Re-sync a cluster (if reachability/governance data looks stale)
```bash
"$TORANA" deployments list                                          # find the deployment id
"$TORANA" deployments sync <DEPLOYMENT_ID>                          # re-run workloads/services/datastores → refresh nodes+governance
```

## FE deep-links (point the human here)
- Reachability graph: `<base>/entity-graph`  (lenses, direction toggle, blast-radius drill)
- Recorded fix-impact: the alert's detail page → **fix-impact-panel**
- Deployments/governance: `<base>/deployments`
