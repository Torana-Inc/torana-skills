---
name: torana-alert-triage
description: >
  Triage and remediate vulnerability alerts assigned to the current developer.
  Reads the dev's assigned alerts from Torana via the `torana` CLI, opens the
  affected file, classifies the finding (true positive / false positive /
  accepted risk), and for true positives drafts a patch on a feature branch
  and opens a real GitHub PR. On PR merge the alert closes and the vulnerability
  transitions to `Fixed`. Trigger whenever the user mentions: triage an alert,
  triage my alerts, work on assigned alerts, fix a vulnerability, fix this
  vuln, patch an alert, alert remediation, my queue, what alerts do I have,
  alerts assigned to me, or any phrasing about handling a security finding
  assigned to them.
metadata:
  version: "1.0"
  last_updated: "2026-05-25"
  platform_version_tested: "2026.1"
---

# Alert Triage — dev-facing vulnerability remediation

> Read an alert from Torana, classify the finding, propose a patch, open a PR.
> All Torana operations go through the `torana` CLI. GitHub operations go
> through `gh` (the GitHub CLI). The skill never makes raw HTTP calls.

---

## Dependencies and precedence

**`torana-skill` must be loaded alongside this skill.** `alert-triage` does
not perform CLI bootstrap or OAuth — it relies on `torana-skill` having
already:

- Installed the CLI wheel and set `$TORANA` and `$TORANA_VENV`
- Configured the platform base URL
- Established an authenticated OAuth session

**Soft check before proceeding:**

```bash
"$TORANA" --version 2>/dev/null || echo "ERROR: torana-skill not loaded — load it first"
"$TORANA" auth status 2>&1 | grep -q "Authenticated" || echo "ERROR: not authenticated — run torana-skill's auth login flow"
```

If either fails, stop and tell the user to load and authenticate
`torana-skill` first.

All CLI invocations in this skill use `"$TORANA"` (quoted) — never bare `torana`.

---

## What this skill does NOT do

- Does NOT scan code for vulnerabilities — that's `torana-scan`.
- Does NOT classify alerts on behalf of an autonomous triage agent — in M2
  the workspace triage agent does that classification *before* this skill
  runs. The skill defers to `triage_verdict='true_positive'` when set.
- Does NOT close the alert after PR merge — the **Torana GitHub App webhook**
  does that automatically (PR merged → alert `resolved`). The skill only creates
  the remediation + links the PR (Step 10); it MUST NOT manually close/resolve
  the alert when the App is installed (that races the webhook). A manual
  `set-state` is a fallback only when the App isn't installed (Step 11).
- Does NOT manage GitHub auth. `gh` must already be authenticated
  (`gh auth status` returns ok). If not, stop and tell the user to run
  `gh auth login`.

## What this skill MUST NOT edit during a triage run

A triage session reads alerts and edits the **target repo** (the one
holding the vulnerable code). It must NEVER edit:

1. **Itself** — `$SKILL_DIR/SKILL.md`, `$SKILL_DIR/recipes/*.md`, or any
   other file under `~/.claude/skills/torana-alert-triage/`. If a recipe
   appears wrong or the skill misbehaves, STOP and report — do not
   "fix-forward" in-line. Skill changes go through the normal edit cycle:
   `pantheon-cli/skills/torana-alert-triage/` → `dev-compose
   install-claude-code-skills torana-alert-triage` → fresh Claude session.

2. **The `torana` CLI source** — `pantheon-cli/torana_cli/*.py`,
   `pantheon-cli/scripts/*`. If a CLI command behaves wrong (wrong flag,
   405, unexpected response shape), report it; don't patch the CLI from
   inside the skill. CLI changes go through their own review cycle.

3. **The detection-framework backend** —
   `pantheon-detection-framework/**`. If an API endpoint returns wrong
   data, report it; don't patch the service from inside the skill.

4. **Other security tooling** — `pantheon-integration/**`,
   `pantheon-datalake/**`, etc.

5. **The plan doc** — `pantheon-cli/docs/VM_E2E_Implementation_Plan.md`
   and anything else under `pantheon-cli/docs/`. Even if the skill
   uncovers a design gap, planning documents are out of scope for a
   triage session.

The only directories the skill is allowed to write to during a triage run:

- The **target repository** itself (for the patch + git ops).
- `/tmp/` and similar ephemeral paths (for working files like
  `/tmp/alert.json`).
- The Torana platform via `torana` CLI mutations (alerts, vulnerabilities).
- GitHub via `gh` CLI (PR creation, comments).

If you find yourself wanting to edit anything outside the target repo or
the Torana platform, **stop and surface the problem** — the user will
decide whether to abort the session and fix the underlying issue out of
band.

---

## Inputs

| Input | Required | Default |
|---|---|---|
| `--alert <alert-id>` | no | If omitted, the skill lists the user's assigned untriaged alerts and lets them pick one |
| `repo_path` | no | current working directory; the skill confirms it matches the alert's `repositories.full_name` |

---

## Procedure

### Step 1 — Identify the developer

Your remediation queue is the set of alerts assigned to **you** — keyed by your
own identity, not a shared alias.

```bash
ME_EMAIL=$("$TORANA" auth me --format json --raw | jq -r .email)
QUEUE="$ME_EMAIL"
echo "Acting as: $ME_EMAIL"
```

If `$ME_EMAIL` is empty or `null`, auth state is broken — stop and ask the
user to re-run `torana auth login` from `torana-skill`.

> **This step used to derive a `dev@<domain>` queue alias** (`QUEUE="${ME_EMAIL/#*@/dev@}"`).
> That alias does not exist anywhere in the platform: `alerts.assigned_to` always
> stores a **user UUID** (escalation assigns the tenant admin's id —
> `alert_triage_service.py`; routing assigns `user_id` — `alert_routing_service.py`),
> and no code path ever writes a `dev@…` value. Listing by the alias therefore
> matched zero rows *always*, so a developer holding an escalated Critical was told
> "No alerts in your remediation queue" (CLI-18). Filtering by email now works —
> the backend resolves an email to its user UUID — so use the real identity.
> If a shared team queue is ever wanted, it needs a real backing user (or an
> explicit queue concept), not a string convention.

### Step 2 — Pick an alert

**If `--alert <id>` was passed:** use it directly, jump to Step 3.

**Otherwise — list alerts in the developer remediation queue:**

```bash
"$TORANA" alerts list \
    --assigned-to "$QUEUE" \
    --format json --raw \
  > /tmp/my-alerts.json

python3 -c "
import json, sys
items = json.load(open('/tmp/my-alerts.json'))
items = items if isinstance(items, list) else items.get('items', [])
# Filter to active states only
active = [a for a in items if a.get('status') in ('pending_remediation', 'escalated', 'triaging', 'awaiting_input')]
if not active:
    print('No alerts in your remediation queue.')
    sys.exit(0)
print(f'{len(active)} alert(s) in queue ({QUEUE!r}):')
print()
for i, a in enumerate(active, 1):
    print(f'  {i:>2}. {a[\"severity\"].upper():<8}  {a.get(\"name\", \"(no name)\")[:60]}')
    print(f'      id={a[\"id\"]}  status={a.get(\"status\")}  verdict={a.get(\"triage_verdict\")}  created={a.get(\"created_at\",\"\")[:19]}')
" QUEUE="$QUEUE"
```

Render the list to the user and ask:

> "Which alert do you want to triage? (1, 2, 3, … or the alert UUID)"

Resolve the user's pick to `$ALERT_ID` (a UUID).

### Step 3 — Fetch alert + extract finding details

```bash
"$TORANA" alert "$ALERT_ID" get --format json --raw > /tmp/alert.json
```

Read `/tmp/alert.json` and extract:

- `severity`, `status`, `triage_verdict` (may be null)
- `assigned_to` — this is a **user UUID**, not an email. Confirm it matches your
  own user id (`"$TORANA" auth me --format json --raw | jq -r .id`); if not, warn
  and stop. Do NOT compare it against `$QUEUE` — that compares a UUID to an email
  and never matches.

**Source-of-truth ordering.** The alert's `rule_run_results[0]` IS the
canonical finding payload — it's the row the detection rule fired against,
captured at fire-time. The matching `vulnerabilities` table row CAN drift
(or be a stale seeded record with different CWE/file values). **Always
read CWE, file, line, snippet from the alert's `rule_run_results`
first; treat the `vulnerability <id> get` row as enrichment only.**

```bash
# Resolve rule_run_results to its first row (it may be a JSON array, a JSON
# object with .data, or a JSON string that needs parsing once).
RRR=$(jq -r '.rule_run_results' /tmp/alert.json)

# Some rules store rule_run_results as a JSON string instead of an object —
# parse once if needed, then take the first row.
FINDING=$(echo "$RRR" | jq '
  if type=="string" then fromjson else . end
  | if type=="array" then .[0]
    elif (.data // null) | type == "array" then .data[0]
    else . end
')

VULN_ID=$(echo "$FINDING" | jq -r '.torana_vulnerability_id // empty')
CWE=$(echo "$FINDING" | jq -r '.cwe_id // .cwe // empty')
SEVERITY=$(echo "$FINDING" | jq -r '.severity // empty')
TITLE=$(echo "$FINDING" | jq -r '.vulnerability_name // .title // empty')
REPO_FULL_NAME=$(echo "$FINDING" | jq -r '.repository_name // .repo_full_name // empty')

# scan_output may itself be JSON-encoded string OR a nested object
SCAN_OUTPUT=$(echo "$FINDING" | jq '
  .scan_output
  | if type=="string" then fromjson else . end
')
FILE_PATH=$(echo "$SCAN_OUTPUT" | jq -r '
  .coordinates.file // (if type=="array" then .[0].coordinates.file else empty end)
')
LINE_NUM=$(echo "$SCAN_OUTPUT" | jq -r '
  .coordinates.line // (if type=="array" then .[0].coordinates.line else empty end)
')
SNIPPET=$(echo "$SCAN_OUTPUT" | jq -r '
  .coordinates.code_snippet // (if type=="array" then .[0].coordinates.code_snippet else empty end)
')

if [ -z "$CWE" ] || [ -z "$FILE_PATH" ]; then
  echo "ERROR: could not extract CWE/file from alert.rule_run_results[0]."
  echo "rule_run_results payload:"
  jq '.rule_run_results' /tmp/alert.json
  exit 1
fi
```

**Optional enrichment via `vulnerability <id> get`:** only call this if the
alert payload is missing fields you genuinely need that the vulnerability
record has (e.g. `is_false_positive` flag, prior `resolution_details`, the
linked repo's `criticality_level`). DO NOT use it to read CWE, file, line,
or snippet — those come from the alert.

```bash
if [ -n "$VULN_ID" ]; then
  "$TORANA" vulnerability "$VULN_ID" get --with-repo --format json --raw \
    > /tmp/vuln.json 2>/dev/null || echo "(vuln record not retrievable — proceeding with alert payload only)"

  # If the vuln row exists, prefer ITS repo info (more authoritative) but
  # ONLY fill in fields that were blank on the alert.
  if [ -f /tmp/vuln.json ] && [ -z "$REPO_FULL_NAME" ]; then
    REPO_FULL_NAME=$(jq -r '._repository.full_name // .repository_name // empty' /tmp/vuln.json)
  fi
fi
```

### Step 4 — Verify working directory

Confirm the user is sitting in the affected repo:

```bash
CURRENT_REPO=$(git remote get-url origin 2>/dev/null | sed -E 's#.*[:/]([^/]+/[^/.]+)(\.git)?$#\1#')
if [ "$CURRENT_REPO" != "$REPO_FULL_NAME" ]; then
  echo "WARNING: you are in '$CURRENT_REPO' but the alert is for '$REPO_FULL_NAME'."
  echo "Either cd into the right repo, or confirm you want to proceed anyway."
fi
```

If mismatched, leave a breadcrumb on the alert before stopping:

```bash
"$TORANA" alert "$ALERT_ID" comment \
    --comment "Triage paused — dev was in wrong repo ($CURRENT_REPO vs $REPO_FULL_NAME)."
```

### Step 5 — Transition to `triaging`

The alert lifecycle is unified (the old `alerts triage-status` verb was removed) —
set the status directly:

```bash
"$TORANA" alert "$ALERT_ID" status \
    --status triaging \
    --message "Picked up by $ME via alert-triage skill"
```

### Step 6 — Open the file, show the snippet

```bash
echo "Affected file: $FILE_PATH:$LINE_NUM"
echo "CWE: $CWE  Severity: $SEVERITY"
echo "Title: $TITLE"
echo
echo "Code snippet:"
echo "$SNIPPET"
echo
echo "Context (file content, ±5 lines around line $LINE_NUM):"
sed -n "$((LINE_NUM-5)),$((LINE_NUM+5))p" "$FILE_PATH"
```

Summarize the finding for the user in one paragraph — what the bug is, why
it matters, what the typical fix shape looks like.

### Step 7 — Local classification (M1 only)

> In M2 the workspace triage agent will classify this *before* the skill
> runs. The skill should read `triage_verdict` from `/tmp/alert.json`; if
> already set to `true_positive`, skip the prompt below and jump to Step 8.

Ask the user:

> "Classify this finding: (t)rue positive, (f)alse positive, or (a)ccepted risk?"

**False positive path:**

```bash
SUMMARY="Reviewed the code at $FILE_PATH:$LINE_NUM — finding is not exploitable in this context. Reason: <one sentence>"
"$TORANA" alert "$ALERT_ID" verdict \
    --triage-verdict false_positive \
    --triage-summary "$SUMMARY"
"$TORANA" alert "$ALERT_ID" status \
    --status closed \
    --resolution-reason false_positive \
    --message "Closed by alert-triage skill"
"$TORANA" vulnerability "$VULN_ID" update \
    --is-false-positive \
    --status "Won't Fix" \
    --resolution-details "FP triage by dev"
echo "Alert $ALERT_ID closed as false_positive. Done."
exit 0
```

**Accepted risk path:**

```bash
SUMMARY="Reviewing $FILE_PATH:$LINE_NUM — finding is real but accepted. Reason: <one sentence>"
"$TORANA" alert "$ALERT_ID" verdict \
    --triage-verdict benign \
    --triage-summary "$SUMMARY"
"$TORANA" alert "$ALERT_ID" status \
    --status closed \
    --resolution-reason accepted_risk \
    --message "Closed by alert-triage skill"
"$TORANA" vulnerability "$VULN_ID" update \
    --is-risk-accepted \
    --status "Risk Accepted" \
    --resolution-details "Risk accepted by dev"
echo "Alert $ALERT_ID closed as accepted_risk. Done."
exit 0
```

**True positive path:** set the verdict early so M2 doesn't double-classify,
then continue to Step 8:

```bash
"$TORANA" alert "$ALERT_ID" verdict \
    --triage-verdict true_positive \
    --triage-summary "Confirmed real $CWE at $FILE_PATH:$LINE_NUM. Patching now."
```

### Step 8 — Patch the code

Look up the matching CWE recipe:

```bash
RECIPE="$SKILL_DIR/recipes/$(echo "$CWE" | tr 'A-Z' 'a-z')-$(...).md"
```

The recipes shipped in v1 of this skill:

| CWE | File | Status in M1 |
|---|---|---|
| CWE-79 (XSS) | `recipes/cwe-79-xss.md` | ✅ end-to-end demo target |
| CWE-89 (SQLi) | `recipes/cwe-89-sqli.md` | ✅ end-to-end demo target |
| CWE-798 (hardcoded credentials) | `recipes/cwe-798-secret.md` | ✅ end-to-end demo target |

The two scan-only seeded CWEs (CWE-1104 vulnerable lodash, CWE-250 container
runs as root) deliberately do NOT have patch recipes in M1 — their
remediation shape (bump a `package.json` pin, edit a `Dockerfile` line) is
different from a SAST-style code fix and lands in a later phase.

If `$CWE` is one of the three above, read the recipe; otherwise generate a
patch from your general knowledge of the CWE class. **Always show the proposed
diff to the user before applying** — they own the merge, you own the proposal.

After the user accepts the diff, apply it. Run the project's tests:

```bash
# Auto-detect the test command. Order of preference:
if [ -f package.json ] && jq -e '.scripts.test' package.json >/dev/null; then
  npm test
elif [ -f Makefile ] && grep -qE "^test:" Makefile; then
  make test
elif [ -f pyproject.toml ] || [ -f setup.py ]; then
  pytest
else
  echo "No test command auto-detected. Skipping tests — please run manually."
fi
```

On test failure, attempt one retry (re-prompt the user with the test output
and refine the diff). On second failure, stop and ask the user how to
proceed — do not push a broken patch.

### Step 8b — Coverage-of-diff + differential test generation (T7)

A green suite is not enough — the *changed* code may have zero coverage, so the
vuln can silently return on the next refactor. Measure coverage **of the diff**,
and if the changed path is uncovered (or the finding is security-class), generate
a **differentially-validated** regression test.

**1. Run the suite WITH coverage** (per ecosystem), producing an artifact:

```bash
# Python
pytest --cov --cov-report=json     # → coverage.json
# Node
npx nyc --reporter=json npm test   # → coverage/coverage-final.json
# Go
go test -coverprofile=cov.out ./...
# none detected → TEST_STATUS=no-suite (skip generation)
```

**2. Intersect coverage with the diff** using the helper:

```bash
BASE_SHA=$(git merge-base main HEAD)   # the pre-fix commit (branch point)
python3 "$SKILL_DIR/references/coverage_of_diff.py" . "$BASE_SHA" <coverage-artifact>
# → {status: covered|uncovered|no-suite, uncovered_changed:[...]}  (exit 0/1/2)
```

- `covered` → `TEST_STATUS=covered`, done.
- `no-suite` → `TEST_STATUS=no-suite` (surface it; never claim covered).
- `uncovered` **OR the finding is security-class** → generate a test (step 3).

**3. Generate a differential regression test.** Use the matching recipe's
"Test generation" section (or, for a security finding with a T9 exploit case,
the **exploit-as-test file T9 emitted** — see §3.11.2). Then **validate it
differentially — it MUST fail on the pre-fix commit and pass on the working tree**
(a test that passes on both proves nothing and is REJECTED):

```bash
# pre-fix: isolated worktree (never touch the working tree) — T3 pattern
TMP=$(mktemp -d); git worktree add --detach "$TMP" "$BASE_SHA"
cp <generated-test> "$TMP/<test-path>"
( cd "$TMP" && <run-just-this-test> ); PRE=$?     # MUST be non-zero (FAIL)
git worktree remove --force "$TMP"; rm -rf "$TMP"
# post-fix: working tree
<run-just-this-test>; POST=$?                     # MUST be zero (PASS)

if [ "$PRE" -ne 0 ] && [ "$POST" -eq 0 ]; then
  git add <test-path>            # committed WITH the fix in Step 9
  TEST_STATUS=generated
else
  TEST_STATUS=uncovered          # do NOT commit a non-differential test
fi
```

Never commit a test that isn't differentially validated (a weak passing test is
worse than none). Record the evidence for Step 10b:

```bash
cat > /tmp/test_evidence.json <<JSON
{"generated_test":"<path>","differential":{"pre_fix":"fail","post_fix":"pass"},
 "coverage":{"status":"$COV_STATUS"},"suite_command":"<cmd>"}
JSON
```

### Step 9 — Commit, push, open PR

```bash
ALERT_SHORT=$(echo "$ALERT_ID" | head -c 8)
# Branch carries the FULL alert id under the `torana/alert-` prefix so the
# PR-merge webhook can correlate via the branch name (the `_ALERT_BRANCH`
# anchor in github_events.parse_alert_id), not only the PR-body trailer.
# Keeping both anchors aligned means correlation still holds if a squash/merge
# policy rewrites the PR body and drops the `Torana-Alert-Id:` trailer.
BRANCH="torana/alert-$ALERT_ID"

git checkout -b "$BRANCH"
git add -p   # let the dev approve the hunks
git commit -m "Fix $CWE at $FILE_PATH:$LINE_NUM (alert $ALERT_SHORT)

Triaged via alert-triage skill.
Alert: $ALERT_ID
Vulnerability: $VULN_ID
Recipe: $(basename "$RECIPE" .md)
"
git push -u origin "$BRANCH"

PR_BODY=$(cat <<EOF
## Vulnerability fix

- **CWE:** $CWE
- **Severity:** $SEVERITY
- **File:** \`$FILE_PATH:$LINE_NUM\`
- **Title:** $TITLE

## Triage context

- **Alert:** \`$ALERT_ID\`
- **Vulnerability:** \`$VULN_ID\`
- **Recipe applied:** $(basename "$RECIPE" .md)
- **Triaged by:** $ME

## Test plan

- [x] Project tests pass
- [ ] Reviewer confirms the patch addresses the root cause
- [ ] Reviewer confirms no regression in the affected handler

---

Torana-Alert-Id: $ALERT_ID

> Generated by the **alert-triage** Claude skill. When the Torana GitHub App is
> installed on this repo, the alert updates **automatically** as the PR moves
> (opened → `pending_remediation`, merged → `resolved`) — no manual close.
> The `Torana-Alert-Id` trailer above lets Torana correlate this PR even if the
> remediation link wasn't pre-recorded.
EOF
)

PR_URL=$(gh pr create \
    --title "Fix $CWE in $FILE_PATH (alert $ALERT_SHORT)" \
    --body "$PR_BODY" \
    --base main \
    | tail -1)
# PR number — needed so the webhook's (repo, pr_number) lookup finds this remediation.
PR_NUMBER=$(echo "$PR_URL" | grep -oE '[0-9]+$')

echo "PR opened: $PR_URL (#$PR_NUMBER)"
```

### Step 10 — Create the remediation (link the PR, follow its life)

Create a first-class **remediation** record. This links the PR to the alert,
flips the alert to `pending_remediation`, and is the entity the PR-lifecycle loop
advances. Capture its id for the merge step.

```bash
REMEDIATION_ID=$("$TORANA" remediations create \
    --alert-id "$ALERT_ID" \
    --pr-url "$PR_URL" \
    --pr-number "$PR_NUMBER" \
    --vulnerability-id "$VULN_ID" \
    --repo "$REPO_FULL_NAME" \
    --description "Fix $CWE in $FILE_PATH" \
    --format json --raw | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
echo "Remediation: $REMEDIATION_ID"
```

`--pr-number` + the canonical `--repo` (the alert's `repository_name`, e.g.
`github.com/org/repo`) are what let the **webhook** match its `(repo, pr_number)`
to *this* remediation — so a real PR event updates this row instead of creating a
duplicate. (`$REPO_FULL_NAME` comes from the alert's `repository_name`, which is
already the canonical key.)

```bash

# (optional, cross-service) reflect on the vulnerability row in the datalake:
"$TORANA" vulnerability "$VULN_ID" update \
    --status "In Progress" \
    --resolution-details "PR: $PR_URL"
```

### Step 10b — Record the test verdict on the Fix-Impact report (T7)

Populate the Fix-Impact report (T6) with the coverage/test-gen verdict from
Step 8b, so the reviewer and security owner see whether the fix is pinned:

```bash
"$TORANA" remediation "$REMEDIATION_ID" impact --compute \
    --test-status "$TEST_STATUS" \
    --test-evidence-file /tmp/test_evidence.json
# → fix_impact_reports.test_status / test_evidence; rendered in the FE
#   Validation panel's test row (T6). --compute also refreshes the blast radius.
```

`$TEST_STATUS` is `covered` / `generated` / `uncovered` / `no-suite` from Step 8b.

### Step 11 — Let the PR lifecycle close the alert (do NOT close it by hand)

**The skill's job ends at creating the remediation + opening the PR.** From here
the **Torana GitHub App webhook** drives the alert automatically as the PR moves:

| PR event | what Torana does | alert |
|---|---|---|
| PR opened | links the remediation | `pending_remediation` |
| CI / review | records activity | (stays) |
| **PR merged** | remediation → merged | **`resolved`** |
| deployed to prod | remediation → deployed_prod | `closed` (`resolution_reason=fixed`) |

So **do not run `alerts status --status closed` or `remediation set-state` after a
merge** — that would race/duplicate the webhook, which is now the source of truth.
Just tell the dev the alert will close itself when the PR merges, and stop.

**Fallback — only if the GitHub App is NOT installed on this repo** (no webhook):
then, and only then, advance it manually after the user confirms the merge:
```bash
# FALLBACK (no App/webhook): manual transition
"$TORANA" remediation "$REMEDIATION_ID" set-state --state merged \
    --message "PR $PR_URL merged (manual — App not installed)"   # → alert resolved
```
If unsure whether the App is installed, prefer doing nothing — the webhook is
idempotent and will reconcile. (The vulnerability's datalake `Fixed` status is a
separate cross-service step, not done here.)

Do NOT advance state speculatively — only after the user confirms the merge /
deploy. (The state machine + alert mapping live server-side in the `remediation`
entity, so the skill just reports the milestone.)

---

## Error handling

| Symptom | Cause | Fix |
|---|---|---|
| `auth me` returns null `.id` | Token expired | Defer to `torana-skill` — re-run `auth login --web --no-browser` |
| `alerts list` returns empty | No alerts assigned, or token has wrong tenant | Confirm `$ME` matches the assignee on the alert via Torana UI |
| `alert <id> status` rejects a value | The unified `AlertStatus` enum is `open/triaging/awaiting_input/pending_remediation/escalated/resolved/closed` — use those, not the old triage-status values | — |
| `remediations create` 404s the alert | Wrong tenant, or `$ALERT_ID` not in this tenant | `torana auth me` — confirm the tenant matches the alert |
| `vulnerability <id> get` returns "no rows" | The `torana_vulnerability_id` in `rule_run_results` is stale | Inspect `/tmp/alert.json`'s `rule_run_results` shape; the path may be different for newer rules |
| `gh pr create` returns "auth required" | GH CLI not authenticated | Tell the user to run `gh auth login` (out of band) |
| Tests fail after patch applied | Patch is wrong | Re-read the recipe; iterate with the dev; do not push |

---

## Required OAuth scopes

The token must include:

| For | Scope |
|---|---|
| `alert <id> status/verdict/comment`, `alerts list/get` | `alert:*` |
| `remediations create` / `remediation <id> set-state` | `alert:*` (P0 reuses alert perms) |
| `vulnerability <id> get/update` | `datalake:*` (read) + `integrations:*` (update endpoint) |
| `auth me` | always available — no extra scope |

If a CLI call returns 403, re-auth via `torana-skill` and tick the needed
scope on the consent screen.

---

## Files in this skill bundle

| File | Purpose |
|---|---|
| `SKILL.md` | This file |
| `recipes/cwe-79-xss.md` | Reflected/stored XSS remediation patterns |
| `recipes/cwe-89-sqli.md` | Parameterized query patterns |
| `recipes/cwe-798-secret.md` | Hardcoded credentials → env vars |
| `wheels/torana_cli-*.whl` | Bundled CLI (added at build time by `make claude-skills`; shared with all skills) |

---

## Changelog

- **v1.0 (2026-05-25)** — Initial release. Drives the M1 dev-facing
  triage loop: list assigned alerts → fetch alert + vulnerability →
  classify → patch (3 CWE recipes covering all SAST-shaped seeded vulns in
  `vm-test-repos/juice-shop-extensions`) → PR → update alert. PR-merge
  close is manual pending the webhook.
