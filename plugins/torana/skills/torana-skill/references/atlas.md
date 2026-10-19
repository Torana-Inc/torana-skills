---
name: atlas
description: >
  Read and operate Atlas, the tenant knowledge tree: one generated skill per node
  (`code/<org>/<repo>`, `runtime/…`, `identity/…`), versioned and rebuilt when its inputs move. Use it to
  browse the tree, read a node's files and history, diff versions, export a node or the tenant, assemble
  the context bundle for a subject, QUERY the knowledge (`context`, `skill`, `facts`, `map`: free, no model),
  ASK a question and read the answer with its proof (`ask`, paid), open the anchor behind a statement,
  read the one-line summary and failure causes, choose which subjects
  get a skill (the selection; nothing is written unless selected), rebuild/suppress/restore a node,
  and manage exclusions.
version: "1.2"
last_updated: "2026-10-16"
---

# Atlas — Torana Platform (CLI)

Atlas keeps one skill per node of the tenant's knowledge tree. Each node has a **path** (slashes included,
e.g. `code/acme/api`), a **template** (`repository`, `category`, …), a **tier** (`hot` / `warm` / `cold`:
how often it is refreshed), a **state** (`active`, `orphaned`, `suppressed`, `degraded`, `quarantined`, …)
and numbered **versions**. A node is **due** when an input moved; `due_reason` says which.

⛔ **Nothing is written unless it is selected.** Every synced repository is listed as a node for free, but a
skill is built only for a **selected** subject (`atlas selection add`). An unselected node is never due and
never built; `node <PATH> rebuild` and `jobs build` on it answer 409 `not_selected`. Root and category nodes
have no subject: they are never selected and are rendered from their children.

## Bootstrap

⛔ Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap. Every command below assumes `"$TORANA"`.

## Who may run what

| Permission | Who has it | Commands |
|---|---|---|
| `atlas:read` | every tenant user | `summary`, `tree`, `nodes list`, `node <PATH> get\|log\|show\|diff\|export\|snapshots\|snapshot`, `selection list`, `runs list\|causes`, `run <ID> get`, `producers list`, `exclusions list`, `ownership-ladder show`, `context [KEY…]`, `context get`, `skill`, `facts`, `map`, `answer <ID> get\|bundle`, `node <PATH> anchors\|anchor`, `reachability`, `code <PATH> overview\|entries\|libraries\|place\|flow\|path\|search`, `assemble`, `export`, `metrics`, `kinds list\|show`, `profiles list\|show\|assignments list\|effective\|drift\|spend` |
| `atlas:ask` | whoever the tenant grants it (PAID) | `ask`, `answer <ID> cancel` |
| `atlas:admin` | an Atlas administrator (not every tenant user) | `selection add\|remove`, `node <PATH> rebuild\|suppress\|restore`, `exclusions add`, `exclusion <ID> delete`, `plan` |

Atlas does nothing for a tenant until it is **enrolled** (the opt-in); an empty tree on a tenant usually means it is not.

## Start here: the summary

```bash
"$TORANA" atlas summary                                # Code facts: N of M indexed · Skills: written, waiting for the model; then one sentence + key/value
```

The server computes every count (`written` = selected with a version; `not_written` = selected, no version yet;
`failing` = selected whose last run failed). Never recompute them from `nodes list`. "builders paused" means
no background builder is configured: selected skills are written only by "write now" (`node <PATH> rebuild`).
"build cost" reads "a build costs about $0.63, at most $2.00" (typical cost from history, and the per-build cap)
or "no cost history yet". "waiting for the model" = selected skills Atlas cannot write here yet (the model is not
available, or refused this environment's credential); their code facts are still indexed. Human views print times as `14 Oct 11:43 UTC`; `--json` keeps the raw ISO values.

## Choose what gets a skill: the selection

```bash
"$TORANA" atlas selection list                         # first line: N selected · N available · N never include; FAILING column
"$TORANA" atlas selection list --available --q payments   # --selected | --available; --q matches path or subject
"$TORANA" atlas selection list --available --tier hot  # --tier hot|warm|cold = priority High|Normal|Low
"$TORANA" atlas selection add code/acme/api repo:github.com/acme/web   # node paths or subjects, any mix
"$TORANA" atlas selection remove code/acme/legacy      # no longer built; written versions stay readable
```

- `add` makes each subject due like a first build; the background builders write it when workers > 0, or
  write one now with `"$TORANA" atlas node <PATH> rebuild`.
- More than 100 subjects are sent in batches of 100. A path is resolved to its subject first; a category path
  (`code`) is refused, since it has no subject.
- Per-subject refusals come back in `refused`: `excluded` (on the never-include list, `atlas exclusions list`;
  delete the exclusion first) or `unknown_subject`. Any refusal makes the command exit 1; the rest are still applied.
- `--json` prints `{changed, unchanged, refused}` merged across batches.
- `failing` (on `selection list` rows and `node get`) uses the summary's rule: selected, and the latest run since
  it was selected failed. `node get` prints that run's error as `last run error`; group failures with `runs causes`.

## Who owns a repository: the ownership ladder

A repository skill's "who owns it" comes from an ordered list of rungs; the first rung that finds an owner
answers, and the skill names the rung. Default: `codeowners` (CODEOWNERS, known) → `recorded_owner` (the
repository's recorded owner email, known) → `team_access` (teams with push access or stronger, plus `owns`
edges; believed) → `organization` (the owning organisation; shown, but the question counts as unanswered).

```bash
"$TORANA" atlas ownership-ladder show                       # effective rungs in words; "platform default" or "set for this tenant"
```

- A change moves the `ownership_ladder` input's watermark: the tenant's selected repository skills become due
  (`due_reason` `watermark:ownership_ladder`) and are rewritten when builders run or on `node <PATH> rebuild`.

## Read the tree

```bash
"$TORANA" atlas tree                                   # ASCII tree, labels in words: [hot] state:suppressed due:watermark v4
"$TORANA" atlas tree --depth 2 --tier hot
"$TORANA" atlas nodes list --due                       # flat list of nodes due for a build
"$TORANA" atlas nodes list --template repository --json
```

## One node

```bash
"$TORANA" atlas node code/acme/api get                 # Code facts: + Skill: lines, then skill name, index card, selected, failing, last run error, state, inputs (moved), version
"$TORANA" atlas node code/acme/api log                 # versions, newest first (+ PROFILE)
"$TORANA" atlas node code/acme/api show                # the node's files now (its current version)
"$TORANA" atlas node code/acme/api show --version 3 --file SKILL.md   # one file's body (raw on stdout)
"$TORANA" atlas node code/acme/api diff --from 3 --to 4 [--file SKILL.md]
"$TORANA" atlas node code/acme/api export --out ./api-skill [--version 3]
"$TORANA" atlas node code/acme/api snapshots           # code snapshots, newest first: SEQ · COMMIT · INDEXED · ORIGIN · STATE (words)
"$TORANA" atlas node code/acme/api snapshot [3]        # one snapshot (default: the latest) and its files
"$TORANA" atlas node code/acme/api show --snapshot 3 --file facts/build.json   # one file of a code snapshot
"$TORANA" atlas node code/acme/api anchors --snapshot 3                        # a snapshot's anchors (anchor ID --snapshot 3 for one)
```

**Two things per node: code facts and the skill.** Atlas keeps them apart. The **code snapshot** (facts, extractor
anchors, code index, call graph at one commit) is computed from code and data alone: free, no model, refreshed whenever
the code or data moves. The **skill** (SKILL.md and its prose, a version) is written from a snapshot by the model, and
only when it is available and allowed. `node <PATH> get` prints both, in the server's words, glyph beside the words:

```
Code facts: ✓ commit abc1234, indexed 19 Oct 06:10 UTC (snapshot 3)
Skill: ○ Not written yet: the model is not available in this environment
```

So a node can have code facts and no skill. The code walker, reachability, `show --file index/… --header` and `facts`
read the latest code snapshot, so they answer even when no skill is written. `context`, `skill` and `ask` read the
written skill only. A snapshot is cited `atlas:<path>@s<seq>#…`; a version is still `atlas:<path>@<n>#…`, and both resolve.

The root and category nodes (`code`, …) are **rendered from their children when read**: they have no
versions, are never due and cannot be rebuilt (409 `rendered_at_read_time`). Read them with `show` (no
`--version`), `show --file facts/children.yaml` or `export`; `tree` labels them "rendered from children".

⚠️ File output is `--out`, never `-o`: `-o` is the global `--format` flag anywhere on the line.

**Consent withdrawn.** A version built from a source whose consent was withdrawn has two states:
- **`⊘ Hidden: consent withdrawn; deleted by <time>`.** Its row stays in `log`, but its content is a 404 `consent_missing`.
  Granting the source again before that time restores it.
- **`✕ Deleted: consent withdrawn, <time>`.** Its files are gone for good (404 `consent_purged`), and only a rebuild
  replaces it.

Per source, `"$TORANA" atlas consent purges` lists when consent was withdrawn, the deletion deadline, how many versions
and code snapshots wait (WAITING, PENDING SNAPSHOTS) and how many were deleted (DELETED, DELETED SNAPSHOTS). A code
snapshot is hidden and deleted the same way as a version. Consent itself is granted and revoked with `torana integrations knowledge-consent`.


## Runs and producers

```bash
"$TORANA" atlas runs list --since 24h --status failed  # --since: 30m / 24h / 7d or an ISO time
"$TORANA" atlas runs list --node code/acme/api
"$TORANA" atlas runs list --status indexed [--stage index|write|all]   # STAGE + OUTCOME columns, outcome in words
"$TORANA" atlas run <RUN_ID> get                       # phase, status, error, trace id, version produced, stage, outcome_words
"$TORANA" atlas runs causes [--since 30d] [--node code/acme/api]   # failed runs grouped by cause, with an example run
"$TORANA" atlas producers list                         # runs, failure rate and cost over 30 days
```

A run has two stages: **index** (the code snapshot, free) always first, then **write** (the skill) when one is needed,
allowed and possible. Status `indexed` = the code facts were stored and no skill was written (OUTCOME says why, e.g.
"indexed; skill waiting for the model"). That is not a failure: the skill waits, and the code facts are current.

## Query the knowledge (free) and ask a question (paid)

Two ways in, over the same knowledge. **`context` and the pulls are deterministic: no model, no cost, fast. YOU do the
inferring.** **`ask` runs one bounded model session and costs money**: use `context` first, and `ask` only when the
question needs inference. If an answer looks wrong, run `context` with the same keys: if the facts are right, synthesis
failed; if they are missing, retrieval did.

Keys are entity keys `<type>:<rest>`: `repo:github.com/acme/api`, `image:…`, `pkg:pypi/litellm`.
No keys = the tenant overview. A node's subject (`atlas nodes list --json`) is its repo key.

```bash
"$TORANA" atlas context repo:github.com/acme/api --statements                # which skills, why, how certain, what is missing
"$TORANA" atlas context repo:github.com/acme/api --question "which base image?" --delivery hybrid   # + what to pull next
"$TORANA" atlas context --question "what runs in payments?" --explain        # no keys: the overview, reasons shown
"$TORANA" atlas context get <REQUEST_ID> [--out bundle.tar]                  # the stored response, exactly as served
"$TORANA" atlas skill atlas-code-acme-api [--file facts/usage.json] [--version 3] [--term package:litellm]
"$TORANA" atlas facts repo:github.com/acme/api --term litellm [--file facts/usage.json]   # --term REQUIRED; records + the anchors they cite; from the code snapshot
"$TORANA" atlas facts repo:github.com/acme/api --term litellm --from skill   # the records exactly as the written skill cites them
"$TORANA" atlas map dependencies --filter litellm [--limit 50]               # rows mentioning TEXT
"$TORANA" atlas map deployment --limit 500                                   # no --filter: the whole map (up to --limit, max 500; `total` says if more); cells are never truncated
"$TORANA" atlas map ingress --filter service:payments/checkout              # which external paths reach a service, per rung, and whether the edge asks for a token
"$TORANA" atlas node code/acme/api show --file facts/usage.json --term litellm   # a fact file, sliced (current version)
```

`skill NAME` takes the **skill name** (`node <PATH> get` prints it, and the `pull` block of a `--delivery hybrid` context
lists the names). `--term` is `field:value`; a bare value is expanded to the fields that file slices on. A slice says
`kept K of N` and whether it is `complete`. `map ingress` rows are tagged: `✓` a Kubernetes Ingress routes to it, `?` a repository DECLARES an nginx route for an environment (not checked against what is live, cluster not matched), `○` nothing readable; `🛡? IP list (unverified)` is never public. A name no row mentions returns one `○` row, not an empty list. `skill` prints the file on stdout and the version/slice on stderr.

```bash
"$TORANA" atlas ask "Which base image does acme/api build FROM?" --wait
"$TORANA" atlas ask "Who owns payments?" --key repo:github.com/acme/payments --max-budget 0.5 --wait --json
"$TORANA" atlas ask "Is this reachable?" --fact "detection=alert 41 fired on checkout" --wait   # YOUR fact, marked caller-supplied
"$TORANA" atlas answer <REQUEST_ID> get [--wait]      # poll a running ask; exit 8 if it failed or was cancelled
"$TORANA" atlas answer <REQUEST_ID> cancel            # kills the session; cost is on the answer
"$TORANA" atlas answer <REQUEST_ID> bundle --out given.tar   # the knowledge the session was given
```

`ask` answers at once with a request id (`status running`); `--wait` follows it (status on stderr, the answer on stdout; exit 0
complete, 8 failed/cancelled/timed out). Cost is on the answer (`COST $0.31`) and capped per ask (`--max-budget`, default $0.75).

### Is it used? (reachability, free, no model)

Asks the repository's stored **code index**, not a model: does the repository import a package, or does an entry point
(route, CLI command, task, `main`) reach a function? One question per call, or many with `--questions-file`.

```bash
"$TORANA" atlas reachability --repository repo:github.com/acme/api --package litellm --ecosystem pypi
"$TORANA" atlas reachability --repository repo:github.com/acme/api --file src/api.py --function handler
"$TORANA" atlas reachability --repository repo:github.com/acme/api --package requests --ecosystem pypi --commit 1a2b3c4   # the commit a finding was scanned at
"$TORANA" atlas node code/acme/api show --file index/imports.json --header     # what the index covers: files, languages, counts
```

Every question gets one of three states, each with its word beside the mark:
- `✓ measured`: answered at the commit Atlas built (or the one you named, when it is the same commit). The verdict is
  `reachable`, `imported_transitively`, `build_only`, `not_imported`, `inconclusive` …, with a certainty: `known` only when
  every condition is met, else `believed`.
- `✓ measured_at_other_commit`: Atlas built another commit, and no file this answer rests on changed between the two.
- `○ not_known` with a reason: `not_selected`, `not_built_yet`, `building`, `not_enrolled`, `index_missing` (built before
  the code index existed; the next build adds it), `changed_since_built`, `commit_unknown_to_atlas`, `language_unsupported`,
  `parser_missing`, `ambiguous_commit`. A `not_known` is an answer, not an error: never turn it into "not used".

An absence over part of what ships is not an absence: an answer that could not read every component says `inconclusive`
and names what was missing. Each answer lists its evidence as anchors (`…#ix:imports:<f>:<line>`); open one as below.
The tenant-wide `export` leaves code indexes out; `node <PATH> export` includes them.

### Walk a service's code (free, no model)

`atlas code <PATH>` walks one repository node's stored code index: its doors (API routes, CLI commands, scripts,
background tasks), its folders, files and functions with their callers and callees, and the libraries it imports.
Needs `atlas:read`. It reads the node's latest **code snapshot** (header `◉ <path> · snapshot 3 · commit abc1234`, then
the `Skill:` line), so it works before any skill is written; `--snapshot K` reads an older snapshot ("older snapshot"),
`--version N` the snapshot a written version came from; `--json` prints the API body.

```bash
"$TORANA" atlas code code/acme/api overview                                   # counts + "Data quality, in words"
"$TORANA" atlas code code/acme/api entries --kind route                       # METHOD PATH · FUNCTION · FILE:LINE
"$TORANA" atlas code code/acme/api libraries --declared-never-imported        # name · kind · version · imported in N files · mapping
"$TORANA" atlas code code/acme/api place --kind folder                        # the service root (no --id)
"$TORANA" atlas code code/acme/api place --kind function --id 'src/llm.py::complete'
"$TORANA" atlas code code/acme/api flow --function 'src/api/chat.py::chat'    # what it calls, 3 levels; libraries at the ends
"$TORANA" atlas code code/acme/api path --function 'src/llm.py::complete'     # one chain from an entry point
"$TORANA" atlas code code/acme/api search litellm                             # each result prints the command that opens it
```

Ids: a function is `<file>::<qualname>`; a route is `<function id>@<decorator line>` (one function can carry several
routes); a library is its normalised name. Repeat the words exactly as printed; they are claims with limits:
- `?~ possible`: the call may go to several functions of that name, its only target is a test file, or what the call is made on is unknown (a literal, an indexed item, another call's result, or a list/dict/set/str method on a plain value), so it matches by name only. Never "calls".
- `entry (by name only)`: an entry point found only because a `__main__` block elsewhere calls that name (older index).
- `file level`: a library imported by the function's FILE, not proven called by that function.
- `Library calls per function: not recorded yet`: an index built before format 2; the next build adds them.
- `imported in N files`: what the code IMPORTS. Never say a library is or is not "used"; "declared, no import found"
  is a count with its mapping basis beside it (`guessed from the package name` can be wrong).
- `the full URL may be longer`: one router mount level is followed; `where this router is mounted is not known` otherwise.

### Reading the proof of a statement

Every statement has a **certainty, written as a word beside its mark**: `✓ evidenced` (an anchor proves it),
`? believed` (inferred; say so when you repeat it), `○ not_known` (the knowledge does not have it: an `open question`
file names what would close it). Never repeat a `believed` or `not_known` statement as fact. A statement resting only on a
fact you supplied says `basis: caller-supplied`: it was never evidenced.

Each anchor line ends with the command that opens it. To check a claim:

```bash
"$TORANA" atlas node code/acme/api anchor a:17 --version 3     # kind, file:line, the quote, source: <github link>, first cited in vN
"$TORANA" atlas node code/acme/api anchors --version 3 --all   # every anchor of the version
"$TORANA" atlas node code/acme/api anchor 'atlas:code/acme/api@3#ix:imports:4:12'   # a code-index anchor: the import line, the quote, the commit
```

A code-index quote that reads `[withheld]` (a secret scanner flagged it) or `[cut]` (too long to store whole) is shown as
that marker, never the text; open the source link to read the line.

A ref like `atlas:code/acme/api@3#a:17` is `node code/acme/api`, `--version 3`, id `a:17`. `UNRESOLVED` on a proof line
means the cited anchor id is not in that version: treat the statement as unproven. A statement with no anchor is `believed`
or `not_known`, never `evidenced`. A `gap` says what is missing and what would unlock it (`select code/acme/api`).

## Context for a subject (older form)

`context` replaces `assemble` (kept one more release). Use `context` for new work.

```bash
"$TORANA" atlas assemble --subject repo:github.com/acme/api --explain     # which nodes, which portion, why
"$TORANA" atlas assemble --subject tenant --budget 40000 --out bundle.tar  # also download the tarball
"$TORANA" atlas export --out ./atlas-export                               # whole tenant, current versions
"$TORANA" atlas export --path code/acme/api --out ./api-skills           # one node and everything under it
"$TORANA" atlas metrics --since 7d
```

Subjects: `tenant`, `repo:<key>`, `alert:<id>`. `--goal build` assembles for a build session instead of an answer.

## Change a node (atlas:admin)

```bash
"$TORANA" atlas node code/acme/api rebuild [--full]    # queues a run; prints its id
"$TORANA" atlas node code/acme/legacy suppress --reason "archived repository"   # also writes an exclusion
"$TORANA" atlas node code/acme/legacy restore
"$TORANA" atlas exclusions list
"$TORANA" atlas exclusions add --template repository --subject 'repo:github.com/acme/legacy-%' --reason archived [--until 2027-01-01T00:00:00Z]
"$TORANA" atlas exclusion <EXCLUSION_ID> delete --yes
"$TORANA" atlas plan [--template repository]           # dry run: nodes to create/orphan, projected cost; writes nothing
"$TORANA" atlas plan --bump-kind repository            # dry run: what bumping a kind's version would rebuild, and the cost
```

A rebuild of a node that is not selected answers 409 `not_selected` (select it first). A rebuild of a node
already being built answers 409 `lease_held`; a build refused by the tenant's daily
budget answers 429 `tenant_budget_exhausted`. Both are "try later", not a broken node.

`node <PATH> rebuild` answers at once with a `run_id`. `--wait` follows that run: phase changes on stderr, the final
run on stdout; exit 0 when it succeeded or was unchanged, 8 when it failed, was quarantined, or `--timeout` (default
1800 s) passed. Ctrl-C stops the watching, not the run. A rebuild also returns a node the retry rule left `degraded`
to `active`, so fix the cause of its failures first.

## Builder profiles, policy and kinds

A **profile** is the named recipe (model, bounds, prompt, cost cap) a node build or an answer runs with. A
profile is **assigned** to a (template, tier) at platform or tenant scope; `effective` shows which one a build
would use and which rung of the ladder chose it. A **policy** key is a platform limit or switch (budgets,
allowed models, bounds). Reads are for every tenant user (a tenant sees figures for its own runs, never the
platform's spec); profiles, assignments and policy are set by Torana, not by the tenant.

```bash
"$TORANA" atlas kinds list                               # the node templates: shape, version, phase, enabled, node count
"$TORANA" atlas kinds show repository                    # path rule, sections, card fields, limits
"$TORANA" atlas profiles list [--use build|answer]       # 30-day runs, cost, golden rate, assignment count
"$TORANA" atlas profiles show platform-default           # description, revision, where it is assigned
"$TORANA" atlas profiles assignments list                # platform rows, tenant rows, and the resolved template x tier grid
"$TORANA" atlas profiles effective --node code/acme/api  # or: --template repository --tier warm   (--use answer for chat)
"$TORANA" atlas profiles drift [--reason rules|profile|tier|before_profiles]   # nodes last built with another profile than now
"$TORANA" atlas profiles spend                           # per-profile cost of this tenant's runs
```


## Failures

- 404 on every `atlas` command: Atlas is not available on this deployment. Ask your Torana administrator before
  reporting a missing node.
- 404 on one node: the path is wrong. Paths have no leading slash; take them from `atlas tree` or `atlas nodes list`.
- Exit codes: 3 not found, 4 permission denied, 5 not logged in, 6 validation error.
