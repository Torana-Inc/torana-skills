# Build lifecycle — proposals, blueprints, cook, deploy

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap first.**

> ⚠️ **BUILDING a program is not this skill's job.** When the user wants to build, create,
> generate or deploy a program, invoke the **`torana-build`** skill (plus the domain skill,
> e.g. `torana-vm`). Those carry the mandatory grounding discipline. This page exists so you
> can *read and reason about* build state — not drive a build from here.

---

## The one thing `--help` cannot tell you

**It is a state machine, not four independent verbs.**

```
proposal ──▶ blueprint ──▶ cook ──▶ deploy
```

- **proposal** — collects intent. What should exist.
- **blueprint** — plans it. What will be built, and against which data.
- **cook** — generates the artifacts (transformers, rules, widgets, routes…).
- **deploy** — makes a version live in the workspace.

A stage only accepts input once the previous one has completed. You cannot cook an
unplanned proposal, and you cannot deploy an uncooked one. When a command is rejected as
"not in the right state", that is this machine talking — read the proposal's current stage
before retrying.

## ⛔ Hook-blocked commands

`blueprint run` and `cook run|step` launch the **platform's own authoring agents** (the
"Torana harness"). A PreToolUse guard blocks them without an explicit override. Do not run
them from this skill's context — they are reserved for a user explicitly asking to exercise
that path. Driving them blind produces ungrounded programs that deploy green and return
nothing.

## Reading build state

```bash
"$TORANA" build capabilities                          # what this platform's driver supports
"$TORANA" build proposals list --workspace-id <WID>
"$TORANA" build proposal <PID> show                   # one proposal + blueprint + artifacts
"$TORANA" build blueprints list --workspace-id <WID>
"$TORANA" build versions list --workspace-id <WID>    # deployment snapshots
"$TORANA" build deployment <DID> get
```

`build proposal <PID> show` returns a **named-key object** (`proposal`, `blueprint`,
`artifacts`, `overview`) — a detail/report, not a list. Do not expect `items`.

## Uninstalling an app version

Deploy is no longer one-way. `uninstall` removes what a version installed and returns the app
to the previous one; uninstalling every live version returns it to **v0** — app alive, zero
artifacts.

```bash
"$TORANA" workspace <WID> build versions list                      # STATE column: LIVE | UNINSTALLED
"$TORANA" workspace <WID> build versions uninstall 11              # PREVIEW (default)
"$TORANA" workspace <WID> build versions uninstall 10 11 --no-dry-run
"$TORANA" build versions uninstall --workspace-id <WID> 11         # top-level form
```

⛔ **IRREVERSIBLE.** The uninstalled proposals become `uninstalled`, which is **TERMINAL** —
they cannot be redeployed, only **rebuilt from their intent** (the intent text survives in the
frozen manifest). Dry-run is the default; `--yes` skips the prompt, never the preview.

⚠️ **Contiguous suffix only.** With v1–v11 live, `11`, `10 11` and `1 2 3 4 5 6 7 8 9 10 11`
are legal; `5`, `1`, `1 11` are refused with a 409 that names the live stack and every legal
request. Order does not matter (`11 10` == `10 11`). The rule exists because removing v5 while
v6–v11 stand on what it installed would strip their foundation, and nothing downstream notices
until a widget returns nothing.

⭐ **An UNINSTALLED version stays in the timeline.** Its frozen manifest is provenance — "what
was live at v11" must stay answerable precisely when the artifacts are gone. So `versions list`
still shows it, with `STATE = UNINSTALLED`. Read the STATE column, not the presence of a row.

⚠️ **Version numbers are never reused.** After uninstalling v11 the next deploy is **v12**.

⭐ **A SHARED row in the preview is RELEASED, not deleted** — a refcounted catalog relation is
torn down only when its last reference goes. "15 artifacts removed" does not mean 15 things
were destroyed.

## Explaining a build — what it DECIDED, not just which phases ran

⭐ These are SA-scoped and answer the question you actually have when a build fails or ships
something odd. `lifecycle` says which phases ran; these say *why it stopped*.

```bash
"$TORANA" admin build trace <PID>                  # intent → steps → DECISIONS → gates → deploy
"$TORANA" admin build trace <PID> --failed-only    # only steps carrying a refusal
"$TORANA" admin build trace <PID> --gates-only --step 1.2
"$TORANA" admin build gate-evidence <PID>          # raw gate rows: outcome, attempt, reason
"$TORANA" admin build gate-evidence <PID> --failed-only
"$TORANA" admin build build-health --since 30      # how the build SYSTEM is operating, per harness
"$TORANA" admin build versions <WID>               # every version of one app, newest first
"$TORANA" admin build proposals list --built-via claude_skill
```

**How to read a trace.** Per step it shows the artifact produced, the DECISIONS behind it
(catalog REUSE vs AUTHORED, and the vocab-reuse ratio) and the GATES that judged it. A
**repeated gate with a rising `attempt` number is a retry loop** — the author kept
re-depositing the same thing. That signature was invisible before this existed.

**How to read build-health.** It splits by `built_via`, and the comparison is the point: both
harnesses drive the same FSM through the same gates, so a gate refusing one far more than the
other is a defect in that consumer's WIRING, not in the gate. A harness showing many
`catalog_first` refusals and **zero** catalog reuses is structurally unable to satisfy it.

⚠️ **A build with no gate rows is not a clean build.** Anything built before gate evidence
shipped has none. The trace says so explicitly — read "predates gate evidence" as *unknown*,
never as *passed*.

## Traps

⚠️ **"Deployable" is a claim about the proposal, not about the data.** A proposal can be
deployable and still be built on an anchor that has since gone stale. Check freshness before
trusting a deploy that has sat for a while.

⛔ **`artifact add` carries three CALLER-OWNED fields, and new SQL without one is REFUSED.**
`--catalog-entry-id` (reusing an entry — carry no `sql`), `--catalog-decision-id` (you
recorded a miss first), `--required-integrations`. Before these existed the values could only
be smuggled inside `definition`, so the catalog gate was unsatisfiable from the CLI path and
every deposit of new SQL failed with a message naming CLI verbs.

⚠️ **There is no `torana build-v2` group.** The FSM is `torana build proposal <id> <verb>`;
the SA observability commands are under `torana admin build`. Two different groups, and
guessing the wrong one produces a "No such command" that looks like a missing capability.

⚠️ **One deployable lineage per workspace.** If a cook is refused, an earlier proposal may
still hold the lineage — look at what is already deployable before assuming a bug.

## Repairing a deposited artifact — `artifact edit`

⭐ **`--semantic-description-file` is the flag you will not guess.** `edit` is the repair
path, and the INTENT is the field most likely to need repair — but it used to accept only
`--definition`, and re-adding 409s on the unique key.

```bash
"$TORANA" build proposal <PID> artifact edit <AID> \
    --semantic-description-file intent.txt      # repair the INTENT
"$TORANA" build proposal <PID> artifact edit <AID> \
    --definition-file def.json                  # repair the SQL/config
```

⚠️ Both are optional and independent — pass either or both. Passing NEITHER errors rather
than silently succeeding.

⭐ An INTENT-ONLY edit does not re-run the definition gates and does not cascade dependents
back to draft: nothing downstream depends on the prose, and a deployed artifact stays
deployed. An edit carrying a `--definition` still runs every gate.

⚠️ A conforming five-part intent runs ~1,400 characters, which is why the `-file` form
exists. The inline `--semantic-description` works for short cases.
