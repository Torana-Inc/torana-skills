# Communication — how to hand work back to a human

⛔ **Load this when you are about to WRITE TO THE USER**: narrating a phase transition, or
writing the final report (built or refused). Everything else in this skill is mechanism;
this is the part the person actually reads.

⚠️ **Why this is a separate file.** Across three verified build sessions the MECHANICS never
failed — probes ran, gates fired, refusals were correct, every number was true. The
COMMUNICATION failed twice: correct answers handed back naming `PEER_GAP`, `vm.tf.em_032`,
`missing_column` and a decision UUID to a reader who wanted to know whether their team was
keeping up. A right answer nobody can read is not a right answer.

⭐ **The rule that governs everything below** (also stated in `SKILL.md`, because it is too
important to live only in a file you might not load): **assume a business reader, layer the
detail, and ALWAYS signal that more exists.** Never silently omit — say what you are holding
back, then hold it back.

---

### ⛔ WHO IS READING — layer the answer, and always say more exists

**Assume a business reader until proven otherwise.** The person asking "what should we fix
first?" is usually a CISO, a security lead or an engineering manager. They do not know what
`PEER_GAP`, `vm.tf.em_032`, `missing_column` or a decision UUID are, and those terms make a
correct answer *unreadable* — which is the same as a wrong one.

⚠️ **But the reader is sometimes an engineer**, and stripping the detail fails them just as
badly. So do not choose an audience. **LAYER the answer** and let the reader descend:

| Layer | Contains | Who it is for |
|---|---|---|
| **1 — the answer** | the finding, in their words, with the number that matters | everyone |
| **2 — why / what next** | the cause and the action, still in plain language | everyone |
| **3 — the detail** | column names, verdict codes, catalog entry ids, decision ids | the engineer who asks |

⭐ **Layer 3 is COLLAPSED, never dropped.** Put it in a `<details>` block — the chat renderer
supports it natively:

```markdown
<details><summary>Technical detail</summary>

`vulnerabilities.vulnerability_resolution_date` — supply verdict `PEER_GAP`.
Catalog near-miss `vm.tf.em_032`; recorded as `missing_column`, decision `fe6be9f3…`.

</details>
```

⛔ **ALWAYS SIGNAL THAT MORE EXISTS.** A reader who cannot see that detail is available
assumes there is none, and stops asking. The `<summary>` line is that signal — it is not
decoration, it is the affordance that makes the layering honest. **Never silently omit**:
say what you are holding back, then hold it back.

⚠️ **The `🔍 CATALOG` block is LAYER 3.** It proves the catalog was consulted — genuinely
non-negotiable as an *audit* record, and it already lives in the trace and in
`catalog_decision_id`, durably, whether or not you print it. Narrating it in full to a
business reader adds nothing they can act on. Put the one-line outcome in layer 2
("reused a reviewed definition rather than writing new SQL") and the entry ids, grains and
rejection axes inside the collapsed block.

⚠️ **Measured 2026-08-18** (`d6e52fe1`, the MTTR build): a correct, well-reasoned refusal was
handed back naming `PEER_GAP`, `vm.tf.em_032`, `missing_column` and a decision UUID in the
top-level prose. Every fact was right and verified. It was still the wrong answer *for the
person who asked*, because nothing in the skill said who that person is.

### Narrate the transition, not the mechanics

Between phases, say in one or two plain sentences what you found and what it changes. Not
the commands; what they *meant*.

| Don't say | Say |
|---|---|
| "Running `torana entity-graph edges`…" | "The graph has `owns` and `exposed_via` edges — ownership is reachable, so team attribution is on the table." |
| "Catalog list returned 85 entries." | "Read all 85 catalog entries. Two are close to what you need; I'm checking whether their grain actually fits." |
| "Cook step 3 validated." | "The prioritisation view is built and validated against your real columns." |

**The catalog decision is narrated in full, always** — the `🔍 CATALOG` block with what you
looked for, the entries considered with their grain, the decision, and the axis on which you
rejected the closest. That is not covered by "narrate transitions"; it is a separate,
non-negotiable output specified in the operating loop.

### The FINAL REPORT — what to hand back when the work is done

A build ends with a report the user acts on. It is read once, often by someone who did not
watch the run, and it decides whether something goes live. Six sections, in this order.
Anything not serving one of them is noise.

```
1. STATUS          one line: what state the thing is in, and what happens next
2. WHAT I FOUND    the answer to their actual question — before any inventory of work
3. WHAT I BUILT    the artifacts, grouped, in user terms
4. JUDGEMENT CALLS what you decided that they might have decided differently
5. CAVEATS         what is weak, unproven, or worth watching — in your own words
6. THE ASK         one question, and nothing is live until it is answered
```

**1 — STATUS, first line, no preamble.**
> "Built and validated — **stopping here for your go-ahead before anything goes live.**"

They need to know instantly whether something happened to their platform. Never bury this
under a narrative.

**2 — WHAT I FOUND, before WHAT I BUILT.** The user asked a question; answer it. The
artifacts are how you answered, not the answer. Lead with the number that changes their
mind, and show the funnel that produced it:

> Your team isn't behind. The queue is lying to you.
>
> | Stage | Count |
> |---|---|
> | Open scan records (what the ticket queue counts) | **6,179** |
> | Distinct CVEs behind them | 491 |
> | **Actually fixable right now** | **67** |

Every number here comes from THEIR live data and you have run the query. A figure you did
not verify does not belong in a report someone will quote.

**3 — WHAT I BUILT, in user terms, grouped.** Not a list of artifact keys. Say what each
thing DOES, and name reuse explicitly where it happened:

> - **Foundation transformer** — reuses the reviewed catalog definition `vm.tf.em_012`,
>   so its counts agree with every other app asking this question. Not new SQL.
> - **Queue table** — component, package manager, exact target version, findings cleared.

**4 — JUDGEMENT CALLS.** The section most often skipped and most worth keeping. Anything
you decided that a reasonable person might have decided differently, with the reason:

> **No per-team breakdown.** `asset_team` is populated on 29 of 1,220 assets with one
> distinct value — that panel would have rendered a single "unassigned" bar.

Two or three. If you have none, you probably made choices without noticing them.

**5 — CAVEATS.** What is weak, in plain sentences. **Never a confidence percentage** — a
number nobody computed borrows credibility from the real ones beside it. Write what a
reader could act on:

> The widgets query the base tables directly rather than the shared `vm_tf_em_012` table,
> because that table materializes at install and did not exist to validate against. Same
> grain and filters, so the numbers match — but it is a duplication worth collapsing once
> the table exists.

Include here anything you could NOT verify, and say so plainly. A caveat you volunteer is
worth more than one the reader finds later.

### ⛔ WHEN YOU BUILD NOTHING — the refusal report

The six sections above assume something was built. **A refusal is a different report**, and it
is the HARDER one: the user gets nothing they asked for, so the reason has to land in their
terms or it reads as a failure to try. It is also the case with the most technical material
lying around — every diagnostic you just gathered — which is exactly what NOT to lead with.

```
1. WHAT I DIDN'T DO   one line, plainly, and that nothing changed
2. WHY                the cause IN THEIR TERMS — what is absent from their world, not which
                      column is NULL. One number that makes it concrete.
3. WHAT WOULD FIX IT  the action, and who takes it — connect a tool, run a scan, assign owners
4. WHAT I CAN DO NOW  a real alternative from THEIR data, verified, or say honestly there is none
5. THE ASK            one question
   <details>          the columns, verdicts, catalog ids, decision id — collapsed
```

⭐ **The distinction that matters most in §2** is *"nobody has recorded this"* vs *"this is
genuinely zero"*. They look identical in a query result and mean opposite things. Say which:

> Nothing in your data records **when** a vulnerability was fixed — not one of 6,063.
> So "how long do we take to fix things" has no answer to compute; any number would be invented.

⛔ **Never substitute a proxy and keep the original title.** If the honest metric is
unavailable, offer the different one BY ITS OWN NAME. "Mean age of open findings" titled as
MTTR renders, validates, deploys green — and tells a board the opposite of the truth.

⚠️ **This rule is about the METRIC, not the SAMPLE — do not stretch it.** "The column
cannot be filled" is a refusal. "There are only 3 rows so far" is a CAVEAT on a widget you
still build (`SKILL.md` § WHEN TO REFUSE). Measured 2026-08-18 (`b962e9eb`): a session
refused partly because the sample was n=1 per team — which would refuse a perfectly
truthful widget on any quiet quarter. Say the volume plainly and build it.

⭐ **So a report can carry BOTH shapes at once**, and often should: refuse the part that
cannot be truthful, build the part that can, and put the thin-sample warning in CAVEATS
rather than using it as a reason to build nothing.

**6 — THE ASK.** One question. State clearly that nothing is live until they answer:

> **Deploy it?** Nothing is live until you say so.

### After a deploy — report what you VERIFIED, not what you submitted

A deploy that returns success is not a deploy that worked. Widgets can fail to attach,
schedulers can bind to nothing, a reused entry may not materialize. Check, then report what
you checked:

> Deployed. Verified: both widgets attached (not dropped), the scheduler bound to a real
> transformer UUID and is enabled, and the reused catalog entry materialized to a real
> table with 141 ranked rows.

**If something did not verify, that is the headline, not a footnote.** A green report that
omits a failed check spends trust you have not earned.

### When the plan changes, say so

Discovery routinely invalidates the plan — a missing edge type removes an option, an empty
column kills a whole approach. **Update the todo list and say why in one line.** A silently
rewritten plan is worse than no plan: the reader is still watching the old one.

> "The ownership join is empty here (1,191 of 1,220 assets have no team), so step 4 changes:
> attribution has to come from the graph, and I've added a step to verify that path
> resolves before I build on it."

### What this is not

- **Not a substitute for the deploy gate.** Progress narration is visibility; the gate is
  consent. Never let a well-narrated build drift into deploying without the explicit yes.
- **Not commentary on every tool call.** One transition, one or two sentences. A play-by-play
  is as unreadable as silence.
- **Not for ADVISE answers.** A question with a short answer gets the answer, not a project
  plan. Use the tracker when the work has phases a reader could get lost in.

---