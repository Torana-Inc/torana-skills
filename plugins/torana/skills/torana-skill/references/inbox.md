# Inbox — read an item as the screen shows it, find out why it is where it is, decide, close or reopen it, look at a CVE or CWE across an app

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap first.**

The **Inbox** is the list of work an app has for you. An **item** is one thing in it. An **entry** is an item that
stands for a group of **findings** that one fix clears ("Upgrade <package>", "Mitigate <package>"); a finding on its own is
also an item. A finding is one scanner result: one CVE, in one package, in one place. Items live in two **boxes**:
**Needs attention** (`needs_attention`) and **Closed** (`closed`). An **app** is what the API's JSON sometimes calls a
workspace; `<APP_ID>` is its id. The alert commands take `--workspace-id <APP_ID>` today; `--app-id` replaces it in a
coming release.

Everything a card says here is written by the platform, once, and is the same text the screen shows. Relay it; do not
rephrase it into something the platform did not say. Never rebuild a card from `get`: that view is the raw record, and
what you compose will drift from what the user is looking at.

## Start here

```bash
"$TORANA" alerts boxes --workspace-id <APP_ID>                          # how many items are in each box
"$TORANA" alerts list --workspace-id <APP_ID> --box needs_attention     # the work, in the ranking's order
"$TORANA" alert <ITEM_ID> view                                         # one item, as the screen shows it
"$TORANA" alert <ITEM_ID> view --section verdict                       # one card of it
"$TORANA" alerts cve CVE-YYYY-NNNN --workspace-id <APP_ID>              # a CVE across the app
"$TORANA" alerts cwe CWE-89 --workspace-id <APP_ID>                     # a weakness across the app
```

Handed an Inbox link? `…/workspaces/<id>/inbox?box=<box>&alert=<ITEM_ID>`: the `alert` query value IS the item id to
pass to `alert <ITEM_ID> view`. The app is implied by the item. An item belongs to one account: run it from the account that
owns it, or the id answers "not found".

**Choosing the route (part of App first).** A question about one item goes to `alert <ITEM_ID> view`. A question that
selects items by a property goes to `alerts list --where "<condition>"`; one that looks for a word, name or phrase (a package,
service, host, CVE) goes to `alerts list --search "<text>"`, the Inbox's search box, which also looks inside the findings grouped in an entry (a name
grep over the list misses those; the MATCHED column says where each row matched). A question across items
(which, how many, since when, joined with facts about the finding) goes to the SQL skill over `inbox_items`, joined to the
app relation its `JOIN KEY` line names; facts about the finding come from that relation, not from the item. A filter
the server does not support is refused with a message and no rows, never answered with an unfiltered list.

**The words.** The platform holds one set of words for verdicts, statuses, severities and closed reasons; `alerts labels` prints it, and the `*_label` fields in a response use the same words. Quote the label, not the stored code.

**History across items** (what happened, by whom, since when): `activities list --type <type>[,<type>] --actor <actor> --since <window> --all`
lists them (one page by default; the API reports no total, so add `--all` before counting). One kind of event can
have several types, so list the types the question covers. For counts and joins, use SQL over `inbox_activities`
(its time column is `at`). Never read a count off one page.

## How to read a card

`alert <ITEM_ID> view` prints one block per card, in the screen's order. Each card has a heading, one line saying what
the card shows, its content, and sometimes a muted note about what the counts are over.

```
Mitigate libexample
critical  ·  Needs attention  ·  open  ·  SLA: due soon (due <date>, 09:00)

ABOUT
  What this item is: its description, what it affects, the CVEs it covers and the CWEs it covers.
  What it is: Mitigating libexample clears 40 findings
  Affected: libexample 2.4.1-1 in service-a, service-b and 6 more
    CVE-YYYY-NNNN
      CWE: CWE-NNN · <weakness name>
      <one-line description of the weakness> …

VERDICT  — Triage agent (14) · Ranking rules (26)
  Whether these findings are real, who decided and why.
  True positive: 40 findings, running, internet-facing, no fixed version for any of them
  Ranking rules: 26 findings
    • Severity: High (15) · Critical (6) · Low (5) · Internet-facing: yes (26)
    ↳ Show all reasons (2): rerun with --all-reasons
  Triage agent: 14 findings
    • Relied on (of 14 findings): running 14 · internet-facing 14 · Critical 6 · customer data 5
    ↳ Show all reasons (14): rerun with --all-reasons
  Counted over the 40 findings open in this entry.

HOW TO FIX
  The mitigation: no fixed version exists, the app's own guidance, and the distribution's own security tracker entry for each CVE.
  Mitigation: No fixed version exists yet for the 4 CVEs in this entry. Mitigate libexample; for example restrict what reaches the vulnerable code, … Follow the security tracker entry for each CVE:
    → CVE-YYYY-NNNN  <tracker URL>
    and 1 more
  Other CVEs in libexample are fixed by upgrading to 2.4.1-3: see
    → Upgrade libexample to 2.4.1-3 (Inbox entry)  <ITEM_ID>

WHAT THIS FIX CLEARS
  The open findings this one fix resolves, and how many more are already closed.
  Clears 40 open findings: 22 at or above your severity floor, 6 below, 12 not classified. 5 more are already closed.
```

| Part | What it tells you |
|---|---|
| The line under the item name | Its severity, box and status, and `SLA: breached`, `due soon` or `on track` with the deadline in your time zone. No SLA text means the item has no deadline (an unknown severity has none on purpose) or is closed. |
| Heading line and `—` attribution | The card, and who decided it (the triage agent, the ranking rules, a person), with a count when several did. |
| The line under the heading | What the card shows. It is worded from what this item's card really holds, so it names code, CWEs or tracker links only when they are there. |
| `True positive: 40 findings, running, …` | One line per verdict, with how many findings and what is true of all of them. A quality true of all says "for any of them" where it would otherwise read as package-wide; true of only some it says so: "no fixed version for 14 of them (not known for 3)". |
| `↳ Show all reasons (N)` | The individual reasons are folded. Add `--all-reasons` to print them. |
| `⚠` before a line | A warning the platform raises on purpose: findings for one vulnerability decided both ways, a past CISA due date, a verdict the platform corrected. Say it; do not soften it. |
| The muted line at the end of a card | What the counts are over ("Counted over the 40 findings open in this entry."), or a cap ("The table shows the 10 most exposed of 25 findings."). |
| `Mitigation:` and the links | When no fixed version exists for the CVEs in this entry, the app's own guidance is printed as written, then one tracker link per CVE for the distributions the platform can map. `and N more` follows the links it is about. When the same package has another entry (for example the CVEs an upgrade fixes), a line links to it. |
| `Not available` | The platform did not supply the value. It is never a zero. |
| The item line: `Finding severity` and `Rule severity` | Two labelled values. The item's severity is the finding's for a finding item and the rule's declared severity for a situation entry; the rule's reads `Not declared` when it declares none. Severity feeds the item's priority, and priority alone orders the list: there is no severity sort. Quote each value with its label; never call one "the severity" when they differ. |
| Exposure: `internet-facing`, and a sign-in detail | Exposure is exposed or not exposed. Reachable from the internet counts as exposed even when a visitor must sign in; the sign-in method is shown as a detail beside it (`no sign-in`, `AWS IAM sign-in`, `sign-in not recorded`), never a reason to call the asset not exposed. |
| `Not running` | Findings on images that no service runs are set aside as `Not running`, but only when the estate is fully accounted for: every service's running image is known, and no host sits outside a cluster. When it is not, those findings stay in the list. |

An empty card says why (`empty`), or `unavailable` when it could not be built. Neither is an error.

## Which command answers which question

| Question | Command |
|---|---|
| What is in my Inbox, and how much? | `"$TORANA" alerts boxes --workspace-id <APP_ID>` then `"$TORANA" alerts list --workspace-id <APP_ID> --box needs_attention` |
| What is this item? Its CVEs, CWEs, the code in GitHub | `"$TORANA" alert <ITEM_ID> view --section about` |
| Who decided it, and why? | `"$TORANA" alert <ITEM_ID> view --section verdict` (add `--all-reasons` for every reason) |
| What ground does a verdict rest on, and is there evidence? | `"$TORANA" alerts reason-codes` for the grounds; `"$TORANA" alert <ITEM_ID> get` for this item's `reason_code` and `verdict_evidence` (see *Reading a verdict*) |
| What do I do about it? | `"$TORANA" alert <ITEM_ID> view --section how-to-fix` |
| Is the vulnerable code actually used? | `"$TORANA" alert <ITEM_ID> view --section reachability` — the newest measured verdict, its evidence (commit, analyzer, where the function is, the call path) and what it did to the priority. ⚠️ Present only on a FINDING something has measured: absent on an entry (its members hold the measurements) and on an image-layer finding the entity graph cannot trace to a repository that builds it. An absent card is the right answer, not a gap. |
| What does this one fix clear? | `"$TORANA" alert <ITEM_ID> view --section clears` (on a situation entry: `--section affected`) |
| Which scanners reported it, how often seen? | `"$TORANA" alert <ITEM_ID> view --section reported-by` |
| Why is it in this box, or why was it closed? | `"$TORANA" alert <ITEM_ID> view --section why-here` |
| Counting findings by the reason they were set aside | Not one item's `why-here`: the app's own dashboard counts them. Find the widget that groups findings by the reason they were set aside or deferred (`"$TORANA" dashboards list --app-id <APP_ID>`, then `"$TORANA" dashboard <DASHBOARD_ID> render`), and quote each reason with its count. A reason the card marks "not fixable yet" is a different outcome from "set aside": give each its own count and label. Read the card's freshness line and say so when it is stale. To count from the data instead, group the app's findings by their reason column through the data analyst route. Read the card yourself and give the counts in the same answer: a question that asks "why" or "how many" is not answered by describing where the numbers live. When the account has one app, use it; ask which app only when there are several. |
| What happened to it, newest first? | `"$TORANA" alert <ITEM_ID> view --section history` (in JSON the events are `sections.history.events`: `at`, `who`, `what`, `text`) |
| How could an attacker reach it? | `"$TORANA" alert <ITEM_ID> view --section exposure-path` (asked for by name; needs permission to read the data lake) |
| The findings behind an entry | `"$TORANA" alert <ENTRY_ID> members` (each row says `state` open or closed, and its `box`) |
| How do we know any of this? | `"$TORANA" alert <ITEM_ID> proof` (each claim and the rows behind it) |
| A plain-words summary of the item | `"$TORANA" alert <ITEM_ID> brief get` |
| Where does this CVE stand across the app? | `"$TORANA" alerts cve <CVE> --workspace-id <APP_ID>` |
| Where is this weakness found across the app? | `"$TORANA" alerts cwe <CWE> --workspace-id <APP_ID>` |
| Which items are overdue? | `"$TORANA" alerts list --workspace-id <APP_ID> --overdue` (the platform decides; the SLA column and each item's header say `breached`, `due soon` or `on track`; `--overdue` is the shortcut for `--sla-state breached`) |
| Which items are close to, or past, their deadline? | `"$TORANA" alerts list --workspace-id <APP_ID> --sla-state due_soon,breached` (also `on_track`, `none`; the value is checked, a typo is an error naming the valid ones) |
| How many items, and how many findings does the list leave out? | The text list ends with the platform's count ("N items, and M more findings grouped under entries; add --include-members"); in `--format json` read `total` (entries) and `members_not_included`. `--all` pages through the ENTRIES; it never adds the grouped findings |
| How many findings of an entry are already closed? | `"$TORANA" alert <ENTRY_ID> view --format json`: `header.findings_already_closed` (also `members_open`, `members_closed`); the Clears card says it in words |
| Only the work changed lately | `"$TORANA" alerts list --workspace-id <APP_ID> --sort newest --since 2d` |

**Answering a deadline question.** Count the rows you are about to show before you write the first sentence. If
any open item's deadline falls inside the warning period (read `sla_warning_lead_days` from the app's policy) or
inside the number of days the user asked about, open with that count and the earliest date, for example "<N> items are
due within 7 days, the earliest on <date>", then list them with their owning team and how many findings each covers.
Never open with "nothing is near its deadline" above a table that has such rows. Quote the platform's `SLA:` label as
written; when it says `on track` for a deadline that is inside the warning period, say both facts and that they
disagree. Name the policy windows the deadlines come from (`sla_window_by_severity`) and say whether a source is
recorded for them; do not call them a named framework's windows unless the policy says so.

**Answering "how many findings".** Inbox rows are items, and one item can group many findings, so an item count is
never the answer to a question about findings. Label what you quote: "<N> items" or "<M> findings grouped under
them", never a bare "<N> open". For findings, count them: how many are open at the scanners, and then how many of
those are set aside, as two numbers with their reasons (the set-aside row above). Read the findings from the app's
findings table through the data analyst route when no card carries the total. Never answer "the platform gives no
total" while that table can count them, and never replace a findings count by the item count; if you quote both,
say which is which.

`--section` can be repeated, takes the card's name in lower case with hyphens, and is checked against the kind of item:
an unknown key is refused with the list of valid ones. `--format json` returns `{header, sections}` with the same words,
and every section carries `description` (what the card shows) and `cli` (the command that prints just that card).
The `verdict` section also carries `verdicts` (`[{verdict, count, label}]`), `decided_by` (`[{source, count, label}]`) and, when it counts several findings, `counted_over`, in the same shape for an entry and for a single finding.
`--no-activity` leaves the History rows out of the whole view.

## Closed items and the two boxes

There are two boxes, `needs_attention` and `closed`. There is no Moved box: work that moved to another entry is listed in
`closed` with the reason `moved`.

```bash
"$TORANA" alerts list --workspace-id <APP_ID> --box closed --why fixed           # closed because it was fixed
"$TORANA" alerts list --workspace-id <APP_ID> --why moved --all                  # what moved, and where its work went
"$TORANA" alerts list --workspace-id <APP_ID> --verdict true_positive --decided-by system
```

A closed item's **Why it's here** card says who closed it, why, and what is still left to do. The platform closes an item
only when it is sure: a stopped workload closes it as "no longer deployed" and leaves its verdict as it was, and the item
reopens by itself if the workload runs again. A card that says **Corrected by the platform** was an item the platform
corrected after the fact; its original reasoning is folded behind "Show the agent's original reasoning".

## Decide, close, reopen

```bash
"$TORANA" alert <ITEM_ID> verdict --triage-verdict true_positive --reason-code exposed_and_fixable \
    --proposed-fix "Upgrade libexample 1.0.0 to 1.0.1"
"$TORANA" alerts reason-codes                                  # the grounds a verdict may cite
"$TORANA" alert <ITEM_ID> close --reason accepted_risk --message "Compensating control in place"
"$TORANA" alert <ITEM_ID> reopen --message "still reported"
"$TORANA" alert <ITEM_ID> keep-closed                          # agree with a closure the platform made
"$TORANA" alert <ITEM_ID> comment --comment "Waiting on the vendor"
```

**Before any change, read first, even when told "check with me".** Run the lookups, then ask:

1. Find the exact item the change acts on. An entry groups findings, so the target may be one of its members
   (`alert <ENTRY_ID> members`); take that item's own id.
2. Quote its current status and verdict (`alert <ITEM_ID> view --section verdict`, and the status line).
3. Print the full command you would run, with the real ids and a `<reason-code>`, for example
   `alert <ITEM_ID> close --reason <reason> --message "..."`.
4. Then ask. Run nothing until the customer says yes.

A verdict is a judgement about the finding: whether it is real. "Benign" and "false positive" are for reasons about the
finding itself (the vulnerable code is not reachable, the scanner is wrong), never because a workload stopped. A person's
verdict stands: the platform and the triage agent do not replace it. `status` only closes; use `reopen`, `escalate`
and `assign` for the other moves. A closed item is refused with the reason.

If the triage agent disagrees with the fix the app declared for an item, How to fix says "The triage agent disagrees with
this fix: <its sentence>. A person needs to decide." and the item waits in Needs attention for a person.

## Reading a verdict: its ground and its evidence

A verdict is a judgement ("True positive", "False positive", "Benign", "Inconclusive") and it rests on ONE **ground**: the reason the platform
records beside it. `"$TORANA" alerts reason-codes` lists every ground, which verdicts it can accompany, and what it says. The Verdict card shows the
decider's reasons in its own words (a person's reason is the ground's label); `alert <ITEM_ID> get` shows the ground code (`reason_code`) and the
evidence (`verdict_evidence`). Relay what they say; do not restate a ground as something stronger.

| Ground (what the card or the list says) | What it means, and what to tell the user |
|---|---|
| **The record cannot rule it out** (`cannot_rule_out`) | The platform's own record does not show the finding is harmless, so it stays a true positive. This is the last resort when nothing stronger applies. It is NOT "someone confirmed it is exploitable": say it that plainly. |
| **The agent read the code or configuration and confirmed the flaw** (`agent_confirmed_by_analysis`) | The triage agent read the flagged code and found the flaw. It must cite what it found and where (the Evidence line). It is only offered for findings whose code the platform serves. |
| **The agent's analysis of the finding record shows this is real, and the code is not served for this rule** (`agent_confirmed_from_record`) | The same kind of confirmation for findings whose code is never served (for example a hard-coded secret), where no code could be read: the agent reasoned from the finding record and cites it. It never closes anything. |
| **Known exploited, public exploit, zero-day or ransomware use**, **Reachable where it runs and a fix exists** | Facts the platform holds about the finding; no agent opinion involved. |
| **Could not be decided from the record** (`needs_a_person`) | Inconclusive: the item waits for a person. |

**Evidence.** A ground the agent rests on its OWN reading (the two "agent confirmed" grounds, and the agent's analysis when it closes) must come with
the evidence: what was found and where, in enough words to check. `alert <ITEM_ID> get` carries it as `verdict_evidence`, and while an agent's
verdict is still only a recommendation waiting for a person, the card shows it as an **Evidence** line beside "Recommends". A ground that rests on the
platform's record (`cannot_rule_out` and the facts above) carries no evidence, because the record is the evidence. If an item's verdict rests on the
agent's reading and `verdict_evidence` is empty, say that it has none; do not infer one.

**A person records their own ground.** `alert <ITEM_ID> verdict --triage-verdict true_positive --reason-code <ground> --verdict-evidence "<what you
found>"`. The "agent confirmed" grounds describe the agent's work, so as a person choose the ground you actually rest on and put what you found in the
evidence. A person's verdict is never overridden by the agent or the platform.

**A stopped image never makes a finding benign.** If the workload stopped, the item closes as "no longer deployed" and its verdict stays what it was.
A card that says **Corrected by the platform** explains an item that had been closed as benign for that reason.

## A CVE or a CWE across an app

`alerts cve` and `alerts cwe` are the collection commands (not `alert <ID> …`): they answer "what does the platform hold
about this CVE or CWE in this app?" under the section names the screen's drawer uses. `--workspace-id` is required.

```bash
"$TORANA" alerts cve CVE-YYYY-NNNN --workspace-id <APP_ID>                         # every section, "what to do" first
"$TORANA" alerts cve CVE-YYYY-NNNN --workspace-id <APP_ID> --section verdict --section reported-by
"$TORANA" alerts cve CVE-YYYY-NNNN --workspace-id <APP_ID> --section blast-radius --ecosystem <ecosystem> --package <package> --version <version>
"$TORANA" alerts cve CVE-YYYY-NNNN --workspace-id <APP_ID> --section how-to-fix --check-upgrade --ecosystem <ecosystem> --package <package> \
    --installed <version> --target <version>
"$TORANA" alerts cwe CWE-89 --workspace-id <APP_ID> --section location              # the files, with links to GitHub
```

CVE sections: `about, where-found, blast-radius, verdict, how-to-fix, reported-by, history`. CWE sections: `about,
where-found, location, verdict, reported-by, related`. The first line of a CVE view says what to do ("N open findings to
fix:" with the Inbox entry that holds them, or "Nothing open for this CVE."). The view is LIVE: open findings whose item
is not "no longer deployed" or "fixed at source"; the rest is one line of counts. `blast-radius` with the package options
works for pypi, golang, npm and maven; "the entity graph has no node for this package version" means the graph has no such
node, not that nothing is affected. `--check-upgrade` compares known records; "none known introduced" is never a
guarantee. Repeat `--version` to cover every installed version at once.

## The proof and the brief

`alert <ITEM_ID> proof` shows each claim the platform made about the item and the rows and rules behind it; `--claim <id>`
traces one; `--format json` is the record itself. `alert <ITEM_ID> brief get` shows the item's AI brief: the proven claims in
prose, each sentence with the claims it cites, checked against the proof as it is now ("◇ claims changed since written"
marks a sentence to rewrite). Reading a brief changes nothing and works for anyone who can read the item.

```bash
"$TORANA" alert <ITEM_ID> brief get                # the latest brief, with staleness against the proof now (bare `brief` is the same)
"$TORANA" alert <ITEM_ID> brief write --wait       # write a new one: one AI call, about a minute
```

`brief write` starts work and stores a new brief, so it is a person's action and is refused in the agent sandbox. Quote
a brief's sentence only with its cites.

Exit codes: `0` ok, `2` a usage error (an unknown section key, a missing option), `3` "No brief yet".

## Operator commands (not for everyday use)

These run, but are not listed by `--help`, because everyday Inbox work does not need them. Use them only when an operator
asks:

| Command | What it does |
|---|---|
| `alerts correct <CORRECTION>` | Corrects items the platform recorded wrongly. A dry run unless `--apply`; selects one exact shape and nothing else; a second run changes nothing. |
| `alerts reconcile-sla`, `alerts reconcile-owners`, `alerts regroup` | Repair deadlines, owners and entry grouping after a rule change. A dry run unless `--apply`. |
| `alerts create`, `alerts triage-agents` | Raise an item by hand; list the triage agents. |
| `alert <ITEM_ID> compress-context`, `invoke`, `cancel` | Inspect or steer the triage agent's run for an item. |
