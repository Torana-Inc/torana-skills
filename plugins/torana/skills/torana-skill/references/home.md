# Home: an app's own page

An app's Home says what needs a decision, what the app dealt with, how the app itself is running, and what it
cannot see. The platform prepares it about every hour: it proves each open item from live data first, then writes
the page. The `torana` CLI prints the same page the screen shows, card by card.

`$TORANA` is the CLI and `$APP_ID` is the app's id (`"$TORANA" apps list`). Every command here is read-only
unless it says otherwise.

⛔ **Never re-word the page.** Each card's lines are written once, by the platform, and are the same on the screen.
Copy the line you are reporting. Do not recount, re-sort or paraphrase a number.

## Contents

- [Read the page, or one card](#read-the-page-or-one-card)
- [The marks](#the-marks)
- [Is the page current? Refresh it](#is-the-page-current-refresh-it)
- [One item: why it is there, its proof, its brief](#one-item-why-it-is-there-its-proof-its-brief)
- [How this app is running](#how-this-app-is-running)
- [Handled, and the events in the window](#handled-and-the-events-in-the-window)
- [Earlier pages](#earlier-pages)
- [What matters to you](#what-matters-to-you)
- [When something is switched off, or there is no page](#when-something-is-switched-off-or-there-is-no-page)
- [Exit codes](#exit-codes)

## Read the page, or one card

```bash
"$TORANA" app "$APP_ID" ai-home get                         # every card the screen draws, in page order
"$TORANA" app "$APP_ID" ai-home get --section needs-you     # one card
"$TORANA" app "$APP_ID" ai-home get --section handled --section rules --json
```

| `--section` | The card |
|---|---|
| `act-first` | The few things to do before anything else on this page. |
| `summary` | The page in one sentence, its headline counts, and how the run came down to them. |
| `what-matters` | The questions this app answers for you, each with its current answer. |
| `trust` | What could make this page wrong, said only when something could. |
| `health` | Whether the app itself is working: its data syncs, checks, agents and alert routing. |
| `needs-you` | The decisions waiting on a person, one card per decision. |
| `handled` | What the app closed or acted on without you in this window. |
| `rules` | Whether the app's checks ran, what they matched, and how the alert list is moving. |
| `dashboards` | The app's own figures, grouped by dashboard, with what each one says. |
| `blind` | The figures this page cannot compute, and what would supply them. |

- A bare `get` prints the cards the screen draws. A card with nothing to say (`act-first`, `trust`, `blind` on a
  good day) is left out, exactly as on the screen. `--section KEY` still prints it, with the sentence that says so:
  "No coverage caveats on this page."
- "This app's Home does not have this card." means the app's page layout does not include it. That is not an error.
- Under a line, `→` is the command that opens that line: an item's proof, a rule, an integration, a widget's rows.
  Run that command; do not build your own.
- JSON is one report: `{run_id, app_id, status, trigger, generated_at, window{label, since_at, now_at}, features,
  sections_version, changes, sections[]}`. A section is `{key, title, description, cli, lines[], notes[], empty,
  unavailable, drawn}`; a line is `{kind, text, marker, indent, cites[], commands[], source, parts}`. `text` is
  the finished line. `parts` holds the same values by name (for example `parts.headline` on a `card` or `row`
  line). With `--section`, `sections` holds only those cards.
- A `counter` line (the `rules` card) also carries `key`, `label` and `value` on the line itself, and its text
  leads with the label: `open, older than a day: 84 (of those open now)`. Find a counter by `key`
  (`open_now`, `open_older_than_a_day`, `newly_opened`, `newly_closed`, `closed_total`) or `label`; `parts.of` names
  the counter it is part of.
- **Possibly out of date.** The page is written once and never re-narrated. When an Inbox item on the `needs-you`
  card changed after the page was prepared (its title, status, severity, verdict, target version or the findings it
  clears), the line under that item is a `changed` line marked ◐: "May be out of date: since this page was
  prepared …, its target version is now 1.88.6 (was 1.96.2). Last updated …". A sentence under the stamp says how
  many changed. `changes` in the JSON is `{checked, checked_at, prepared_at, note, items[{alert_id, gone,
  fields[{field, label, then, now}], changed_at, text}]}`. Believe the Inbox (`torana alert <id> view`, the
  line's `→`), not the old card text. "Could not check whether these items changed…" means the check failed: the
  card may or may not be current.
- An entry's "What does it clear?" claim copies the Inbox's own count and split ("82 findings (72 at or above your
  floor, 10 not classified), …"), so Home and the Inbox say the same number.

## The marks

| Mark | Meaning |
|---|---|
| ✦ | Written by AI (a recommendation, a summary). Everything else is written by code from the data. |
| ◆ | A proven fact: it can be traced to the rows it was read from. |
| ▲ | Needs attention. |
| ◐ | Watch: not wrong, but not fully trustworthy (for example a figure with no reliable date, or a card whose item changed after the page was prepared). |
| ✓ | Fine. |
| ○ | Switched off, or never ran. |
| `—` | Not known. ⛔ It is never zero. |
| `N+` | At least N: the count hit a limit. |

## Is the page current? Refresh it

```bash
"$TORANA" app "$APP_ID" ai-home status
# Current: prepared 47 min ago (run fed02957-…).
#   Next scheduled refresh: 2026-10-12 10:06 UTC (every 60 min).

"$TORANA" app "$APP_ID" ai-home status --json     # {app_id, page, state, in_flight, last_failure, schedule, features}
```

`state` is one of `current`, `refreshing`, `last_refresh_failed`, `never_prepared`. Every state exits 0: a state
is not an error. While a page is being prepared, readers keep seeing the previous one.

```bash
# ⚠️ CHANGES THE APP: prepares a new page (the screen's Regenerate button). About a minute or two.
"$TORANA" app "$APP_ID" ai-home refresh --wait
#   … proving
#   … queued_for_llm
#   … writing
# Home page prepared (run e38106f0-…, success).

"$TORANA" app "$APP_ID" ai-home refresh            # returns at once; follow it with `ai-home status`
"$TORANA" app "$APP_ID" ai-home refresh --wait --timeout 600
```

- With `--wait`, exit `0` means the new page is ready. Exit `8` means the attempt failed or timed out, or
  `--timeout` passed first; the previous page is still shown, and `ai-home runs get <RUN_ID>` says why.
- "A refresh is already running" is not an error: with `--wait` the command follows that one.
- An agent may not run `refresh`. It can read `status` and tell the user to refresh.

## One item: why it is there, its proof, its brief

The item id is on the `→` lines under a Needs-you card (`… ai-home item <ALERT_ID> …`).

```bash
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" get                    # the item's card, as the page shows it
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" get --section cites    # the facts the page cited for it, as stored
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" get --section ledger   # its proof now, claim by claim
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" get --section graph    # its exposure path
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" get --section rows     # the alerts in the same decision
"$TORANA" app "$APP_ID" ai-home get --section needs-you --cites         # every cited fact, under its line
```

- `cites` is what the page **stored** when it was prepared. `ledger` and `graph` are the proof **now**. To see
  whether they still agree:

```bash
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" check
# 21 of 21 claims are the same as on the page (run fed02957-…); 0 differ.
```

  Each claim is `same`, `changed` (both texts are printed), `gone` or `new`. A claim that only aged ("37 hours
  ago") reads `changed`. It writes nothing and exits 0 either way.
- "Not in this run's proof." after a cited id means the page cited a fact its stored proof does not hold.
- One claim in full, with every row and rule behind it: `"$TORANA" alert "$ALERT_ID" proof --claim <CLAIM_ID>`.
- "This item is not on the current Home page." (exit 3): the id is not on the page. List the ones that are with
  `ai-home get --section needs-you`.

The AI brief is two commands, one that reads and one that writes:

```bash
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" brief get              # exit 3 when there is none yet
# ⚠️ CHANGES THE APP: one AI call over the item's proven claims, about a minute.
"$TORANA" app "$APP_ID" ai-home item "$ALERT_ID" brief write --wait
```

A line that offers no `brief get` command is an item that has no brief (no proof model, or a grouped check). An
agent may run `brief get`, not `brief write`.

## How this app is running

```bash
"$TORANA" app "$APP_ID" ai-home get --section health
```

The first line is the verdict. Each line under it says what is wrong, what it costs and what to do, and carries
its own `→` command when the fix is yours (`torana integration <ID> get` for a failing data sync,
`torana rule <ID> get` for a check that cannot fire). ⛔ Act on the line's own command. "nothing for you to do"
means the fault is on Torana's side.

## Handled, and the events in the window

```bash
"$TORANA" app "$APP_ID" ai-home get --section handled
```

- A row says "Closed" only when the alert is closed. "Acted on by the app" means the app did something (ran a
  playbook, gave a verdict) and the alert is still open; it may also be on a Needs-you card.
- The ✦ first line is the AI's summary of the window. The rows under it are from the data.

"N events in the window" on the summary card counts the app's own activity (data syncs, rule runs, agent work).
It is not a count of findings. List those events:

```bash
"$TORANA" app "$APP_ID" ai-home events               # the page's own window
"$TORANA" app "$APP_ID" ai-home events --window 24h
```

A row is a group of repeated events (`×` is how many; it keeps counting after the page was prepared). The footer
says the page's figure, and says so when the rows listed are not that many ("(listed here: N)"); rows that began
after the page was prepared are left out and counted in the last line.

## Earlier pages

```bash
"$TORANA" app "$APP_ID" ai-home runs list             # every attempt, newest first; "◀ shown" marks the page readers see
"$TORANA" app "$APP_ID" ai-home runs get "$RUN_ID"    # how one ended, and why it failed
"$TORANA" app "$APP_ID" ai-home get --run "$RUN_ID"   # read that page
```

The platform keeps the last 24 pages. "That page is no longer kept" is exit 3.

## What matters to you

The app's own questions, each with its current answer. They are not part of a stored page: `get` reads them
live, so with `--run` the card says the answers are the current ones.

```bash
"$TORANA" app "$APP_ID" ai-home get --section what-matters
"$TORANA" app "$APP_ID" ai-home questions list
"$TORANA" app "$APP_ID" ai-home questions catalog
# ⚠️ CHANGES THE APP: adds a question to its Home.
"$TORANA" app "$APP_ID" ai-home questions ask --pick "$CATALOG_ID" --wait
```

The full lifecycle (confirm a reading, thresholds, move, remove, restore) is in
[workspaces.md](workspaces.md#what-matters-to-you-the-apps-own-questions).

## When something is switched off, or there is no page

Three parts of What matters can be switched off for an environment: the feature itself, typing your own
question, and searching the ready-made list. Scheduled refresh can be switched off too. `ai-home status` lists
every one that is off, in a sentence, on a line starting `○`.

- A command for a switched-off feature prints that one sentence and exits 3 or 4, for example "Typing your own
  question is turned off in this environment. Pick one from the list." ⛔ Report the sentence. It is not a
  missing capability and not a stale deployment; do not go looking for one.
- With What matters off, `get --section what-matters` prints the reason and asks the server nothing.

No page yet is a state, exit 0:

```text
No Home page has been prepared for this app yet.
  Prepare it now:  torana app <APP_ID> ai-home refresh --wait
```

The second line is the truth for that app: "The platform prepares the first one within the hour" when a first
page is coming by itself, "Prepare it now" when it is not (a new app with no page is not prepared automatically).

**When a question needs the Home page and there is none**, say so in the first sentence ("No Home page has been
prepared for this app yet") and give the prepare command as an offer, with one line saying that it changes the app.
Do not run `ai-home refresh` yourself unless the customer asked for the page to be prepared. If the status line says
a first page is already scheduled, say that too, and do not guess when it will appear.

"This server does not send finished sections yet; showing the previous layout." means the server is older than
this CLI. The page is still correct; `--section` is not available on it.

## Exit codes

`0` success, or a state (`status`, no page yet, a refresh already running) · `2` a wrong option or an unknown
card key · `3` not found: the item is not on the page, there is no brief, the page is no longer kept, or the
feature is switched off · `4` not allowed, or typing your own question is switched off · `5` not logged in ·
`8` `refresh --wait`: the attempt failed, timed out, or `--timeout` passed.
