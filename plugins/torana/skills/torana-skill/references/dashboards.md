# Dashboards — read them as the screen shows them, find out why a widget is empty or stale, sweep an app, edit

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap first.**

A **dashboard** is one tab of an app's Dashboards page. A **widget** is one card on it: a
saved query plus how to draw its result. An **app** is what the API's JSON sometimes calls a
workspace; `<APP_ID>` is its id.

Everything a card says here is written by the platform, once, and is the same text the screen
shows. Relay it; do not rephrase it into something the platform did not say.

## Start here

```bash
"$TORANA" apps list                                   # find the app's id
"$TORANA" dashboards list --app-id <APP_ID>           # its dashboards, in the screen's tab order
"$TORANA" dashboard <DASHBOARD_ID> render             # one dashboard: one card per widget
"$TORANA" widget <WIDGET_ID> render                   # one widget's card
"$TORANA" app <APP_ID> widgets list                   # every widget of the app: health, freshness, status
```

`"$TORANA" dashboard <DASHBOARD_ID> widgets list` lists the widgets on a dashboard (names and
ids only) when you need a widget's id.

## How to read a card

```
<Widget title>   [table]
  <The widget's one-line description.>
  Health      ▲ Blocked — yours. This widget cannot return anything on this account: 1 of the <N> fields it reads are not being supplied.
              Owner: your setup — a tool needs connecting or configuring
  Freshness   ⚠ Stale — oldest data is from <date and time, UTC> (<how long ago>)
              What to do: <the platform's next step, naming the transformer or integration>
              Data as of <how long ago> · Last push <how long ago> · Query ran <how long ago>
              Where: Find “<transformer name>” in Data Transformers
  Empty       ○ Nothing to show yet. Your <integration name> sync is failing, so this has stopped updating.
              Affects <table.field>
  cli: torana widget <WIDGET_ID> render
```

| Part | What it tells you |
|---|---|
| Title, `[type]`, description | What the widget shows. `widget <ID> render` also prints "How to read this:", the author's longer explanation. |
| **Health** | Whether every field the widget reads is being supplied. Printed only when something is not. States: `✓ Healthy`, `◐ Degraded` (it returns rows, some fields are empty), `▲ Blocked — yours` (you need to connect or configure a tool), `✕ Blocked — ours` (the platform does not collect it yet), `? unknown`. The **Owner** line says who can close the gap. |
| **Freshness** | `⚠ Stale` means the data is older than it should be. "What to do" is the platform's own next step; "Where" names the transformer or integration to look at. A card that is not stale shows only the data-age line. |
| **Empty** / **Failed** | Why the card shows nothing (below). |
| rows | The table, series or value. Cells are never cut short. A long table is followed by its row count. |
| `cli:` | The command that prints this card again. |

**The three reasons a card shows nothing, and who fixes each:**

| The card says | What happened | Who fixes it |
|---|---|---|
| `○ Nothing to show yet. <reason>` and `Affects <fields>` | A supply gap: data the widget needs is not arriving (a tool is not connected, a sync is failing, a field is not reported). | The **Owner** on the Health line. |
| `○ No data available. The query ran and returned no rows.` | Nothing matches right now. This is often the correct answer ("critical findings opened today: none"). | Nobody. |
| `✕ This widget could not be loaded. <message>` | The widget's query failed. | Whoever maintains the widget, starting from the message. |

## Which command answers which question

| Question | Command |
|---|---|
| Why is this widget empty, and who needs to fix it? | `"$TORANA" widget <WIDGET_ID> render --section empty --section health` |
| Every field it is missing, and why | `"$TORANA" widget <WIDGET_ID> health` (add `--all` for the full list) |
| Is it stale, and what do I do about it? | `"$TORANA" widget <WIDGET_ID> render --section freshness` (also lists each table behind it) |
| Why is the number what it is? | `"$TORANA" widget <WIDGET_ID> why` |
| Where does the data come from? | `"$TORANA" widget <WIDGET_ID> provenance` |
| Which records are behind one number? | `"$TORANA" widget <WIDGET_ID> decompose --key <COL>=<VALUE>` |
| More rows than the card shows | `"$TORANA" widget <WIDGET_ID> explore --page 2` |
| The widget's SQL | `"$TORANA" widget <WIDGET_ID> explore --show-sql` |

`--section` takes `about`, `health`, `freshness`, `empty`, `data`, and can be repeated. Without
it you get every part. `--refresh` runs the query again now; without it a result up to 30
minutes old is reused (the card's "Query ran …" says how old).

## Ask the assistant about a widget

⛔ Never run `widget <WIDGET_ID> chat`, even when the customer asks for the widget's chat (rule: SKILL.md, "You answer; you never drive Torana's agents"). Explain the widget yourself: read it with `widget <WIDGET_ID> render --section empty --section health` and the commands above. The commands below are listed so you can recognise them.

```bash
"$TORANA" widget <WIDGET_ID> chat -m "Why did this number go up this week?"
"$TORANA" widget <WIDGET_ID> chat -m "Which teams own these?" --json     # {chat_id, status, reply, ...}
"$TORANA" widget <WIDGET_ID> chat-enabled                                 # is widget chat switched on for this account
```

This is the "ask about this widget" button on a card. It opens a chat with the Ask AI
assistant pinned to the widget, sends the question and waits for the reply (a reply can
take a minute or two; `--timeout` sets how long to wait, default 300 seconds). The reply is
on stdout; the chat's id is on stderr as `[chat <CHAT_ID>]`. Each call opens its own chat: to
ask a follow-up in the same one use `"$TORANA" chat <CHAT_ID> send -m "..."`.

Exit codes: 0 the assistant replied · 7 it stopped to ask you something (answer with
`"$TORANA" chat <CHAT_ID> answer`) · 8 the turn failed, timed out or was cancelled · 9 with
`--no-wait`, a turn is already running · 3 no such widget, or the assistant is not available
on this account. Chat commands are covered in [chat.md](chat.md).

## Sweep an app: which widgets are stale or broken?

```bash
"$TORANA" app <APP_ID> widgets list --fail-on stale --fail-on error
"$TORANA" app <APP_ID> widgets list --refresh --fail-on stale --fail-on empty --fail-on error
"$TORANA" app <APP_ID> widgets list --json          # items[]: name, health_state, status, freshness, reason, id
```

One row per widget: HEALTH, STATUS (`success` / `no_data` / `error`), ROWS, FRESHNESS
(`fresh` / `stale` / `unknown` / `pushed`), the dashboards it is on, its id. HEALTH and STATUS
are different questions: a degraded widget still returns rows, and a widget with `no_data` can
be perfectly healthy. A large app takes a while (the health check is the slow part);
`--no-render` gives health alone.

**Exit codes** (the same for `dashboard <ID> render`, `widget <ID> render` and the sweep):

| Exit | Meaning |
|---|---|
| 0 | Everything rendered and nothing matched `--fail-on`. An empty widget is exit 0 unless you pass `--fail-on empty`. |
| 1 | A widget failed to render (with or without `--fail-on`), or a widget matched `--fail-on stale` / `empty`. One line on stderr says what matched. The cards, or the JSON, are still printed. |
| 2 | A wrong option, or a `--widget` that is not on the dashboard. |
| 3 | No dashboard, or no widget, has that id. |

`--json` on `dashboard <ID> render` returns `{dashboard, widgets, summary, failed_on}`:
`summary` counts `ok`, `empty`, `error`, `stale` and `unhealthy`; each entry of `widgets`
carries `card` (the sentences above) and `health`.

## Editing

A widget needs a query, then the widget, then a place on a dashboard.

```bash
# 1. the query (q.json: {"sql_command": "SELECT severity, count(*) AS n FROM vulnerabilities GROUP BY severity", "workspace_id": "<APP_ID>"})
"$TORANA" queries create --name "Open by severity" --file q.json

# 2. the widget, attached to a dashboard in the same step
#    (w.json: {"widget_type": "table", "display_config": {"columns": ["severity", "n"]}})
"$TORANA" widgets create --name "Open by severity" --dashboard-id <DASHBOARD_ID> \
    --app-id <APP_ID> --query-id <QUERY_ID> --file w.json

# 3. look at it
"$TORANA" dashboard <DASHBOARD_ID> render --widget <WIDGET_ID>
```

`display_config` is required and differs per `widget_type`; the names in it must be columns
the query returns:

| `widget_type` | `display_config` |
|---|---|
| `table` | `{"columns": ["col_a", "col_b"]}` |
| `scalar` | `{"value_column": "n", "label": "Open criticals"}` |
| `bar`, `line` | `{"x_axis": "severity", "y_axis": "count"}` |
| `pie` | `{"x_axis": "...", "y_axis": "...", "label_field": "severity", "value_field": "count"}` |

```bash
"$TORANA" dashboards create --name "Security Overview" --app-id <APP_ID>
"$TORANA" dashboard <DASHBOARD_ID> update --name "New name"
"$TORANA" dashboard <DASHBOARD_ID> widgets add <WIDGET_ID>        # an existing widget
"$TORANA" dashboard <DASHBOARD_ID> widgets remove <WIDGET_ID> --yes   # off the dashboard; the widget stays
"$TORANA" dashboard <DASHBOARD_ID> move --target-app-id <APP_ID>
"$TORANA" dashboard <DASHBOARD_ID> delete --yes                   # the dashboard only; its widgets stay

"$TORANA" widget <WIDGET_ID> update --name "New title"
"$TORANA" widget <WIDGET_ID> update --sql "SELECT severity, count(*) AS n FROM vulnerabilities WHERE severity = 'Critical' GROUP BY severity"
"$TORANA" widget <WIDGET_ID> update --file w.json                 # widget_type and display_config TOGETHER
"$TORANA" widget <WIDGET_ID> delete --yes
```

- **`widget <ID> update --sql`** runs the new SQL once before saving it. Exit 6 means the new
  SQL did not run (a typo, a column that does not exist, not a SELECT): nothing was changed, and
  the database's message is printed. Fix the SQL and run the command again. A query used by other
  widgets is refused (their numbers would change too) unless you pass `--allow-shared`.
- **`widget <ID> delete`** does what the screen's delete button does: takes the widget off every
  dashboard of its app, deletes it, and deletes its query. The query is kept when another widget
  uses it, or with `--keep-query`; the output says which.
- **`widget <ID> move --target-app-id`** can be refused with "Permission denied - requires
  widget:update" even for an account that can update the same widget. That is a platform defect,
  not something to work around; move the dashboard, or recreate the widget in the other app.

## Authoring rules

- Do not build a widget that reports platform health or data freshness. The Stale badge and the
  Health line on every card already say it, from the platform's own records.
- A description says what the widget shows and how to read it, in words that stay true on any
  account. No counts, names or dates from one environment.
- Use placeholders (`<APP_ID>`, `<DASHBOARD_ID>`, `<WIDGET_ID>`) in anything you write down for
  someone else.

## Operator commands (not for everyday use)

Still callable, not listed in `--help`: `"$TORANA" active-dashboards list | create | delete`
(the list can answer "not found" on a platform where the feature is not deployed),
`"$TORANA" plan <PLAN_ID> dashboard add | delete | get | list | update` and
`"$TORANA" plan <PLAN_ID> widget add | delete | get | list | update` (dashboards and widgets as
artifacts of a plan). `"$TORANA" widget <WIDGET_ID> verdict` is a one-word classification that
often answers `unknown`; use `render --section empty --section health` instead.
