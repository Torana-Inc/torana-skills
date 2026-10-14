# Chat: Torana's Ask AI assistant

Hold a conversation with Torana's Ask AI assistant from the CLI: ask, wait for the reply,
answer the questions it asks you, and find or stop your chats.

> ⛔ **Read chats; never drive them.** You may list chats, read a chat's history and see which
> are waiting on the customer (`chats list`, `chat <CHAT_ID> history`, `chat <CHAT_ID> status`,
> below under "Find, read, stop, steer, rename"). Never run `chats start`, `chat <CHAT_ID> send | answer | steer`
> or `widget <WIDGET_ID> chat`, even when the customer asks you to "ask Torana's assistant" or "use
> the Chat tab". Say in one line that this plugin answers from the platform itself and that Ask AI
> is in the product's Ask AI page, then answer the question yourself with the CLI: the app's
> artifacts first, then the `torana-data-analyst` skill. Show a question a chat is waiting on to
> the customer; never answer it for them. The rest of this page describes what the commands do so
> you can read their output; it is not an invitation to run the ones above.

> Words: an **app** is a workspace in the API (`--app-id` takes its id; find it with
> `"$TORANA" apps list`). A **chat** is a session in the API: the `chat_id` you see in the
> output is the same value as `session_id`.

## Which assistant

| You want to… | Use | The agent it talks to |
|---|---|---|
| Ask AI, scoped to an app | `chats start --agent "$ASK_AI_ID" --app-id <APP_ID>` (find the id below) | The "Ask AI Orchestrator" agent |
| Ask about one widget, as the widget's chat icon does | `widget <WIDGET_ID> chat` (see `references/workspaces.md`) | The "Ask AI Orchestrator" agent |

**Find Ask AI by name; never hard-code an id.** It is the published, active agent named exactly `Ask AI Orchestrator`:

```bash
ASK_AI_ID=$("$TORANA" --json agents list --search "Ask AI Orchestrator" --no-health \
  | jq -r '.items[] | select(.name=="Ask AI Orchestrator" and .state=="published" and .is_active) | .id' | head -1)
```

If nothing comes back, Ask AI is not available on this account: tell the customer to use the Ask AI page, and
stop. Never fall back to another agent.

## Ask and wait

```bash
# Ask. The command waits for the reply (default up to 300 s) and prints it.
"$TORANA" chats start --agent "$ASK_AI_ID" --app-id "$APP_ID" -m "What should I look at first in this app today?"

# For a script or an agent: JSON. Keep chat_id to continue the conversation.
"$TORANA" --json chats start --agent "$ASK_AI_ID" --app-id "$APP_ID" -m "Summarise what changed in this app this week" \
  | jq -r '.reply, .chat_id, .status'

# Continue the same chat
"$TORANA" chat "$CHAT_ID" send -m "Which of those are internet-facing?"
"$TORANA" --json chat "$CHAT_ID" send -m "Reply with exactly the word OK." | jq -r .reply

# Watch the reply being written (tool steps go to stderr)
"$TORANA" chat "$CHAT_ID" send -m "Summarise the top three." --stream

# A long question from a file; allow more time
"$TORANA" chat "$CHAT_ID" send --message-file question.txt --timeout 600

# Open a chat with a name and ask later
"$TORANA" chats start --agent "$ASK_AI_ID" --app-id "$APP_ID" --title "Weekly remediation review"
```

JSON result of `chats start -m`, `chat <CHAT_ID> send` and `chat <CHAT_ID> answer`:

| Key | Meaning |
|---|---|
| `status` | `completed`, `waiting`, `failed`, `timeout`, `cancelled`, `wait_timeout`, `busy`, or `sent` (with `--no-wait`) |
| `reply` | EVERY assistant message of this turn, in order, joined by a blank line: its streamed text and the markdown it put on screen (`ui_markdown_display`). Tables and charts it displayed are not in `reply`; read them with `history --detail` |
| `chat_id`, `session_id` | The chat (same value) |
| `turn_id` | The turn this message started |
| `tool_steps` | The tools the assistant called, in order (`[{name}]`) |
| `pending_question` | The question it asked, when `status` is `waiting` |
| `message_sent` | `false` when the message was NOT sent (an open question, or a busy chat) |

## Exit codes: always check them

| Exit | Meaning | What to do |
|---|---|---|
| 0 | The assistant replied | Use `reply` |
| 7 | The assistant is **waiting on an answer** | Show the user the question. ⛔ Never answer it for them. Then `chat <CHAT_ID> answer …` |
| 8 | The run failed, timed out or was cancelled; or `--timeout` passed while it was still running | `chat <CHAT_ID> status`, then `chat <CHAT_ID> history` |
| 9 | A turn is already running (only with `--no-wait`) | Wait, or drop `--no-wait` |
| 2 | Usage error, including `answer` when nothing is being asked | Read the message |
| 3 | No such chat or app, or the app has no assistant | Check the id |

When `--timeout` passes, the turn **keeps running** on the server. Exit 8 then means "I stopped
waiting", not "it failed": check `status` before retrying, or you will start a second turn.

## When the assistant asks a question

The assistant sometimes stops to ask: a choice between options, a yes/no confirmation before
it changes something, or a short form. The chat then waits (for up to 24 hours).

```bash
# Chats in an app that are waiting on you
"$TORANA" chats list --agent "$ASK_AI_ID" --app-id "$APP_ID" --waiting

# Read the question, its numbered options and the command that answers it
"$TORANA" chat "$CHAT_ID" status
"$TORANA" --json chat "$CHAT_ID" status | jq '{state, question: .pending.prompt, options: .pending.options}'

# Answer. Give exactly one of these, matching the kind of question:
"$TORANA" chat "$CHAT_ID" answer --option 2                       # a numbered choice
"$TORANA" chat "$CHAT_ID" answer --text "Only the production repositories"   # your own words
"$TORANA" chat "$CHAT_ID" answer --approve                        # a confirmation: yes
"$TORANA" chat "$CHAT_ID" answer --reject --reason "Wrong dashboard"         # a confirmation: no
"$TORANA" chat "$CHAT_ID" answer --values '{"owner": "alice", "due_date": "2026-11-01"}'   # a form
```

`answer` prints the question and your answer, then waits for the assistant to continue, with
the same output and exit codes as `send` (7 again means it asked a follow-up question).

Rules that matter:

- ⛔ **`send` never answers a question.** If the chat is waiting, `send` sends nothing and
  exits 7 with the question (`message_sent: false`). This is deliberate: the server treats any
  message sent to a waiting chat as the answer.
- **A confirmation is a decision the user must make.** It usually guards a write (creating a
  dashboard, changing a rule). Show them the question and its details; run `--approve` only
  when they say yes.
- `--option` takes the number shown, or the exact label. Repeat it only when the question
  allows several (`pending.allow_multiple`).
- `--text` works for a choice question that allows your own words (`pending.allow_free_text`),
  not for a confirmation or a form.
- `answer` exits 2 with "This chat is not waiting on a question" when there is nothing to
  answer: it was already answered (here or on the screen) or it expired.

## Find, read, stop, steer, rename

```bash
"$TORANA" chats list --agent "$ASK_AI_ID" --app-id "$APP_ID"   # newest first; STATE = waiting on you | running | idle
"$TORANA" --json chats list --agent "$ASK_AI_ID" --app-id "$APP_ID" | jq '.items[] | {chat_id, name, state}'
"$TORANA" chat "$CHAT_ID" history                       # the whole conversation
"$TORANA" chat "$CHAT_ID" history --last 3                # last 3 TURNS, each shown in full (JSON: agent.text, agent.messages[])
"$TORANA" chat "$CHAT_ID" status                        # running, waiting on you, or idle
"$TORANA" chat "$CHAT_ID" stop                          # stop the running turn
"$TORANA" chat "$CHAT_ID" steer -m "Only consider the production repositories"   # redirect it instead
"$TORANA" chat "$CHAT_ID" rename --title "Weekly remediation review"
"$TORANA" chat "$CHAT_ID" delete --yes                    # soft delete; owner only; refused (exit 1) while a turn runs: stop it first
```

- `chats list` returns up to `--limit` chats (default 50, max 100). `has_more: true` in the
  JSON (a line on stderr in text) means there are more: add `--offset`.
- `stop` on a chat with nothing running says "Nothing is running in this chat." and exits 0.
- `steer` only works while a turn is running; otherwise it exits 2 and you should `send`.
- A message sent while a turn is running waits for that turn to end and is then sent.
  With `--no-wait` it is not sent and the command exits 9.

## Known limits

- `chat <CHAT_ID> delete` is a soft delete (the chat disappears from every list and read; it cannot be restored from the CLI). A tenant admin can delete any chat of the tenant; other users only their own.
- A question expires after 24 hours; the chat then goes back to idle and `send` works again.
- `chats list` needs `--agent` (Ask AI), optionally with `--app-id`: there is no list of chats across all agents.
- Token and cost figures for a turn are not in the output.
- An agent running inside the platform cannot use `chats start`, `chat … send` or
  `chat … answer` (the platform's command policy refuses commands that change something);
  it can use `chats list`, `chat … history` and `chat … status`.

