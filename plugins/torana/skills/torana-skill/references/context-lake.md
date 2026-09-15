---
name: context-lake
description: >
  Manage Torana Context Lake — the persistent memory and preference store for AI agents. Use
  this skill when users want to store or retrieve agent memory, manage user preferences, view
  context lake collections, query stored context, or troubleshoot why an agent is not
  remembering information across sessions.
version: "1.0"
last_updated: "2026-04-16"
platform_version_tested: "2026.1"
---

# Context Lake — Torana Platform (CLI)

The Torana Context Lake provides persistent, tenant-scoped memory for AI agents. Unlike session
state (which is lost when a chat ends), Context Lake stores information across sessions —
user preferences, agent memory, assembled context, and learned facts that persist indefinitely.
All operations go through the `torana` CLI — no curl, no raw API calls.

---

## Bootstrap — Install & Authenticate

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap — the canonical
one.** It is not repeated here on purpose: a copied block drifts from the original, and a
stale bootstrap makes real commands look missing (the exact wrong conclusion the surface
check exists to prevent). Every command on this page assumes `"$TORANA"` is set by it.

---

## Core Concepts

### What Is the Context Lake?

The Context Lake is the persistent memory subsystem for Torana AI agents. It solves the
fundamental problem of agents losing all learned information at the end of a session.

The Context Lake has four distinct feature areas:

| Feature | Env Flag | What it stores |
|---|---|---|
| **User Memory** | `CONTEXT_LAKE_USER_MEMORY_ENABLED` | Facts the agent learns about the user — name, role, preferences, past requests |
| **User Preferences** | `CONTEXT_LAKE_USER_PREFERENCES_ENABLED` | Explicit user preference key-value pairs (e.g., `preferred_format: table`) |
| **Assembly** | `CONTEXT_LAKE_ASSEMBLY_ENABLED` | Pre-assembled context blobs injected into agent prompts at session start |
| **Context Lake (master)** | `CONTEXT_LAKE_ENABLED` | Master switch; must be `true` for any feature to work |

### Memory vs Preferences

**Memory** — Unstructured facts about a user or their environment, learned organically during
conversation. The agent summarizes and stores these automatically. Examples:
- "User is a senior security analyst focused on cloud infrastructure"
- "User prefers concise answers with bullet points"
- "User's primary environment is AWS with Kubernetes"

**Preferences** — Explicit key-value settings that persist across sessions. Examples:
- `preferred_output_format: table`
- `default_severity_filter: high`
- `always_include_remediation: true`

### Assembly

Assembly is a mechanism for pre-loading relevant context into an agent's system prompt at
session start, before the user sends any message. The assembly service queries the context
lake for facts relevant to the user and injects them as a structured context block.

This means an agent can greet a returning user with relevant context without the user having
to re-explain who they are or what they are working on.

### Storage

Context Lake uses two storage backends:
- **PostgreSQL** — structured preference records, assembly configs, metadata
- **Qdrant** — vector store for semantic search over memory entries

Memory entries are embedded using the configured embedding model and stored in Qdrant so
the agent can retrieve semantically relevant memories based on the current conversation.

---

## States and Lifecycle

### Memory Entry States

| State | Meaning |
|---|---|
| `active` | Memory entry is live and will be retrieved by agents |
| `archived` | Memory entry is preserved but excluded from retrieval |
| `expired` | Memory entry has passed its TTL and will not be retrieved |

Memory entries have an optional `ttl_days` field. After `ttl_days` days, the entry is
automatically excluded from retrieval (though it remains in the database for audit).

### Preference States

Preferences are key-value pairs with no lifecycle state. Setting a preference updates it
immediately. Deleting a preference removes it. There is no draft or approval step.

---

## How It Works

### Memory Storage Flow

1. During a conversation, the agent recognizes a fact worth remembering
2. The agent calls the `store_memory` tool with the fact text
3. The Context Lake service embeds the text using the configured embedding model
4. The embedding and metadata are stored in Qdrant under the user's namespace
5. The fact is also stored in PostgreSQL with metadata (source, agent_id, created_at, ttl)

### Memory Retrieval Flow

1. At the start of a session (or during a conversation), the agent calls `retrieve_memories`
2. The query text is embedded
3. Qdrant performs a semantic similarity search against the user's stored memories
4. The top-k most relevant memories (above the score threshold) are returned
5. The agent uses these memories as context for its responses

### Preference Update Flow

1. During a conversation, the user expresses a preference (or the agent infers one)
2. The agent calls `update_preference(key, value)` to persist it
3. The preference is stored in PostgreSQL and mirrored to session state for same-session reads
4. On the next session start, the preference is available immediately without re-stating it

### Assembly Flow

1. At session start, the assembly service is invoked with the user's context (user_id, tenant_id, namespace_id)
2. The service queries PostgreSQL for explicit preferences
3. The service queries Qdrant for high-relevance memory entries
4. Both are formatted into a structured context block
5. The context block is prepended to the agent's system prompt before the user's first message

---

## Multi-Tenant Considerations

Context Lake enforces strict tenant and user isolation:

- Memory entries are scoped by `tenant_id`, `namespace_id`, and `user_id`
- Qdrant collection names are namespaced; cross-tenant queries are impossible
- A user can only access their own memories and preferences
- Tenant admin can view (but not modify) any user's stored context within their tenant
- Context is never shared across tenants

---

## Troubleshooting Guide

### Agent is not remembering information across sessions

**Check list:**
1. Is `CONTEXT_LAKE_ENABLED=true` in the environment? This is the master switch.
2. Is `CONTEXT_LAKE_USER_MEMORY_ENABLED=true`? Memory requires this feature flag.
3. Does the agent have the `store_memory` and `retrieve_memories` tools loaded? Check agent health.
4. Is Qdrant reachable? Memory uses Qdrant for vector storage.
5. Was the memory actually stored? Use `context-lake memory list` to check entries for the user.

### Agent is not applying user preferences

**Check list:**
1. Is `CONTEXT_LAKE_USER_PREFERENCES_ENABLED=true`?
2. Is the preference actually stored? Use `context-lake preferences list` to verify.
3. Is the agent using `update_preference` (the persistent version) or `set_user_preference` (the deprecated session-only version)?
4. Is the assembly feature enabled? Without assembly, preferences won't be injected at session start.

### Memory search returning irrelevant results

- The embedding model dimensions must match the Qdrant collection dimensions (768 for most models)
- If the Gemini embedding model is used, `output_dimensionality` must be explicitly set to 768 (Gemini returns 3072 by default)
- The CLI has no `memory search` verb — retrieval happens inside the agent turn. Exercise
  the agent and inspect what it recalled, and use `context-lake memory list` to confirm the
  entries exist in the first place

### Memory entries not expiring

Memory TTL is enforced at query time (entries past their TTL are filtered out), not by a background job. There is no bulk `cleanup` verb — expired entries stay in the store and are simply never returned. To remove one explicitly, use `context-lake memory delete <memory-id>`.

---

## Best Practices

1. **Enable the master switch first.** `CONTEXT_LAKE_ENABLED=true` must be set before any per-feature flags have effect.

2. **Use assembly for high-value agents.** Enable assembly for agents that benefit from knowing who the user is from the first message (e.g., a personal security analyst agent). Disable it for stateless query agents where user context is irrelevant.

3. **Set memory TTLs for sensitive facts.** If an agent stores sensitive information (e.g., specific vulnerability details about an asset), set a short TTL (e.g., 7 days) so stale security facts don't persist indefinitely.

4. **Prefer `update_preference` over `set_user_preference`.** The `set_user_preference` tool is deprecated — it only persists for the current session. `update_preference` writes to the Context Lake and persists across sessions.

5. **Monitor embedding dimensions.** When switching embedding models, verify the vector dimensions match the Qdrant collection. A mismatch causes silent insertion failures.

6. **Use scoped memory queries.** When retrieving memories, always scope by `user_id` and optionally by `agent_id` to avoid cross-contamination between different users or different agents' memories.

---

## Discovering Commands

> ⚠️ **This is the one group where `--help` browsing does NOT guide you.** Most of
> `context-lake --help` is a flat wall of auto-generated `admin-*` / `superadmin-*` /
> `*-by-<param>` commands whose docstrings only restate the endpoint name
> ("Admin Get Candidate Context."). **Use the four curated sub-groups below.** Treat
> everything else in that listing as low-signal: it works, but it will not teach you
> what it does.

**The curated sub-groups — these are the ones to use:**

| Sub-group | Verbs | For |
|---|---|---|
| `context-lake memory` | `list` · `get` · `create` · `delete` | stored memory entries |
| `context-lake preferences` | `list` · `get` · `set` · `delete` | persistent user preferences |
| `context-lake entity-links` | `list` · `get` · `create` · `delete` | cross-service entity relationships |
| `context-lake feedback` | `list` · `get` · `submit` | thumbs up/down quality signal |

⚠️ **`memory` is singular.** There is no `memories` group — that name is rejected.

```bash
"$TORANA" context-lake memory --help
"$TORANA" context-lake preferences --help
"$TORANA" context-lake entity-links --help
"$TORANA" context-lake feedback --help
```

Flat admin/stats commands that are still worth knowing (they carry no sub-group):

```bash
"$TORANA" context-lake memory-enabled       # is memory saving switched on?
"$TORANA" context-lake feedback-enabled     # is feedback capture switched on?
"$TORANA" context-lake memory-stats         # admin: memory store stats
"$TORANA" context-lake assembly-config      # admin: current assembly config
"$TORANA" context-lake assembly-stats       # admin: assembly run stats
```

## Typical Workflows

### Inspect stored memories for a user

```bash
# List memory entries (paginated)
"$TORANA" context-lake memory list
"$TORANA" context-lake memory list --page 2 --page-size 50

# Get a specific memory entry
"$TORANA" context-lake memory get <memory-id>

# Create / delete
"$TORANA" context-lake memory create --help
"$TORANA" context-lake memory delete <memory-id>
```

⚠️ **There is no `memory search` verb.** Semantic retrieval is what the *agent* does at
turn time via its `recall` tool; the CLI exposes the store, not the search. To test
retrieval, exercise the agent, then inspect what it recalled.

### Manage user preferences

```bash
# List all preferences
"$TORANA" context-lake preferences list

# Get a specific preference
"$TORANA" context-lake preferences get preferred_output_format

# Set a preference
"$TORANA" context-lake preferences set preferred_output_format table

# Delete a preference
"$TORANA" context-lake preferences delete preferred_output_format
```

### Inspect assembly configuration

```bash
"$TORANA" context-lake assembly-config     # current assembly config (admin)
"$TORANA" context-lake assembly-stats      # assembly run stats (admin)
```

⚠️ **There is no `assembly` group and no `assembly preview` verb** — these are two flat
commands, hyphenated. The per-turn Context Preview (what *would* be injected) is an
admin **UI** panel, not a CLI verb.

### Entity links and feedback

```bash
# Cross-service entity relationships (CVE → affected assets, etc.)
"$TORANA" context-lake entity-links list
"$TORANA" context-lake entity-links get <link-id>

# Quality signal
"$TORANA" context-lake feedback list
"$TORANA" context-lake feedback submit --help
```

⚠️ **There is no `collections` group.** Vector storage is an implementation detail of the
memory service and is not exposed as a CLI-managed collection surface.

---

## Error Reference

| CLI output | Meaning | Fix |
|---|---|---|
| `Not authenticated` | No cached token | Run OAuth login (see bootstrap) |
| `Session expired` | Refresh token invalid | Re-run OAuth login |
| `403 Forbidden` | Token missing scope | Re-auth with correct account |
| `Cannot reach <url>` | Wrong base-url or network | `"$TORANA" config get base-url`; verify tunnel |
| `Context Lake disabled` | Master switch is off | Set `CONTEXT_LAKE_ENABLED=true` in environment |
| `Dimension mismatch` | Embedding model changed, Qdrant collection not updated | Re-create the collection with the new dimension; re-embed existing memories |

<!-- CHANGELOG
v1.0 (2026-04-16) - Initial CLI-based context lake skill
-->
