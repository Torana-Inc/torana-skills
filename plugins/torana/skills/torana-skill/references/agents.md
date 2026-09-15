---
name: agents
description: Build, configure, publish, and use AI agents in the Torana platform. Use this skill when users want to create agents, add tools to agents, publish or activate agents, chat with agents, check agent health, manage prompts, view audit logs, or troubleshoot agent issues. Covers the full agent lifecycle from creation through production use.
version: "2.0"
last_updated: "2026-04-16"
platform_version_tested: "2026.1"
---

# Agents — Torana Platform (CLI)

AI agents in Torana are intelligent assistants powered by LLMs that can analyze security data, call
external APIs, delegate to other agents, and stream answers in real time. All agent operations are
performed through the `torana` CLI — no curl, no raw API calls.

---

## Bootstrap — Install & Authenticate

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap — the canonical
one.** It is not repeated here on purpose: a copied block drifts from the original, and a
stale bootstrap makes real commands look missing (the exact wrong conclusion the surface
check exists to prevent). Every command on this page assumes `"$TORANA"` is set by it.

---

## Core Concepts

### What is an Agent?

An agent is an AI-powered assistant with a specific identity, purpose, and set of capabilities. Each agent has:

- **Name and description** — human-readable identification
- **Instructions** — detailed behavior guidelines written in plain language, combined at runtime with any assigned prompt template
- **Prompt** — an optional reusable template from the platform's prompt library, prepended to the agent's own instructions
- **Model** — the LLM powering the agent (Claude, Gemini, GPT variants)
- **Model config** — temperature, max tokens, and provider-specific settings such as Gemini thinking budget
- **Tools** — the external capabilities the agent can call during a conversation
- **Tags** — comma-separated labels for categorisation and feature flags (e.g., `use-ag-ui:true`)

Agents do not hold conversation state themselves. State lives in **sessions** managed by the platform.

### Agent Types

| Type | Role | Use Case |
|---|---|---|
| **SIMPLE** | Standalone assistant with its own tools | Security Analyst, Dashboard Agent, Vulnerability Triage |
| **ROOT** | Orchestrator that delegates to sub-agents | Program Manager, Workflow Orchestrator |
| **SUB** | Specialist called by a root agent | Detection Planner, Data Transformer, SIEM Query Agent |

A ROOT agent does not call APIs directly. It decomposes user requests and delegates work to SUB agents, then synthesises their answers. A SUB agent can itself be a ROOT, creating a hierarchy.

### Key Terminology

| Term | Definition |
|---|---|
| **Agent** | The configured AI assistant entity with instructions, tools, and a model |
| **Session** | A stateful multi-turn conversation between a user and an agent |
| **Tool** | An external capability the agent can invoke — an API, another agent, or a function |
| **Prompt** | A reusable instruction template from the library, prepended to agent instructions |
| **Version** | An independent iteration of an agent (same name, different config/instructions) |
| **Health** | The ratio of tools successfully loaded vs tools intended — healthy, degraded, or error |
| **Audit log** | A complete record of one agent execution: tokens, cost, tool calls, timing |
| **Correlation ID** | UUID linking all logs for a single user request across turns |

### Tools — Four Types

**1. Integration tools** — call REST APIs discovered from the Workflow Framework

- Reference format: `provider:uuid`, `api_group:uuid`, or `api:uuid`
- Bearer token authentication is injected automatically
- Example: `api:550e8400-e29b-41d4-a716-446655440000`
- The platform converts these references into OpenAPI toolsets at agent load time

**2. Agent tools** — use another published and active agent as a tool

- Reference format: the agent's UUID string (not prefixed)
- Enables ROOT → SUB delegation hierarchies
- The referenced agent must be PUBLISHED and active (`is_active=true`) before the parent can be published
- Example: `f47ac10b-58cc-4372-a567-0e02b2c3d479`

**3. Function tools** — custom functions defined in the platform database

- Types: `function`, `code_interpreter`, `file_search`
- Defined separately and referenced by name

**4. UI component tools** — interactive frontend widgets rendered in chat

- Tagged with `use-ag-ui:true` on the agent; the AG-UI prompt is automatically injected

---

## States & Lifecycle

### Agent States

Agents move through a strict state machine. The database records two orthogonal dimensions: `state` (DRAFT or PUBLISHED) and `is_active` (boolean). "ACTIVE" in human terms means PUBLISHED + is_active=true.

| State | state field | is_active | Editable? | Usable in chat? |
|---|---|---|---|---|
| **DRAFT** | draft | false | Yes | No |
| **PUBLISHED** | published | false | No | No — immutable but not yet live |
| **ACTIVE** | published | true | No | Yes |
| **INACTIVE** | published | false | No | No — was active, now deactivated |

### State Transitions

| Transition | Endpoint | Pre-conditions |
|---|---|---|
| DRAFT → PUBLISHED | publish | Name + description must be set; for ROOT agents all child agents must themselves be PUBLISHED; no circular dependencies |
| PUBLISHED → ACTIVE | activate | Agent must be PUBLISHED; for ROOT agents all child agents must be ACTIVE |
| ACTIVE → INACTIVE | deactivate | Agent must be ACTIVE |
| PUBLISHED → DRAFT (new version) | new-version | Agent must be PUBLISHED; creates a DRAFT copy with version incremented |

### Lifecycle Overview

```
CREATE (DRAFT) → ADD TOOLS → WRITE INSTRUCTIONS → PUBLISH → ACTIVATE → CHAT
                                                                 ↓
                                                          DEACTIVATE → NEW-VERSION → (loop)
```

---

## How It Works

### Building a New Agent

1. Create the agent in DRAFT state. Choose agent type (simple/root/sub), write initial instructions, pick a model.
2. Optionally assign a prompt from the library — the prompt's content will be prepended to your instructions.
3. Add tools one at a time. Use integration tools for REST APIs, agent tools for sub-agents.
4. Test instructions and refine in DRAFT. The agent is not callable in chat yet.
5. Publish — the agent is now immutable and validated. Publishing fails if required child agents are not published.
6. Activate — the agent is now live and callable.

For ROOT agents: all sub-agents must be built, published, and activated first. Then create the root agent and add the sub-agent UUIDs as `agent` type tools. Publish and activate the root last.

### Chatting with an Agent

1. Create a session. Returns a `session_id`.
2. Send a message with `session_id` and message content. The response streams via Server-Sent Events (SSE).
3. The agent processes the message, calls tools as needed (each tool call is transparent in the event stream), and streams its answer.
4. Retrieve full history via sessions history command.

The SSE stream sends events for: thinking, tool invocations with inputs, tool results, text chunks, and a final done event.

### Hierarchical Agent Execution

When a ROOT agent receives a message it:
1. Analyses the request and decides which sub-agents to invoke.
2. Calls each sub-agent as a tool call. The sub-agent executes with its own tools and returns a result.
3. Synthesises all sub-agent results into a final answer.
4. Streams the combined answer back to the user.

### Versioning

Every `publish` action freezes an agent version. To change a published/active agent:
1. Call `new-version` — creates a DRAFT copy with `version` incremented.
2. Edit the new draft.
3. Publish and activate the new version.
4. The old version can be deactivated independently.

---

## Multi-Tenant Considerations

All agents are scoped by `tenant_id` and `namespace_id`. An agent created by Tenant A is never visible to Tenant B.

- **Tenant admin** sees only their tenant's agents.
- **Regular users** interact with agents via chat but cannot create or modify agents unless granted `agents:create`/`agents:update` permissions.

Prompts with `is_public=true` are visible to all tenants. Custom prompts created within a tenant are private to that tenant.

Agent tools referencing sub-agents must reference agents within the same tenant. Cross-tenant agent delegation is not supported.

---

## Troubleshooting Guide

### Common Issues

| Issue | Symptoms | Root Cause | Fix |
|---|---|---|---|
| **Agent health degraded** | Health score < 1.0; health shows missing tools | An integration API or sub-agent referenced in tools was deleted or became unavailable | Use drift command to list missing tools; delete stale tool references and add valid ones; or reconcile with `remove_stale=true` |
| **Agent will not publish** | publish returns error | Missing name/description, or for ROOT agents a child agent is not yet published, or circular dependency detected | Check all required fields; ensure all child agents are PUBLISHED; check for loops in agent→sub-agent references |
| **Chat returns no response** | Stream completes with no text | Agent not ACTIVE, or upstream LLM quota exhausted, or Gemini empty-STOP bug triggered | Verify agent is PUBLISHED + active; check audit logs for error status; for Gemini set `thinking_budget` in `provider_config` |
| **Tool calls fail during chat** | Audit log shows tool execution errors | Integration API is down, credentials expired, or tool reference format is wrong | Check Workflow Framework health; verify integration credentials; confirm `api:uuid` format is correct |
| **Agent changes not visible** | Updated agent but behaviour unchanged | PUBLISHED agents are immutable; update created a new version but the old version is still active | Confirm the new version was published and activated; deactivate the old version if needed |
| **Circular dependency error** | Publish fails with circular dependency message | Agent A includes Agent B as a tool, and Agent B includes Agent A as a tool | Redesign the hierarchy; a sub-agent cannot reference its own parent |

### Diagnostic Approach

1. Check agent state and `is_active`.
2. Check health score — look at `intended_tools_count` vs `loaded_tools_count`.
3. Check drift — lists tools in the database config that no longer exist in the integration catalogue.
4. For chat failures, get the `correlation_id` from the error event, then query audit logs and look for `ERROR` status entries.
5. For tool failures, look at `tool_execution_details` in the audit log — each tool shows input, output, duration, and success flag.

---

## Best Practices

1. **Start with SIMPLE before ROOT** — build and validate each sub-agent independently before wiring them into a root orchestrator.
2. **Write clear, scoped instructions** — tell the agent exactly what it should and should not do. Use the prompt library for common security personas.
3. **Test one tool at a time** — add tools incrementally and chat-test after each addition.
4. **Use the prompt library** — the platform ships 44+ pre-built prompts for common security roles.
5. **Monitor health after deployment** — a degraded health score means tools are missing and the agent will silently skip those capabilities.
6. **Version before every change** — never edit a live agent in place.
7. **Set a thinking budget for Gemini** — always set `provider_config.gemini.thinking_budget` (e.g., 8000) when using Gemini models to prevent MALFORMED_FUNCTION_CALL and empty-STOP errors.
8. **Clean up test agents** — tag test agents with `test-agent:true` and delete them when done.

---

## Discovering Commands

The CLI is the source of truth. Use plural to list, then singular + `--help` to discover instance commands:

```bash
"$TORANA" agents list                   # get IDs
"$TORANA" agent <id> --help             # see all commands for that agent
"$TORANA" agents --help
"$TORANA" agents create --help
"$TORANA" prompts --help
"$TORANA" agent-tools --help
```

## Typical Workflows

### Create, publish, and activate an agent

```bash
# Create a draft agent
"$TORANA" agents create \
  --name "Vulnerability Analyst" \
  --description "Analyzes CVEs and provides remediation guidance" \
  --agent-type simple \
  --instructions "You are a security expert..."

# Add a tool
"$TORANA" agent <agent-id> tools add --tool-type integration --tool-reference "api:<uuid>"

# Publish the agent
"$TORANA" agent <agent-id> publish

# Activate the agent
"$TORANA" agent <agent-id> activate

# Verify state
"$TORANA" agent <agent-id> get
```

### Start a chat session

```bash
# Create a session
"$TORANA" agent <agent-id> sessions create

# Chat (session-id from above)
"$TORANA" agent <agent-id> chat --session-id <session-id> --message "What is CVE-2024-1234?"

# View conversation history
"$TORANA" agent <agent-id> sessions history <session-id>
```

### Check agent health

```bash
"$TORANA" agent <agent-id> health
"$TORANA" agents health-summary
"$TORANA" agent <agent-id> drift
"$TORANA" agent <agent-id> reconcile
```

### Manage prompts

```bash
"$TORANA" prompts list
"$TORANA" prompt <id> get          # instance op — singular form
"$TORANA" prompts popular
```

### View audit logs

Audit logs are a top-level group, not a sub-command of `agents`:

```bash
"$TORANA" audit-logs list --agent-id <id>
"$TORANA" audit-logs list --agent-id <id> --format json
"$TORANA" audit-logs --help        # sessions, turns, trace, token summaries
```

---

## Error Reference

| CLI output | Meaning | Fix |
|---|---|---|
| `Not authenticated` | No cached token | Run OAuth login (see bootstrap) |
| `Session expired` | Refresh token invalid | Re-run OAuth login |
| `403 Forbidden` | Token missing scope | Re-auth with correct account |
| `Cannot reach <url>` | Wrong base-url or network | `"$TORANA" config get base-url`; verify tunnel |

<!-- CHANGELOG
v1.0 (2026-02-28) - Initial skill creation
v2.0 (2026-04-16) - Migrated execution mechanics to torana CLI; removed curl/tg/tp/td
-->
