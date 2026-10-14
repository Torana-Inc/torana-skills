---
name: tenants
description: >
  Manages IAM for Torana tenant administrators — covering users, roles, permissions, tokens,
  audit logs, and activity monitoring within the tenant. Use this skill when a tenant admin
  wants to create or manage users, assign roles, create custom roles, check permissions,
  revoke tokens, or query audit and security logs. Does NOT cover tenant creation,
  namespace management, or impersonation (super admin operations).
version: "2.0"
last_updated: "2026-04-16"
platform_version_tested: "2026.1"
---

# Tenant IAM — Torana Platform (CLI)

This skill covers identity and access management for **tenant administrators**. It includes
user lifecycle management, role-based access control, token management, and audit/activity
logs. All operations go through the `torana` CLI — no curl, no raw API calls.

> **Scope:** Tenant admin operations only. Tenant creation, namespace management, tenant
> suspension/deletion, and impersonation are super admin operations not covered here.

---

## Bootstrap — Install & Authenticate

⛔ **Run the bootstrap block in [`../SKILL.md`](../SKILL.md) § Bootstrap — the canonical
one.** It is not repeated here on purpose: a copied block drifts from the original, and a
stale bootstrap makes real commands look missing (the exact wrong conclusion the surface
check exists to prevent). Every command on this page assumes `"$TORANA"` is set by it.

---

## Core Concepts

### The IAM Hierarchy

```
Tenant (Organization / Customer)
  └── Namespace (Subdivision within tenant — currently "default" for all resources)
      └── Resources (integrations, agents, dashboards, workflows, etc. in all services)
```

**Tenant** — The top-level isolation boundary. Each customer is a tenant. All data for a tenant is
isolated from other tenants. Tenants have a `domain` (e.g. `acme.com`), a `plan`, and a `status`.

**Namespace** — A subdivision within a tenant. Currently the platform uses a single `default`
namespace per tenant. The namespace_id is NOT carried in the JWT — it is derived automatically
at request time from the tenant's default namespace.

**Resources** — Everything managed by the platform (integrations, agents, workflows, etc.).
Every resource record MUST have `tenant_id`, `namespace_id`, and `is_deleted`.

### Users

Users are people who log in. Each user belongs to exactly one tenant (scoped by `tenant_id`).
Users do NOT have a `namespace_id` — they are tenant-scoped only.

Key user attributes:
- `email`, `name`, `first_name`, `last_name`, `display_name`
- `department`, `job_title`, `employee_id`, `manager_id` (optional business context)
- `status` — lifecycle state (see States section below)
- `is_active` — quick enable/disable flag
- `failed_login_attempts` — increments on bad password; locks after 5 failures
- `locked_until` — timestamp until which the account is locked

### Roles and Permissions

**4 system roles** (cannot be deleted or modified):

| Role | Scope | Access Level |
|---|---|---|
| `super_admin` | Platform | Full platform access; hardcoded `["*"]` permissions |
| `tenant_admin` | Tenant | Full access within the tenant: users, roles, namespaces, all resources |
| `tenant_user` | Tenant | Standard access — read-only on most resources, create/execute on some |
| `readonly` | Tenant | Read-only across the board |

Custom roles can be created per-tenant. A role has:
- `name`, `display_name`, `description`
- `scope` — `platform`, `tenant`, or `namespace`
- `role_type` — `system` or `custom`
- `permissions` — list of permission strings

**Permission format** — Always `resource:action` (note: the platform has TWO conventions in use):
- New convention (preferred): `resource:action` — e.g. `documents:read`, `collections:create`
- Legacy convention: `action:resource` — e.g. `read:integrations`, `write:agents`

**Critical rule: ALWAYS use singular resource names.**
- Correct: `integration:read`, `dashboard:create`, `document:delete`
- Wrong: `integrations:read`, `dashboards:create`, `documents:delete`

**Wildcard**: `resource:*` means all actions on that resource. `*` alone is reserved for the platform operator role.

### Permission Groups

The platform defines named permission groups that expand to lists of granular permissions.
Groups follow the pattern `domain.level` e.g.:
- `tenant_management.full` — full tenant-level access excluding system destruction
- `tenant_management.limited` — view and create, no admin
- `user_management.full` / `.limited`
- `data_management.full` / `.limited` / `data_access.read` / `data_access.write`
- `detection_management.full`, `agent_management.full`
- `integration_management.full`
- `settings_management.full`, `audit_logs.full`, `analytics.full`

### Audit Logging

Every operation is automatically recorded in `audit_logs`. A log entry captures:
- `event_type` — `authentication`, `user_management`, `tenant_management`, `rbac`, `security`
- `action` — specific action performed (e.g. `login`, `create_user`, `assign_role`)
- `resource_type`, `resource_id` — what was affected
- `user_id`, `user_email` — who did it (can be NULL for system events)
- `tenant_id`, `namespace_id` — tenant context
- `ip_address`, `user_agent`, `request_id`
- `status` — `success`, `failure`, `error`
- `status_code`, `error_message`, `duration_ms`
- `details` — flexible JSON with additional context

Audit logs are immutable: they are never updated or deleted.

**Sign-in events** are audit rows with `event_type = authentication` and `action` one of `login.success`,
`login.failure`, `logout`. Each records the account, tenant, client IP (as nginx saw it, `ip_source = x-real-ip`),
user agent, method (`password` or `oauth_web`) and, for failures, a reason: `invalid_credentials`, `unknown_user`,
`locked` (locked or disabled by an admin), `account_disabled`, `idp_user_missing`, `idp_error`,
`tenant_state_unavailable`, `internal_error` or `user_row_missing`.

Sign-in activity (who signed in, from which IP) is not readable with a tenant account: sign-in rows are hidden from
`audit-logs list` / `statistics` / `security-events` / `get`, and another user's `last_login_at` reads `null`. So a
tenant admin finding no `authentication` rows is the rule working, not missing data.

Every audit-log read is pinned to your own tenant; another tenant's `--tenant-id` gets 403.

### Tokens

JWT tokens are stored in PostgreSQL. Two types:
- `ACCESS` — short-lived (~30 minutes)
- `REFRESH` — long-lived (~7 days)

Tokens can be revoked explicitly via the API. A revoked token stores `revoked_at`, `revoked_by`,
and `revocation_reason`. The token also tracks `usage_count`, `last_used_at`, `ip_address`,
`device_info`, `user_agent` for security analysis.

JWT structure (what is encoded in the token):
```json
{
  "sub": "<database-user-id>",
  "email": "user@example.com",
  "name": "User Name",
  "tenant_id": "<tenant-uuid>",
  "roles": ["tenant_admin"],
  "permissions": ["read:integrations", "write:agents", ...],
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "<unique-id>"
}
```

Note: `namespace_id` is NOT in the JWT. It is derived at runtime.

---

## States and Lifecycle

### User States

| Status | Meaning | Can Login? |
|---|---|---|
| `active` | Normal operating state | Yes |
| `inactive` | Deactivated (e.g. offboarded) | No |
| `suspended` | Temporarily blocked | No |
| `locked` | Too many failed logins; `locked_until` set | No (until lock expires) |

Account locking:
- Each failed login increments `failed_login_attempts`
- After 5 failures the account is locked for 24 hours (`locked_until = now + 24h`)
- Successful login resets `failed_login_attempts` to 0
- Admin can unlock a user explicitly via the API

State transitions:
- Create user → `active`
- Admin suspend → `suspended`; resume → `active`
- Admin disable → `is_active = False`; re-enable → `is_active = True`
- Too many failed logins → `locked_until` set
- Admin unlock → `locked_until = None`, `failed_login_attempts = 0`

### Token States

| State | Meaning |
|---|---|
| Valid | `is_revoked = False` and `expires_at` in the future |
| Expired | `expires_at` is past; `is_revoked` may be False |
| Revoked | `is_revoked = True`; `revoked_at` set |

---

## How It Works

### User Management Flow

1. Create user with its password and role in one call (`users create --password … --role …`); the user
   is created in PostgreSQL and synced to Keycloak
2. Optionally assign further roles (`roles assign`)
3. User logs in: `torana auth login`
4. Manage lifecycle: suspend, unlock, reset-password, toggle-enabled as needed

### Permission Check Flow

1. User calls an API endpoint
2. API Gateway extracts the `Authorization: Bearer <token>` header
3. JWT is decoded; `tenant_id`, `roles`, `permissions` are extracted
4. `namespace_id` is derived from tenant's default namespace
5. Endpoint checks required permission against `permissions` list in JWT
6. If missing → 403 Forbidden

Permissions in the JWT are the union of all permissions from all roles assigned to the user.

---

## Multi-Tenant Considerations

- The `tenant_id` in the JWT is used to filter all data queries
- Tenant admin sees ONLY their own tenant's users, roles, and resources
- Tenant deletion and hard-delete are super admin operations only
- Bootstrap tenant (Torana's own tenant) cannot be deleted

---

## Troubleshooting Guide

### User Cannot Log In

**Symptoms**: Login returns 401, user says password is correct.

**Check list**:
1. Is `locked_until` in the future? → Unlock the user or wait
2. Is `is_active = False`? → Re-enable via toggle-enabled
3. Is `status != "active"`? → Update status or unsuspend
4. Is the tenant suspended? → Check tenant status (super admin required to resume)
5. Is the user's `keycloak_sync_status = "failed"`? → Keycloak sync issue; check auth logs

### 403 Forbidden on API Call

**Symptoms**: User is logged in but gets 403 on specific endpoints.

**Check list**:
1. Inspect the user's effective permissions
2. What permission does the endpoint require? (Check endpoint documentation)
3. What roles does the user have? → Get user's roles
4. Does any of those roles include the required permission? → Get role details
5. If not, assign the correct role or add permission to existing role

### Token Expired / Invalid Token

**Symptoms**: Requests return 401 with "token expired" or "invalid token".

**Resolution**:
1. Client should use the refresh token
2. If refresh token also expired, user must log in again
3. If token was explicitly revoked, user must log in again
4. Check token states filtered by `user_id`

### Audit Log Shows Unexpected Actions

**Symptoms**: Audit logs show actions performed by a user who claims not to have done them.

**Investigation**:
1. Cross-check what that account did: `"$TORANA" audit-logs list --user <email> --since 30d`
2. If a security incident is suspected, force re-authentication (tenant force-logout) and disable the user
3. For the sign-in IP and device, ask your Torana contact: sign-in detail is not readable with a tenant account

### Failed Login Count Rising

**Symptoms**: repeated failed sign-ins.

**Investigation**:
1. `"$TORANA" audit-logs security-events` lists failed and errored sign-ins together with other security events
2. Note that the identity provider temporarily locks an account after rapid failures (about 2 within a second, for
   about 60 s) and reports it as a wrong password. A correct password shortly after a burst can still fail; wait
   before concluding
3. For the source IP and the failure reason per attempt, ask your Torana contact

---

## Best Practices

1. **Use system roles as the starting point.** Start users with `tenant_user` or `readonly` and
   upgrade to `tenant_admin` only when needed.

2. **Follow singular permission naming.** When creating custom roles or checking permissions,
   use singular: `dashboard:read` not `dashboards:read`. Mixed styles in the platform are a
   legacy issue; new code should always use singular.

3. **Review audit logs regularly.** The audit log is the definitive record. Use
   security-events to check for anomalies (failed logins, unusual actions).

4. **Validate tenant plan limits before provisioning.** Check tenant usage before adding users.
   Exceeding quotas will result in errors during resource creation.

5. **Set role permissions before assigning to users.** Define the complete permission list on
   a custom role before assigning it. Adding permissions later requires token re-issuance for
   existing sessions to reflect the changes.

6. **Revoke tokens on security events.** If a user's credentials are compromised, immediately
   revoke all tokens for that user and force re-authentication.

---

## Discovering Commands

The CLI is the source of truth. Before any operation:

```bash
"$TORANA" users --help
"$TORANA" roles --help
"$TORANA" permissions --help
"$TORANA" tokens --help
"$TORANA" audit-logs --help
"$TORANA" activities --help
```

## Typical Workflows

### Create and onboard a user

`--email`, `--name` and `--password` (min 8 chars) are required. `--role` is one of
`tenant_readonly_user`, `tenant_user` (the default), `tenant_admin` (also grants `tenant_user`) or
`super_admin`.

| Caller | Tenant | Roles it may grant |
|---|---|---|
| Tenant admin | its own tenant only: omit `--tenant-id`. Another tenant → 403 (exit 4) | all except `super_admin` (403) |

```bash
# Tenant admin adds a user to its own tenant
"$TORANA" users create \
  --email "alice@acme.com" --name "Alice Smith" \
  --password 'S3cure-pass' --role tenant_admin

```

A tenant admin acts only on users of its own tenant: `users get / update / delete / reset-password /
toggle-enabled` on another tenant's user returns "not found" (exit 3), not 403.

### Change a user's roles

Either REPLACE the whole set by name, or add/remove one role by id. The same tenant and `super_admin`
rules as `users create` apply (403 otherwise).

```bash
# Replace: the user ends up with exactly these roles
"$TORANA" users update <user-id> --role tenant_user --role tenant_admin

# Add one: role id FIRST (positional), user is --user-id. --namespace-id is optional
# (defaults to the user's tenant's default namespace)
"$TORANA" roles list              # system roles; a tenant admin sees all but super_admin
"$TORANA" roles assign <role-id> --user-id <user-id>

# Remove one
"$TORANA" roles role-assignment remove <role-id> <user-id> --yes
```

### Create a custom role with specific permissions

```bash
# Create the role (name and description on the command line)
"$TORANA" roles create --name "security_analyst" \
  --description "Security analyst - read access plus alert acknowledgment"
# To set permissions in the same call, put them in a file: read an existing role as the model
#   "$TORANA" roles get <role-id> --format yaml > role.yaml   (edit it, then: roles create --file role.yaml)

# Assign to a user
"$TORANA" roles assign <role-id> --user-id <user-id>
```

### Manage user lifecycle

```bash
# Enable / disable an account — this is the one lifecycle switch.
# There is no separate `unlock` or `suspend` verb; both are this toggle.
"$TORANA" users toggle-enabled <user-id>

# Reset password
"$TORANA" users reset-password <user-id> --new-password 'N3w-pass'
```

### Token management

```bash
# List sign-in tokens (access and refresh): type, created, expires, revoked, reason, last used. They have no name or scopes.
"$TORANA" tokens list

# Revoke a specific token
"$TORANA" tokens revoke-token <token-id>

# Revoke ALL tokens for a user (security incident response)
"$TORANA" tokens revoke-admin <user-id> --reason "incident response"

# Clean up expired tokens
"$TORANA" tokens cleanup-expired
```


### Query audit logs and security events

```bash
# Recent audit logs for the tenant
"$TORANA" audit-logs list

# Filter: event type, account (email), status, IP, time (ISO or 30m / 2h / 7d)
"$TORANA" audit-logs list --event-type user_management --since 7d
"$TORANA" audit-logs list --user someone@acme.com --status failure

# Security events (last N hours — brute force, suspicious logins)
"$TORANA" audit-logs security-events

# Audit log statistics (`stats` is an alias)
"$TORANA" audit-logs statistics
"$TORANA" audit-logs stats --since 7d
```

**Not in the CLI:** "who signed in" and "active users right now". Say plainly that neither is visible with a tenant
account.

# Activity log
"$TORANA" activities list
"$TORANA" activities list --user-id <user-id>
```

---

## Error Reference

| CLI output | Meaning | Fix |
|---|---|---|
| `Not authenticated` | No cached token | Run OAuth login (see bootstrap) |
| `Session expired` | Refresh token invalid | Re-run OAuth login |
| `403 Forbidden` | Token missing scope | Re-auth with correct account (must be tenant_admin) |
| `Cannot reach <url>` | Wrong base-url or network | `"$TORANA" config get base-url`; verify tunnel |

<!-- CHANGELOG
v1.0 (2026-02-28) - Initial skill creation.
v2.0 (2026-04-16) - Scoped to tenant admin only; migrated to torana CLI; removed curl/tg/tp/td
-->
