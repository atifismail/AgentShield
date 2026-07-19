# API Reference

An interactive, always-up-to-date version of this reference is served by the application itself:
`GET /swagger-ui.html` (browsable UI) and `GET /v3/api-docs` (raw OpenAPI JSON). Both are on by
default; the `prod` profile turns them off unless `AGENTSHIELD_ENABLE_API_DOCS=true` is set, since
the schema/examples aren't meant for a public audience by default (`docs/operations.md`).

All endpoints are JSON over HTTP. Two authentication modes coexist:

- **Agents** call `POST /api/gateway/invoke` with `Authorization: Bearer <agent-token>` — a
  per-agent token issued via the agent registry, checked against a stored SHA-256 hash. This is
  the only endpoint agents use.
- **Human operators** (admin console / other `/api/**` endpoints) authenticate with a session
  from the form-login UI, or HTTP Basic for scripts/tooling. Role-based access control applies
  per `docs/policy-guide.md` and `SecurityConfig`.

## Gateway

### `POST /api/gateway/invoke`

Request:

```json
{
  "agentId": "informational only, not used for auth",
  "toolId": "mock-database",
  "action": "deleteRecords",
  "actionCategory": "DESTRUCTIVE",
  "targetEnvironment": "PROD",
  "input": { "table": "users", "where": "status = 'inactive'" },
  "context": { "userId": "user-001", "taskId": "task-001", "reason": "cleanup" }
}
```

Notes on fields that differ from a literal domain-object mapping:

- `toolId` is the tool's registered **name** (e.g. `mock-database`), not a numeric ID.
- `agentId` is accepted for readability/logging but is **not** used for authentication — the
  agent's identity comes entirely from the bearer token.
- `actionCategory` is one of `READ`, `WRITE`, `DESTRUCTIVE`, `CREDENTIAL_ACCESS`, `EXTERNAL_TRANSFER`.

Responses:

```json
{"decision": "ALLOW", "riskLevel": "LOW", "reason": null, "approvalRequestId": null, "result": {}}
{"decision": "DENY", "riskLevel": "CRITICAL", "reason": "production destructive actions require prior human approval and cannot be auto-allowed", "approvalRequestId": null, "result": null}
{"decision": "APPROVAL_REQUIRED", "riskLevel": "HIGH", "reason": "production write actions require human approval", "approvalRequestId": 42, "result": null}
```

`401` if the bearer token doesn't match any agent. `429` if the calling token/IP exceeds the
gateway rate limit (`agentshield.gateway.rate-limit.max-requests-per-minute`, default 60/min).

**Approval resume model:** when a call comes back `APPROVAL_REQUIRED`, the agent does not retry —
a human approves or rejects via `POST /api/approvals/{id}/approve|reject`, and *approving executes
the call immediately* against the tool. If the agent needs the eventual result, it (or an operator)
can look up `GET /api/audit/correlation/{correlationId}` using the correlation ID logged alongside
the original request.

## Agents — `/api/agents`

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/api/agents` | ADMIN | Register an agent |
| GET | `/api/agents` | any authenticated | List agents |
| GET | `/api/agents/{id}` | any authenticated | Get one agent |
| PUT | `/api/agents/{id}` | ADMIN | Update description/owner/environment/allowed groups |
| POST | `/api/agents/{id}/enable` | ADMIN | Re-enable |
| POST | `/api/agents/{id}/disable` | ADMIN | Disable (fails closed via policy rule 1) |
| DELETE | `/api/agents/{id}` | ADMIN | Soft-delete — equivalent to disable; the agent and its history are kept, not removed |
| POST | `/api/agents/{id}/rotate-token` | ADMIN | Revokes all active credentials and issues a new one. Returns the plaintext token **once** — it is never retrievable again |
| GET | `/api/agents/{id}/credentials` | ADMIN | List credentials (prefix + status only, never the token) |
| POST | `/api/agents/{id}/credentials` | ADMIN | Issue a new credential, body `{"validForMinutes": <optional>}`. Returns the plaintext token **once** |
| POST | `/api/agents/{id}/credentials/{credentialId}/revoke` | ADMIN | Revoke a single credential immediately |

Agent authentication (`/api/gateway/invoke`) accepts any `ACTIVE`, unexpired credential's token; a
revoked or expired credential authenticates nothing regardless of how recently it worked. An
agent can have multiple credentials at once — useful for rotating without downtime (issue the new
one, update the caller, then revoke the old one).

## Tools — `/api/tools`

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/api/tools` | ADMIN / TOOL_OWNER | Register a tool; starts `PENDING` |
| GET | `/api/tools` | any authenticated | List tools |
| GET | `/api/tools/{id}` | any authenticated | Get one tool |
| GET | `/api/tools/{id}/versions` | any authenticated | Version/drift history |
| POST | `/api/tools/{id}/refresh` | ADMIN / TOOL_OWNER | Re-fingerprint schema/description; flips to `DRIFTED` if changed |
| POST | `/api/tools/{id}/approve` | ADMIN / TOOL_OWNER / SECURITY_ANALYST | Approve the latest detected version |
| POST | `/api/tools/{id}/reject` | ADMIN / TOOL_OWNER / SECURITY_ANALYST | Reject the latest detected version |

## MCP servers — `/api/mcp-servers`

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/api/mcp-servers` | any authenticated | Register an MCP server: `{name, transportType, endpointUrl, owner, environment, toolGroup}` |
| GET | `/api/mcp-servers` | any authenticated | List servers |
| GET | `/api/mcp-servers/{id}` | any authenticated | Get one server |
| PATCH | `/api/mcp-servers/{id}/auth` | ADMIN | Set how AgentShield authenticates itself to this server: `{authMode: "NONE"\|"OAUTH2"\|"STDIO_ENV", oauthIssuer, oauthResource, oauthTokenEndpoint, oauthClientId, oauthClientSecretRef, oauthScopes}` |
| POST | `/api/mcp-servers/{id}/discover` | any authenticated | Call `tools/list` and sync the result into the regular tool registry |

Only `transportType: "HTTP"` is actually implemented — `SSE` and `STDIO` can be registered (the
schema supports them) but discovery/invocation for them returns a clear "not implemented yet"
error rather than pretending to work.

Discovery creates or updates a regular `Tool` row per MCP tool found, named
`<serverName>:<mcpToolName>` — from that point on it behaves exactly like any other tool:
it starts `PENDING`, goes through `/api/tools/{id}/approve` like normal, and is called via
`POST /api/gateway/invoke` with `toolId` set to that qualified name. A tool whose description or
input schema changed since the last discovery flips to `DRIFTED` (the same mechanism as any other
tool); a tool that's no longer returned by `tools/list` is marked `REJECTED`. Both go through the
existing tool-registry drift/approval workflow — nothing gateway-side changes for MCP tools.

**Being APPROVED is not sufficient to call an MCP-backed tool** — see MCP consents below.

### MCP OAuth (`authMode: "OAUTH2"`)

When a server requires OAuth, AgentShield acts as its own OAuth 2.1 client using the
`client_credentials` grant (no browser/human-resource-owner redirect — the human consent step is
the MCP consent grant itself, below). `oauthClientSecretRef` is a *reference name* resolved
against ordinary Spring configuration (typically an environment variable of that exact name) —
never a plaintext secret in the request body. Tokens are validated on receipt
(audience/issuer/expiry/scope) before being cached (AES-256-GCM encrypted); a wrong-audience or
wrong-issuer token is rejected and never used. Requires
`agentshield.mcp.oauth-token-encryption-key` to be set (see `docs/operations.md`) — acquisition
fails closed, with a clear reason, if it isn't.

## MCP consents — `/api/mcp-consents`

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/mcp-consents?agentId=&mcpServerId=` | ADMIN / SECURITY_ANALYST | List/filter |
| POST | `/api/mcp-consents` | ADMIN / SECURITY_ANALYST | Grant: `{agentId, mcpServerId, toolName, actionCategory, expiresAt}` — `toolName`/`actionCategory`/`expiresAt` are optional; omitted means "any"/"never expires" |
| POST | `/api/mcp-consents/{id}/revoke` | ADMIN / SECURITY_ANALYST | Immediate — the next call from that agent to that MCP server is denied |

The direct confused-deputy control (`docs/threat-model.md`): a tool discovered from an MCP server
being `APPROVED` is necessary but not sufficient. The calling agent must also hold an ACTIVE,
unexpired consent grant scoped to that MCP server (and, if the grant is that specific, the exact
tool/action category) — checked by the policy engine's rule 11
(`docs/policy-guide.md`) before every call, before any OAuth token is even requested. No grant,
no call — regardless of whether the target MCP server itself requires OAuth.

## Policies — `/api/policies`

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/policies` | ADMIN / SECURITY_ANALYST | List all policy version records |
| GET | `/api/policies/{name}/versions` | ADMIN / SECURITY_ANALYST | Versions for one policy name |
| POST | `/api/policies` | ADMIN / SECURITY_ANALYST | Create a new (disabled) version |
| POST | `/api/policies/{id}/enable` | ADMIN / SECURITY_ANALYST | Enable a version (disables sibling versions of the same name) |
| POST | `/api/policies/{id}/disable` | ADMIN / SECURITY_ANALYST | Disable a version |
| POST | `/api/policies/dry-run` | ADMIN / SECURITY_ANALYST | Evaluate a hypothetical request against the live default rules, no persistence |

The stored `rule_json` on a policy version is versioned metadata for review/rollback. The rules
that actually execute are the fixed default rules in `PolicyEngine`, plus any policy overrides
below — see `docs/policy-guide.md`.

## Policy overrides — `/api/policy-overrides`

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/policy-overrides` | ADMIN / SECURITY_ANALYST | List all overrides |
| POST | `/api/policy-overrides` | ADMIN / SECURITY_ANALYST | Create one — `{actionCategory, targetEnvironment, toolGroup, agentName, decision, reason, priority}`, all match fields optional (null = matches anything) |
| POST | `/api/policy-overrides/{id}/enable` | ADMIN / SECURITY_ANALYST | |
| POST | `/api/policy-overrides/{id}/disable` | ADMIN / SECURITY_ANALYST | |
| DELETE | `/api/policy-overrides/{id}` | ADMIN / SECURITY_ANALYST | |

Overrides are database-backed rules an operator can add without a code change. They are only
consulted when the fixed `PolicyEngine` rules would otherwise ALLOW a request — an override can
add extra restriction (`DENY`/`APPROVAL_REQUIRED`) or a deliberate scoped allowance (`ALLOW`), but
it can never bypass a fixed DENY or APPROVAL_REQUIRED rule (e.g. a disabled agent stays denied
regardless of any override). Every create/enable/disable/delete is audited.

## Approvals — `/api/approvals`

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/approvals?pendingOnly=true` | any authenticated | Queue |
| GET | `/api/approvals/{id}` | any authenticated | Detail |
| POST | `/api/approvals/{id}/approve` | ADMIN / APPROVER | Approves **and executes** the original call; response includes `executionResult` |
| POST | `/api/approvals/{id}/reject` | ADMIN / APPROVER | Rejects; the original `GatewayRequest` stays `DENIED` |

Pending approvals past their `expiresAt` (default 60 minutes, `agentshield.approval.default-expiration-minutes`) are swept to `EXPIRED` every minute by a scheduled job.

## Audit — `/api/audit`

| Method | Path | Notes |
|---|---|---|
| GET | `/api/audit?agentId=&toolId=&severity=&since=&page=&size=` | Filtered, paginated search |
| GET | `/api/audit/correlation/{correlationId}` | Full timeline for one gateway request |
| GET | `/api/audit/verify-integrity` | Read-only: recomputes the audit hash chain and reports whether it's intact — see `docs/operations.md` |

Every audit event is chained: its `event_hash` covers its own content plus the previous event's
hash (SHA-256), so editing or deleting a historical row is detectable. Writes serialize on this
chain (a per-write row lock), which is a deliberate correctness-over-throughput tradeoff for a
security audit trail.

## Incidents — `/api/incidents`

| Method | Path | Notes |
|---|---|---|
| GET | `/api/incidents?page=&size=` | List, newest first |
| GET | `/api/incidents/{id}` | Detail — links back to `relatedAuditEventId` / `relatedGatewayRequestId` |
| PATCH | `/api/incidents/{id}/status` | ADMIN/SECURITY_ANALYST. Body `{"status": "OPEN\|ACKNOWLEDGED\|RESOLVED\|FALSE_POSITIVE"}` |

## Error shape

Validation/not-found/conflict/auth errors return:

```json
{"timestamp": "2026-07-18T04:00:00Z", "status": 404, "error": "agent 99 not found"}
```
