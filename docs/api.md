# API Reference

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
that actually execute are the fixed default rules in `PolicyEngine` for this release — see
`docs/policy-guide.md`.

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

## Error shape

Validation/not-found/conflict/auth errors return:

```json
{"timestamp": "2026-07-18T04:00:00Z", "status": 404, "error": "agent 99 not found"}
```
