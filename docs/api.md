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
| POST | `/api/tools/{id}/approve` | ADMIN / TOOL_OWNER / SECURITY_ANALYST | Approve the latest detected version — rejected if the tool's source type requires a verified signature it doesn't have yet, see below |
| POST | `/api/tools/{id}/reject` | ADMIN / TOOL_OWNER / SECURITY_ANALYST | Reject the latest detected version |
| GET | `/api/tools/{id}/provenance` | any authenticated | Latest supply-chain provenance record for the tool |
| POST | `/api/tools/{id}/provenance/verify` | ADMIN / SECURITY_ANALYST | Submit a signature for verification: `{bundleJson, expectedIdentity, expectedIssuer}` |
| POST | `/api/tools/{id}/provenance/revoke` | ADMIN / SECURITY_ANALYST | Revoke: `{reason}` — immediately forces the tool to `DRIFTED`, blocking calls |

### Supply-chain provenance

Every tool version automatically gets a Level-1 checksum record (`UNVERIFIED`) at registration,
MCP discovery, or drift time — no action needed, and nothing about existing behavior changes.
Level 2 (cryptographic signature verification) is opt-in: an ADMIN/SECURITY_ANALYST submits a
[`cosign sign-blob --bundle`](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
artifact via `POST /api/tools/{id}/provenance/verify`, verified in-process against Sigstore's
public trust root (audience-checked against `expectedIdentity`/`expectedIssuer`, the OIDC
identity/issuer the signing certificate must carry). AgentShield never signs anything itself —
signing always happens in the tool/skill publisher's own CI; AgentShield only verifies.

The artifact that must be signed is the exact same content already used for fingerprinting
(`schemaJson` + `description`, concatenated in that order) — the digest checked is derived
directly from the tool version's own fingerprint hash.

Whether a signature is *required* before approval is controlled by trust policy
(`agentshield.provenance.require-signature-for`, see `docs/operations.md`) — empty by default,
so every tool stays at Level 1 until an operator opts a source type in. `BUILT_IN` tools (the
bundled demo tools) are always exempt, regardless of policy.

## MCP servers — `/api/mcp-servers`

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/api/mcp-servers` | any authenticated | Register an MCP server: `{name, transportType, endpointUrl, command, args, stdioEnvAllowlist, owner, environment, toolGroup}` |
| GET | `/api/mcp-servers` | any authenticated | List servers |
| GET | `/api/mcp-servers/{id}` | any authenticated | Get one server |
| PATCH | `/api/mcp-servers/{id}/auth` | ADMIN | Set how AgentShield authenticates itself to this server: `{authMode: "NONE"\|"OAUTH2"\|"STDIO_ENV", oauthIssuer, oauthResource, oauthTokenEndpoint, oauthClientId, oauthClientSecretRef, oauthScopes}` |
| POST | `/api/mcp-servers/{id}/discover` | any authenticated | Call `tools/list` and sync the result into the regular tool registry |
| GET | `/api/mcp-servers/{id}/stdio/status` | ADMIN / SECURITY_ANALYST | `{running, pid, startedAt, lastActivityAt}` — in-memory runtime state, not persisted |
| POST | `/api/mcp-servers/{id}/stdio/start` | ADMIN | Eagerly spawn the sandboxed subprocess now, instead of waiting for first use |
| POST | `/api/mcp-servers/{id}/stdio/stop` | ADMIN | Force-stop it (e.g. suspected compromise) |
| GET | `/api/mcp-servers/{id}/sse/status` | ADMIN / SECURITY_ANALYST | `{running, pid: null, startedAt, lastActivityAt}` for the persistent SSE connection |
| POST | `/api/mcp-servers/{id}/sse/start` | ADMIN | Eagerly open the connection now, instead of waiting for first use |
| POST | `/api/mcp-servers/{id}/sse/stop` | ADMIN | Force-close it |

All three `transportType` values (`HTTP`, `SSE`, `STDIO`) are implemented per
`design-stdio-sse-mcp-transport-and-sandboxing.md`. `SSE` opens a persistent Server-Sent-Events
connection per the legacy MCP SSE transport (an initial `GET` receives an `endpoint` event naming
a session-scoped POST URL; `tools/list`/`tools/call` requests are POSTed there, responses arrive
asynchronously as `message` events, correlated by JSON-RPC `id`). It's HTTP-based like the plain
`HTTP` transport — same SSRF policy (`OutboundEndpointValidator`), same OAuth2
`client_credentials` flow when `authMode: OAUTH2` — with no subprocess/filesystem/environment
concerns and no feature flag. Bounded by `agentshield.mcp.sse.call-timeout-seconds`,
`max-response-bytes`, `idle-timeout-minutes`, and `reconnect-max-attempts`; every connection
open/close/failure and call timeout/oversized-response rejection is audited
(`mcp.sse_connection_opened`/`_closed`/`_failed`, `mcp.sse_call_timeout`, `mcp.sse_response_rejected`).

**`STDIO` transport is gated behind `agentshield.stdio.enabled` (default `false`)** — registering
or invoking a stdio server while disabled fails closed. It spawns a locally-sandboxed subprocess
per `design-stdio-sse-mcp-transport-and-sandboxing.md`: the executable must be on
`agentshield.stdio.allowed-commands` (empty by default — nothing is spawnable until an operator
allowlists it), its environment is built from scratch and contains **nothing** from AgentShield's
own process unless a name is explicitly listed in `stdioEnvAllowlist` (comma-separated names,
never values — `HOME`/`USERPROFILE` are treated the same as any other name but are documented as
sensitive; see `docs/operations.md`), and calls are bounded by
`agentshield.stdio.call-timeout-seconds`/`max-output-bytes`/`max-concurrent-processes`. Every
process start/stop/crash and every call timeout/output-size rejection is audited
(`mcp.stdio_process_*`, `mcp.stdio_call_timeout`, `mcp.stdio_output_rejected`). AgentShield cannot
enforce per-process network egress or memory/CPU limits from inside the JVM — see the design doc
and `docs/operations.md` for what must be enforced externally before enabling this in production
(a startup guard refuses to start a `prod`-profile deployment with stdio enabled unless
`agentshield.stdio.external-sandbox-acknowledged=true` is also set).

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
| GET | `/api/policies/replay/{gatewayRequestId}` | ADMIN / SECURITY_ANALYST | Replay a historical gateway request's facts against the live rules + current overrides; shows original vs simulated decision, never calls the tool |

The stored `rule_json` on a policy version is versioned metadata for review/rollback. The rules
that actually execute are the fixed default rules in `PolicyEngine`, plus any policy overrides
below — see `docs/policy-guide.md`. The replay endpoint therefore simulates against the live rules
+ current overrides, not against a stored draft `rule_json` version (the engine doesn't consume
that field at runtime yet, so "draft policy" replay is out of scope for this release — see
`improvement_plan.md`). There's also a "Simulate against current policy" button on each gateway
request's detail page (`/gateway-requests/{id}`).

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

## DLP — `/api/dlp`

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/api/dlp/rag/scan` | any authenticated | Stateless scan: `{text, sourceName}` in, `{action, blocked, redactedText, findings}` out. Does not persist `text` itself — only the `DlpFinding` metadata (indicator/category/confidence/location, never the matched substring), same discipline as gateway response scanning |
| GET | `/api/dlp/findings?stage=&category=&since=&page=&size=` | any authenticated | Filtered, paginated search over persisted findings |
| GET | `/api/dlp/profiles` | any authenticated | List classification profiles |
| POST | `/api/dlp/profiles` | ADMIN / SECURITY_ANALYST | Create: `{name, locale, detectSecrets, detectPii, detectPromptInjection, customPatterns, defaultAction, priority}` |
| POST | `/api/dlp/profiles/{id}/enable` | ADMIN / SECURITY_ANALYST | |
| POST | `/api/dlp/profiles/{id}/disable` | ADMIN / SECURITY_ANALYST | |

`SecretDetector` and `PromptInjectionDetector` (already used for tool-response scanning) plus the
new `PiiDetector` (email/phone/SSN-like/resident-registration-number-like/Luhn-validated
credit-card-like patterns, plus operator-configured custom regexes) all run against a
`ClassificationProfile`'s configuration. `defaultAction` is one of `ALLOW`, `REDACT`, `TOKENIZE`,
`BLOCK`, `APPROVAL_REQUIRED` — `REDACT`/`TOKENIZE` sanitize the content in place (an irreversible
`[REDACTED:<CATEGORY>]` placeholder by default, or a reversible opaque token if
`agentshield.dlp.enable-reversible-tokenization` is explicitly enabled) rather than blocking the
call. When no enabled profile exists yet, scanning still runs against a safe built-in default (all
detectors on, `BLOCK` on any match) — DLP protection does not require any setup to be active.

**Gateway integration:** `POST /api/gateway/invoke` now scans the inbound tool-call arguments
(`input`) the same way it has always scanned tool *responses* — only reached when the fixed
policy rules would otherwise `ALLOW`, so a DLP `BLOCK`/`APPROVAL_REQUIRED` finding overrides the
`ALLOW` (new rule IDs `deny-dlp-block` / `require-approval-dlp-finding`), while a
`REDACT`/`TOKENIZE` finding swaps in the sanitized payload before forwarding to the tool. The
persisted `GatewayRequest.requestBodyJson` (used for approval replay) is left as the original,
un-redacted submission, same as it already was for prod-write/external-transfer approvals — DLP
does not change what an approving human ultimately executes.

## Governance evidence export — `/api/governance`

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/governance/report?from=<ISO-8601>&to=<ISO-8601>` | ADMIN / SECURITY_ANALYST | JSON evidence report for the range |
| GET | `/api/governance/report?format=markdown&from=<ISO-8601>&to=<ISO-8601>` | ADMIN / SECURITY_ANALYST | Same report as a downloadable Markdown file |

Read-only snapshot assembled from existing operational tables — registered agents, approved
tools, denied actions in range, approval records in range (with approved/rejected/expired
breakdown), tool drift events in range, incidents opened in range, and the policy versions
currently in force. Sections are labeled with the NIST AI RMF function they evidence
(govern/map/measure/manage). `from` must be strictly before `to` or the request is rejected with
400. There's also an operator-facing form at `/governance`.

## Code Trust — `/api/codetrust`

AI-coding-assistant scan submission, block/pass policy, human review of blocked assessments, and
signed/verifiable receipts for passed ones. **Not a SAST engine** — this endpoint ingests findings
a caller already produced (see `scripts/agentshield-code-scan.sh` for a thin reference client) and
applies policy/receipt logic to them.

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/api/codetrust/assessments` | ADMIN / SECURITY_ANALYST / CI_SCANNER | Submit `{repo, commitSha, branch, author, source, requiresRescan, requestedBy, findings[]}`. `findings[]` items are `{filePath, line, category, severity, ruleId, message}`; `category` is one of `SECRET/LICENSE/DEPENDENCY_RISK/INSECURE_PATTERN/CRYPTO_AUTH_CHANGE`, `severity` reuses the existing `RiskLevel` scale. Evaluated synchronously: any `HIGH`/`CRITICAL` finding → `BLOCKED`; `requiresRescan=true` → stays `PENDING` regardless of findings (used when a submission represents an unverified AI-suggested fix); otherwise → `PASSED` with a receipt issued immediately |
| GET | `/api/codetrust/assessments` | ADMIN / SECURITY_ANALYST / CI_SCANNER | List all, newest first |
| GET | `/api/codetrust/assessments/{id}` | ADMIN / SECURITY_ANALYST / CI_SCANNER | Full detail incl. findings and receipt (if issued) |
| POST | `/api/codetrust/assessments/{id}/approve` | ADMIN / SECURITY_ANALYST | Only valid on a `BLOCKED` assessment (409 otherwise). Passes it and issues a receipt — `CI_SCANNER` cannot call this |
| POST | `/api/codetrust/assessments/{id}/reject` | ADMIN / SECURITY_ANALYST | Only valid on a `BLOCKED` assessment; stays `BLOCKED`, no receipt |
| POST | `/api/codetrust/receipts/{assessmentId}/verify` | ADMIN / SECURITY_ANALYST / CI_SCANNER | Self-contained: recomputes the Ed25519 signature check from the receipt's own stored `commitSha`/`scanSummaryHash` columns against the current signing key. Returns `{valid, commitSha, scanSummaryHash, signerKeyId}` |
| GET | `/api/codetrust/signing-key` | any authenticated | `{algorithm, keyId, publicKeyBase64, ephemeral}` — lets a third party (CI system, auditor) verify a receipt independently, without any AgentShield credentials or database access |

Receipts are signed with a local Ed25519 keypair (`ReceiptSigningKeyProvider`) — JDK-native, no new
dependency, and deliberately separate from the Sigstore keyless verifier used elsewhere in this
codebase (that one only ever *verifies* other publishers' signatures; this is the one place
AgentShield signs something itself). If `agentshield.codetrust.signing-private-key`/
`-public-key` are not configured, an ephemeral keypair is generated at startup — fine for
dev/demo/test, but `ProductionSafetyChecks` refuses to start with the `prod` profile active on an
ephemeral key, since every receipt signed before a restart would fail verification after one.
Review state (`approvedBy`/`approvedAt`/`rejectedBy`/`rejectedAt`) lives directly on the
assessment rather than going through `/api/approvals` — `ApprovalRequest` mandatorily references
a `GatewayRequest` and its approval executes a tool call, neither of which applies to reviewing a
code assessment.

## SIEM export and detection validation — `/api/siem`

Normalized event export for SIEM/SOAR ingest, a named detection-rule catalog, and a bundled
attack-scenario simulator that proves the cataloged rules still fire — **not** a SIEM replacement;
this feeds one.

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/siem/export?from=<ISO-8601>&to=<ISO-8601>` | ADMIN / SECURITY_ANALYST | JSON array of flat events for the range |
| GET | `/api/siem/export?from=<ISO-8601>&to=<ISO-8601>&format=ndjson` | ADMIN / SECURITY_ANALYST | Same events as newline-delimited JSON (`application/x-ndjson`), one object per line — the shape real SIEM/Splunk/Elastic bulk ingest expects |
| POST | `/api/siem/validate` | ADMIN / SECURITY_ANALYST, `demo` profile only | Replays 12 in-process scenarios (the original 10 `docs/demo-lab.md` scenarios plus 2 from the SOC Validation Module, see below) against the seeded demo agents/tools and returns each scenario's pass/fail plus which `DetectionRule` fired. A 13th scenario (MCP token misuse) is validated by a dedicated automated test instead — see below. 404s (profile inactive) outside `demo`, same as `/demo/**`. |

Each exported event is one flat object per `GatewayRequest`: `eventType`, `timestamp`, `agentId`,
`toolName`, `operation`, `targetResource`, `decision`, `riskScore`, `findings[]` (detector
category+confidence pairs only — never a raw matched value, the same discipline `DlpFinding`
already enforces), `approvalStatus`, `policyRuleIds[]`, and `traceId` (the existing
`GatewayRequest.correlationId`, reused rather than inventing a second identifier).

The detection-rule catalog (`detection_rules` table, seeded by `V16__detection_rule_catalog.sql`,
extended by `V19__soc_validation.sql`) names 15 identifiers that already fire today — 7 fixed
`PolicyEngine` rule ids, 4 `BehaviorBaselineRules` finding codes, 2 DLP rule ids from
`PolicyEngine.evaluateDlp`, plus `mcp-oauth-token-rejected` (existing MCP OAuth token validation)
and `codetrust-blocked` (Phase 3's code-assessment blocking) — it is a catalog of existing
controls, not new detection logic. Each catalog entry also carries a nullable MITRE ATT&CK
reference (`mitreAttackId`; `ATLAS:`-prefixed for a MITRE ATLAS, not classic ATT&CK, mapping) —
left null where forcing one would be a weak, invented reference (behavioral-anomaly detection
methods and the tool-misuse rule have no honest single-technique fit; see the V19 migration
comment for the full reasoning). `GET /siem/coverage` (operator UI, not an API endpoint) shows the
catalog joined against last-fired time (`agentshield_detection_rule_fired_total{rule="..."}`) and
last-validated time (from `/api/siem/validate` runs, persisted in `detection_validation_runs`).

## SOC Validation Module — `/api/siem/validation`

Folds the research plan's "AI SOC Validation Lab" (N1) into AgentShield as a module rather than a
separate product. Adds 2 more in-process scenarios to the simulator above (RAG data leakage,
scenario-11; an AI coding assistant introducing a secret, scenario-12) plus a vendor-neutral
alert-import validator: checks whether a downstream SIEM/alerting tool's actual exported alerts
match what AgentShield's scenario catalog says should be catchable.

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/api/siem/validation/scenarios/run` | ADMIN / SECURITY_ANALYST, `demo` profile only | Equivalent to `/api/siem/validate` under this module's namespace. |
| POST | `/api/siem/validation/alerts/import` | ADMIN / SECURITY_ANALYST | Body: `{"alerts": [{"alertName", "ruleId", "timestamp", "sourceEvent"}, ...]}` — a generic, vendor-neutral shape (no Elastic/Splunk/Logpresso-specific fields). Matches against the built-in `ExpectedDetectionsManifest`, persists a `ValidationRun`, and returns matched/missed scenarios plus any unexpected alert names. |
| GET | `/api/siem/validation/runs/{id}/report?format=html\|md` | ADMIN / SECURITY_ANALYST | Renders the stored run as an escaped HTML page or Markdown document (`md` is the default). |

**Scenario-10 (MCP token misuse) is deliberately not part of the 12-scenario in-process
simulator.** Genuinely proving a wrong-audience/issuer token gets rejected requires a live mock
OAuth authorization server, which only exists as test-only infrastructure
(`com.agentshield.support.MockOAuthServerController`, `src/test`) — adding an equivalent to
`src/main` would mean shipping mock authorization-server endpoints in every real deployment. It is
instead validated by a dedicated test, `McpTokenMisuseAttackScenarioTest`, which still records a
`DetectionValidationRun` row so it shows up in the coverage/validation dashboards.

**A 14th scenario from the original plan, certificate-expiry-near-miss, is not implemented at
all** — it is a TrustAtlas concept (certificate lifecycle), and this codebase has no certificate
management. The `/siem/validation` dashboard lists it explicitly as "N/A — TrustAtlas scope"
rather than silently omitting it.

## Error shape

Validation/not-found/conflict/auth errors return:

```json
{"timestamp": "2026-07-18T04:00:00Z", "status": 404, "error": "agent 99 not found"}
```
