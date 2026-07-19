# Secrets Management

A review of where secrets exist in AgentShield's design, what's already enforced, and what remains
an operator responsibility. Written for the production-readiness checklist item "secrets management
verified for production; no plaintext secrets in config, logs, audit events, or database fields."

## Inventory: every secret this system handles

| Secret | At rest | In transit / API | Notes |
|---|---|---|---|
| Agent bearer tokens | SHA-256 hash only (`agent_credentials.token_hash`) — plaintext exists only at issuance response, never stored | Bearer header on every gateway call | `TokenHasher.sha256Hex`; a leaked database dump cannot be used to authenticate as an agent |
| Admin/user passwords | BCrypt hash only (`app_users.password_hash`) | Basic/form-login credentials, never returned by any API | Standard Spring Security `PasswordEncoder` |
| Raw tool response bodies (optional) | AES-256-GCM encrypted (`gateway_tool_responses.raw_response_encrypted`), **off by default** | Never returned via any API — write-only from the app's perspective, read path doesn't exist | `RawResponseEncryptor`; key: `agentshield.audit.raw-response-encryption-key` |
| MCP OAuth access tokens | AES-256-GCM encrypted (`mcp_oauth_tokens.access_token_encrypted`) | Never returned via any API or audit event — only the *outcome* (validated/rejected) is recorded | `McpTokenEncryptor`; key: `agentshield.mcp.oauth-token-encryption-key`; independent key from the one above — a leak of one doesn't compromise the other |
| MCP OAuth client secret | **Never stored** — only a *reference name* (`mcp_servers.oauth_client_secret_ref`) is persisted; the actual value is resolved from the deployment's own config/secret source at token-request time | The reference name (not the value) is returned by `GET /api/mcp-servers` — this is intentional, same as exposing an env var *name* | Same pattern as `stdioEnvAllowlist` (§ below) |
| Stdio MCP subprocess environment values | **Never stored** — `stdioEnvAllowlist` persists variable *names* only; values are resolved from `System.getenv()` on the AgentShield process at spawn time | Names (not values) returned by `GET /api/mcp-servers` | design-stdio-sse-mcp-transport-and-sandboxing.md §5.2 |
| Database credentials | Deployment-level env var (`AGENTSHIELD_DB_PASSWORD`) | JDBC connection only | Not an AgentShield-internal secret — standard deployment secret |
| Detected secrets in tool responses (the thing `SecretDetector` finds) | **Never persisted in cleartext** when a match is found — `response_summary` is replaced with `"[response blocked — see block_reason and detector_matches_json]"`; `detector_matches_json` stores only indicator *names* (e.g. `"aws-access-key"`), never the matched text | Never returned to the agent | `GatewayServiceIntegrationTest.secretInResponseIsBlockedForExternalTransferAndCreatesIncident` asserts this across audit messages, metadata, incident summary, and the full serialized API response |

## What's already enforced (verified by reading the code, not just design intent)

- **No plaintext secret ever appears in an audit event.** `AuditService.record()` accepts a
  `metadata` map that callers populate — every call site that could plausibly include something
  sensitive (OAuth token audit events, secret-detection audit events) passes only indicator
  names/reasons, never raw values. Confirmed by grep: no call site passes a token, password, or
  detector-matched string into `metadata` or `message`.
- **No plaintext secret is logged.** Grepped every `log.info`/`log.debug`/`log.warn`/`log.error`
  call site referencing password/token/secret/credential — the only match
  (`AdminUserInitializer`) logs the *username* of the bootstrap admin account, never the password.
- **Two independent encryption keys**, not shared key material, for the two things this app
  optionally encrypts at rest (raw tool responses, cached MCP OAuth tokens) — a compromise of one
  key's blast radius doesn't extend to the other.
- **Encrypted values are never returned by any API response** — the raw-response and OAuth-token
  ciphertext columns have no corresponding read endpoint at all, encrypted or not.
- **Reference-not-value pattern** for both MCP OAuth client secrets and stdio environment values —
  the database never holds the actual secret material for either, only names that get resolved
  against the *deployment's* own environment/secret source at the moment they're needed.

## Operator responsibilities (not something the application can enforce for you)

- **`AGENTSHIELD_ADMIN_PASSWORD`, `AGENTSHIELD_DB_PASSWORD`, the two `*_ENCRYPTION_KEY` values, and
  any MCP OAuth client secret / stdio env values** must themselves be provisioned through your
  platform's actual secret manager (Kubernetes Secrets, a cloud secret manager, etc.) — not
  committed to source control or left as plaintext in a `docker-compose.override.yml` you forget
  to gitignore. `ProductionSafetyChecks` catches the specific case of a still-default admin
  password in the `prod` profile; it cannot detect a real password that's merely stored insecurely
  elsewhere in your infrastructure.
- **Rotate keys/credentials on a schedule and after any suspected exposure** — see
  `docs/runbooks/key-token-rotation.md`. The application has no automatic rotation.
- **Database-level access control** is entirely your responsibility — AgentShield's encryption
  protects specific *columns* it chooses to encrypt; it does not protect the database as a whole
  from someone with direct SQL access reading `agent_credentials.token_hash` (safe, it's a hash)
  or, more importantly, tables this document doesn't cover (agents, tools, policies) that aren't
  secrets but are still sensitive configuration.
- **This document doesn't cover git history** — if a real secret was ever committed (even to a
  since-deleted file), it remains in git history until purged. Not applicable to this project's
  own repository as far as this review found, but worth stating as a standing check for any fork.

## Known gap

Neither encryption key supports rotation-with-re-encryption (see
`docs/runbooks/key-token-rotation.md`) — rotating either key orphans data encrypted under the old
one. For the OAuth token key this is low-cost (tokens are transparently re-acquired — see the
`McpOAuthTokenService.getValidToken` fallback added alongside this review). For the raw-response
key, rotation is destructive to historical encrypted responses by design; this is an accepted
tradeoff given raw retention is off by default and, when enabled, is already an explicit,
deliberate operator choice.
