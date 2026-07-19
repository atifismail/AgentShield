# Runbook: Key and Token Rotation

## Agent credentials

Full procedure in `docs/operations.md` "Agent token rotation" — summary:

- **Routine/scheduled rotation** (no suspected compromise): issue a new credential
  (`POST /api/agents/{id}/credentials`), roll it out to the agent's deployed config, then revoke
  the old one (`POST /api/agents/{id}/credentials/{credentialId}/revoke`) once confirmed switched
  over. Zero downtime.
- **Suspected leak/compromise**: `POST /api/agents/{id}/rotate-token` — revokes every active
  credential for that agent and issues one new one in a single call. Accept the downtime; don't
  wait for a graceful overlap window when a credential may be in a leaked state.

Both are ADMIN-only and audited (`agent.credential_issued`/`_revoked` event types) — confirm the
rotation shows up on the Audit page after the fact.

## Admin password (`AGENTSHIELD_ADMIN_PASSWORD`)

This only seeds the *initial* admin user (`AdminUserInitializer` — only runs once, when the
`app_users` table is empty). Rotating it after first boot means changing the actual user's
password through the running application, not the environment variable:

1. Log in as an existing ADMIN user.
2. Use the admin user management UI/API to set a new password for the account (or create a new
   ADMIN account and disable the old one, if you also want to rotate *who* holds admin access).
3. Update wherever `AGENTSHIELD_ADMIN_PASSWORD` is stored in your secret manager for consistency,
   even though it won't be re-read on restart — it's confusing to leave it stale, and some
   deployment tooling may display it as "the" admin password.

There's no dedicated single-command rotation endpoint for this today — it goes through the normal
user-management path, same as any other `AppUser`.

## Encryption keys

Two independent AES-256-GCM keys, each `agentshield.<x>.encryption-key` / `AGENTSHIELD_<X>_ENCRYPTION_KEY`,
deliberately **not** shared key material (different blast radius if one leaks — see
`docs/operations.md`):

- `agentshield.audit.raw-response-encryption-key` — encrypts raw tool response bodies, only when
  raw retention is explicitly enabled (off by default).
- `agentshield.mcp.oauth-token-encryption-key` — encrypts cached MCP OAuth access tokens.

**Rotating either key re-encrypts nothing automatically** — there's no key-versioning or
re-encryption job in this codebase. Rotating a key makes every *existing* encrypted value
unreadable (`McpTokenEncryptor`/the raw-response encryptor will fail to decrypt rows written under
the old key). Practical procedure:

1. Generate a new key: `openssl rand -base64 32`.
2. For the OAuth token key: rotating it is low-cost — cached tokens are just re-fetched from the
   MCP server's authorization server on next use (`McpOAuthTokenService` fetches fresh if
   decryption/lookup fails to produce a usable token). Just update the env var and restart; no
   manual cleanup needed beyond expecting a burst of fresh token-acquisition calls right after.
3. For the raw-response encryption key: rotating it **orphans any previously-stored encrypted raw
   responses** (they become permanently undecryptable, since there's no re-encryption path). If
   you need those specific historical records, decrypt and archive them separately *before*
   rotating. Otherwise, accept the loss — raw retention is off by default for exactly this kind of
   sensitivity, so this should be a rare, deliberate operation, not routine.
4. Restart the app with the new key set. Verify via a fresh MCP OAuth-backed call (for the OAuth
   key) or a fresh raw-retention-enabled tool call (for the response key) that new writes succeed.

## Database credentials

Standard practice, no AgentShield-specific procedure: update the credential at your database/secret
manager, then restart the app with the new `AGENTSHIELD_DB_PASSWORD`. HikariCP re-establishes
connections on restart; there's no live credential-swap without a restart in this codebase.
