# Operations Guide

## Health and readiness

- `GET /actuator/health` — overall health, including database connectivity.
- `GET /actuator/health/liveness` / `GET /actuator/health/readiness` — Kubernetes probe endpoints.
- `GET /actuator/prometheus` — Prometheus-format metrics scrape endpoint.
- `GET /actuator/metrics` — individual metric browsing.

## Metrics

Product-specific metrics (`com.agentshield.metrics.GatewayMetrics`), on top of the usual JVM/HTTP
ones Spring Boot exposes automatically:

**Counters**

| Name | Tags | Meaning |
|---|---|---|
| `agentshield_gateway_requests_total` | — | Every `/api/gateway/invoke` call, including auth failures |
| `agentshield_gateway_decisions_total` | `decision` (ALLOW/DENY/APPROVAL_REQUIRED) | Every policy decision recorded, pre- and post-response-scan |
| `agentshield_gateway_denied_total` | — | Subset of the above where `decision=DENY` |
| `agentshield_gateway_approval_required_total` | — | Subset of the above where `decision=APPROVAL_REQUIRED` |
| `agentshield_tool_drift_detected_total` | — | A tool's live fingerprint stopped matching its approved hash |
| `agentshield_response_blocked_total` | — | A tool response was blocked by the secret/injection scanners |
| `agentshield_incidents_created_total` | — | An incident record was created |
| `agentshield_mcp_oauth_token_rejected_total` | — | An OAuth token from an MCP server's authorization server failed validation (wrong audience/issuer/expired/scope) |

**Gauges**

| Name | Meaning |
|---|---|
| `agentshield_audit_integrity_valid` | `1` if the last scheduled audit-chain verification (every 30m, `AuditIntegrityService.scheduledVerify`) passed, `0` if it found tampering |

**Timers**

| Name | Measures |
|---|---|
| `agentshield_gateway_latency_seconds` | The full `/api/gateway/invoke` call, auth through response |
| `agentshield_policy_evaluation_latency_seconds` | Request-time and response-time policy evaluation |
| `agentshield_tool_forward_latency_seconds` | The outbound call to the tool endpoint |

## Monitoring and alerting

`monitoring/prometheus-alerts.yml` is a ready-to-load Prometheus rule file covering the
production-readiness checklist's alerting requirements against the metrics above: deny spikes,
blocked responses, tool drift, new incidents, audit integrity failure, MCP OAuth token rejections,
elevated gateway latency, and requests that don't produce a matching policy decision (a fail-closed
violation, per AGENTS.md rule 6, that would indicate a real bug). Point your Prometheus server's
`rule_files` at it, or import it into whatever Alertmanager-compatible tooling you run — it assumes
a scrape job labeled `job="agentshield"` against `/actuator/prometheus`; adjust the selector if
yours differs. Every metric it references is emitted unconditionally, no extra config needed.

## Configuration

All runtime configuration is environment-variable driven (see `src/main/resources/application.yml` for the full list and defaults):

| Variable | Purpose | Default |
|---|---|---|
| `AGENTSHIELD_DB_VENDOR` | `postgresql` or `mariadb` | `postgresql` |
| `AGENTSHIELD_DB_URL` | JDBC URL | `jdbc:postgresql://localhost:5432/agentshield` |
| `AGENTSHIELD_DB_USER` | Database username | `agentshield` |
| `AGENTSHIELD_DB_PASSWORD` | Database password | `agentshield` |
| `AGENTSHIELD_PORT` | HTTP port | `8080` |
| `AGENTSHIELD_ADMIN_USER` | Bootstrap admin username | `admin` |
| `AGENTSHIELD_ADMIN_PASSWORD` | Bootstrap admin password | `changeit` — **change this before any non-local use** |
| `AGENTSHIELD_ENABLE_API_DOCS` | Turns on `/swagger-ui.html` + `/v3/api-docs` under the `prod` profile | `false` (always on outside `prod`) |

## Database migrations

Schema changes are managed exclusively through Flyway migrations, with one vendor-specific set
per supported database: `src/main/resources/db/migration/postgresql/` and
`src/main/resources/db/migration/mariadb/`. A schema change needs a matching migration added to
both, with the same version number and the same effect, even though the DDL syntax differs.
Never modify a migration that has already been applied to a shared environment — add a new one
instead. `spring.jpa.hibernate.ddl-auto` is fixed at `validate`; Hibernate will refuse to start
if the schema and entities disagree, which is intentional.

## Agent token rotation

Agents authenticate with a bearer token whose SHA-256 hash is the only thing stored — the
plaintext is returned exactly once, at issuance. To rotate without downtime:

1. `POST /api/agents/{id}/credentials` (body `{"validForMinutes": <optional>}`) issues a new
   credential alongside the existing one and returns its plaintext token.
2. Update the agent's deployed configuration to use the new token.
3. `POST /api/agents/{id}/credentials/{credentialId}/revoke` on the old credential once you've
   confirmed the agent is using the new one.

`POST /api/agents/{id}/rotate-token` does all of this in one call — revokes every active
credential for the agent and issues a single new one — for the case where you don't need an
overlap window (e.g. responding to a suspected leak). Both paths are ADMIN-only and audited.

## Backup and restore

The only durable state is the PostgreSQL database. Standard `pg_dump`/`pg_restore` (or your managed Postgres provider's snapshot mechanism) is sufficient:

```bash
pg_dump -h localhost -U agentshield agentshield > agentshield-backup.sql
psql -h localhost -U agentshield agentshield < agentshield-backup.sql
```

Take a backup before applying a new Flyway migration in production.

## Fail-closed behavior

The gateway is fail-closed, unconditionally: any unexpected error while evaluating policy or
risk results in a DENY, never an ALLOW. There is no fail-open configuration in this release —
this is deliberate (see AGENTS.md rule 6).

## Audit trail integrity

Every audit event is part of a SHA-256 hash chain (each event's hash covers its own content plus
the previous event's hash), so a historical row edited or deleted directly in the database — not
through the application — is detectable. Check it any time:

```bash
curl -u admin:changeit http://localhost:8080/api/audit/verify-integrity
```

`{"valid": true, "eventsChecked": N}` means the chain is intact. `{"valid": false,
"firstBrokenEventId": <id>, "reason": ...}` means something changed row `<id>` outside the
application — investigate immediately, this should never happen in normal operation. The same
check is available as a "Verify Integrity" button on the Audit page in the admin UI. Rows written
before this feature shipped have no hash and are skipped rather than reported as broken.

## Tool response forensics

Every gateway call that reaches a tool records a `gateway_tool_responses` row: HTTP status code,
a SHA-256 hash of the raw response body, a bounded `response_summary`, and (if the response was
blocked) the block reason and the detector indicator names that matched — never the matched text
itself. This lets an investigator confirm what happened without the database holding a permanent
copy of whatever the tool returned, including any secrets or injected instructions in it.

The raw response body itself is **not** stored by default. To opt in for a specific deployment
(e.g. a regulated environment that needs full forensic replay), set:

- `agentshield.audit.retain-raw-tool-responses=true`
- `agentshield.audit.raw-response-encryption-key=<base64-encoded 32-byte AES-256 key>`

The application refuses to start if retention is enabled without a valid key — there is no
plaintext-fallback path. Generate a key with `openssl rand -base64 32` and manage it via your
platform's secret manager, the same as `AGENTSHIELD_ADMIN_PASSWORD`. When enabled, each raw body
is encrypted with AES-256-GCM using a fresh random IV per response before being written to
`raw_response_encrypted`.

## MCP authorization and consent

Every MCP-backed tool call additionally requires an ACTIVE `McpConsent` grant for the calling
agent, regardless of whether the target MCP server itself needs OAuth — see
`docs/policy-guide.md` rule 11 and `docs/threat-model.md`. Manage grants at
`POST /api/mcp-consents` or the MCP page in the admin UI (`/mcp-servers`).

For MCP servers configured with `authMode: OAUTH2` (`PATCH /api/mcp-servers/{id}/auth`),
AgentShield caches the OAuth access token it acquires for itself, encrypted the same way as raw
tool response retention above. Set:

- `agentshield.mcp.oauth-token-encryption-key=<base64-encoded 32-byte AES-256 key>`

Unlike raw-response retention this key is only required once at least one MCP server is
configured with `authMode: OAUTH2` — token acquisition for that server fails closed with a clear
audit reason (`mcp.oauth_token_rejected`) if the key isn't set, rather than the whole application
refusing to start. `oauthClientSecretRef` (set alongside `authMode`) is a reference name resolved
against ordinary Spring configuration (an environment variable of that exact name, or any other
configured property source) — the plaintext secret itself is never stored in the database.

## Stdio MCP transport and sandboxing

Full design: `design-stdio-sse-mcp-transport-and-sandboxing.md` (local-only, not published — same
as the other design docs, but this operational summary is the part every deployer needs).

**Off by default** (`agentshield.stdio.enabled=false`). Registering or invoking a `STDIO`-transport
MCP server fails closed while disabled — this is the highest-risk capability in the codebase
(arbitrary local subprocess execution), so it's an explicit opt-in, not a default posture.

To enable it:

```yaml
agentshield:
  stdio:
    enabled: true
    allowed-commands: [node, python3, npx]   # empty by default — nothing is spawnable until listed
    sandbox-root: mcp-sandboxes               # each server gets its own subdirectory here
    idle-timeout-minutes: 15
    call-timeout-seconds: 30
    max-output-bytes: 1048576
    max-concurrent-processes: 10
```

**Environment variables are empty by default, per server.** `stdioEnvAllowlist` (set at
registration, comma-separated names — never values) controls exactly which variable names are
copied into a spawned subprocess's environment, resolved from AgentShield's own process
environment at spawn time. Nothing is passed through automatically — not even `PATH`; if a stdio
tool fails with "command not found," add `PATH` to that server's allowlist. **`HOME` and
`USERPROFILE` are treated the same as any other name (they may be allowlisted if a tool genuinely
needs them) but are sensitive**: either can expose the AgentShield process's home-directory path
and, more importantly, many interpreters consult `HOME`/`USERPROFILE` to locate their *own*
credential caches (`~/.npmrc`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, etc.) — only
allowlist either when a specific tool requires it, and know what's in that directory before you
do. If an allowlisted name isn't actually set on the AgentShield process itself, spawning fails
closed with a clear error naming the missing variable.

**AgentShield cannot enforce per-process network egress or memory/CPU limits from inside the
JVM** — there is no portable API for this without OS namespaces/cgroups/seccomp, which this
project deliberately avoids depending on (no added native dependency, no shell-out). These must be
enforced at the deployment layer instead:

- A Kubernetes `NetworkPolicy` restricting egress for any deployment with stdio enabled — this is
  the real mitigation for the fact that a spawned subprocess has the same network access as
  AgentShield itself.
- Pod `resources.limits` (`memory`, `cpu`) as the backstop for the fact that AgentShield can't cap
  an individual subprocess's resource usage — blunt (a runaway child can get the whole pod
  OOM-killed), but real.
- `securityContext: { runAsNonRoot: true, readOnlyRootFilesystem: true }` with
  `agentshield.stdio.sandbox-root` mounted as a separate writable volume — the only writable path.
- Only register stdio MCP servers whose code you trust to the same degree as a local dependency —
  a stdio MCP server *is* local code execution by design; AgentShield's consent/approval layers
  control who may invoke it, not what its code does once running.

**Production startup guard.** If `agentshield.stdio.enabled=true` while the `prod` Spring profile
is active, the app refuses to start unless `agentshield.stdio.external-sandbox-acknowledged=true`
is also set — confirming the checklist above has actually been applied, not just read. This
mirrors the existing "refuses to start with the default admin password in prod" check
(`ProductionSafetyChecks`) — it can't verify a `NetworkPolicy` actually exists any more than that
check can verify a password is *good*, only that a known-bad default isn't still in place; its
purpose is to convert a silent, easy-to-miss gap into a loud, impossible-to-miss one.

```
AGENTSHIELD_STDIO_ENABLED=true
AGENTSHIELD_STDIO_EXTERNAL_SANDBOX_ACKNOWLEDGED=true
```

Every subprocess start/stop/crash and every call-timeout/output-size rejection is audited
(`mcp.stdio_process_started`/`_stopped`/`_crashed`/`_spawn_failed`, `mcp.stdio_call_timeout`,
`mcp.stdio_output_rejected`) — monitor these the same way you'd monitor deny spikes elsewhere.

**Windows note** (this project is developed on Windows; production is Linux-only per the
`Dockerfile`): npm/npx-installed CLI tools on Windows are commonly `.cmd` batch-file shims, which
Windows can only launch via `cmd.exe /c`, reintroducing a narrower metacharacter risk that direct
`.exe`/binary invocation doesn't have. `agentshield.stdio.allow-windows-batch-commands` defaults to
`false` (rejecting `.cmd`/`.bat` commands) for exactly this reason — leave it off in any
Linux/production deployment; it exists only for local Windows development convenience.

## SSE MCP transport

Much lighter than stdio — SSE is HTTP-based, so it's governed by the same
`OutboundEndpointValidator` SSRF policy and OAuth2 flow as the plain `HTTP` transport, with no
feature flag, no command allowlist, and no environment/filesystem concerns. Config:

```yaml
agentshield:
  mcp:
    sse:
      call-timeout-seconds: 30
      idle-timeout-minutes: 15
      max-response-bytes: 1048576
      reconnect-max-attempts: 3
      reconnect-initial-backoff-millis: 500
```

Every connection open/close/failure and call-timeout/oversized-response rejection is audited
(`mcp.sse_connection_opened`/`_closed`/`_failed`, `mcp.sse_call_timeout`,
`mcp.sse_response_rejected`) — monitor these the same way as the stdio events above.

## Tool/skill supply-chain provenance trust policy

Every tool version gets an automatic Level-1 checksum record; Level 2 (Sigstore signature
verification, `docs/api.md` "Supply-chain provenance") is opt-in per `ToolSourceType`
(`BUILT_IN`, `MCP`, `LOCAL_SKILL`, `REMOTE_PACKAGE`, `CUSTOM_HTTP`) via:

```yaml
agentshield:
  provenance:
    require-signature-for: []   # e.g. [MCP, REMOTE_PACKAGE] — empty means Level 1 everywhere
```

An empty list (the shipped default) means every tool stays at Level 1 (checksum-only) — nothing
currently approved becomes blocked by upgrading to a version with this feature. An operator opts
a source type in deliberately, once they're ready to require it; `BUILT_IN` is always exempt
regardless of this setting. AgentShield never signs anything and holds no private key material —
it only verifies signatures the tool/skill publisher already produced in their own CI (see
`docs/api.md` for the exact artifact convention). Self-managed/offline signing keys (rather than
Sigstore's public keyless infrastructure) are already supported on the *signing* side by cosign's
existing KMS provider integrations (e.g. `cosign sign-blob --key openbao://mykey`) — this doesn't
change anything about how AgentShield verifies.

## Rate limiting and request size

`POST /api/gateway/invoke` is rate-limited per bearer token (falling back to remote address),
default 60 requests/minute (`agentshield.gateway.rate-limit.max-requests-per-minute`); a limit
breach returns `429`. All `/api/**` requests are capped at 1 MiB by default
(`agentshield.gateway.max-request-bytes`); larger requests get `413`. The gateway also enforces a
separate, business-level maximum on the `input` payload specifically (`agentshield.gateway.max-payload-bytes`,
default 256 KiB, policy rule `deny-oversized-payload`).

## Running locally

```bash
# Full stack (app + PostgreSQL)
docker compose up

# App only, against a locally running PostgreSQL
./gradlew bootRun

# Tests — integration tests run against a real MariaDB via Testcontainers
# (requires a running Docker daemon), no manual database setup needed
./gradlew test
```

## Production checklist

- Set `SPRING_PROFILES_ACTIVE=prod` (both the Helm chart and `k8s/agentshield.yaml` already do this) — see `docs/deployment.md` for exactly what it changes. It will refuse to start rather than come up insecure, so treat a crash-on-boot here as the check working, not a bug.
- Change `AGENTSHIELD_ADMIN_PASSWORD` to a real value and rotate it out of plain environment variables (use your platform's secret manager) — the `prod` profile won't start with the default `changeit`.
- Add every real tool's hostname to `agentshield.gateway.outbound.allowed-hosts` — the `prod` profile denies all outbound tool calls by default otherwise.
- Point `AGENTSHIELD_DB_URL` at a managed, backed-up PostgreSQL instance.
- Put a TLS-terminating proxy or ingress in front of the service — AgentShield itself serves plain HTTP, and the `prod` profile's `Secure` session cookie requires TLS to work at all.
- Review the default policy version and adjust rules for your environment before enabling `ENFORCE` mode broadly; use dry-run first.
- Scrape `/actuator/prometheus` from your existing monitoring stack.
- Periodically check `GET /api/audit/verify-integrity` (or the "Verify Integrity" button on the Audit page).
- Leave `agentshield.stdio.enabled=false` unless you specifically need stdio MCP servers — if you do enable it, apply the `NetworkPolicy`/resource-limits/`securityContext` checklist under "Stdio MCP transport and sandboxing" above *before* setting `agentshield.stdio.external-sandbox-acknowledged=true` (the app won't start in `prod` without it once stdio is enabled, by design).
