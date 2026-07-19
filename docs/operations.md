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

**Timers**

| Name | Measures |
|---|---|
| `agentshield_gateway_latency_seconds` | The full `/api/gateway/invoke` call, auth through response |
| `agentshield_policy_evaluation_latency_seconds` | Request-time and response-time policy evaluation |
| `agentshield_tool_forward_latency_seconds` | The outbound call to the tool endpoint |

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
