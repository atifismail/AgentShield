# Operations Guide

## Health and readiness

- `GET /actuator/health` — overall health, including database connectivity.
- `GET /actuator/health/liveness` / `GET /actuator/health/readiness` — Kubernetes probe endpoints.
- `GET /actuator/prometheus` — Prometheus-format metrics scrape endpoint.
- `GET /actuator/metrics` — individual metric browsing.

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

- Change `AGENTSHIELD_ADMIN_PASSWORD` and rotate it out of plain environment variables (use your platform's secret manager).
- Point `AGENTSHIELD_DB_URL` at a managed, backed-up PostgreSQL instance.
- Put a TLS-terminating proxy or ingress in front of the service — AgentShield itself serves plain HTTP.
- Review the default policy version and adjust rules for your environment before enabling `ENFORCE` mode broadly; use dry-run first.
- Scrape `/actuator/prometheus` from your existing monitoring stack.
