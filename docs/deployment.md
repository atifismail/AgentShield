# Deployment Guide

## Profiles

| Profile | Purpose |
|---|---|
| *(none)* | Base behavior: no demo mock tools, no demo seed data. Fine for local development against a real database. |
| `demo` | Enables the bundled mock tools under `/demo/**` and seeds demo agents/tools/tokens — see `docs/demo-lab.md`. **Do not enable in production.** |
| `prod` | Secure-by-default overrides for a real deployment (see below). **Refuses to start** if `demo` is also active, or if `AGENTSHIELD_ADMIN_PASSWORD` is unset/still `changeit`. |
| `test` | Used automatically by the test suite (Testcontainers wiring); not something you set yourself. |

Set with `SPRING_PROFILES_ACTIVE=demo` (env var) or `--spring.profiles.active=demo` (arg). When the `demo` profile is off, `/demo/**` requires authentication like everything else and then 404s (no such controller is registered) — an anonymous request gets `401` rather than a bare `404`, which leaks less information about what's behind that path.

### The `prod` profile

Both the Helm chart and the plain Kubernetes manifests set `SPRING_PROFILES_ACTIVE=prod` by
default. It changes, relative to the base profile:

- Fails fast at startup (before the app accepts any traffic) if `demo` is also active, or if the
  admin password is missing/default — see `docs/operations.md`.
- Outbound tool calls are **deny-by-default**: only hosts explicitly listed in
  `agentshield.gateway.outbound.allowed-hosts` are reachable at all — there's no "allow anything
  that doesn't resolve to a private IP range" fallback like the base profile has. Add every real
  tool's hostname to that list before relying on it in production.
- `/actuator/info` and `/actuator/metrics` are no longer exposed (only `/actuator/health*` and
  `/actuator/prometheus` are).
- Thymeleaf template caching is on (off by default, which is meant for local editing).
- The session cookie is `Secure` + `HttpOnly` — this requires a TLS-terminating proxy in front;
  logging in over plain HTTP won't work with this profile active.

## Local development

```bash
SPRING_PROFILES_ACTIVE=demo ./gradlew bootRun
```

Requires a PostgreSQL instance reachable via `AGENTSHIELD_DB_URL` (defaults to `jdbc:postgresql://localhost:5432/agentshield`). For a quick local database:

```bash
docker run --name agentshield-postgres -e POSTGRES_DB=agentshield -e POSTGRES_USER=agentshield -e POSTGRES_PASSWORD=agentshield -p 5432:5432 -d postgres:16-alpine
```

## Docker Compose (recommended for trying AgentShield out)

```bash
docker compose up --build
```

This starts PostgreSQL and the AgentShield application together, with the `demo` profile active by default (see `docker-compose.yml`) so the attack lab works out of the box. The app listens on `http://localhost:8080`. Flyway migrations run automatically on startup. For a production-shaped run, override `SPRING_PROFILES_ACTIVE` to empty.

## Database support

AgentShield supports **PostgreSQL** (default) and **MariaDB**. Each has its own Flyway migration set under `src/main/resources/db/migration/{postgresql,mariadb}/` — same schema, vendor-appropriate DDL.

To run against MariaDB instead, set:

```bash
AGENTSHIELD_DB_VENDOR=mariadb
AGENTSHIELD_DB_URL=jdbc:mariadb://localhost:3306/agentshield
```

The test suite runs against a real MariaDB instance via Testcontainers (requires a running Docker daemon) rather than an in-memory database, so `./gradlew test` exercises the same SQL dialect a MariaDB deployment would use.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AGENTSHIELD_DB_VENDOR` | `postgresql` | `postgresql` or `mariadb` — selects the Flyway migration set |
| `AGENTSHIELD_DB_URL` | `jdbc:postgresql://localhost:5432/agentshield` | JDBC URL |
| `AGENTSHIELD_DB_USER` | `agentshield` | Database user |
| `AGENTSHIELD_DB_PASSWORD` | `agentshield` | Database password |
| `AGENTSHIELD_PORT` | `8080` | HTTP port |
| `AGENTSHIELD_ADMIN_USER` | `admin` | Bootstrap admin username |
| `AGENTSHIELD_ADMIN_PASSWORD` | `changeit` | Bootstrap admin password — change this before any non-local use |

## Kubernetes

Two options are provided:

- **Helm chart** at `helm/agentshield/`. Install with:

  ```bash
  kubectl create secret generic agentshield-db-credentials --from-literal=username=agentshield --from-literal=password=CHANGE_ME
  kubectl create secret generic agentshield-admin-credentials --from-literal=username=admin --from-literal=password=CHANGE_ME
  helm install agentshield ./helm/agentshield
  ```

- **Plain manifests** at `k8s/agentshield.yaml` for environments that don't use Helm. Same secret prerequisites apply.

Both configurations expect an external PostgreSQL instance (not bundled) reachable at the URL configured via `AGENTSHIELD_DB_URL`/`database.url`.

## Building a container image

```bash
docker build -t agentshield:0.1.0 .
```

Multi-stage build: compiles with `eclipse-temurin:21-jdk`, runs on `eclipse-temurin:21-jre` as a non-root user.

## Health and readiness

- Liveness: `GET /actuator/health/liveness`
- Readiness: `GET /actuator/health/readiness`
- Metrics (Prometheus format): `GET /actuator/prometheus`

## Backup and restore

AgentShield stores all state in PostgreSQL. Back up with standard tooling:

```bash
pg_dump -h <host> -U agentshield agentshield > agentshield-backup.sql
```

Restore into a fresh database before starting the application (Flyway will detect the existing schema version and skip already-applied migrations):

```bash
psql -h <host> -U agentshield agentshield < agentshield-backup.sql
```

Audit and policy-decision writes are append-only from the application's perspective — no in-place mutation of historical rows — so backups taken at any point are consistent for audit purposes.

For a docker-compose environment, `scripts/backup-postgres.sh`/`restore-postgres.sh` wrap the
equivalent `pg_dump --format=custom`/`pg_restore` commands against the running `postgres` service —
see `docs/runbooks/disaster-recovery.md` for the full procedure and post-restore checklist.
