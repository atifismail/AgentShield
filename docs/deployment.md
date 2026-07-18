# Deployment Guide

## Local development

```bash
./gradlew bootRun
```

Requires a PostgreSQL instance reachable via `AGENTSHIELD_DB_URL` (defaults to `jdbc:postgresql://localhost:5432/agentshield`). For a quick local database:

```bash
docker run --name agentshield-postgres -e POSTGRES_DB=agentshield -e POSTGRES_USER=agentshield -e POSTGRES_PASSWORD=agentshield -p 5432:5432 -d postgres:16-alpine
```

## Docker Compose (recommended for trying AgentShield out)

```bash
docker compose up --build
```

This starts PostgreSQL and the AgentShield application together. The app listens on `http://localhost:8080`. Flyway migrations run automatically on startup.

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
