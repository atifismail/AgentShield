# AgentShield

AgentShield is a runtime security gateway for AI agents. It sits between agents and the tools they call, enforces allow/deny/approval policy on every tool invocation, detects poisoned tools and malicious tool responses, and keeps a complete audit trail.

> Secure AI agents before they touch production systems.

## What it does

- **Gateway** — every agent tool call is routed through a single `/api/gateway/invoke` endpoint that decides ALLOW, DENY, or APPROVAL_REQUIRED.
- **Tool registry** — fingerprints tool schemas/descriptions and blocks a tool the moment it drifts from its last-approved version.
- **Policy engine** — a versioned, testable rule set (least privilege, environment-aware, approval-gated) with a human-readable reason on every decision.
- **Risk engine** — deterministic scoring by action category, environment, tool trust state, and detector hits.
- **Detectors** — deterministic prompt-injection and secret-pattern scanning of tool responses, no paid API required.
- **Approval workflow** — high-risk actions queue for human sign-off instead of executing blind.
- **Audit trail** — every request produces a searchable, correlated audit record.

See `docs/architecture.md` and `docs/threat-model.md` for the full design and the specific risks each control addresses.

## Tech stack

Java 21, Spring Boot, Spring Security, Spring Data JPA, PostgreSQL (default) or MariaDB, Flyway, Gradle on the backend; server-rendered Bootstrap 5 + jQuery + DataTables + Chart.js on the frontend. No paid or cloud-only services required.

## Quickstart

```bash
# Full stack (app + PostgreSQL) via Docker Compose
docker compose up

# Or run against a local PostgreSQL
./gradlew bootRun

# Run the test suite (H2, no external dependencies)
./gradlew test
```

Then open `http://localhost:8080` for the dashboard.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — components and request flow
- [`docs/threat-model.md`](docs/threat-model.md) — the six risks AgentShield addresses and their controls
- [`docs/policy-guide.md`](docs/policy-guide.md) — default policy rules, risk scoring, detection patterns
- [`docs/api.md`](docs/api.md) — REST API reference
- [`docs/deployment.md`](docs/deployment.md) — Docker Compose, Helm, Kubernetes
- [`docs/operations.md`](docs/operations.md) — configuration, backups, production checklist
- [`docs/demo-lab.md`](docs/demo-lab.md) — run the 5 scripted attack scenarios against a live instance

## Project status

Early-stage, MVP scope. See the roadmap issues for what's next.

## License

GPLv3 — see [`LICENSE`](LICENSE).
