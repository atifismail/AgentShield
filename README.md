# AgentShield

AgentShield is a runtime security gateway for AI agents. It sits between agents and the tools they call, enforces allow/deny/approval policy on every tool invocation, detects poisoned tools and malicious tool responses, and keeps a complete audit trail.

> Secure AI agents before they touch production systems.

## What it does

- **Gateway** — every agent tool call is routed through a single `/api/gateway/invoke` endpoint that decides ALLOW, DENY, or APPROVAL_REQUIRED.
- **Tool registry** — fingerprints tool schemas/descriptions and blocks a tool the moment it drifts from its last-approved version; MCP servers are discovered into the same registry, gated by explicit per-agent consent grants (the confused-deputy control) and OAuth 2.1 for servers that require it.
- **Policy engine** — a versioned, testable rule set (least privilege, environment-aware, approval-gated), plus database-backed overrides for operator-added rules without a code change.
- **Risk engine** — deterministic scoring by action category, environment, tool trust state, and detector confidence/category.
- **Detectors** — deterministic prompt-injection and secret-pattern scanning of tool responses, with confidence levels and categories, no paid API required.
- **Approval workflow** — high-risk actions queue for human sign-off; approving executes the action immediately, with row-level locking so a duplicate approval can't execute it twice.
- **Response forensics** — every tool response gets a hashed, sanitized forensic record (raw body retained only if explicitly enabled and encrypted).
- **Audit trail** — every request produces a searchable, correlated, tamper-evident (hash-chained) audit record.
- **Metrics & docs** — Prometheus-format metrics at `/actuator/prometheus`, interactive API docs at `/swagger-ui.html`.

See `docs/architecture.md` and `docs/threat-model.md` for the full design and the specific risks each control addresses.

## Tech stack

Java 21, Spring Boot, Spring Security, Spring Data JPA, PostgreSQL (default) or MariaDB, Flyway, Gradle on the backend; server-rendered Bootstrap 5 + jQuery + DataTables + Chart.js on the frontend. No paid or cloud-only services required.

## Quickstart

```bash
# Full stack (app + PostgreSQL) via Docker Compose
docker compose up

# Or run against a local PostgreSQL
./gradlew bootRun

# Run the test suite (real MariaDB via Testcontainers — needs a running Docker daemon)
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

Past MVP: the core gateway, policy/risk/detection engines, approval workflow, tamper-evident
audit trail, agent token lifecycle, tool drift detection, MCP tool discovery and consent/OAuth
authorization, response forensics, production hardening, and OpenAPI docs are implemented and
tested (unit, integration, and negative-security-path coverage) against both PostgreSQL and
MariaDB. `docs/threat-model.md` tracks known gaps not yet covered — notably tool/skill
supply-chain provenance (signing/pinning) and local-tool sandboxing — which are the current
priorities. See the roadmap issues for what's next.

## License

GPLv3 — see [`LICENSE`](LICENSE).
