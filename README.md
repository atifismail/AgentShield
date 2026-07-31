# AgentShield

**Open-source AI Agent Security Gateway.** AgentShield sits between agents and the tools they call, enforces allow/deny/approval policy on every tool invocation, detects poisoned tools and malicious tool responses, and keeps a complete audit trail.

> Stop unsafe AI agent actions before they reach production systems.

## What it does

- **Gateway** — every agent tool call is routed through a single `/api/gateway/invoke` endpoint that decides ALLOW, DENY, or APPROVAL_REQUIRED.
- **Tool registry** — fingerprints tool schemas/descriptions and blocks a tool the moment it drifts from its last-approved version; MCP servers are discovered into the same registry, gated by explicit per-agent consent grants (the confused-deputy control) and OAuth 2.1 for servers that require it.
- **Supply-chain provenance** — every tool version gets an automatic checksum record, plus opt-in Sigstore keyless signature verification (AgentShield only ever verifies — it never signs or holds a private key).
- **Policy engine** — a versioned, testable rule set (least privilege, environment-aware, approval-gated), plus database-backed overrides for operator-added rules without a code change.
- **Risk engine** — deterministic scoring by action category, environment, tool trust state, and detector confidence/category.
- **Detectors** — deterministic prompt-injection, secret-pattern, and PII scanning of both inbound tool-call arguments and tool responses, with confidence levels and categories, no paid API required.
- **DLP** — operator-configured classification profiles decide allow/redact/tokenize/block/approval-required per detector match; a standalone endpoint lets an external RAG ingestion pipeline classify a chunk before indexing it.
- **Code Trust** — submit an AI-coding-assistant scan result (`scripts/agentshield-code-scan.sh` is a thin reference CLI, not a SAST engine); a CRITICAL/HIGH finding blocks the commit until a human reviews it, and a passing assessment gets a locally Ed25519-signed, independently verifiable receipt.
- **SIEM export & SOC Validation** — a flat, SIEM-friendly event export plus a named `DetectionRule` catalog (15 identifiers, each with an optional MITRE ATT&CK reference); an in-process attack simulator replays 12 scenarios to prove the catalog still fires, and a vendor-neutral alert-import validator checks whether a downstream SIEM's actual alerts match what's expected.
- **Approval workflow** — high-risk actions queue for human sign-off; approving executes the action immediately, with row-level locking so a duplicate approval can't execute it twice. Approval routing profiles route a request to the correct role by priority/predicate match; an explicit, expiring per-agent tool grant model is available as a data-driven alternative to the legacy allowed-tool-group string (opt-in via `agentshield.grants.transition-mode`, default unchanged).
- **Policy evaluation/simulation** — run a versioned suite of synthetic fixtures through the real pre-call policy/grant/MCP-consent components with zero tool forwarding, to test a policy or tool change before relying on it in production.
- **Response forensics** — every tool response gets a hashed, sanitized forensic record (raw body retained only if explicitly enabled and encrypted).
- **Audit trail & evidence export** — every request produces a searchable, correlated, tamper-evident (hash-chained) audit record; a versioned JSON/SARIF evidence bundle (`docs/schemas/`) exports tool-call/policy-decision/approval/evaluation-run events for a date range.
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
- [`docs/threat-model.md`](docs/threat-model.md) — the seven risks AgentShield addresses and their controls
- [`docs/policy-guide.md`](docs/policy-guide.md) — default policy rules, risk scoring, detection patterns
- [`docs/api.md`](docs/api.md) — REST API reference
- [`docs/deployment.md`](docs/deployment.md) — Docker Compose, Helm, Kubernetes
- [`docs/operations.md`](docs/operations.md) — configuration, backups, production checklist
- [`docs/demo-lab.md`](docs/demo-lab.md) — run the 5 scripted attack scenarios against a live instance

## Community & support

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build/test workflow, PR process, security disclosure
- [`ROADMAP.md`](ROADMAP.md) — what's shipped, planned, and under consideration
- [`SUPPORT.md`](SUPPORT.md) — community support channels and commercial support options

## Project status

Past MVP: the core gateway, policy/risk/detection engines, DLP scanning (inbound arguments,
responses, and a standalone RAG-chunk endpoint), an AI-coding-assistant code-trust workflow
(block/pass policy, human review, signed receipts), approval workflow, tamper-evident audit trail,
agent token lifecycle, tool drift detection, MCP tool discovery and consent/OAuth authorization,
tool/skill supply-chain provenance (checksums + opt-in Sigstore signature verification), response
forensics, production hardening, OpenAPI docs, explicit per-agent tool grants, approval routing
profiles, a no-tool-forwarding policy evaluation engine, and a versioned evidence bundle export
are implemented and tested (unit, integration, and negative-security-path coverage) against both
PostgreSQL and MariaDB. `docs/threat-model.md` tracks known gaps not yet covered. See
[`ROADMAP.md`](ROADMAP.md) for what's next. As with any release, treat "tested" as test-suite
verified, not as an operational-deployment guarantee — see `docs/operations.md` before running in
production.

## License

GPLv3 — see [`LICENSE`](LICENSE).
