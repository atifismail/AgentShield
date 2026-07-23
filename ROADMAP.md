# Roadmap

This is a living, best-effort roadmap, not a delivery commitment or a set of dates. It reflects
what's already solid, what's actively planned, and what's under consideration.

## Shipped

The core gateway is past MVP and covered by unit, integration, and negative-security-path tests:
gateway/policy/risk engine, tool registry with drift detection and supply-chain provenance, MCP
server registration/discovery/consent across HTTP, SSE, and sandboxed stdio transports, DLP
scanning of inbound tool arguments **and** tool responses (secrets, PII, prompt injection, custom
patterns), the approval workflow (single-use, race-tested), a tamper-evident hash-chained audit
trail, SIEM export, an in-process detection-validation/attack-simulation module, and an
AI-coding-assistant code-trust workflow. See [`README.md`](README.md#project-status) and
[`docs/`](docs) for details.

## Planned — API surface reconciliation

The current API paths are stable and tested, but a few don't match earlier planning-doc naming.
These are naming/completeness gaps, not correctness bugs:

- A dedicated `POST /api/mcp-servers/{id}/proxy` route distinct from the generic
  `POST /api/gateway/invoke` path, for callers that want to address a specific MCP server
  directly.
- A `GET /api/mcp-servers/{id}/tools` (or equivalent MCP-scoped) listing endpoint, alongside the
  existing generic `GET /api/tools`.
- Separate description-hash / input-schema-hash fields on `Tool`, rather than one combined
  fingerprint hash.
- `riskTier` and `defaultAction` fields on `Tool`/`McpServer`, surfaced explicitly rather than
  derived from policy rules at evaluation time.

## Planned — policy and approval model

- An explicit per-agent tool **grant** model (`POST /api/agents/{id}/grants`) with expiry, as a
  data-driven alternative to the current `allowedToolGroups` string field.
- An **approval profile** model for routing rules (who can approve what, by risk tier/tool group),
  rather than a single generic approval queue.
- Extending the policy engine's condition set (currently agent/tool/action-category/environment)
  to also cover user, MCP server, resource path, and token scope as first-class conditions.

## Planned — SOC/SIEM

- Formal per-event JSON Schemas for tool-call, policy-decision, and approval events, published
  alongside the existing flat SIEM export.
- Exportable Sigma-style detection rule files, in addition to the current `DetectionRule` DB
  catalog.

## Under consideration

- **RAG source model** — a `POST /api/rag/sources/{id}/scan` per-source endpoint, instead of the
  current stateless `POST /api/dlp/rag/scan`.
- **Cross-product identity/posture integration** — if a companion certificate/machine-identity
  project (TrustAtlas) reaches a stable posture API, AgentShield could add a policy predicate
  based on certificate validity/expiry for agent/workload identities. Nothing in this repository
  depends on that today.
- **Enterprise packaging** — HA/clustering, multi-tenant admin, SSO/RBAC, long-term audit
  retention, and certified builds are explicitly out of scope for the open-source edition; see
  [`SUPPORT.md`](SUPPORT.md) for how these map to commercial support.

## How to influence this

Open an issue describing the use case. Concrete, narrow proposals (a policy condition, a
detector, an export format) are easier to land than broad new subsystems — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow.
