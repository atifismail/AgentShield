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

**Explicit Entitlements and Reproducible Evidence** (see
`docs/release-notes/explicit-entitlements-baseline.md` for the baseline this release started
from):

- `GET /api/mcp-servers/{id}/tools` (MCP-scoped tool listing) and
  `POST /api/mcp-servers/{id}/proxy` (thin server-addressing adapter over the generic gateway
  invoke path), additive alongside the existing generic endpoints.
- Independent, canonicalized `descriptionHash`/`inputSchemaHash`/`outputSchemaHash` fingerprints
  on `Tool`, plus `riskTier` and `defaultAction` fields — separate from, and never replacing, the
  legacy combined `approvedHash`/`currentHash` fingerprint.
- An explicit, expiring per-agent tool **grant** model (`POST /api/agents/{id}/grants`), governed
  by `agentshield.grants.transition-mode` (`GROUPS_ONLY` by default — every existing installation
  is unaffected until an operator opts in to `GRANTS_OR_GROUPS`/`GRANTS_REQUIRED`).
- **Approval routing profiles** (`POST /api/approval-profiles`) that route an already-
  `APPROVAL_REQUIRED` request to the correct human role by priority/predicate match, without ever
  changing the underlying ALLOW/DENY/APPROVAL_REQUIRED decision.
- A **policy evaluation engine** (`POST /api/evaluations/suites`, `POST /api/evaluations/runs`)
  that runs a versioned, synthetic fixture suite through the real pre-call policy/grant/MCP-
  consent components with zero tool forwarding — useful for testing a policy or tool change
  before relying on it in production.
- A versioned **evidence bundle** export (`GET /api/governance/evidence?format=json|sarif`) with
  published JSON Schemas under `docs/schemas/` — additive alongside the existing governance
  report/markdown export, which is unchanged.

## Planned — SOC/SIEM

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
