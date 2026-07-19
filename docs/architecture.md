# Architecture

## Overview

AgentShield is a runtime security gateway that sits between AI agents and the tools they call. Every tool invocation an agent wants to make is routed through AgentShield instead of going directly to the target system.

```text
User / Application / AI Agent
        |
        v
AgentShield Gateway
        |
        +-- Policy Engine
        +-- Tool Registry
        +-- Risk Engine
        +-- Approval Workflow
        +-- Audit Service
        |
        v
MCP Servers / APIs / Databases / Git / Filesystem / Cloud Tools
```

## Components

**Gateway** (`com.agentshield.gateway`) — the single entry point, `POST /api/gateway/invoke`. Authenticates the calling agent, normalizes the request, and orchestrates policy evaluation, risk scoring, forwarding, and response scanning. Fails closed: any error during evaluation results in a deny, never a silent allow.

**Agent registry** (`com.agentshield.agent`) — tracks which agents exist, their status (enabled/disabled), owning team, environment, and which tool groups they're allowed to call. Agents authenticate with a bearer token; only its hash is stored.

**Tool registry** (`com.agentshield.tool`) — tracks registered tools (Git, database, filesystem, SaaS, shell, MCP), their declared schema/description, and an approval state. Every time a tool's schema or description is fingerprinted, the hash is compared against the last-approved hash; a mismatch marks the tool as drifted until a human re-approves it. Every tool version also gets a supply-chain provenance record: a Level-1 checksum automatically, and — opt-in per `ToolSourceType` via trust policy — Level-2 Sigstore signature verification (in-process, via `dev.sigstore:sigstore-java`'s `KeylessVerifier`, never the `cosign` CLI). AgentShield only ever verifies signatures the tool/skill publisher produced elsewhere; it never signs anything or holds private key material. A failed or revoked signature forces the tool back to `DRIFTED`, reusing the same enforcement drift already has — no separate blocking mechanism.

**MCP integration** (`com.agentshield.mcp`) — registers MCP servers and discovers their tools via JSON-RPC (`tools/list`). Each discovered tool becomes a regular row in the tool registry above (linked back to its MCP server), so it goes through the exact same approval/drift/gateway pipeline as a plain HTTP tool. All three transports (`HTTP`, `SSE`, `STDIO`) are implemented per `design-stdio-sse-mcp-transport-and-sandboxing.md`.
`SSE` (`com.agentshield.mcp.McpSseConnectionManager`) is a persistent Server-Sent-Events connection —
HTTP-based like the plain `HTTP` transport, so it has no subprocess/environment/filesystem concerns
and no feature flag; it's governed by the same `OutboundEndpointValidator` SSRF policy and OAuth2
flow as `HTTP`, bounded by call timeout/response-size/idle-timeout/reconnect limits.
STDIO spawns a locally-sandboxed subprocess per `design-stdio-sse-mcp-transport-and-sandboxing.md`
(`com.agentshield.mcp.StdioMcpProcessManager`) — gated behind `agentshield.stdio.enabled` (off by
default), command-allowlisted, environment built from scratch (nothing from AgentShield's own
process unless explicitly allowlisted by name), and bounded by call timeout/output-size/process-count
limits. AgentShield cannot enforce per-process network egress or memory/CPU limits from inside the
JVM — see `docs/operations.md` for what a production deployment must enforce externally. AgentShield acts as an MCP *proxy server* in MCP's own terminology — a single backend holding credentials to third-party MCP servers on behalf of many agents — so it implements the confused-deputy mitigation the MCP spec requires for that topology: an agent needs an explicit, ADMIN/SECURITY_ANALYST-granted `McpConsent` for a given MCP server (optionally scoped to a tool/action category) before a call is allowed, checked by the policy engine before any OAuth token is even requested. Servers that require OAuth 2.1 (`authMode: OAUTH2`) are called using the `client_credentials` grant, with tokens validated on receipt (audience/issuer/expiry/scope) and cached encrypted — see `docs/policy-guide.md` rule 11 and `docs/operations.md`.

**Policy engine** (`com.agentshield.policy`) — evaluates a normalized request against a set of rules and returns ALLOW, DENY, or APPROVAL_REQUIRED with a reason. Rules are versioned; a dry-run mode lets you test a policy change against a hypothetical request before enabling it.

**Risk engine** (`com.agentshield.risk`) — assigns a deterministic risk score (and LOW/MEDIUM/HIGH/CRITICAL level) to a request based on the action category, target environment, tool trust state, and any detector hits. Includes the prompt-injection and secret-pattern detectors used to inspect tool responses before they flow back to the agent.

**Approval workflow** (`com.agentshield.approval`) — queues actions that policy marks as requiring human sign-off, and exposes approve/reject endpoints with expiration handling.

**Audit** (`com.agentshield.audit`) — every gateway request produces one or more audit events (received, policy decision, response scan, outcome), correlated by a `correlationId` so a security analyst can reconstruct the full timeline of a single call.

**Incidents** (`com.agentshield.incident`) — a critical detector finding (secret leak, prompt injection, blocked destructive action) generates an incident record linking back to the triggering audit event and gateway request.

## Data flow for a single tool call

1. Agent sends a normalized request to `/api/gateway/invoke` with its bearer token.
2. Gateway authenticates the agent and persists a `GatewayRequest`.
3. Policy engine evaluates the 10 default rules against the request (agent status, tool approval/drift state, environment, action category, allowed tool groups, payload size).
4. Risk engine scores the request.
5. If ALLOW: the gateway forwards the call to the tool's registered endpoint, scans the response for secrets/prompt-injection, records a `GatewayToolResponse` forensic row (status code, response hash, sanitized summary, matched detector indicators — raw body only if retention is explicitly enabled, see `docs/operations.md`), and returns the result to the agent.
6. If DENY: the call never reaches the tool; the agent gets a reason.
7. If APPROVAL_REQUIRED: an `ApprovalRequest` is created and queued for a human; the agent gets a reference id.
8. Every step writes an audit event.

## Why this design

- **Fail-closed by default** — a gateway that silently allows on error is worse than no gateway.
- **Deterministic detection for the MVP** — prompt-injection and secret scanning use rule/pattern matching, not a paid LLM API, so the product works fully offline and without external dependencies.
- **Everything auditable** — every decision (allow, deny, approval) is traceable back to the specific policy rule and risk factors that produced it.
