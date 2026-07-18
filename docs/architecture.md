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

**Tool registry** (`com.agentshield.tool`) — tracks registered tools (Git, database, filesystem, SaaS, shell, MCP), their declared schema/description, and an approval state. Every time a tool's schema or description is fingerprinted, the hash is compared against the last-approved hash; a mismatch marks the tool as drifted until a human re-approves it.

**MCP integration** (`com.agentshield.mcp`) — registers MCP servers and discovers their tools via JSON-RPC (`tools/list`). Each discovered tool becomes a regular row in the tool registry above (linked back to its MCP server), so it goes through the exact same approval/drift/gateway pipeline as a plain HTTP tool. Only the HTTP transport is implemented; SSE and STDIO are modeled in the schema for a future release.

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
5. If ALLOW: the gateway forwards the call to the tool's registered endpoint, scans the response for secrets/prompt-injection, and returns the result to the agent.
6. If DENY: the call never reaches the tool; the agent gets a reason.
7. If APPROVAL_REQUIRED: an `ApprovalRequest` is created and queued for a human; the agent gets a reference id.
8. Every step writes an audit event.

## Why this design

- **Fail-closed by default** — a gateway that silently allows on error is worse than no gateway.
- **Deterministic detection for the MVP** — prompt-injection and secret scanning use rule/pattern matching, not a paid LLM API, so the product works fully offline and without external dependencies.
- **Everything auditable** — every decision (allow, deny, approval) is traceable back to the specific policy rule and risk factors that produced it.
