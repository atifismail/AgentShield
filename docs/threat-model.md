# Threat Model

AgentShield exists to address six specific risks that show up once AI agents are given tool access. This document describes each risk and the corresponding control.

## 1. Tool poisoning

**Risk:** MCP tool descriptions, schemas, prompts, or responses can contain malicious or misleading instructions. A tool's metadata can also change silently after it was first reviewed and approved.

**Control:** the tool registry fingerprints a tool's schema and description (SHA-256 hash). Any change flips the tool into a DRIFTED state, which the policy engine denies by default until a human re-approves the new version. Every detected drift is recorded as a `ToolVersion` for review.

## 2. Excessive agency

**Risk:** agents are frequently granted more tool authority than the task requires.

**Control:** agents are scoped to explicit allowed tool groups; a call to a tool outside an agent's allowed groups is denied. Action categories (READ/WRITE/DESTRUCTIVE/CREDENTIAL_ACCESS/EXTERNAL_TRANSFER) drive risk scoring so higher-authority actions require more scrutiny or human approval by default.

## 3. Identity abuse

**Risk:** agents reusing human credentials or long-lived administrator secrets.

**Control:** agents authenticate to the gateway with their own per-agent bearer token (hash stored, never the plaintext). The gateway never forwards a caller's own credentials to the downstream tool — the tool call is made by the gateway using the tool's own registered endpoint.

## 4. Prompt and response injection

**Risk:** a tool's response can contain hidden instructions attempting to override the agent's system prompt or exfiltrate data once it re-enters the model's context.

**Control:** every tool response is scanned by the prompt-injection detector before being returned to the agent. A match is treated as a critical risk factor and blocks the response.

## 5. Poor auditability

**Risk:** without a record of what an agent did and why it was allowed, security teams cannot investigate an incident.

**Control:** every gateway request produces a full audit trail — the request, the policy decision and its reason, the risk score, any approval decision, and a hash of the tool's response — searchable and correlated by a single id per request.

## 6. Supply-chain risk

**Risk:** MCP servers, local tools, skills, and plugins are all trust dependencies introduced into the agent's execution environment.

**Control:** the tool registry acts as an explicit allowlist. An unregistered or unapproved tool cannot be called through the gateway at all.

## Known gaps

Identified by a source-code review (2026-07-19) against current OWASP Agentic AI Top 10, OWASP
Agentic Skills Top 10, MCP security best practices, MCP authorization guidance, and NIST AI RMF
guidance. Not yet implemented — tracked here rather than silently assumed covered.

- ~~**MCP confused-deputy risk.**~~ Addressed: every MCP-backed tool call now requires an
  explicit, ADMIN/SECURITY_ANALYST-granted `McpConsent` for the calling agent (scoped to the MCP
  server, and optionally a specific tool/action category), checked before any OAuth token is
  requested — see `docs/policy-guide.md` rule 11, `docs/api.md` (MCP consents), and
  `docs/architecture.md`. OAuth 2.1 token audience/issuer/expiry/scope validation is implemented
  for servers with `authMode: OAUTH2`, and wrong-audience/wrong-issuer tokens are rejected and
  never cached. Local/stdio credential brokering is designed but not yet implemented, pending
  stdio transport support itself (still a gap, tracked below under weak local-tool isolation).
- **Tool/skill supply-chain provenance.** §1 (tool poisoning) covers detecting drift after the
  fact via fingerprint hashing, but there's no signature or checksum verification at
  registration time, no trusted-publisher metadata, and no pinning of external instruction URLs
  by content hash — so a tool can still be *approved* while already compromised, not just drift
  after approval.
- **Weak local-tool isolation.** Tool execution (HTTP or MCP) has no per-tool filesystem,
  environment-variable, or outbound-network allowlist, and no resource/timeout limits beyond the
  gateway's own outbound-endpoint validation (§6, `docs/api.md`). A future local/stdio MCP
  execution mode in particular needs this before it can be considered safe by default.
- **Governance evidence export.** §5 (poor auditability) covers the raw audit trail, but there's
  no mapping of AgentShield's controls to a governance framework (e.g. NIST AI RMF's
  govern/map/measure/manage functions) or an exportable evidence report for compliance review.

## Non-goals

AgentShield is not a SIEM replacement, not a full DLP platform, not a general chatbot, and not an antivirus or broad cloud security suite. It focuses specifically on the boundary between an agent and the tools it calls.
