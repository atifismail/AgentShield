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

## 7. Sensitive-content exposure (secrets, PII, injected data)

**Risk:** a tool-call argument, tool result, or RAG chunk can carry credentials, PII, or other
sensitive content into or out of an agent's context — not just an injected instruction (§4), but
the underlying data itself.

**Control:** `com.agentshield.dlp` scans inbound tool-call arguments (and, already, tool responses)
with `SecretDetector`, `PiiDetector`, and `PromptInjectionDetector` against an operator-configured
`ClassificationProfile`, applying allow/redact/tokenize/block/approval-required per match — see
`docs/api.md`'s DLP section. A standalone `POST /api/dlp/rag/scan` endpoint lets an external RAG
ingestion pipeline classify a chunk before indexing it. **Scope, stated plainly:** this is
content-stage scanning against inbound gateway traffic and ad hoc scan requests — there is no
`rag_source`/ingestion-pipeline registry, no per-tenant policy scoping, and no OCR/image scanning;
see the non-goal below.

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
  never cached. Local/stdio credential brokering (env-var allowlisting) is now implemented too —
  see the next item.
- ~~**Tool/skill supply-chain provenance.**~~ Partially addressed: §1 (tool poisoning) already
  covered detecting drift after the fact via fingerprint hashing; every tool version now also
  gets an automatic Level-1 checksum record, and optional Level-2 Sigstore keyless signature
  verification (in-process, `dev.sigstore:sigstore-java`, never a `cosign` CLI dependency),
  opt-in per `ToolSourceType` via `agentshield.provenance.require-signature-for` — see
  `docs/api.md` "Supply-chain provenance" and `docs/operations.md`. AgentShield only ever
  verifies; it never signs or holds private key material. A failed or revoked signature forces
  the tool back to `DRIFTED` immediately. **Still open:** trusted-publisher metadata display,
  pinning of external instruction URLs by content hash (no such URL-fetching mechanism exists
  yet in this codebase to pin), and provenance for `LOCAL_SKILL`/`REMOTE_PACKAGE` source types
  (neither has an entity yet — stdio MCP transport is now implemented, but these two source types
  specifically still have no registration/fetch mechanism of their own).
- ~~**Weak local-tool isolation.**~~ Partially addressed for stdio MCP servers (the only local
  code execution path in this codebase): `agentshield.stdio.enabled` defaults to `false`;
  spawnable commands must be explicitly allowlisted (empty by default); each subprocess's
  environment is built from scratch (nothing from AgentShield's own process unless a name is
  explicitly listed, `HOME`/`USERPROFILE` included — see `docs/operations.md`); working-directory
  placement under a dedicated sandbox root; and call-timeout/output-size/process-count limits, all
  audited (`mcp.stdio_*` events) — see `design-stdio-sse-mcp-transport-and-sandboxing.md` and
  `docs/api.md`. **Still open, stated plainly:** AgentShield cannot enforce per-process network
  egress or memory/CPU limits from inside the JVM (no OS namespaces/cgroups/seccomp from pure
  Java), and there is no filesystem confinement beyond working-directory placement plus the
  existing non-root OS user — both are deployment-layer responsibilities (Kubernetes
  `NetworkPolicy`, `resources.limits`, `securityContext`; see `docs/operations.md`). A `prod`-profile
  deployment refuses to start with stdio enabled unless
  `agentshield.stdio.external-sandbox-acknowledged=true` confirms this has been done.
- ~~**Governance evidence export.**~~ Addressed: `GET /api/governance/report` exports registered
  agents, approved tools, denied actions, approval records, tool drift events, incidents, and
  policy versions for a date range, mapped to NIST AI RMF's govern/map/measure/manage functions,
  as JSON or downloadable Markdown — see `docs/api.md`.

## Non-goals

AgentShield is not a SIEM replacement, not a general chatbot, and not an antivirus or broad cloud
security suite. It focuses specifically on the boundary between an agent and the tools it calls.
It now includes targeted DLP scanning at that boundary (§7) — deterministic pattern detectors
plus operator-configured classification profiles — but this is not a full enterprise DLP platform:
no OCR/image scanning, no document-management integration, and no RAG source/ingestion registry
(nothing in this codebase performs real RAG ingestion yet — see `docs/api.md`).
