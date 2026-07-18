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

## Non-goals

AgentShield is not a SIEM replacement, not a full DLP platform, not a general chatbot, and not an antivirus or broad cloud security suite. It focuses specifically on the boundary between an agent and the tools it calls.
