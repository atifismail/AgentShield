# Runbook: Incident Response

For a CRITICAL-severity `Incident` record, a `AgentShieldResponseBlockedSpike` /
`AgentShieldIncidentCreated` alert, or a cluster of WARNING-severity behavior-baseline anomalies
(`com.agentshield.behavior`).

## 1. Triage

Open the **Incidents** page (`/incidents`) and find the new record(s). Each incident links back
to its `relatedAuditEventId`/`relatedGatewayRequestId` — follow that to the **Audit** page's
correlation timeline (`/audit/correlation/{correlationId}`) to see the full sequence of what the
agent requested, what the policy engine decided, and (if it got that far) what the tool actually
returned.

Incident severity tells you what kind of finding this is:

- **CRITICAL** — a confirmed policy violation: a blocked secret-like response
  (`SecretDetector` + `deny-secret-external-transfer`), a blocked prompt-injection response
  (`PromptInjectionDetector` + `deny-prompt-injection-response`), or a stdio/SSE MCP transport
  failure closed for a security reason (command not allowlisted, missing env var, output-size
  limit). The gateway already blocked the harmful action — the incident exists so a human confirms
  what happened and why, not to prevent an in-progress attack.
- **WARNING** — a behavior-baseline anomaly (`com.agentshield.behavior.BehaviorBaselineService`):
  first-time tool/action/environment combination for an established agent, repeated denials in a
  short window, unusual approval-required frequency, or a request-volume spike. These are
  observational — the underlying action may have already been legitimately ALLOWed or DENYed by
  policy; the WARNING is "this doesn't match the agent's normal pattern," not "this was blocked."

## 2. Investigate

- **Which agent, which tool, which credential?** The correlation timeline shows the agent name and
  (for gateway-request-linked incidents) the credential prefix used — check the Agent detail page
  (`/agents/{id}`) for that agent's configured `allowedToolGroups`, status, and recent call
  history.
- **Was this a real attack, a false positive, or a legitimate-but-unusual action?** Read the
  detector match indicators (`detectorMatchesJson` on the tool response, indicator names only —
  raw matched text is never stored, by design) and the policy decision reason.
- **Is this part of a pattern?** Search Audit for the same agent/tool/correlation prefix over a
  wider time window. Check the Governance page (`/governance`) for a broader date-range summary if
  this might be part of something larger.

## 3. Respond

Depending on what you find:

- **Confirmed malicious/compromised agent** — disable the agent (`POST /api/agents/{id}/disable`
  or the Agent detail page) and revoke its credential(s) immediately (see
  [key-token-rotation.md](key-token-rotation.md)). This is the fastest way to stop further calls
  without touching policy config.
- **Confirmed malicious/drifted tool** — the tool should already be `DRIFTED` if this was a
  fingerprint mismatch; if not, reject it manually via the Tools page. For a provenance-verified
  tool, consider `POST /api/tools/{id}/provenance/revoke`.
- **False positive (detector over-triggered)** — mark the incident `FALSE_POSITIVE`
  (`PATCH /api/incidents/{id}/status`). If this is a recurring false-positive pattern, that's a
  signal the detector or a policy override needs tuning — file it as a follow-up, don't just
  dismiss each occurrence individually.
- **Legitimate-but-unusual (behavior-baseline WARNING only)** — mark `ACKNOWLEDGED` once reviewed;
  no further action needed if the underlying action was already correctly ALLOWed/DENIED by
  policy.

## 4. Close out

Update the incident status (`OPEN` → `ACKNOWLEDGED` → `RESOLVED`, or `FALSE_POSITIVE`) via the
Incidents page. For anything that involved disabling an agent or revoking a credential, note the
correlation ID and reason somewhere durable outside AgentShield too (ticket system, postmortem
doc) — AgentShield's audit trail proves *what* happened technically, but doesn't replace your
organization's own incident tracking.

## Escalation

If the investigation suggests AgentShield itself was bypassed or misbehaved (not just an agent
doing something it was allowed to but shouldn't have been), that's a product bug, not a normal
incident — stop, don't just close it out, and escalate to whoever owns this deployment/codebase.
