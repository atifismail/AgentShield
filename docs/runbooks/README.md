# Runbooks

Operational procedures for running AgentShield in production. These are step-by-step "do this
when X happens" documents — for reference/conceptual material (what a feature does and why), see
the main `docs/` directory instead.

| Runbook | When to use it |
|---|---|
| [deployment.md](deployment.md) | Deploying a new release or config change |
| [incident-response.md](incident-response.md) | A CRITICAL incident or alert fires |
| [audit-integrity-verification.md](audit-integrity-verification.md) | The audit chain integrity alert fires, or a scheduled/manual verification |
| [key-token-rotation.md](key-token-rotation.md) | Rotating the admin password, agent credentials, or encryption keys |
| [disaster-recovery.md](disaster-recovery.md) | Database loss/corruption, restoring from backup |

## Before you're on call

Read `docs/operations.md` (config, metrics, fail-closed behavior, audit trail) and
`docs/threat-model.md` (what AgentShield defends against, and its known gaps) once, fully, before
your first on-call rotation — these runbooks assume that context and don't re-explain it.

## Triage priority

When multiple things need attention, in order:

1. **Audit integrity failure** (`AgentShieldAuditIntegrityFailed` alert, `agentshield_audit_integrity_valid == 0`) —
   treat as an active security incident, not a bug report. See
   [audit-integrity-verification.md](audit-integrity-verification.md) immediately.
2. **Response-blocked / incident-created spikes** — a blocked secret or prompt-injection response,
   or a cluster of behavior-baseline anomalies. See [incident-response.md](incident-response.md).
3. **App down / failing health checks** — see [deployment.md](deployment.md)'s rollback section.
4. **Deny spikes, elevated latency** — usually a misconfiguration or a downstream tool problem,
   not an active attack; investigate via the Audit page before assuming the worst.
