# Runbook: Audit Integrity Verification

For the `AgentShieldAuditIntegrityFailed` alert, a manual periodic check, or investigating a
suspected security incident where you need to confirm the audit trail itself wasn't tampered with.

## Background

Every audit event's hash covers its own content plus the previous event's hash
(`com.agentshield.audit.AuditHashChain`) — editing or deleting a historical row breaks the chain
from that point forward, in a way that's detectable but not preventable at the database layer
(this is a detection control, not an access control; database-level access control is a separate,
infrastructure-level responsibility). `AuditIntegrityService` runs this check two ways:

- **On demand**: `GET /api/audit/verify-integrity`, or the "Verify Integrity" button on the Audit
  page. Always available, always authoritative.
- **Scheduled**: every 30 minutes (`AuditIntegrityService.scheduledVerify`), backing the
  `agentshield_audit_integrity_valid` Prometheus gauge and the `AgentShieldAuditIntegrityFailed`
  alert (`monitoring/prometheus-alerts.yml`).

## When the alert fires

1. **Treat it as an active security incident until proven otherwise** — don't assume it's a bug
   first. A broken hash chain means either (a) direct database tampering, bypassing the
   application entirely, or (b) a genuine application bug in the hash-chain write path. Both are
   serious; (a) is worse.
2. Run `GET /api/audit/verify-integrity` yourself to get the authoritative, current result:
   ```json
   {"valid": false, "eventsChecked": 1042, "firstBrokenEventId": 1043, "reason": "stored event_hash does not match its recomputed content hash"}
   ```
3. Note `firstBrokenEventId` and `reason`. Two distinct failure reasons mean different things:
   - `"stored event_hash does not match its recomputed content hash"` — the row's own content
     (message, metadata, actor, etc.) was edited after it was written.
   - `"previous_event_hash does not match the prior row's event_hash"` — a row was deleted, or
     rows were reordered/renumbered, breaking the link between consecutive events.
4. Look for a `audit.integrity_check_failed` (CRITICAL) event written by the scheduled check
   itself, around the time the alert fired — its metadata records the same `firstBrokenEventId`
   and `reason`, timestamped, which helps narrow down *when* the break was introduced relative to
   other activity in the window before it.

## Investigate

- **Database access logs** (outside AgentShield — your DB's own audit/query log, if enabled): who
  or what connected and ran an `UPDATE`/`DELETE` against `audit_events` around the suspected
  window? AgentShield's own application code never updates or deletes audit rows after writing
  them (`AuditService.record()` only ever inserts) — any mutation came from a direct database
  connection, not through the app.
- **Was this a deployment/migration?** Check recent Flyway migrations — a schema migration that
  touched `audit_events` (there shouldn't be one; this table has never needed a migration since
  its creation) would be a legitimate, explainable cause. Absent that, treat it as unexplained.
- **Correlate with other signals** — was there a suspicious login, an unusual admin API call, or a
  broader compromise indicator around the same time? Check `app_users` for unexpected accounts.

## Containment (if tampering is confirmed, not a bug)

1. Rotate every credential that could plausibly have had direct database access (DB user
   password, any shared infrastructure credentials) — see
   [key-token-rotation.md](key-token-rotation.md).
2. Preserve the current (tampered) database state for forensics before doing anything else
   destructive — take a fresh `pg_dump` immediately, separate from your regular backup rotation,
   and keep it.
3. Restrict database network access to only the application while you investigate further.
4. This is the point to involve your organization's broader incident response process — a
   confirmed audit-log tampering event is evidence of a compromise elsewhere, not something
   AgentShield's own scope can fully contain by itself.

## If it turns out to be a bug, not tampering

File it as a P0 — a hash-chain write bug undermines the entire tamper-evidence guarantee this
feature exists for. Include the exact `firstBrokenEventId`/`reason`, and whatever write path was
active around that time (which service/endpoint was calling `AuditService.record()`).

## Recovery

There is no automated "repair" for a broken chain by design — silently re-linking it would defeat
the point of tamper-evidence. Once the cause is understood and contained, the chain will show a
broken link at that specific point permanently; document the finding (what broke, when, why) so a
future investigator doesn't re-discover the same historical break and re-open a closed
investigation. `docs/threat-model.md` and this runbook are good places to log the postmortem
reference.
