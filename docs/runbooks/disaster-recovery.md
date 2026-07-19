# Runbook: Disaster Recovery

Database loss, corruption, or a "restore to a known-good point" need (e.g. after confirmed audit
tampering — see [audit-integrity-verification.md](audit-integrity-verification.md)'s containment
step).

## What's durable, what isn't

AgentShield's **only** durable state is the PostgreSQL (or MariaDB) database — the application
itself is stateless (stdio/SSE MCP connection state is explicitly in-memory-only and expected to
be lost/re-established on restart, per `design-stdio-sse-mcp-transport-and-sandboxing.md`). Losing
the database means losing everything: agents, tools, policies, approvals, and the entire audit
trail. There is nothing else to recover.

## Backup

**Docker Compose / local:**
```bash
./scripts/backup-postgres.sh [output_dir]
```
Wraps `pg_dump --format=custom` against the running `postgres` service. Custom format supports
selective/parallel restore and is generally smaller than plain SQL dumps.

**Managed PostgreSQL (RDS, Cloud SQL, etc.):** use your provider's native automated backup/snapshot
feature as the primary mechanism — it's continuous and handles point-in-time recovery, which a
periodic `pg_dump` cron job cannot. Treat `pg_dump` as a supplementary, portable export (e.g. for
migrating between providers), not the primary backup mechanism in that context.

**Schedule:** back up at least daily; more frequently if your approval/audit volume is high enough
that losing a day's worth of audit trail would itself be a compliance problem. Audit and
policy-decision rows are append-only from the application's perspective, so a backup taken at any
point is internally consistent — there's no "mid-transaction" state to worry about beyond what
`pg_dump`'s own transactional snapshot already handles.

## Restore

**Docker Compose / local:**
```bash
docker compose stop app          # stop the app first — see the script's own warning
./scripts/restore-postgres.sh <dump_file>
docker compose start app
```

**Managed PostgreSQL:** use your provider's point-in-time-recovery or snapshot-restore feature,
then point `AGENTSHIELD_DB_URL` at the restored instance (or restore in place, depending on your
provider's model). If restoring from a `pg_dump` export instead:
```bash
pg_restore -h <host> -U agentshield -d agentshield --clean --if-exists --no-owner < backup.dump
```

## After restoring

1. Start the app and confirm `GET /actuator/health` is `UP` — Flyway will detect the restored
   schema version and skip already-applied migrations automatically.
2. Run `GET /api/audit/verify-integrity` — a restore from a *clean* backup should verify fine; if
   it doesn't, the backup itself may have been taken after a tampering event (see
   [audit-integrity-verification.md](audit-integrity-verification.md)), or the restore was
   incomplete.
3. Confirm agent credentials still work — rotate any that were issued *after* the backup point but
   before the incident that necessitated the restore (they're gone from the restored data, but the
   agents holding them will still try to use them and get `401`s until reissued).
4. Communicate the restore point (timestamp of the backup used) to anyone depending on data
   created after that point — approvals, incidents, and audit events between the backup and the
   restore are permanently lost, not just delayed.

## Testing this runbook

`scripts/backup-postgres.sh`/`restore-postgres.sh` should be exercised periodically against a
non-production instance (or the local docker-compose stack) — a backup procedure nobody has ever
restored from is not a tested backup procedure. This wasn't done as part of writing this runbook
(no live environment was available at the time); do a full backup → wipe → restore → verify cycle
before relying on this in a real incident, and note the date/result here once you have.
