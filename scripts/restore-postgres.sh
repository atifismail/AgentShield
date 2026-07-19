#!/usr/bin/env bash
# Restores an AgentShield PostgreSQL dump (created by backup-postgres.sh) into a running
# docker-compose "postgres" service, replacing its current contents.
#
# IMPORTANT: stop the "app" service first (docker compose stop app) — restoring into a database
# with an active connection pool can fail on lock conflicts, and the app would otherwise serve
# stale/inconsistent data mid-restore.
#
# Usage: ./scripts/restore-postgres.sh <dump_file>
set -euo pipefail

DUMP_FILE="${1:?Usage: $0 <dump_file>}"
if [ ! -f "$DUMP_FILE" ]; then
  echo "Dump file not found: $DUMP_FILE" >&2
  exit 1
fi

echo "WARNING: this replaces all data in the 'agentshield' database with the contents of $DUMP_FILE."
read -r -p "Type 'restore' to continue: " CONFIRM
if [ "$CONFIRM" != "restore" ]; then
  echo "Aborted."
  exit 1
fi

echo "Restoring $DUMP_FILE into agentshield database ..."
docker compose exec -T postgres pg_restore -U agentshield -d agentshield --clean --if-exists --no-owner < "$DUMP_FILE"

echo "Restore complete. Restart the app service if it was stopped: docker compose start app"
