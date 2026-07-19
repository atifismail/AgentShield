#!/usr/bin/env bash
# Dumps the AgentShield PostgreSQL database from a running docker-compose stack to a local,
# timestamped custom-format dump file. Requires the "postgres" service to be up
# (docker compose up -d postgres, or the full stack).
#
# Usage: ./scripts/backup-postgres.sh [output_dir]
set -euo pipefail

OUTPUT_DIR="${1:-./backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_FILE="$OUTPUT_DIR/agentshield-$TIMESTAMP.dump"

mkdir -p "$OUTPUT_DIR"

echo "Backing up agentshield database to $OUTPUT_FILE ..."
docker compose exec -T postgres pg_dump -U agentshield -d agentshield --format=custom > "$OUTPUT_FILE"

echo "Backup complete: $OUTPUT_FILE ($(du -h "$OUTPUT_FILE" | cut -f1))"
echo "Restore with: ./scripts/restore-postgres.sh $OUTPUT_FILE"
