#!/usr/bin/env bash
# Copyright (c) 2026 Vassel Goleyu. MIT License.
# Restores a backup made by backup.sh: deploy/restore.sh backups/db-<stamp>.dump [backups/evidence-<stamp>.tgz]
# This REPLACES the current database content. The API and worker are stopped while it runs.
set -euo pipefail
cd "$(dirname "$0")"
db_dump=${1:?usage: restore.sh DB_DUMP [EVIDENCE_TGZ]}
evidence=${2:-}
[ -f "$db_dump" ] || { echo "no such file: $db_dump" >&2; exit 1; }
compose=(docker compose -f docker-compose.prod.yml)
"${compose[@]}" stop app worker
"${compose[@]}" exec -T postgres pg_restore -U vexledger -d vexledger --clean --if-exists --no-owner --exit-on-error < "$db_dump"
"${compose[@]}" up -d app worker
if [ -n "$evidence" ]; then
    [ -f "$evidence" ] || { echo "no such file: $evidence" >&2; exit 1; }
    "${compose[@]}" exec -T app tar xzf - -C /data/evidence < "$evidence"
fi
echo "restore finished"
