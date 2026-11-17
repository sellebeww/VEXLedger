#!/usr/bin/env bash
# Copyright (c) 2026 Vassel Goleyu. MIT License.
# Backs up the database (pg_dump, custom format) and the evidence files into deploy/backups/.
# Run from anywhere: deploy/backup.sh. Keep the files off this server too (see docs/DEPLOY.md).
set -euo pipefail
cd "$(dirname "$0")"
compose=(docker compose -f docker-compose.prod.yml)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p backups
umask 077
"${compose[@]}" exec -T postgres pg_dump -U vexledger -Fc vexledger > "backups/db-$stamp.dump"
"${compose[@]}" exec -T app tar czf - -C /data/evidence . > "backups/evidence-$stamp.tgz"
echo "backup written: backups/db-$stamp.dump backups/evidence-$stamp.tgz"
