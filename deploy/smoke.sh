#!/usr/bin/env bash
# Copyright (c) 2026 Vassel Goleyu. MIT License.
# Smoke test of the production stack on THIS machine: builds the images, starts the stack behind
# Caddy with local TLS and SYNTHETIC OSV data, then checks /readyz, creates an admin with the CLI,
# uploads the demo SBOM, lists findings and runs the whole demo (tools/seed_demo.py).
# Needs Docker, uv and openssl. Uses throwaway secrets and removes everything it started (volumes too).
set -euo pipefail
cd "$(dirname "$0")"
compose_file="$PWD/docker-compose.prod.yml"  # absolute: the script later cd's to the repo root
port=${SMOKE_HTTPS_PORT:-8443}
envfile=$(mktemp)
trap 'docker compose -f "$compose_file" --env-file "$envfile" down -v --remove-orphans >/dev/null 2>&1; rm -f "$envfile"' EXIT
cat > "$envfile" <<ENV
SITE_ADDRESS=localhost
HTTP_PORT=${SMOKE_HTTP_PORT:-8080}
HTTPS_PORT=$port
POSTGRES_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)
VEXLEDGER_VEX_BASE_URL=https://localhost:$port
DEMO_OSV_FIXTURES=1
ENV
password="smoke-$(openssl rand -hex 12)"
compose=(docker compose -f "$compose_file" --env-file "$envfile")
build_flag=--build
[ "${SMOKE_NO_BUILD:-0}" = 1 ] && build_flag=  # reuse images already built locally
"${compose[@]}" up -d $build_flag --wait --wait-timeout 300
echo "== UI shell (a blank page must fail the smoke test)"
ui=$(curl -ksSL --fail "https://localhost:$port/login/")
case "$ui" in *'id="__nuxt"'*) echo "UI shell ok (${#ui} bytes)" ;; *) echo "UI shell is empty or wrong"; exit 1 ;; esac
echo "== readyz"
curl -ksS --fail "https://localhost:$port/readyz"; echo
echo "== create-admin (CLI inside the app container)"
"${compose[@]}" exec -T -e VEXLEDGER_ADMIN_PASSWORD="$password" app vexledger create-admin admin
echo "== demo walkthrough through Caddy (upload SBOM, findings, triage, export, validate)"
cd ..
VEXLEDGER_ADMIN_PASSWORD="$password" uv run python tools/seed_demo.py --url "https://localhost:$port" --insecure --out "$(mktemp -d)"
echo "SMOKE OK"
