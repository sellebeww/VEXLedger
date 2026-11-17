# Copyright (c) 2026 Vassel Goleyu. MIT License.
COMPOSE = docker compose -f deploy/docker-compose.dev.yml

.PHONY: verify dev-up dev-down migrate e2e demo-stack demo
verify:
	uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src && uv run pytest -q --cov=src --cov-fail-under=85 && (cd web && npm run lint && npm run typecheck && npm test && npm run build)

dev-up:
	$(COMPOSE) up -d --wait

dev-down:
	$(COMPOSE) down

migrate:
	uv run alembic upgrade head

e2e:
	cd web && npm run e2e

# Full demo stack (own database, SYNTHETIC OSV records); run the UI with `cd web && npm run dev`.
demo-stack:
	uv run python tools/e2e_stack.py

# Owner demo from scratch in one command: fresh DB, API + worker in demo mode (SYNTHETIC OSV),
# then the scripted walkthrough (tools/seed_demo.py). Then `cd web && npm run dev`, admin login.
demo: dev-up
	uv run python tools/e2e_stack.py --demo
