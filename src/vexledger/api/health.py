# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Liveness and readiness probes."""

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


async def _check(name: str, request: Request) -> str | None:
    """Return None when healthy, otherwise a short error description."""
    timeout = request.app.state.settings.readiness_timeout_s
    try:
        async with asyncio.timeout(timeout):
            if name == "database":
                async with request.app.state.engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
            else:
                await request.app.state.redis.ping()
    except Exception as exc:  # probe must report any failure, not raise
        return type(exc).__name__
    return None


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    errors = {n: await _check(n, request) for n in ("database", "redis")}
    ok = all(e is None for e in errors.values())
    body = {
        "status": "ok" if ok else "unavailable",
        "checks": {n: e or "ok" for n, e in errors.items()},
    }
    return JSONResponse(body, status_code=200 if ok else 503)
