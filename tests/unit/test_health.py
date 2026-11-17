# Copyright (c) 2026 Vassel Goleyu. MIT License.
import httpx
from hypothesis import given
from hypothesis import strategies as st

from vexledger.api.app import create_app
from vexledger.api.middleware import resolve_request_id
from vexledger.config import Settings


async def test_healthz_ok_and_request_id_header(settings: Settings) -> None:
    app = create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/healthz", headers={"x-request-id": "abc-12345678"})
    assert resp.json() == {"status": "ok"}
    assert resp.headers["x-request-id"] == "abc-12345678"


async def test_readyz_503_when_dependencies_down() -> None:
    # Port 1 refuses connections, so both checks must fail fast and report 503.
    s = Settings(
        env="test",
        database_url="postgresql+asyncpg://u:p@127.0.0.1:1/x",
        redis_url="redis://127.0.0.1:1/0",
    )
    app = create_app(s)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            resp = await c.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["status"] == "unavailable"


@given(st.text(max_size=200))
def test_request_id_is_always_safe(raw: str) -> None:
    rid = resolve_request_id(raw)
    assert 8 <= len(rid) <= 64
    assert all(ch.isalnum() or ch in "._-" for ch in rid)
