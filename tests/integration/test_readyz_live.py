# Copyright (c) 2026 Vassel Goleyu. MIT License.
import httpx
import pytest

from vexledger.api.app import create_app
from vexledger.config import Settings

pytestmark = pytest.mark.integration


async def test_readyz_ok_against_real_services(settings: Settings, require_infra: None) -> None:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            resp = await c.get("/readyz")
    assert resp.status_code == 200
    assert resp.json()["checks"] == {"database": "ok", "redis": "ok"}
