# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""API test harness: the real app on the real test database and a private Redis database.

Every JSON response seen during a test is recorded and, at teardown, validated against the
OpenAPI schema of the route that served it (a simple contract test for the whole suite). A status
code that the route does not document fails the test too.
"""

import hashlib
import json
import re
import secrets
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vexledger.api.app import create_app
from vexledger.auth.provider import make_hasher
from vexledger.config import Settings
from vexledger.db.models import ApiToken, User
from vexledger.db.session import make_engine, make_session_factory

PASSWORD = "correct horse battery staple"


class Recorder:
    """Outermost ASGI wrapper: keeps (method, route template, status, body) of every response."""

    def __init__(self, app: ASGIApp, sink: list[dict[str, Any]]) -> None:
        self.app = app
        self.sink = sink

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = 0
        ctype = ""
        chunks: list[bytes] = []

        async def wrapper(message: Message) -> None:
            nonlocal status, ctype
            if message["type"] == "http.response.start":
                status = message["status"]
                ctype = dict(message["headers"]).get(b"content-type", b"").decode()
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))
            await send(message)

        await self.app(scope, receive, wrapper)
        if scope.get("route") is not None and ctype.startswith("application/json"):
            self.sink.append(
                {
                    "method": scope["method"].lower(),
                    "path": scope["path"],
                    "status": status,
                    "body": b"".join(chunks),
                }
            )


@dataclass
class Clock:
    offset: timedelta = timedelta(0)

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset

    def advance(self, **kw: float) -> None:
        self.offset += timedelta(**kw)


@dataclass
class Person:
    id: uuid.UUID
    username: str
    role: str
    password: str
    token: str


@dataclass
class Env:
    settings: Settings
    app: Any
    factory: async_sessionmaker[AsyncSession]
    redis: Redis
    clock: Clock
    transport: httpx.ASGITransport
    lifespan: Any
    engine: Any
    recorded: list[dict[str, Any]] = field(default_factory=list)
    _clients: list[httpx.AsyncClient] = field(default_factory=list)

    def client(self, person: Person | None = None) -> httpx.AsyncClient:
        headers = {"Authorization": f"Bearer {person.token}"} if person else {}
        c = httpx.AsyncClient(transport=self.transport, base_url="http://test", headers=headers)
        self._clients.append(c)
        return c

    async def person(self, role: str, *, active: bool = True) -> Person:
        hasher = make_hasher(self.settings)
        username = f"{role}-{uuid.uuid4().hex[:10]}"
        token = "vxl_" + secrets.token_urlsafe(32)
        async with self.factory() as session, session.begin():
            user = User(
                username=username, password_hash=hasher.hash(PASSWORD), role=role, is_active=active
            )
            session.add(user)
            await session.flush()
            session.add(
                ApiToken(
                    user_id=user.id,
                    name="test",
                    token_hash=hashlib.sha256(token.encode()).hexdigest(),
                )
            )
            return Person(user.id, username, role, PASSWORD, token)

    async def login(self, person: Person) -> tuple[httpx.AsyncClient, str]:
        """A cookie-session client and its CSRF token."""
        c = self.client()
        r = await c.post(
            "/api/v1/auth/login", json={"username": person.username, "password": person.password}
        )
        assert r.status_code == 200, r.text
        return c, r.json()["csrf_token"]


def _template(spec: dict[str, Any], method: str, path: str) -> str | None:
    """The OpenAPI path template that serves `path` (literal segments beat parameters)."""
    best: tuple[int, str] | None = None
    for template, ops in spec["paths"].items():
        if method not in ops:
            continue
        pattern = re.sub(r"\\\{[^/]*?\\\}", "[^/]+", re.escape(template))
        if re.fullmatch(pattern, path):
            literal = len(re.sub(r"\{[^/]*\}", "", template))
            if best is None or literal > best[0]:
                best = (literal, template)
    return best[1] if best else None


def _check_contract(app: Any, recorded: list[dict[str, Any]]) -> None:
    spec = app.openapi()
    for rec in recorded:
        if rec["status"] == 405:  # a method the route does not have: not part of the contract
            continue
        template = _template(spec, rec["method"], rec["path"])
        assert template is not None, f"{rec['method']} {rec['path']} is not in the OpenAPI schema"
        rec["path"] = template
        operation = spec["paths"][template][rec["method"]]
        response = operation["responses"].get(str(rec["status"]))
        assert response is not None, (
            f"{rec['method'].upper()} {rec['path']} answered {rec['status']} "
            "which the schema does not document"
        )
        schema = response.get("content", {}).get("application/json", {}).get("schema")
        if schema is None:
            continue
        doc = {**schema, "components": spec["components"]}
        errors = list(Draft202012Validator(doc).iter_errors(json.loads(rec["body"])))
        assert not errors, (
            f"{rec['method'].upper()} {rec['path']} {rec['status']} breaks its schema: "
            f"{errors[0].message}"
        )


@pytest.fixture
async def env(
    migrated_url: str, tmp_path: Path, settings: Settings
) -> AsyncIterator[Callable[..., Any]]:
    """Returns a builder, so a test can override settings (`await env(max_upload_mb=1)`)."""
    created: list[tuple[Env, Redis]] = []

    async def build(**overrides: Any) -> Env:
        redis_url = settings.redis_url.rsplit("/", 1)[0] + "/5"
        s = Settings(
            env=overrides.pop("env", "test"),
            database_url=migrated_url,
            redis_url=redis_url,
            evidence_dir=str(tmp_path / "evidence"),
            **overrides,
        )
        redis = Redis.from_url(redis_url)
        await redis.flushdb()
        clock = Clock()
        app = create_app(s, clock=clock)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        sink: list[dict[str, Any]] = []
        transport = httpx.ASGITransport(app=Recorder(app, sink), raise_app_exceptions=False)
        engine = make_engine(migrated_url)
        e = Env(
            s, app, make_session_factory(engine), redis, clock, transport, lifespan, engine, sink
        )
        created.append((e, redis))
        return e

    yield build
    for e, redis in created:
        for c in e._clients:
            await c.aclose()
        await e.lifespan.__aexit__(None, None, None)
        await e.engine.dispose()
        await redis.flushdb()
        await redis.aclose()
        _check_contract(e.app, e.recorded)


@pytest.fixture
def env_sync(settings: Settings) -> Any:
    """The app object alone (no lifespan, no I/O), for route introspection."""
    return create_app(settings)
