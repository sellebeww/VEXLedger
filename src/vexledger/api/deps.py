# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Authentication, CSRF and role checks. Every endpoint (except login) depends on `require(...)`."""

import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from fastapi import Depends, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vexledger.api.errors import ApiError
from vexledger.auth.store import TOKEN_PREFIX, SessionStore, hash_secret
from vexledger.config import Settings
from vexledger.db.models import ApiToken, User

SESSION_COOKIE = "vexledger_session"
CSRF_HEADER = "x-csrf-token"
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_TOKEN_TOUCH_INTERVAL = timedelta(minutes=1)


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    username: str
    role: str
    via: Literal["session", "token"]
    session_id: str | None = None
    csrf: str | None = None


def factory_of(request: Request) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.factory
    return factory


def settings_of(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def now_of(request: Request) -> datetime:
    clock: Callable[[], datetime] = request.app.state.clock
    return clock()


async def db(request: Request) -> AsyncIterator[AsyncSession]:
    """A session for the handler; writers open `session.begin()` themselves."""
    async with factory_of(request)() as session:
        yield session


def _unauthorized(message: str = "authentication required") -> ApiError:
    return ApiError(401, "unauthorized", message, headers={"WWW-Authenticate": "Bearer"})


async def _from_token(request: Request, raw: str) -> Principal:
    if not raw.startswith(TOKEN_PREFIX):
        raise _unauthorized("invalid token")
    async with factory_of(request)() as session:
        row = (
            await session.execute(
                select(ApiToken, User)
                .join(User, User.id == ApiToken.user_id)
                .where(ApiToken.token_hash == hash_secret(raw))
            )
        ).one_or_none()
        if row is None or row[0].revoked_at is not None or not row[1].is_active:
            raise _unauthorized("invalid token")
        token, user = row
        now = now_of(request)
        if token.last_used_at is None or now - token.last_used_at > _TOKEN_TOUCH_INTERVAL:
            await session.execute(
                update(ApiToken).where(ApiToken.id == token.id).values(last_used_at=now)
            )
            await session.commit()
        return Principal(user.id, user.username, user.role, "token")


async def _from_session(request: Request, sid: str) -> Principal:
    sessions: SessionStore = request.app.state.sessions
    data = await sessions.get(sid)
    if data is None:
        raise _unauthorized("session expired")
    async with factory_of(request)() as session:
        user = await session.get(User, data.user_id)
    if user is None or not user.is_active:
        raise _unauthorized("session expired")
    if request.method not in _SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not secrets.compare_digest(sent.encode(), data.csrf.encode()):
            raise ApiError(403, "csrf_failed", "missing or invalid CSRF token")
    return Principal(user.id, user.username, user.role, "session", sid, data.csrf)


async def authenticate(request: Request) -> Principal:
    header = request.headers.get("authorization")
    if header is not None:
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer" or not value:
            raise _unauthorized("invalid Authorization header")
        return await _from_token(request, value.strip())  # a bad token never falls back to a cookie
    sid = request.cookies.get(SESSION_COOKIE)
    if sid is None:
        raise _unauthorized()
    return await _from_session(request, sid)


def require(minimum: str) -> Callable[[Request], Awaitable[Principal]]:
    """Dependency factory: authenticate, check CSRF (sessions only), then the role."""

    async def dependency(request: Request) -> Principal:
        principal = await authenticate(request)
        if ROLE_RANK[principal.role] < ROLE_RANK[minimum]:
            raise ApiError(403, "forbidden", f"requires role {minimum}")
        return principal

    dependency.__name__ = f"require_{minimum}"
    dependency.required_role = minimum  # type: ignore[attr-defined]  # read by the matrix test
    return dependency


# Module-level singletons, so FastAPI resolves each role check once per request.
require_viewer = require("viewer")
require_analyst = require("analyst")
require_admin = require("admin")
Viewer = Depends(require_viewer)
Analyst = Depends(require_analyst)
Admin = Depends(require_admin)
