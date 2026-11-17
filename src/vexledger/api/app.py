# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""FastAPI application factory."""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from arq.connections import ArqRedis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from redis.asyncio import Redis

from vexledger.api.errors import ErrorOut, install_error_handlers
from vexledger.api.health import router as health_router
from vexledger.api.middleware import RequestIdMiddleware
from vexledger.api.routes import admin, auth, findings, products
from vexledger.api.security import BodyLimitMiddleware, SecurityHeadersMiddleware
from vexledger.auth.provider import LocalAuthProvider, make_hasher
from vexledger.auth.store import RateLimiter, SessionStore
from vexledger.config import Settings, get_settings
from vexledger.config.logging import configure_logging
from vexledger.db.session import make_engine, make_session_factory
from vexledger.services.evidence_storage import MAX_EVIDENCE_BYTES, FilesystemEvidenceStorage
from vexledger.worker.tasks import create_queue


class LazyQueue:
    """The Arq pool is opened on first use, so the API starts (and reports 503) without Redis."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._pool: ArqRedis | None = None

    async def pool(self) -> ArqRedis:
        if self._pool is None:
            self._pool = await create_queue(self._settings)
        return self._pool

    async def aclose(self) -> None:
        if self._pool is not None:
            await self._pool.aclose()


_MULTIPART_OVERHEAD = 256 * 1024

DESCRIPTION = """\
Workbench for the lifecycle of VEX statements: CycloneDX SBOM in, OpenVEX out.

**Authentication.** Browser clients log in (`POST /auth/login`), get an HttpOnly session cookie
and send the returned CSRF token in `X-CSRF-Token` on every mutation. Scripts and CI use a personal
token: `Authorization: Bearer vxl_...` (no CSRF needed). Roles: `viewer` reads, `analyst` also
triages, uploads and exports, `admin` also manages users, tokens and product settings.

**Errors.** Always `{"error": {"code", "message", "field?", "details?", "request_id"}}` with a
stable `code`.

VEXLedger records triage decisions made by people. It does not decide exploitability, gives no
compliance guarantee, and its OpenVEX documents are not signed.
"""

TAGS = [
    {"name": "auth", "description": "Login, sessions and personal API tokens"},
    {"name": "products", "description": "Products, releases, SBOM upload, gate, export, diff"},
    {"name": "findings", "description": "Triage, evidence and assignment"},
    {"name": "admin", "description": "Users, all tokens and the audit log (admin)"},
    {"name": "health", "description": "Probes"},
]


def _operation_id(route: APIRoute) -> str:
    return route.name


def create_app(
    settings: Settings | None = None, *, clock: Callable[[], datetime] | None = None
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(settings.database_url)
        redis = Redis.from_url(settings.redis_url)
        hasher = make_hasher(settings)
        app.state.settings = settings
        app.state.clock = clock or (lambda: datetime.now(UTC))
        app.state.engine = engine
        app.state.factory = make_session_factory(engine)
        app.state.redis = redis
        app.state.queue = LazyQueue(settings)
        app.state.hasher = hasher
        app.state.auth_provider = LocalAuthProvider(hasher)
        app.state.sessions = SessionStore(redis, settings.session_ttl_s)
        app.state.limiter = RateLimiter(redis, settings.login_window_s)
        app.state.evidence_storage = FilesystemEvidenceStorage(
            Path(settings.evidence_dir), MAX_EVIDENCE_BYTES
        )
        try:
            yield
        finally:
            await app.state.queue.aclose()
            await redis.aclose()
            await engine.dispose()

    app = FastAPI(
        title="VEXLedger API",
        version="0.1.0",
        description=DESCRIPTION,
        openapi_tags=TAGS,
        lifespan=lifespan,
        generate_unique_id_function=_operation_id,
        responses={503: {"model": ErrorOut, "description": "Redis or Postgres is unreachable"}},
    )
    install_error_handlers(app)

    def limit_for(path: str) -> int:
        if path.endswith("/sbom"):
            return settings.max_upload_mb * 1024 * 1024 + _MULTIPART_OVERHEAD
        if path.endswith("/evidence/file"):
            return MAX_EVIDENCE_BYTES + _MULTIPART_OVERHEAD
        return settings.json_body_max_kb * 1024

    # Last added is outermost: request id, security headers, CORS, then the body limit.
    app.add_middleware(BodyLimitMiddleware, limit_for=limit_for)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.cookie_secure)
    app.add_middleware(RequestIdMiddleware)

    app.include_router(health_router)
    for module in (auth, products, findings, admin):
        app.include_router(module.router, prefix="/api/v1")
    return app
