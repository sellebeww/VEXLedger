# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Login, sessions and personal API tokens."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.api.deps import (
    SESSION_COOKIE,
    Principal,
    Viewer,
    db,
    factory_of,
    now_of,
    settings_of,
)
from vexledger.api.errors import AUTHED, READ, VALIDATED, ApiError, ErrorOut
from vexledger.api.schemas import (
    LoginIn,
    SessionOut,
    TokenCreatedOut,
    TokenCreateIn,
    TokenOut,
    UserOut,
)
from vexledger.auth.provider import AuthProvider
from vexledger.auth.store import RateLimiter, SessionStore, hash_secret, new_api_token
from vexledger.db.errors import NotFoundError
from vexledger.db.models import ApiToken, User
from vexledger.db.repos.audit import append_audit

router = APIRouter(prefix="/auth", tags=["auth"])


def client_ip(request: Request) -> str:
    # Behind a proxy run uvicorn with --proxy-headers and --forwarded-allow-ips (docs/API.md).
    return request.client.host if request.client else "unknown"


@router.post(
    "/login",
    response_model=SessionOut,
    summary="Log in with username and password",
    responses={
        401: {"model": ErrorOut, "description": "Wrong credentials"},
        413: {"model": ErrorOut, "description": "Request body too large"},
        422: {"model": ErrorOut, "description": "Validation failed"},
        429: {"model": ErrorOut, "description": "Too many failed attempts (see Retry-After)"},
    },
)
async def login(body: LoginIn, request: Request, response: Response) -> SessionOut:
    """Sets an HttpOnly session cookie and returns the CSRF token for later mutations."""
    settings = settings_of(request)
    limiter: RateLimiter = request.app.state.limiter
    provider: AuthProvider = request.app.state.auth_provider
    sessions: SessionStore = request.app.state.sessions
    ip = client_ip(request)
    account = body.username.strip().lower()[:64]
    keys = (
        (f"ip:{ip}", settings.login_max_per_ip),
        (f"acct:{account}", settings.login_max_per_account),
    )
    for key, limit in keys:
        if (wait := await limiter.blocked(key, limit)) is not None:
            raise ApiError(
                429,
                "rate_limited",
                "too many failed login attempts, try again later",
                headers={"Retry-After": str(wait)},
            )
    factory = factory_of(request)
    async with factory() as session:
        user = await provider.authenticate(session, body.username.strip(), body.password)
    if user is None:
        for key, _ in keys:
            await limiter.hit(key)
        async with factory() as session, session.begin():
            append_audit(
                session,
                actor_id=None,
                action="auth.login_failed",
                entity_type="user",
                entity_id=account,
                after={"ip": ip},
            )
        raise ApiError(401, "invalid_credentials", "invalid username or password")
    await limiter.reset(f"acct:{account}")
    sid, data = await sessions.create(user.id)
    async with factory() as session, session.begin():
        append_audit(
            session,
            actor_id=user.id,
            action="auth.login",
            entity_type="user",
            entity_id=str(user.id),
            after={"ip": ip},
        )
    response.set_cookie(
        SESSION_COOKIE,
        sid,
        max_age=settings.session_ttl_s,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )
    return SessionOut(
        user=UserOut.model_validate(user),
        csrf_token=data.csrf,
        demo_data=settings.demo_osv_fixtures,
    )


@router.post(
    "/logout",
    status_code=204,
    summary="End the session",
    responses=AUTHED,
)
async def logout(request: Request, p: Principal = Viewer) -> Response:
    if p.session_id is not None:
        await request.app.state.sessions.delete(p.session_id)
    async with factory_of(request)() as session, session.begin():
        append_audit(
            session,
            actor_id=p.user_id,
            action="auth.logout",
            entity_type="user",
            entity_id=str(p.user_id),
        )
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get(
    "/me",
    response_model=SessionOut,
    summary="The current user (and the CSRF token of the session)",
    responses=AUTHED,
)
async def me(
    request: Request, session: AsyncSession = Depends(db), p: Principal = Viewer
) -> SessionOut:
    user = await session.get(User, p.user_id)
    if user is None:
        raise NotFoundError("user not found")
    return SessionOut(
        user=UserOut.model_validate(user),
        csrf_token=p.csrf,
        demo_data=settings_of(request).demo_osv_fixtures,
    )


@router.post(
    "/tokens",
    status_code=201,
    response_model=TokenCreatedOut,
    summary="Create a personal API token (session only)",
    responses=VALIDATED,
)
async def create_token(
    body: TokenCreateIn, request: Request, p: Principal = Viewer
) -> TokenCreatedOut:
    """The token has the role of its owner and is shown once. Tokens cannot mint tokens."""
    if p.via != "session":
        raise ApiError(403, "session_required", "tokens can only be created from a login session")
    raw = new_api_token()
    async with factory_of(request)() as session, session.begin():
        row = ApiToken(user_id=p.user_id, name=body.name.strip(), token_hash=hash_secret(raw))
        session.add(row)
        await session.flush()
        append_audit(
            session,
            actor_id=p.user_id,
            action="token.create",
            entity_type="api_token",
            entity_id=str(row.id),
            after={"name": row.name},
        )
        out = TokenOut.model_validate(row)
    return TokenCreatedOut(**out.model_dump(), token=raw)


@router.get(
    "/tokens",
    response_model=list[TokenOut],
    summary="Your API tokens (never the secret)",
    responses=AUTHED,
)
async def list_tokens(session: AsyncSession = Depends(db), p: Principal = Viewer) -> list[TokenOut]:
    rows = (
        await session.execute(
            select(ApiToken)
            .where(ApiToken.user_id == p.user_id)
            .order_by(ApiToken.created_at.desc())
        )
    ).scalars()
    return [TokenOut.model_validate(r) for r in rows]


async def revoke_token(
    session: AsyncSession,
    token_id: uuid.UUID,
    *,
    owner: uuid.UUID | None,
    actor: uuid.UUID,
    now: datetime,
) -> None:
    """Revoke (idempotently) a token; `owner` restricts to the caller's own tokens."""
    query = select(ApiToken).where(ApiToken.id == token_id).with_for_update()
    if owner is not None:
        query = query.where(ApiToken.user_id == owner)
    row = (await session.execute(query)).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"token {token_id} not found")
    if row.revoked_at is None:
        await session.execute(
            update(ApiToken).where(ApiToken.id == token_id).values(revoked_at=now)
        )
        append_audit(
            session,
            actor_id=actor,
            action="token.revoke",
            entity_type="api_token",
            entity_id=str(token_id),
            after={"owner": str(row.user_id)},
        )


@router.delete(
    "/tokens/{token_id}",
    status_code=204,
    summary="Revoke one of your tokens",
    responses=READ,
)
async def delete_token(token_id: uuid.UUID, request: Request, p: Principal = Viewer) -> Response:
    async with factory_of(request)() as session, session.begin():
        await revoke_token(session, token_id, owner=p.user_id, actor=p.user_id, now=now_of(request))
    return Response(status_code=204)
