# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Admin only: users, all API tokens and the audit log."""

import asyncio
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.api.deps import Admin, Principal, db, factory_of, now_of, settings_of
from vexledger.api.errors import AUTHED, VALIDATED, WRITE, ApiError
from vexledger.api.routes.auth import revoke_token
from vexledger.api.schemas import (
    AuditOut,
    AuditPageOut,
    TokenOut,
    UserCreateIn,
    UserOut,
    UserPatchIn,
)
from vexledger.auth.store import SessionStore
from vexledger.db.errors import NotFoundError
from vexledger.db.models import ApiToken, AuditLog, User
from vexledger.db.repos.audit import append_audit
from vexledger.db.repos.users import UserRepository

router = APIRouter(prefix="/admin", tags=["admin"])


def _check_password(password: str, minimum: int) -> None:
    if len(password) < minimum:
        raise ApiError(
            422,
            "password_too_short",
            f"password needs at least {minimum} characters",
            field="password",
        )


@router.get("/users", response_model=list[UserOut], summary="List users", responses=AUTHED)
async def list_users(session: AsyncSession = Depends(db), _: Principal = Admin) -> list[UserOut]:
    rows = (await session.execute(select(User).order_by(User.username))).scalars()
    return [UserOut.model_validate(r) for r in rows]


@router.post(
    "/users", status_code=201, response_model=UserOut, summary="Create a user", responses=WRITE
)
async def create_user(body: UserCreateIn, request: Request, p: Principal = Admin) -> UserOut:
    _check_password(body.password, settings_of(request).password_min_length)
    hashed = await asyncio.to_thread(request.app.state.hasher.hash, body.password)
    try:
        async with factory_of(request)() as session, session.begin():
            user = await UserRepository(session).create(
                username=body.username, password_hash=hashed, role=body.role, actor_id=p.user_id
            )
            await session.refresh(user)
            return UserOut.model_validate(user)
    except IntegrityError as exc:
        raise ApiError(409, "user_exists", "that username is taken") from exc


@router.patch(
    "/users/{user_id}",
    response_model=UserOut,
    summary="Change role, activation or password of a user",
    responses=WRITE,
)
async def patch_user(
    user_id: Annotated[uuid.UUID, Path()], body: UserPatchIn, request: Request, p: Principal = Admin
) -> UserOut:
    """Deactivating a user or resetting the password also ends that user's sessions."""
    if body.password is not None:
        _check_password(body.password, settings_of(request).password_min_length)
    new_hash = (
        await asyncio.to_thread(request.app.state.hasher.hash, body.password)
        if body.password is not None
        else None
    )
    async with factory_of(request)() as session, session.begin():
        user = (
            await session.execute(select(User).where(User.id == user_id).with_for_update())
        ).scalar_one_or_none()
        if user is None:
            raise NotFoundError(f"user {user_id} not found")
        loses_admin = (
            user.role == "admin"
            and user.is_active
            and (body.role not in (None, "admin") or body.is_active is False)
        )
        if loses_admin:
            others = (
                await session.execute(
                    select(User.id)
                    .where(User.role == "admin", User.is_active, User.id != user_id)
                    .with_for_update()
                )
            ).first()
            if others is None:
                raise ApiError(
                    409, "last_admin", "the last active admin cannot be demoted or deactivated"
                )
        before = {"role": user.role, "is_active": user.is_active}
        if body.role is not None:
            user.role = body.role
        if body.is_active is not None:
            user.is_active = body.is_active
        if new_hash is not None:
            user.password_hash = new_hash
        append_audit(
            session,
            actor_id=p.user_id,
            action="user.update",
            entity_type="user",
            entity_id=str(user_id),
            before=before,
            after={
                "role": user.role,
                "is_active": user.is_active,
                "password_changed": new_hash is not None,
            },
        )
        await session.flush()
        out = UserOut.model_validate(user)
    if new_hash is not None or body.is_active is False:
        sessions: SessionStore = request.app.state.sessions
        await sessions.delete_all_for(user_id)
    return out


@router.get(
    "/tokens",
    response_model=list[TokenOut],
    summary="All API tokens (no secrets)",
    responses=AUTHED,
)
async def list_all_tokens(
    session: AsyncSession = Depends(db), _: Principal = Admin
) -> list[TokenOut]:
    rows = (await session.execute(select(ApiToken).order_by(ApiToken.created_at.desc()))).scalars()
    return [TokenOut.model_validate(r) for r in rows]


@router.delete(
    "/tokens/{token_id}",
    status_code=204,
    summary="Revoke any API token",
    responses=WRITE,
)
async def revoke_any_token(token_id: uuid.UUID, request: Request, p: Principal = Admin) -> Response:
    async with factory_of(request)() as session, session.begin():
        await revoke_token(session, token_id, owner=None, actor=p.user_id, now=now_of(request))
    return Response(status_code=204)


@router.get(
    "/audit",
    response_model=AuditPageOut,
    summary="Audit log, newest first (keyset pagination by `before_id`)",
    responses=VALIDATED,
)
async def audit(
    entity_type: Annotated[str | None, Query(pattern=r"^[a-z_]{1,40}$")] = None,
    entity_id: Annotated[str | None, Query(max_length=100, pattern=r"^[^\x00]*$")] = None,
    actor_id: uuid.UUID | None = None,
    action: Annotated[str | None, Query(pattern=r"^[a-z_.]{1,60}$")] = None,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    session: AsyncSession = Depends(db),
    _: Principal = Admin,
) -> AuditPageOut:
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit + 1)
    for column, value in (
        (AuditLog.entity_type, entity_type),
        (AuditLog.entity_id, entity_id),
        (AuditLog.actor_id, actor_id),
        (AuditLog.action, action),
    ):
        if value is not None:
            query = query.where(column == value)
    if before_id is not None:
        query = query.where(AuditLog.id < before_id)
    rows = list((await session.execute(query)).scalars())
    page = rows[:limit]
    return AuditPageOut(
        items=[AuditOut.model_validate(r) for r in page],
        next_before_id=page[-1].id if len(rows) > limit else None,
    )
