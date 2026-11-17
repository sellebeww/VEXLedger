# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""User aggregate."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.db.models import User
from vexledger.db.repos.audit import append_audit


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self, *, username: str, password_hash: str, role: str, actor_id: uuid.UUID | None = None
    ) -> User:
        user = User(username=username, password_hash=password_hash, role=role)
        self.session.add(user)
        await self.session.flush()
        append_audit(
            self.session,
            actor_id=actor_id,
            action="user.create",
            entity_type="user",
            entity_id=str(user.id),
            after={"username": username, "role": role},
        )
        return user

    async def get_by_username(self, username: str) -> User | None:
        result = await self.session.execute(
            select(User).where(func.lower(User.username) == username.lower())
        )
        return result.scalar_one_or_none()
