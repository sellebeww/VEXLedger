# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Authentication behind an interface, so OIDC can replace local accounts later."""

import asyncio
from abc import ABC, abstractmethod

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.config import Settings
from vexledger.db.models import User
from vexledger.db.repos.users import UserRepository


class AuthProvider(ABC):
    @abstractmethod
    async def authenticate(
        self, session: AsyncSession, username: str, password: str
    ) -> User | None:
        """Return the active user for valid credentials, otherwise None (never say which part)."""


def make_hasher(settings: Settings) -> PasswordHasher:
    """argon2id. Tests use the cheapest parameters; every other environment the library defaults."""
    if settings.env == "test":
        return PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    return PasswordHasher()


class LocalAuthProvider(AuthProvider):
    def __init__(self, hasher: PasswordHasher) -> None:
        self.hasher = hasher
        # Verified against when the user does not exist, so timing does not reveal accounts.
        self._dummy = hasher.hash("vexledger-dummy-password")

    async def authenticate(
        self, session: AsyncSession, username: str, password: str
    ) -> User | None:
        user = await UserRepository(session).get_by_username(username)
        try:  # argon2 is CPU-bound: keep it off the event loop
            await asyncio.to_thread(
                self.hasher.verify, user.password_hash if user else self._dummy, password
            )
        except VerificationError, InvalidHashError:
            return None
        return user if user is not None and user.is_active else None
