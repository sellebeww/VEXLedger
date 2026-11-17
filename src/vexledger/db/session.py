# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Engine and session factory helpers."""

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

# No I/O without a timeout: seconds for connecting, and for any single statement.
_TIMEOUTS = {"timeout": 10, "command_timeout": 120}


def make_engine(url: str, *, null_pool: bool = False) -> AsyncEngine:
    if null_pool:
        return create_async_engine(url, poolclass=NullPool, connect_args=_TIMEOUTS)
    return create_async_engine(url, pool_pre_ping=True, connect_args=_TIMEOUTS)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Sessions never auto-expire after commit; callers open transactions explicitly."""
    return async_sessionmaker(engine, expire_on_commit=False)
