# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Integration fixtures: a throwaway Postgres database built from the real migrations."""

import asyncio
from collections.abc import AsyncIterator, Callable, Iterator
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import respx
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from vexledger.config import Settings
from vexledger.db.session import make_engine, make_session_factory
from vexledger.osv.client import OsvClient
from vexledger.services.metrics import Metrics

from .osv_fake import BASE, FakeOsv


def alembic_config(url: str) -> Config:
    cfg = Config("alembic.ini")
    cfg.attributes["url"] = url
    return cfg


async def _recreate_database(admin_url: str, name: str) -> None:
    engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await engine.dispose()


def database_url(settings: Settings, name: str) -> str:
    return make_url(settings.database_url).set(database=name).render_as_string(hide_password=False)


@pytest.fixture(scope="session")
def create_database() -> Callable[[str], str]:
    """Return a function that recreates a database (from nothing) and returns its URL."""
    settings = Settings(env="test")

    def _create(name: str) -> str:
        # A worker thread has no running event loop, whatever the caller is doing.
        with ThreadPoolExecutor(1) as pool:
            pool.submit(
                asyncio.run, _recreate_database(database_url(settings, "postgres"), name)
            ).result()
        return database_url(settings, name)

    return _create


@pytest.fixture(scope="session")
def migrated_url(create_database: Callable[[str], str], require_infra: None) -> str:
    url = create_database("vexledger_test")
    with ThreadPoolExecutor(1) as pool:  # real migrations, from an empty database
        pool.submit(command.upgrade, alembic_config(url), "head").result()
    return url


@pytest.fixture
async def engine(migrated_url: str) -> AsyncIterator[AsyncEngine]:
    eng = make_engine(migrated_url, null_pool=True)
    yield eng
    await eng.dispose()


@pytest.fixture
def factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return make_session_factory(engine)


@pytest.fixture(autouse=True)
async def clean_osv_cache(factory: async_sessionmaker[AsyncSession]) -> None:
    """The OSV record store and purl cache are shared mutable tables; start every test clean."""
    async with factory() as session, session.begin():
        await session.execute(text("DELETE FROM purl_query_cache"))
        await session.execute(text("DELETE FROM vulnerabilities"))


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as r:
        yield r


@pytest.fixture
def fake(router: respx.MockRouter) -> FakeOsv:
    return FakeOsv(router)


@pytest.fixture
async def osv(fake: FakeOsv) -> AsyncIterator[OsvClient]:
    async def no_sleep(_: float) -> None:
        return None

    async with httpx.AsyncClient() as http:
        yield OsvClient(BASE, client=http, max_retries=1, sleep=no_sleep, metrics=Metrics())
