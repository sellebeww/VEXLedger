# Copyright (c) 2026 Vassel Goleyu. MIT License.
import asyncio
from collections.abc import Callable

import pytest
from alembic import command
from sqlalchemy import text

from vexledger.db.session import make_engine

from .conftest import alembic_config

pytestmark = pytest.mark.integration

EXPECTED_TABLES = {
    "users",
    "api_tokens",
    "products",
    "releases",
    "sboms",
    "components",
    "component_edges",
    "vulnerabilities",
    "purl_query_cache",
    "findings",
    "vex_statements",
    "evidence",
    "evidence_files",
    "vex_exports",
    "audit_log",
}


async def _tables(url: str) -> tuple[set[str], int]:
    engine = make_engine(url, null_pool=True)
    async with engine.connect() as conn:
        tables = set(
            (
                await conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                    )
                )
            ).scalars()
        )
        funcs = (
            await conn.execute(
                text("SELECT count(*) FROM pg_proc WHERE proname = 'vexledger_forbid_modification'")
            )
        ).scalar_one()
    await engine.dispose()
    return tables, funcs


async def test_upgrade_from_zero_downgrade_and_upgrade_again(
    create_database: Callable[[str], str], require_infra: None
) -> None:
    url = await asyncio.to_thread(create_database, "vexledger_migration_test")
    cfg = alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    tables, funcs = await _tables(url)
    assert tables >= EXPECTED_TABLES
    assert funcs == 1

    await asyncio.to_thread(command.downgrade, cfg, "base")
    tables, funcs = await _tables(url)
    assert tables == {"alembic_version"}
    assert funcs == 0

    await asyncio.to_thread(command.upgrade, cfg, "head")
    assert (await _tables(url))[0] >= EXPECTED_TABLES


async def test_models_and_migration_agree(migrated_url: str) -> None:
    """Autogenerate against the migrated database must find nothing left to do."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    import vexledger.db.models  # noqa: F401
    from vexledger.db.base import Base

    engine = make_engine(migrated_url, null_pool=True)
    async with engine.connect() as conn:
        diff = await conn.run_sync(
            lambda sync: compare_metadata(MigrationContext.configure(sync), Base.metadata)
        )
    await engine.dispose()
    assert diff == []
