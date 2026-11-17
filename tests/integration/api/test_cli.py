# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""`vexledger create-admin` bootstraps the first admin."""

import asyncio
import uuid

import pytest
from argon2 import PasswordHasher
from sqlalchemy import select

from vexledger import cli
from vexledger.config import get_settings
from vexledger.db.models import AuditLog, User
from vexledger.db.session import make_engine, make_session_factory


@pytest.fixture
def cli_env(migrated_url, monkeypatch):
    monkeypatch.setenv("VEXLEDGER_DATABASE_URL", migrated_url)
    get_settings.cache_clear()
    yield migrated_url
    get_settings.cache_clear()


def _fetch(url, username):
    async def go():
        engine = make_engine(url, null_pool=True)
        async with make_session_factory(engine)() as s:
            user = (
                await s.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            audit = (
                (await s.execute(select(AuditLog.action).where(AuditLog.entity_id == str(user.id))))
                .scalars()
                .all()
                if user
                else []
            )
        await engine.dispose()
        return user, audit

    return asyncio.run(go())


def test_create_admin_and_refusals(cli_env, monkeypatch, capsys):
    name = f"boot-{uuid.uuid4().hex[:8]}"
    monkeypatch.setenv(cli.PASSWORD_ENV, "a-long-enough-password")
    assert cli.main(["create-admin", name]) == 0
    user, audit = _fetch(cli_env, name)
    assert user.role == "admin" and user.is_active and "a-long-enough" not in user.password_hash
    assert user.password_hash.startswith("$argon2id$")
    PasswordHasher().verify(user.password_hash, "a-long-enough-password")
    assert audit == ["user.create"]
    assert "created" in capsys.readouterr().out

    assert cli.main(["create-admin", name]) == 1  # duplicate
    assert "already exists" in capsys.readouterr().err
    assert cli.main(["create-admin", "x y"]) == 1  # bad username
    monkeypatch.setenv(cli.PASSWORD_ENV, "short")
    assert cli.main(["create-admin", f"short-{uuid.uuid4().hex[:6]}"]) == 1
    assert "at least 12" in capsys.readouterr().err


def test_create_admin_without_a_password_source_fails(cli_env, monkeypatch, capsys):
    monkeypatch.delenv(cli.PASSWORD_ENV, raising=False)
    monkeypatch.setattr("sys.stdin", open("/dev/null"))  # noqa: SIM115
    assert cli.main(["create-admin", "nobody-here"]) == 1
    assert "no terminal" in capsys.readouterr().err
