# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Shared fixtures."""

import os
import socket
from urllib.parse import urlparse

import pytest

from vexledger.config import Settings


def _reachable(url: str) -> bool:
    parsed = urlparse(url.replace("+asyncpg", ""))
    try:
        with socket.create_connection((parsed.hostname or "localhost", parsed.port or 0), 1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings(env="test")


@pytest.fixture(scope="session")
def require_infra(settings: Settings) -> None:
    """Skip integration tests when Postgres/Redis are down, unless REQUIRE_INFRA=1 (CI)."""
    if _reachable(settings.database_url) and _reachable(settings.redis_url):
        return
    if os.environ.get("REQUIRE_INFRA") == "1":
        pytest.fail("Postgres/Redis unreachable but REQUIRE_INFRA=1")
    pytest.skip("Postgres/Redis not running (make dev-up)")
