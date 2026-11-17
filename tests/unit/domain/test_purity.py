# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""The domain package must stay free of database, network and system-clock access."""

import ast
from pathlib import Path

import pytest

DOMAIN = Path(__file__).parents[3] / "src" / "vexledger" / "domain"
FORBIDDEN_MODULES = {
    "sqlalchemy",
    "asyncpg",
    "redis",
    "httpx",
    "requests",
    "urllib.request",
    "socket",
    "aiohttp",
    "time",
    "random",
    "uuid",
    "os",
    "subprocess",
    "vexledger.db",
    "vexledger.api",
    "vexledger.services",
    "vexledger.worker",
    "vexledger.osv",
}
FORBIDDEN_CALLS = {"now", "utcnow", "today", "time", "monotonic", "perf_counter"}


@pytest.mark.parametrize(
    "path", sorted(DOMAIN.rglob("*.py")), ids=lambda p: str(p.relative_to(DOMAIN))
)
def test_module_has_no_io_or_clock(path: Path) -> None:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in FORBIDDEN_CALLS, (
                f"{path.name}: clock call .{node.func.attr}()"
            )
            continue
        else:
            continue
        for name in names:
            assert not any(name == m or name.startswith(m + ".") for m in FORBIDDEN_MODULES), (
                f"{path.name} imports {name}"
            )
