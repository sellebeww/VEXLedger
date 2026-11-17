# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Synthetic data builders for integration tests (unique slugs, so tests never collide)."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vexledger.db.models import Component, ComponentEdge, Product, Release
from vexledger.db.models import Finding as FindingRow
from vexledger.db.repos.components import ComponentRepository
from vexledger.db.repos.findings import FindingRepository
from vexledger.db.repos.products import ProductRepository, ReleaseRepository

NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)


def component(release_id: uuid.UUID, name: str, version: str = "1.0", **kw: Any) -> Component:
    ref_key = f"pypi/{name}"
    return Component(
        id=uuid.uuid4(),
        release_id=release_id,
        name=name,
        version=version,
        purl_original=f"pkg:pypi/{name}@{version}",
        purl_normal=f"pkg:pypi/{name}@{version}",
        component_key=ref_key,
        component_ref=f"{ref_key}@{version}",
        ecosystem="PyPI",
        **kw,
    )


@dataclass
class Seeded:
    product: Product
    release: Release
    components: dict[str, Component]


async def seed_release(
    factory: async_sessionmaker[AsyncSession],
    names: list[str] | None = None,
    edges: list[tuple[str, str]] | None = None,
    root: str = "app",
) -> Seeded:
    """A product with one release, a root component and the named components."""
    names = names or []
    async with factory() as session, session.begin():
        product = await ProductRepository(session).create(
            slug=f"p-{uuid.uuid4().hex[:12]}",
            name="Synthetic",
            purl="pkg:generic/synthetic",
            vex_author="Example (synthetic)",
            actor_id=None,
        )
        release = await ReleaseRepository(session).create(
            product_id=product.id, version="1.0.0", actor_id=None
        )
        comps = {root: component(release.id, root, is_root=True)}
        comps.update({n: component(release.id, n) for n in names})
        edge_rows = [
            ComponentEdge(parent_id=comps[a].id, child_id=comps[b].id, release_id=release.id)
            for a, b in (edges or [])
        ]
        await ComponentRepository(session).add_all(list(comps.values()), edge_rows)
    return Seeded(product, release, comps)


async def seed_finding(
    factory: async_sessionmaker[AsyncSession],
    seeded: Seeded,
    component_name: str,
    vuln: str = "CVE-2099-0001",
    **kw: Any,
) -> FindingRow:
    async with factory() as session, session.begin():
        return await FindingRepository(session).create(
            release_id=seeded.release.id,
            component=seeded.components[component_name],
            canonical_vuln_id=vuln,
            alias_ids=kw.pop("alias_ids", []),
            **kw,
        )
