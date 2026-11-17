# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Helpers for pipeline tests: products, releases, SBOM import, and the standard scenario."""

import json
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.unit.test_sbom_import import bom, comp
from vexledger.db.models import Product, Release
from vexledger.db.repos.products import ProductRepository, ReleaseRepository
from vexledger.services.importer import import_sbom

from .osv_fake import FakeOsv
from .seed import NOW

Factory = async_sessionmaker[AsyncSession]
TTL = timedelta(hours=6)


async def create_release(
    factory: Factory, product: Product | None = None, version: str = "1.0.0", inherit: bool = True
) -> tuple[Product, Release]:
    async with factory() as s, s.begin():
        if product is None:
            product = await ProductRepository(s).create(
                slug=f"p-{uuid.uuid4().hex[:12]}",
                name="Synthetic",
                purl="pkg:generic/synthetic",
                vex_author="Example (synthetic)",
                actor_id=None,
                inherit_enabled=inherit,
            )
        release = await ReleaseRepository(s).create(
            product_id=product.id, version=version, actor_id=None
        )
    return product, release


def components(
    npm_version: str = "1.0.1", maven_version: str = "2.0.1", pypi_version: str = "1.5"
) -> list[dict[str, Any]]:
    return [
        comp("synthetic-pkg", pypi_version),
        comp("synthetic-pkg", "2.0"),
        comp("@synthetic/lib", npm_version, purl=f"pkg:npm/%40synthetic/lib@{npm_version}"),
        comp("lib", maven_version, purl=f"pkg:maven/org.synthetic/lib@{maven_version}"),
        comp("Mod", "v1.3.0", purl="pkg:golang/github.com/Synthetic/Mod@v1.3.0"),
        comp("curl", "7.0", purl="pkg:deb/debian/curl@7.0"),
        comp("mystery", purl=None),
    ]


async def import_components(
    factory: Factory, release: Release, comps: list[dict[str, Any]]
) -> None:
    root = comp("app", "1.0.0", purl="pkg:generic/app@1.0.0", ref="app")
    data = json.dumps(bom(comps, root=root)).encode()
    await import_sbom(factory, release_id=release.id, data=data, actor_id=None)


def serve_standard(
    fake: FakeOsv,
    npm_version: str = "1.0.1",
    maven_version: str = "2.0.1",
    pypi_version: str = "1.5",
) -> None:
    """The scenario: alias triple, boundary + withdrawn, npm, maven, go. Six findings in total."""
    fake.serve(
        f"pkg:pypi/synthetic-pkg@{pypi_version}",
        "CVE-2099-0001",
        "GHSA-synt-0001-aaaa",
        "PYSEC-2099-1",
    )
    fake.serve("pkg:pypi/synthetic-pkg@2.0", "CVE-2099-0001", "GHSA-synt-wd-0005")
    fake.serve(f"pkg:npm/%40synthetic/lib@{npm_version}", "GHSA-synt-npm-0002")
    fake.serve(f"pkg:maven/org.synthetic/lib@{maven_version}", "GHSA-synt-mvn-0003")
    fake.serve("pkg:golang/github.com/Synthetic/Mod@v1.3.0", "GO-2099-0004")


__all__ = ["NOW", "TTL", "components", "create_release", "import_components", "serve_standard"]
