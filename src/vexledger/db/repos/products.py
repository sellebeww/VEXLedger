# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Product and release aggregates."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.db.errors import NotFoundError
from vexledger.db.models import RELEASE_STATUSES, Product, Release
from vexledger.db.repos.audit import append_audit
from vexledger.domain.statements import ValidityPolicy


def validity_policy(product: Product) -> ValidityPolicy:
    return ValidityPolicy(
        not_affected_days=product.validity_not_affected_days,
        under_investigation_days=product.validity_under_investigation_days,
        affected_days=product.validity_affected_days,
        fixed_days=product.validity_fixed_days,
    )


class ProductRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        slug: str,
        name: str,
        purl: str,
        vex_author: str,
        actor_id: uuid.UUID | None,
        inherit_enabled: bool = True,
    ) -> Product:
        product = Product(
            slug=slug, name=name, purl=purl, vex_author=vex_author, inherit_enabled=inherit_enabled
        )
        self.session.add(product)
        await self.session.flush()
        append_audit(
            self.session,
            actor_id=actor_id,
            action="product.create",
            entity_type="product",
            entity_id=str(product.id),
            after={"slug": slug, "vex_author": vex_author, "inherit_enabled": inherit_enabled},
        )
        return product

    async def get_by_slug(self, slug: str) -> Product:
        product = (
            await self.session.execute(select(Product).where(Product.slug == slug))
        ).scalar_one_or_none()
        if product is None:
            raise NotFoundError(f"product {slug!r} not found")
        return product


class ReleaseRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self, *, product_id: uuid.UUID, version: str, actor_id: uuid.UUID | None
    ) -> Release:
        """Assign the next ordering under a product row lock (no concurrent collisions)."""
        await self.session.execute(
            select(Product.id).where(Product.id == product_id).with_for_update()
        )
        next_ordering = (
            await self.session.execute(
                select(func.coalesce(func.max(Release.ordering), 0) + 1).where(
                    Release.product_id == product_id
                )
            )
        ).scalar_one()
        release = Release(product_id=product_id, version=version, ordering=next_ordering)
        self.session.add(release)
        await self.session.flush()
        append_audit(
            self.session,
            actor_id=actor_id,
            action="release.create",
            entity_type="release",
            entity_id=str(release.id),
            after={"product_id": str(product_id), "version": version, "ordering": next_ordering},
        )
        return release

    async def previous(self, release: Release) -> Release | None:
        """The newest release of the same product that is older by ordering."""
        result = await self.session.execute(
            select(Release)
            .where(Release.product_id == release.product_id, Release.ordering < release.ordering)
            .order_by(Release.ordering.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def set_status(
        self,
        release_id: uuid.UUID,
        status: str,
        *,
        error: str | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> None:
        if status not in RELEASE_STATUSES:
            raise ValueError(f"unknown release status {status!r}")
        release = await self.session.get(Release, release_id, with_for_update=True)
        if release is None:
            raise NotFoundError(f"release {release_id} not found")
        before = {"status": release.status}
        release.status = status
        release.match_error = error
        append_audit(
            self.session,
            actor_id=actor_id,
            action="release.status",
            entity_type="release",
            entity_id=str(release_id),
            before=before,
            after={"status": status, "error": error},
        )
