# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Export history (one row per published document version)."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.db.models import Release, VexExport
from vexledger.db.repos.audit import append_audit
from vexledger.domain.openvex import LastExport


class ExportRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def last(self, release_id: uuid.UUID) -> LastExport | None:
        row = (
            await self.session.execute(
                select(VexExport)
                .where(VexExport.release_id == release_id)
                .order_by(VexExport.version.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        return None if row is None else LastExport(row.version, row.content_sha256, row.document)

    async def record(
        self,
        *,
        release_id: uuid.UUID,
        version: int,
        content_sha256: str,
        document: bytes,
        actor_id: uuid.UUID | None,
    ) -> VexExport:
        """Lock the release row so concurrent exports serialize; (release, version) is unique."""
        await self.session.execute(
            select(Release.id).where(Release.id == release_id).with_for_update()
        )
        export = VexExport(
            release_id=release_id,
            version=version,
            content_sha256=content_sha256,
            document=document,
            created_by=actor_id,
        )
        self.session.add(export)
        await self.session.flush()
        append_audit(
            self.session,
            actor_id=actor_id,
            action="export.create",
            entity_type="release",
            entity_id=str(release_id),
            after={"version": version, "content_sha256": content_sha256},
        )
        return export
