# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Persist a parsed SBOM for a release, idempotently."""

import asyncio
import hashlib
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vexledger.db.errors import ConflictError, NotFoundError
from vexledger.db.models import Component, ComponentEdge, Release, Sbom
from vexledger.db.repos.audit import append_audit
from vexledger.services.sbom import (
    MAX_STORED_WARNINGS,
    ParsedSbom,
    SbomLimits,
    SbomTooLargeError,
    parse_sbom,
)


@dataclass(frozen=True)
class ImportResult:
    sbom_id: uuid.UUID
    created: bool  # False: the same SBOM was already imported for this release
    sha256: str
    spec_version: str | None
    size_bytes: int
    component_count: int
    edge_count: int
    root_present: bool
    no_purl_count: int
    unsupported_ecosystem_count: int
    warnings: tuple[dict[str, Any], ...]
    warning_summary: dict[str, int]  # code -> count, shown to the user


def _stored_warnings(parsed: ParsedSbom) -> list[dict[str, Any]]:
    items = [
        {"code": w.code, "message": w.message[:300], "ref": w.ref}
        for w in parsed.warnings[:MAX_STORED_WARNINGS]
    ]
    omitted = len(parsed.warnings) - len(items)
    if omitted > 0:
        items.append(
            {
                "code": "warnings_truncated",
                "message": f"{omitted} more warnings omitted",
                "ref": None,
            }
        )
    return items


async def _result(session: AsyncSession, sbom: Sbom, *, created: bool) -> ImportResult:
    counts = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(Component.no_purl),
                func.count().filter(Component.unsupported_ecosystem),
                func.count().filter(Component.is_root),
            ).where(Component.release_id == sbom.release_id)
        )
    ).one()
    edges = (
        await session.execute(
            select(func.count())
            .select_from(ComponentEdge)
            .where(ComponentEdge.release_id == sbom.release_id)
        )
    ).scalar_one()
    summary = Counter(w["code"] for w in sbom.import_warnings)
    return ImportResult(
        sbom_id=sbom.id,
        created=created,
        sha256=sbom.sha256,
        spec_version=sbom.spec_version,
        size_bytes=sbom.size_bytes,
        component_count=counts[0],
        edge_count=edges,
        root_present=counts[3] > 0,
        no_purl_count=counts[1],
        unsupported_ecosystem_count=counts[2],
        warnings=tuple(sbom.import_warnings),
        warning_summary=dict(summary),
    )


async def _existing(session: AsyncSession, release_id: uuid.UUID) -> Sbom | None:
    return (
        await session.execute(select(Sbom).where(Sbom.release_id == release_id))
    ).scalar_one_or_none()


async def import_sbom(
    factory: async_sessionmaker[AsyncSession],
    *,
    release_id: uuid.UUID,
    data: bytes,
    actor_id: uuid.UUID | None,
    limits: SbomLimits = SbomLimits(),  # noqa: B008
) -> ImportResult:
    """Validate, flatten and store an SBOM. Same bytes again: the existing result, no writes.

    A different SBOM for a release that already has one is a conflict: a new SBOM is a new
    release. Raises SbomError subclasses for bad input, NotFoundError, ConflictError.
    """
    if len(data) > limits.max_bytes:
        raise SbomTooLargeError(f"SBOM exceeds {limits.max_bytes} bytes")
    sha = hashlib.sha256(data).hexdigest()

    async with factory() as session:
        if await session.get(Release, release_id) is None:
            raise NotFoundError(f"release {release_id} not found")
        if (found := await _existing(session, release_id)) is not None:
            if found.sha256 == sha:
                return await _result(session, found, created=False)
            raise ConflictError("this release already has a different SBOM; create a new release")

    # Parsing and schema validation are CPU-bound: keep them off the event loop.
    parsed = await asyncio.to_thread(parse_sbom, data, limits)

    async with factory() as session, session.begin():
        await session.execute(select(Release.id).where(Release.id == release_id).with_for_update())
        if (found := await _existing(session, release_id)) is not None:  # raced with another import
            if found.sha256 == sha:
                return await _result(session, found, created=False)
            raise ConflictError("this release already has a different SBOM; create a new release")
        sbom = Sbom(
            release_id=release_id,
            sha256=parsed.sha256,
            size_bytes=parsed.size_bytes,
            spec_version=parsed.spec_version,
            raw=parsed.document,
            import_warnings=_stored_warnings(parsed),
            uploaded_by=actor_id,
        )
        session.add(sbom)
        ids = {c.index: uuid.uuid4() for c in parsed.components}
        if parsed.components:
            await session.execute(
                insert(Component),
                [
                    {
                        "id": ids[c.index],
                        "release_id": release_id,
                        "bom_ref": c.bom_refs[0] if c.bom_refs else None,
                        "name": c.name,
                        "version": c.version,
                        "purl_original": c.purl_original,
                        "purl_normal": c.purl_normal,
                        "component_key": c.component_key,
                        "component_ref": c.component_ref,
                        "ecosystem": c.ecosystem,
                        "component_hash": c.component_hash,
                        "no_purl": c.no_purl,
                        "unsupported_ecosystem": c.unsupported_ecosystem,
                        "is_root": c.is_root,
                    }
                    for c in parsed.components
                ],
            )
        if parsed.edges:
            await session.execute(
                insert(ComponentEdge),
                [
                    {"parent_id": ids[p], "child_id": ids[c], "release_id": release_id}
                    for p, c in parsed.edges
                ],
            )
        await session.flush()
        append_audit(
            session,
            actor_id=actor_id,
            action="sbom.import",
            entity_type="release",
            entity_id=str(release_id),
            after={
                "sha256": parsed.sha256,
                "spec_version": parsed.spec_version,
                "components": len(parsed.components),
                "edges": len(parsed.edges),
                "warnings": len(parsed.warnings),
            },
        )
        await session.flush()
        return await _result(session, sbom, created=True)


async def stored_import_result(session: AsyncSession, sbom: Sbom) -> ImportResult:
    """The import summary of an SBOM that is already stored (for release detail)."""
    return await _result(session, sbom, created=False)
