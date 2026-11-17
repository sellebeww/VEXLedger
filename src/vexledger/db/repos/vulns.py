# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""OSV record cache and the purl query cache."""

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.db.models import PurlQueryCache, Vulnerability
from vexledger.domain.osv_model import parse_record

DEFAULT_CACHE_TTL = timedelta(hours=6)


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


class VulnerabilityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert(self, raw: Mapping[str, Any], fetched_at: datetime) -> None:
        """Store a record unless a newer `modified` is already cached."""
        record = parse_record(raw)
        if record.modified is None:
            raise ValueError(f"OSV record {record.id} has no modified timestamp")
        values = {
            "osv_id": record.id,
            "modified": _parse_ts(record.modified),
            "aliases": list(record.aliases),
            "severity": {
                "entries": [list(e) for e in record.severity.entries],
                "database_specific": record.severity.database_specific,
            },
            "withdrawn": _parse_ts(record.withdrawn) if record.withdrawn else None,
            "raw": dict(raw),
            "fetched_at": fetched_at,
        }
        stmt = insert(Vulnerability).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[Vulnerability.osv_id],
            set_={k: v for k, v in values.items() if k != "osv_id"},
            where=Vulnerability.modified <= stmt.excluded.modified,
        )
        await self.session.execute(stmt)

    async def get_many(self, osv_ids: Sequence[str]) -> list[Vulnerability]:
        result = await self.session.execute(
            select(Vulnerability)
            .where(Vulnerability.osv_id.in_(osv_ids))
            .order_by(Vulnerability.osv_id)
        )
        return list(result.scalars())

    async def cache_put(self, purl: str, osv_ids: Sequence[str], fetched_at: datetime) -> None:
        stmt = insert(PurlQueryCache).values(
            purl=purl, osv_ids=sorted(set(osv_ids)), fetched_at=fetched_at
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[PurlQueryCache.purl],
            set_={"osv_ids": stmt.excluded.osv_ids, "fetched_at": stmt.excluded.fetched_at},
        )
        await self.session.execute(stmt)

    async def cache_get_fresh(
        self, purls: Sequence[str], now: datetime, ttl: timedelta = DEFAULT_CACHE_TTL
    ) -> dict[str, list[str]]:
        """Cached answers younger than the TTL; purls missing from the result must be queried."""
        result = await self.session.execute(
            select(PurlQueryCache).where(
                PurlQueryCache.purl.in_(purls), PurlQueryCache.fetched_at > now - ttl
            )
        )
        return {row.purl: list(row.osv_ids) for row in result.scalars()}
