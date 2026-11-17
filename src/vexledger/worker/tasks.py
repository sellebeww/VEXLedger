# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Arq tasks: matching, periodic resync and the expiry report."""

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from arq import Retry
from arq.connections import ArqRedis, RedisSettings, create_pool
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import aliased

from vexledger.config import Settings, get_settings
from vexledger.db.models import Release, Sbom, VexStatement
from vexledger.db.session import make_engine, make_session_factory
from vexledger.demo.osv_fixtures import DemoOsvTransport
from vexledger.osv.client import OsvClient, default_timeout
from vexledger.osv.errors import OsvUnavailableError
from vexledger.services.matching import ReleaseNotReadyError, match_release
from vexledger.services.metrics import Metrics

_log = logging.getLogger("vexledger.worker")
MATCH_JOB = "match_release"
MAX_RETRY_DEFER_S = 3600


def retry_defer_seconds(job_try: int) -> int:
    """Backoff between match attempts: 1, 2, 4, ... minutes, capped at an hour."""
    return int(min(60 * 2 ** max(job_try - 1, 0), MAX_RETRY_DEFER_S))


async def create_queue(settings: Settings) -> ArqRedis:
    return await create_pool(RedisSettings.from_dsn(settings.redis_url))


async def enqueue_match(pool: ArqRedis, release_id: uuid.UUID) -> bool:
    """Queue a match unless one for this release is already queued or running."""
    job = await pool.enqueue_job(MATCH_JOB, str(release_id), _job_id=f"match-{release_id}")
    return job is not None


async def startup(ctx: dict[str, Any]) -> None:
    settings = get_settings()
    engine = make_engine(settings.database_url)
    metrics = Metrics()
    http = httpx.AsyncClient(
        transport=DemoOsvTransport() if settings.demo_osv_fixtures else None,
        http2=settings.osv_http2 and not settings.demo_osv_fixtures,
        timeout=default_timeout(settings.osv_connect_timeout_s, settings.osv_read_timeout_s),
    )
    ctx.update(
        settings=settings,
        engine=engine,
        factory=make_session_factory(engine),
        metrics=metrics,
        http=http,
        osv=OsvClient(
            settings.osv_base_url,
            client=http,
            max_retries=settings.osv_max_retries,
            concurrency=settings.osv_concurrency,
            metrics=metrics,
        ),
        clock=lambda: datetime.now(UTC),
    )


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["http"].aclose()
    await ctx["engine"].dispose()


async def match_release_job(ctx: dict[str, Any], release_id: str) -> dict[str, Any]:
    """Match one release. Transient OSV trouble reschedules the job with backoff."""
    settings: Settings = ctx["settings"]
    clock: Callable[[], datetime] = ctx["clock"]
    try:
        summary = await match_release(
            ctx["factory"],
            ctx["osv"],
            uuid.UUID(release_id),
            now=clock(),
            metrics=ctx["metrics"],
            cache_ttl=_ttl(settings),
        )
    except ReleaseNotReadyError:
        return {"status": "skipped", "reason": "no SBOM imported"}
    except OsvUnavailableError:
        job_try: int = ctx.get("job_try", 1)
        if job_try < settings.match_max_tries:
            # The release is already MATCH_FAILED with the reason; the retry resets it to PENDING.
            raise Retry(defer=retry_defer_seconds(job_try)) from None
        raise
    return {
        "status": "matched",
        "findings_created": summary.findings_created,
        "notes": len(summary.notes),
    }


def _ttl(settings: Settings) -> timedelta:
    return timedelta(hours=settings.osv_cache_ttl_hours)


async def latest_release_ids(factory: async_sessionmaker[AsyncSession]) -> list[uuid.UUID]:
    """The newest release (by ordering) of each product that has an SBOM."""
    async with factory() as session:
        rows = await session.execute(
            select(Release.id)
            .join(Sbom, Sbom.release_id == Release.id)
            .distinct(Release.product_id)
            .order_by(Release.product_id, Release.ordering.desc())
        )
        return list(rows.scalars())


async def resync_latest_releases(ctx: dict[str, Any]) -> int:
    """Every 6 hours: queue a re-match of each product's latest release.

    Also retries releases left MATCH_FAILED or MATCH_PENDING. New vulnerabilities become new
    UNTRIAGED findings through the normal idempotent match.
    """
    pool: ArqRedis = ctx["redis"]
    queued = 0
    for release_id in await latest_release_ids(ctx["factory"]):
        queued += await enqueue_match(pool, release_id)
    _log.info("resync queued", extra={"extra_fields": {"releases": queued}})
    return queued


async def count_expired_statements(factory: async_sessionmaker[AsyncSession], now: datetime) -> int:
    """Newest statements of their chains whose valid_until has passed (state EXPIRED is derived)."""
    successor = aliased(VexStatement)
    async with factory() as session:
        return (
            await session.execute(
                select(func.count())
                .select_from(VexStatement)
                .where(
                    VexStatement.valid_until.is_not(None),
                    VexStatement.valid_until <= now,
                    ~exists().where(successor.supersedes_id == VexStatement.id),
                )
            )
        ).scalar_one()


async def expire_statements(ctx: dict[str, Any]) -> int:
    """Hourly: report how many statements are expired. It writes nothing to statements."""
    count = await count_expired_statements(ctx["factory"], ctx["clock"]())
    ctx["metrics"].counters["statements_expired"] = count  # a gauge: the current number
    ctx["metrics"].log("expiry report", expired_statements=count)
    return count
