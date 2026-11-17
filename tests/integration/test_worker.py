# Copyright (c) 2026 Vassel Goleyu. MIT License.
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from arq import Retry
from arq.connections import RedisSettings
from arq.worker import Worker, func
from sqlalchemy import func as sqlfunc
from sqlalchemy import select

from vexledger.config import Settings
from vexledger.db.models import VexStatement
from vexledger.db.repos.findings import FindingRepository
from vexledger.db.repos.statements import create_successor_statement
from vexledger.domain.model import Status
from vexledger.domain.statements import StatementDraft
from vexledger.osv.errors import OsvPermanentError, OsvUnavailableError
from vexledger.services.metrics import Metrics
from vexledger.worker import tasks
from vexledger.worker.settings import WorkerSettings
from vexledger.worker.tasks import (
    count_expired_statements,
    enqueue_match,
    expire_statements,
    latest_release_ids,
    match_release_job,
    resync_latest_releases,
    retry_defer_seconds,
    shutdown,
    startup,
)

from .pipeline_helpers import components, create_release, import_components, serve_standard
from .seed import NOW, seed_finding, seed_release

pytestmark = pytest.mark.integration


def ctx_for(factory: Any, osv: Any = None, job_try: int = 1, max_tries: int = 3) -> dict[str, Any]:
    return {
        "factory": factory,
        "osv": osv,
        "metrics": Metrics(),
        "settings": Settings(env="test", match_max_tries=max_tries),
        "clock": lambda: NOW,
        "job_try": job_try,
    }


def test_retry_backoff_grows_and_is_capped() -> None:
    assert [retry_defer_seconds(n) for n in (1, 2, 3, 4)] == [60, 120, 240, 480]
    assert retry_defer_seconds(50) == 3600
    assert retry_defer_seconds(0) == 60


def test_worker_settings_declare_the_jobs_and_schedules() -> None:
    assert [f.name for f in WorkerSettings.functions] == ["match_release"]
    crons = {c.name: c for c in WorkerSettings.cron_jobs}
    assert crons["cron:resync_latest_releases"].hour == {0, 6, 12, 18}  # every 6 hours
    assert crons["cron:resync_latest_releases"].minute == 0
    assert crons["cron:expire_statements"].hour is None  # every hour
    assert crons["cron:expire_statements"].minute == 0
    assert (
        WorkerSettings.keep_result == 0 and WorkerSettings.max_tries == Settings().match_max_tries
    )


async def test_match_job_success_and_skip(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    ctx = ctx_for(factory, osv)
    assert await match_release_job(ctx, str(release.id)) == {
        "status": "skipped",
        "reason": "no SBOM imported",
    }
    await import_components(factory, release, components())
    serve_standard(fake)
    result = await match_release_job(ctx, str(release.id))
    assert result["status"] == "matched" and result["findings_created"] == 6


async def test_transient_osv_failure_reschedules_with_backoff_then_gives_up(
    factory, fake, osv
) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    await import_components(factory, release, components())
    fake.down = True
    with pytest.raises(Retry) as retry:
        await match_release_job(ctx_for(factory, osv, job_try=1), str(release.id))
    assert retry.value.defer_score == 60_000  # arq stores the delay in milliseconds
    with pytest.raises(Retry) as second:
        await match_release_job(ctx_for(factory, osv, job_try=2), str(release.id))
    assert second.value.defer_score == 120_000
    with pytest.raises(
        OsvUnavailableError
    ):  # last allowed try: the error stands, release stays MATCH_FAILED
        await match_release_job(ctx_for(factory, osv, job_try=3), str(release.id))


async def test_permanent_osv_error_is_not_retried(factory, router, osv) -> None:  # type: ignore[no-untyped-def]
    import httpx

    from .osv_fake import BASE

    _, release = await create_release(factory)
    await import_components(factory, release, components())
    router.post(BASE + "/v1/querybatch").mock(return_value=httpx.Response(400))
    with pytest.raises(OsvPermanentError):
        await match_release_job(ctx_for(factory, osv), str(release.id))


async def test_latest_release_per_product_with_an_sbom(factory) -> None:  # type: ignore[no-untyped-def]
    p1, r1a = await create_release(factory)
    _, r1b = await create_release(factory, p1, "2.0.0")
    _, r1c = await create_release(factory, p1, "3.0.0")  # newest, but no SBOM yet
    _, other = await create_release(factory)  # another product
    for r in (r1a, r1b, other):
        await import_components(factory, r, components())
    ids = set(await latest_release_ids(factory))
    assert r1b.id in ids and other.id in ids
    assert r1a.id not in ids and r1c.id not in ids


class FakePool:
    def __init__(self) -> None:
        self.jobs: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    async def enqueue_job(self, name: str, *args: Any, **kw: Any) -> object | None:
        if any(j[2].get("_job_id") == kw.get("_job_id") for j in self.jobs):
            return None
        self.jobs.append((name, args, kw))
        return object()


async def test_resync_queues_each_latest_release_once(factory) -> None:  # type: ignore[no-untyped-def]
    p, r1 = await create_release(factory)
    _, r2 = await create_release(factory, p, "2.0.0")
    for r in (r1, r2):
        await import_components(factory, r, components())
    pool = FakePool()
    ctx = ctx_for(factory)
    ctx["redis"] = pool
    first = await resync_latest_releases(ctx)
    again = await resync_latest_releases(ctx)  # a job with the same id is already queued
    assert first >= 1 and again == 0
    mine = [j for j in pool.jobs if j[1] == (str(r2.id),)]
    assert mine and mine[0][0] == "match_release" and mine[0][2]["_job_id"] == f"match-{r2.id}"
    assert not [j for j in pool.jobs if j[1] == (str(r1.id),)]


async def test_enqueue_match_against_a_real_redis(settings: Settings) -> None:
    from arq.connections import create_pool

    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    redis_settings.database = 15  # a scratch database, never the application's queue
    pool = await create_pool(redis_settings)
    try:
        release_id = uuid.uuid4()
        assert await enqueue_match(pool, release_id) is True
        assert await enqueue_match(pool, release_id) is False  # already queued
    finally:
        await pool.flushdb()
        await pool.aclose()


async def test_arq_worker_loop_runs_with_the_installed_redis_client(settings: Settings) -> None:
    from arq.connections import create_pool

    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    redis_settings.database = 15
    seen: list[str] = []

    async def hello(ctx: dict[str, Any], who: str) -> str:
        seen.append(who)
        return who

    pool = await create_pool(redis_settings)
    try:
        await pool.enqueue_job("hello", "world")
        worker = Worker(
            functions=[func(hello, name="hello")],
            redis_settings=redis_settings,
            burst=True,
            poll_delay=0.1,
            keep_result=0,
            handle_signals=False,
        )
        await worker.main()
        await worker.close()
        assert seen == ["world"]
    finally:
        await pool.flushdb()
        await pool.aclose()


async def test_expiry_report_counts_only_expired_chain_heads_and_writes_nothing(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["a", "b", "c", "d"])
    now = NOW + timedelta(days=30)
    baseline = await count_expired_statements(factory, now)
    expired_head = await seed_finding(factory, seeded, "a")
    superseded = await seed_finding(factory, seeded, "b")
    live = await seed_finding(factory, seeded, "c")
    forever = await seed_finding(factory, seeded, "d")
    ui = StatementDraft(Status.UNDER_INVESTIGATION)  # 14 days
    for f in (expired_head, superseded):
        await create_successor_statement(
            factory,
            finding_id=f.id,
            draft=ui,
            expected_head_id=None,
            actor_id=None,
            actor_name="t",
            now=NOW,
        )
    async with factory() as s:
        first = await FindingRepository(s).triaged_for_release(seeded.release.id)
    head_b = next(
        t.statement
        for t in first
        if t.finding.canonical_vuln_id == superseded.canonical_vuln_id
        and t.finding.component_ref.startswith("pypi/b")
    )
    assert head_b is not None
    await create_successor_statement(
        factory,
        finding_id=superseded.id,
        draft=StatementDraft(Status.AFFECTED, action_statement="Upgrade."),
        expected_head_id=uuid.UUID(head_b.id),
        actor_id=None,
        actor_name="t",
        now=NOW + timedelta(days=1),
    )
    await create_successor_statement(
        factory,
        finding_id=live.id,
        draft=StatementDraft(Status.UNDER_INVESTIGATION, valid_until=NOW + timedelta(days=90)),
        expected_head_id=None,
        actor_id=None,
        actor_name="t",
        now=NOW,
    )
    await create_successor_statement(
        factory,
        finding_id=forever.id,
        draft=StatementDraft(Status.AFFECTED, action_statement="Upgrade."),
        expected_head_id=None,
        actor_id=None,
        actor_name="t",
        now=NOW,
    )
    async with factory() as s:
        before = (await s.execute(select(sqlfunc.count()).select_from(VexStatement))).scalar_one()
    assert (
        await count_expired_statements(factory, now) == baseline + 1
    )  # only the expired head of finding a
    ctx = ctx_for(factory)
    ctx["clock"] = lambda: now
    assert await expire_statements(ctx) == baseline + 1
    assert ctx["metrics"].counters["statements_expired"] == baseline + 1
    async with factory() as s:
        after = (await s.execute(select(sqlfunc.count()).select_from(VexStatement))).scalar_one()
    assert after == before  # report only: no statement row was written


async def test_startup_and_shutdown_manage_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    tasks.get_settings.cache_clear()
    ctx: dict[str, Any] = {}
    await startup(ctx)
    try:
        assert ctx["osv"] is not None and not ctx["http"].is_closed
        assert ctx["clock"]().tzinfo is UTC and ctx["clock"]() > datetime(2026, 1, 1, tzinfo=UTC)
    finally:
        await shutdown(ctx)
    assert ctx["http"].is_closed
