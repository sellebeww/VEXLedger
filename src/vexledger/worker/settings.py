# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Arq worker definition. Run with: python -m vexledger.worker"""

from typing import Any, ClassVar

from arq import cron
from arq.connections import RedisSettings
from arq.worker import func

from vexledger.config import get_settings
from vexledger.worker.tasks import (
    MATCH_JOB,
    expire_statements,
    match_release_job,
    resync_latest_releases,
    shutdown,
    startup,
)

_settings = get_settings()


class WorkerSettings:
    functions: ClassVar[list[Any]] = [func(match_release_job, name=MATCH_JOB)]
    cron_jobs: ClassVar[list[Any]] = [
        cron(resync_latest_releases, hour={0, 6, 12, 18}, minute=0, run_at_startup=False),
        cron(expire_statements, minute=0, run_at_startup=False),
    ]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(_settings.redis_url)
    max_tries = _settings.match_max_tries
    job_timeout = _settings.worker_job_timeout_s
    keep_result = 0  # job state lives in the database; a finished job id may be queued again
    max_jobs = 4
    health_check_interval = 30  # heartbeat in Redis, read by `python -m vexledger.worker --check`
