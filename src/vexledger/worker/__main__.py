# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Starts the Arq worker: `python -m vexledger.worker` (Docker image and demo stack).

Why not the `arq` command: `arq` 0.25 calls `asyncio.get_event_loop()` at start-up, which raises
on Python 3.14 when no loop exists yet. Creating the loop first is enough.
`--check` is the container healthcheck: exit 0 when the worker's heartbeat in Redis is fresh.
"""

import asyncio
import sys

from arq import run_worker
from arq.worker import check_health

from vexledger.worker.settings import WorkerSettings

if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        raise SystemExit(check_health(WorkerSettings))  # type: ignore[arg-type]
    asyncio.set_event_loop(asyncio.new_event_loop())
    run_worker(WorkerSettings)  # type: ignore[arg-type]
