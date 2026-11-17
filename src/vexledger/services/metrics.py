# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Minimal in-process counters, reported through structured logs (no /metrics endpoint yet)."""

import logging
from collections import Counter
from typing import Any

_log = logging.getLogger("vexledger.metrics")


class Metrics:
    """Counters plus a duration summary. Not thread-safe, which is fine for one event loop."""

    def __init__(self) -> None:
        self.counters: Counter[str] = Counter()
        self.durations: dict[str, list[float]] = {}

    def inc(self, name: str, amount: int = 1) -> None:
        self.counters[name] += amount

    def observe(self, name: str, seconds: float) -> None:
        self.durations.setdefault(name, []).append(seconds)

    def snapshot(self) -> dict[str, Any]:
        out: dict[str, Any] = dict(self.counters)
        for name, values in self.durations.items():
            out[f"{name}_count"] = len(values)
            out[f"{name}_seconds_sum"] = round(sum(values), 6)
            out[f"{name}_seconds_max"] = round(max(values), 6)
        return out

    def log(self, event: str, **fields: Any) -> None:
        _log.info(event, extra={"extra_fields": {**fields, "metrics": self.snapshot()}})
