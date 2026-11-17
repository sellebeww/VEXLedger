# Copyright (c) 2026 Vassel Goleyu. MIT License.
import logging

import pytest

from vexledger.services.metrics import Metrics


def test_counters_and_duration_summary() -> None:
    m = Metrics()
    m.inc("osv_queries", 3)
    m.inc("osv_queries")
    m.observe("match_duration", 0.5)
    m.observe("match_duration", 1.5)
    snap = m.snapshot()
    assert snap["osv_queries"] == 4
    assert snap["match_duration_count"] == 2
    assert snap["match_duration_seconds_sum"] == 2.0
    assert snap["match_duration_seconds_max"] == 1.5


def test_log_emits_one_structured_record(caplog: pytest.LogCaptureFixture) -> None:
    m = Metrics()
    m.inc("osv_retries")
    with caplog.at_level(logging.INFO, logger="vexledger.metrics"):
        m.log("match completed", release_id="r1")
    (record,) = caplog.records
    assert record.extra_fields["release_id"] == "r1"  # type: ignore[attr-defined]
    assert record.extra_fields["metrics"]["osv_retries"] == 1  # type: ignore[attr-defined]
