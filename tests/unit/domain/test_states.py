# Copyright (c) 2026 Vassel Goleyu. MIT License.
from datetime import timedelta

import pytest

from vexledger.domain.model import FindingState as S
from vexledger.domain.model import Status
from vexledger.domain.states import derive_finding_state, gate_summary, is_open_for_gate

from .factories import NOW, finding, stmt, tf, with_

F = finding()
FR = finding(needs_review=True)


@pytest.mark.parametrize(
    ("f", "statement", "withdrawn", "expected"),
    [
        (F, None, False, S.UNTRIAGED),
        (FR, None, False, S.NEEDS_REVIEW),
        (F, stmt(valid_until=NOW + timedelta(days=1)), False, S.TRIAGED),
        (F, stmt(valid_until=None, status=Status.AFFECTED), False, S.TRIAGED),
        (F, stmt(valid_until=NOW - timedelta(days=1)), False, S.EXPIRED),
        (F, stmt(inherited_from_id="old", valid_until=NOW + timedelta(days=1)), False, S.INHERITED),
        (F, stmt(inherited_from_id="old", valid_until=NOW - timedelta(days=1)), False, S.EXPIRED),
        (F, None, True, S.WITHDRAWN),
        (F, stmt(), True, S.WITHDRAWN),
        (FR, stmt(), False, S.TRIAGED),  # a statement made after the review flag settles it
    ],
)
def test_state_table(f, statement, withdrawn, expected) -> None:  # type: ignore[no-untyped-def]
    assert derive_finding_state(f, statement, withdrawn, NOW) is expected


def test_expiry_exactly_at_the_boundary() -> None:
    s = stmt(valid_until=NOW)
    assert derive_finding_state(F, s, False, NOW) is S.EXPIRED
    assert derive_finding_state(F, s, False, NOW - timedelta(seconds=1)) is S.TRIAGED


def test_open_for_gate_matches_the_table() -> None:
    assert {s for s in S if is_open_for_gate(s)} == {S.UNTRIAGED, S.NEEDS_REVIEW, S.EXPIRED}


def test_gate_counts_open_and_reports_investigating_separately() -> None:
    soon = NOW + timedelta(days=5)
    rows = [
        tf(finding("CVE-1", "pypi/a@1")),  # UNTRIAGED
        tf(finding("CVE-2", "pypi/a@1", needs_review=True)),  # NEEDS_REVIEW
        tf(finding("CVE-3", "pypi/a@1"), stmt(valid_until=NOW)),  # EXPIRED
        tf(
            finding("CVE-4", "pypi/a@1"), stmt(status=Status.UNDER_INVESTIGATION, valid_until=soon)
        ),  # investigating
        tf(
            finding("CVE-5", "pypi/a@1"),
            stmt(status=Status.UNDER_INVESTIGATION, valid_until=soon, inherited_from_id="x"),
        ),
        tf(finding("CVE-6", "pypi/a@1"), stmt(valid_until=soon)),  # TRIAGED
        tf(
            finding("CVE-7", "pypi/a@1"), stmt(valid_until=soon, inherited_from_id="x")
        ),  # INHERITED
        tf(finding("CVE-8", "pypi/a@1"), None, withdrawn=True),
        tf(
            finding("CVE-9", "pypi/a@1"), stmt(status=Status.UNDER_INVESTIGATION, valid_until=NOW)
        ),  # expired investigation is open
    ]
    g = gate_summary(rows, NOW)
    assert (g.total, g.open_count, g.investigating_count) == (9, 4, 2)
    assert g.open_ids == (
        ("CVE-1", "pypi/a@1"),
        ("CVE-2", "pypi/a@1"),
        ("CVE-3", "pypi/a@1"),
        ("CVE-9", "pypi/a@1"),
    )
    assert not g.complete


def test_gate_is_complete_with_only_investigating_findings() -> None:
    row = tf(F, stmt(status=Status.UNDER_INVESTIGATION, valid_until=NOW + timedelta(days=1)))
    g = gate_summary([row], NOW)
    assert g.complete
    assert g.investigating_count == 1


def test_empty_gate_is_complete() -> None:
    assert gate_summary([], NOW).complete


def test_with_helper_is_available() -> None:
    assert with_(stmt(), id="z").id == "z"
