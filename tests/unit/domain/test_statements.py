# Copyright (c) 2026 Vassel Goleyu. MIT License.
from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from vexledger.domain.errors import (
    ChainError,
    ErrorCode,
    NaiveDatetimeError,
    StatementValidationError,
)
from vexledger.domain.model import Evidence, EvidenceKind, Justification, Status
from vexledger.domain.statements import (
    DEFAULT_POLICY,
    StatementDraft,
    ValidityPolicy,
    build_successor,
    default_valid_until,
    find_head,
    is_expired,
    validate_new_statement,
)

from .factories import LATER, NOTES, NOW, finding, stmt

J = Justification.VULNERABLE_CODE_NOT_PRESENT
NA, AF, FX, UI = Status.NOT_AFFECTED, Status.AFFECTED, Status.FIXED, Status.UNDER_INVESTIGATION
X20 = "x" * 20
X10 = "y" * 10


def code_of(draft: StatementDraft, active=None, now: datetime = NOW) -> ErrorCode | None:  # type: ignore[no-untyped-def]
    try:
        validate_new_statement(active, draft, now)
    except StatementValidationError as exc:
        return exc.code
    return None


@pytest.mark.parametrize(
    ("draft", "expected"),
    [
        (StatementDraft(NA), ErrorCode.JUSTIFICATION_REQUIRED),
        (StatementDraft(NA, justification=J), ErrorCode.IMPACT_STATEMENT_REQUIRED),
        (
            StatementDraft(NA, justification=J, impact_statement="x" * 19),
            ErrorCode.IMPACT_STATEMENT_REQUIRED,
        ),
        (
            StatementDraft(NA, justification=J, impact_statement="x" * 19 + "   "),
            ErrorCode.IMPACT_STATEMENT_REQUIRED,
        ),
        (
            StatementDraft(NA, justification=J, impact_statement="   "),
            ErrorCode.IMPACT_STATEMENT_REQUIRED,
        ),
        (StatementDraft(NA, justification=J, impact_statement=X20), None),
        (StatementDraft(NA, justification=J, impact_statement="  " + X20 + "  "), None),
        (StatementDraft(AF), ErrorCode.ACTION_STATEMENT_REQUIRED),
        (StatementDraft(AF, action_statement="  "), ErrorCode.ACTION_STATEMENT_REQUIRED),
        (StatementDraft(AF, action_statement="Upgrade."), None),
        (StatementDraft(FX), ErrorCode.STATUS_NOTES_REQUIRED),
        (StatementDraft(FX, status_notes="y" * 9), ErrorCode.STATUS_NOTES_REQUIRED),
        (StatementDraft(FX, status_notes=X10), None),
        (StatementDraft(UI), None),
        (
            StatementDraft(AF, justification=J, action_statement="Upgrade."),
            ErrorCode.JUSTIFICATION_NOT_ALLOWED,
        ),
        (
            StatementDraft(FX, justification=J, status_notes=X10),
            ErrorCode.JUSTIFICATION_NOT_ALLOWED,
        ),
        (StatementDraft(UI, justification=J), ErrorCode.JUSTIFICATION_NOT_ALLOWED),
        (StatementDraft(UI, valid_until=NOW), ErrorCode.VALID_UNTIL_NOT_IN_FUTURE),
        (
            StatementDraft(UI, valid_until=NOW - timedelta(seconds=1)),
            ErrorCode.VALID_UNTIL_NOT_IN_FUTURE,
        ),
        (StatementDraft(UI, valid_until=NOW + timedelta(seconds=1)), None),
    ],
)
def test_validation_rules(draft: StatementDraft, expected: ErrorCode | None) -> None:
    assert code_of(draft) is expected


@pytest.mark.parametrize("justification", list(Justification))
def test_all_five_justifications_are_accepted(justification: Justification) -> None:
    assert len(list(Justification)) == 5
    assert code_of(StatementDraft(NA, justification=justification, impact_statement=X20)) is None


def test_status_and_justification_values_are_exact_openvex_strings() -> None:
    assert [s.value for s in Status] == ["not_affected", "affected", "fixed", "under_investigation"]
    assert {j.value for j in Justification} == {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }


@pytest.mark.parametrize(
    "evidence",
    [
        Evidence(EvidenceKind.LINK, "ftp://example.test/x"),
        Evidence(EvidenceKind.LINK, "javascript:alert(1)"),
        Evidence(EvidenceKind.LINK, "example.test/no-scheme"),
        Evidence(EvidenceKind.NOTE, "   "),
        Evidence(EvidenceKind.FILE, "abc.txt"),
        Evidence(EvidenceKind.FILE, "abc.txt", "NOTHEX" * 11),
        Evidence(EvidenceKind.FILE, "abc.txt", "a" * 63),
    ],
)
def test_invalid_evidence_is_rejected(evidence: Evidence) -> None:
    assert code_of(StatementDraft(UI, evidence=(evidence,))) is ErrorCode.EVIDENCE_INVALID


def test_valid_evidence_of_each_kind_is_accepted() -> None:
    ev = (
        Evidence(EvidenceKind.LINK, "https://example.test/analysis"),
        Evidence(EvidenceKind.LINK, "http://example.test/a"),
        Evidence(EvidenceKind.NOTE, "checked the call graph"),
        Evidence(EvidenceKind.FILE, "5f2a.pdf", "a" * 64),
    )
    assert code_of(StatementDraft(UI, evidence=ev)) is None


def test_naive_datetimes_are_rejected() -> None:
    with pytest.raises(NaiveDatetimeError):
        validate_new_statement(None, StatementDraft(UI), datetime(2030, 1, 1))
    with pytest.raises(NaiveDatetimeError):
        validate_new_statement(None, StatementDraft(UI, valid_until=datetime(2031, 1, 1)), NOW)


# no-op and extension


def _active():  # type: ignore[no-untyped-def]
    return stmt(status=NA, valid_until=NOW + timedelta(days=30), impact_statement=X20)


def _same_draft() -> StatementDraft:
    return StatementDraft(
        NA, justification=J, impact_statement=X20, valid_until=NOW + timedelta(days=30)
    )


def test_identical_draft_is_a_no_op() -> None:
    assert code_of(_same_draft(), _active()) is ErrorCode.NO_OP


@pytest.mark.parametrize(
    "url",
    [
        "http:/example.test",
        "HTTP://example.test",
        "https://",
        "https://exa mple.test",
        "//x.test",
        "ftp://x.test",
    ],
)
def test_links_must_be_absolute_lowercase_http_urls(url: str) -> None:
    d = StatementDraft(UI, evidence=(Evidence(EvidenceKind.LINK, url),))
    assert code_of(d) is ErrorCode.EVIDENCE_INVALID


def test_allow_identical_lets_a_confirmation_through_but_still_validates() -> None:
    validate_new_statement(_active(), _same_draft(), NOW, allow_identical=True)
    bad = replace(_same_draft(), impact_statement="short")
    with pytest.raises(StatementValidationError) as exc:
        validate_new_statement(_active(), bad, NOW, allow_identical=True)
    assert exc.value.code is ErrorCode.IMPACT_STATEMENT_REQUIRED


def test_whitespace_only_differences_are_still_a_no_op() -> None:
    d = replace(_same_draft(), impact_statement="  " + X20 + " ")
    assert code_of(d, _active()) is ErrorCode.NO_OP


def test_extending_valid_until_is_accepted() -> None:
    d = replace(_same_draft(), valid_until=NOW + timedelta(days=90))
    assert code_of(d, _active()) is None


@pytest.mark.parametrize(
    "change",
    [
        {"justification": Justification.COMPONENT_NOT_PRESENT},
        {"impact_statement": "z" * 25},
        {"status_notes": "some notes here"},
        {"evidence": (Evidence(EvidenceKind.NOTE, "new evidence"),)},
    ],
)
def test_any_content_change_is_accepted(change: dict[str, object]) -> None:
    assert code_of(replace(_same_draft(), **change), _active()) is None


def test_a_different_status_is_accepted() -> None:
    assert code_of(StatementDraft(AF, action_statement="Upgrade."), _active()) is None


def test_default_validity_makes_a_resubmission_a_confirmation_not_a_no_op() -> None:
    first = build_successor(
        finding(),
        None,
        StatementDraft(NA, justification=J, impact_statement=X20),
        NOW,
        new_id="a",
        created_by="u",
    )
    again = StatementDraft(NA, justification=J, impact_statement=X20)
    assert code_of(again, first, NOW + timedelta(days=1)) is None  # new default expiry differs
    assert code_of(again, first, NOW) is ErrorCode.NO_OP  # same instant: truly identical


def test_an_expired_current_statement_never_blocks_a_resubmission() -> None:
    expired = stmt(valid_until=NOW - timedelta(days=1), impact_statement=X20)
    d = StatementDraft(NA, justification=J, impact_statement=X20, valid_until=expired.valid_until)
    assert code_of(replace(d, valid_until=None), expired) is None


# expiry and defaults


def test_expiry_boundary_is_inclusive_of_the_instant() -> None:
    s = stmt(valid_until=NOW)
    assert is_expired(s, NOW)
    assert not is_expired(s, NOW - timedelta(microseconds=1))
    assert is_expired(s, NOW + timedelta(microseconds=1))


def test_statements_without_valid_until_never_expire() -> None:
    assert not is_expired(stmt(status=AF, valid_until=None), NOW + timedelta(days=36500))


def test_default_validity_per_status_and_per_product_policy() -> None:
    assert default_valid_until(NA, NOW) == NOW + timedelta(days=180)
    assert default_valid_until(UI, NOW) == NOW + timedelta(days=14)
    assert default_valid_until(AF, NOW) is None
    assert default_valid_until(FX, NOW) is None
    custom = ValidityPolicy(
        not_affected_days=30, under_investigation_days=None, affected_days=7, fixed_days=1
    )
    assert default_valid_until(NA, NOW, custom) == NOW + timedelta(days=30)
    assert default_valid_until(UI, NOW, custom) is None
    assert default_valid_until(AF, NOW, custom) == NOW + timedelta(days=7)
    assert default_valid_until(FX, NOW, custom) == NOW + timedelta(days=1)
    assert DEFAULT_POLICY.not_affected_days == 180


# successor and chain


def test_build_successor_sets_supersedes_and_defaults() -> None:
    f = finding()
    first = build_successor(f, None, StatementDraft(UI), NOW, new_id="s1", created_by="ann")
    assert first.supersedes_id is None
    assert first.valid_until == NOW + timedelta(days=14)
    assert (first.canonical_vuln_id, first.component_ref, first.created_by) == (
        f.canonical_vuln_id,
        f.component_ref,
        "ann",
    )
    second = build_successor(
        f, first, StatementDraft(FX, status_notes=NOTES), LATER, new_id="s2", created_by="bob"
    )
    assert second.supersedes_id == "s1"
    assert second.valid_until is None
    assert second.inherited_from_id is None


def test_successor_of_an_expired_statement_still_supersedes_it() -> None:
    f = finding()
    old = stmt(sid="old", status=UI, valid_until=NOW + timedelta(days=1))
    new = build_successor(
        f, old, StatementDraft(UI), NOW + timedelta(days=2), new_id="n", created_by="u"
    )
    assert new.supersedes_id == "old"


def test_successor_trims_text_and_orders_evidence_stably() -> None:
    ev = (
        Evidence(EvidenceKind.NOTE, "b note"),
        Evidence(EvidenceKind.LINK, "https://example.test/a"),
    )
    s = build_successor(
        finding(),
        None,
        StatementDraft(NA, justification=J, impact_statement="  " + X20 + "  ", evidence=ev),
        NOW,
        new_id="a",
        created_by="u",
    )
    assert s.impact_statement == X20
    assert (
        s.evidence
        == build_successor(
            finding(),
            None,
            StatementDraft(NA, justification=J, impact_statement=X20, evidence=ev[::-1]),
            NOW,
            new_id="a",
            created_by="u",
        ).evidence
    )


def test_invalid_draft_does_not_build() -> None:
    with pytest.raises(StatementValidationError) as exc:
        build_successor(finding(), None, StatementDraft(NA), NOW, new_id="a", created_by="u")
    assert exc.value.code is ErrorCode.JUSTIFICATION_REQUIRED
    assert exc.value.field == "justification"


def test_chain_of_three_has_a_single_head() -> None:
    a, b, c = stmt("a"), stmt("b", supersedes_id="a"), stmt("c", supersedes_id="b")
    assert find_head([c, a, b]) == c
    assert find_head([a]) == a
    assert find_head([]) is None


@pytest.mark.parametrize(
    "rows",
    [
        [stmt("a"), stmt("a")],  # duplicate id
        [stmt("a"), stmt("b", supersedes_id="zzz")],  # dangling
        [stmt("a"), stmt("b", supersedes_id="a"), stmt("c", supersedes_id="a")],  # fork
        [stmt("a", supersedes_id="b"), stmt("b", supersedes_id="a")],  # pure cycle
        [
            stmt("a"),
            stmt("b", supersedes_id="a"),
            stmt("x", supersedes_id="y"),
            stmt("y", supersedes_id="x"),
        ],  # cycle beside a chain
        [stmt("a"), stmt("b")],  # two heads
        [stmt("a", supersedes_id="a")],  # self loop
    ],
)
def test_broken_chains_raise(rows) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ChainError):
        find_head(rows)
