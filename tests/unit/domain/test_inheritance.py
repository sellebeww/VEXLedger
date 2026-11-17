# Copyright (c) 2026 Vassel Goleyu. MIT License.
from datetime import timedelta
from itertools import permutations

import pytest

from vexledger.domain.inheritance import (
    InheritAction,
    InheritancePolicy,
    flag_needs_review,
    inherited_statement,
    plan_inheritance,
)
from vexledger.domain.model import FindingState, Status
from vexledger.domain.osv_model import parse_record
from vexledger.domain.states import derive_finding_state
from vexledger.domain.vulns import group_records

from .factories import NOW, finding, stmt, tf

ON = InheritancePolicy(True)
OFF = InheritancePolicy(False)
NEXT = NOW + timedelta(days=10)


def test_identical_component_inherits_with_the_original_valid_until() -> None:
    old = stmt("old", valid_until=NOW + timedelta(days=20))
    (item,) = plan_inheritance([tf(finding(), old)], [finding()], ON, NEXT)
    assert item.action is InheritAction.INHERIT
    assert item.source == old
    assert item.valid_until == old.valid_until  # never extended
    new = inherited_statement(item, now=NEXT, new_id="n1", created_by="system")
    assert new.inherited_from_id == "old"
    assert new.valid_until == old.valid_until
    assert new.supersedes_id is None
    assert new.created_at == NEXT
    assert (new.status, new.justification, new.impact_statement) == (
        old.status,
        old.justification,
        old.impact_statement,
    )
    assert derive_finding_state(item.finding, new, False, NEXT) is FindingState.INHERITED


def test_version_change_needs_review_and_keeps_old_statement_as_context() -> None:
    old = stmt("old", ref="pypi/foo@1.0")
    (item,) = plan_inheritance(
        [tf(finding(ref="pypi/foo@1.0"), old)], [finding(ref="pypi/foo@1.1")], ON, NOW
    )
    assert item.action is InheritAction.NEEDS_REVIEW
    assert item.source == old
    assert item.valid_until is None
    assert item.reason == "component_version_changed"
    flagged = flag_needs_review(item)
    assert flagged.needs_review
    assert derive_finding_state(flagged, None, False, NOW) is FindingState.NEEDS_REVIEW


def test_hash_change_needs_review() -> None:
    old = stmt("old")
    prev = tf(finding(component_hash="aaa"), old)
    (item,) = plan_inheritance([prev], [finding(component_hash="bbb")], ON, NOW)
    assert (item.action, item.reason) == (InheritAction.NEEDS_REVIEW, "component_hash_changed")


@pytest.mark.parametrize(("old_hash", "new_hash"), [("aaa", None), (None, "aaa")])
def test_hash_present_on_one_side_only_counts_as_a_change(old_hash, new_hash) -> None:  # type: ignore[no-untyped-def]
    (item,) = plan_inheritance(
        [tf(finding(component_hash=old_hash), stmt("old"))],
        [finding(component_hash=new_hash)],
        ON,
        NOW,
    )
    assert item.action is InheritAction.NEEDS_REVIEW


def test_both_without_hash_inherit() -> None:
    (item,) = plan_inheritance([tf(finding(), stmt("old"))], [finding()], ON, NOW)
    assert item.action is InheritAction.INHERIT


def test_inherit_disabled_yields_none_even_for_identical_components() -> None:
    (item,) = plan_inheritance([tf(finding(), stmt("old"))], [finding()], OFF, NOW)
    assert (item.action, item.source, item.reason) == (InheritAction.NONE, None, "inherit_disabled")
    assert not flag_needs_review(item).needs_review


def test_expired_statements_are_not_inherited_and_not_review_material() -> None:
    old = stmt("old", valid_until=NEXT - timedelta(days=1))
    same = plan_inheritance([tf(finding(), old)], [finding()], ON, NEXT)[0]
    changed = plan_inheritance(
        [tf(finding(ref="pypi/foo@0.9"), old)], [finding(ref="pypi/foo@1.0")], ON, NEXT
    )[0]
    assert same.action is InheritAction.NONE
    assert changed.action is InheritAction.NONE
    assert same.reason == "no_active_statement"


def test_expiry_boundary_instant_is_not_inherited() -> None:
    old = stmt("old", valid_until=NEXT)
    assert (
        plan_inheritance([tf(finding(), old)], [finding()], ON, NEXT)[0].action
        is InheritAction.NONE
    )


def test_unrelated_findings_and_untriaged_previous_findings_yield_none() -> None:
    prev = [
        tf(finding("CVE-OTHER"), stmt("a", vuln="CVE-OTHER")),
        tf(finding("CVE-2099-0001"), None),
    ]
    (item,) = plan_inheritance(prev, [finding("CVE-2099-0001")], ON, NOW)
    assert item.action is InheritAction.NONE


def test_other_component_with_same_vulnerability_does_not_match() -> None:
    prev = [tf(finding(ref="pypi/bar@1.0"), stmt("a", ref="pypi/bar@1.0"))]
    assert (
        plan_inheritance(prev, [finding(ref="pypi/foo@1.0")], ON, NOW)[0].action
        is InheritAction.NONE
    )


def test_withdrawn_previous_finding_is_ignored() -> None:
    assert (
        plan_inheritance([tf(finding(), stmt("a"), withdrawn=True)], [finding()], ON, NOW)[0].action
        is InheritAction.NONE
    )


def test_inherited_statement_chains_onward() -> None:
    first = stmt("old", valid_until=NOW + timedelta(days=100))
    second = inherited_statement(
        plan_inheritance([tf(finding(), first)], [finding()], ON, NOW)[0],
        now=NOW,
        new_id="n1",
        created_by="system",
    )
    third = plan_inheritance([tf(finding(), second)], [finding()], ON, NEXT)[0]
    assert third.action is InheritAction.INHERIT
    assert third.valid_until == first.valid_until


def test_materializing_a_non_inherit_item_is_refused() -> None:
    item = plan_inheritance([], [finding()], ON, NOW)[0]
    with pytest.raises(ValueError, match="only INHERIT"):
        inherited_statement(item, now=NOW, new_id="x", created_by="s")


def test_same_vulnerability_from_different_records_matches_through_canonical_id() -> None:
    old_rec = parse_record({"id": "GHSA-x", "aliases": ["CVE-2099-5"]})
    new_recs = [
        parse_record({"id": "CVE-2099-5", "aliases": ["GHSA-x"]}),
        parse_record({"id": "GHSA-x", "aliases": ["CVE-2099-5"]}),
    ]
    old_g, new_g = group_records([old_rec])[0], group_records(new_recs)[0]
    assert old_g.canonical_id == new_g.canonical_id == "CVE-2099-5"
    f_old = finding(old_g.canonical_id, aliases=old_g.aliases)
    f_new = finding(new_g.canonical_id, aliases=new_g.aliases)
    assert (
        plan_inheritance([tf(f_old, stmt("old", vuln="CVE-2099-5"))], [f_new], ON, NOW)[0].action
        is InheritAction.INHERIT
    )


def test_alias_drift_between_releases_still_matches() -> None:
    # Previous release knew only GHSA-x; the new record learned the CVE alias (id changed).
    f_old = finding("GHSA-x")
    f_new = finding("CVE-2099-5", aliases=("GHSA-x",))
    assert (
        plan_inheritance([tf(f_old, stmt("old", vuln="GHSA-x"))], [f_new], ON, NOW)[0].action
        is InheritAction.INHERIT
    )


def test_multiple_candidates_pick_the_identical_component_then_the_newest_statement() -> None:
    a = tf(
        finding(ref="pypi/foo@1.0"),
        stmt("a", ref="pypi/foo@1.0", status=Status.UNDER_INVESTIGATION, created_at=NOW),
    )
    b = tf(
        finding(ref="pypi/foo@2.0"),
        stmt("b", ref="pypi/foo@2.0", created_at=NOW + timedelta(days=1)),
    )
    assert (
        plan_inheritance([a, b], [finding(ref="pypi/foo@1.0")], ON, NOW + timedelta(days=2))[
            0
        ].source.id
        == "a"
    )  # type: ignore[union-attr]
    assert (
        plan_inheritance([a, b], [finding(ref="pypi/foo@3.0")], ON, NOW + timedelta(days=2))[
            0
        ].source.id
        == "b"
    )  # type: ignore[union-attr]


def test_plan_has_one_item_per_new_finding_sorted_and_input_order_independent() -> None:
    prev = [
        tf(finding("CVE-2", ref="pypi/a@1"), stmt("s2", vuln="CVE-2", ref="pypi/a@1")),
        tf(finding("CVE-1", ref="pypi/b@1"), stmt("s1", vuln="CVE-1", ref="pypi/b@1")),
    ]
    new = [
        finding("CVE-3", ref="pypi/c@1"),
        finding("CVE-2", ref="pypi/a@1"),
        finding("CVE-1", ref="pypi/b@2"),
    ]
    results = {
        tuple(
            (i.finding.canonical_vuln_id, i.action)
            for i in plan_inheritance(list(p), list(n), ON, NOW)
        )
        for p in permutations(prev)
        for n in permutations(new)
    }
    assert results == {
        (
            ("CVE-1", InheritAction.NEEDS_REVIEW),
            ("CVE-2", InheritAction.INHERIT),
            ("CVE-3", InheritAction.NONE),
        )
    }
