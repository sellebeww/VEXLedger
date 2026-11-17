# Copyright (c) 2026 Vassel Goleyu. MIT License.
from itertools import permutations

from vexledger.domain.diff import (
    ComponentSnapshot as C,
)
from vexledger.domain.diff import (
    HashChange,
    PersistingFinding,
    ReleaseSnapshot,
    VersionChange,
    diff_releases,
)
from vexledger.domain.model import FindingState as S
from vexledger.domain.model import Status

from .factories import NOW, finding, stmt, tf


def snap(components, findings) -> ReleaseSnapshot:  # type: ignore[no-untyped-def]
    return ReleaseSnapshot(components, findings)


def test_component_added_removed_and_version_changed() -> None:
    a = snap([C("pypi/a", "1"), C("pypi/b", "1"), C("pypi/c", "1.0")], [])
    b = snap([C("pypi/a", "1"), C("pypi/c", "1.1"), C("npm/d", "2")], [])
    d = diff_releases(a, b, NOW)
    assert d.components_added == ("npm/d",)
    assert d.components_removed == ("pypi/b",)
    assert d.version_changed == (VersionChange("pypi/c", ("1.0",), ("1.1",)),)
    assert d.hash_changed == ()


def test_hash_change_with_the_same_version() -> None:
    d = diff_releases(snap([C("pypi/a", "1", "aaa")], []), snap([C("pypi/a", "1", "bbb")], []), NOW)
    assert d.hash_changed == (HashChange("pypi/a", ("1",), ("aaa",), ("bbb",)),)
    assert d.version_changed == ()
    none_to_hash = diff_releases(
        snap([C("pypi/a", "1")], []), snap([C("pypi/a", "1", "bbb")], []), NOW
    )
    assert none_to_hash.hash_changed[0].from_hashes == (None,)


def test_identical_releases_have_an_empty_diff() -> None:
    s = snap([C("pypi/a", "1", "h")], [tf(finding())])
    d = diff_releases(s, s, NOW)
    assert d.components_added == d.components_removed == d.version_changed == d.hash_changed == ()
    assert d.findings_new == d.findings_resolved == ()
    assert len(d.findings_persisting) == 1


def test_multiple_versions_of_one_component_are_compared_as_sets() -> None:
    a = snap([C("pypi/a", "1"), C("pypi/a", "2")], [])
    b = snap([C("pypi/a", "2"), C("pypi/a", "3")], [])
    assert diff_releases(a, b, NOW).version_changed == (
        VersionChange("pypi/a", ("1", "2"), ("2", "3")),
    )


def test_findings_new_resolved_and_persisting_with_states() -> None:
    triaged = stmt("s", vuln="CVE-P")
    a = snap([], [tf(finding("CVE-R"), None), tf(finding("CVE-P", ref="pypi/a@1"), triaged)])
    b = snap(
        [],
        [
            tf(finding("CVE-N"), None),
            tf(finding("CVE-P", ref="pypi/a@2"), stmt("t", vuln="CVE-P", inherited_from_id="s")),
        ],
    )
    d = diff_releases(a, b, NOW)
    assert [f.canonical_vuln_id for f in d.findings_new] == ["CVE-N"]
    assert [f.canonical_vuln_id for f in d.findings_resolved] == ["CVE-R"]
    assert d.findings_new[0].state is S.UNTRIAGED
    assert d.findings_persisting == (PersistingFinding("CVE-P", "pypi/a", S.TRIAGED, S.INHERITED),)


def test_statement_summary_counts_release_b() -> None:
    b = snap(
        [],
        [
            tf(finding("CVE-1"), stmt("a", inherited_from_id="x")),
            tf(finding("CVE-2"), stmt("b", inherited_from_id="x")),
            tf(finding("CVE-3", needs_review=True)),
            tf(finding("CVE-4"), stmt("c", status=Status.AFFECTED, valid_until=None)),
            tf(finding("CVE-5")),
        ],
    )
    d = diff_releases(snap([], []), b, NOW)
    assert (d.statements.inherited, d.statements.needs_review) == (2, 1)


def test_same_vulnerability_on_a_different_component_is_a_different_finding() -> None:
    a = snap([], [tf(finding("CVE-1", ref="pypi/a@1"))])
    b = snap([], [tf(finding("CVE-1", ref="pypi/b@1"))])
    d = diff_releases(a, b, NOW)
    assert len(d.findings_new) == len(d.findings_resolved) == 1
    assert d.findings_persisting == ()


def test_result_is_independent_of_input_order() -> None:
    comps_a = [C("pypi/a", "1"), C("pypi/b", "1", "h"), C("pypi/c", "1")]
    comps_b = [C("pypi/a", "2"), C("pypi/b", "1", "g"), C("npm/z", "1")]
    fa = [
        tf(finding("CVE-1", ref="pypi/a@1")),
        tf(finding("CVE-2", ref="pypi/b@1")),
        tf(finding("CVE-3", ref="pypi/c@1")),
    ]
    fb = [
        tf(finding("CVE-1", ref="pypi/a@2")),
        tf(finding("CVE-4", ref="npm/z@1")),
        tf(finding("CVE-2", ref="pypi/b@1")),
    ]
    base = diff_releases(snap(comps_a, fa), snap(comps_b, fb), NOW)
    for ca in permutations(comps_a):
        for fbp in permutations(fb):
            assert (
                diff_releases(snap(list(ca), fa[::-1]), snap(comps_b[::-1], list(fbp)), NOW) == base
            )
