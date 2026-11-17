# Copyright (c) 2026 Vassel Goleyu. MIT License.
import pytest

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.osv_model import Affected, Event, VersionRange
from vexledger.domain.ranges import Verdict, evaluate_affected

A, N, U = Verdict.AFFECTED, Verdict.NOT_AFFECTED, Verdict.UNKNOWN


def rng(rtype: str, *events: tuple[str, str], malformed: bool = False) -> VersionRange:
    return VersionRange(rtype, tuple(Event(k, v) for k, v in events), malformed)


def entry(*ranges: VersionRange, versions: tuple[str, ...] = ()) -> Affected:
    return Affected(None, tuple(ranges), versions)


def verdict(e: Affected, version: str, eco: Ecosystem = Ecosystem.NPM) -> Verdict:
    return evaluate_affected(e, version, eco).verdict


FIXED = entry(rng("SEMVER", ("introduced", "1.0.0"), ("fixed", "2.0.0")))


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("0.9.9", N),
        ("1.0.0", A),
        ("1.0.1", A),
        ("1.9.9", A),
        ("2.0.0", N),
        ("2.0.1", N),
        ("1.0.0-rc.1", N),
        ("2.0.0-rc.1", A),
    ],
)
def test_introduced_inclusive_fixed_exclusive(version: str, expected: Verdict) -> None:
    assert verdict(FIXED, version) is expected


LAST = entry(rng("SEMVER", ("introduced", "1.0.0"), ("last_affected", "1.5.0")))


@pytest.mark.parametrize(
    ("version", "expected"), [("0.9.0", N), ("1.0.0", A), ("1.5.0", A), ("1.5.1", N), ("2.0.0", N)]
)
def test_last_affected_is_inclusive(version: str, expected: Verdict) -> None:
    assert verdict(LAST, version) is expected


def test_introduced_zero_covers_everything_before_fix() -> None:
    e = entry(rng("SEMVER", ("introduced", "0"), ("fixed", "1.0.2")))
    assert verdict(e, "0.0.1") is A
    assert verdict(e, "0.0.0-alpha") is A
    assert verdict(e, "1.0.2") is N


def test_introduced_zero_without_fix_is_open_ended() -> None:
    e = entry(rng("SEMVER", ("introduced", "0")))
    assert verdict(e, "999.0.0") is A


def test_multiple_intervals_in_one_range() -> None:
    e = entry(
        rng(
            "SEMVER",
            ("introduced", "1.0.0"),
            ("fixed", "1.0.2"),
            ("introduced", "3.0.0"),
            ("fixed", "3.2.5"),
        )
    )
    got = {
        v: verdict(e, v)
        for v in ["0.5.0", "1.0.0", "1.0.1", "1.0.2", "2.0.0", "3.0.0", "3.2.4", "3.2.5", "4.0.0"]
    }
    assert got == {
        "0.5.0": N,
        "1.0.0": A,
        "1.0.1": A,
        "1.0.2": N,
        "2.0.0": N,
        "3.0.0": A,
        "3.2.4": A,
        "3.2.5": N,
        "4.0.0": N,
    }


def test_events_are_sorted_before_evaluation() -> None:
    e = entry(
        rng(
            "SEMVER",
            ("fixed", "3.2.5"),
            ("introduced", "3.0.0"),
            ("fixed", "1.0.2"),
            ("introduced", "1.0.0"),
        )
    )
    assert verdict(e, "1.0.1") is A
    assert verdict(e, "2.0.0") is N
    assert verdict(e, "3.1.0") is A


def test_introduced_and_fixed_at_same_version_is_empty() -> None:
    e = entry(rng("SEMVER", ("fixed", "1.0.0"), ("introduced", "1.0.0")))
    assert verdict(e, "1.0.0") is N
    assert verdict(e, "0.9.0") is N


def test_limit_is_exclusive_upper_bound() -> None:
    e = entry(rng("SEMVER", ("introduced", "0"), ("limit", "2.0.0")))
    assert verdict(e, "1.9.9") is A
    assert verdict(e, "2.0.0") is N


def test_limit_star_and_multiple_limits() -> None:
    assert verdict(entry(rng("SEMVER", ("introduced", "0"), ("limit", "*"))), "50.0.0") is A
    e = entry(rng("SEMVER", ("introduced", "0"), ("limit", "1.0.0"), ("limit", "3.0.0")))
    assert verdict(e, "2.0.0") is A  # before any one limit is enough
    assert verdict(e, "3.0.0") is N


def test_ranges_are_evaluated_independently() -> None:
    e = entry(
        rng("SEMVER", ("introduced", "1.0.0"), ("fixed", "1.1.0")),
        rng("SEMVER", ("introduced", "5.0.0"), ("fixed", "5.1.0")),
    )
    assert verdict(e, "5.0.5") is A
    assert verdict(e, "3.0.0") is N


def test_pypi_ecosystem_range_uses_pep440() -> None:
    e = entry(rng("ECOSYSTEM", ("introduced", "0"), ("fixed", "1.0")))
    assert verdict(e, "1.0rc1", Ecosystem.PYPI) is A
    assert verdict(e, "1.0.post1", Ecosystem.PYPI) is N
    assert verdict(e, "0.9.dev1", Ecosystem.PYPI) is A


def test_maven_ecosystem_range_uses_comparable_version() -> None:
    e = entry(rng("ECOSYSTEM", ("introduced", "0"), ("fixed", "2.1")))
    assert verdict(e, "2.1-SNAPSHOT", Ecosystem.MAVEN) is A
    assert verdict(e, "2.1", Ecosystem.MAVEN) is N
    assert verdict(e, "2.1.0", Ecosystem.MAVEN) is N
    assert verdict(e, "2.0.9", Ecosystem.MAVEN) is A


def test_go_semver_range_accepts_v_prefixed_component_versions() -> None:
    e = entry(rng("SEMVER", ("introduced", "0"), ("fixed", "1.4.0")))
    assert verdict(e, "v1.3.9", Ecosystem.GO) is A
    assert verdict(e, "v1.4.0", Ecosystem.GO) is N
    assert verdict(e, "v0.0.0-20200101000000-abcdefabcdef", Ecosystem.GO) is A


def test_versions_list_is_exact_string_match() -> None:
    e = entry(versions=("1.0", "1.5"))
    assert verdict(e, "1.0", Ecosystem.PYPI) is A
    assert verdict(e, "1.0.0", Ecosystem.PYPI) is N  # not listed verbatim: no guessing equivalence
    assert verdict(e, "2.0", Ecosystem.PYPI) is N


def test_go_versions_list_ignores_v_prefix() -> None:
    assert verdict(entry(versions=("1.2.3",)), "v1.2.3", Ecosystem.GO) is A


def test_listed_version_wins_even_if_ranges_cannot_be_evaluated() -> None:
    e = entry(rng("SEMVER", ("introduced", "0")), versions=("not-a-version",))
    assert verdict(e, "not-a-version") is A


@pytest.mark.parametrize("version", ["", "latest", "1.0", "x.y.z"])
def test_invalid_component_version_is_unknown_never_affected(version: str) -> None:
    assert verdict(FIXED, version) is U


def test_invalid_version_in_events_is_unknown() -> None:
    assert verdict(entry(rng("SEMVER", ("introduced", "1.0.0"), ("fixed", "soon"))), "1.5.0") is U
    assert verdict(entry(rng("SEMVER", ("introduced", "0"), ("limit", "later"))), "1.5.0") is U


def test_malformed_and_unknown_range_types_are_unknown() -> None:
    assert verdict(entry(rng("SEMVER", malformed=True)), "1.0.0") is U
    assert verdict(entry(rng("MYSTERY", ("introduced", "0"))), "1.0.0") is U
    assert verdict(entry(rng("SEMVER", ("fixed", "2.0.0"))), "1.0.0") is U  # no introduced event


def test_git_ranges_are_ignored_and_noted() -> None:
    git = rng("GIT", ("introduced", "0"), ("fixed", "0123456789abcdef0123456789abcdef01234567"))
    only_git = evaluate_affected(entry(git), "1.0.0", Ecosystem.NPM)
    assert only_git.verdict is U
    assert "git_range_ignored" in only_git.notes
    with_list = evaluate_affected(entry(git, versions=("0.5.0",)), "1.0.0", Ecosystem.NPM)
    assert with_list.verdict is N
    assert "git_range_ignored" in with_list.notes
    mixed = evaluate_affected(
        entry(git, rng("SEMVER", ("introduced", "0"), ("fixed", "2.0.0"))), "1.0.0", Ecosystem.NPM
    )
    assert mixed.verdict is A
    assert "git_range_ignored" in mixed.notes


def test_entry_without_ranges_or_versions_is_unknown() -> None:
    assert evaluate_affected(entry(), "1.0.0", Ecosystem.NPM).verdict is U


def test_unknown_range_blocks_a_negative_answer_but_not_a_positive_one() -> None:
    bad = rng("SEMVER", ("introduced", "0"), ("fixed", "soon"))
    good_no = rng("SEMVER", ("introduced", "5.0.0"), ("fixed", "6.0.0"))
    good_yes = rng("SEMVER", ("introduced", "1.0.0"), ("fixed", "2.0.0"))
    assert verdict(entry(bad, good_no), "1.5.0") is U
    assert verdict(entry(bad, good_yes), "1.5.0") is A
