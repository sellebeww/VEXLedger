# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Vectors ported from Maven's ComparableVersionTest (maven-3.9.x); see docs/VERSION_TESTS.md."""

import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.errors import InvalidVersionError
from vexledger.domain.versions import scheme_for

S = scheme_for(Ecosystem.MAVEN)

VERSIONS_QUALIFIER = [
    "1-alpha2snapshot",
    "1-alpha2",
    "1-alpha-123",
    "1-beta-2",
    "1-beta123",
    "1-m2",
    "1-m11",
    "1-rc",
    "1-cr2",
    "1-rc123",
    "1-SNAPSHOT",
    "1",
    "1-sp",
    "1-sp2",
    "1-sp123",
    "1-abc",
    "1-def",
    "1-pom-1",
    "1-1-snapshot",
    "1-1",
    "1-2",
    "1-123",
]
VERSIONS_NUMBER = [
    "2.0",
    "2.0.a",
    "2-1",
    "2.0.2",
    "2.0.123",
    "2.1.0",
    "2.1-a",
    "2.1b",
    "2.1-c",
    "2.1-1",
    "2.1.0.1",
    "2.2",
    "2.123",
    "11.a2",
    "11.a11",
    "11.b2",
    "11.b11",
    "11.m2",
    "11.m11",
    "11",
    "11.a",
    "11b",
    "11c",
    "11m",
]


def _check_chain(chain: list[str]) -> None:
    # Like the Java test: every earlier entry sorts below every later one (not just neighbours).
    for i in range(1, len(chain)):
        for j in range(i, len(chain)):
            assert S.compare(chain[i - 1], chain[j]) < 0, (chain[i - 1], chain[j])
            assert S.compare(chain[j], chain[i - 1]) > 0, (chain[j], chain[i - 1])


def test_qualifier_chain() -> None:
    _check_chain(VERSIONS_QUALIFIER)


def test_number_chain() -> None:
    _check_chain(VERSIONS_NUMBER)


EQUAL = [
    ("1", "1"),
    ("1", "1.0"),
    ("1", "1.0.0"),
    ("1.0", "1.0.0"),
    ("1", "1-0"),
    ("1", "1.0-0"),
    ("1.0", "1.0-0"),
    ("1a", "1-a"),
    ("1a", "1.0-a"),
    ("1a", "1.0.0-a"),
    ("1.0a", "1-a"),
    ("1.0.0a", "1-a"),
    ("1x", "1-x"),
    ("1x", "1.0-x"),
    ("1x", "1.0.0-x"),
    ("1.0x", "1-x"),
    ("1.0.0x", "1-x"),
    ("1ga", "1"),
    ("1release", "1"),
    ("1final", "1"),
    ("1cr", "1rc"),
    ("1a1", "1-alpha-1"),
    ("1b2", "1-beta-2"),
    ("1m3", "1-milestone-3"),
    ("1X", "1x"),
    ("1A", "1a"),
    ("1B", "1b"),
    ("1M", "1m"),
    ("1Ga", "1"),
    ("1GA", "1"),
    ("1RELEASE", "1"),
    ("1RELeaSE", "1"),
    ("1Final", "1"),
    ("1FINAL", "1"),
    ("1Cr", "1Rc"),
    ("1cR", "1rC"),
    ("1m3", "1Milestone3"),
    ("1m3", "1MileStone3"),
    ("1m3", "1MILESTONE3"),
    ("1-abcdefghijklmnopqrstuvwxyz", "1-ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
]


@pytest.mark.parametrize(("a", "b"), EQUAL)
def test_equal_pairs(a: str, b: str) -> None:
    assert S.compare(a, b) == 0
    assert S.compare(b, a) == 0


ORDERED = [
    ("1", "2"),
    ("1.5", "2"),
    ("1", "2.5"),
    ("1.0", "1.1"),
    ("1.1", "1.2"),
    ("1.0.0", "1.1"),
    ("1.0.1", "1.1"),
    ("1.1", "1.2.0"),
    ("1.0-alpha-1", "1.0"),
    ("1.0-alpha-1", "1.0-alpha-2"),
    ("1.0-alpha-1", "1.0-beta-1"),
    ("1.0-beta-1", "1.0-SNAPSHOT"),
    ("1.0-SNAPSHOT", "1.0"),
    ("1.0-alpha-1-SNAPSHOT", "1.0-alpha-1"),
    ("1.0", "1.0-1"),
    ("1.0-1", "1.0-2"),
    ("1.0.0", "1.0-1"),
    ("2.0-1", "2.0.1"),
    ("2.0.1-klm", "2.0.1-lmn"),
    ("2.0.1", "2.0.1-xyz"),
    ("2.0.1", "2.0.1-123"),
    ("2.0.1-xyz", "2.0.1-123"),
    # MNG-5568
    ("6.1.0rc3", "6.1.0"),
    ("6.1.0rc3", "6.1H.5-beta"),
    ("6.1.0", "6.1H.5-beta"),
    # MNG-6572 (long numbers: Int, Long and BigInteger items)
    ("20190126.230843", "1234567890.12345"),
    ("1234567890.12345", "123456789012345.1H.5-beta"),
    ("20190126.230843", "123456789012345.1H.5-beta"),
    ("123456789012345.1H.5-beta", "12345678901234567890.1H.5-beta"),
    ("1234567890.12345", "12345678901234567890.1H.5-beta"),
    ("20190126.230843", "12345678901234567890.1H.5-beta"),
    # MNG-6964
    ("1-0.alpha", "1"),
    ("1-0.beta", "1"),
    ("1-0.alpha", "1-0.beta"),
    # Commonly seen release qualifiers
    ("1.0-RC1", "1.0"),
    ("1.0", "1.0-sp1"),
    ("1.0-M1", "1.0-RC1"),
    ("1.0-alpha", "1.0-beta"),
]


@pytest.mark.parametrize(("low", "high"), ORDERED)
def test_ordered_pairs(low: str, high: str) -> None:
    assert S.compare(low, high) == -1
    assert S.compare(high, low) == 1


def test_leading_zero_runs_are_equal() -> None:
    ones = ["0" * n + "1" for n in range(0, 19)]
    zeros = ["0" * n for n in range(1, 20)]
    for group in (ones, zeros):
        for a, b in itertools.combinations(group, 2):
            assert S.compare(a, b) == 0


@pytest.mark.parametrize("x", ["abc", "alpha", "a", "beta", "b", "def", "milestone", "m", "RC"])
def test_mng7644(x: str) -> None:
    assert S.compare(f"1.0.0.{x}1", f"1.0.0-{x}2") < 0
    assert S.compare(f"2-{x}", f"2.0.{x}") == 0
    assert S.compare(f"2-{x}", f"2.0.0.{x}") == 0
    assert S.compare(f"2.0.{x}", f"2.0.0.{x}") == 0


@pytest.mark.parametrize("raw", ["", "   "])
def test_empty_version_is_invalid(raw: str) -> None:
    with pytest.raises(InvalidVersionError):
        S.parse(raw)


@pytest.mark.parametrize("raw", VERSIONS_QUALIFIER + VERSIONS_NUMBER)
def test_canonical_is_stable_for_all_vectors(raw: str) -> None:
    # Same check the Java test performs on every vector: canonical(canonical(v)) == canonical(v).
    c = S.parse(raw).canonical
    assert S.parse(c).canonical == c
    assert S.compare(c, raw) == 0


_maven = st.text(alphabet="0123456789.-abcmrsxGA", min_size=1, max_size=10)


@given(_maven, _maven)
@settings(max_examples=1500)
def test_antisymmetry(a: str, b: str) -> None:
    assert S.compare(a, b) == -S.compare(b, a)


@given(_maven)
def test_reflexive(a: str) -> None:
    assert S.compare(a, a) == 0


# Upstream's canonical form is NOT idempotent for every string (for example "0b" prints "b",
# which parses differently), so the round-trip property is limited to well-formed versions:
# a non-zero number first, then separator-delimited numbers or qualifier words.
_token = st.one_of(
    st.integers(1, 99).map(str),
    st.sampled_from(["alpha", "beta", "rc", "snapshot", "sp", "x", "milestone"]),
)
_well_formed = st.builds(
    lambda first, rest: str(first) + "".join(sep + tok for sep, tok in rest),
    st.integers(1, 99),
    st.lists(st.tuples(st.sampled_from([".", "-"]), _token), max_size=4),
)


@given(_well_formed)
def test_canonical_round_trip_is_stable_for_well_formed(a: str) -> None:
    c = S.parse(a).canonical
    assert S.parse(c).canonical == c
    assert S.compare(c, a) == 0


# Maven's ordering is not transitive for odd strings (found by hypothesis, never run against Java
# here): "0" < "b" <= "0A0" < "0" and "1" <= "1.sp.1" <= "1.alpha" < "1". The port matches every
# upstream vector, so this is assumed to be upstream behaviour. Transitivity is asserted for the
# version shapes seen in practice: dotted numbers plus at most one conventional suffix.
_suffix = st.sampled_from(
    [
        "",
        "-SNAPSHOT",
        "-alpha-1",
        "-beta-2",
        "-rc-1",
        "-sp-1",
        "-1",
        "-2",
        ".RELEASE",
        ".Final",
        ".M1",
        ".RC1",
        ".SP1",
        "-M3",
        "-RC2",
        ".GA",
    ]
)
_realistic = st.builds(
    lambda nums, suffix: ".".join(map(str, nums)) + suffix,
    st.lists(st.integers(0, 30), min_size=1, max_size=4),
    _suffix,
)


@settings(max_examples=1500)
@given(_realistic, _realistic, _realistic)
def test_transitivity_for_realistic_versions(a: str, b: str, c: str) -> None:
    if S.compare(a, b) <= 0 and S.compare(b, c) <= 0:
        assert S.compare(a, c) <= 0


def test_known_upstream_style_intransitivity_is_documented_not_hidden() -> None:
    assert S.compare("0", "b") == -1
    assert S.compare("b", "0A0") <= 0
    assert S.compare("0", "0A0") == 1
    assert S.compare("1", "1.sp.1") <= 0 < S.compare("1", "1.alpha")
    assert S.compare("1.sp.1", "1.alpha") <= 0


@pytest.mark.parametrize(
    ("a", "b"), [("1.0.RELEASE", "1.0"), ("5.4.0.Final", "5.4.0"), ("1.0-ga", "1.0")]
)
def test_release_aliases_with_dot_or_dash_equal_plain_version(a: str, b: str) -> None:
    assert S.compare(a, b) == 0


def test_spring_style_qualifier_chain() -> None:
    chain = ["1.0.0.M1", "1.0.0.RC1", "1.0.0.RELEASE", "1.0.0.SP1", "1.0.1"]
    for i, low in enumerate(chain):
        for high in chain[i + 1 :]:
            assert S.compare(low, high) == -1, (low, high)


def test_snapshot_below_release_but_unknown_qualifier_above() -> None:
    assert S.compare("1.0.0-SNAPSHOT", "1.0") == -1
    assert S.compare("1.0-foo", "1.0") == 1
