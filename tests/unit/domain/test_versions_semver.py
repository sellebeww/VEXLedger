# Copyright (c) 2026 Vassel Goleyu. MIT License.
import pytest
from hypothesis import given
from hypothesis import strategies as st

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.errors import InvalidVersionError
from vexledger.domain.versions import scheme_for

S = scheme_for(Ecosystem.NPM)
GO = scheme_for(Ecosystem.GO)

# SemVer 2.0.0 section 11 example chain.
SPEC_CHAIN = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
    "1.0.1",
    "1.1.0",
    "1.10.0",
    "2.0.0",
]


def test_spec_chain_strictly_ascending() -> None:
    for i, low in enumerate(SPEC_CHAIN):
        for high in SPEC_CHAIN[i + 1 :]:
            assert S.compare(low, high) == -1, (low, high)
            assert S.compare(high, low) == 1


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.0.0+a", "1.0.0+b"),
        ("1.0.0+build.1", "1.0.0"),
        ("v1.2.3", "1.2.3"),
        ("v2.0.0+incompatible", "v2.0.0"),
        ("1.0.0-rc.1+x", "1.0.0-rc.1+y"),
    ],
)
def test_equal_ignoring_build_and_v_prefix(a: str, b: str) -> None:
    assert S.compare(a, b) == 0


def test_numeric_not_lexical() -> None:
    assert S.compare("1.2.10", "1.2.9") == 1
    assert S.compare("2.0.0", "1.99.99") == 1
    assert S.compare("1.0.0-alpha.10", "1.0.0-alpha.9") == 1


def test_numeric_identifiers_below_alphanumeric() -> None:
    assert S.compare("1.0.0-1", "1.0.0-a") == -1
    assert S.compare("1.0.0-alpha", "1.0.0-alpha.1") == -1
    assert S.compare("1.0.0-0a", "1.0.0-1") == 1  # '0a' is alphanumeric, '1' numeric


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "1",
        "1.0",
        "1.0.0.0",
        "01.0.0",
        "1.00.0",
        "1.0.0-",
        "1.0.0-01",
        "1.0.0-a..b",
        "1.0.0+",
        "1.0.0-a_b",
        "x.y.z",
        "V1.0.0",
        "1.0.0 ",
    ],
)
def test_invalid_semver_raises(raw: str) -> None:
    with pytest.raises(InvalidVersionError):
        S.parse(raw)


def test_go_pseudo_versions_order() -> None:
    chain = [
        "v0.0.0-20190101000000-aaaaaaaaaaaa",
        "v0.0.0-20200101000000-bbbbbbbbbbbb",
        "v0.0.0",
        "v1.2.3-pre",
        "v1.2.3-pre.0.20191109021931-daa7c04131f5",
        "v1.2.3",
        "v1.2.4-0.20191109021931-daa7c04131f5",
        "v1.2.4",
    ]
    for i, low in enumerate(chain):
        for high in chain[i + 1 :]:
            assert GO.compare(low, high) == -1, (low, high)


def test_go_pseudo_version_after_tag_it_derives_from() -> None:
    # vX.Y.(Z+1)-0.<ts>-<hash> sorts after vX.Y.Z and before vX.Y.(Z+1)
    assert GO.compare("v1.2.4-0.20191109021931-daa7c04131f5", "v1.2.3") == 1
    assert GO.compare("v1.2.4-0.20191109021931-daa7c04131f5", "v1.2.4") == -1


_ident = st.one_of(
    st.integers(0, 12).map(str), st.sampled_from(["alpha", "beta", "rc", "x-1", "0a"])
)
_semver = st.builds(
    lambda core, pre: ".".join(map(str, core)) + ("-" + ".".join(pre) if pre else ""),
    st.tuples(st.integers(0, 12), st.integers(0, 12), st.integers(0, 12)),
    st.lists(_ident, max_size=3),
)


@given(_semver, _semver)
def test_antisymmetry(a: str, b: str) -> None:
    assert S.compare(a, b) == -S.compare(b, a)


@given(_semver, _semver, _semver)
def test_transitivity(a: str, b: str, c: str) -> None:
    if S.compare(a, b) <= 0 and S.compare(b, c) <= 0:
        assert S.compare(a, c) <= 0


@given(_semver)
def test_canonical_round_trip_is_stable(a: str) -> None:
    v = S.parse(a)
    assert S.parse(v.canonical).canonical == v.canonical
    assert S.parse(v.canonical).cmp(v) == 0


def test_numbers_beyond_machine_words_compare_numerically() -> None:
    assert S.compare("1.0.99999999999999999999", "1.0.100000000000000000000") == -1
    assert S.compare("1.0.0-alpha.99999999999999999999", "1.0.0-alpha.100000000000000000000") == -1


def test_prerelease_with_more_fields_is_greater_when_prefix_equal() -> None:
    assert S.compare("1.0.0-rc.1", "1.0.0-rc.1.1") == -1
    assert S.compare("1.0.0-rc.1.1", "1.0.0-rc.2") == -1
