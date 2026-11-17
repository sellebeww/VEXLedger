# Copyright (c) 2026 Vassel Goleyu. MIT License.
import pytest
from hypothesis import given
from hypothesis import strategies as st

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.errors import InvalidVersionError
from vexledger.domain.versions import scheme_for

S = scheme_for(Ecosystem.PYPI)

# PEP 440 total order, ascending (examples from the PEP's ordering rules).
ORDER = [
    "1.0.dev1",
    "1.0a1.dev1",
    "1.0a1",
    "1.0a2",
    "1.0b1",
    "1.0rc1",
    "1.0",
    "1.0+abc",
    "1.0+abd",
    "1.0.post1.dev1",
    "1.0.post1",
    "1.0.1",
    "1.1.dev1",
    "1.1",
    "1.10",
    "2.0",
    "1!0.1",
]


def test_total_order_is_strict_ascending() -> None:
    for i, low in enumerate(ORDER):
        for high in ORDER[i + 1 :]:
            assert S.compare(low, high) == -1, (low, high)
            assert S.compare(high, low) == 1, (high, low)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.0", "1.0.0"),
        ("1.0-1", "1.0.post1"),
        ("1.0RC1", "1.0rc1"),
        ("v1.0", "1.0"),
        ("1.0c1", "1.0rc1"),
        ("1.0alpha1", "1.0a1"),
        ("01.0", "1.0"),
    ],
)
def test_equivalent_spellings(a: str, b: str) -> None:
    assert S.compare(a, b) == 0


def test_epoch_beats_everything() -> None:
    assert S.compare("1!0.5", "99.9") == 1


def test_local_version_only_breaks_ties_on_public_version() -> None:
    assert S.compare("1.0+local", "1.0") == 1
    assert S.compare("1.0+local", "1.0.post1") == -1


def test_prerelease_below_release_and_dev_below_prerelease() -> None:
    assert S.compare("2.0rc1", "2.0") == -1
    assert S.compare("2.0.dev0", "2.0a0") == -1


@pytest.mark.parametrize("raw", ["", "abc", "1.0.x", "1..0", "1.0+", "1.0-", "latest", "1.0 beta"])
def test_invalid_versions_raise(raw: str) -> None:
    with pytest.raises(InvalidVersionError):
        S.parse(raw)


_pep440 = st.builds(
    lambda epoch, rel, pre, post, dev: (
        (f"{epoch}!" if epoch else "")
        + ".".join(map(str, rel))
        + (pre or "")
        + (f".post{post}" if post is not None else "")
        + (f".dev{dev}" if dev is not None else "")
    ),
    st.integers(0, 2),
    st.lists(st.integers(0, 20), min_size=1, max_size=4),
    st.one_of(
        st.none(),
        st.builds(lambda k, n: f"{k}{n}", st.sampled_from(["a", "b", "rc"]), st.integers(0, 5)),
    ),
    st.one_of(st.none(), st.integers(0, 5)),
    st.one_of(st.none(), st.integers(0, 5)),
)


@given(_pep440, _pep440)
def test_antisymmetry(a: str, b: str) -> None:
    assert S.compare(a, b) == -S.compare(b, a)


@given(_pep440, _pep440, _pep440)
def test_transitivity(a: str, b: str, c: str) -> None:
    if S.compare(a, b) <= 0 and S.compare(b, c) <= 0:
        assert S.compare(a, c) <= 0


@given(_pep440)
def test_canonical_round_trip_is_stable(a: str) -> None:
    v = S.parse(a)
    again = S.parse(v.canonical)
    assert again.canonical == v.canonical
    assert again.cmp(v) == 0


@pytest.mark.parametrize(
    ("a", "b"),
    [("1.0a", "1.0a0"), ("1.0.post", "1.0.post0"), ("1.0-dev", "1.0.dev0"), ("1.0.0.0", "1")],
)
def test_implicit_zero_spellings(a: str, b: str) -> None:
    assert S.compare(a, b) == 0


def test_local_segments_compare_numerically_and_letters_sort_below_numbers() -> None:
    assert S.compare("1.0+10", "1.0+2") == 1
    assert S.compare("1.0+abc", "1.0+1") == -1
    assert S.compare("1.0+a.1", "1.0+a") == 1
