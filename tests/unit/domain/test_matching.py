# Copyright (c) 2026 Vassel Goleyu. MIT License.
import json
from collections.abc import Callable

import pytest

from vexledger.domain.matching import Discrepancy, MatchResult, compare_with_osv, local_match
from vexledger.domain.osv_model import OsvRecord, parse_record
from vexledger.domain.purl import parse_purl
from vexledger.domain.ranges import Verdict

from .conftest import FIXTURES

A, N, U = Verdict.AFFECTED, Verdict.NOT_AFFECTED, Verdict.UNKNOWN
PYPI_GROUP = ["CVE-2099-0001", "GHSA-synt-0001-aaaa", "PYSEC-2099-1"]
Loader = Callable[[str], OsvRecord]


def match(purl: str, ids: list[str], load: Loader) -> MatchResult:
    return local_match(parse_purl(purl), [load(i) for i in ids])


def verdicts(result: MatchResult) -> dict[str, Verdict]:
    return {r.record_id: r.verdict for r in result.records}


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.json")), ids=lambda p: p.stem)
def test_every_fixture_parses_and_declares_itself_synthetic_by_naming(path) -> None:  # type: ignore[no-untyped-def]
    assert parse_record(json.loads(path.read_text())).id == path.stem


def test_alias_group_is_one_finding_with_all_aliases(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@1.5", PYPI_GROUP, load_record)
    assert len(r.groups) == 1
    g = r.groups[0]
    assert g.group.canonical_id == "CVE-2099-0001"
    assert g.group.aliases == ("GHSA-synt-0001-aaaa", "PYSEC-2099-1")
    assert g.verdict is A
    assert verdicts(r) == {"CVE-2099-0001": A, "GHSA-synt-0001-aaaa": A, "PYSEC-2099-1": N}
    assert r.component_ref == "pypi/synthetic-pkg@1.5"


def test_fixed_version_is_not_affected(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@2.0", PYPI_GROUP, load_record)
    assert r.groups[0].verdict is N
    assert r.affected_groups == ()


def test_pypi_name_spelling_does_not_matter(load_record: Loader) -> None:
    assert match("pkg:pypi/Synthetic_Pkg@1.0", PYPI_GROUP, load_record).groups[0].verdict is A


def test_npm_scoped_package_and_two_intervals(load_record: Loader) -> None:
    ids = ["GHSA-synt-npm-0002"]
    got = {
        v: match(f"pkg:npm/%40synthetic/lib@{v}", ids, load_record).groups[0].verdict
        for v in ["0.9.0", "1.0.1", "1.0.2", "3.1.0", "3.2.5"]
    }
    assert got == {"0.9.0": N, "1.0.1": A, "1.0.2": N, "3.1.0": A, "3.2.5": N}
    assert match("pkg:npm/%40Synthetic/Lib@1.0.1", ids, load_record).groups[0].verdict is A


def test_maven_ordering_rules_apply(load_record: Loader) -> None:
    ids = ["GHSA-synt-mvn-0003"]
    got = {
        v: match(f"pkg:maven/org.synthetic/lib@{v}", ids, load_record).groups[0].verdict
        for v in ["2.0.1", "2.1-SNAPSHOT", "2.1", "2.1-1", "2.1.1"]
    }
    assert got == {"2.0.1": A, "2.1-SNAPSHOT": A, "2.1": A, "2.1-1": N, "2.1.1": N}


def test_go_is_case_sensitive_and_handles_v_prefix(load_record: Loader) -> None:
    ids = ["GO-2099-0004"]
    assert (
        match("pkg:golang/github.com/Synthetic/Mod@v1.3.0", ids, load_record).groups[0].verdict is A
    )
    assert (
        match("pkg:golang/github.com/Synthetic/Mod@v1.4.0", ids, load_record).groups[0].verdict is N
    )
    other = match("pkg:golang/github.com/synthetic/mod@v1.3.0", ids, load_record)
    assert other.records[0].notes == ("no_affected_entry_for_package",)
    assert other.groups[0].verdict is N


def test_record_for_another_package_is_not_affected(load_record: Loader) -> None:
    r = match("pkg:pypi/other-pkg@1.0", PYPI_GROUP, load_record)
    assert all(rv.notes == ("no_affected_entry_for_package",) for rv in r.records)
    assert r.groups[0].verdict is N


def test_git_only_record_is_unknown_with_note(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@1.0", ["OSV-2099-0006"], load_record)
    assert r.records[0].verdict is U
    assert "git_range_ignored" in r.records[0].notes


def test_withdrawn_group(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@1.0", ["GHSA-synt-wd-0005"], load_record)
    assert r.groups[0].group.withdrawn
    assert r.records[0].withdrawn


def test_withdrawn_member_does_not_decide_a_live_group() -> None:
    live = parse_record(
        {
            "id": "GHSA-live",
            "aliases": ["GHSA-gone"],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "p"}, "versions": ["2.0"]}],
        }
    )
    gone = parse_record(
        {
            "id": "GHSA-gone",
            "aliases": ["GHSA-live"],
            "withdrawn": "2099-01-01T00:00:00Z",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "p"}, "versions": ["1.0"]}],
        }
    )
    r = local_match(parse_purl("pkg:pypi/p@1.0"), [live, gone])
    assert verdicts(r) == {"GHSA-gone": A, "GHSA-live": N}
    assert not r.groups[0].group.withdrawn
    assert r.groups[0].verdict is N


@pytest.mark.parametrize(
    ("purl", "note"),
    [
        ("pkg:deb/debian/curl@7.0", "unsupported_ecosystem"),
        ("pkg:pypi/synthetic-pkg", "component_has_no_version"),
    ],
)
def test_unmatchable_components_yield_unknown_never_clean(
    purl: str, note: str, load_record: Loader
) -> None:
    r = match(purl, PYPI_GROUP, load_record)
    assert set(verdicts(r).values()) == {U}
    assert all(rv.notes == (note,) for rv in r.records)
    assert r.groups[0].verdict is U


def test_invalid_component_version_is_unknown(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@not-a-version", ["CVE-2099-0001"], load_record)
    assert r.records[0].verdict is U


def test_package_purl_field_can_identify_the_package() -> None:
    rec = parse_record(
        {
            "id": "X-1",
            "affected": [
                {
                    "package": {
                        "ecosystem": "SomethingElse",
                        "name": "n",
                        "purl": "pkg:pypi/Synthetic_Pkg",
                    },
                    "versions": ["1.0"],
                }
            ],
        }
    )
    assert local_match(parse_purl("pkg:pypi/synthetic-pkg@1.0"), [rec]).records[0].verdict is A
    bad = parse_record(
        {
            "id": "X-2",
            "affected": [
                {
                    "package": {"ecosystem": "SomethingElse", "name": "n", "purl": "garbage"},
                    "versions": ["1.0"],
                }
            ],
        }
    )
    assert local_match(parse_purl("pkg:pypi/synthetic-pkg@1.0"), [bad]).records[0].notes == (
        "no_affected_entry_for_package",
    )


def test_result_does_not_depend_on_input_order(load_record: Loader) -> None:
    ids = [*PYPI_GROUP, "GHSA-synt-wd-0005", "OSV-2099-0006"]
    base = match("pkg:pypi/synthetic-pkg@1.5", ids, load_record)
    shuffled = ids[::-1]
    assert match("pkg:pypi/synthetic-pkg@1.5", shuffled, load_record) == base


# compare_with_osv


def test_agreement_is_no_discrepancy(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@1.5", PYPI_GROUP, load_record)
    assert compare_with_osv(r, ["CVE-2099-0001"]) is None
    assert compare_with_osv(r, ["GHSA-synt-0001-aaaa"]) is None  # any alias counts as OSV having it


def test_local_affected_but_osv_silent(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@1.5", PYPI_GROUP, load_record)
    assert compare_with_osv(r, []) == Discrepancy(only_local=("CVE-2099-0001",), only_osv=())


def test_osv_returned_but_local_rules_out(load_record: Loader) -> None:
    r = match("pkg:pypi/synthetic-pkg@2.0", PYPI_GROUP, load_record)
    assert compare_with_osv(r, ["CVE-2099-0001"]) == Discrepancy(
        only_local=(), only_osv=("CVE-2099-0001",)
    )
    assert compare_with_osv(r, []) is None


def test_unknown_withdrawn_and_unmatchable_never_count(load_record: Loader) -> None:
    git = match("pkg:pypi/synthetic-pkg@1.0", ["OSV-2099-0006"], load_record)
    assert compare_with_osv(git, ["OSV-2099-0006"]) is None
    assert compare_with_osv(git, []) is None
    wd = match("pkg:pypi/synthetic-pkg@1.0", ["GHSA-synt-wd-0005"], load_record)
    assert compare_with_osv(wd, []) is None
    deb = match("pkg:deb/debian/curl@7.0", PYPI_GROUP, load_record)
    assert compare_with_osv(deb, ["CVE-2099-0001"]) is None


def test_discrepancy_lists_are_sorted(load_record: Loader) -> None:
    ids = ["GO-2099-0004", "GHSA-synt-npm-0002"]
    r = local_match(parse_purl("pkg:npm/%40synthetic/lib@1.0.1"), [load_record(i) for i in ids])
    d = compare_with_osv(r, ["GO-2099-0004"])
    assert d == Discrepancy(only_local=("GHSA-synt-npm-0002",), only_osv=("CVE-2099-0004",))
