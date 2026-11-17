# Copyright (c) 2026 Vassel Goleyu. MIT License.
import pytest
from hypothesis import given
from hypothesis import strategies as st

from vexledger.domain.errors import InvalidOsvRecordError
from vexledger.domain.osv_model import OsvRecord, parse_record
from vexledger.domain.vulns import choose_canonical_id, extract_severity, group_records


def rec(rid: str, aliases: tuple[str, ...] = (), withdrawn: bool = False) -> OsvRecord:
    data: dict[str, object] = {"id": rid, "aliases": list(aliases)}
    if withdrawn:
        data["withdrawn"] = "2099-01-01T00:00:00Z"
    return parse_record(data)


def test_transitive_alias_chain_is_one_group() -> None:
    # A aliases B, B aliases C: A, B and C are one vulnerability.
    groups = group_records([rec("A-1", ("B-1",)), rec("B-1", ("C-1",)), rec("C-1")])
    assert len(groups) == 1
    assert set(groups[0].record_ids) == {"A-1", "B-1", "C-1"}
    assert groups[0].canonical_id == "A-1"
    assert groups[0].aliases == ("B-1", "C-1")


def test_chain_links_through_alias_only_ids() -> None:
    groups = group_records([rec("GHSA-x", ("CVE-1",)), rec("PYSEC-y", ("CVE-1",))])
    assert len(groups) == 1
    assert groups[0].canonical_id == "CVE-1"
    assert groups[0].aliases == ("GHSA-x", "PYSEC-y")


def test_one_sided_alias_declaration_still_merges() -> None:
    assert len(group_records([rec("GHSA-a", ("CVE-1",)), rec("CVE-1")])) == 1


def test_unrelated_records_stay_separate_and_sorted() -> None:
    groups = group_records([rec("GHSA-b"), rec("GHSA-a")])
    assert [g.canonical_id for g in groups] == ["GHSA-a", "GHSA-b"]


def test_two_cves_in_one_group_pick_smallest_lexicographically() -> None:
    assert choose_canonical_id(["CVE-2021-9999", "CVE-2021-10000", "GHSA-a"]) == "CVE-2021-10000"
    g = group_records([rec("GHSA-a", ("CVE-2021-2000", "CVE-2020-9000"))])[0]
    assert g.canonical_id == "CVE-2020-9000"
    assert "CVE-2021-2000" in g.aliases


def test_without_cve_prefers_ghsa_then_smallest_other() -> None:
    assert choose_canonical_id(["PYSEC-2020-1", "GHSA-zzzz", "GHSA-aaaa", "OSV-1"]) == "GHSA-aaaa"
    assert choose_canonical_id(["PYSEC-2020-2", "OSV-1", "GO-2020-1"]) == "GO-2020-1"


def test_cve_beats_ghsa_even_if_ghsa_sorts_first() -> None:
    assert choose_canonical_id(["GHSA-aaaa", "CVE-2099-1"]) == "CVE-2099-1"


def test_canonical_id_of_nothing_is_an_error() -> None:
    with pytest.raises(ValueError, match="no ids"):
        choose_canonical_id([])


def test_withdrawn_only_when_every_record_in_group_is_withdrawn() -> None:
    assert group_records([rec("GHSA-a", withdrawn=True)])[0].withdrawn
    both = group_records([rec("GHSA-a", ("CVE-1",), withdrawn=True), rec("CVE-1")])
    assert len(both) == 1
    assert not both[0].withdrawn
    all_w = group_records([rec("GHSA-a", ("CVE-1",), withdrawn=True), rec("CVE-1", withdrawn=True)])
    assert all_w[0].withdrawn


def test_duplicate_record_ids_collapse() -> None:
    assert len(group_records([rec("GHSA-a"), rec("GHSA-a")])[0].records) == 1


@given(st.permutations(["A-1", "B-1", "C-1", "D-1"]))
def test_grouping_is_independent_of_input_order(order: list[str]) -> None:
    data = {"A-1": ("B-1",), "B-1": ("C-1",), "C-1": (), "D-1": ()}
    groups = group_records([rec(i, data[i]) for i in order])
    assert [(g.canonical_id, g.record_ids) for g in groups] == [
        ("A-1", ("A-1", "B-1", "C-1")),
        ("D-1", ("D-1",)),
    ]


def test_severity_is_extracted_as_published(load_record) -> None:  # type: ignore[no-untyped-def]
    sev = extract_severity(load_record("CVE-2099-0001"))
    assert sev.entries == (("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),)
    assert sev.database_specific == "HIGH"
    empty = extract_severity(load_record("PYSEC-2099-1"))
    assert empty.entries == ()
    assert empty.database_specific is None


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"id": ""},
        {"id": 5},
        {"id": "X", "aliases": "CVE-1"},
        {"id": "X", "aliases": [1]},
        {"id": "X", "affected": "no"},
        {"id": "X", "affected": ["no"]},
        {"id": "X", "affected": [{"ranges": "no"}]},
    ],
)
def test_unusable_records_raise_typed_error(data: dict[str, object]) -> None:
    with pytest.raises(InvalidOsvRecordError):
        parse_record(data)


def test_bad_events_mark_only_that_range_malformed() -> None:
    r = parse_record(
        {
            "id": "X-1",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "p"},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "1.0.0", "fixed": "2.0.0"}]},
                        {"type": "SEMVER", "events": [{"introduced": "1.0.0"}]},
                        "junk",
                    ],
                }
            ],
        }
    )
    ranges = r.affected[0].ranges
    assert [x.malformed for x in ranges] == [True, False, True]
