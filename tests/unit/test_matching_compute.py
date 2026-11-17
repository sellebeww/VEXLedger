# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""compute_findings is pure. OSV records come from the synthetic fixtures (not recordings)."""

import json
import uuid
from pathlib import Path

from vexledger.domain.osv_model import OsvRecord, parse_record
from vexledger.domain.purl import parse_purl
from vexledger.services.matching import compute_findings

FIXTURES = Path(__file__).parents[1] / "fixtures" / "osv_synthetic"
CID = uuid.uuid4()


def rec(name: str) -> OsvRecord:
    return parse_record(json.loads((FIXTURES / f"{name}.json").read_text()))


def compute(purl: str, *names: str):  # type: ignore[no-untyped-def]
    return compute_findings(CID, parse_purl(purl), [rec(n) for n in names])


def test_ghsa_pysec_and_cve_become_one_finding() -> None:
    (f,) = compute(
        "pkg:pypi/synthetic-pkg@1.5", "CVE-2099-0001", "GHSA-synt-0001-aaaa", "PYSEC-2099-1"
    )
    assert f.canonical_vuln_id == "CVE-2099-0001"
    assert f.alias_ids == ("GHSA-synt-0001-aaaa", "PYSEC-2099-1")
    assert f.component_ref == "pypi/synthetic-pkg@1.5" and f.component_id == CID
    assert (
        f.severity_label == "HIGH"
    )  # the canonical record's database_specific.severity, as published
    assert not f.withdrawn and f.discrepancy is None


def test_withdrawn_group_is_flagged() -> None:
    (f,) = compute("pkg:pypi/synthetic-pkg@1.0", "GHSA-synt-wd-0005")
    assert f.withdrawn


def test_osv_and_local_agree_below_the_fixed_version() -> None:
    (f,) = compute("pkg:pypi/synthetic-pkg@1.9", "CVE-2099-0001")
    assert f.discrepancy is None


def test_osv_says_affected_at_exactly_the_fixed_version_is_a_discrepancy_and_osv_wins() -> None:
    (f,) = compute("pkg:pypi/synthetic-pkg@2.0", "CVE-2099-0001")  # fixed in 2.0, so local says no
    assert f.discrepancy == {"only_osv": True, "local_verdict": "NOT_AFFECTED"}
    assert f.canonical_vuln_id == "CVE-2099-0001"  # the finding exists regardless


def test_unknown_local_verdict_is_not_a_discrepancy() -> None:
    (f,) = compute("pkg:pypi/synthetic-pkg@1.0", "OSV-2099-0006")  # GIT-only record
    assert f.discrepancy is None


def test_no_records_no_findings() -> None:
    assert compute("pkg:pypi/synthetic-pkg@1.0") == []


def test_severity_falls_back_to_another_record_of_the_group() -> None:
    (f,) = compute(
        "pkg:pypi/synthetic-pkg@1.5", "GHSA-synt-0001-aaaa", "PYSEC-2099-1"
    )  # no CVE record held
    assert f.canonical_vuln_id == "CVE-2099-0001" and f.severity_label is None


def test_separate_groups_stay_separate() -> None:
    found = compute("pkg:pypi/synthetic-pkg@1.0", "CVE-2099-0001", "OSV-2099-0006")
    assert [f.canonical_vuln_id for f in found] == ["CVE-2099-0001", "OSV-2099-0006"]
