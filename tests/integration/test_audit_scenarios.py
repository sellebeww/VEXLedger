# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""multi-alias merging and three-release inheritance, written
independently of test_pipeline.py. All OSV records here are SYNTHETIC (hand-assembled)."""

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from tests.unit.test_sbom_import import comp
from vexledger.db.models import Finding as FindingRow
from vexledger.db.models import VexStatement
from vexledger.db.repos.findings import FindingRepository
from vexledger.db.repos.statements import create_successor_statement
from vexledger.domain.model import FindingState as S
from vexledger.domain.model import Justification, Status
from vexledger.domain.statements import StatementDraft
from vexledger.services.matching import match_release

from .pipeline_helpers import NOW, TTL, create_release, import_components

pytestmark = pytest.mark.integration


def pypi_record(rid: str, aliases: list[str], *, name: str = "alias-pkg") -> dict[str, Any]:
    return {
        "id": rid,
        "aliases": aliases,
        "modified": "2099-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": name},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "99.0"}]}
                ],
            }
        ],
    }


async def listed(factory, release, now=NOW):  # type: ignore[no-untyped-def]
    async with factory() as s:
        page = await FindingRepository(s).list_for_release(release.id, now=now, page_size=100)
    return {(v.finding.canonical_vuln_id, v.finding.component_ref): v for v in page.items}


async def test_transitive_alias_chain_across_three_records_is_one_finding(factory, fake, osv):  # type: ignore[no-untyped-def]
    """PYSEC -> GHSA -> CVE where only the neighbours declare each other: ONE finding."""
    _, release = await create_release(factory)
    await import_components(factory, release, [comp("alias-pkg", "1.0")])
    fake.records["PYSEC-2099-9"] = pypi_record("PYSEC-2099-9", ["GHSA-aaaa-bbbb-cccc"])
    fake.records["GHSA-aaaa-bbbb-cccc"] = pypi_record(
        "GHSA-aaaa-bbbb-cccc", ["PYSEC-2099-9", "CVE-2099-5001"]
    )
    fake.records["CVE-2099-5001"] = pypi_record("CVE-2099-5001", [])
    fake.by_purl["pkg:pypi/alias-pkg@1.0"] = [
        "PYSEC-2099-9",
        "GHSA-aaaa-bbbb-cccc",
        "CVE-2099-5001",
    ]
    await match_release(factory, osv, release.id, now=NOW, cache_ttl=TTL)
    found = await listed(factory, release)
    assert list(found) == [("CVE-2099-5001", "pypi/alias-pkg@1.0")]
    aliases = set(found[("CVE-2099-5001", "pypi/alias-pkg@1.0")].finding.aliases)
    assert {"PYSEC-2099-9", "GHSA-aaaa-bbbb-cccc"} <= aliases


async def test_two_cves_in_one_group_pick_the_smallest_and_keep_both(factory, fake, osv):  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    await import_components(factory, release, [comp("alias-pkg", "1.0")])
    fake.records["GHSA-dddd-eeee-ffff"] = pypi_record(
        "GHSA-dddd-eeee-ffff", ["CVE-2099-5009", "CVE-2099-5002"]
    )
    fake.by_purl["pkg:pypi/alias-pkg@1.0"] = ["GHSA-dddd-eeee-ffff"]
    await match_release(factory, osv, release.id, now=NOW, cache_ttl=TTL)
    found = await listed(factory, release)
    assert list(found) == [("CVE-2099-5002", "pypi/alias-pkg@1.0")]
    view = found[("CVE-2099-5002", "pypi/alias-pkg@1.0")]
    assert {"CVE-2099-5009", "GHSA-dddd-eeee-ffff"} <= set(view.finding.aliases)


async def test_same_vulnerability_on_two_versions_is_two_findings(factory, fake, osv):  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    await import_components(factory, release, [comp("alias-pkg", "1.0"), comp("alias-pkg", "1.5")])
    fake.records["CVE-2099-5003"] = pypi_record("CVE-2099-5003", [])
    for v in ("1.0", "1.5"):
        fake.by_purl[f"pkg:pypi/alias-pkg@{v}"] = ["CVE-2099-5003"]
    await match_release(factory, osv, release.id, now=NOW, cache_ttl=TTL)
    assert sorted(await listed(factory, release)) == [
        ("CVE-2099-5003", "pypi/alias-pkg@1.0"),
        ("CVE-2099-5003", "pypi/alias-pkg@1.5"),
    ]


async def test_three_release_chain_inherits_without_extending_validity(factory, fake, osv):  # type: ignore[no-untyped-def]
    product, r1 = await create_release(factory, version="1.0.0")
    base = [comp("alias-pkg", "1.0"), comp("other-pkg", "3.0")]
    await import_components(factory, r1, base)
    fake.records["CVE-2099-5004"] = pypi_record("CVE-2099-5004", [])
    fake.records["CVE-2099-5005"] = pypi_record("CVE-2099-5005", [], name="other-pkg")
    fake.by_purl["pkg:pypi/alias-pkg@1.0"] = ["CVE-2099-5004"]
    fake.by_purl["pkg:pypi/other-pkg@3.0"] = ["CVE-2099-5005"]
    await match_release(factory, osv, r1.id, now=NOW, cache_ttl=TTL)
    triage = StatementDraft(
        Status.NOT_AFFECTED,
        justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
        impact_statement="The vulnerable function is never reachable from our code.",
    )
    original = {}
    for key, view in (await listed(factory, r1)).items():
        original[key[0]] = await create_successor_statement(
            factory,
            finding_id=view.id,
            draft=triage,
            expected_head_id=None,
            actor_id=None,
            actor_name="ann",
            now=NOW,
        )
    _, r2 = await create_release(factory, product, "2.0.0")
    await import_components(factory, r2, base)
    t2 = NOW + timedelta(days=10)
    await match_release(factory, osv, r2.id, now=t2, cache_ttl=TTL)
    assert {v.state for v in (await listed(factory, r2, t2)).values()} == {S.INHERITED}
    # release 3: alias-pkg identical, other-pkg bumped to 3.1 (OSV still says vulnerable)
    _, r3 = await create_release(factory, product, "3.0.0")
    await import_components(factory, r3, [comp("alias-pkg", "1.0"), comp("other-pkg", "3.1")])
    fake.by_purl["pkg:pypi/other-pkg@3.1"] = ["CVE-2099-5005"]
    t3 = NOW + timedelta(days=20)
    await match_release(factory, osv, r3.id, now=t3, cache_ttl=TTL)
    f3 = await listed(factory, r3, t3)
    kept = f3[("CVE-2099-5004", "pypi/alias-pkg@1.0")]
    moved = f3[("CVE-2099-5005", "pypi/other-pkg@3.1")]
    assert kept.state is S.INHERITED and moved.state is S.NEEDS_REVIEW
    assert kept.statement is not None
    # validity is release 1's original, never refreshed along the chain
    assert kept.statement.valid_until == original["CVE-2099-5004"].valid_until
    async with factory() as s:
        rows = (
            (
                await s.execute(
                    select(VexStatement)
                    .join(FindingRow, FindingRow.id == VexStatement.finding_id)
                    .where(FindingRow.release_id.in_([r1.id, r2.id, r3.id]))
                )
            )
            .scalars()
            .all()
        )
    inherited_rows = [r for r in rows if r.inherited_from_id is not None]
    assert len(inherited_rows) == 3  # r2: two; r3: one (alias-pkg); NEEDS_REVIEW adds none
    assert all(r.supersedes_id is None for r in inherited_rows)


async def test_a_listed_record_that_cannot_be_loaded_fails_the_match_not_hides_it(  # type: ignore[no-untyped-def]
    factory, fake, osv
):
    """The only record for a vulnerability answers 404: the release must NOT be MATCHED."""
    from vexledger.db.models import Release
    from vexledger.osv.errors import OsvProtocolError

    _, release = await create_release(factory)
    await import_components(factory, release, [comp("alias-pkg", "1.0")])
    fake.records["CVE-2099-5100"] = pypi_record("CVE-2099-5100", [])
    fake.by_purl["pkg:pypi/alias-pkg@1.0"] = ["CVE-2099-5100"]
    fake.missing.add("CVE-2099-5100")
    with pytest.raises(OsvProtocolError):
        await match_release(factory, osv, release.id, now=NOW, cache_ttl=TTL)
    async with factory() as s:
        row = await s.get(Release, release.id)
    assert row is not None and row.status == "MATCH_FAILED"
    assert "CVE-2099-5100" in (row.match_error or "")
    assert await listed(factory, release) == {}
