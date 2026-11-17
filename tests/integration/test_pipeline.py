# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""match_release end to end against a fake OSV (synthetic records) and a real Postgres."""

import asyncio
import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from vexledger.db.models import AuditLog, EvidenceFile, PurlQueryCache, Release, VexStatement
from vexledger.db.models import Finding as FindingRow
from vexledger.db.repos.findings import FindingRepository
from vexledger.db.repos.statements import create_successor_statement
from vexledger.domain.model import FindingState as S
from vexledger.domain.model import Justification, Status
from vexledger.domain.statements import StatementDraft
from vexledger.osv.errors import OsvProtocolError, OsvUnavailableError
from vexledger.services.matching import ReleaseNotReadyError, match_release

from .osv_fake import BASE
from .pipeline_helpers import (
    NOW,
    TTL,
    components,
    create_release,
    import_components,
    serve_standard,
)

pytestmark = pytest.mark.integration


async def run(factory, osv, release, now=NOW):  # type: ignore[no-untyped-def]
    return await match_release(factory, osv, release.id, now=now, cache_ttl=TTL)


async def release_row(factory, release):  # type: ignore[no-untyped-def]
    async with factory() as s:
        return await s.get(Release, release.id)


async def findings(factory, release, **kw):  # type: ignore[no-untyped-def]
    async with factory() as s:
        page = await FindingRepository(s).list_for_release(
            release.id, now=kw.pop("now", NOW), page_size=100, **kw
        )
    return {(v.finding.canonical_vuln_id, v.finding.component_ref): v for v in page.items}


async def counts(factory, release):  # type: ignore[no-untyped-def]
    async with factory() as s:
        nf = (
            await s.execute(
                select(func.count())
                .select_from(FindingRow)
                .where(FindingRow.release_id == release.id)
            )
        ).scalar_one()
        ns = (
            await s.execute(
                select(func.count())
                .select_from(VexStatement)
                .join(FindingRow, FindingRow.id == VexStatement.finding_id)
                .where(FindingRow.release_id == release.id)
            )
        ).scalar_one()
    return nf, ns


async def prepared(factory, fake, **kw):  # type: ignore[no-untyped-def]
    product, release = await create_release(factory, **kw)
    await import_components(factory, release, components())
    serve_standard(fake)
    return product, release


async def test_first_match_builds_the_expected_findings(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    summary = await run(factory, osv, release)
    assert (await release_row(factory, release)).status == "MATCHED"
    assert (summary.components_matched, summary.unique_purls) == (
        5,
        5,
    )  # deb and no-purl components are not matched
    assert (
        summary.findings_created,
        summary.findings_updated,
        summary.withdrawn,
        summary.discrepancies,
    ) == (6, 0, 1, 1)
    got = await findings(factory, release)
    assert len(got) == 6
    triple = got[("CVE-2099-0001", "pypi/synthetic-pkg@1.5")]
    assert triple.finding.aliases == (
        "GHSA-synt-0001-aaaa",
        "PYSEC-2099-1",
    )  # three OSV records, one finding
    assert (
        triple.state is S.UNTRIAGED
        and triple.severity_label == "HIGH"
        and triple.ecosystem == "PyPI"
    )
    boundary = got[
        ("CVE-2099-0001", "pypi/synthetic-pkg@2.0")
    ]  # OSV says affected exactly at the fixed version
    assert boundary.state is S.UNTRIAGED
    async with factory() as s:
        row = (await s.execute(select(FindingRow).where(FindingRow.id == boundary.id))).scalar_one()
        assert row.match_discrepancy == {"only_osv": True, "local_verdict": "NOT_AFFECTED"}
    assert got[("GHSA-synt-wd-0005", "pypi/synthetic-pkg@2.0")].state is S.WITHDRAWN
    # a group that has a CVE among its ids is named by the smallest CVE, even without a CVE record
    assert ("CVE-2099-0003", "maven/org.synthetic/lib@2.0.1") in got
    assert ("CVE-2099-0004", "golang/github.com/Synthetic/Mod@v1.3.0") in got
    assert fake.batch_calls == 1  # unique purls in one batch
    assert sorted(fake.detail_calls) == sorted(set(fake.detail_calls))  # every record fetched once


async def test_running_twice_does_not_duplicate_anything(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    await run(factory, osv, release)
    before = await counts(factory, release)
    again = await run(factory, osv, release, NOW + timedelta(hours=1))
    assert (again.findings_created, again.findings_updated) == (0, 6)
    assert await counts(factory, release) == before == (6, 0)
    assert (
        fake.batch_calls == 1 and len(fake.detail_calls) == 7
    )  # served from the cache and the record store
    assert again.cache_hits == 5


async def test_concurrent_runs_are_safe(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    results = await asyncio.gather(*(run(factory, osv, release) for _ in range(3)))
    assert sum(r.findings_created for r in results) == 6
    assert (await counts(factory, release))[0] == 6


async def test_cache_expires_after_the_ttl_but_details_are_not_refetched(
    factory, fake, osv
) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    await run(factory, osv, release)
    await run(factory, osv, release, NOW + TTL - timedelta(seconds=1))
    assert fake.batch_calls == 1
    await run(factory, osv, release, NOW + TTL + timedelta(seconds=1))
    assert fake.batch_calls == 2
    assert len(fake.detail_calls) == 7  # same modified timestamps, nothing to refetch


async def test_a_newer_modified_record_is_refetched(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    await run(factory, osv, release)
    fake.records["GHSA-synt-npm-0002"] = {
        **fake.records["GHSA-synt-npm-0002"],
        "modified": "2099-06-01T00:00:00Z",
    }
    await run(factory, osv, release, NOW + TTL + timedelta(seconds=1))
    assert fake.detail_calls.count("GHSA-synt-npm-0002") == 2
    assert fake.detail_calls.count("CVE-2099-0001") == 1


async def test_a_vulnerability_published_later_becomes_a_new_untriaged_finding(
    factory, fake, osv
) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    await run(factory, osv, release)
    fake.serve("pkg:npm/%40synthetic/lib@1.0.1", "GHSA-synt-npm-0002", "OSV-2099-0006")
    later = await run(factory, osv, release, NOW + TTL + timedelta(hours=1))
    assert later.findings_created == 1
    assert (await findings(factory, release))[
        ("OSV-2099-0006", "npm/%40synthetic/lib@1.0.1")
    ].state is S.UNTRIAGED


async def test_second_release_inherits_and_flags_changed_components(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    product, r1 = await prepared(factory, fake)
    await run(factory, osv, r1)
    f1 = await findings(factory, r1)
    npm, maven = (
        f1[("GHSA-synt-npm-0002", "npm/%40synthetic/lib@1.0.1")],
        f1[("CVE-2099-0003", "maven/org.synthetic/lib@2.0.1")],
    )
    triage = StatementDraft(
        Status.NOT_AFFECTED,
        justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
        impact_statement="The vulnerable function is never called here.",
    )
    originals = {}
    for view in (npm, maven):
        originals[view.id] = await create_successor_statement(
            factory,
            finding_id=view.id,
            draft=triage,
            expected_head_id=None,
            actor_id=None,
            actor_name="ann",
            now=NOW,
        )
    # release 2: the npm component is identical, the maven component moved to another version
    _, r2 = await create_release(factory, product, "2.0.0")
    await import_components(factory, r2, components(maven_version="2.0.2"))
    serve_standard(fake, maven_version="2.0.2")
    later = NOW + timedelta(days=10)
    summary = await run(factory, osv, r2, later)
    assert (summary.inherited, summary.needs_review) == (1, 1)
    f2 = await findings(factory, r2, now=later)
    inherited = f2[("GHSA-synt-npm-0002", "npm/%40synthetic/lib@1.0.1")]
    review = f2[("CVE-2099-0003", "maven/org.synthetic/lib@2.0.2")]
    assert inherited.state is S.INHERITED and review.state is S.NEEDS_REVIEW
    st = inherited.statement
    original = originals[npm.id]
    assert (
        st is not None
        and st.inherited_from_id == original.id
        and st.valid_until == original.valid_until
    )  # never extended
    assert (
        st.created_by == "system" and st.status is Status.NOT_AFFECTED and st.supersedes_id is None
    )
    assert f2[("CVE-2099-0001", "pypi/synthetic-pkg@1.5")].state is S.UNTRIAGED
    # running again changes nothing: no second inherited statement, no second review flag
    before = await counts(factory, r2)
    again = await run(factory, osv, r2, later + timedelta(hours=1))
    assert await counts(factory, r2) == before
    assert again.inherited == 0 and again.needs_review == 1
    async with factory() as s:
        audits = (
            await s.execute(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    AuditLog.action == "finding.needs_review", AuditLog.entity_id == str(review.id)
                )
            )
        ).scalar_one()
    assert audits == 1


async def test_inheritance_can_be_switched_off_per_product(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    product, r1 = await prepared(factory, fake, inherit=False)
    await run(factory, osv, r1)
    npm = (await findings(factory, r1))[("GHSA-synt-npm-0002", "npm/%40synthetic/lib@1.0.1")]
    await create_successor_statement(
        factory,
        finding_id=npm.id,
        draft=StatementDraft(Status.UNDER_INVESTIGATION),
        expected_head_id=None,
        actor_id=None,
        actor_name="ann",
        now=NOW,
    )
    _, r2 = await create_release(factory, product, "2.0.0")
    await import_components(factory, r2, components())
    summary = await run(factory, osv, r2, NOW + timedelta(days=1))
    assert (summary.inherited, summary.needs_review) == (0, 0)
    assert (await findings(factory, r2, now=NOW + timedelta(days=1)))[
        ("GHSA-synt-npm-0002", "npm/%40synthetic/lib@1.0.1")
    ].state is S.UNTRIAGED


async def test_an_expired_statement_is_not_inherited(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    product, r1 = await prepared(factory, fake)
    await run(factory, osv, r1)
    npm = (await findings(factory, r1))[("GHSA-synt-npm-0002", "npm/%40synthetic/lib@1.0.1")]
    await create_successor_statement(
        factory,
        finding_id=npm.id,
        draft=StatementDraft(Status.UNDER_INVESTIGATION),
        expected_head_id=None,
        actor_id=None,
        actor_name="ann",
        now=NOW,
    )  # 14 days
    _, r2 = await create_release(factory, product, "2.0.0")
    await import_components(factory, r2, components())
    summary = await run(factory, osv, r2, NOW + timedelta(days=30))
    assert summary.inherited == 0


# failure modes


async def test_osv_down_marks_the_release_failed_and_never_shows_zero_findings(
    factory, fake, osv
) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    fake.down = True
    with pytest.raises(OsvUnavailableError):
        await run(factory, osv, release)
    row = await release_row(factory, release)
    assert row.status == "MATCH_FAILED" and "OsvUnavailableError" in (row.match_error or "")
    assert (await counts(factory, release)) == (0, 0)  # no findings, and the status says why
    assert osv.metrics.counters["match_failures"] == 1
    fake.down = False
    summary = await run(factory, osv, release, NOW + timedelta(minutes=5))
    row = await release_row(factory, release)
    assert row.status == "MATCHED" and row.match_error is None and summary.findings_created == 6


async def test_failure_after_a_successful_match_keeps_the_old_findings_but_flags_the_release(
    factory, fake, osv
) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    await run(factory, osv, release)
    fake.down = True
    with pytest.raises(OsvUnavailableError):
        await run(factory, osv, release, NOW + TTL + timedelta(hours=1))
    assert (await release_row(factory, release)).status == "MATCH_FAILED"
    assert (await counts(factory, release))[0] == 6  # earlier findings are untouched


async def test_partial_failure_resumes_from_the_cache(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    fake.failing.add("GO-2099-0004")  # one record cannot be fetched
    with pytest.raises(OsvUnavailableError):
        await run(factory, osv, release)
    assert (await release_row(factory, release)).status == "MATCH_FAILED"
    assert (await counts(factory, release)) == (0, 0)
    assert fake.batch_calls == 1
    fake.failing.clear()
    summary = await run(factory, osv, release, NOW + timedelta(minutes=1))
    assert (await release_row(factory, release)).status == "MATCHED"
    assert summary.findings_created == 6
    assert fake.batch_calls == 1  # the purl answers were cached before the details failed


async def test_a_malformed_osv_response_fails_without_poisoning_the_cache(
    factory, router, osv
) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    await import_components(factory, release, components())
    router.post(BASE + "/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": "garbage"})
    )
    with pytest.raises(OsvProtocolError):
        await run(factory, osv, release)
    row = await release_row(factory, release)
    assert row.status == "MATCH_FAILED" and "OsvProtocolError" in (row.match_error or "")
    async with factory() as s:
        entry = await s.get(PurlQueryCache, "pkg:npm/%40synthetic/lib@1.0.1")
    assert entry is None  # nothing from the bad response was cached


async def test_a_vanished_detail_is_skipped_with_a_note(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await prepared(factory, fake)
    fake.missing.add("PYSEC-2099-1")
    summary = await run(factory, osv, release)
    assert any("PYSEC-2099-1" in n for n in summary.notes)
    row = await release_row(factory, release)
    assert row.status == "MATCHED" and any("PYSEC-2099-1" in n for n in row.match_notes)
    triple = (await findings(factory, release))[("CVE-2099-0001", "pypi/synthetic-pkg@1.5")]
    # the other records still list PYSEC-2099-1 as an alias, so the group keeps it
    assert triple.finding.aliases == ("GHSA-synt-0001-aaaa", "PYSEC-2099-1")
    assert osv.metrics.counters["osv_detail_missing"] == 1


async def test_a_release_without_an_sbom_is_not_matched_and_not_failed(factory, fake, osv) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    with pytest.raises(ReleaseNotReadyError):
        await run(factory, osv, release)
    assert (await release_row(factory, release)).status == "MATCH_PENDING"
    assert fake.batch_calls == 0


async def test_a_release_with_nothing_matchable_is_matched_with_zero_queries(
    factory, fake, osv
) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    from tests.unit.test_sbom_import import comp

    await import_components(
        factory,
        release,
        [comp("curl", "7.0", purl="pkg:deb/debian/curl@7.0"), comp("m", purl=None)],
    )
    summary = await run(factory, osv, release)
    assert (summary.components_matched, summary.findings_created) == (0, 0)
    assert fake.batch_calls == 0
    assert (await release_row(factory, release)).status == "MATCHED"


async def test_missing_release_is_not_found(factory, osv) -> None:  # type: ignore[no-untyped-def]
    from vexledger.db.errors import NotFoundError

    with pytest.raises(NotFoundError):
        await match_release(factory, osv, uuid.uuid4(), now=NOW)


async def test_evidence_of_the_source_statement_is_copied_to_the_inherited_one(
    factory, fake, osv
) -> None:  # type: ignore[no-untyped-def]
    from vexledger.domain.model import Evidence as DomainEvidence
    from vexledger.domain.model import EvidenceKind

    product, r1 = await prepared(factory, fake)
    await run(factory, osv, r1)
    npm = (await findings(factory, r1))[("GHSA-synt-npm-0002", "npm/%40synthetic/lib@1.0.1")]
    async with factory() as s, s.begin():
        s.add(
            EvidenceFile(
                storage_name="d" * 32 + ".txt",
                original_name="n.txt",
                sha256="d" * 64,
                size_bytes=4,
                detected_type="txt",
            )
        )
    ev = (
        DomainEvidence(EvidenceKind.FILE, "d" * 32 + ".txt", "d" * 64),
        DomainEvidence(EvidenceKind.LINK, "https://example.test/a"),
    )
    await create_successor_statement(
        factory,
        finding_id=npm.id,
        draft=StatementDraft(Status.AFFECTED, action_statement="Upgrade soon.", evidence=ev),
        expected_head_id=None,
        actor_id=None,
        actor_name="ann",
        now=NOW,
    )
    _, r2 = await create_release(factory, product, "2.0.0")
    await import_components(factory, r2, components())
    await run(factory, osv, r2, NOW + timedelta(days=1))
    async with factory() as s:
        triaged = await FindingRepository(s).triaged_for_release(r2.id)
    inherited = next(t for t in triaged if t.finding.canonical_vuln_id == "GHSA-synt-npm-0002")
    assert inherited.statement is not None
    assert {(e.kind, e.value) for e in inherited.statement.evidence} == {
        (EvidenceKind.FILE, "d" * 32 + ".txt"),
        (EvidenceKind.LINK, "https://example.test/a"),
    }
