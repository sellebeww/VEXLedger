# Copyright (c) 2026 Vassel Goleyu. MIT License.
import asyncio
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from vexledger.db.errors import NotFoundError
from vexledger.db.models import AuditLog, Release
from vexledger.db.repos.exports import ExportRepository
from vexledger.db.repos.products import ProductRepository, ReleaseRepository, validity_policy
from vexledger.db.repos.users import UserRepository
from vexledger.db.repos.vulns import VulnerabilityRepository

from .seed import NOW, seed_release

pytestmark = pytest.mark.integration


def osv(modified: str, summary: str = "s") -> dict[str, object]:
    return {
        "id": "SYNTH-1",
        "modified": modified,
        "aliases": ["CVE-2099-1"],
        "summary": summary,
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
        "database_specific": {"severity": "HIGH"},
    }


async def test_product_defaults_audit_and_lookup(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory)
    async with factory() as s:
        product = await ProductRepository(s).get_by_slug(seeded.product.slug)
        policy = validity_policy(product)
        audit = (
            (await s.execute(select(AuditLog).where(AuditLog.entity_id == str(product.id))))
            .scalars()
            .all()
        )
        with pytest.raises(NotFoundError):
            await ProductRepository(s).get_by_slug("nope")
    assert (
        policy.not_affected_days,
        policy.under_investigation_days,
        policy.affected_days,
        policy.fixed_days,
    ) == (180, 14, None, None)
    assert product.inherit_enabled
    assert [a.action for a in audit] == ["product.create"]


async def test_release_ordering_is_sequential_even_when_created_concurrently(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory)

    async def make(version: str) -> None:
        async with factory() as s, s.begin():
            await ReleaseRepository(s).create(
                product_id=seeded.product.id, version=version, actor_id=None
            )

    await asyncio.gather(*(make(f"2.{i}") for i in range(5)))
    async with factory() as s:
        rows = (
            (
                await s.execute(
                    select(Release)
                    .where(Release.product_id == seeded.product.id)
                    .order_by(Release.ordering)
                )
            )
            .scalars()
            .all()
        )
        assert [r.ordering for r in rows] == [1, 2, 3, 4, 5, 6]
        prev = await ReleaseRepository(s).previous(rows[3])
        assert prev is not None and prev.id == rows[2].id
        assert await ReleaseRepository(s).previous(rows[0]) is None


async def test_release_status_changes_are_audited_and_validated(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory)
    async with factory() as s, s.begin():
        await ReleaseRepository(s).set_status(
            seeded.release.id, "MATCH_FAILED", error="OSV unreachable"
        )
    async with factory() as s:
        rel = await s.get(Release, seeded.release.id)
        assert rel is not None and (rel.status, rel.match_error) == (
            "MATCH_FAILED",
            "OSV unreachable",
        )
        actions = (
            (
                await s.execute(
                    select(AuditLog.action)
                    .where(AuditLog.entity_id == str(rel.id))
                    .order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )
        assert actions == ["release.create", "release.status"]
        with pytest.raises(ValueError, match="unknown release status"):
            await ReleaseRepository(s).set_status(rel.id, "DONE")
        with pytest.raises(NotFoundError):
            await ReleaseRepository(s).set_status(uuid.uuid4(), "MATCHED")


async def test_users_are_created_with_audit_and_found_case_insensitively(factory) -> None:  # type: ignore[no-untyped-def]
    name = f"Eve-{uuid.uuid4().hex[:8]}"
    async with factory() as s, s.begin():
        user = await UserRepository(s).create(username=name, password_hash="hash", role="viewer")
    async with factory() as s:
        found = await UserRepository(s).get_by_username(name.upper())
        assert found is not None and found.id == user.id
        assert await UserRepository(s).get_by_username("nobody-here") is None
        assert (
            await s.execute(select(AuditLog).where(AuditLog.entity_id == str(user.id)))
        ).scalar_one().action == "user.create"


async def test_vulnerability_upsert_keeps_the_newest_record(factory) -> None:  # type: ignore[no-untyped-def]
    uid = f"SYNTH-{uuid.uuid4().hex[:8]}"
    newer, older = osv("2099-02-01T00:00:00Z", "new"), osv("2099-01-01T00:00:00Z", "old")
    for rec in (newer, older):
        rec["id"] = uid
    async with factory() as s, s.begin():
        await VulnerabilityRepository(s).upsert(newer, NOW)
        await VulnerabilityRepository(s).upsert(older, NOW)  # stale: must not overwrite
    async with factory() as s:
        (v,) = await VulnerabilityRepository(s).get_many([uid])
    assert v.raw["summary"] == "new"
    assert v.aliases == ["CVE-2099-1"]
    assert v.severity == {"entries": [["CVSS_V3", "CVSS:3.1/AV:N"]], "database_specific": "HIGH"}
    assert v.withdrawn is None
    async with factory() as s, s.begin():
        wd = {**newer, "modified": "2099-03-01T00:00:00Z", "withdrawn": "2099-03-01T00:00:00Z"}
        await VulnerabilityRepository(s).upsert(wd, NOW)
    async with factory() as s:
        (v,) = await VulnerabilityRepository(s).get_many([uid])
    assert v.withdrawn is not None


async def test_vulnerability_without_modified_is_refused(factory) -> None:  # type: ignore[no-untyped-def]
    async with factory() as s:
        with pytest.raises(ValueError, match="modified"):
            await VulnerabilityRepository(s).upsert({"id": "X-1"}, NOW)


async def test_purl_cache_respects_the_ttl(factory) -> None:  # type: ignore[no-untyped-def]
    purl = f"pkg:pypi/cache-{uuid.uuid4().hex[:8]}@1"
    async with factory() as s, s.begin():
        await VulnerabilityRepository(s).cache_put(purl, ["B-2", "A-1", "A-1"], NOW)
    async with factory() as s:
        repo = VulnerabilityRepository(s)
        assert await repo.cache_get_fresh([purl], NOW + timedelta(hours=5)) == {
            purl: ["A-1", "B-2"]
        }
        assert (
            await repo.cache_get_fresh([purl], NOW + timedelta(hours=6)) == {}
        )  # exactly the TTL: stale
        assert await repo.cache_get_fresh([purl, "pkg:pypi/other@1"], NOW) == {purl: ["A-1", "B-2"]}
    async with factory() as s, s.begin():
        await VulnerabilityRepository(s).cache_put(
            purl, [], NOW + timedelta(hours=7)
        )  # refreshed, now clean
    async with factory() as s:
        assert await VulnerabilityRepository(s).cache_get_fresh(
            [purl], NOW + timedelta(hours=8)
        ) == {purl: []}


async def test_export_history(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory)
    rid = seeded.release.id
    async with factory() as s:
        assert await ExportRepository(s).last(rid) is None
    for version, doc in ((1, b"one"), (2, b"two")):
        async with factory() as s, s.begin():
            await ExportRepository(s).record(
                release_id=rid,
                version=version,
                content_sha256=f"{version}" * 64,
                document=doc,
                actor_id=None,
            )
    async with factory() as s:
        last = await ExportRepository(s).last(rid)
    assert last is not None and (last.version, last.document) == (2, b"two")
    with pytest.raises(IntegrityError, match="uq_vex_exports_release_version"):
        async with factory() as s, s.begin():
            await ExportRepository(s).record(
                release_id=rid, version=2, content_sha256="x" * 64, document=b"dup", actor_id=None
            )
