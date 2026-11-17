# Copyright (c) 2026 Vassel Goleyu. MIT License.
import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from tests.unit.test_sbom_import import SBOMS, bom, comp
from vexledger.db.errors import ConflictError, NotFoundError
from vexledger.db.models import AuditLog, Component, ComponentEdge, Sbom
from vexledger.db.repos.components import ComponentRepository
from vexledger.services.importer import import_sbom
from vexledger.services.sbom import SbomLimits, SbomSchemaError, SbomTooLargeError

from .pipeline_helpers import create_release

pytestmark = pytest.mark.integration


def doc_bytes(*extra_components: dict) -> bytes:  # type: ignore[type-arg]
    root = comp("app", "1.0.0", purl="pkg:generic/app@1.0.0", ref="app")
    a, b = comp("a", "1.0"), comp("b", "1.0")
    deps = [
        {"ref": "app", "dependsOn": ["a@1.0"]},
        {"ref": "a@1.0", "dependsOn": ["b@1.0", "ghost"]},
    ]
    return json.dumps(
        bom(
            [
                a,
                b,
                comp("nop", purl=None),
                comp("deb", "1", purl="pkg:deb/x/y@1"),
                *extra_components,
            ],
            deps,
            root=root,
        )
    ).encode()


async def count(factory, model, **where):  # type: ignore[no-untyped-def]
    async with factory() as s:
        q = select(func.count()).select_from(model)
        for k, v in where.items():
            q = q.where(getattr(model, k) == v)
        return (await s.execute(q)).scalar_one()


async def test_import_stores_components_edges_flags_and_warnings(factory) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    r = await import_sbom(factory, release_id=release.id, data=doc_bytes(), actor_id=None)
    assert r.created and r.spec_version == "1.6"
    assert (r.component_count, r.edge_count, r.root_present) == (5, 2, True)
    assert (r.no_purl_count, r.unsupported_ecosystem_count) == (1, 1)
    assert r.warning_summary == {
        "no_purl": 1,
        "unsupported_ecosystem": 1,
        "dangling_dependency_ref": 1,
    }
    async with factory() as s:
        rows = {
            c.name: c
            for c in (
                await s.execute(select(Component).where(Component.release_id == release.id))
            ).scalars()
        }
        sbom = (await s.execute(select(Sbom).where(Sbom.release_id == release.id))).scalar_one()
        audit = (
            (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.entity_id == str(release.id), AuditLog.action == "sbom.import"
                    )
                )
            )
            .scalars()
            .all()
        )
        paths = await ComponentRepository(s).shortest_paths(release.id)
    assert (
        rows["app"].is_root
        and rows["a"].component_ref == "pypi/a@1.0"
        and rows["a"].ecosystem == "PyPI"
    )
    assert rows["nop"].no_purl and rows["nop"].component_ref is None
    assert rows["deb"].unsupported_ecosystem and rows["deb"].ecosystem is None
    assert (
        sbom.sha256 == r.sha256
        and sbom.raw["bomFormat"] == "CycloneDX"
        and sbom.spec_version == "1.6"
    )
    assert len(audit) == 1
    assert (
        paths.is_direct(rows["a"].id) is True and paths.is_direct(rows["b"].id) is False
    )  # graph query on imported data


async def test_importing_the_same_sbom_again_returns_the_existing_result(factory) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    data = doc_bytes()
    first = await import_sbom(factory, release_id=release.id, data=data, actor_id=None)
    second = await import_sbom(factory, release_id=release.id, data=data, actor_id=None)
    assert not second.created and second.sbom_id == first.sbom_id
    assert second.warnings == first.warnings and second.warning_summary == first.warning_summary
    assert (second.component_count, second.edge_count) == (first.component_count, first.edge_count)
    assert await count(factory, Component, release_id=release.id) == 5
    assert await count(factory, Sbom, release_id=release.id) == 1


async def test_a_different_sbom_for_the_same_release_is_a_conflict(factory) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    await import_sbom(factory, release_id=release.id, data=doc_bytes(), actor_id=None)
    with pytest.raises(ConflictError, match="different SBOM"):
        await import_sbom(
            factory, release_id=release.id, data=doc_bytes(comp("extra")), actor_id=None
        )
    assert await count(factory, Component, release_id=release.id) == 5


async def test_concurrent_identical_imports_write_once(factory) -> None:  # type: ignore[no-untyped-def]
    import asyncio

    _, release = await create_release(factory)
    results = await asyncio.gather(
        *(
            import_sbom(factory, release_id=release.id, data=doc_bytes(), actor_id=None)
            for _ in range(4)
        )
    )
    assert sum(r.created for r in results) == 1
    assert len({r.sbom_id for r in results}) == 1
    assert await count(factory, Component, release_id=release.id) == 5


async def test_same_sbom_in_two_releases_is_independent(factory) -> None:  # type: ignore[no-untyped-def]
    product, r1 = await create_release(factory)
    _, r2 = await create_release(factory, product, "2.0.0")
    a = await import_sbom(factory, release_id=r1.id, data=doc_bytes(), actor_id=None)
    b = await import_sbom(factory, release_id=r2.id, data=doc_bytes(), actor_id=None)
    assert a.created and b.created and a.sbom_id != b.sbom_id


async def test_bad_input_writes_nothing(factory) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    with pytest.raises(SbomSchemaError):
        await import_sbom(
            factory,
            release_id=release.id,
            data=json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [{"type": "library"}],
                }
            ).encode(),
            actor_id=None,
        )
    with pytest.raises(SbomTooLargeError):
        await import_sbom(
            factory,
            release_id=release.id,
            data=doc_bytes(),
            actor_id=None,
            limits=SbomLimits(max_bytes=10),
        )
    assert await count(factory, Sbom, release_id=release.id) == 0
    assert await count(factory, Component, release_id=release.id) == 0


async def test_unknown_release_is_not_found(factory) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(NotFoundError):
        await import_sbom(factory, release_id=uuid.uuid4(), data=doc_bytes(), actor_id=None)


async def test_real_sbom_imports_end_to_end(factory) -> None:  # type: ignore[no-untyped-def]
    _, release = await create_release(factory)
    data = (SBOMS / "uv-env-1.6-with-root.cdx.json").read_bytes()
    r = await import_sbom(factory, release_id=release.id, data=data, actor_id=None)
    assert r.created and r.root_present and r.component_count >= 90 and r.edge_count > 90
    async with factory() as s:
        paths = await ComponentRepository(s).shortest_paths(release.id)
        edges = (
            await s.execute(
                select(func.count())
                .select_from(ComponentEdge)
                .where(ComponentEdge.release_id == release.id)
            )
        ).scalar_one()
    assert edges == r.edge_count
    assert any(paths.is_direct(cid) for cid in [c for c in paths._depth])  # type: ignore[attr-defined]
    assert datetime.now(UTC).year >= 2026
