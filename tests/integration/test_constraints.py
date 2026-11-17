# Copyright (c) 2026 Vassel Goleyu. MIT License.
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from vexledger.db.models import Component, Evidence, EvidenceFile, Release, User, VexStatement
from vexledger.db.repos.components import ComponentRepository

from .seed import NOW, component, seed_finding, seed_release

pytestmark = pytest.mark.integration


def stmt(finding_id: uuid.UUID, **kw) -> VexStatement:  # type: ignore[no-untyped-def]
    base = dict(
        id=uuid.uuid4(),
        finding_id=finding_id,
        canonical_vuln_id="CVE-2099-0001",
        component_ref="pypi/lib@1.0",
        status="under_investigation",
        created_by="t",
        created_at=NOW,
    )
    base.update(kw)
    return VexStatement(**base)


async def test_finding_is_unique_per_release_component_ref_and_vulnerability(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    await seed_finding(factory, seeded, "lib")
    with pytest.raises(IntegrityError, match="uq_findings_release_ref_vuln"):
        await seed_finding(factory, seeded, "lib")
    await seed_finding(
        factory, seeded, "lib", vuln="CVE-2099-0002"
    )  # another vulnerability is fine


@pytest.mark.parametrize(
    ("fields", "constraint"),
    [
        ({"status": "maybe"}, "ck_statements_status"),
        ({"status": "not_affected"}, "ck_statements_not_affected_fields"),
        (
            {
                "status": "not_affected",
                "justification": "component_not_present",
                "impact_statement": "too short",
            },
            "ck_statements_not_affected_fields",
        ),
        ({"status": "affected"}, "ck_statements_affected_fields"),
        ({"status": "fixed", "status_notes": "short"}, "ck_statements_fixed_fields"),
        (
            {"justification": "component_not_present"},
            "ck_statements_justification_only_not_affected",
        ),
        (
            {"status": "not_affected", "justification": "bogus", "impact_statement": "x" * 25},
            "ck_statements_justification",
        ),
    ],
)
async def test_statement_checks_back_up_the_domain_rules(factory, fields, constraint) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    with pytest.raises(IntegrityError, match=constraint):
        async with factory() as s, s.begin():
            s.add(stmt(finding.id, **fields))


async def test_a_chain_cannot_fork_and_has_one_root(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    root = stmt(finding.id)
    async with factory() as s, s.begin():
        s.add(root)
    with pytest.raises(IntegrityError, match="uq_statements_one_root"):
        async with factory() as s, s.begin():
            s.add(stmt(finding.id))
    async with factory() as s, s.begin():
        s.add(stmt(finding.id, supersedes_id=root.id))
    with pytest.raises(IntegrityError, match="uq_statements_supersedes"):
        async with factory() as s, s.begin():
            s.add(stmt(finding.id, supersedes_id=root.id))


async def test_evidence_shape_and_link_scheme(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    st = stmt(finding.id)
    async with factory() as s, s.begin():
        s.add(st)
    bad = [
        Evidence(statement_id=st.id, kind="LINK", value="javascript:alert(1)"),
        Evidence(statement_id=st.id, kind="LINK", value="ftp://example.test/x"),
        Evidence(statement_id=st.id, kind="NOTE", value="   "),
        Evidence(statement_id=st.id, kind="FILE", value="x"),
        Evidence(statement_id=st.id, kind="PIGEON", value="x"),
    ]
    for ev in bad:
        with pytest.raises(IntegrityError):
            async with factory() as s, s.begin():
                s.add(ev)
    async with factory() as s, s.begin():
        f = EvidenceFile(
            storage_name=uuid.uuid4().hex + ".txt",
            original_name="a.txt",
            sha256="a" * 64,
            size_bytes=3,
            detected_type="txt",
        )
        s.add(f)
        await s.flush()
        s.add_all(
            [
                Evidence(statement_id=st.id, kind="LINK", value="https://example.test/a"),
                Evidence(statement_id=st.id, kind="NOTE", value="text"),
                Evidence(statement_id=st.id, kind="FILE", evidence_file_id=f.id),
            ]
        )


async def test_release_version_and_ordering_are_unique_per_product(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory)
    for kw in ({"version": "1.0.0", "ordering": 99}, {"version": "9.9.9", "ordering": 1}):
        with pytest.raises(IntegrityError):
            async with factory() as s, s.begin():
                s.add(Release(product_id=seeded.product.id, **kw))
    with pytest.raises(IntegrityError, match="ck_releases_status"):
        async with factory() as s, s.begin():
            s.add(Release(product_id=seeded.product.id, version="2", ordering=2, status="DONE"))


async def test_component_constraints(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    rid = seeded.release.id
    with pytest.raises(IntegrityError, match="uq_components_release_ref"):
        async with factory() as s, s.begin():
            s.add(component(rid, "lib"))  # same component_ref twice (duplicates must be merged)
    with pytest.raises(IntegrityError, match="uq_components_one_root"):
        async with factory() as s, s.begin():
            s.add(component(rid, "other-root", is_root=True))
    with pytest.raises(IntegrityError, match="ck_components_purl"):
        async with factory() as s, s.begin():
            s.add(Component(release_id=rid, name="x"))  # neither a purl nor the NO_PURL flag
    async with factory() as s, s.begin():  # NO_PURL components are stored, never dropped
        s.add(Component(release_id=rid, name="mystery", no_purl=True))
        s.add(Component(release_id=rid, name="other", no_purl=True))
    with pytest.raises(IntegrityError, match="ck_components_no_purl"):
        async with factory() as s, s.begin():
            s.add(Component(release_id=rid, name="bad", no_purl=True, purl_normal="pkg:pypi/x@1"))


async def test_edges_reject_self_loops_and_duplicates(factory) -> None:  # type: ignore[no-untyped-def]
    from vexledger.db.models import ComponentEdge

    seeded = await seed_release(factory, ["a"], [("app", "a")])
    a, app = seeded.components["a"], seeded.components["app"]
    with pytest.raises(IntegrityError, match="ck_edges_no_self_loop"):
        async with factory() as s, s.begin():
            await ComponentRepository(s).add_all(
                [], [ComponentEdge(parent_id=a.id, child_id=a.id, release_id=seeded.release.id)]
            )
    with pytest.raises(IntegrityError):
        async with factory() as s, s.begin():
            await ComponentRepository(s).add_all(
                [], [ComponentEdge(parent_id=app.id, child_id=a.id, release_id=seeded.release.id)]
            )


async def test_usernames_are_unique_case_insensitively_and_roles_are_checked(factory) -> None:  # type: ignore[no-untyped-def]
    name = f"Ann-{uuid.uuid4().hex[:8]}"
    async with factory() as s, s.begin():
        s.add(User(username=name, password_hash="x", role="analyst"))
    with pytest.raises(IntegrityError, match="uq_users_username_lower"):
        async with factory() as s, s.begin():
            s.add(User(username=name.lower(), password_hash="x", role="viewer"))
    with pytest.raises(IntegrityError, match="ck_users_role"):
        async with factory() as s, s.begin():
            s.add(User(username=name + "2", password_hash="x", role="root"))


async def test_foreign_keys_are_enforced(factory) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(IntegrityError):
        async with factory() as s, s.begin():
            await s.execute(
                text(
                    "INSERT INTO sboms (release_id, sha256, size_bytes, raw) VALUES (:r, 'x', 1, '{}')"
                ),
                {"r": uuid.uuid4()},
            )
