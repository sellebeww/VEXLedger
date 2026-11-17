# Copyright (c) 2026 Vassel Goleyu. MIT License.
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import event

from vexledger.db.models import User, VexStatement
from vexledger.db.repos.findings import FindingRepository
from vexledger.domain.model import FindingState as S

from .seed import NOW, seed_finding, seed_release

pytestmark = pytest.mark.integration

QUERY_AT = NOW + timedelta(days=30)
IMPACT = "The vulnerable function is never reachable here."


def row(finding_id, status="under_investigation", **kw):  # type: ignore[no-untyped-def]
    base = dict(
        id=uuid.uuid4(),
        finding_id=finding_id,
        canonical_vuln_id="x",
        component_ref="x",
        status=status,
        created_by="t",
        created_at=NOW,
    )
    if status == "not_affected":
        base.update(justification="component_not_present", impact_statement=IMPACT)
    base.update(kw)
    return VexStatement(**base)


async def build_dataset(factory):  # type: ignore[no-untyped-def]
    """Findings in every state; the dict maps vulnerability id to the expected state."""
    seeded = await seed_release(factory, ["a", "b"])
    user_id = uuid.uuid4()
    async with factory() as s, s.begin():
        s.add(User(id=user_id, username=f"u-{user_id.hex[:8]}", password_hash="x", role="analyst"))
    spec = [  # vuln, component, severity, kwargs for finding, statements
        ("V-UNTRIAGED", "a", "HIGH", {}, []),
        ("V-REVIEW", "a", "LOW", {"needs_review": True}, []),
        (
            "V-TRIAGED",
            "b",
            "CRITICAL",
            {},
            [{"status": "not_affected", "valid_until": NOW + timedelta(days=400)}],
        ),
        (
            "V-EXPIRED",
            "b",
            "MODERATE",
            {},
            [{"status": "not_affected", "valid_until": NOW + timedelta(days=10)}],
        ),
        (
            "V-INHERITED",
            "a",
            None,
            {},
            [{"status": "not_affected", "valid_until": NOW + timedelta(days=400), "inherit": True}],
        ),
        ("V-WITHDRAWN", "b", "HIGH", {"withdrawn": True}, []),
        (
            "V-INVESTIGATING",
            "a",
            "high",
            {"assignee_id": user_id},
            [{"status": "under_investigation", "valid_until": NOW + timedelta(days=400)}],
        ),
        (
            "V-CHAIN",
            "b",
            "LOW",
            {},
            [
                {"status": "under_investigation", "valid_until": NOW + timedelta(days=10)},
                {"status": "affected", "action_statement": "Upgrade.", "valid_until": None},
            ],
        ),
        (
            "V-NEVER",
            "a",
            "LOW",
            {},
            [{"status": "affected", "action_statement": "Upgrade.", "valid_until": None}],
        ),
    ]
    expected = {
        "V-UNTRIAGED": S.UNTRIAGED,
        "V-REVIEW": S.NEEDS_REVIEW,
        "V-TRIAGED": S.TRIAGED,
        "V-EXPIRED": S.EXPIRED,
        "V-INHERITED": S.INHERITED,
        "V-WITHDRAWN": S.WITHDRAWN,
        "V-INVESTIGATING": S.TRIAGED,
        "V-CHAIN": S.TRIAGED,
        "V-NEVER": S.TRIAGED,
    }
    source_id = None
    async with factory() as s, s.begin():
        repo = FindingRepository(s)
        for vuln, comp, sev, fkw, stmts in spec:
            f = await repo.create(
                release_id=seeded.release.id,
                component=seeded.components[comp],
                canonical_vuln_id=vuln,
                alias_ids=[],
                severity_label=sev,
                **fkw,
            )
            prev = None
            for st in stmts:
                st = dict(st)
                inherit = st.pop("inherit", False)
                r = row(
                    f.id, supersedes_id=prev, inherited_from_id=source_id if inherit else None, **st
                )
                s.add(r)
                await s.flush()
                prev = r.id
                source_id = (
                    source_id or r.id
                )  # the first statement written is the inheritance source
    return seeded, expected, user_id


async def listed(factory, seeded, **kw):  # type: ignore[no-untyped-def]
    async with factory() as s:
        return await FindingRepository(s).list_for_release(seeded.release.id, now=QUERY_AT, **kw)


async def test_states_match_the_domain_rules_for_every_row(factory) -> None:  # type: ignore[no-untyped-def]
    seeded, expected, _ = await build_dataset(factory)
    page = await listed(factory, seeded, page_size=100)
    assert page.total == len(expected)
    assert {v.finding.canonical_vuln_id: v.state for v in page.items} == expected
    by_id = {v.finding.canonical_vuln_id: v for v in page.items}
    assert by_id["V-INVESTIGATING"].investigating
    assert not by_id["V-TRIAGED"].investigating
    chain = by_id["V-CHAIN"].statement
    assert (
        chain is not None and chain.status.value == "affected"
    )  # the newest row of the chain decides


async def test_state_filter(factory) -> None:  # type: ignore[no-untyped-def]
    seeded, _, _ = await build_dataset(factory)
    open_states = frozenset({S.UNTRIAGED, S.NEEDS_REVIEW, S.EXPIRED})
    page = await listed(factory, seeded, states=open_states)
    assert {v.finding.canonical_vuln_id for v in page.items} == {
        "V-UNTRIAGED",
        "V-REVIEW",
        "V-EXPIRED",
    }
    assert page.total == 3


async def test_severity_ecosystem_and_assignee_filters(factory) -> None:  # type: ignore[no-untyped-def]
    seeded, _, user_id = await build_dataset(factory)
    high = await listed(factory, seeded, severity="HIGH")
    assert {v.finding.canonical_vuln_id for v in high.items} == {
        "V-UNTRIAGED",
        "V-WITHDRAWN",
        "V-INVESTIGATING",
    }  # case-insensitive
    assert (await listed(factory, seeded, ecosystem="PyPI")).total == 9
    assert (await listed(factory, seeded, ecosystem="npm")).total == 0
    mine = await listed(factory, seeded, assignee_id=user_id)
    assert [v.finding.canonical_vuln_id for v in mine.items] == ["V-INVESTIGATING"]
    combined = await listed(factory, seeded, severity="LOW", states=frozenset({S.TRIAGED}))
    assert {v.finding.canonical_vuln_id for v in combined.items} == {"V-CHAIN", "V-NEVER"}


async def test_sorting_and_pagination_are_stable(factory) -> None:  # type: ignore[no-untyped-def]
    seeded, _, _ = await build_dataset(factory)
    by_vuln = await listed(factory, seeded, sort="vulnerability", page_size=100)
    ids = [v.finding.canonical_vuln_id for v in by_vuln.items]
    assert ids == sorted(ids)
    desc = await listed(factory, seeded, sort="vulnerability", descending=True, page_size=100)
    assert [v.finding.canonical_vuln_id for v in desc.items] == ids[::-1]
    by_sev = await listed(factory, seeded, sort="severity", page_size=100)
    assert by_sev.items[0].finding.canonical_vuln_id == "V-TRIAGED"  # CRITICAL first
    assert by_sev.items[-1].severity_label is None  # unknown severity last
    pages = [
        await listed(factory, seeded, sort="vulnerability", page=p, page_size=4)
        for p in (1, 2, 3, 4)
    ]
    assert [len(p.items) for p in pages] == [4, 4, 1, 0]
    assert [v.finding.canonical_vuln_id for p in pages for v in p.items] == ids
    assert all(p.total == 9 for p in pages)
    by_state = await listed(factory, seeded, sort="state", page_size=100)
    assert by_state.items[0].state is S.UNTRIAGED


async def test_invalid_paging_is_rejected(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["a"])
    for kw in ({"page": 0}, {"page_size": 0}, {"page_size": 501}):
        with pytest.raises(ValueError, match="page"):
            await listed(factory, seeded, **kw)


async def test_listing_uses_a_single_query_regardless_of_size(factory, engine) -> None:  # type: ignore[no-untyped-def]
    seeded, _, _ = await build_dataset(factory)
    statements: list[str] = []

    def record(conn, cursor, statement, *a):  # type: ignore[no-untyped-def]
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    try:
        page = await listed(factory, seeded, page_size=100)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record)
    assert page.total == 9
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) == 1, selects


async def test_releases_do_not_leak_into_each_other(factory) -> None:  # type: ignore[no-untyped-def]
    one = await seed_release(factory, ["a"])
    two = await seed_release(factory, ["a"])
    await seed_finding(factory, one, "a")
    assert (await listed(factory, two)).total == 0
    assert (await listed(factory, one)).total == 1


async def test_sorting_by_component_and_creating_without_a_ref_fails(factory) -> None:  # type: ignore[no-untyped-def]
    from vexledger.db.models import Component

    seeded, _, _ = await build_dataset(factory)
    by_component = await listed(factory, seeded, sort="component", page_size=100)
    refs = [v.finding.component_ref for v in by_component.items]
    assert refs == sorted(refs)
    async with factory() as s:
        with pytest.raises(ValueError, match="component_ref"):
            await FindingRepository(s).create(
                release_id=seeded.release.id,
                component=Component(name="x", no_purl=True),
                canonical_vuln_id="V-X",
                alias_ids=[],
            )
