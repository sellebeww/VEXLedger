# Copyright (c) 2026 Vassel Goleyu. MIT License.
import asyncio
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from vexledger.db.errors import ConflictError, NotFoundError
from vexledger.db.models import AuditLog, Evidence, EvidenceFile, VexStatement
from vexledger.db.repos.statements import create_successor_statement, head_statement
from vexledger.domain.errors import ErrorCode, StatementValidationError
from vexledger.domain.model import Evidence as DomainEvidence
from vexledger.domain.model import EvidenceKind, Justification, Status
from vexledger.domain.statements import StatementDraft, ValidityPolicy

from .seed import NOW, seed_finding, seed_release

pytestmark = pytest.mark.integration

IMPACT = "The vulnerable function is never reachable here."
NA = StatementDraft(
    Status.NOT_AFFECTED,
    justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
    impact_statement=IMPACT,
)
UI = StatementDraft(Status.UNDER_INVESTIGATION)


async def create(factory, finding_id, draft, expected, **kw):  # type: ignore[no-untyped-def]
    return await create_successor_statement(
        factory,
        finding_id=finding_id,
        draft=draft,
        expected_head_id=expected,
        actor_id=None,
        actor_name="ann",
        now=kw.pop("now", NOW),
        **kw,
    )


async def count(factory, model, **where):  # type: ignore[no-untyped-def]
    async with factory() as s:
        q = select(func.count()).select_from(model)
        for k, v in where.items():
            q = q.where(getattr(model, k) == v)
        return (await s.execute(q)).scalar_one()


async def test_chain_of_successors_with_evidence_and_audit(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    async with factory() as s, s.begin():
        s.add(
            EvidenceFile(
                storage_name="f" * 32 + ".txt",
                original_name="n.txt",
                sha256="c" * 64,
                size_bytes=5,
                detected_type="txt",
            )
        )
    evidence = (
        DomainEvidence(EvidenceKind.LINK, "https://example.test/analysis"),
        DomainEvidence(EvidenceKind.NOTE, "call graph checked"),
        DomainEvidence(EvidenceKind.FILE, "f" * 32 + ".txt", "c" * 64),
    )
    first = await create(factory, finding.id, UI, None)
    second = await create(factory, finding.id, NA, uuid.UUID(first.id), now=NOW + timedelta(days=1))
    third = await create(
        factory,
        finding.id,
        StatementDraft(**{**NA.__dict__, "evidence": evidence}),
        uuid.UUID(second.id),
        now=NOW + timedelta(days=2),
    )
    assert (first.supersedes_id, second.supersedes_id, third.supersedes_id) == (
        None,
        first.id,
        second.id,
    )
    assert first.valid_until == NOW + timedelta(days=14)  # product default (under_investigation)
    async with factory() as s:
        head = await head_statement(s, finding.id)
        assert head is not None and str(head.id) == third.id
        kinds = sorted(
            (
                await s.execute(select(Evidence.kind).where(Evidence.statement_id == head.id))
            ).scalars()
        )
        assert kinds == ["FILE", "LINK", "NOTE"]
        audit = (
            (
                await s.execute(
                    select(AuditLog)
                    .where(
                        AuditLog.entity_id == str(finding.id), AuditLog.action == "statement.create"
                    )
                    .order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )
    assert len(audit) == 3
    assert audit[0].before is None
    assert audit[1].before is not None and audit[1].before["id"] == first.id
    assert audit[2].after is not None and audit[2].after["supersedes_id"] == second.id


async def test_stale_expectation_is_a_conflict_and_writes_nothing(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    first = await create(factory, finding.id, UI, None)
    with pytest.raises(ConflictError) as exc:
        await create(factory, finding.id, NA, None)  # caller still believes there is no statement
    assert exc.value.current_head_id == uuid.UUID(first.id)
    with pytest.raises(ConflictError):
        await create(factory, finding.id, NA, uuid.uuid4())
    assert await count(factory, VexStatement, finding_id=finding.id) == 1
    assert await count(factory, AuditLog, entity_id=str(finding.id)) == 1


async def test_two_analysts_at_once_exactly_one_wins(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    first = await create(factory, finding.id, UI, None)
    head = uuid.UUID(first.id)
    other = StatementDraft(Status.AFFECTED, action_statement="Upgrade now.")
    results = await asyncio.gather(
        create(factory, finding.id, NA, head, now=NOW + timedelta(days=1)),
        create(factory, finding.id, other, head, now=NOW + timedelta(days=1)),
        return_exceptions=True,
    )
    wins = [r for r in results if not isinstance(r, BaseException)]
    conflicts = [r for r in results if isinstance(r, ConflictError)]
    assert len(wins) == 1 and len(conflicts) == 1
    assert await count(factory, VexStatement, finding_id=finding.id) == 2
    async with factory() as s:
        head_row = await head_statement(s, finding.id)
    assert head_row is not None and str(head_row.id) == wins[0].id  # type: ignore[union-attr]


async def test_many_concurrent_first_statements_yield_one_root(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    results = await asyncio.gather(
        *(create(factory, finding.id, UI, None) for _ in range(6)), return_exceptions=True
    )
    assert sum(not isinstance(r, BaseException) for r in results) == 1
    assert all(isinstance(r, ConflictError) for r in results if isinstance(r, BaseException))
    assert await count(factory, VexStatement, finding_id=finding.id) == 1


async def test_invalid_drafts_and_noops_write_nothing(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    with pytest.raises(StatementValidationError) as exc:
        await create(factory, finding.id, StatementDraft(Status.NOT_AFFECTED), None)
    assert exc.value.code is ErrorCode.JUSTIFICATION_REQUIRED
    first = await create(factory, finding.id, UI, None)
    with pytest.raises(StatementValidationError) as noop:
        await create(factory, finding.id, UI, uuid.UUID(first.id))
    assert noop.value.code is ErrorCode.NO_OP
    assert await count(factory, VexStatement, finding_id=finding.id) == 1
    assert await count(factory, AuditLog, entity_id=str(finding.id)) == 1


async def test_unknown_file_evidence_is_rejected(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    bad = StatementDraft(
        Status.UNDER_INVESTIGATION,
        evidence=(DomainEvidence(EvidenceKind.FILE, "0" * 32 + ".txt", "d" * 64),),
    )
    with pytest.raises(StatementValidationError) as exc:
        await create(factory, finding.id, bad, None)
    assert exc.value.code is ErrorCode.EVIDENCE_INVALID
    assert await count(factory, VexStatement, finding_id=finding.id) == 0


async def test_missing_finding_is_not_found(factory) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(NotFoundError):
        await create(factory, uuid.uuid4(), UI, None)


async def test_product_validity_policy_is_applied(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    policy = ValidityPolicy(not_affected_days=7, under_investigation_days=2)
    st = await create(factory, finding.id, UI, None, policy=policy)
    assert st.valid_until == NOW + timedelta(days=2)


async def test_evidence_is_loaded_back_for_no_op_detection_and_next_successor(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    async with factory() as s, s.begin():
        s.add(
            EvidenceFile(
                storage_name="e" * 32 + ".pdf",
                original_name="r.pdf",
                sha256="e" * 64,
                size_bytes=9,
                detected_type="pdf",
            )
        )
    evidence = (
        DomainEvidence(EvidenceKind.FILE, "e" * 32 + ".pdf", "e" * 64),
        DomainEvidence(EvidenceKind.LINK, "https://example.test/x"),
    )
    draft = StatementDraft(
        Status.UNDER_INVESTIGATION, evidence=evidence, valid_until=NOW + timedelta(days=5)
    )
    first = await create(factory, finding.id, draft, None)
    # Identical content, evidence included (loaded from the database), is a no-op.
    with pytest.raises(StatementValidationError) as exc:
        await create(factory, finding.id, draft, uuid.UUID(first.id))
    assert exc.value.code is ErrorCode.NO_OP
    # Replacing the evidence is a real change and chains onto the first statement.
    changed = StatementDraft(
        Status.UNDER_INVESTIGATION, evidence=evidence[:1], valid_until=NOW + timedelta(days=5)
    )
    second = await create(factory, finding.id, changed, uuid.UUID(first.id))
    assert second.supersedes_id == first.id
    assert [e.kind for e in second.evidence] == [EvidenceKind.FILE]
