# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Statement aggregate: the atomic append of the next row in a finding's chain."""

import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime

from sqlalchemy import exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import aliased

from vexledger.db.errors import ConflictError, NotFoundError
from vexledger.db.mapping import finding_to_domain, statement_to_domain
from vexledger.db.models import Component, EvidenceFile, VexStatement
from vexledger.db.models import Evidence as EvidenceRow
from vexledger.db.models import Finding as FindingRow
from vexledger.db.repos.audit import append_audit
from vexledger.domain.errors import DomainError, ErrorCode, StatementValidationError
from vexledger.domain.model import Evidence, EvidenceKind, Statement
from vexledger.domain.statements import (
    DEFAULT_POLICY,
    StatementDraft,
    ValidityPolicy,
    build_successor,
)


async def head_statement(session: AsyncSession, finding_id: uuid.UUID) -> VexStatement | None:
    """The newest row of the chain: the one no other statement supersedes."""
    successor = aliased(VexStatement)
    result = await session.execute(
        select(VexStatement).where(
            VexStatement.finding_id == finding_id,
            ~exists().where(successor.supersedes_id == VexStatement.id),
        )
    )
    return result.scalar_one_or_none()


async def statement_evidence(
    session: AsyncSession, statement_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, list[tuple[EvidenceRow, EvidenceFile | None]]]:
    """Evidence of many statements in one query."""
    result = await session.execute(
        select(EvidenceRow, EvidenceFile)
        .outerjoin(EvidenceFile, EvidenceFile.id == EvidenceRow.evidence_file_id)
        .where(EvidenceRow.statement_id.in_(statement_ids))
        .order_by(EvidenceRow.id)
    )
    out: dict[uuid.UUID, list[tuple[EvidenceRow, EvidenceFile | None]]] = {}
    for ev, file in result.all():
        out.setdefault(ev.statement_id, []).append((ev, file))
    return out


async def _resolve_files(
    session: AsyncSession, evidence: Sequence[Evidence]
) -> dict[str, EvidenceFile]:
    names = [e.value for e in evidence if e.kind is EvidenceKind.FILE]
    if not names:
        return {}
    rows = (
        await session.execute(select(EvidenceFile).where(EvidenceFile.storage_name.in_(names)))
    ).scalars()
    files = {f.storage_name: f for f in rows}
    for e in evidence:
        if e.kind is EvidenceKind.FILE and (
            e.value not in files or files[e.value].sha256 != e.sha256
        ):
            raise StatementValidationError(
                ErrorCode.EVIDENCE_INVALID,
                "file evidence is unknown or its hash differs",
                "evidence",
            )
    return files


async def append_successor(
    session: AsyncSession,
    *,
    finding_id: uuid.UUID,
    draft: StatementDraft,
    expected_head_id: uuid.UUID | None,
    check_head: bool,
    actor_id: uuid.UUID | None,
    actor_name: str,
    now: datetime,
    policy: ValidityPolicy = DEFAULT_POLICY,
    reason: str | None = None,
    allow_identical: bool = False,
) -> Statement:
    """Validate and append the next statement inside the caller's transaction.

    The finding row is locked first, so two analysts editing the same finding are serialized.
    With `check_head`, `expected_head_id` is the statement the caller saw as current (None: none
    yet); if the chain moved on, ConflictError is raised and nothing is written. Unique indexes
    on supersedes_id and on the chain root are a second line of defence.
    """
    found = (
        await session.execute(
            select(FindingRow, Component)
            .join(Component, Component.id == FindingRow.component_id)
            .where(FindingRow.id == finding_id)
            .with_for_update(of=FindingRow)
        )
    ).one_or_none()
    if found is None:
        raise NotFoundError(f"finding {finding_id} not found")
    finding_row, component = found
    head = await head_statement(session, finding_id)
    if check_head and (head.id if head else None) != expected_head_id:
        raise ConflictError("the finding changed since it was read", head.id if head else None)
    head_domain = None
    if head is not None:
        ev = (await statement_evidence(session, [head.id])).get(head.id, [])
        head_domain = statement_to_domain(head, ev)

    new_id = uuid.uuid4()
    built = build_successor(
        finding_to_domain(finding_row, component),
        head_domain,
        draft,
        now,
        new_id=str(new_id),
        created_by=actor_name,
        policy=policy,
        allow_identical=allow_identical,
    )
    files = await _resolve_files(session, built.evidence)
    session.add(
        VexStatement(
            id=new_id,
            finding_id=finding_id,
            canonical_vuln_id=built.canonical_vuln_id,
            component_ref=built.component_ref,
            status=built.status.value,
            justification=built.justification.value if built.justification else None,
            impact_statement=built.impact_statement,
            action_statement=built.action_statement,
            status_notes=built.status_notes,
            created_by=built.created_by,
            created_at=built.created_at,
            valid_until=built.valid_until,
            supersedes_id=head.id if head else None,
        )
    )
    try:
        await session.flush()
        for e in built.evidence:
            if e.kind is EvidenceKind.FILE:
                session.add(
                    EvidenceRow(
                        statement_id=new_id, kind="FILE", evidence_file_id=files[e.value].id
                    )
                )
            else:
                session.add(EvidenceRow(statement_id=new_id, kind=e.kind.value, value=e.value))
        append_audit(
            session,
            actor_id=actor_id,
            action="statement.create",
            entity_type="finding",
            entity_id=str(finding_id),
            before=_summary(head) if head else None,
            after={
                "id": str(new_id),
                "status": built.status.value,
                "supersedes_id": str(head.id) if head else None,
            },
            reason=reason,
        )
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError("the finding changed since it was read") from exc
    return built


async def create_successor_statement(
    factory: async_sessionmaker[AsyncSession],
    *,
    finding_id: uuid.UUID,
    draft: StatementDraft,
    expected_head_id: uuid.UUID | None,
    actor_id: uuid.UUID | None,
    actor_name: str,
    now: datetime,
    policy: ValidityPolicy = DEFAULT_POLICY,
    reason: str | None = None,
    check_head: bool = True,
    allow_identical: bool = False,
) -> Statement:
    """One statement in its own transaction (see `append_successor`)."""
    async with factory() as session, session.begin():
        return await append_successor(
            session,
            finding_id=finding_id,
            draft=draft,
            expected_head_id=expected_head_id,
            check_head=check_head,
            actor_id=actor_id,
            actor_name=actor_name,
            now=now,
            policy=policy,
            reason=reason,
            allow_identical=allow_identical,
        )


class BulkItemError(Exception):
    """One finding of a bulk triage failed; the whole transaction is rolled back."""

    def __init__(self, finding_id: uuid.UUID, cause: Exception) -> None:
        super().__init__(str(cause))
        self.finding_id = finding_id
        self.cause = cause


async def create_successors_bulk(
    factory: async_sessionmaker[AsyncSession],
    *,
    finding_ids: Sequence[uuid.UUID],
    draft: StatementDraft,
    actor_id: uuid.UUID | None,
    actor_name: str,
    now: datetime,
    policies: Mapping[uuid.UUID, ValidityPolicy],
    reason: str | None = None,
) -> list[Statement]:
    """One statement per finding, all or nothing, each audited. Findings are locked in id order."""
    out: list[Statement] = []
    async with factory() as session, session.begin():
        for fid in sorted(finding_ids):
            try:
                out.append(
                    await append_successor(
                        session,
                        finding_id=fid,
                        draft=draft,
                        expected_head_id=None,
                        check_head=False,
                        actor_id=actor_id,
                        actor_name=actor_name,
                        now=now,
                        policy=policies.get(fid, DEFAULT_POLICY),
                        reason=reason,
                    )
                )
            except (DomainError, IntegrityError) as exc:
                raise BulkItemError(fid, exc) from exc
    return out


def _summary(row: VexStatement) -> dict[str, str | None]:
    return {
        "id": str(row.id),
        "status": row.status,
        "valid_until": row.valid_until.isoformat() if row.valid_until else None,
    }


async def insert_inherited_statement(
    session: AsyncSession,
    *,
    finding_id: uuid.UUID,
    statement: Statement,
    actor_id: uuid.UUID | None,
) -> None:
    """Write an INHERIT plan item as the chain root, in the caller's transaction."""
    if statement.inherited_from_id is None:
        raise ValueError("an inherited statement must reference its source")
    files = await _resolve_files(session, statement.evidence)
    new_id = uuid.UUID(statement.id)
    session.add(
        VexStatement(
            id=new_id,
            finding_id=finding_id,
            canonical_vuln_id=statement.canonical_vuln_id,
            component_ref=statement.component_ref,
            status=statement.status.value,
            justification=statement.justification.value if statement.justification else None,
            impact_statement=statement.impact_statement,
            action_statement=statement.action_statement,
            status_notes=statement.status_notes,
            created_by=statement.created_by,
            created_at=statement.created_at,
            valid_until=statement.valid_until,
            inherited_from_id=uuid.UUID(statement.inherited_from_id),
        )
    )
    await session.flush()
    for e in statement.evidence:
        if e.kind is EvidenceKind.FILE:
            session.add(
                EvidenceRow(statement_id=new_id, kind="FILE", evidence_file_id=files[e.value].id)
            )
        else:
            session.add(EvidenceRow(statement_id=new_id, kind=e.kind.value, value=e.value))
    append_audit(
        session,
        actor_id=actor_id,
        action="statement.inherit",
        entity_type="finding",
        entity_id=str(finding_id),
        after={"id": str(new_id), "inherited_from_id": statement.inherited_from_id},
    )
    await session.flush()
