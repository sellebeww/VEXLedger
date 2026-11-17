# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Finding aggregate: creation and the derived-state listing."""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import and_, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from vexledger.db.mapping import finding_to_domain, statement_to_domain
from vexledger.db.models import Component, VexStatement
from vexledger.db.models import Finding as FindingRow
from vexledger.db.repos.statements import statement_evidence
from vexledger.domain.model import Finding, FindingState, Statement, TriagedFinding
from vexledger.domain.states import derive_finding_state, is_under_investigation

SortKey = Literal["state", "severity", "vulnerability", "component"]
_STATE_ORDER = {s: i for i, s in enumerate(FindingState)}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class FindingView:
    id: uuid.UUID
    finding: Finding
    statement: Statement | None  # newest row of the chain; evidence is not loaded here
    state: FindingState
    investigating: bool
    severity_label: str | None
    ecosystem: str | None
    assignee_id: uuid.UUID | None
    withdrawn: bool


@dataclass(frozen=True)
class FindingPage:
    items: tuple[FindingView, ...]
    total: int
    page: int
    page_size: int


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        *,
        release_id: uuid.UUID,
        component: Component,
        canonical_vuln_id: str,
        alias_ids: list[str],
        severity_label: str | None = None,
        withdrawn: bool = False,
        needs_review: bool = False,
        assignee_id: uuid.UUID | None = None,
    ) -> FindingRow:
        if component.component_ref is None:
            raise ValueError("cannot create a finding for a component without a component_ref")
        row = FindingRow(
            release_id=release_id,
            component_id=component.id,
            component_ref=component.component_ref,
            canonical_vuln_id=canonical_vuln_id,
            alias_ids=sorted(set(alias_ids) - {canonical_vuln_id}),
            severity_label=severity_label,
            withdrawn=withdrawn,
            needs_review=needs_review,
            assignee_id=assignee_id,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_for_release(
        self,
        release_id: uuid.UUID,
        *,
        now: datetime,
        states: frozenset[FindingState] | None = None,
        severity: str | None = None,
        ecosystem: str | None = None,
        assignee_id: uuid.UUID | None = None,
        sort: SortKey = "state",
        descending: bool = False,
        page: int = 1,
        page_size: int = 50,
    ) -> FindingPage:
        """One query for the release (findings, components, newest statements; no N+1).

        State is derived by the domain function, so SQL never re-implements table 5.3. Filters
        that do not depend on state run in SQL; state filter, sort and paging run on the result.
        """
        if page < 1 or not 1 <= page_size <= 500:
            raise ValueError("page must be >= 1 and page_size within 1..500")
        successor = aliased(VexStatement)
        head = aliased(VexStatement)
        query = (
            select(FindingRow, Component, head)
            .join(Component, Component.id == FindingRow.component_id)
            .outerjoin(
                head,
                and_(
                    head.finding_id == FindingRow.id,
                    ~exists().where(successor.supersedes_id == head.id),
                ),
            )
            .where(FindingRow.release_id == release_id)
        )
        if severity is not None:
            query = query.where(func.lower(FindingRow.severity_label) == severity.lower())
        if ecosystem is not None:
            query = query.where(Component.ecosystem == ecosystem)
        if assignee_id is not None:
            query = query.where(FindingRow.assignee_id == assignee_id)

        views: list[FindingView] = []
        for row, component, head_row in (await self.session.execute(query)).all():
            domain_finding = finding_to_domain(row, component)
            statement = statement_to_domain(head_row) if head_row is not None else None
            state = derive_finding_state(domain_finding, statement, row.withdrawn, now)
            if states is not None and state not in states:
                continue
            views.append(
                FindingView(
                    id=row.id,
                    finding=domain_finding,
                    statement=statement,
                    state=state,
                    investigating=is_under_investigation(state, statement),
                    severity_label=row.severity_label,
                    ecosystem=component.ecosystem,
                    assignee_id=row.assignee_id,
                    withdrawn=row.withdrawn,
                )
            )
        views.sort(
            key=lambda v: (
                _sort_key(v, sort),
                v.finding.canonical_vuln_id,
                v.finding.component_ref,
                str(v.id),
            )
        )
        if descending:
            views.reverse()
        start = (page - 1) * page_size
        return FindingPage(tuple(views[start : start + page_size]), len(views), page, page_size)

    async def triaged_for_release(self, release_id: uuid.UUID) -> list[TriagedFinding]:
        """Every finding with the newest statement of its chain, evidence included (2 queries)."""
        successor = aliased(VexStatement)
        head = aliased(VexStatement)
        rows = (
            await self.session.execute(
                select(FindingRow, Component, head)
                .join(Component, Component.id == FindingRow.component_id)
                .outerjoin(
                    head,
                    and_(
                        head.finding_id == FindingRow.id,
                        ~exists().where(successor.supersedes_id == head.id),
                    ),
                )
                .where(FindingRow.release_id == release_id)
            )
        ).all()
        evidence = await statement_evidence(
            self.session, [h.id for _, _, h in rows if h is not None]
        )
        return [
            TriagedFinding(
                finding_to_domain(row, component),
                statement_to_domain(h, evidence.get(h.id, [])) if h is not None else None,
                row.withdrawn,
            )
            for row, component, h in rows
        ]


def _sort_key(view: FindingView, sort: SortKey) -> tuple[int, str]:
    if sort == "state":
        return (_STATE_ORDER[view.state], "")
    if sort == "severity":
        label = (view.severity_label or "").upper()
        return (_SEVERITY_ORDER.get(label, len(_SEVERITY_ORDER)), label)
    if sort == "vulnerability":
        return (0, view.finding.canonical_vuln_id)
    return (0, view.finding.component_ref)
