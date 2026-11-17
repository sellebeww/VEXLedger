# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Pure planning of statement inheritance between consecutive releases."""

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from vexledger.domain.model import Finding, Statement, TriagedFinding
from vexledger.domain.statements import is_expired


class InheritAction(StrEnum):
    INHERIT = "INHERIT"  # copy the statement; state becomes INHERITED
    NEEDS_REVIEW = "NEEDS_REVIEW"  # component changed; old statement is context only
    NONE = "NONE"  # nothing to carry over; state stays UNTRIAGED


@dataclass(frozen=True)
class InheritancePolicy:
    inherit_enabled: bool = True


@dataclass(frozen=True)
class PlanItem:
    finding: Finding  # the finding of the NEW release
    action: InheritAction
    source: Statement | None  # statement inherited from, or shown as context for NEEDS_REVIEW
    valid_until: datetime | None  # INHERIT only: the original value, never extended
    reason: str


def _best(candidates: list[TriagedFinding], finding: Finding) -> TriagedFinding:
    def rank(c: TriagedFinding) -> tuple[bool, datetime, str]:
        assert c.statement is not None  # noqa: S101 - candidates always carry a statement
        return (
            c.finding.canonical_vuln_id == finding.canonical_vuln_id,
            c.statement.created_at,
            c.statement.id,
        )

    return max(candidates, key=rank)


def _plan_one(
    finding: Finding,
    previous: Sequence[TriagedFinding],
    policy: InheritancePolicy,
    now: datetime,
) -> PlanItem:
    if not policy.inherit_enabled:
        return PlanItem(finding, InheritAction.NONE, None, None, "inherit_disabled")
    candidates = [
        p
        for p in previous
        if p.statement is not None
        and not p.withdrawn
        and not is_expired(p.statement, now)
        and p.finding.component_key == finding.component_key
        # Ids are compared through aliases so a record that gained or lost an alias still matches.
        and p.finding.all_vuln_ids & finding.all_vuln_ids
    ]
    if not candidates:
        return PlanItem(finding, InheritAction.NONE, None, None, "no_active_statement")
    identical = [
        c
        for c in candidates
        if c.finding.component_ref == finding.component_ref
        and c.finding.component_hash == finding.component_hash
    ]
    if identical:
        source = _best(identical, finding).statement
        assert source is not None  # noqa: S101
        return PlanItem(
            finding, InheritAction.INHERIT, source, source.valid_until, "component_unchanged"
        )
    same_ref = [c for c in candidates if c.finding.component_ref == finding.component_ref]
    chosen = _best(same_ref or candidates, finding).statement
    return PlanItem(
        finding,
        InheritAction.NEEDS_REVIEW,
        chosen,
        None,
        "component_hash_changed" if same_ref else "component_version_changed",
    )


def plan_inheritance(
    previous: Sequence[TriagedFinding],
    new_findings: Sequence[Finding],
    policy: InheritancePolicy,
    now: datetime,
) -> tuple[PlanItem, ...]:
    """One item per new finding, sorted by (canonical id, component_ref). Deterministic."""
    items = [_plan_one(f, previous, policy, now) for f in new_findings]
    return tuple(
        sorted(items, key=lambda i: (i.finding.canonical_vuln_id, i.finding.component_ref))
    )


def inherited_statement(
    item: PlanItem, *, now: datetime, new_id: str, created_by: str
) -> Statement:
    """Materialize an INHERIT item as a new statement row for the new release."""
    if item.action is not InheritAction.INHERIT or item.source is None:
        raise ValueError("only INHERIT items can be materialized")
    src = item.source
    return replace(
        src,
        id=new_id,
        canonical_vuln_id=item.finding.canonical_vuln_id,
        component_ref=item.finding.component_ref,
        created_at=now,
        created_by=created_by,
        valid_until=item.valid_until,
        supersedes_id=None,
        inherited_from_id=src.id,
    )


def flag_needs_review(item: PlanItem) -> Finding:
    """The new finding with its review flag set, for NEEDS_REVIEW items (unchanged otherwise)."""
    return replace(item.finding, needs_review=item.action is InheritAction.NEEDS_REVIEW)
