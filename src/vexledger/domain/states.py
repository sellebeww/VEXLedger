# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Derived finding state (table 5.3) and the completeness gate (5.8)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from vexledger.domain.model import Finding, FindingState, Statement, Status, TriagedFinding
from vexledger.domain.statements import is_expired

_OPEN = frozenset({FindingState.UNTRIAGED, FindingState.NEEDS_REVIEW, FindingState.EXPIRED})


def derive_finding_state(
    finding: Finding,
    statement: Statement | None,
    withdrawn: bool,
    now: datetime,
) -> FindingState:
    """`statement` is the newest row of the finding's chain, even when it has expired."""
    if withdrawn:
        return FindingState.WITHDRAWN
    if statement is None:
        return FindingState.NEEDS_REVIEW if finding.needs_review else FindingState.UNTRIAGED
    if is_expired(statement, now):
        return FindingState.EXPIRED
    return (
        FindingState.INHERITED if statement.inherited_from_id is not None else FindingState.TRIAGED
    )


def is_open_for_gate(state: FindingState) -> bool:
    return state in _OPEN


def is_under_investigation(state: FindingState, statement: Statement | None) -> bool:
    """A live under_investigation statement counts as TRIAGED/INHERITED but is reported apart."""
    return (
        statement is not None
        and statement.status is Status.UNDER_INVESTIGATION
        and state in (FindingState.TRIAGED, FindingState.INHERITED)
    )


@dataclass(frozen=True)
class GateSummary:
    total: int
    open_count: int  # UNTRIAGED + NEEDS_REVIEW + EXPIRED
    investigating_count: int  # live under_investigation, reported separately
    open_ids: tuple[tuple[str, str], ...]  # (canonical_vuln_id, component_ref), sorted

    @property
    def complete(self) -> bool:
        """Passes when nothing is open; investigating findings are reported, not blocking."""
        return self.open_count == 0


def gate_summary(findings: Sequence[TriagedFinding], now: datetime) -> GateSummary:
    open_ids: list[tuple[str, str]] = []
    investigating = 0
    for tf in findings:
        state = derive_finding_state(tf.finding, tf.statement, tf.withdrawn, now)
        if is_open_for_gate(state):
            open_ids.append((tf.finding.canonical_vuln_id, tf.finding.component_ref))
        elif is_under_investigation(state, tf.statement):
            investigating += 1
    return GateSummary(len(findings), len(open_ids), investigating, tuple(sorted(open_ids)))
