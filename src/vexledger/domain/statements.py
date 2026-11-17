# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Statement validation, successors, expiry and the supersedes chain."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from vexledger.domain.errors import (
    ChainError,
    ErrorCode,
    NaiveDatetimeError,
    StatementValidationError,
)
from vexledger.domain.model import Evidence, EvidenceKind, Finding, Justification, Statement, Status

MIN_IMPACT_CHARS = 20
MIN_STATUS_NOTES_CHARS = 10


@dataclass(frozen=True)
class ValidityPolicy:
    """Default validity in days per status; None means the statement never expires. Per product."""

    not_affected_days: int | None = 180
    under_investigation_days: int | None = 14
    affected_days: int | None = None
    fixed_days: int | None = None

    def days_for(self, status: Status) -> int | None:
        return {
            Status.NOT_AFFECTED: self.not_affected_days,
            Status.UNDER_INVESTIGATION: self.under_investigation_days,
            Status.AFFECTED: self.affected_days,
            Status.FIXED: self.fixed_days,
        }[status]


DEFAULT_POLICY = ValidityPolicy()


@dataclass(frozen=True)
class StatementDraft:
    """What the analyst submits. valid_until=None means: use the policy default for the status."""

    status: Status
    justification: Justification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    status_notes: str | None = None
    evidence: tuple[Evidence, ...] = ()
    valid_until: datetime | None = None


@dataclass(frozen=True)
class _Content:
    status: Status
    justification: Justification | None
    impact_statement: str | None
    action_statement: str | None
    status_notes: str | None
    evidence: frozenset[Evidence]
    valid_until: datetime | None


def _aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise NaiveDatetimeError(f"{name} must be timezone-aware")
    return value


def _clean(text: str | None) -> str | None:
    text = text.strip() if text is not None else None
    return text or None


def default_valid_until(
    status: Status, now: datetime, policy: ValidityPolicy = DEFAULT_POLICY
) -> datetime | None:
    days = policy.days_for(status)
    return None if days is None else _aware(now, "now") + timedelta(days=days)


def is_expired(statement: Statement, now: datetime) -> bool:
    """Expired exactly at valid_until (the boundary instant already counts as expired)."""
    _aware(now, "now")
    return statement.valid_until is not None and now >= _aware(statement.valid_until, "valid_until")


def _is_http_url(value: str) -> bool:
    """Lowercase http(s):// with a host and no whitespace (the database CHECK is `^https?://`)."""
    if not value.startswith(("http://", "https://")) or any(c.isspace() for c in value):
        return False
    return bool(urlsplit(value).hostname)


def _check_evidence(items: tuple[Evidence, ...]) -> None:
    for ev in items:
        problem = None
        if not ev.value.strip():
            problem = "empty value"
        elif ev.kind is EvidenceKind.LINK and not _is_http_url(ev.value):
            problem = "link must be an absolute http or https URL"
        elif ev.kind is EvidenceKind.FILE and (
            ev.sha256 is None
            or len(ev.sha256) != 64
            or any(c not in "0123456789abcdef" for c in ev.sha256)
        ):
            problem = "file evidence needs a lowercase hex sha256"
        if problem:
            raise StatementValidationError(
                ErrorCode.EVIDENCE_INVALID, f"evidence: {problem}", "evidence"
            )


def _resolve(draft: StatementDraft, now: datetime, policy: ValidityPolicy) -> _Content:
    valid_until = (
        draft.valid_until
        if draft.valid_until is not None
        else default_valid_until(draft.status, now, policy)
    )
    return _Content(
        status=draft.status,
        justification=draft.justification,
        impact_statement=_clean(draft.impact_statement),
        action_statement=_clean(draft.action_statement),
        status_notes=_clean(draft.status_notes),
        evidence=frozenset(draft.evidence),
        valid_until=valid_until,
    )


def _content_of(statement: Statement) -> _Content:
    return _Content(
        statement.status,
        statement.justification,
        statement.impact_statement,
        statement.action_statement,
        statement.status_notes,
        frozenset(statement.evidence),
        statement.valid_until,
    )


def validate_new_statement(
    current_active: Statement | None,
    draft: StatementDraft,
    now: datetime,
    policy: ValidityPolicy = DEFAULT_POLICY,
    *,
    allow_identical: bool = False,
) -> None:
    """Raise StatementValidationError (stable code) unless the draft may be recorded now.

    `allow_identical` lets an analyst confirm an inherited statement whose content (for example
    a never-expiring `affected`) would otherwise be an identical no-op.
    """
    _aware(now, "now")
    c = _resolve(draft, now, policy)
    err = StatementValidationError

    if c.status is Status.NOT_AFFECTED:
        if c.justification is None:
            raise err(
                ErrorCode.JUSTIFICATION_REQUIRED,
                "not_affected needs a justification",
                "justification",
            )
        if c.impact_statement is None or len(c.impact_statement) < MIN_IMPACT_CHARS:
            raise err(
                ErrorCode.IMPACT_STATEMENT_REQUIRED,
                f"impact_statement needs at least {MIN_IMPACT_CHARS} characters",
                "impact_statement",
            )
    elif c.justification is not None:
        raise err(
            ErrorCode.JUSTIFICATION_NOT_ALLOWED,
            "justification is only valid for not_affected",
            "justification",
        )
    if c.status is Status.AFFECTED and c.action_statement is None:
        raise err(
            ErrorCode.ACTION_STATEMENT_REQUIRED,
            "affected needs an action_statement",
            "action_statement",
        )
    if c.status is Status.FIXED and (
        c.status_notes is None or len(c.status_notes) < MIN_STATUS_NOTES_CHARS
    ):
        raise err(
            ErrorCode.STATUS_NOTES_REQUIRED,
            f"fixed needs status_notes of at least {MIN_STATUS_NOTES_CHARS} characters",
            "status_notes",
        )
    _check_evidence(draft.evidence)
    if c.valid_until is not None and _aware(c.valid_until, "valid_until") <= now:
        raise err(
            ErrorCode.VALID_UNTIL_NOT_IN_FUTURE, "valid_until must be in the future", "valid_until"
        )
    if (
        not allow_identical
        and current_active is not None
        and not is_expired(current_active, now)
        and _content_of(current_active) == c
    ):
        raise err(ErrorCode.NO_OP, "identical to the active statement")


def build_successor(
    finding: Finding,
    latest: Statement | None,
    draft: StatementDraft,
    now: datetime,
    *,
    new_id: str,
    created_by: str,
    policy: ValidityPolicy = DEFAULT_POLICY,
    allow_identical: bool = False,
) -> Statement:
    """Validate and build the next row. `latest` may be expired and is still superseded."""
    active = latest if latest is not None and not is_expired(latest, now) else None
    validate_new_statement(active, draft, now, policy, allow_identical=allow_identical)
    c = _resolve(draft, now, policy)
    return Statement(
        id=new_id,
        canonical_vuln_id=finding.canonical_vuln_id,
        component_ref=finding.component_ref,
        status=c.status,
        created_at=now,
        created_by=created_by,
        justification=c.justification,
        impact_statement=c.impact_statement,
        action_statement=c.action_statement,
        status_notes=c.status_notes,
        evidence=tuple(sorted(c.evidence, key=lambda e: (e.kind, e.value, e.sha256 or ""))),
        valid_until=c.valid_until,
        supersedes_id=latest.id if latest is not None else None,
    )


def find_head(statements: Sequence[Statement]) -> Statement | None:
    """Newest row of a chain; ChainError on duplicate ids, dangling links, forks or cycles."""
    if not statements:
        return None
    by_id = {s.id: s for s in statements}
    if len(by_id) != len(statements):
        raise ChainError("duplicate statement id")
    superseded: set[str] = set()
    for s in statements:
        if s.supersedes_id is None:
            continue
        if s.supersedes_id not in by_id:
            raise ChainError(f"{s.id} supersedes unknown {s.supersedes_id}")
        if s.supersedes_id in superseded:
            raise ChainError(f"{s.supersedes_id} is superseded twice")
        superseded.add(s.supersedes_id)
    heads = [s for s in statements if s.id not in superseded]
    if len(heads) != 1:
        raise ChainError("chain has no single head (cycle or fork)")
    seen: set[str] = set()
    node: Statement | None = heads[0]
    while node is not None:
        if node.id in seen:
            raise ChainError("cycle in supersedes chain")
        seen.add(node.id)
        node = by_id.get(node.supersedes_id) if node.supersedes_id else None
    if len(seen) != len(statements):
        raise ChainError("chain is not connected")
    return heads[0]
