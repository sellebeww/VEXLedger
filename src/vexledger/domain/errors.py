# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Typed domain errors."""

from enum import StrEnum


class DomainError(Exception):
    """Base class for all domain errors."""


class InvalidPurlError(DomainError):
    """The package URL is malformed or violates a per-type rule."""


class InvalidVersionError(DomainError):
    """The version string is not valid for the ecosystem's version scheme."""


class InvalidOsvRecordError(DomainError):
    """The OSV record is structurally unusable (for example it has no id)."""


class NaiveDatetimeError(DomainError):
    """A datetime without timezone was given; all timestamps must be timezone-aware (UTC)."""


class ErrorCode(StrEnum):
    """Stable codes for API and UI. Never rename a value once released."""

    JUSTIFICATION_REQUIRED = "justification_required"
    JUSTIFICATION_NOT_ALLOWED = "justification_not_allowed"
    IMPACT_STATEMENT_REQUIRED = "impact_statement_required"
    ACTION_STATEMENT_REQUIRED = "action_statement_required"
    STATUS_NOTES_REQUIRED = "status_notes_required"
    EVIDENCE_INVALID = "evidence_invalid"
    VALID_UNTIL_NOT_IN_FUTURE = "valid_until_not_in_future"
    NO_OP = "no_op"
    CHAIN_INVALID = "chain_invalid"
    NO_EXPORTABLE_STATEMENTS = "no_exportable_statements"
    DOCUMENT_INVALID = "document_invalid"


class StatementValidationError(DomainError):
    def __init__(self, code: ErrorCode, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.field = field


class ChainError(DomainError):
    """The supersedes chain of a finding is broken (cycle, fork, dangling or duplicate id)."""

    code = ErrorCode.CHAIN_INVALID


class ExportError(DomainError):
    def __init__(self, code: ErrorCode, message: str, problems: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.code = code
        self.problems = problems
