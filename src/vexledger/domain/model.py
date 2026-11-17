# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Immutable types for the statement lifecycle."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Status(StrEnum):
    """Exactly the OpenVEX status labels."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class Justification(StrEnum):
    """Exactly the five OpenVEX justification labels (only valid for not_affected)."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class FindingState(StrEnum):
    UNTRIAGED = "UNTRIAGED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    EXPIRED = "EXPIRED"
    INHERITED = "INHERITED"
    TRIAGED = "TRIAGED"
    WITHDRAWN = "WITHDRAWN"


class EvidenceKind(StrEnum):
    LINK = "LINK"  # stored and shown, never fetched by the server
    FILE = "FILE"  # value is the random stored name; sha256 is mandatory
    NOTE = "NOTE"  # plain text


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    value: str
    sha256: str | None = None


@dataclass(frozen=True)
class Finding:
    """One vulnerability on one component of one release (canonical id + component_ref)."""

    canonical_vuln_id: str
    aliases: tuple[str, ...]
    component_key: str
    component_ref: str
    component_purl: str
    component_hash: str | None = None
    # Set by an inheritance plan when an earlier statement no longer applies to this release.
    needs_review: bool = False

    @property
    def all_vuln_ids(self) -> frozenset[str]:
        return frozenset((self.canonical_vuln_id, *self.aliases))


@dataclass(frozen=True)
class Statement:
    """An append-only VEX statement row. It is never updated; changes are new rows."""

    id: str
    canonical_vuln_id: str
    component_ref: str
    status: Status
    created_at: datetime
    created_by: str
    justification: Justification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    status_notes: str | None = None
    evidence: tuple[Evidence, ...] = ()
    valid_until: datetime | None = None
    supersedes_id: str | None = None
    inherited_from_id: str | None = None


@dataclass(frozen=True)
class TriagedFinding:
    """A finding with the latest statement of its chain (possibly expired) and its OSV status."""

    finding: Finding
    statement: Statement | None = None
    withdrawn: bool = False
