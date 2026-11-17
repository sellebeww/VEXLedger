# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Request and response models of /api/v1 (they are the OpenAPI contract)."""

import re
import uuid
from datetime import datetime
from typing import Any, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from vexledger.domain.diff import ReleaseDiff
from vexledger.domain.model import FindingState, Justification, Status

SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
Role = Literal["admin", "analyst", "viewer"]


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


def _bad_text(value: object) -> bool:
    """NUL (PostgreSQL text cannot hold it) or lone surrogates (not encodable as UTF-8)."""
    if isinstance(value, str):
        if "\x00" in value:
            return True
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return True
        return False
    if isinstance(value, BaseModel):
        return any(_bad_text(v) for v in value.__dict__.values())
    if isinstance(value, list | tuple):
        return any(_bad_text(v) for v in value)
    return False


class _In(BaseModel):
    """Request bodies: text the database cannot store is rejected up front."""

    @model_validator(mode="after")
    def _storable_text(self) -> Self:
        if _bad_text(self):
            raise ValueError("NUL characters and lone surrogates are not allowed")
        return self


# ---- auth and users -------------------------------------------------------------------------
class LoginIn(_In):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(_Out):
    id: uuid.UUID
    username: str
    role: Role
    is_active: bool
    created_at: datetime


class SessionOut(BaseModel):
    user: UserOut
    csrf_token: str | None = Field(
        None, description="Send as X-CSRF-Token on every mutation made with the session cookie."
    )
    demo_data: bool = Field(
        False, description="True when OSV records are SYNTHETIC demo data (the UI shows a banner)."
    )


class TokenCreateIn(_In):
    name: str = Field(min_length=1, max_length=100)


class TokenOut(_Out):
    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class TokenCreatedOut(TokenOut):
    token: str = Field(description="Shown exactly once; only its SHA-256 is stored.")


class UserCreateIn(_In):
    username: str
    password: str = Field(max_length=256)
    role: Role

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        if not USERNAME.fullmatch(v):
            raise ValueError("username must be 3-64 characters of letters, digits, . _ -")
        return v


class UserPatchIn(_In):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(None, max_length=256)


# ---- products and releases ------------------------------------------------------------------
_days = Field(None, ge=1, le=3650, description="Default validity in days; null means no expiry.")


class ProductIn(_In):
    slug: str
    name: str = Field(min_length=1, max_length=200)
    purl: str = Field(min_length=1, max_length=500, description="Product purl without version.")
    vex_author: str = Field(min_length=1, max_length=200)
    inherit_enabled: bool = True
    validity_not_affected_days: int | None = Field(180, ge=1, le=3650)
    validity_under_investigation_days: int | None = Field(14, ge=1, le=3650)
    validity_affected_days: int | None = _days
    validity_fixed_days: int | None = _days

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not SLUG.fullmatch(v):
            raise ValueError("slug must match ^[a-z0-9][a-z0-9-]{0,62}$")
        return v


class ProductPatchIn(_In):
    """Only fields that are sent change; an explicit null on a validity field means no expiry."""

    name: str | None = Field(None, min_length=1, max_length=200)
    purl: str | None = Field(None, min_length=1, max_length=500)
    vex_author: str | None = Field(None, min_length=1, max_length=200)
    inherit_enabled: bool | None = None
    validity_not_affected_days: int | None = _days
    validity_under_investigation_days: int | None = _days
    validity_affected_days: int | None = _days
    validity_fixed_days: int | None = _days


class ProductOut(_Out):
    id: uuid.UUID
    slug: str
    name: str
    purl: str
    vex_author: str
    inherit_enabled: bool
    validity_not_affected_days: int | None
    validity_under_investigation_days: int | None
    validity_affected_days: int | None
    validity_fixed_days: int | None
    created_at: datetime


class ReleaseIn(_In):
    version: str

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not VERSION.fullmatch(v):
            raise ValueError("version must match ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
        return v


class ReleaseOut(_Out):
    id: uuid.UUID
    version: str
    ordering: int
    status: Literal["MATCH_PENDING", "MATCHED", "MATCH_FAILED"]
    match_error: str | None
    has_sbom: bool
    created_at: datetime


class SbomOut(BaseModel):
    sha256: str
    spec_version: str | None
    size_bytes: int
    component_count: int
    edge_count: int
    root_present: bool
    no_purl_count: int
    unsupported_ecosystem_count: int
    warning_summary: dict[str, int]
    warnings: list[dict[str, Any]]


class ReleaseDetailOut(ReleaseOut):
    match_notes: list[str]
    sbom: SbomOut | None
    finding_total: int
    open_count: int
    investigating_count: int
    findings_by_state: dict[str, int]


class UploadOut(BaseModel):
    release: ReleaseOut
    sbom: SbomOut
    created: bool = Field(description="False: the very same SBOM was already imported.")
    match_status: Literal["MATCH_PENDING", "MATCHED", "MATCH_FAILED"]
    queued: bool = Field(description="Whether a matching job was queued by this request.")


class MatchStatusOut(BaseModel):
    status: Literal["MATCH_PENDING", "MATCHED", "MATCH_FAILED"]
    error: str | None
    notes: list[str]
    finding_total: int


class GateItem(BaseModel):
    vulnerability_id: str
    component_ref: str


class GateOut(BaseModel):
    release_version: str
    match_status: Literal["MATCH_PENDING", "MATCHED", "MATCH_FAILED"]
    complete: bool = Field(description="Matched and nothing open (investigating does not block).")
    total: int
    open_count: int
    investigating_count: int
    open: list[GateItem]


class ExportListItem(_Out):
    version: int
    content_sha256: str
    created_by: uuid.UUID | None
    created_at: datetime


class DiffOut(BaseModel):
    from_version: str
    to_version: str
    diff: ReleaseDiff


# ---- findings and statements ----------------------------------------------------------------
class EvidenceIn(_In):
    kind: Literal["LINK", "NOTE"]
    value: str = Field(min_length=1, max_length=4000)


class DraftIn(_In):
    status: Status
    justification: Justification | None = None
    impact_statement: str | None = Field(None, max_length=10_000)
    action_statement: str | None = Field(None, max_length=10_000)
    status_notes: str | None = Field(None, max_length=10_000)
    evidence: list[EvidenceIn] = Field(default_factory=list, max_length=20)
    valid_until: AwareDatetime | None = Field(
        None, description="Omit to use the product default for the status."
    )
    reason: str | None = Field(None, max_length=500, description="Recorded in the audit log.")


class TriageIn(DraftIn):
    expected_head_id: uuid.UUID | None = Field(
        None,
        description="The statement id you saw as current. 409 if the chain moved on. Omit to skip.",
    )


class BulkTriageIn(DraftIn):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def _unique(self) -> Self:
        if len(set(self.finding_ids)) != len(self.finding_ids):
            raise ValueError("finding_ids must be unique")
        return self


class ConfirmIn(_In):
    valid_until: AwareDatetime | None = None
    expected_head_id: uuid.UUID | None = None
    reason: str | None = Field(None, max_length=500)


class EvidenceAddIn(EvidenceIn):
    expected_head_id: uuid.UUID | None = None


class AssigneeIn(_In):
    assignee_id: uuid.UUID | None


class AssignmentOut(BaseModel):
    finding_id: uuid.UUID
    assignee_id: uuid.UUID | None


class EvidenceOut(BaseModel):
    id: uuid.UUID
    kind: Literal["LINK", "NOTE", "FILE"]
    value: str | None = Field(None, description="URL (never fetched) or plain text.")
    file_id: uuid.UUID | None = None
    file_name: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    detected_type: str | None = None
    download_url: str | None = None


class StatementOut(BaseModel):
    id: uuid.UUID
    status: Status
    justification: Justification | None
    impact_statement: str | None
    action_statement: str | None
    status_notes: str | None
    created_by: str
    created_at: datetime
    valid_until: datetime | None
    supersedes_id: uuid.UUID | None
    inherited_from_id: uuid.UUID | None
    evidence: list[EvidenceOut]
    without_evidence: bool


class BulkTriageOut(BaseModel):
    created: int
    statements: list[StatementOut]


class FindingItem(BaseModel):
    id: uuid.UUID
    vulnerability_id: str
    aliases: list[str]
    component_ref: str
    component_purl: str
    ecosystem: str | None
    severity_label: str | None
    state: FindingState
    investigating: bool
    assignee_id: uuid.UUID | None
    statement_status: Status | None
    statement_valid_until: datetime | None
    head_id: uuid.UUID | None


class FindingPageOut(BaseModel):
    match_status: Literal["MATCH_PENDING", "MATCHED", "MATCH_FAILED"]
    items: list[FindingItem]
    total: int
    page: int
    page_size: int


class OsvRecordOut(BaseModel):
    id: str
    aliases: list[str]
    summary: str | None
    details: str | None
    severity: list[dict[str, Any]]
    references: list[dict[str, Any]]
    published: str | None
    modified: datetime
    withdrawn: datetime | None


class ComponentOut(BaseModel):
    id: uuid.UUID
    name: str
    version: str | None
    purl: str | None
    component_ref: str | None
    ecosystem: str | None
    component_hash: str | None


class PathNode(BaseModel):
    component_id: uuid.UUID
    name: str
    version: str | None


class DependencyPathOut(BaseModel):
    reachable: bool
    direct: bool | None = Field(description="True direct, False transitive, null unreachable.")
    path: list[PathNode]


class ReviewContextOut(BaseModel):
    """The statement an older release had for the same vulnerability and component key."""

    release_version: str
    statement: StatementOut


class FindingDetailOut(FindingItem):
    product_slug: str
    release_version: str
    release_id: uuid.UUID
    match_discrepancy: dict[str, Any] | None
    component: ComponentOut
    dependency_path: DependencyPathOut
    osv: list[OsvRecordOut]
    statements: list[StatementOut] = Field(description="Newest first; the first is the head.")
    review_context: ReviewContextOut | None = Field(
        None,
        description="NEEDS_REVIEW only: the newest statement of the previous release for the "
        "same vulnerability and component key. Context, never an active statement.",
    )


class AuditOut(_Out):
    id: int
    at: datetime
    actor_id: uuid.UUID | None
    action: str
    entity_type: str
    entity_id: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    reason: str | None


class AuditPageOut(BaseModel):
    items: list[AuditOut]
    next_before_id: int | None
