# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""SQLAlchemy 2.0 models. All timestamps are timestamptz (UTC).

Enumerations are text columns guarded by CHECK constraints (no PG enum types, so values can
evolve through plain migrations). Immutability of statements, evidence, exports and the audit
log is enforced by triggers created in the migration, not here.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vexledger.db.base import Base


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )


def _tstz(**kw: Any) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, **kw)


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


ROLES = ("admin", "analyst", "viewer")
RELEASE_STATUSES = ("MATCH_PENDING", "MATCHED", "MATCH_FAILED")
STATEMENT_STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)
EVIDENCE_KINDS = ("LINK", "FILE", "NOTE")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(_in("role", ROLES), name="ck_users_role"),
        Index("uq_users_username_lower", text("lower(username)"), unique=True),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    username: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = _tstz()


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(
        Text, nullable=False, unique=True
    )  # sha-256 hex; the token is shown once
    created_at: Mapped[datetime] = _tstz()
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Product(Base):
    __tablename__ = "products"
    __table_args__ = (
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]*$'", name="ck_products_slug"),
        CheckConstraint(
            "(validity_not_affected_days IS NULL OR validity_not_affected_days > 0)"
            " AND (validity_under_investigation_days IS NULL OR validity_under_investigation_days > 0)"
            " AND (validity_affected_days IS NULL OR validity_affected_days > 0)"
            " AND (validity_fixed_days IS NULL OR validity_fixed_days > 0)",
            name="ck_products_validity_positive",
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    purl: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # product purl without the release version
    vex_author: Mapped[str] = mapped_column(Text, nullable=False)
    inherit_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    validity_not_affected_days: Mapped[int | None] = mapped_column(
        Integer, server_default=text("180")
    )
    validity_under_investigation_days: Mapped[int | None] = mapped_column(
        Integer, server_default=text("14")
    )
    validity_affected_days: Mapped[int | None] = mapped_column(Integer)
    validity_fixed_days: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = _tstz()


class Release(Base):
    __tablename__ = "releases"
    __table_args__ = (
        CheckConstraint(_in("status", RELEASE_STATUSES), name="ck_releases_status"),
        UniqueConstraint("product_id", "version", name="uq_releases_product_version"),
        UniqueConstraint("product_id", "ordering", name="uq_releases_product_ordering"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    product_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("products.id"), nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    ordering: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="MATCH_PENDING")
    match_error: Mapped[str | None] = mapped_column(Text)
    # Non-fatal remarks of the last successful match (e.g. OSV records that vanished).
    match_notes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    created_at: Mapped[datetime] = _tstz()


class Sbom(Base):
    __tablename__ = "sboms"
    __table_args__ = (CheckConstraint("size_bytes >= 0", name="ck_sboms_size"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    release_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("releases.id"), nullable=False, unique=True
    )
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    spec_version: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    import_warnings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    uploaded_at: Mapped[datetime] = _tstz()


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (
        CheckConstraint(
            "NOT no_purl OR (purl_normal IS NULL AND component_ref IS NULL)",
            name="ck_components_no_purl",
        ),
        CheckConstraint(
            "no_purl OR (purl_normal IS NOT NULL AND component_key IS NOT NULL)",
            name="ck_components_purl",
        ),
        Index(
            "uq_components_release_ref",
            "release_id",
            "component_ref",
            unique=True,
            postgresql_where=text("component_ref IS NOT NULL"),
        ),
        Index(
            "uq_components_release_bom_ref",
            "release_id",
            "bom_ref",
            unique=True,
            postgresql_where=text("bom_ref IS NOT NULL"),
        ),
        Index("ix_components_release_key", "release_id", "component_key"),
        Index(
            "uq_components_one_root", "release_id", unique=True, postgresql_where=text("is_root")
        ),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    release_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("releases.id"), nullable=False)
    bom_ref: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str | None] = mapped_column(Text)
    purl_original: Mapped[str | None] = mapped_column(Text)
    purl_normal: Mapped[str | None] = mapped_column(Text)
    component_key: Mapped[str | None] = mapped_column(Text)
    component_ref: Mapped[str | None] = mapped_column(Text)
    ecosystem: Mapped[str | None] = mapped_column(Text)  # OSV ecosystem name, NULL when unsupported
    component_hash: Mapped[str | None] = mapped_column(Text)
    no_purl: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    unsupported_ecosystem: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    is_root: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class ComponentEdge(Base):
    __tablename__ = "component_edges"
    __table_args__ = (
        CheckConstraint("parent_id <> child_id", name="ck_edges_no_self_loop"),
        Index("ix_edges_release_parent", "release_id", "parent_id"),
        Index("ix_edges_child", "child_id"),
    )
    parent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("components.id"), primary_key=True)
    child_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("components.id"), primary_key=True)
    release_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("releases.id"), nullable=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    osv_id: Mapped[str] = mapped_column(Text, primary_key=True)
    modified: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    severity: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB
    )  # as published, see domain Severity
    withdrawn: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    fetched_at: Mapped[datetime] = _tstz()
    __table_args__ = (Index("ix_vulnerabilities_aliases", "aliases", postgresql_using="gin"),)


class PurlQueryCache(Base):
    __tablename__ = "purl_query_cache"
    purl: Mapped[str] = mapped_column(Text, primary_key=True)
    osv_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (Index("ix_purl_query_cache_fetched_at", "fetched_at"),)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "release_id", "component_ref", "canonical_vuln_id", name="uq_findings_release_ref_vuln"
        ),
        Index("ix_findings_release_vuln", "release_id", "canonical_vuln_id"),
        Index("ix_findings_component", "component_id"),
        Index(
            "ix_findings_assignee", "assignee_id", postgresql_where=text("assignee_id IS NOT NULL")
        ),
        Index("ix_findings_release_severity", "release_id", "severity_label"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    release_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("releases.id"), nullable=False)
    component_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("components.id"), nullable=False)
    component_ref: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_vuln_id: Mapped[str] = mapped_column(Text, nullable=False)
    alias_ids: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    severity_label: Mapped[str | None] = mapped_column(
        Text
    )  # database_specific.severity as published
    match_discrepancy: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    withdrawn: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    needs_review: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _tstz()


class VexStatement(Base):
    """Append-only (UPDATE and DELETE are rejected by a trigger)."""

    __tablename__ = "vex_statements"
    __table_args__ = (
        CheckConstraint(_in("status", STATEMENT_STATUSES), name="ck_statements_status"),
        CheckConstraint(
            f"justification IS NULL OR ({_in('justification', JUSTIFICATIONS)})",
            name="ck_statements_justification",
        ),
        CheckConstraint(
            "status = 'not_affected' OR justification IS NULL",
            name="ck_statements_justification_only_not_affected",
        ),
        CheckConstraint(
            "status <> 'not_affected' OR (justification IS NOT NULL AND char_length(btrim(coalesce(impact_statement, ''))) >= 20)",
            name="ck_statements_not_affected_fields",
        ),
        CheckConstraint(
            "status <> 'affected' OR char_length(btrim(coalesce(action_statement, ''))) > 0",
            name="ck_statements_affected_fields",
        ),
        CheckConstraint(
            "status <> 'fixed' OR char_length(btrim(coalesce(status_notes, ''))) >= 10",
            name="ck_statements_fixed_fields",
        ),
        CheckConstraint(
            "supersedes_id IS NULL OR supersedes_id <> id", name="ck_statements_no_self_supersede"
        ),
        Index("ix_statements_finding_created", "finding_id", "created_at"),
        # One successor per statement and one root per finding: forks are impossible.
        Index(
            "uq_statements_supersedes",
            "supersedes_id",
            unique=True,
            postgresql_where=text("supersedes_id IS NOT NULL"),
        ),
        Index(
            "uq_statements_one_root",
            "finding_id",
            unique=True,
            postgresql_where=text("supersedes_id IS NULL"),
        ),
        Index(
            "ix_statements_valid_until",
            "valid_until",
            postgresql_where=text("valid_until IS NOT NULL"),
        ),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)
    canonical_vuln_id: Mapped[str] = mapped_column(Text, nullable=False)
    component_ref: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    justification: Mapped[str | None] = mapped_column(Text)
    impact_statement: Mapped[str | None] = mapped_column(Text)
    action_statement: Mapped[str | None] = mapped_column(Text)
    status_notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vex_statements.id"))
    inherited_from_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vex_statements.id"))
    evidence: Mapped[list[Evidence]] = relationship(back_populates="statement", lazy="raise")


class EvidenceFile(Base):
    __tablename__ = "evidence_files"
    __table_args__ = (CheckConstraint("size_bytes > 0", name="ck_evidence_files_size"),)
    id: Mapped[uuid.UUID] = _uuid_pk()
    storage_name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    original_name: Mapped[str] = mapped_column(Text, nullable=False)  # display only, never a path
    sha256: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_type: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _tstz()


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint(_in("kind", EVIDENCE_KINDS), name="ck_evidence_kind"),
        CheckConstraint(
            "(kind = 'FILE' AND evidence_file_id IS NOT NULL AND value IS NULL)"
            " OR (kind IN ('LINK', 'NOTE') AND evidence_file_id IS NULL AND char_length(btrim(coalesce(value, ''))) > 0)",
            name="ck_evidence_shape",
        ),
        CheckConstraint("kind <> 'LINK' OR value ~ '^https?://'", name="ck_evidence_link_scheme"),
        Index("ix_evidence_statement", "statement_id"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    statement_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vex_statements.id"), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str | None] = mapped_column(Text)
    evidence_file_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence_files.id"))
    statement: Mapped[VexStatement] = relationship(back_populates="evidence", lazy="raise")
    file: Mapped[EvidenceFile | None] = relationship(lazy="raise")


class VexExport(Base):
    __tablename__ = "vex_exports"
    __table_args__ = (
        UniqueConstraint("release_id", "version", name="uq_vex_exports_release_version"),
        CheckConstraint("version >= 1", name="ck_vex_exports_version"),
    )
    id: Mapped[uuid.UUID] = _uuid_pk()
    release_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("releases.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    content_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    document: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )  # exact bytes served for this version
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _tstz()


class AuditLog(Base):
    """Append-only (UPDATE, DELETE and TRUNCATE are rejected by triggers)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_entity", "entity_type", "entity_id", "id"),
        Index("ix_audit_at", "at"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = _tstz()
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[str] = mapped_column(Text, nullable=False)
    before: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    reason: Mapped[str | None] = mapped_column(Text)
