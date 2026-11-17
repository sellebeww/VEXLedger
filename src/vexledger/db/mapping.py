# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Conversions between rows and the pure domain types."""

import uuid
from collections.abc import Sequence

from vexledger.db.models import Component, EvidenceFile, VexStatement
from vexledger.db.models import Evidence as EvidenceRow
from vexledger.db.models import Finding as FindingRow
from vexledger.domain.model import Evidence, EvidenceKind, Finding, Justification, Statement, Status


def finding_to_domain(row: FindingRow, component: Component) -> Finding:
    if component.component_key is None or component.component_ref is None:
        raise ValueError("findings only exist for components with a valid purl")
    return Finding(
        canonical_vuln_id=row.canonical_vuln_id,
        aliases=tuple(sorted(row.alias_ids)),
        component_key=component.component_key,
        component_ref=component.component_ref,
        component_purl=component.purl_original or component.purl_normal or component.component_ref,
        component_hash=component.component_hash,
        needs_review=row.needs_review,
    )


def evidence_to_domain(row: EvidenceRow, file: EvidenceFile | None) -> Evidence:
    if row.kind == "FILE":
        assert file is not None  # noqa: S101 - guaranteed by ck_evidence_shape
        return Evidence(EvidenceKind.FILE, file.storage_name, file.sha256)
    return Evidence(EvidenceKind(row.kind), row.value or "")


def statement_to_domain(
    row: VexStatement, evidence: Sequence[tuple[EvidenceRow, EvidenceFile | None]] = ()
) -> Statement:
    return Statement(
        id=str(row.id),
        canonical_vuln_id=row.canonical_vuln_id,
        component_ref=row.component_ref,
        status=Status(row.status),
        created_at=row.created_at,
        created_by=row.created_by,
        justification=Justification(row.justification) if row.justification else None,
        impact_statement=row.impact_statement,
        action_statement=row.action_statement,
        status_notes=row.status_notes,
        evidence=tuple(evidence_to_domain(e, f) for e, f in evidence),
        valid_until=row.valid_until,
        supersedes_id=str(row.supersedes_id) if row.supersedes_id else None,
        inherited_from_id=str(row.inherited_from_id) if row.inherited_from_id else None,
    )


def parse_id(value: str | None) -> uuid.UUID | None:
    return uuid.UUID(value) if value else None
