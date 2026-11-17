# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Append-only audit log writer. Every mutation calls this inside its own transaction."""

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.db.models import AuditLog


def append_audit(
    session: AsyncSession,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    entity_type: str,
    entity_id: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    reason: str | None = None,
) -> None:
    session.add(
        AuditLog(
            actor_id=actor_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            before=before,
            after=after,
            reason=reason,
        )
    )
