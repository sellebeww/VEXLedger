# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Persistence-level errors (the API maps them to HTTP 404 and 409)."""

import uuid

from vexledger.domain.errors import DomainError


class NotFoundError(DomainError):
    pass


class ConflictError(DomainError):
    """The caller acted on stale state, for example another analyst changed the finding first."""

    def __init__(self, message: str, current_head_id: uuid.UUID | None = None) -> None:
        super().__init__(message)
        self.current_head_id = current_head_id
