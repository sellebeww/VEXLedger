# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Typed OSV client errors. Callers decide on retry from the class, never from message text."""

from vexledger.domain.errors import DomainError


class OsvError(DomainError):
    """Base class."""


class OsvUnavailableError(OsvError):
    """Transient: network failure, timeout, 429 or 5xx that outlasted the retries."""


class OsvPermanentError(OsvError):
    """The request was rejected (4xx other than 404/429); retrying will not help."""


class OsvProtocolError(OsvError):
    """The response did not match the documented shape. Nothing from it is trusted or cached."""
