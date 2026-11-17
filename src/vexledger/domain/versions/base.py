# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Uniform version scheme interface."""

from abc import ABC, abstractmethod


class ParsedVersion(ABC):
    @property
    @abstractmethod
    def canonical(self) -> str:
        """Normalized spelling; parsing it again yields an equal version."""

    @abstractmethod
    def cmp(self, other: ParsedVersion) -> int:
        """Negative, zero or positive like a three-way comparison."""


class VersionScheme(ABC):
    @abstractmethod
    def parse(self, raw: str) -> ParsedVersion:
        """Parse or raise InvalidVersionError."""

    def compare(self, a: str, b: str) -> int:
        """Return -1, 0 or 1. Raises InvalidVersionError if either side is invalid."""
        diff = self.parse(a).cmp(self.parse(b))
        return (diff > 0) - (diff < 0)
