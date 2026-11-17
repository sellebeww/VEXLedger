# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""PEP 440 (PyPI) via the reference 'packaging' library."""

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from vexledger.domain.errors import InvalidVersionError
from vexledger.domain.versions.base import ParsedVersion, VersionScheme


@dataclass(frozen=True)
class _Pep440Version(ParsedVersion):
    value: Version

    @property
    def canonical(self) -> str:
        return str(self.value)

    def cmp(self, other: ParsedVersion) -> int:
        assert isinstance(other, _Pep440Version)  # noqa: S101 - schemes are never mixed
        return (self.value > other.value) - (self.value < other.value)


class Pep440Scheme(VersionScheme):
    def parse(self, raw: str) -> ParsedVersion:
        try:
            return _Pep440Version(Version(raw))
        except (InvalidVersion, TypeError) as exc:
            raise InvalidVersionError(f"invalid PEP 440 version {raw!r}") from exc
