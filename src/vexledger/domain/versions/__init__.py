# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Per-ecosystem version schemes with a uniform interface."""

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.versions.base import ParsedVersion, VersionScheme
from vexledger.domain.versions.maven import MavenScheme
from vexledger.domain.versions.pep440 import Pep440Scheme
from vexledger.domain.versions.semver import SemverScheme

SEMVER = SemverScheme()

_SCHEMES: dict[Ecosystem, VersionScheme] = {
    Ecosystem.PYPI: Pep440Scheme(),
    Ecosystem.NPM: SEMVER,
    Ecosystem.GO: SEMVER,
    Ecosystem.MAVEN: MavenScheme(),
}


def scheme_for(ecosystem: Ecosystem) -> VersionScheme:
    return _SCHEMES[ecosystem]


__all__ = ["SEMVER", "ParsedVersion", "VersionScheme", "scheme_for"]
