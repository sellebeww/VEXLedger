# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Supported ecosystems and the purl type mapping."""

from enum import StrEnum


class Ecosystem(StrEnum):
    """Values are the exact OSV ecosystem names."""

    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    GO = "Go"


_PURL_TYPE_TO_ECOSYSTEM = {
    "pypi": Ecosystem.PYPI,
    "npm": Ecosystem.NPM,
    "maven": Ecosystem.MAVEN,
    "golang": Ecosystem.GO,
}


def ecosystem_for_purl_type(purl_type: str) -> Ecosystem | None:
    """Return the ecosystem, or None for an unsupported purl type (explicit, never guessed)."""
    return _PURL_TYPE_TO_ECOSYSTEM.get(purl_type)
