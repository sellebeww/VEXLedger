# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Package URL parsing and normalization."""

import re
from dataclasses import dataclass

from packageurl import PackageURL

from vexledger.domain.ecosystem import Ecosystem, ecosystem_for_purl_type
from vexledger.domain.errors import InvalidPurlError

_PYPI_SEPARATORS = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of '-', '_' and '.' become one '-'."""
    return _PYPI_SEPARATORS.sub("-", name).lower()


@dataclass(frozen=True)
class Purl:
    original: str
    type: str
    namespace: str | None
    name: str
    version: str | None
    qualifiers: tuple[tuple[str, str], ...]
    subpath: str | None
    ecosystem: Ecosystem | None

    @property
    def supported(self) -> bool:
        return self.ecosystem is not None

    @property
    def component_key(self) -> str:
        """type/namespace/name without version, qualifiers or subpath (canonical encoding)."""
        canonical = PackageURL(type=self.type, namespace=self.namespace, name=self.name)
        return canonical.to_string().removeprefix("pkg:")

    @property
    def canonical(self) -> str:
        """Canonical purl string: normalized names, qualifiers and subpath kept."""
        return PackageURL(
            type=self.type,
            namespace=self.namespace,
            name=self.name,
            version=self.version,
            qualifiers=dict(self.qualifiers),
            subpath=self.subpath,
        ).to_string()

    @property
    def component_ref(self) -> str | None:
        """component_key@version, or None when the purl carries no version."""
        return None if self.version is None else f"{self.component_key}@{self.version}"

    @property
    def osv_name(self) -> str | None:
        """Package name as OSV spells it, or None for unsupported ecosystems."""
        match self.ecosystem:
            case Ecosystem.MAVEN:
                return f"{self.namespace}:{self.name}"
            case Ecosystem.GO | Ecosystem.NPM:
                return f"{self.namespace}/{self.name}" if self.namespace else self.name
            case Ecosystem.PYPI:
                return self.name
            case None:
                return None


def parse_purl(raw: str) -> Purl:
    try:
        parsed = PackageURL.from_string(raw)
    except ValueError as exc:
        raise InvalidPurlError(f"invalid purl {raw!r}: {exc}") from exc
    if "/" in parsed.name:
        raise InvalidPurlError(f"invalid purl {raw!r}: name must not contain '/'")

    ptype = parsed.type
    namespace = parsed.namespace or None
    name = parsed.name
    match ptype:
        case "pypi":
            if namespace is not None:
                raise InvalidPurlError(f"invalid purl {raw!r}: pypi has no namespace")
            name = normalize_pypi_name(name)
        case "npm":
            name = name.lower()
            namespace = namespace.lower() if namespace else None
        case "maven":
            if namespace is None:
                raise InvalidPurlError(f"invalid purl {raw!r}: maven requires a groupId namespace")
        case _:
            pass  # golang and unsupported types keep their case as given

    return Purl(
        original=raw,
        type=ptype,
        namespace=namespace,
        name=name,
        version=parsed.version or None,
        qualifiers=tuple(sorted(_qualifier_items(parsed.qualifiers))),
        subpath=parsed.subpath or None,
        ecosystem=ecosystem_for_purl_type(ptype),
    )


def _qualifier_items(qualifiers: dict[str, str] | str | None) -> list[tuple[str, str]]:
    if isinstance(qualifiers, dict):
        return list(qualifiers.items())
    return []
