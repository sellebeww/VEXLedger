# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Semantic Versioning 2.0.0 precedence (npm, Go, and OSV SEMVER ranges).

An optional leading 'v' is accepted (Go module versions carry it, OSV data does not).
Build metadata never affects ordering. Go pseudo-versions are ordinary pre-release
versions (e.g. v0.0.0-20191109021931-daa7c04131f5), which this ordering handles.
"""

import re
from dataclasses import dataclass

from vexledger.domain.errors import InvalidVersionError
from vexledger.domain.versions.base import ParsedVersion, VersionScheme

_NUM = r"(0|[1-9][0-9]*)"
_PRE_ID = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_BUILD_ID = r"[0-9A-Za-z-]+"
_SEMVER = re.compile(
    rf"v?{_NUM}\.{_NUM}\.{_NUM}(?:-({_PRE_ID}(?:\.{_PRE_ID})*))?(?:\+({_BUILD_ID}(?:\.{_BUILD_ID})*))?"
)


def _cmp_ident(a: str, b: str) -> int:
    a_num, b_num = a.isdigit(), b.isdigit()
    if a_num and b_num:
        return (int(a) > int(b)) - (int(a) < int(b))
    if a_num != b_num:
        return -1 if a_num else 1  # numeric identifiers sort below alphanumeric ones
    return (a > b) - (a < b)


@dataclass(frozen=True)
class _SemverVersion(ParsedVersion):
    core: tuple[int, int, int]
    pre: tuple[str, ...]
    build: tuple[str, ...]

    @property
    def canonical(self) -> str:
        out = ".".join(map(str, self.core))
        if self.pre:
            out += "-" + ".".join(self.pre)
        if self.build:
            out += "+" + ".".join(self.build)
        return out

    def cmp(self, other: ParsedVersion) -> int:
        assert isinstance(other, _SemverVersion)  # noqa: S101 - schemes are never mixed
        if self.core != other.core:
            return -1 if self.core < other.core else 1
        if not self.pre or not other.pre:
            return (not self.pre) - (not other.pre)  # a release outranks its pre-releases
        for a, b in zip(self.pre, other.pre, strict=False):
            result = _cmp_ident(a, b)
            if result:
                return result
        return (len(self.pre) > len(other.pre)) - (len(self.pre) < len(other.pre))


class SemverScheme(VersionScheme):
    def parse(self, raw: str) -> ParsedVersion:
        m = _SEMVER.fullmatch(raw)
        if m is None:
            raise InvalidVersionError(f"invalid semantic version {raw!r}")
        major, minor, patch, pre, build = m.groups()
        return _SemverVersion(
            core=(int(major), int(minor), int(patch)),
            pre=tuple(pre.split(".")) if pre else (),
            build=tuple(build.split(".")) if build else (),
        )
