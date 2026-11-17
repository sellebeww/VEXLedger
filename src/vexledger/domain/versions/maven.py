# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Maven version ordering, a port of Apache Maven's ComparableVersion (maven-3.9.x).

Source: https://github.com/apache/maven/blob/maven-3.9.x/maven-artifact/src/main/java/
org/apache/maven/artifact/versioning/ComparableVersion.java (see docs/VERSION_TESTS.md).
Differences from the Java original: arbitrary-size integers are plain Python ints (Maven's
Int/Long/BigInteger items order identically to numeric order), and only ASCII digits count
as digits. An empty version is rejected (Java accepts it).
"""

from dataclasses import dataclass

from vexledger.domain.errors import InvalidVersionError
from vexledger.domain.versions.base import ParsedVersion, VersionScheme

_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}
_RELEASE_KEY = str(_QUALIFIERS.index(""))
_DIGITS = frozenset("0123456789")


@dataclass(frozen=True)
class _Str:
    value: str

    @classmethod
    def make(cls, value: str, followed_by_digit: bool) -> _Str:
        if followed_by_digit:
            value = _SHORT.get(value, value)
        return cls(_ALIASES.get(value, value))

    def key(self) -> str:
        if self.value in _QUALIFIERS:
            return str(_QUALIFIERS.index(self.value))
        return f"{len(_QUALIFIERS)}-{self.value}"


type _Item = int | _Str | list["_Item"]


def _sign(x: int) -> int:
    return (x > 0) - (x < 0)


def _is_null(item: _Item) -> bool:
    if isinstance(item, int):
        return item == 0
    if isinstance(item, _Str):
        return item.key() == _RELEASE_KEY
    return len(item) == 0


def _cmp_null(item: _Item) -> int:
    """item.compareTo(null): how an item compares with a missing counterpart."""
    if isinstance(item, int):
        return 0 if item == 0 else 1
    if isinstance(item, _Str):
        return _sign((item.key() > _RELEASE_KEY) - (item.key() < _RELEASE_KEY))
    for sub in item:
        result = _cmp_null(sub)
        if result:
            return result
    return 0


def _cmp(left: _Item | None, right: _Item | None) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        assert right is not None  # noqa: S101
        return -_cmp_null(right)
    if right is None:
        return _cmp_null(left)
    if isinstance(left, int):
        if isinstance(right, int):
            return (left > right) - (left < right)
        return 1  # a number outranks a qualifier or a sub-list
    if isinstance(left, _Str):
        if isinstance(right, _Str):
            lk, rk = left.key(), right.key()
            return (lk > rk) - (lk < rk)
        return -1  # a qualifier ranks below numbers and sub-lists
    if isinstance(right, int):
        return -1
    if isinstance(right, _Str):
        return 1
    for i in range(max(len(left), len(right))):
        a = left[i] if i < len(left) else None
        b = right[i] if i < len(right) else None
        result = _cmp(a, b)
        if result:
            return result
    return 0


def _normalize(items: list[_Item]) -> None:
    for i in range(len(items) - 1, -1, -1):
        last = items[i]
        if _is_null(last):
            del items[i]
        elif not isinstance(last, list):
            break


def _parse_item(is_digit: bool, text: str) -> _Item:
    if is_digit:
        return int(text)  # leading zeros are irrelevant for int()
    return _Str.make(text, False)


def _to_string(items: list[_Item]) -> str:
    out = ""
    for item in items:
        if out:
            out += "-" if isinstance(item, list) else "."
        out += (
            _to_string(item)
            if isinstance(item, list)
            else str(item.value if isinstance(item, _Str) else item)
        )
    return out


def _parse(version: str) -> list[_Item]:
    version = version.lower()
    root: list[_Item] = []
    current = root
    stack: list[list[_Item]] = [root]
    is_digit = False
    start = 0

    def descend() -> list[_Item]:
        child: list[_Item] = []
        current.append(child)
        stack.append(child)
        return child

    for i, c in enumerate(version):
        if c in ".-":
            current.append(0 if i == start else _parse_item(is_digit, version[start:i]))
            start = i + 1
            if c == "-":
                current = descend()
        elif c in _DIGITS:
            if not is_digit and i > start:
                if current:
                    current = descend()
                current.append(_Str.make(version[start:i], True))
                start = i
                current = descend()
            is_digit = True
        else:
            if is_digit and i > start:
                current.append(_parse_item(True, version[start:i]))
                start = i
                current = descend()
            is_digit = False

    if len(version) > start:
        if not is_digit and current:
            current = descend()
        current.append(_parse_item(is_digit, version[start:]))

    while stack:
        _normalize(stack.pop())
    return root


@dataclass(frozen=True)
class _MavenVersion(ParsedVersion):
    items: list[_Item]

    @property
    def canonical(self) -> str:
        return _to_string(self.items) or "0"  # Java prints \"\" for the zero version

    def cmp(self, other: ParsedVersion) -> int:
        assert isinstance(other, _MavenVersion)  # noqa: S101 - schemes are never mixed
        return _cmp(self.items, other.items)


class MavenScheme(VersionScheme):
    def parse(self, raw: str) -> ParsedVersion:
        if not raw.strip():
            raise InvalidVersionError("empty Maven version")
        return _MavenVersion(_parse(raw))
