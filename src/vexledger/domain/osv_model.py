# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Typed, immutable view of an OSV record (https://ossf.github.io/osv-schema/).

Only the fields the domain needs are kept. The raw JSON stays with the caller.
Input is untrusted: structural problems that make a record unusable raise
InvalidOsvRecordError; problems confined to one range mark that range malformed so
evaluation yields UNKNOWN instead of discarding the whole record.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from vexledger.domain.errors import InvalidOsvRecordError

_EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")


@dataclass(frozen=True)
class Event:
    kind: str  # one of _EVENT_KINDS
    value: str


@dataclass(frozen=True)
class VersionRange:
    type: str  # SEMVER, ECOSYSTEM, GIT or something unknown (kept verbatim)
    events: tuple[Event, ...]
    malformed: bool = False


@dataclass(frozen=True)
class AffectedPackage:
    ecosystem: str
    name: str
    purl: str | None


@dataclass(frozen=True)
class Affected:
    package: AffectedPackage | None
    ranges: tuple[VersionRange, ...]
    versions: tuple[str, ...]


@dataclass(frozen=True)
class Severity:
    """Severity exactly as published: (type, score) pairs plus database_specific.severity."""

    entries: tuple[tuple[str, str], ...]
    database_specific: str | None


@dataclass(frozen=True)
class OsvRecord:
    id: str
    aliases: tuple[str, ...]
    modified: str | None
    withdrawn: str | None
    severity: Severity
    affected: tuple[Affected, ...]


def _str_tuple(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise InvalidOsvRecordError(f"{field} must be a list of strings")
    return tuple(value)


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _parse_range(raw: object) -> VersionRange:
    if not isinstance(raw, Mapping):
        return VersionRange(type="", events=(), malformed=True)
    rtype = raw.get("type")
    events_raw = raw.get("events")
    events: list[Event] = []
    malformed = not isinstance(rtype, str) or not isinstance(events_raw, list)
    if isinstance(events_raw, list):
        for evt in events_raw:
            if (
                isinstance(evt, Mapping)
                and len(evt) == 1
                and next(iter(evt)) in _EVENT_KINDS
                and isinstance(next(iter(evt.values())), str)
            ):
                kind, value = next(iter(evt.items()))
                events.append(Event(kind, value))
            else:
                malformed = True  # schema: exactly one known key per event object
    return VersionRange(
        type=rtype if isinstance(rtype, str) else "",
        events=tuple(events),
        malformed=malformed,
    )


def _parse_affected(raw: object) -> Affected:
    if not isinstance(raw, Mapping):
        raise InvalidOsvRecordError("affected[] entries must be objects")
    pkg_raw = raw.get("package")
    package: AffectedPackage | None = None
    if isinstance(pkg_raw, Mapping):
        eco, name = pkg_raw.get("ecosystem"), pkg_raw.get("name")
        if isinstance(eco, str) and isinstance(name, str):
            package = AffectedPackage(eco, name, _opt_str(pkg_raw.get("purl")))
    ranges_raw = raw.get("ranges") or []
    if not isinstance(ranges_raw, list):
        raise InvalidOsvRecordError("affected[].ranges must be a list")
    return Affected(
        package=package,
        ranges=tuple(_parse_range(r) for r in ranges_raw),
        versions=_str_tuple(raw.get("versions"), "affected[].versions"),
    )


def _parse_severity(data: Mapping[str, object]) -> Severity:
    entries: list[tuple[str, str]] = []
    raw = data.get("severity")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, Mapping):
                stype, score = item.get("type"), item.get("score")
                if isinstance(stype, str) and isinstance(score, str):
                    entries.append((stype, score))
    db = data.get("database_specific")
    return Severity(
        entries=tuple(entries),
        database_specific=_opt_str(db.get("severity")) if isinstance(db, Mapping) else None,
    )


def parse_record(data: Mapping[str, object]) -> OsvRecord:
    rid = data.get("id")
    if not isinstance(rid, str) or not rid:
        raise InvalidOsvRecordError("OSV record has no id")
    affected_raw = data.get("affected") or []
    if not isinstance(affected_raw, list):
        raise InvalidOsvRecordError("affected must be a list")
    return OsvRecord(
        id=rid,
        aliases=_str_tuple(data.get("aliases"), "aliases"),
        modified=_opt_str(data.get("modified")),
        withdrawn=_opt_str(data.get("withdrawn")),
        severity=_parse_severity(data),
        affected=tuple(_parse_affected(a) for a in affected_raw),
    )
