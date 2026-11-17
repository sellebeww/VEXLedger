# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Evaluation of OSV affected[].ranges[] and affected[].versions[].

Semantics follow the OSV schema "Evaluation" section (ossf/osv-schema docs/schema.md,
main at commit ef84846d74dc87816baf791da76d5f123bb0081e, fetched 2026-11-16):
  - a version is affected if it is listed in `versions` (exact string match) or lies in a range;
  - within a range: `introduced` is inclusive, `fixed` exclusive, `last_affected` inclusive,
    `limit` exclusive upper bound ("*" or no limit event means unbounded);
  - `introduced: "0"` sorts before every version;
  - SEMVER ranges use SemVer 2.0 order, ECOSYSTEM ranges the ecosystem's own order;
  - GIT ranges need a commit graph, so they are ignored and reported in the notes.
Anything that cannot be decided (invalid version, unsupported scheme, malformed range)
yields UNKNOWN. This module never guesses.
"""

from dataclasses import dataclass
from enum import StrEnum
from functools import cmp_to_key

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.errors import InvalidVersionError
from vexledger.domain.osv_model import Affected, Event, VersionRange
from vexledger.domain.versions import SEMVER, ParsedVersion, VersionScheme, scheme_for


class Verdict(StrEnum):
    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RangeResult:
    verdict: Verdict
    notes: tuple[str, ...] = ()


def _unknown(note: str) -> RangeResult:
    return RangeResult(Verdict.UNKNOWN, (note,))


def _evaluate_range(rng: VersionRange, version: str, ecosystem: Ecosystem) -> RangeResult:
    if rng.malformed:
        return _unknown("malformed_range")
    if rng.type not in ("SEMVER", "ECOSYSTEM"):
        return _unknown(f"unsupported_range_type_{rng.type or 'none'}")
    scheme: VersionScheme = SEMVER if rng.type == "SEMVER" else scheme_for(ecosystem)
    try:
        v = scheme.parse(version)
        limits = [e for e in rng.events if e.kind == "limit"]
        if limits and not any(_before_limit(v, e, scheme) for e in limits):
            return RangeResult(Verdict.NOT_AFFECTED)
        events = [e for e in rng.events if e.kind != "limit"]
        if not any(e.kind == "introduced" for e in events):
            return _unknown("range_without_introduced")
        parsed = [(e, _parse_event(e, scheme)) for e in events]
    except InvalidVersionError:
        return _unknown(f"invalid_version_in_{rng.type.lower()}_range")

    def order(a: tuple[Event, ParsedVersion | None], b: tuple[Event, ParsedVersion | None]) -> int:
        (ea, pa), (eb, pb) = a, b
        if pa is None and pb is None:
            return _kind_rank(ea) - _kind_rank(eb)
        if pa is None:
            return -1
        if pb is None:
            return 1
        return pa.cmp(pb) or _kind_rank(ea) - _kind_rank(eb)

    vulnerable = False
    for event, pv in sorted(parsed, key=cmp_to_key(order)):
        if event.kind == "introduced":
            vulnerable = vulnerable or pv is None or v.cmp(pv) >= 0
        elif pv is not None and _closes(event.kind, v.cmp(pv)):
            vulnerable = False
    return RangeResult(Verdict.AFFECTED if vulnerable else Verdict.NOT_AFFECTED)


def _closes(kind: str, cmp_to_event: int) -> bool:
    """fixed ends the range at v >= fixed; last_affected ends it only when v > last_affected."""
    return cmp_to_event >= 0 if kind == "fixed" else kind == "last_affected" and cmp_to_event > 0


def _kind_rank(event: Event) -> int:
    return 0 if event.kind == "introduced" else 1  # at equal versions, introduced applies first


def _parse_event(event: Event, scheme: VersionScheme) -> ParsedVersion | None:
    """None stands for the special introduced value "0" (below every version)."""
    if event.kind == "introduced" and event.value == "0":
        return None
    return scheme.parse(event.value)


def _before_limit(v: ParsedVersion, event: Event, scheme: VersionScheme) -> bool:
    return event.value == "*" or v.cmp(scheme.parse(event.value)) < 0


def _listed(version: str, versions: tuple[str, ...], ecosystem: Ecosystem) -> bool:
    if ecosystem is Ecosystem.GO:  # OSV lists Go versions without the 'v' purls carry
        return version.removeprefix("v") in {v.removeprefix("v") for v in versions}
    return version in versions


def evaluate_affected(entry: Affected, version: str, ecosystem: Ecosystem) -> RangeResult:
    """Verdict for one affected[] entry whose package is already known to match."""
    notes: list[str] = []
    if _listed(version, entry.versions, ecosystem):
        return RangeResult(Verdict.AFFECTED, ("listed_in_versions",))
    results: list[RangeResult] = []
    for rng in entry.ranges:
        if rng.type == "GIT" and not rng.malformed:
            notes.append("git_range_ignored")
        else:
            results.append(_evaluate_range(rng, version, ecosystem))
    for r in results:
        notes.extend(r.notes)
    verdicts = {r.verdict for r in results}
    if Verdict.AFFECTED in verdicts:
        return RangeResult(Verdict.AFFECTED, tuple(notes))
    if Verdict.UNKNOWN in verdicts:
        return RangeResult(Verdict.UNKNOWN, tuple(notes))
    if verdicts or entry.versions:
        return RangeResult(Verdict.NOT_AFFECTED, tuple(notes))
    return RangeResult(Verdict.UNKNOWN, (*notes, "no_ranges_or_versions"))
