# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Local matcher: cross-check and offline mode. OSV stays the authority."""

from collections.abc import Collection, Sequence
from dataclasses import dataclass

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.errors import InvalidPurlError
from vexledger.domain.osv_model import AffectedPackage, OsvRecord
from vexledger.domain.purl import Purl, normalize_pypi_name, parse_purl
from vexledger.domain.ranges import RangeResult, Verdict, evaluate_affected
from vexledger.domain.vulns import VulnGroup, group_records


@dataclass(frozen=True)
class RecordVerdict:
    record_id: str
    verdict: Verdict
    withdrawn: bool
    notes: tuple[str, ...]


@dataclass(frozen=True)
class GroupVerdict:
    group: VulnGroup
    verdict: Verdict  # computed from non-withdrawn records (all records if all are withdrawn)


@dataclass(frozen=True)
class MatchResult:
    component_ref: str | None
    records: tuple[RecordVerdict, ...]
    groups: tuple[GroupVerdict, ...]
    notes: tuple[str, ...] = ()

    @property
    def affected_groups(self) -> tuple[GroupVerdict, ...]:
        return tuple(g for g in self.groups if g.verdict is Verdict.AFFECTED)


@dataclass(frozen=True)
class Discrepancy:
    only_local: tuple[str, ...]  # canonical ids the local matcher flags but OSV did not return
    only_osv: tuple[str, ...]  # canonical ids OSV returned but the local matcher rules out


def _package_matches(pkg: AffectedPackage, component: Purl) -> bool:
    if component.ecosystem is None:
        return False
    if pkg.ecosystem == component.ecosystem.value:
        if component.ecosystem is Ecosystem.PYPI:
            return normalize_pypi_name(pkg.name) == component.osv_name
        if component.ecosystem is Ecosystem.NPM:
            return pkg.name.lower() == component.osv_name
        return pkg.name == component.osv_name
    if pkg.purl is not None:
        try:
            return parse_purl(pkg.purl).component_key == component.component_key
        except InvalidPurlError:
            return False
    return False


def _combine(results: Sequence[RangeResult]) -> RangeResult:
    notes = tuple(n for r in results for n in r.notes)
    verdicts = {r.verdict for r in results}
    for verdict in (Verdict.AFFECTED, Verdict.UNKNOWN):
        if verdict in verdicts:
            return RangeResult(verdict, notes)
    return RangeResult(Verdict.NOT_AFFECTED, notes)


def _evaluate_record(record: OsvRecord, component: Purl) -> RecordVerdict:
    assert component.ecosystem is not None and component.version is not None  # noqa: S101
    results = [
        evaluate_affected(entry, component.version, component.ecosystem)
        for entry in record.affected
        if entry.package is not None and _package_matches(entry.package, component)
    ]
    if not results:
        return RecordVerdict(
            record.id,
            Verdict.NOT_AFFECTED,
            record.withdrawn is not None,
            ("no_affected_entry_for_package",),
        )
    combined = _combine(results)
    return RecordVerdict(record.id, combined.verdict, record.withdrawn is not None, combined.notes)


def _group_verdict(group: VulnGroup, by_id: dict[str, RecordVerdict]) -> Verdict:
    live = [by_id[r.id] for r in group.records if r.withdrawn is None] or [
        by_id[r.id] for r in group.records
    ]
    verdicts = {v.verdict for v in live}
    for verdict in (Verdict.AFFECTED, Verdict.UNKNOWN):
        if verdict in verdicts:
            return verdict
    return Verdict.NOT_AFFECTED


def local_match(component: Purl, vuln_records: Sequence[OsvRecord]) -> MatchResult:
    """Evaluate every record against the component. Pure: same input, same output."""
    groups = group_records(vuln_records)
    if component.ecosystem is None or component.version is None:
        note = (
            "unsupported_ecosystem" if component.ecosystem is None else "component_has_no_version"
        )
        records = tuple(
            RecordVerdict(r.id, Verdict.UNKNOWN, r.withdrawn is not None, (note,))
            for g in groups
            for r in g.records
        )
    else:
        records = tuple(_evaluate_record(r, component) for g in groups for r in g.records)
    by_id = {r.record_id: r for r in records}
    return MatchResult(
        component_ref=component.component_ref,
        records=tuple(sorted(records, key=lambda r: r.record_id)),
        groups=tuple(GroupVerdict(g, _group_verdict(g, by_id)) for g in groups),
    )


def compare_with_osv(local: MatchResult, osv_ids: Collection[str]) -> Discrepancy | None:
    """Flag disagreements with OSV's answer. UNKNOWN and withdrawn groups never count."""
    returned = set(osv_ids)
    only_local: list[str] = []
    only_osv: list[str] = []
    for gv in local.groups:
        if gv.group.withdrawn:
            continue
        osv_has = bool(returned & ({gv.group.canonical_id} | set(gv.group.aliases)))
        if gv.verdict is Verdict.AFFECTED and not osv_has:
            only_local.append(gv.group.canonical_id)
        elif gv.verdict is Verdict.NOT_AFFECTED and osv_has:
            only_osv.append(gv.group.canonical_id)
    if not only_local and not only_osv:
        return None
    return Discrepancy(tuple(sorted(only_local)), tuple(sorted(only_osv)))
