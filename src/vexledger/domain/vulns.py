# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Vulnerability identity: alias grouping, canonical id, withdrawn, severity.

Design choices:
  - Records are linked through `aliases` transitively (union-find over record ids and alias ids).
    `related` is deliberately not an alias.
  - Canonical id: smallest CVE-* by plain string order, else smallest GHSA-*, else the smallest
    remaining id. Ids without a record (alias only) still take part in the choice.
  - A group is withdrawn only when every record in it is withdrawn.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from vexledger.domain.osv_model import OsvRecord, Severity


def choose_canonical_id(ids: Iterable[str]) -> str:
    pool = sorted(set(ids))
    if not pool:
        raise ValueError("no ids to choose from")
    for prefix in ("CVE-", "GHSA-"):
        matching = [i for i in pool if i.startswith(prefix)]
        if matching:
            return matching[0]
    return pool[0]


def extract_severity(record: OsvRecord) -> Severity:
    """Severity exactly as published; it is information only and never decides a VEX status."""
    return record.severity


@dataclass(frozen=True)
class VulnGroup:
    canonical_id: str
    aliases: tuple[str, ...]  # every other id in the group, sorted
    records: tuple[OsvRecord, ...]  # sorted by record id
    withdrawn: bool

    @property
    def record_ids(self) -> tuple[str, ...]:
        return tuple(r.id for r in self.records)


def group_records(records: Iterable[OsvRecord]) -> tuple[VulnGroup, ...]:
    """Merge records that alias each other (transitively). Output is sorted by canonical id."""
    unique = {r.id: r for r in records}  # same id twice: last one wins
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for rec in unique.values():
        find(rec.id)
        for alias in rec.aliases:
            parent[find(alias)] = find(rec.id)

    members: dict[str, set[str]] = {}
    for ident in list(parent):
        members.setdefault(find(ident), set()).add(ident)
    by_root: dict[str, list[OsvRecord]] = {}
    for rec in unique.values():
        by_root.setdefault(find(rec.id), []).append(rec)

    groups = []
    for root, recs in by_root.items():
        canonical = choose_canonical_id(members[root])
        groups.append(
            VulnGroup(
                canonical_id=canonical,
                aliases=tuple(sorted(members[root] - {canonical})),
                records=tuple(sorted(recs, key=lambda r: r.id)),
                withdrawn=all(r.withdrawn is not None for r in recs),
            )
        )
    return tuple(sorted(groups, key=lambda g: g.canonical_id))
