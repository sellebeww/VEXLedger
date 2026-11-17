# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""match_release: from stored components to findings.

Phases: (A) read the matchable components; (B) network and cache, each step committed on its
own so retries resume cheaply; (C) one transaction that locks the release, upserts findings,
plans and applies inheritance, and marks the release MATCHED. Any failure before (C) commits
marks the release MATCH_FAILED with a reason: a failed match is never shown as "0 findings".
"""

import contextlib
import logging
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vexledger.db.errors import NotFoundError
from vexledger.db.mapping import finding_to_domain
from vexledger.db.models import Component, Product, Release, Sbom, VexStatement
from vexledger.db.models import Finding as FindingRow
from vexledger.db.repos.audit import append_audit
from vexledger.db.repos.findings import FindingRepository
from vexledger.db.repos.products import ReleaseRepository
from vexledger.db.repos.statements import insert_inherited_statement
from vexledger.db.repos.vulns import DEFAULT_CACHE_TTL, VulnerabilityRepository
from vexledger.domain.errors import DomainError
from vexledger.domain.inheritance import (
    InheritAction,
    InheritancePolicy,
    inherited_statement,
    plan_inheritance,
)
from vexledger.domain.matching import compare_with_osv, local_match
from vexledger.domain.model import Finding
from vexledger.domain.osv_model import OsvRecord, parse_record
from vexledger.domain.purl import Purl, parse_purl
from vexledger.domain.ranges import Verdict
from vexledger.domain.vulns import VulnGroup, group_records
from vexledger.osv.client import BATCH_SIZE, OsvClient, OsvRef
from vexledger.osv.errors import OsvError, OsvProtocolError
from vexledger.services.metrics import Metrics

_log = logging.getLogger("vexledger.matching")
DETAIL_CHUNK = 200
_IN_CHUNK = 5000


class ReleaseNotReadyError(DomainError):
    """The release has no imported SBOM yet, so there is nothing to match (not a failure)."""


@dataclass(frozen=True)
class ComputedFinding:
    component_id: uuid.UUID
    component_ref: str
    canonical_vuln_id: str
    alias_ids: tuple[str, ...]
    severity_label: str | None
    withdrawn: bool
    discrepancy: dict[str, Any] | None


@dataclass(frozen=True)
class MatchSummary:
    release_id: uuid.UUID
    components_matched: int
    unique_purls: int
    cache_hits: int
    findings_created: int
    findings_updated: int
    withdrawn: int
    discrepancies: int
    inherited: int
    needs_review: int
    notes: tuple[str, ...]


def _severity_label(group: VulnGroup) -> str | None:
    """database_specific.severity as published: the canonical record's, else the first found."""
    ordered = sorted(group.records, key=lambda r: (r.id != group.canonical_id, r.id))
    return next(
        (r.severity.database_specific for r in ordered if r.severity.database_specific), None
    )


def compute_findings(
    component_id: uuid.UUID, purl: Purl, records: Sequence[OsvRecord]
) -> list[ComputedFinding]:
    """Pure: one finding per alias group OSV returned for this component.

    OSV is the authority. The local matcher only cross-checks: a group OSV returned but the
    local matcher rules out is stored as a discrepancy (UNKNOWN never counts).
    """
    assert purl.component_ref is not None  # noqa: S101 - only matchable components get here
    local = local_match(purl, records)
    discrepancy = compare_with_osv(local, [r.id for r in records])
    only_osv = set(discrepancy.only_osv) if discrepancy else set()
    verdicts = {gv.group.canonical_id: gv.verdict for gv in local.groups}
    out = []
    for group in group_records(records):
        flagged = group.canonical_id in only_osv
        out.append(
            ComputedFinding(
                component_id=component_id,
                component_ref=purl.component_ref,
                canonical_vuln_id=group.canonical_id,
                alias_ids=group.aliases,
                severity_label=_severity_label(group),
                withdrawn=group.withdrawn,
                discrepancy=(
                    {"only_osv": True, "local_verdict": verdicts[group.canonical_id].value}
                    if flagged and verdicts[group.canonical_id] is Verdict.NOT_AFFECTED
                    else None
                ),
            )
        )
    return out


def _chunks(items: Sequence[str], size: int) -> list[Sequence[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _newer(ref: OsvRef, stored: datetime | None) -> bool:
    if stored is None:
        return True
    if ref.modified is None:
        return False
    return datetime.fromisoformat(ref.modified) > stored


async def _fetch_refs(
    factory: async_sessionmaker[AsyncSession],
    osv: OsvClient,
    purls: list[str],
    now: datetime,
    ttl: timedelta,
    metrics: Metrics,
) -> tuple[dict[str, list[OsvRef]], int]:
    """OSV ids per purl from the cache or the network. Returns (refs, cache_hits)."""
    async with factory() as session:
        cached = await VulnerabilityRepository(session).cache_get_fresh(purls, now, ttl)
    metrics.inc("osv_cache_hits", len(cached))
    refs: dict[str, list[OsvRef]] = {p: [OsvRef(i, None) for i in ids] for p, ids in cached.items()}
    misses = [p for p in purls if p not in cached]
    metrics.inc("osv_cache_misses", len(misses))
    for chunk in _chunks(misses, BATCH_SIZE):
        found = await osv.query_purls(chunk)
        async with factory() as session, session.begin():  # cache only complete, validated answers
            repo = VulnerabilityRepository(session)
            for purl, items in found.items():
                await repo.cache_put(purl, [r.id for r in items], now)
        refs.update({p: list(items) for p, items in found.items()})
    return refs, len(cached)


async def _hydrate(
    factory: async_sessionmaker[AsyncSession],
    osv: OsvClient,
    refs: dict[str, list[OsvRef]],
    now: datetime,
) -> tuple[dict[str, OsvRecord], list[str]]:
    """Make sure every returned id has a stored record; return parsed records and notes."""
    newest: dict[str, OsvRef] = {}
    for items in refs.values():
        for ref in items:
            known = newest.get(ref.id)
            if known is None or (ref.modified and (known.modified or "") < ref.modified):
                newest[ref.id] = ref
    ids = sorted(newest)
    stored_modified: dict[str, datetime] = {}
    async with factory() as session:
        for chunk in _chunks(ids, _IN_CHUNK):
            for v in await VulnerabilityRepository(session).get_many(list(chunk)):
                stored_modified[v.osv_id] = v.modified
    need = [i for i in ids if _newer(newest[i], stored_modified.get(i))]
    notes: list[str] = []
    for chunk in _chunks(need, DETAIL_CHUNK):
        fetched = await osv.fetch_vulnerabilities(list(chunk))
        async with factory() as session, session.begin():
            repo = VulnerabilityRepository(session)
            for osv_id, raw in fetched.items():
                if raw is None:
                    notes.append(f"OSV no longer has {osv_id} (404); skipped")
                else:
                    await repo.upsert(raw, now)
    records: dict[str, OsvRecord] = {}
    async with factory() as session:
        for chunk in _chunks(ids, _IN_CHUNK):
            for v in await VulnerabilityRepository(session).get_many(list(chunk)):
                try:
                    records[v.osv_id] = parse_record(v.raw)
                except DomainError as exc:
                    notes.append(f"record {v.osv_id} is unusable ({type(exc).__name__}); skipped")
    for osv_id in ids:
        if osv_id not in records and not any(osv_id in n for n in notes):
            notes.append(f"record {osv_id} is not stored; skipped")
    return records, notes


async def _write_findings(
    factory: async_sessionmaker[AsyncSession],
    release_id: uuid.UUID,
    computed: list[ComputedFinding],
    now: datetime,
    notes: list[str],
    summary_fields: dict[str, int],
) -> tuple[int, int, int, int, int]:
    """Phase C. Returns (created, updated, inherited, needs_review, withdrawn)."""
    async with factory() as session, session.begin():
        release = await session.get(Release, release_id, with_for_update=True)
        if release is None:
            raise NotFoundError(f"release {release_id} not found")
        product = await session.get(Product, release.product_id)
        assert product is not None  # noqa: S101 - FK guarantees it
        existing = {
            (f.component_ref, f.canonical_vuln_id): f
            for f in (
                await session.execute(select(FindingRow).where(FindingRow.release_id == release_id))
            ).scalars()
        }
        components = {
            c.id: c
            for c in (
                await session.execute(select(Component).where(Component.release_id == release_id))
            ).scalars()
        }
        created = updated = withdrawn = 0
        rows: list[FindingRow] = []
        for cf in computed:
            row = existing.get((cf.component_ref, cf.canonical_vuln_id))
            if row is None:
                row = FindingRow(
                    release_id=release_id,
                    component_id=cf.component_id,
                    component_ref=cf.component_ref,
                    canonical_vuln_id=cf.canonical_vuln_id,
                )
                session.add(row)
                existing[(cf.component_ref, cf.canonical_vuln_id)] = row
                created += 1
            else:
                updated += 1
            row.alias_ids = sorted(cf.alias_ids)
            row.severity_label = cf.severity_label
            row.match_discrepancy = cf.discrepancy
            row.withdrawn = cf.withdrawn
            withdrawn += cf.withdrawn
            rows.append(row)
        await session.flush()

        inherited = needs_review = 0
        if rows:
            has_statement = set(
                (
                    await session.execute(
                        select(VexStatement.finding_id).where(
                            VexStatement.finding_id.in_([r.id for r in rows])
                        )
                    )
                ).scalars()
            )
            todo = [r for r in rows if r.id not in has_statement]
            previous = await ReleaseRepository(session).previous(release)
            if todo and previous is not None:
                prev_findings = await FindingRepository(session).triaged_for_release(previous.id)
                by_key: dict[tuple[str, str], FindingRow] = {
                    (r.component_ref, r.canonical_vuln_id): r for r in todo
                }
                new_domain: list[Finding] = [
                    finding_to_domain(r, components[r.component_id]) for r in todo
                ]
                plan = plan_inheritance(
                    prev_findings, new_domain, InheritancePolicy(product.inherit_enabled), now
                )
                for item in plan:
                    row = by_key[(item.finding.component_ref, item.finding.canonical_vuln_id)]
                    if item.action is InheritAction.INHERIT:
                        stmt = inherited_statement(
                            item, now=now, new_id=str(uuid.uuid4()), created_by="system"
                        )
                        await insert_inherited_statement(
                            session, finding_id=row.id, statement=stmt, actor_id=None
                        )
                        inherited += 1
                    elif item.action is InheritAction.NEEDS_REVIEW:
                        needs_review += 1
                        if not row.needs_review:
                            row.needs_review = True
                            append_audit(
                                session,
                                actor_id=None,
                                action="finding.needs_review",
                                entity_type="finding",
                                entity_id=str(row.id),
                                after={"reason": item.reason},
                            )
        release.status = "MATCHED"
        release.match_error = None
        release.match_notes = notes
        append_audit(
            session,
            actor_id=None,
            action="release.matched",
            entity_type="release",
            entity_id=str(release_id),
            after={
                **summary_fields,
                "created": created,
                "updated": updated,
                "inherited": inherited,
                "needs_review": needs_review,
            },
        )
        return created, updated, inherited, needs_review, withdrawn


async def _mark_failed(
    factory: async_sessionmaker[AsyncSession], release_id: uuid.UUID, reason: str
) -> None:
    async with factory() as session, session.begin():
        await ReleaseRepository(session).set_status(release_id, "MATCH_FAILED", error=reason[:500])


async def match_release(
    factory: async_sessionmaker[AsyncSession],
    osv: OsvClient,
    release_id: uuid.UUID,
    *,
    now: datetime,
    metrics: Metrics | None = None,
    cache_ttl: timedelta = DEFAULT_CACHE_TTL,
) -> MatchSummary:
    """Match a release against OSV. Idempotent. On failure the release is MATCH_FAILED and the
    error is re-raised (transient OsvUnavailableError lets the worker reschedule)."""
    metrics = metrics or osv.metrics
    started = time.perf_counter()
    async with factory() as session:
        if await session.get(Release, release_id) is None:
            raise NotFoundError(f"release {release_id} not found")
        if (
            await session.execute(select(Sbom.id).where(Sbom.release_id == release_id))
        ).first() is None:
            raise ReleaseNotReadyError(f"release {release_id} has no imported SBOM")
    try:
        async with factory() as session:
            release = await session.get(Release, release_id)
            if release is None:
                raise NotFoundError(f"release {release_id} not found")
            was_failed = release.status == "MATCH_FAILED"
            rows = (
                (
                    await session.execute(
                        select(Component).where(
                            Component.release_id == release_id,
                            Component.is_root.is_(False),
                            Component.no_purl.is_(False),
                            Component.unsupported_ecosystem.is_(False),
                            Component.component_ref.is_not(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            matchable = [(c.id, parse_purl(f"pkg:{c.component_ref}")) for c in rows]
        if was_failed:
            async with factory() as session, session.begin():
                await ReleaseRepository(session).set_status(release_id, "MATCH_PENDING")

        purls = sorted({f"pkg:{p.component_ref}" for _, p in matchable})
        refs, hits = await _fetch_refs(factory, osv, purls, now, cache_ttl, metrics)
        records, notes = await _hydrate(factory, osv, refs, now)
        listed = {ref.id for items in refs.values() for ref in items}
        covered = records.keys() | {alias for r in records.values() for alias in r.aliases}
        if lost := sorted(listed - covered):
            # A vulnerability OSV reported must never vanish: fail loudly instead of "MATCHED".
            raise OsvProtocolError(
                f"OSV listed {len(lost)} record(s) it could not provide, first: {lost[0]}; "
                "the result would be incomplete"
            )

        computed: list[ComputedFinding] = []
        for component_id, purl in matchable:
            ids = {r.id for r in refs.get(f"pkg:{purl.component_ref}", [])}
            computed.extend(
                compute_findings(
                    component_id, purl, [records[i] for i in sorted(ids) if i in records]
                )
            )
        discrepancies = sum(1 for c in computed if c.discrepancy)
        metrics.inc("match_discrepancies", discrepancies)
        created, updated, inherited, needs_review, withdrawn = await _write_findings(
            factory,
            release_id,
            computed,
            now,
            notes,
            {"components": len(matchable), "purls": len(purls), "discrepancies": discrepancies},
        )
    except Exception as exc:
        metrics.inc("match_failures")
        reason = (
            f"{type(exc).__name__}: {exc}" if isinstance(exc, OsvError) else f"{type(exc).__name__}"
        )
        with contextlib.suppress(NotFoundError):  # a missing release has nothing to mark
            await _mark_failed(factory, release_id, reason)
        _log.warning(
            "match failed",
            extra={"extra_fields": {"release_id": str(release_id), "reason": reason}},
        )
        raise
    elapsed = time.perf_counter() - started
    metrics.observe("match_duration", elapsed)
    summary = MatchSummary(
        release_id,
        len(matchable),
        len(purls),
        hits,
        created,
        updated,
        withdrawn,
        discrepancies,
        inherited,
        needs_review,
        tuple(notes),
    )
    metrics.log(
        "match completed",
        release_id=str(release_id),
        seconds=round(elapsed, 3),
        created=created,
        updated=updated,
        inherited=inherited,
        needs_review=needs_review,
        notes=len(notes),
    )
    return summary
