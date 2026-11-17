# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Deterministic diff of two releases of the same product."""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from vexledger.domain.model import FindingState, TriagedFinding
from vexledger.domain.states import derive_finding_state


@dataclass(frozen=True)
class ComponentSnapshot:
    component_key: str
    version: str
    component_hash: str | None = None


@dataclass(frozen=True)
class ReleaseSnapshot:
    components: Sequence[ComponentSnapshot]
    findings: Sequence[TriagedFinding]


@dataclass(frozen=True)
class VersionChange:
    component_key: str
    from_versions: tuple[str, ...]
    to_versions: tuple[str, ...]


@dataclass(frozen=True)
class HashChange:
    """Same versions on both sides but different content hashes."""

    component_key: str
    versions: tuple[str, ...]
    from_hashes: tuple[str | None, ...]
    to_hashes: tuple[str | None, ...]


@dataclass(frozen=True)
class PersistingFinding:
    canonical_vuln_id: str
    component_key: str
    state_a: FindingState
    state_b: FindingState


@dataclass(frozen=True)
class FindingRef:
    canonical_vuln_id: str
    component_key: str
    state: FindingState


@dataclass(frozen=True)
class StatementSummary:
    """Over the findings of release b."""

    inherited: int
    needs_review: int


@dataclass(frozen=True)
class ReleaseDiff:
    components_added: tuple[str, ...]  # component keys
    components_removed: tuple[str, ...]
    version_changed: tuple[VersionChange, ...]
    hash_changed: tuple[HashChange, ...]
    findings_new: tuple[FindingRef, ...]
    findings_resolved: tuple[FindingRef, ...]
    findings_persisting: tuple[PersistingFinding, ...]
    statements: StatementSummary


def _by_key(components: Sequence[ComponentSnapshot]) -> dict[str, set[tuple[str, str | None]]]:
    out: dict[str, set[tuple[str, str | None]]] = defaultdict(set)
    for c in components:
        out[c.component_key].add((c.version, c.component_hash))
    return out


def _sorted_hashes(pairs: set[tuple[str, str | None]]) -> tuple[str | None, ...]:
    return tuple(sorted((h for _, h in pairs), key=lambda h: (h is not None, h or "")))


def _findings(snapshot: ReleaseSnapshot, now: datetime) -> dict[tuple[str, str], FindingRef]:
    out: dict[tuple[str, str], FindingRef] = {}
    for tf in snapshot.findings:
        key = (tf.finding.canonical_vuln_id, tf.finding.component_key)
        state = derive_finding_state(tf.finding, tf.statement, tf.withdrawn, now)
        out[key] = FindingRef(key[0], key[1], state)
    return out


def diff_releases(a: ReleaseSnapshot, b: ReleaseSnapshot, now: datetime) -> ReleaseDiff:
    """Compare a (older) with b (newer). Components match by key, findings by (vuln id, key)."""
    ca, cb = _by_key(a.components), _by_key(b.components)
    version_changed: list[VersionChange] = []
    hash_changed: list[HashChange] = []
    for key in sorted(ca.keys() & cb.keys()):
        va = tuple(sorted({v for v, _ in ca[key]}))
        vb = tuple(sorted({v for v, _ in cb[key]}))
        if va != vb:
            version_changed.append(VersionChange(key, va, vb))
        elif ca[key] != cb[key]:
            hash_changed.append(
                HashChange(key, va, _sorted_hashes(ca[key]), _sorted_hashes(cb[key]))
            )

    fa, fb = _findings(a, now), _findings(b, now)
    return ReleaseDiff(
        components_added=tuple(sorted(cb.keys() - ca.keys())),
        components_removed=tuple(sorted(ca.keys() - cb.keys())),
        version_changed=tuple(version_changed),
        hash_changed=tuple(hash_changed),
        findings_new=tuple(fb[k] for k in sorted(fb.keys() - fa.keys())),
        findings_resolved=tuple(fa[k] for k in sorted(fa.keys() - fb.keys())),
        findings_persisting=tuple(
            PersistingFinding(k[0], k[1], fa[k].state, fb[k].state)
            for k in sorted(fa.keys() & fb.keys())
        ),
        statements=StatementSummary(
            inherited=sum(1 for r in fb.values() if r.state is FindingState.INHERITED),
            needs_review=sum(1 for r in fb.values() if r.state is FindingState.NEEDS_REVIEW),
        ),
    )
