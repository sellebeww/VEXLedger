# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Builders shared by the API tests."""

import json
import uuid
from typing import Any

from tests.integration.seed import Seeded, seed_finding, seed_release
from vexledger.db.models import Release
from vexledger.db.repos.products import ReleaseRepository

API = "/api/v1"


def sbom_bytes(*packages: tuple[str, str], root: str = "app") -> bytes:
    comps = [
        {
            "type": "library",
            "name": n,
            "version": v,
            "bom-ref": f"{n}@{v}",
            "purl": f"pkg:pypi/{n}@{v}",
        }
        for n, v in packages
    ]
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": root, "bom-ref": root}},
        "components": comps,
        "dependencies": [{"ref": root, "dependsOn": [c["bom-ref"] for c in comps]}],
    }
    return json.dumps(doc).encode()


async def mark(env: Any, release: Release, status: str = "MATCHED") -> None:
    async with env.factory() as session, session.begin():
        await ReleaseRepository(session).set_status(release.id, status)


async def seeded_with_findings(
    env: Any, *vulns: str, component: str = "lib", matched: bool = True
) -> tuple[Seeded, dict[str, uuid.UUID]]:
    """One product/release with a root, one component and a finding per vulnerability id."""
    s = await seed_release(env.factory, [component], edges=[("app", component)])
    ids = {}
    for v in vulns:
        ids[v] = (await seed_finding(env.factory, s, component, v)).id
    if matched:
        await mark(env, s.release)
    return s, ids


def url(s: Seeded, tail: str = "") -> str:
    return f"{API}/products/{s.product.slug}/releases/{s.release.version}{tail}"


NOT_AFFECTED = {
    "status": "not_affected",
    "justification": "vulnerable_code_not_present",
    "impact_statement": "The vulnerable function is never linked into our build.",
}


async def add_release(
    env: Any, s: Seeded, version: str, components: dict[str, str], vulns: dict[str, list[str]]
) -> tuple[Release, dict[tuple[str, str], uuid.UUID]]:
    """A later release of the same product: its components (name -> version) and findings."""
    from tests.integration.seed import component
    from vexledger.db.repos.components import ComponentRepository
    from vexledger.db.repos.findings import FindingRepository

    ids: dict[tuple[str, str], uuid.UUID] = {}
    async with env.factory() as session, session.begin():
        release = await ReleaseRepository(session).create(
            product_id=s.product.id, version=version, actor_id=None
        )
        rows = {"app": component(release.id, "app", "1.0", is_root=True)}
        rows.update({n: component(release.id, n, v) for n, v in components.items()})
        await ComponentRepository(session).add_all(list(rows.values()))
        for name, vuln_ids in vulns.items():
            for vuln in vuln_ids:
                f = await FindingRepository(session).create(
                    release_id=release.id,
                    component=rows[name],
                    canonical_vuln_id=vuln,
                    alias_ids=[],
                )
                ids[(name, vuln)] = f.id
    await mark(env, release)
    return release, ids
