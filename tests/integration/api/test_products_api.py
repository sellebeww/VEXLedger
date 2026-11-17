# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Products, releases, SBOM upload (idempotency, limits), match status."""

import uuid
from pathlib import Path

from sqlalchemy import select

from vexledger.db.models import AuditLog

from .helpers import API, sbom_bytes

PRODUCT = {
    "slug": "web-app",
    "name": "Web App",
    "purl": "pkg:generic/web-app",
    "vex_author": "Example Corp (synthetic)",
}


def _slug() -> str:
    return f"p-{uuid.uuid4().hex[:10]}"


async def _product(env, admin, **kw):
    body = {**PRODUCT, "slug": _slug(), **kw}
    r = await env.client(admin).post(f"{API}/products", json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def test_product_crud_and_settings(env):
    e = await env()
    admin = await e.person("admin")
    c = e.client(admin)
    p = await _product(e, admin)
    assert p["inherit_enabled"] is True and p["validity_not_affected_days"] == 180
    assert p["validity_affected_days"] is None
    assert (await c.get(f"{API}/products/{p['slug']}")).json()["id"] == p["id"]
    assert p["slug"] in [x["slug"] for x in (await c.get(f"{API}/products")).json()]

    r = await c.patch(
        f"{API}/products/{p['slug']}",
        json={
            "inherit_enabled": False,
            "validity_not_affected_days": 30,
            "validity_fixed_days": 90,
        },
    )
    assert r.status_code == 200
    out = r.json()
    assert out["inherit_enabled"] is False and out["validity_not_affected_days"] == 30
    assert out["validity_fixed_days"] == 90 and out["validity_under_investigation_days"] == 14
    cleared = await c.patch(
        f"{API}/products/{p['slug']}", json={"validity_not_affected_days": None}
    )
    assert cleared.json()["validity_not_affected_days"] is None  # explicit null: never expires

    assert (await c.delete(f"{API}/products/{p['slug']}")).status_code == 405  # no delete route
    async with e.factory() as s:
        actions = set(
            (
                await s.execute(select(AuditLog.action).where(AuditLog.entity_id == p["id"]))
            ).scalars()
        )
    assert {"product.create", "product.update"} <= actions


async def test_product_validation_and_conflicts(env):
    e = await env()
    admin = await e.person("admin")
    c = e.client(admin)
    p = await _product(e, admin)
    dup = await c.post(f"{API}/products", json={**PRODUCT, "slug": p["slug"]})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "product_exists"
    bad_slug = await c.post(f"{API}/products", json={**PRODUCT, "slug": "Bad Slug"})
    assert bad_slug.status_code == 422 and bad_slug.json()["error"]["code"] == "validation_error"
    for purl in ("not a purl", "pkg:generic/app@1.0", "pkg:generic/app?x=1"):
        r = await c.post(f"{API}/products", json={**PRODUCT, "slug": _slug(), "purl": purl})
        assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_purl", purl
    zero = await c.post(
        f"{API}/products", json={**PRODUCT, "slug": _slug(), "validity_fixed_days": 0}
    )
    assert zero.status_code == 422
    nul = await c.post(f"{API}/products", json={**PRODUCT, "slug": _slug(), "name": "a\u0000b"})
    assert nul.status_code == 422
    null_name = await c.patch(f"{API}/products/{p['slug']}", json={"name": None})
    assert null_name.status_code == 422
    assert (await c.get(f"{API}/products/does-not-exist")).status_code == 404
    assert (await c.get(f"{API}/products/%00")).status_code == 422  # no 500 from a NUL byte


async def test_releases_create_list_detail_and_delete_guard(env):
    e = await env()
    admin, analyst = await e.person("admin"), await e.person("analyst")
    p = await _product(e, admin)
    c = e.client(analyst)
    r1 = await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "1.0.0"})
    r2 = await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "1.1.0"})
    assert r1.status_code == r2.status_code == 201
    assert r1.json()["status"] == "MATCH_PENDING" and r1.json()["has_sbom"] is False
    assert r2.json()["ordering"] == r1.json()["ordering"] + 1
    dup = await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "1.0.0"})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "release_exists"
    bad = await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "../etc"})
    assert bad.status_code == 422
    listing = (await c.get(f"{API}/products/{p['slug']}/releases")).json()
    assert [x["version"] for x in listing] == ["1.1.0", "1.0.0"]
    detail = (await c.get(f"{API}/products/{p['slug']}/releases/1.0.0")).json()
    assert detail["finding_total"] == 0 and detail["sbom"] is None
    assert set(detail["findings_by_state"]) >= {"UNTRIAGED", "INHERITED", "WITHDRAWN"}
    assert (await c.get(f"{API}/products/{p['slug']}/releases/9.9.9")).status_code == 404


async def test_sbom_upload_is_accepted_idempotent_and_queues_matching(env):
    e = await env()
    admin, analyst = await e.person("admin"), await e.person("analyst")
    p = await _product(e, admin)
    c = e.client(analyst)
    await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "1.0.0"})
    up = f"{API}/products/{p['slug']}/releases/1.0.0/sbom"
    data = sbom_bytes(("requests", "2.0.0"), ("idna", "3.0"))

    r = await c.post(up, files={"file": ("bom.json", data, "application/json")})
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["created"] is True and out["queued"] is True
    assert out["match_status"] == "MATCH_PENDING" and out["release"]["has_sbom"] is True
    assert out["sbom"]["component_count"] == 3 and out["sbom"]["spec_version"] == "1.5"
    assert await e.redis.zcard("arq:queue") == 1  # one matching job, for this release

    again = await c.post(up, files={"file": ("bom.json", data, "application/json")})
    assert again.status_code == 202 and again.json()["created"] is False
    assert again.json()["sbom"]["sha256"] == out["sbom"]["sha256"]
    assert await e.redis.zcard("arq:queue") == 1  # still one job: no duplicate

    other = await c.post(
        up, files={"file": ("bom.json", sbom_bytes(("x", "1")), "application/json")}
    )
    assert other.status_code == 409  # a different SBOM means a new release

    status = (await c.get(f"{API}/products/{p['slug']}/releases/1.0.0/match-status")).json()
    assert status["status"] == "MATCH_PENDING" and status["finding_total"] == 0
    detail = (await c.get(f"{API}/products/{p['slug']}/releases/1.0.0")).json()
    assert detail["sbom"]["sha256"] == out["sbom"]["sha256"]


async def test_sbom_upload_rejects_bad_input_with_stable_codes(env):
    e = await env()
    admin, analyst = await e.person("admin"), await e.person("analyst")
    p = await _product(e, admin)
    c = e.client(analyst)
    await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "1.0.0"})
    up = f"{API}/products/{p['slug']}/releases/1.0.0/sbom"
    not_json = await c.post(up, files={"file": ("bom.json", b"<xml/>", "application/xml")})
    assert not_json.status_code == 422 and not_json.json()["error"]["code"] == "sbom_not_json"
    wrong = await c.post(
        up, files={"file": ("bom.json", b'{"bomFormat": "SPDX"}', "application/json")}
    )
    assert wrong.status_code == 422
    missing = await c.post(up)
    assert missing.status_code == 422
    assert (
        await c.post(
            f"{API}/products/{p['slug']}/releases/7.7.7/sbom", files={"file": ("b.json", b"{}")}
        )
    ).status_code == 404
    status = (await c.get(f"{API}/products/{p['slug']}/releases/1.0.0")).json()
    assert status["sbom"] is None  # nothing was stored


async def test_oversized_bodies_are_refused_before_they_are_read(env):
    e = await env(max_upload_mb=1, json_body_max_kb=2)
    admin, analyst = await e.person("admin"), await e.person("analyst")
    p = await _product(e, admin)
    c = e.client(analyst)
    await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "1.0.0"})
    up = f"{API}/products/{p['slug']}/releases/1.0.0/sbom"
    big = await c.post(up, files={"file": ("bom.json", b"0" * (1_400_000), "application/json")})
    assert big.status_code == 413 and big.json()["error"]["code"] == "payload_too_large"
    huge_json = await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "1" * 5000})
    assert huge_json.status_code == 413

    async def stream():  # no Content-Length: counted while streaming
        for _ in range(10):
            yield b"x" * 1000

    chunked = await c.post(
        f"{API}/products/{p['slug']}/releases",
        content=stream(),
        headers={"content-type": "application/json"},
    )
    assert chunked.status_code == 413


async def test_real_sbom_fixture_uploads(env):
    e = await env()
    admin, analyst = await e.person("admin"), await e.person("analyst")
    p = await _product(e, admin)
    c = e.client(analyst)
    await c.post(f"{API}/products/{p['slug']}/releases", json={"version": "2.0.0"})
    data = Path("tests/fixtures/sboms/uv-env-1.6-with-root.cdx.json").read_bytes()
    r = await c.post(
        f"{API}/products/{p['slug']}/releases/2.0.0/sbom", files={"file": ("bom.json", data)}
    )
    assert r.status_code == 202 and r.json()["sbom"]["root_present"] is True
