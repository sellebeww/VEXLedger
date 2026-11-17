# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Users, audit log, headers, CORS, error hygiene and OpenAPI quality."""

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import select, update

from vexledger.api.routes import products as products_routes
from vexledger.config import Settings
from vexledger.db.models import AuditLog, User

from .conftest import PASSWORD
from .helpers import API, NOT_AFFECTED, sbom_bytes, seeded_with_findings, url


async def test_user_management(env):
    e = await env()
    admin = await e.person("admin")
    c = e.client(admin)
    name = f"new-{uuid.uuid4().hex[:8]}"
    r = await c.post(
        f"{API}/admin/users",
        json={"username": name, "password": "a-long-enough-pass", "role": "analyst"},
    )
    assert r.status_code == 201 and r.json()["role"] == "analyst" and "password" not in r.text
    uid = r.json()["id"]
    assert name in [u["username"] for u in (await c.get(f"{API}/admin/users")).json()]
    login = await e.client().post(
        f"{API}/auth/login", json={"username": name.upper(), "password": "a-long-enough-pass"}
    )
    assert login.status_code == 200  # usernames are case-insensitive

    dup = await c.post(
        f"{API}/admin/users",
        json={"username": name.upper(), "password": "a-long-enough-pass", "role": "viewer"},
    )
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "user_exists"
    short = await c.post(
        f"{API}/admin/users", json={"username": "someone", "password": "short", "role": "viewer"}
    )
    assert short.status_code == 422 and short.json()["error"]["code"] == "password_too_short"
    bad_name = await c.post(
        f"{API}/admin/users",
        json={"username": "x y", "password": "a-long-enough-pass", "role": "viewer"},
    )
    assert bad_name.status_code == 422
    bad_role = await c.post(
        f"{API}/admin/users",
        json={"username": "someone", "password": "a-long-enough-pass", "role": "root"},
    )
    assert bad_role.status_code == 422

    upd = await c.patch(
        f"{API}/admin/users/{uid}", json={"role": "viewer", "password": "another-long-pass"}
    )
    assert upd.status_code == 200 and upd.json()["role"] == "viewer"
    assert (
        await e.client().post(
            f"{API}/auth/login", json={"username": name, "password": "a-long-enough-pass"}
        )
    ).status_code == 401
    assert (
        await e.client().post(
            f"{API}/auth/login", json={"username": name, "password": "another-long-pass"}
        )
    ).status_code == 200
    assert (
        await c.patch(f"{API}/admin/users/{uuid.uuid4()}", json={"role": "viewer"})
    ).status_code == 404


async def test_the_last_active_admin_cannot_be_removed(env):
    e = await env()
    me = await e.person("admin")
    async with e.factory() as s, s.begin():
        await s.execute(
            update(User).where(User.role == "admin", User.id != me.id).values(is_active=False)
        )
    c = e.client(me)
    for body in ({"role": "viewer"}, {"is_active": False}):
        r = await c.patch(f"{API}/admin/users/{me.id}", json=body)
        assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin"
    other = await e.person("admin")
    assert (
        await c.patch(f"{API}/admin/users/{me.id}", json={"role": "analyst"})
    ).status_code == 200
    assert (
        await e.client(other).patch(f"{API}/admin/users/{me.id}", json={"is_active": False})
    ).status_code == 200


async def test_every_mutation_lands_in_the_audit_log_and_it_pages(env):
    e = await env()
    admin = await e.person("admin")
    c = e.client(admin)
    slug = f"p-{uuid.uuid4().hex[:8]}"
    await c.post(
        f"{API}/products",
        json={"slug": slug, "name": "n", "purl": "pkg:generic/n", "vex_author": "a"},
    )
    await c.post(f"{API}/products/{slug}/releases", json={"version": "1.0.0"})
    await c.post(
        f"{API}/products/{slug}/releases/1.0.0/sbom",
        files={"file": ("b.json", sbom_bytes(("idna", "3.0")))},
    )
    s, ids = await seeded_with_findings(e, "CVE-2099-0001", "CVE-2099-0002")
    fid, other = ids["CVE-2099-0001"], ids["CVE-2099-0002"]
    await c.post(f"{API}/findings/{fid}/triage", json=NOT_AFFECTED)
    await c.post(f"{API}/findings/bulk-triage", json={**NOT_AFFECTED, "finding_ids": [str(other)]})
    await c.post(f"{API}/findings/{fid}/evidence/file", files={"file": ("a.txt", b"log")})
    await c.put(f"{API}/findings/{fid}/assignee", json={"assignee_id": str(admin.id)})
    await c.post(url(s, "/export"))
    await c.patch(f"{API}/products/{slug}", json={"inherit_enabled": False})
    client, csrf = await e.login(admin)
    tok = (
        await client.post(f"{API}/auth/tokens", json={"name": "t"}, headers={"X-CSRF-Token": csrf})
    ).json()
    await client.delete(f"{API}/auth/tokens/{tok['id']}", headers={"X-CSRF-Token": csrf})
    await c.post(
        f"{API}/admin/users",
        json={
            "username": f"u-{uuid.uuid4().hex[:8]}",
            "password": "a-long-enough-pass",
            "role": "viewer",
        },
    )

    seen, before = [], None
    while True:
        params = {"limit": 5, **({"before_id": before} if before else {})}
        page = (await c.get(f"{API}/admin/audit", params=params)).json()
        seen += page["items"]
        before = page["next_before_id"]
        if before is None:
            break
    ids_seen = [i["id"] for i in seen]
    assert ids_seen == sorted(ids_seen, reverse=True) and len(ids_seen) == len(set(ids_seen))
    actions = {i["action"] for i in seen}
    assert {
        "product.create",
        "release.create",
        "sbom.import",
        "statement.create",
        "evidence_file.create",
        "finding.assign",
        "export.create",
        "product.update",
        "token.create",
        "token.revoke",
        "user.create",
        "auth.login",
    } <= actions
    mine = (
        await c.get(
            f"{API}/admin/audit", params={"action": "statement.create", "entity_id": str(fid)}
        )
    ).json()
    assert len(mine["items"]) == 2  # triage + the evidence statement
    assert all(i["actor_id"] == str(admin.id) for i in mine["items"])
    assert mine["items"][0]["after"]["supersedes_id"] == mine["items"][1]["after"]["id"]
    for bad in ({"limit": 0}, {"limit": 201}, {"before_id": 0}, {"action": "DROP TABLE"}):
        assert (await c.get(f"{API}/admin/audit", params=bad)).status_code == 422


async def test_security_headers_on_every_response(env):
    e = await env()
    c = e.client(await e.person("viewer"))
    for path in (f"{API}/products", f"{API}/nope", "/healthz"):
        h = (await c.get(path)).headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer" and h["x-request-id"]
    api = (await c.get(f"{API}/products")).headers
    assert (
        "default-src 'none'" in api["content-security-policy"]
        and api["cache-control"] == "no-store"
    )
    docs = await c.get("/docs")
    assert (
        docs.status_code == 200 and "content-security-policy" not in docs.headers
    )  # Swagger UI needs scripts


async def test_cors_is_strict(env):
    e = await env(cors_origins=["https://app.example.test"])
    c = e.client()
    pre = await c.options(
        f"{API}/products",
        headers={
            "Origin": "https://app.example.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-csrf-token",
        },
    )
    assert pre.headers["access-control-allow-origin"] == "https://app.example.test"
    assert pre.headers["access-control-allow-credentials"] == "true"
    evil = await c.options(
        f"{API}/products",
        headers={"Origin": "https://evil.example.test", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in evil.headers
    plain = (
        await (await env())
        .client()
        .get(f"{API}/products", headers={"Origin": "https://app.example.test"})
    )
    assert "access-control-allow-origin" not in plain.headers  # default: no cross-origin access
    with pytest.raises(ValidationError):
        Settings(cors_origins=["*"])


async def test_errors_never_leak_internals(env, monkeypatch):
    e = await env()
    c = e.client(await e.person("viewer"))

    async def boom(self, slug):
        raise RuntimeError("super-secret-internal-detail")

    monkeypatch.setattr(products_routes.ProductRepository, "get_by_slug", boom)
    r = await c.get(f"{API}/products/anything")
    assert r.status_code == 500
    body = r.json()["error"]
    assert body["code"] == "internal_error" and body["request_id"]
    assert "secret" not in r.text and "Traceback" not in r.text and "RuntimeError" not in r.text
    for path, method, status in (
        (f"{API}/no-such-route", "GET", 404),
        (f"{API}/products", "DELETE", 405),
    ):
        r = await c.request(method, path)
        assert r.status_code == status and set(r.json()["error"]) >= {"code", "message"}


async def test_openapi_is_complete_and_tidy(env):
    e = await env()
    spec = (await e.client().get("/openapi.json")).json()
    assert spec["info"]["title"] == "VEXLedger API" and "not signed" in spec["info"]["description"]
    operation_ids, count = set(), 0
    for path, ops in spec["paths"].items():
        if not path.startswith(API):
            continue
        for method, op in ops.items():
            count += 1
            where = f"{method.upper()} {path}"
            assert op.get("summary") and op.get("tags"), where
            assert op["operationId"] not in operation_ids, where
            operation_ids.add(op["operationId"])
            if path != f"{API}/auth/login":
                assert "401" in op["responses"] and "403" in op["responses"], where
            has_input = op.get("parameters") or op.get("requestBody")
            if has_input and path != f"{API}/auth/login":
                assert "422" in op["responses"], where
    assert count >= 34
    schema422 = spec["paths"][f"{API}/findings/bulk-triage"]["post"]["responses"]["422"]
    assert schema422["content"]["application/json"]["schema"]["$ref"].endswith("/ErrorOut")
    assert (await e.client().get("/redoc")).status_code == 200


async def test_audit_rows_of_a_failed_request_are_not_written(env):
    e = await env()
    c = e.client(await e.person("analyst"))
    s, ids = await seeded_with_findings(e, "CVE-2099-0001")
    await c.post(f"{API}/findings/{ids['CVE-2099-0001']}/triage", json={"status": "not_affected"})
    async with e.factory() as session:
        n = len(
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.entity_id == str(ids["CVE-2099-0001"]))
                )
            )
            .scalars()
            .all()
        )
    assert n == 0
    assert PASSWORD  # imported for parity with the other modules
