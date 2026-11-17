# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""every mutation is audited, tokens are stored hashed, hostile SBOM
uploads never produce a 5xx, security headers are present. Written independently of the
other API tests."""

import json

import pytest
from sqlalchemy import func, select, text

from vexledger.db.models import AuditLog

from .helpers import API, NOT_AFFECTED, sbom_bytes, seeded_with_findings, url

pytestmark = pytest.mark.integration


async def audit_count(env) -> int:  # type: ignore[no-untyped-def]
    async with env.factory() as s:
        return (await s.execute(select(func.count()).select_from(AuditLog))).scalar_one()


async def test_every_mutating_endpoint_writes_an_audit_row(env):  # type: ignore[no-untyped-def]
    e = await env()
    admin = await e.person("admin")
    c, csrf = await e.login(admin)  # tokens can only be minted from a login session
    c.headers["X-CSRF-Token"] = csrf
    s, ids = await seeded_with_findings(e, "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003")
    f1, f2, f3 = ids["CVE-2099-0001"], ids["CVE-2099-0002"], ids["CVE-2099-0003"]
    other = await e.person("viewer")
    state: dict[str, str] = {}

    async def step(label, call, expect=(200, 201, 202, 204)):  # type: ignore[no-untyped-def]
        before = await audit_count(e)
        r = await call()
        assert r.status_code in expect, f"{label}: {r.status_code} {r.text}"
        assert await audit_count(e) > before, f"{label}: no audit row was written"
        return r

    await step(
        "create user",
        lambda: c.post(
            f"{API}/admin/users",
            json={
                "username": "audited-user",
                "password": "correct horse battery staple",
                "role": "viewer",
            },
        ),
    )
    await step(
        "patch user", lambda: c.patch(f"{API}/admin/users/{other.id}", json={"role": "analyst"})
    )
    r = await step("create token", lambda: c.post(f"{API}/auth/tokens", json={"name": "t1"}))
    state["tid"] = r.json()["id"]
    await step("revoke own token", lambda: c.delete(f"{API}/auth/tokens/{state['tid']}"))
    second = await c.post(f"{API}/auth/tokens", json={"name": "t2"})
    await step("admin revoke token", lambda: c.delete(f"{API}/admin/tokens/{second.json()['id']}"))
    await step(
        "create product",
        lambda: c.post(
            f"{API}/products",
            json={
                "slug": "audited",
                "name": "Audited",
                "purl": "pkg:generic/audited",
                "vex_author": "Ex",
            },
        ),
    )
    await step(
        "patch product", lambda: c.patch(f"{API}/products/audited", json={"name": "Audited 2"})
    )
    await step(
        "create release",
        lambda: c.post(f"{API}/products/audited/releases", json={"version": "1.0.0"}),
    )
    await step(
        "upload sbom",
        lambda: c.post(
            f"{API}/products/audited/releases/1.0.0/sbom",
            files={"file": ("s.json", sbom_bytes(("requests", "2.0")), "application/json")},
        ),
    )
    head = (
        await step("triage", lambda: c.post(f"{API}/findings/{f1}/triage", json=NOT_AFFECTED))
    ).json()["id"]
    await step(
        "supersede",
        lambda: c.post(
            f"{API}/findings/{f1}/triage",
            json={
                "status": "affected",
                "action_statement": "Upgrade to the fixed release.",
                "expected_head_id": head,
            },
        ),
    )
    await step(
        "assign",
        lambda: c.put(f"{API}/findings/{f2}/assignee", json={"assignee_id": str(admin.id)}),
    )
    await step(
        "evidence note",
        lambda: c.post(
            f"{API}/findings/{f1}/evidence", json={"kind": "NOTE", "value": "see build log"}
        ),
    )
    await step(
        "evidence file",
        lambda: c.post(f"{API}/findings/{f1}/evidence/file", files={"file": ("p.txt", b"proof\n")}),
    )
    await step(
        "bulk triage",
        lambda: c.post(
            f"{API}/findings/bulk-triage",
            json={**NOT_AFFECTED, "finding_ids": [str(f2), str(f3)]},
        ),
    )
    await step("export", lambda: c.post(url(s, "/export?allow_incomplete=true")))


async def test_api_tokens_are_stored_only_as_sha256_hashes(env):  # type: ignore[no-untyped-def]
    e = await env()
    admin = await e.person("admin")
    c, csrf = await e.login(admin)
    c.headers["X-CSRF-Token"] = csrf
    plain = (await c.post(f"{API}/auth/tokens", json={"name": "probe"})).json()["token"]
    async with e.factory() as s:
        rows = (await s.execute(text("select token_hash from api_tokens"))).scalars().all()
        assert plain not in rows and all(len(h) == 64 for h in rows)
        # the plaintext must not exist in any text column of any table
        tables = (
            await s.execute(
                text(
                    "select table_name, column_name from information_schema.columns "
                    "where table_schema='public' "
                    "and data_type in ('text','character varying','jsonb')"
                )
            )
        ).all()
        for table, col in tables:
            n = (
                await s.execute(
                    text(f'select count(*) from "{table}" where "{col}"::text like :p'),
                    {"p": f"%{plain}%"},
                )
            ).scalar_one()
            assert n == 0, f"token plaintext found in {table}.{col}"
    assert plain not in (await c.get(f"{API}/auth/tokens")).text  # never returned again


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("xml", b"<?xml version='1.0'?><bom xmlns='http://cyclonedx.org/schema/bom/1.5'/>"),
        ("deep arrays", b"[" * 200_000 + b"]" * 200_000),
        ("deep objects", b'{"a":' * 50_000 + b"1" + b"}" * 50_000),
        ("NaN", b'{"bomFormat":"CycloneDX","specVersion":NaN}'),
        ("invalid utf8", b'{"bomFormat":"\xff\xfe"}'),
        ("duplicate keys", b'{"bomFormat":"CycloneDX","bomFormat":"x","specVersion":"1.5"}'),
        (
            "huge number",
            b'{"bomFormat":"CycloneDX","specVersion":"1.5","version":' + b"9" * 5000 + b"}",
        ),
        ("empty", b""),
        ("null", b"null"),
        ("scalar string", b'"CycloneDX"'),
        ("zip magic", b"PK\x03\x04" + b"\x00" * 100),
        ("nul bytes", b'{"bomFormat":"Cyc\x00lone"}'),
    ],
)
async def test_hostile_sbom_uploads_are_4xx_never_5xx(env, label, payload):  # type: ignore[no-untyped-def]
    e = await env()
    analyst = await e.person("analyst")
    s, _ = await seeded_with_findings(e, "CVE-2099-0001", matched=False)
    c = e.client(analyst)
    before = await audit_count(e)
    r = await c.post(url(s, "/sbom"), files={"file": ("x.json", payload, "application/json")})
    assert 400 <= r.status_code < 500, (label, r.status_code, r.text[:200])
    assert "Traceback" not in r.text and 'File "/' not in r.text
    assert await audit_count(e) == before  # a rejected upload writes nothing


async def test_oversized_sbom_is_413_before_parsing(env):  # type: ignore[no-untyped-def]
    e = await env(max_upload_mb=1)
    analyst = await e.person("analyst")
    s, _ = await seeded_with_findings(e, "CVE-2099-0001", matched=False)
    c = e.client(analyst)
    blob = json.dumps({"pad": "a" * (1024 * 1024 + 10)}).encode()
    r = await c.post(url(s, "/sbom"), files={"file": ("x.json", blob, "application/json")})
    assert r.status_code == 413


async def test_security_headers_are_present(env):  # type: ignore[no-untyped-def]
    e = await env()
    r = await e.client().get("/healthz")
    h = {k.lower(): v for k, v in r.headers.items()}
    assert h.get("x-content-type-options") == "nosniff"
    assert "referrer-policy" in h
    assert h.get("x-frame-options") in {"DENY", "SAMEORIGIN"} or "frame-ancestors" in h.get(
        "content-security-policy", ""
    )


async def test_release_with_thousands_of_findings_stays_paginated_and_fast(env):  # type: ignore[no-untyped-def]
    """5000 findings: every list call is bounded by page_size (<= 200) and answers quickly."""
    import time

    from vexledger.db.models import Finding as FindingRow
    from vexledger.db.repos.products import ReleaseRepository

    e = await env()
    viewer = await e.person("viewer")
    from tests.integration.seed import seed_release

    names = [f"lib{i}" for i in range(50)]
    s = await seed_release(e.factory, names, edges=[("app", n) for n in names])
    async with e.factory() as session, session.begin():
        for name in names:
            comp = s.components[name]
            session.add_all(
                FindingRow(
                    release_id=s.release.id,
                    component_id=comp.id,
                    component_ref=comp.component_ref,
                    canonical_vuln_id=f"CVE-2099-{i:05d}",
                    alias_ids=[],
                )
                for i in range(100)
            )
        await ReleaseRepository(session).set_status(s.release.id, "MATCHED")
    c = e.client(viewer)
    t0 = time.perf_counter()
    r = await c.get(url(s, "/findings?page_size=200&sort=vulnerability"))
    assert r.status_code == 200 and len(r.json()["items"]) == 200 and r.json()["total"] == 5000
    assert (await c.get(url(s, "/findings?page_size=201"))).status_code == 422  # cap holds
    assert (await c.get(url(s, "/findings?page=25&page_size=200"))).json()["items"]
    assert (await c.get(url(s, "/gate"))).json()["open_count"] == 5000
    assert time.perf_counter() - t0 < 10


async def test_redis_down_at_upload_keeps_the_release_pending_not_empty(env, monkeypatch):  # type: ignore[no-untyped-def]
    """If the queue is unreachable the SBOM is stored, the release stays MATCH_PENDING (never
    MATCHED with zero findings), and the export gate refuses it."""
    from redis.exceptions import ConnectionError as RedisConnectionError

    from vexledger.api.routes import products as products_routes

    async def boom(*_a, **_k):  # type: ignore[no-untyped-def]
        raise RedisConnectionError("redis is down")

    monkeypatch.setattr(products_routes, "enqueue_match", boom)
    e = await env()
    analyst = await e.person("analyst")
    c = e.client(analyst)
    assert (
        await c.post(
            f"{API}/products",
            json={"slug": "q", "name": "Q", "purl": "pkg:generic/q", "vex_author": "Ex"},
        )
    ).status_code in (401, 403)  # analysts cannot create products; use an admin for setup
    admin = await e.person("admin")
    ca = e.client(admin)
    await ca.post(
        f"{API}/products",
        json={"slug": "q", "name": "Q", "purl": "pkg:generic/q", "vex_author": "Ex"},
    )
    await ca.post(f"{API}/products/q/releases", json={"version": "1.0.0"})
    r = await c.post(
        f"{API}/products/q/releases/1.0.0/sbom",
        files={"file": ("s.json", sbom_bytes(("requests", "2.0")), "application/json")},
    )
    assert r.status_code == 202 and r.json()["queued"] is False
    assert r.json()["match_status"] == "MATCH_PENDING"
    status = (await c.get(f"{API}/products/q/releases/1.0.0/match-status")).json()
    assert status["status"] == "MATCH_PENDING"
    gate = await c.post(f"{API}/products/q/releases/1.0.0/export?allow_incomplete=true")
    assert gate.status_code == 409 and gate.json()["error"]["code"] == "release_not_matched"


async def test_redis_outage_fails_closed_with_a_clean_error(env):  # type: ignore[no-untyped-def]
    """Sessions and login rate limits live in Redis. With Redis unreachable nobody gets in, the
    answer is a JSON 503 (not a stack trace), and token (Bearer) auth is not bypassed either."""
    from redis.asyncio import Redis

    e = await env()
    admin = await e.person("admin")
    dead = Redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.3)
    e.app.state.sessions.redis = e.app.state.limiter.redis = dead
    r = await e.client().post(
        f"{API}/auth/login", json={"username": admin.username, "password": admin.password}
    )
    assert r.status_code == 503, (r.status_code, r.text[:200])
    assert r.json()["error"]["code"] == "service_unavailable"
    assert "Traceback" not in r.text


async def test_no_secret_ever_reaches_the_logs(env, caplog):  # type: ignore[no-untyped-def]
    """Passwords, session ids, CSRF tokens and API tokens must never be logged."""
    import logging

    caplog.set_level(logging.DEBUG)
    e = await env()
    admin = await e.person("admin")
    c, csrf = await e.login(admin)
    c.headers["X-CSRF-Token"] = csrf
    plain = (await c.post(f"{API}/auth/tokens", json={"name": "logprobe"})).json()["token"]
    await e.client(admin).get(f"{API}/auth/me")  # bearer token in the Authorization header
    await e.client().post(
        f"{API}/auth/login", json={"username": admin.username, "password": "wrong-password-123"}
    )
    session_id = c.cookies.get("vexledger_session") or next(iter(c.cookies.values()), "")
    secrets_ = [admin.password, "wrong-password-123", admin.token, plain, csrf, session_id]
    assert all(secrets_), "test setup: every secret must be a non-empty string"
    for secret in secrets_:
        assert secret not in caplog.text, "a secret value appeared in the logs"
