# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Login, sessions, CSRF, rate limiting and personal API tokens."""

import hashlib

from sqlalchemy import select

from vexledger.db.models import ApiToken, AuditLog

from .conftest import PASSWORD

LOGIN = "/api/v1/auth/login"


async def test_login_sets_a_hardened_cookie_and_returns_the_csrf_token(env):
    e = await env()
    p = await e.person("analyst")
    r = await e.client().post(LOGIN, json={"username": p.username, "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["username"] == p.username and body["csrf_token"]
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "secure" not in cookie


async def test_cookie_is_secure_and_hsts_is_sent_in_prod(env):
    e = await env(env="prod")
    p = await e.person("viewer")
    r = await e.client().post(LOGIN, json={"username": p.username, "password": PASSWORD})
    assert "secure" in r.headers["set-cookie"].lower()
    assert "max-age=31536000" in r.headers["strict-transport-security"]


async def test_bad_credentials_are_indistinguishable(env):
    e = await env()
    p = await e.person("viewer")
    wrong = await e.client().post(
        LOGIN, json={"username": p.username, "password": "nope-nope-nope"}
    )
    ghost = await e.client().post(LOGIN, json={"username": "ghost-user", "password": PASSWORD})
    assert wrong.status_code == ghost.status_code == 401
    assert wrong.json()["error"]["code"] == ghost.json()["error"]["code"] == "invalid_credentials"
    assert wrong.json()["error"]["message"] == ghost.json()["error"]["message"]


async def test_deactivated_user_cannot_log_in(env):
    e = await env()
    p = await e.person("viewer", active=False)
    r = await e.client().post(LOGIN, json={"username": p.username, "password": PASSWORD})
    assert r.status_code == 401


async def test_account_rate_limit_blocks_even_the_right_password_then_success_resets(env):
    e = await env(login_max_per_account=3)
    p = await e.person("viewer")
    c = e.client()
    for _ in range(3):
        r = await c.post(LOGIN, json={"username": p.username, "password": "wrong-wrong-wrong"})
        assert r.status_code == 401
    blocked = await c.post(LOGIN, json={"username": p.username, "password": PASSWORD})
    assert blocked.status_code == 429 and blocked.json()["error"]["code"] == "rate_limited"
    assert int(blocked.headers["retry-after"]) > 0
    other = await e.person("viewer")  # another account is unaffected
    assert (
        await c.post(LOGIN, json={"username": other.username, "password": PASSWORD})
    ).status_code == 200


async def test_successful_login_resets_the_account_counter(env):
    e = await env(login_max_per_account=3)
    p = await e.person("viewer")
    c = e.client()
    for _ in range(2):
        await c.post(LOGIN, json={"username": p.username, "password": "wrong-wrong-wrong"})
    assert (
        await c.post(LOGIN, json={"username": p.username, "password": PASSWORD})
    ).status_code == 200
    for _ in range(2):
        r = await c.post(LOGIN, json={"username": p.username, "password": "wrong-wrong-wrong"})
        assert r.status_code == 401  # would be 429 had the counter survived


async def test_ip_rate_limit_applies_across_accounts(env):
    e = await env(login_max_per_ip=4, login_max_per_account=100)
    c = e.client()
    for i in range(4):
        await c.post(LOGIN, json={"username": f"nobody-{i}", "password": "x"})
    r = await c.post(LOGIN, json={"username": "someone-else", "password": "x"})
    assert r.status_code == 429


async def test_session_mutations_need_the_csrf_token(env):
    e = await env()
    p = await e.person("analyst")
    c, csrf = await e.login(p)
    url, body = "/api/v1/auth/tokens", {"name": "ci"}
    missing = await c.post(url, json=body)
    wrong = await c.post(url, json=body, headers={"X-CSRF-Token": "x" * 43})
    assert missing.status_code == wrong.status_code == 403
    assert missing.json()["error"]["code"] == "csrf_failed"
    assert (await c.get("/api/v1/auth/me")).status_code == 200  # reads need no token
    assert (await c.post(url, json=body, headers={"X-CSRF-Token": csrf})).status_code == 201


async def test_logout_ends_the_session(env):
    e = await env()
    c, csrf = await e.login(await e.person("viewer"))
    assert (await c.post("/api/v1/auth/logout")).status_code == 403  # no CSRF token
    assert (await c.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})).status_code == 204
    assert (await c.get("/api/v1/auth/me")).status_code == 401


async def test_deactivating_a_user_ends_their_session(env):
    e = await env()
    admin = await e.person("admin")
    victim = await e.person("viewer")
    c, _ = await e.login(victim)
    r = await e.client(admin).patch(f"/api/v1/admin/users/{victim.id}", json={"is_active": False})
    assert r.status_code == 200
    assert (await c.get("/api/v1/auth/me")).status_code == 401


async def test_api_token_lifecycle(env):
    e = await env()
    p = await e.person("analyst")
    c, csrf = await e.login(p)
    created = await c.post(
        "/api/v1/auth/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": csrf}
    )
    assert created.status_code == 201
    secret = created.json()["token"]
    assert secret.startswith("vxl_")
    listing = (await c.get("/api/v1/auth/tokens")).json()
    assert all("token" not in t for t in listing)  # shown once, never again
    async with e.factory() as s:
        row = (
            await s.execute(select(ApiToken).where(ApiToken.name == "ci", ApiToken.user_id == p.id))
        ).scalar_one()
    assert (
        row.token_hash == hashlib.sha256(secret.encode()).hexdigest()
        and secret not in row.token_hash
    )

    bearer = e.client()
    bearer.headers["Authorization"] = f"Bearer {secret}"
    me = await bearer.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["user"]["role"] == "analyst"
    assert me.json()["csrf_token"] is None  # tokens need no CSRF

    tid = created.json()["id"]
    assert (
        await c.delete(f"/api/v1/auth/tokens/{tid}", headers={"X-CSRF-Token": csrf})
    ).status_code == 204
    assert (await bearer.get("/api/v1/auth/me")).status_code == 401  # revoked
    again = await c.delete(f"/api/v1/auth/tokens/{tid}", headers={"X-CSRF-Token": csrf})
    assert again.status_code == 204  # idempotent


async def test_token_scope_follows_the_owner_role(env):
    e = await env()
    viewer = await e.person("viewer")
    c = e.client(viewer)
    assert (await c.get("/api/v1/products")).status_code == 200
    assert (await c.post("/api/v1/products", json={})).status_code == 403


async def test_tokens_cannot_mint_tokens_and_cannot_revoke_foreign_tokens(env):
    e = await env()
    a, b = await e.person("analyst"), await e.person("analyst")
    r = await e.client(a).post("/api/v1/auth/tokens", json={"name": "x"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "session_required"
    async with e.factory() as s:
        foreign = (await s.execute(select(ApiToken).where(ApiToken.user_id == b.id))).scalar_one()
    assert (await e.client(a).delete(f"/api/v1/auth/tokens/{foreign.id}")).status_code == 404


async def test_admin_can_revoke_any_token_and_a_bad_bearer_never_falls_back_to_the_cookie(env):
    e = await env()
    admin, user = await e.person("admin"), await e.person("viewer")
    async with e.factory() as s:
        tid = (await s.execute(select(ApiToken.id).where(ApiToken.user_id == user.id))).scalar_one()
    assert (await e.client(admin).delete(f"/api/v1/admin/tokens/{tid}")).status_code == 204
    assert (await e.client(user).get("/api/v1/auth/me")).status_code == 401
    c, _ = await e.login(admin)  # cookie is valid, but the bearer is bad: 401, no fallback
    r = await c.get("/api/v1/auth/me", headers={"Authorization": "Bearer vxl_wrong"})
    assert r.status_code == 401
    assert (
        await c.get("/api/v1/auth/me", headers={"Authorization": "Basic abc"})
    ).status_code == 401


async def test_login_and_token_events_are_audited(env):
    e = await env()
    p = await e.person("viewer")
    c = e.client()
    await c.post(LOGIN, json={"username": p.username, "password": "wrong-wrong-wrong"})
    await c.post(LOGIN, json={"username": p.username, "password": PASSWORD})
    async with e.factory() as s:
        actions = set(
            (
                await s.execute(
                    select(AuditLog.action).where(
                        AuditLog.entity_id.in_([p.username.lower(), str(p.id)])
                    )
                )
            ).scalars()
        )
    assert {"auth.login_failed", "auth.login"} <= actions
