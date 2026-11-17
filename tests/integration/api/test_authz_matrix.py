# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Role x endpoint matrix. Every /api/v1 route must be listed, declare its role, and be enforced."""

import re
import uuid

from fastapi.routing import APIRoute

from vexledger.api.deps import ROLE_RANK

API = "/api/v1"
UID = str(uuid.uuid4())
P = f"{API}/products/x"
R = f"{P}/releases/1.0.0"

# (method, path template, minimum role, "json" | "file" | None). Keep in sync with docs/API.md.
MATRIX: list[tuple[str, str, str, str | None]] = [
    ("GET", "/auth/me", "viewer", None),
    ("POST", "/auth/tokens", "viewer", "json"),
    ("GET", "/auth/tokens", "viewer", None),
    ("DELETE", f"/auth/tokens/{UID}", "viewer", None),
    ("GET", "/products", "viewer", None),
    ("POST", "/products", "admin", "json"),
    ("GET", "/products/x", "viewer", None),
    ("PATCH", "/products/x", "admin", "json"),
    ("GET", "/products/x/releases", "viewer", None),
    ("POST", "/products/x/releases", "analyst", "json"),
    ("GET", "/products/x/releases/1.0.0", "viewer", None),
    ("POST", "/products/x/releases/1.0.0/sbom", "analyst", "file"),
    ("GET", "/products/x/releases/1.0.0/match-status", "viewer", None),
    ("GET", "/products/x/releases/1.0.0/findings", "viewer", None),
    ("GET", "/products/x/releases/1.0.0/gate", "viewer", None),
    ("POST", "/products/x/releases/1.0.0/export", "analyst", None),
    ("GET", "/products/x/releases/1.0.0/exports", "viewer", None),
    ("GET", "/products/x/diff?from=1.0.0&to=1.1.0", "viewer", None),
    ("GET", f"/findings/{UID}", "viewer", None),
    ("POST", f"/findings/{UID}/triage", "analyst", "json"),
    ("POST", "/findings/bulk-triage", "analyst", "json"),
    ("POST", f"/findings/{UID}/confirm", "analyst", "json"),
    ("PUT", f"/findings/{UID}/assignee", "analyst", "json"),
    ("POST", f"/findings/{UID}/evidence", "analyst", "json"),
    ("POST", f"/findings/{UID}/evidence/file", "analyst", "file"),
    ("GET", f"/evidence-files/{UID}/download", "viewer", None),
    ("GET", "/admin/audit", "admin", None),
    ("GET", "/admin/users", "admin", None),
    ("POST", "/admin/users", "admin", "json"),
    ("PATCH", f"/admin/users/{UID}", "admin", "json"),
    ("GET", "/admin/tokens", "admin", None),
    ("DELETE", f"/admin/tokens/{UID}", "admin", None),
    ("POST", "/auth/logout", "viewer", None),  # last: it ends the session used by the loop
]
PUBLIC = {("POST", "/api/v1/auth/login")}


def _template(path: str) -> str:
    """Normalize a concrete matrix path back to its route template."""
    path = path.split("?")[0].replace(UID, "{}")
    for old, new in (
        ("/products/x", "/products/{slug}"),
        ("/releases/1.0.0", "/releases/{version}"),
    ):
        path = path.replace(old, new)
    return path


def _api_routes(app):  # type: ignore[no-untyped-def]
    """(full path, route) of every API route; FastAPI nests included routers lazily."""
    for top in app.routes:
        if hasattr(top, "original_router"):
            prefix = top.include_context.prefix
            for route in top.original_router.routes:
                if isinstance(route, APIRoute) and (prefix + route.path).startswith(API):
                    yield prefix + route.path, route


def test_every_route_is_in_the_matrix_and_declares_the_same_role(env_sync):
    declared: dict[tuple[str, str], str] = {}
    for path, route in _api_routes(env_sync):
        roles = {
            d.call.required_role
            for d in route.dependant.dependencies
            if hasattr(d.call, "required_role")
        }
        for method in route.methods:
            key = (method, re.sub(r"\{(?!slug\}|version\})[^}]+\}", "{}", path))
            if key in PUBLIC:
                assert not roles, f"{key} is public but declares a role"
                continue
            assert len(roles) == 1, f"{key} has no (or several) role dependencies: {roles}"
            declared[key] = roles.pop()
    expected = {(m, API + _template(p)): role for m, p, role, _ in MATRIX}
    assert declared == expected, set(declared) ^ set(expected)


async def _call(client, method, path, kind):
    kwargs = {}
    if kind == "json":
        kwargs["json"] = {}
    elif kind == "file":
        kwargs["files"] = {"file": ("a.txt", b"x")}
    return await client.request(method, API + path, **kwargs)


async def test_each_role_may_call_exactly_its_endpoints(env):
    e = await env()
    anonymous = e.client()
    for role in ("viewer", "analyst", "admin"):
        client, csrf = await e.login(await e.person(role))
        client.headers["X-CSRF-Token"] = csrf
        for method, path, minimum, kind in MATRIX:
            r = await _call(client, method, path, kind)
            if ROLE_RANK[role] >= ROLE_RANK[minimum]:
                assert r.status_code not in (401, 403), f"{role} {method} {path}: {r.status_code}"
            else:
                assert r.status_code == 403, f"{role} {method} {path}: {r.status_code}"
                assert r.json()["error"]["code"] == "forbidden"
    for method, path, _, kind in MATRIX:
        r = await _call(anonymous, method, path, kind)
        assert r.status_code == 401, f"anonymous {method} {path}"
        assert r.json()["error"]["code"] == "unauthorized"


async def test_denied_requests_have_no_side_effects(env):
    e = await env()
    viewer = await e.person("viewer")
    c = e.client(viewer)
    r = await c.post(
        f"{API}/products",
        json={"slug": "sneaky", "name": "n", "purl": "pkg:generic/n", "vex_author": "a"},
    )
    assert r.status_code == 403
    admin = await e.person("admin")
    assert (await e.client(admin).get(f"{API}/products/sneaky")).status_code == 404


async def test_token_auth_follows_the_same_matrix(env):
    e = await env()
    for role in ("viewer", "analyst", "admin"):
        c = e.client(await e.person(role))
        for method, path, minimum, kind in MATRIX:
            if path == "/auth/tokens" and method == "POST":
                continue  # sessions only
            r = await _call(c, method, path, kind)
            allowed = ROLE_RANK[role] >= ROLE_RANK[minimum]
            assert (r.status_code != 403) == allowed, f"{role} {method} {path}: {r.status_code}"
