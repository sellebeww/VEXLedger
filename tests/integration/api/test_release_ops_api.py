# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Gate, OpenVEX export (idempotency, versions, 409), export history and release diff."""

import json

from sqlalchemy import func, select

from vexledger.db.models import AuditLog, VexExport
from vexledger.domain.openvex import validate_document

from .helpers import API, NOT_AFFECTED, add_release, mark, seeded_with_findings, url

AFFECTED = {"status": "affected", "action_statement": "Upgrade to the fixed version next sprint."}
INVESTIGATING = {"status": "under_investigation", "status_notes": "Looking into reachability."}


async def _setup(env, *vulns, matched=True):
    e = await env()
    s, ids = await seeded_with_findings(e, *vulns, matched=matched)
    return e, s, ids, e.client(await e.person("analyst"))


async def _triage(c, fid, body):
    r = await c.post(f"{API}/findings/{fid}/triage", json=body)
    assert r.status_code == 201, r.text


async def test_gate_counts_open_and_investigating_separately(env):
    e, s, ids, c = await _setup(env, "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003")
    g = (await c.get(url(s, "/gate"))).json()
    assert g["complete"] is False and g["open_count"] == 3 and g["total"] == 3
    assert [i["vulnerability_id"] for i in g["open"]] == [
        "CVE-2099-0001",
        "CVE-2099-0002",
        "CVE-2099-0003",
    ]
    await _triage(c, ids["CVE-2099-0001"], NOT_AFFECTED)
    await _triage(c, ids["CVE-2099-0002"], INVESTIGATING)
    g = (await c.get(url(s, "/gate"))).json()
    assert g["open_count"] == 1 and g["investigating_count"] == 1 and g["complete"] is False
    await _triage(c, ids["CVE-2099-0003"], AFFECTED)
    g = (await c.get(url(s, "/gate"))).json()
    assert g["complete"] is True and g["open_count"] == 0 and g["investigating_count"] == 1
    detail = (await c.get(url(s))).json()
    assert detail["findings_by_state"]["TRIAGED"] == 3 and detail["open_count"] == 0


async def test_gate_is_never_complete_while_matching_is_not_done(env):
    e, s, ids, c = await _setup(env, matched=False)
    g = (await c.get(url(s, "/gate"))).json()
    assert g["total"] == 0 and g["open_count"] == 0
    assert g["match_status"] == "MATCH_PENDING" and g["complete"] is False  # not "clean"


async def test_expired_statement_reopens_the_gate(env):
    e, s, ids, c = await _setup(env, "CVE-2099-0001")
    await _triage(c, ids["CVE-2099-0001"], NOT_AFFECTED)
    assert (await c.get(url(s, "/gate"))).json()["complete"] is True
    e.clock.advance(days=181)
    g = (await c.get(url(s, "/gate"))).json()
    assert g["complete"] is False and g["open_count"] == 1
    blocked = await c.post(url(s, "/export"))
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "release_incomplete"


async def test_export_is_blocked_by_the_gate_with_counts(env):
    e, s, ids, c = await _setup(env, "CVE-2099-0001", "CVE-2099-0002")
    await _triage(c, ids["CVE-2099-0001"], NOT_AFFECTED)
    r = await c.post(url(s, "/export"))
    assert r.status_code == 409
    err = r.json()["error"]
    assert err["code"] == "release_incomplete"
    assert err["details"] == {"open_count": 1, "investigating_count": 0, "total": 2}
    async with e.factory() as session:
        n = (
            await session.execute(select(func.count()).where(VexExport.release_id == s.release.id))
        ).scalar_one()
    assert n == 0  # a refused export records nothing


async def test_export_is_idempotent_and_versions_rise_with_changes(env):
    e, s, ids, c = await _setup(env, "CVE-2099-0001", "CVE-2099-0002")
    await _triage(c, ids["CVE-2099-0001"], NOT_AFFECTED)
    first = await c.post(url(s, "/export"), params={"allow_incomplete": "true"})
    assert first.status_code == 200 and first.headers["content-type"] == "application/json"
    assert first.headers["x-vex-version"] == "1" and first.headers["x-vex-new-version"] == "true"
    doc = first.json()
    assert validate_document(doc) == [] and doc["version"] == 1 and len(doc["statements"]) == 1
    assert doc["author"] == "Example (synthetic)" and doc["@id"].endswith("/v1")
    assert "valid_until" not in first.text and "signature" not in first.text.lower()
    st = doc["statements"][0]
    assert st["vulnerability"]["name"] == "CVE-2099-0001" and st["status"] == "not_affected"
    assert st["products"][0]["@id"] == "pkg:generic/synthetic@1.0.0"

    again = await c.post(url(s, "/export"), params={"allow_incomplete": "true"})
    assert again.content == first.content  # byte for byte
    assert again.headers["x-vex-version"] == "1" and again.headers["x-vex-new-version"] == "false"

    await _triage(c, ids["CVE-2099-0002"], AFFECTED)
    third = await c.post(url(s, "/export"))  # complete now: no allow_incomplete needed
    assert (
        third.status_code == 200
        and third.json()["version"] == 2
        and len(third.json()["statements"]) == 2
    )
    assert third.headers["x-vex-content-sha256"] != first.headers["x-vex-content-sha256"]
    assert (await c.post(url(s, "/export"))).content == third.content

    history = (await c.get(url(s, "/exports"))).json()
    assert [h["version"] for h in history] == [2, 1]
    async with e.factory() as session:
        rows = (
            (await session.execute(select(VexExport).where(VexExport.release_id == s.release.id)))
            .scalars()
            .all()
        )
        audited = (
            await session.execute(
                select(func.count()).where(
                    AuditLog.action == "export.create", AuditLog.entity_id == str(s.release.id)
                )
            )
        ).scalar_one()
    assert len(rows) == 2 and audited == 2
    assert rows[0].document == first.content or rows[1].document == first.content


async def test_concurrent_identical_exports_create_one_version(env):
    import asyncio

    e, s, ids, c = await _setup(env, "CVE-2099-0001")
    await _triage(c, ids["CVE-2099-0001"], NOT_AFFECTED)
    results = await asyncio.gather(*(c.post(url(s, "/export")) for _ in range(5)))
    assert {r.status_code for r in results} == {200}
    assert len({r.content for r in results}) == 1
    assert len((await c.get(url(s, "/exports"))).json()) == 1


async def test_export_refuses_unfinished_matching_and_empty_documents(env):
    e, s, ids, c = await _setup(env, "CVE-2099-0001", matched=False)
    r = await c.post(url(s, "/export"), params={"allow_incomplete": "true"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "release_not_matched"
    await mark(e, s.release, "MATCH_FAILED")
    assert (await c.post(url(s, "/export"), params={"allow_incomplete": "true"})).status_code == 409
    await mark(e, s.release, "MATCHED")
    empty = await c.post(url(s, "/export"), params={"allow_incomplete": "true"})
    assert empty.status_code == 422 and empty.json()["error"]["code"] == "no_exportable_statements"


async def test_export_of_unknown_release_is_404(env):
    e, s, ids, c = await _setup(env)
    assert (
        await c.post(f"{API}/products/{s.product.slug}/releases/9.9.9/export")
    ).status_code == 404
    assert (
        await c.get(f"{API}/products/{s.product.slug}/releases/9.9.9/exports")
    ).status_code == 404


async def test_release_diff(env):
    e, s, ids, c = await _setup(env, "CVE-2099-0001", "CVE-2099-0002")
    await add_release(e, s, "1.1.0", {"lib": "2.0", "newlib": "1.0"}, {"lib": ["CVE-2099-0001"]})
    r = await c.get(
        f"{API}/products/{s.product.slug}/diff", params={"from": "1.0.0", "to": "1.1.0"}
    )
    assert r.status_code == 200, r.text
    d = r.json()["diff"]
    assert r.json()["from_version"] == "1.0.0"
    assert d["components_added"] == ["pypi/newlib"] and d["components_removed"] == []
    assert d["version_changed"] == [
        {"component_key": "pypi/lib", "from_versions": ["1.0"], "to_versions": ["2.0"]}
    ]
    assert [f["canonical_vuln_id"] for f in d["findings_resolved"]] == ["CVE-2099-0002"]
    assert [f["canonical_vuln_id"] for f in d["findings_persisting"]] == ["CVE-2099-0001"]
    assert d["findings_new"] == [] and d["statements"] == {"inherited": 0, "needs_review": 0}
    same = await c.get(
        f"{API}/products/{s.product.slug}/diff", params={"from": "1.0.0", "to": "1.1.0"}
    )
    assert same.content == r.content  # deterministic
    assert (
        await c.get(
            f"{API}/products/{s.product.slug}/diff", params={"from": "1.0.0", "to": "8.8.8"}
        )
    ).status_code == 404
    assert (
        await c.get(f"{API}/products/{s.product.slug}/diff", params={"from": "1.0.0"})
    ).status_code == 422
    assert json.loads(r.content)["to_version"] == "1.1.0"
