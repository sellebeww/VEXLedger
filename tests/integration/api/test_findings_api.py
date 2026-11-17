# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Listing, detail, triage (single and bulk), confirmation, assignment and evidence."""

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from vexledger.db.models import AuditLog, Vulnerability
from vexledger.db.models import Finding as FindingRow
from vexledger.db.repos.statements import insert_inherited_statement
from vexledger.domain.model import Statement, Status

from .helpers import API, NOT_AFFECTED, add_release, seeded_with_findings, url

AFFECTED = {"status": "affected", "action_statement": "Upgrade to the fixed version next sprint."}


async def _setup(env, *vulns):
    e = await env()
    s, ids = await seeded_with_findings(e, *vulns)
    analyst = await e.person("analyst")
    return e, s, ids, e.client(analyst), analyst


async def _audit_count(e, entity_id, action="statement.create"):
    async with e.factory() as s:
        return (
            await s.execute(
                select(func.count()).where(
                    AuditLog.entity_id == str(entity_id), AuditLog.action == action
                )
            )
        ).scalar_one()


# ---- listing --------------------------------------------------------------------------------
async def test_list_filters_sorts_and_paginates(env):
    e, s, ids, c, _ = await _setup(
        env, "CVE-2099-0005", "CVE-2099-0001", "CVE-2099-0003", "CVE-2099-0002", "CVE-2099-0004"
    )
    await c.post(f"{API}/findings/{ids['CVE-2099-0001']}/triage", json=AFFECTED)
    base = url(s, "/findings")

    page = (await c.get(base, params={"page_size": 2, "sort": "vulnerability"})).json()
    assert page["total"] == 5 and page["match_status"] == "MATCHED" and page["page"] == 1
    assert [i["vulnerability_id"] for i in page["items"]] == ["CVE-2099-0001", "CVE-2099-0002"]
    last = (await c.get(base, params={"page_size": 2, "page": 3, "sort": "vulnerability"})).json()
    assert [i["vulnerability_id"] for i in last["items"]] == ["CVE-2099-0005"]
    desc = (
        await c.get(base, params={"sort": "vulnerability", "order": "desc", "page_size": 1})
    ).json()
    assert desc["items"][0]["vulnerability_id"] == "CVE-2099-0005"

    triaged = (await c.get(base, params={"state": "TRIAGED"})).json()
    assert [i["vulnerability_id"] for i in triaged["items"]] == ["CVE-2099-0001"]
    assert triaged["items"][0]["statement_status"] == "affected" and triaged["items"][0]["head_id"]
    both = (await c.get(base, params=[("state", "TRIAGED"), ("state", "UNTRIAGED")])).json()
    assert both["total"] == 5
    assert (await c.get(base, params={"state": "EXPIRED"})).json()["total"] == 0
    assert (await c.get(base, params={"ecosystem": "PyPI"})).json()["total"] == 5
    assert (await c.get(base, params={"ecosystem": "npm"})).json()["total"] == 0

    for bad in (
        {"sort": "nope"},
        {"page_size": 201},
        {"page": 0},
        {"state": "BOGUS"},
        {"severity": "a;b"},
    ):
        assert (await c.get(base, params=bad)).status_code == 422, bad


# ---- detail ---------------------------------------------------------------------------------
async def test_detail_has_osv_data_component_path_history_and_evidence(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    async with e.factory() as session, session.begin():
        session.add(
            Vulnerability(
                osv_id="CVE-2099-0001",
                modified=datetime(2099, 1, 1, tzinfo=UTC),
                aliases=[],
                raw={
                    "summary": "Synthetic summary",
                    "details": "Synthetic details",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
                    "references": [
                        {"type": "WEB", "url": "https://example.test/advisory"},
                        {"type": "WEB", "url": "javascript:alert(1)"},
                    ],
                },
            )
        )
    first = await c.post(f"{API}/findings/{fid}/triage", json=NOT_AFFECTED)
    assert first.status_code == 201
    await c.post(
        f"{API}/findings/{fid}/evidence",
        json={"kind": "LINK", "value": "https://example.test/proof"},
    )

    r = await c.get(f"{API}/findings/{fid}")
    assert r.status_code == 200
    d = r.json()
    assert (
        d["state"] == "TRIAGED"
        and d["product_slug"] == s.product.slug
        and d["release_version"] == "1.0.0"
    )
    assert d["component"]["name"] == "lib" and d["component"]["component_ref"] == "pypi/lib@1.0"
    assert d["dependency_path"] == {
        "reachable": True,
        "direct": True,
        "path": [
            {"component_id": str(s.components["app"].id), "name": "app", "version": "1.0"},
            {"component_id": str(s.components["lib"].id), "name": "lib", "version": "1.0"},
        ],
    }
    osv = d["osv"][0]
    assert osv["summary"] == "Synthetic summary" and osv["details"] == "Synthetic details"
    assert [r["url"] for r in osv["references"]] == [
        "https://example.test/advisory"
    ]  # no javascript:
    history = d["statements"]
    assert len(history) == 2 and history[0]["id"] == d["head_id"]
    assert (
        history[0]["supersedes_id"] == history[1]["id"] and history[1]["without_evidence"] is True
    )
    assert history[0]["evidence"][0]["kind"] == "LINK" and history[0]["without_evidence"] is False
    assert (await c.get(f"{API}/findings/{uuid.uuid4()}")).status_code == 404
    assert (await c.get(f"{API}/findings/not-a-uuid")).status_code == 422


# ---- triage rules through the API -----------------------------------------------------------
@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"status": "not_affected", "impact_statement": "x" * 30}, "justification_required"),
        (
            {
                "status": "not_affected",
                "justification": "component_not_present",
                "impact_statement": "too short",
            },
            "impact_statement_required",
        ),
        ({"status": "affected"}, "action_statement_required"),
        ({"status": "fixed", "status_notes": "short"}, "status_notes_required"),
        (
            {"status": "under_investigation", "justification": "component_not_present"},
            "justification_not_allowed",
        ),
        (
            {**NOT_AFFECTED, "evidence": [{"kind": "LINK", "value": "ftp://example.test/x"}]},
            "evidence_invalid",
        ),
        (
            {**NOT_AFFECTED, "evidence": [{"kind": "LINK", "value": "javascript:alert(1)"}]},
            "evidence_invalid",
        ),
        ({**NOT_AFFECTED, "valid_until": "2000-01-01T00:00:00Z"}, "valid_until_not_in_future"),
    ],
)
async def test_every_statement_rule_is_enforced_with_a_stable_code(env, body, code):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    r = await c.post(f"{API}/findings/{fid}/triage", json=body)
    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == code
    detail = (await c.get(f"{API}/findings/{fid}")).json()
    assert detail["state"] == "UNTRIAGED" and detail["statements"] == []  # nothing was written


async def test_input_shape_errors_are_validation_errors_without_echoing_input(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    for body in (
        {"status": "bogus"},
        {**NOT_AFFECTED, "justification": "made_up"},
        {**NOT_AFFECTED, "valid_until": "2099-01-01T00:00:00"},  # naive datetime
        {**NOT_AFFECTED, "impact_statement": "bad\u0000nul and more text here"},
        {**NOT_AFFECTED, "evidence": [{"kind": "FILE", "value": "x"}]},
    ):
        r = await c.post(f"{API}/findings/{fid}/triage", json=body)
        assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error", body
        assert "bogus" not in r.text and "made_up" not in r.text
    raw = b'{"status": "affected", "action_statement": "lone surrogate \\ud800 in this text"}'
    surrogate = await c.post(
        f"{API}/findings/{fid}/triage", content=raw, headers={"content-type": "application/json"}
    )
    assert surrogate.status_code == 422 and surrogate.json()["error"]["code"] == "validation_error"


async def test_a_valid_triage_and_the_no_op_rule(env):
    e, s, ids, c, analyst = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    r = await c.post(f"{API}/findings/{fid}/triage", json={**NOT_AFFECTED, "reason": "reviewed"})
    assert r.status_code == 201
    st = r.json()
    assert st["status"] == "not_affected" and st["created_by"] == analyst.username
    assert st["valid_until"] is not None and st["without_evidence"] is True  # 180 day default
    a = await c.post(f"{API}/findings/{fid}/triage", json=AFFECTED)
    assert a.status_code == 201 and a.json()["supersedes_id"] == st["id"]
    same = await c.post(f"{API}/findings/{fid}/triage", json=AFFECTED)
    assert same.status_code == 422 and same.json()["error"]["code"] == "no_op"
    assert await _audit_count(e, fid) == 2


async def test_stale_expectation_is_a_409_with_the_current_head(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    first = (await c.post(f"{API}/findings/{fid}/triage", json=AFFECTED)).json()
    second = await c.post(
        f"{API}/findings/{fid}/triage",
        json={**NOT_AFFECTED, "expected_head_id": first["id"]},
    )
    assert second.status_code == 201
    stale = await c.post(
        f"{API}/findings/{fid}/triage",
        json={
            "status": "fixed",
            "status_notes": "Fixed in 2.0.0 release.",
            "expected_head_id": first["id"],
        },
    )
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "conflict"
    assert stale.json()["error"]["details"]["current_head_id"] == second.json()["id"]
    missing_head = await c.post(
        f"{API}/findings/{fid}/triage", json={**AFFECTED, "expected_head_id": str(uuid.uuid4())}
    )
    assert missing_head.status_code == 409
    assert await _audit_count(e, fid) == 2  # the rejected writes left no trace


async def test_two_analysts_at_once_exactly_one_wins(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    head = (await c.post(f"{API}/findings/{fid}/triage", json=AFFECTED)).json()["id"]
    other = e.client(await e.person("analyst"))
    bodies = [
        {**NOT_AFFECTED, "expected_head_id": head},
        {"status": "fixed", "status_notes": "Fixed in release 2.0.0.", "expected_head_id": head},
    ]
    results = await asyncio.gather(
        c.post(f"{API}/findings/{fid}/triage", json=bodies[0]),
        other.post(f"{API}/findings/{fid}/triage", json=bodies[1]),
    )
    assert sorted(r.status_code for r in results) == [201, 409]
    assert len((await c.get(f"{API}/findings/{fid}")).json()["statements"]) == 2


async def test_unknown_finding_is_404_for_every_write(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    ghost = uuid.uuid4()
    for path, body in (
        (f"/findings/{ghost}/triage", AFFECTED),
        (f"/findings/{ghost}/confirm", {}),
        (f"/findings/{ghost}/evidence", {"kind": "NOTE", "value": "x"}),
    ):
        assert (await c.post(API + path, json=body)).status_code == 404, path
    assert (
        await c.put(f"{API}/findings/{ghost}/assignee", json={"assignee_id": None})
    ).status_code == 404


# ---- confirmation of inherited statements ---------------------------------------------------
async def test_confirming_an_inherited_statement(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    src = (await c.post(f"{API}/findings/{ids['CVE-2099-0001']}/triage", json=AFFECTED)).json()
    rel_b, ids_b = await add_release(e, s, "1.1.0", {"lib": "1.0"}, {"lib": ["CVE-2099-0001"]})
    fid = ids_b[("lib", "CVE-2099-0001")]
    async with e.factory() as session, session.begin():
        await insert_inherited_statement(
            session,
            finding_id=fid,
            statement=Statement(
                id=str(uuid.uuid4()),
                canonical_vuln_id="CVE-2099-0001",
                component_ref="pypi/lib@1.0",
                status=Status.AFFECTED,
                created_at=datetime.now(UTC),
                created_by="inheritance",
                action_statement=AFFECTED["action_statement"],
                inherited_from_id=src["id"],
            ),
            actor_id=None,
        )
    before = (await c.get(f"{API}/findings/{fid}")).json()
    assert before["state"] == "INHERITED"
    r = await c.post(f"{API}/findings/{fid}/confirm", json={"reason": "still true"})
    assert r.status_code == 201 and r.json()["inherited_from_id"] is None  # affected never expires
    assert r.json()["supersedes_id"] == before["head_id"]
    assert (await c.get(f"{API}/findings/{fid}")).json()["state"] == "TRIAGED"
    again = await c.post(f"{API}/findings/{fid}/confirm", json={})
    assert again.status_code == 409 and again.json()["error"]["code"] == "not_inherited"
    direct = await c.post(f"{API}/findings/{ids['CVE-2099-0001']}/confirm", json={})
    assert direct.status_code == 409  # a direct statement has nothing to confirm
    assert rel_b.version == "1.1.0"


async def test_confirm_without_any_statement_is_refused(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    r = await c.post(f"{API}/findings/{ids['CVE-2099-0001']}/confirm", json={})
    assert r.status_code == 409 and r.json()["error"]["code"] == "not_inherited"


# ---- assignment -----------------------------------------------------------------------------
async def test_assignment_rules_and_filter(env):
    e, s, ids, c, analyst = await _setup(env, "CVE-2099-0001", "CVE-2099-0002")
    fid = ids["CVE-2099-0001"]
    r = await c.put(f"{API}/findings/{fid}/assignee", json={"assignee_id": str(analyst.id)})
    assert r.status_code == 200 and r.json()["assignee_id"] == str(analyst.id)
    mine = (await c.get(url(s, "/findings"), params={"assignee_id": str(analyst.id)})).json()
    assert [i["id"] for i in mine["items"]] == [str(fid)]
    viewer = await e.person("viewer")
    inactive = await e.person("analyst", active=False)
    for who in (viewer.id, inactive.id, uuid.uuid4()):
        bad = await c.put(f"{API}/findings/{fid}/assignee", json={"assignee_id": str(who)})
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_assignee"
    assert (await c.put(f"{API}/findings/{fid}/assignee", json={"assignee_id": None})).json()[
        "assignee_id"
    ] is None
    assert await _audit_count(e, fid, "finding.assign") == 2


# ---- evidence -------------------------------------------------------------------------------
async def test_link_and_note_evidence_append_statements(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    none_yet = await c.post(f"{API}/findings/{fid}/evidence", json={"kind": "NOTE", "value": "n"})
    assert none_yet.status_code == 409 and none_yet.json()["error"]["code"] == "no_statement"
    base = (await c.post(f"{API}/findings/{fid}/triage", json=NOT_AFFECTED)).json()
    link = await c.post(
        f"{API}/findings/{fid}/evidence", json={"kind": "LINK", "value": "https://example.test/x"}
    )
    note = await c.post(
        f"{API}/findings/{fid}/evidence", json={"kind": "NOTE", "value": "<b>plain</b> text"}
    )
    assert link.status_code == note.status_code == 201
    out = note.json()
    assert out["valid_until"] == base["valid_until"] and out["status"] == "not_affected"
    assert {(x["kind"], x["value"]) for x in out["evidence"]} == {
        ("LINK", "https://example.test/x"),
        ("NOTE", "<b>plain</b> text"),
    }
    dup = await c.post(
        f"{API}/findings/{fid}/evidence", json={"kind": "NOTE", "value": "<b>plain</b> text"}
    )
    assert dup.status_code == 422 and dup.json()["error"]["code"] == "no_op"
    for bad in (
        {"kind": "LINK", "value": "file:///etc/passwd"},
        {"kind": "LINK", "value": "javascript:alert(1)"},
    ):
        r = await c.post(f"{API}/findings/{fid}/evidence", json=bad)
        assert r.status_code == 422 and r.json()["error"]["code"] == "evidence_invalid"
    assert (
        await c.post(f"{API}/findings/{fid}/evidence", json={"kind": "FILE", "value": "x"})
    ).status_code == 422
    stale = await c.post(
        f"{API}/findings/{fid}/evidence",
        json={"kind": "NOTE", "value": "z", "expected_head_id": base["id"]},
    )
    assert stale.status_code == 409


async def test_expired_statement_needs_a_new_triage_before_evidence(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    await c.post(f"{API}/findings/{fid}/triage", json=NOT_AFFECTED)
    e.clock.advance(days=181)
    assert (await c.get(f"{API}/findings/{fid}")).json()["state"] == "EXPIRED"
    r = await c.post(f"{API}/findings/{fid}/evidence", json={"kind": "NOTE", "value": "late"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "valid_until_not_in_future"


async def test_file_evidence_upload_and_attachment_only_download(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    await c.post(f"{API}/findings/{fid}/triage", json=NOT_AFFECTED)
    up = f"{API}/findings/{fid}/evidence/file"
    r = await c.post(up, files={"file": ("../../etc/proof.txt", b"build log\n", "text/html")})
    assert r.status_code == 201, r.text
    ev = r.json()["evidence"][0]
    assert ev["kind"] == "FILE" and ev["file_name"] == "proof.txt" and ev["size_bytes"] == 10
    assert len(ev["sha256"]) == 64 and ev["download_url"].endswith("/download")

    d = await c.get(ev["download_url"])
    assert d.status_code == 200 and d.content == b"build log\n"
    assert d.headers["content-disposition"].startswith("attachment;")
    assert d.headers["content-type"] == "application/octet-stream"
    assert d.headers["x-content-type-options"] == "nosniff"
    assert "inline" not in d.headers["content-disposition"]

    for name, data in (("page.html", b"<script>1</script>"), ("run.exe", b"MZ"), ("noext", b"abc")):
        bad = await c.post(up, files={"file": (name, data)})
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "type_not_allowed", name
    fake = await c.post(up, files={"file": ("shot.png", b"<html>not a png</html>")})
    assert fake.status_code == 422 and fake.json()["error"]["code"] == "content_does_not_match_type"
    assert (await c.post(up, files={"file": ("e.txt", b"")})).json()["error"][
        "code"
    ] == "empty_file"
    huge = await c.post(up, files={"file": ("big.txt", b"a" * (11 * 1024 * 1024))})
    assert huge.status_code == 413
    assert (await c.get(f"{API}/evidence-files/{uuid.uuid4()}/download")).status_code == 404


async def test_pdf_and_json_evidence_are_also_never_served_inline(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    fid = ids["CVE-2099-0001"]
    await c.post(f"{API}/findings/{fid}/triage", json=NOT_AFFECTED)
    for name, data in (("a.pdf", b"%PDF-1.4\n"), ("b.json", b'{"a": 1}')):
        r = await c.post(f"{API}/findings/{fid}/evidence/file", files={"file": (name, data)})
        assert r.status_code == 201, r.text
        link = next(x for x in r.json()["evidence"] if x["file_name"] == name)["download_url"]
        d = await c.get(link)
        assert (
            d.headers["content-disposition"].startswith("attachment")
            and d.headers["content-type"] == "application/octet-stream"
        )


# ---- bulk triage ----------------------------------------------------------------------------
async def test_bulk_triage_creates_one_audited_statement_per_finding(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003")
    r = await c.post(
        f"{API}/findings/bulk-triage",
        json={**NOT_AFFECTED, "finding_ids": [str(i) for i in ids.values()], "reason": "batch"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["created"] == 3 and len(r.json()["statements"]) == 3
    for fid in ids.values():
        assert (await c.get(f"{API}/findings/{fid}")).json()["state"] == "TRIAGED"
        assert await _audit_count(e, fid) == 1


async def test_bulk_triage_is_all_or_nothing(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003")
    odd = ids["CVE-2099-0002"]
    await c.post(f"{API}/findings/{odd}/triage", json=AFFECTED)  # this one will be a no-op
    r = await c.post(
        f"{API}/findings/bulk-triage",
        json={**AFFECTED, "finding_ids": [str(i) for i in ids.values()]},
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "no_op"
    assert r.json()["error"]["details"]["finding_id"] == str(odd)
    for vuln, fid in ids.items():
        if fid != odd:
            assert (await c.get(f"{API}/findings/{fid}")).json()["state"] == "UNTRIAGED", vuln
            assert await _audit_count(e, fid) == 0
    assert await _audit_count(e, odd) == 1


async def test_bulk_triage_validation_limits_and_unknown_ids(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001", "CVE-2099-0002")
    fid = str(ids["CVE-2099-0001"])
    invalid = await c.post(
        f"{API}/findings/bulk-triage", json={"status": "not_affected", "finding_ids": [fid]}
    )
    assert (
        invalid.status_code == 422 and invalid.json()["error"]["code"] == "justification_required"
    )
    assert (
        await c.post(f"{API}/findings/bulk-triage", json={**AFFECTED, "finding_ids": []})
    ).status_code == 422
    assert (
        await c.post(f"{API}/findings/bulk-triage", json={**AFFECTED, "finding_ids": [fid, fid]})
    ).status_code == 422
    many = [str(uuid.uuid4()) for _ in range(201)]
    assert (
        await c.post(f"{API}/findings/bulk-triage", json={**AFFECTED, "finding_ids": many})
    ).status_code == 422
    unknown = await c.post(
        f"{API}/findings/bulk-triage", json={**AFFECTED, "finding_ids": [fid, str(uuid.uuid4())]}
    )
    assert unknown.status_code == 404
    assert (await c.get(f"{API}/findings/{fid}")).json()["state"] == "UNTRIAGED"


async def test_bulk_triage_of_the_maximum_200_findings_in_one_transaction(env):
    e = await env()
    from tests.integration.seed import seed_finding, seed_release

    s = await seed_release(e.factory, ["lib"], edges=[("app", "lib")])
    ids = [(await seed_finding(e.factory, s, "lib", f"CVE-2099-{i:04d}")).id for i in range(200)]
    c = e.client(await e.person("analyst"))
    r = await c.post(
        f"{API}/findings/bulk-triage", json={**AFFECTED, "finding_ids": [str(i) for i in ids]}
    )
    assert r.status_code == 201 and r.json()["created"] == 200


async def test_needs_review_finding_shows_the_older_statement_as_context(env):
    e, s, ids, c, _ = await _setup(env, "CVE-2099-0001")
    old = (await c.post(f"{API}/findings/{ids['CVE-2099-0001']}/triage", json=AFFECTED)).json()
    _, ids_b = await add_release(e, s, "1.1.0", {"lib": "1.1"}, {"lib": ["CVE-2099-0001"]})
    fid = ids_b[("lib", "CVE-2099-0001")]
    plain = (await c.get(f"{API}/findings/{fid}")).json()
    assert plain["state"] == "UNTRIAGED" and plain["review_context"] is None
    async with e.factory() as session, session.begin():
        row = await session.get(FindingRow, fid)
        assert row is not None
        row.needs_review = True
    d = (await c.get(f"{API}/findings/{fid}")).json()
    assert d["state"] == "NEEDS_REVIEW" and d["statements"] == []
    assert d["review_context"]["release_version"] == "1.0.0"
    assert d["review_context"]["statement"]["id"] == old["id"]
    # the older release's own finding never carries context
    older = (await c.get(f"{API}/findings/{ids['CVE-2099-0001']}")).json()
    assert older["review_context"] is None
