# Copyright (c) 2026 Vassel Goleyu. MIT License.
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from vexledger.db.models import AuditLog, Evidence, EvidenceFile, VexExport, VexStatement
from vexledger.db.repos.audit import append_audit

from .seed import NOW, seed_finding, seed_release

pytestmark = pytest.mark.integration


async def _statement_id(factory) -> uuid.UUID:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["lib"])
    finding = await seed_finding(factory, seeded, "lib")
    sid = uuid.uuid4()
    async with factory() as s, s.begin():
        s.add(
            VexStatement(
                id=sid,
                finding_id=finding.id,
                canonical_vuln_id="CVE-2099-0001",
                component_ref="pypi/lib@1.0",
                status="under_investigation",
                created_by="t",
                created_at=NOW,
            )
        )
        append_audit(s, actor_id=None, action="t", entity_type="finding", entity_id=str(finding.id))
        file = EvidenceFile(
            storage_name=uuid.uuid4().hex + ".txt",
            original_name="a.txt",
            sha256="a" * 64,
            size_bytes=1,
            detected_type="txt",
        )
        s.add(file)
        await s.flush()
        s.add(Evidence(statement_id=sid, kind="FILE", evidence_file_id=file.id))
        s.add(
            VexExport(
                release_id=seeded.release.id, version=1, content_sha256="b" * 64, document=b"{}"
            )
        )
    return sid


async def test_orm_update_and_delete_of_a_statement_fail(factory) -> None:  # type: ignore[no-untyped-def]
    sid = await _statement_id(factory)
    with pytest.raises(DBAPIError, match="append-only"):
        async with factory() as s, s.begin():
            row = await s.get(VexStatement, sid)
            assert row is not None
            row.status_notes = "tampered"
    with pytest.raises(DBAPIError, match="append-only"):
        async with factory() as s, s.begin():
            row = await s.get(VexStatement, sid)
            await s.delete(row)


@pytest.mark.parametrize(
    "table", ["vex_statements", "audit_log", "evidence", "evidence_files", "vex_exports"]
)
async def test_raw_sql_update_delete_and_truncate_fail(factory, table: str) -> None:  # type: ignore[no-untyped-def]
    await _statement_id(factory)  # makes sure vex_statements and audit_log have rows
    for sql in (f"UPDATE {table} SET id = id", f"DELETE FROM {table}", f"TRUNCATE {table} CASCADE"):
        with pytest.raises(DBAPIError, match="append-only"):
            async with factory() as s, s.begin():
                await s.execute(text(sql))


async def test_audit_log_rows_cannot_be_changed_via_orm(factory) -> None:  # type: ignore[no-untyped-def]
    await _statement_id(factory)
    with pytest.raises(DBAPIError, match="append-only"):
        async with factory() as s, s.begin():
            row = (await s.execute(text("SELECT id FROM audit_log LIMIT 1"))).scalar_one()
            entry = await s.get(AuditLog, row)
            assert entry is not None
            entry.action = "forged"
    with pytest.raises(DBAPIError, match="append-only"):
        async with factory() as s, s.begin():
            await s.execute(text("DELETE FROM audit_log WHERE id = :i"), {"i": row})


async def test_failed_attempts_leave_the_data_intact(factory) -> None:  # type: ignore[no-untyped-def]
    sid = await _statement_id(factory)
    with pytest.raises(DBAPIError):
        async with factory() as s, s.begin():
            await s.execute(text("DELETE FROM vex_statements WHERE id = :i"), {"i": sid})
    async with factory() as s:
        assert (await s.get(VexStatement, sid)) is not None
