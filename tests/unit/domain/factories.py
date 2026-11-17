# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Builders for lifecycle tests. All times are fixed; nothing reads the system clock."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from vexledger.domain.model import (
    Finding,
    Justification,
    Statement,
    Status,
    TriagedFinding,
)

NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=1)
IMPACT = "The vulnerable function is never called by this product."  # > 20 chars
NOTES = "Fixed by upgrading to 2.0."  # > 10 chars


def finding(vuln: str = "CVE-2099-0001", ref: str = "pypi/foo@1.0", **kw: Any) -> Finding:
    key = ref.split("@")[0]
    return Finding(
        canonical_vuln_id=vuln,
        aliases=kw.pop("aliases", ()),
        component_key=kw.pop("component_key", key),
        component_ref=ref,
        component_purl=kw.pop("component_purl", f"pkg:{ref}"),
        **kw,
    )


def stmt(
    sid: str = "s1",
    vuln: str = "CVE-2099-0001",
    ref: str = "pypi/foo@1.0",
    status: Status = Status.NOT_AFFECTED,
    created_at: datetime = NOW,
    **kw: Any,
) -> Statement:
    if status is Status.NOT_AFFECTED:
        kw.setdefault("justification", Justification.VULNERABLE_CODE_NOT_PRESENT)
        kw.setdefault("impact_statement", IMPACT)
    if status is Status.AFFECTED:
        kw.setdefault("action_statement", "Upgrade to 2.0.")
    if status is Status.FIXED:
        kw.setdefault("status_notes", NOTES)
    kw.setdefault("created_by", "analyst")
    kw.setdefault("valid_until", NOW + timedelta(days=180))
    return Statement(sid, vuln, ref, status, created_at, **kw)


def tf(f: Finding, s: Statement | None = None, withdrawn: bool = False) -> TriagedFinding:
    return TriagedFinding(f, s, withdrawn)


def with_(s: Statement, **kw: Any) -> Statement:
    return replace(s, **kw)
