# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""SYNTHETIC OSV records and an in-process httpx transport that serves them.

Nothing here is real vulnerability data. Every id is made up (CVE-2099-*, GHSA-demo-*), every
summary starts with the demo label, and every record claims ALL versions of its package are
affected so the demo behaves the same whatever versions the demo SBOMs hold. It exists so the
whole workflow can be shown without internet access and without implying that any real package
is vulnerable. Package names are real only because the demo SBOMs are real tool output.
"""

import json
from typing import Any

import httpx
from packageurl import PackageURL

DEMO_LABEL = "DATA DEMO SINTETIS"
_MODIFIED = "2099-01-01T00:00:00Z"
_DETAILS = (
    f"{DEMO_LABEL}: made-up record for demonstrating VEXLedger. "
    "It does not describe a real vulnerability."
)

# (id, aliases, PyPI package, withdrawn?)
_SPECS: tuple[tuple[str, tuple[str, ...], str, bool], ...] = (
    ("CVE-2099-1001", ("GHSA-demo-0001-aaaa",), "idna", False),
    ("CVE-2099-1002", ("GHSA-demo-0002-aaaa",), "certifi", False),
    ("GHSA-demo-0003-aaaa", (), "h11", False),
    ("CVE-2099-1004", ("PYSEC-2099-1004",), "pyyaml", False),
    ("CVE-2099-1005", (), "markupsafe", False),
    ("CVE-2099-1006", (), "attrs", False),
    ("CVE-2099-1007", (), "click", False),
    ("CVE-2099-1008", (), "packaging", False),
    ("CVE-2099-1009", (), "pygments", False),
    ("CVE-2099-1010", (), "httpcore", False),
    ("GHSA-demo-wd01-aaaa", (), "anyio", True),
)


def _record(osv_id: str, aliases: tuple[str, ...], package: str, withdrawn: bool) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": osv_id,
        "modified": _MODIFIED,
        "aliases": list(aliases),
        "summary": f"[{DEMO_LABEL}] {osv_id} in {package}",
        "details": _DETAILS,
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}],
        "database_specific": {"severity": "LOW", "vexledger_demo": "synthetic"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9999"}]}
                ],
            }
        ],
    }
    if withdrawn:
        record["withdrawn"] = _MODIFIED
    return record


RECORDS: dict[str, dict[str, Any]] = {s[0]: _record(*s) for s in _SPECS}
_BY_PACKAGE: dict[str, list[str]] = {}
for _id, _aliases, _package, _wd in _SPECS:
    _BY_PACKAGE.setdefault(_package, []).append(_id)


def _ids_for_purl(purl: str) -> list[str]:
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return []
    if parsed.type != "pypi":
        return []
    return _BY_PACKAGE.get(parsed.name.lower().replace("_", "-").replace(".", "-"), [])


class DemoOsvTransport(httpx.AsyncBaseTransport):
    """Answers `POST /v1/querybatch` and `GET /v1/vulns/{id}` from RECORDS, no network."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = [
                {
                    "vulns": [
                        {"id": i, "modified": RECORDS[i]["modified"]}
                        for i in _ids_for_purl(q["package"]["purl"])
                    ]
                }
                for q in queries
            ]
            return httpx.Response(200, json={"results": results})
        if request.method == "GET" and path.startswith("/v1/vulns/"):
            record = RECORDS.get(path.removeprefix("/v1/vulns/"))
            return httpx.Response(200 if record else 404, json=record or {})
        return httpx.Response(404, json={})
