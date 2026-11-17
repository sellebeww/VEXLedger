# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""The offline demo transport serves SYNTHETIC records through the real OSV client."""

import httpx
import pytest

from vexledger.demo.osv_fixtures import DEMO_LABEL, RECORDS, DemoOsvTransport
from vexledger.osv.client import OsvClient


@pytest.fixture
def client() -> OsvClient:
    http = httpx.AsyncClient(transport=DemoOsvTransport())
    return OsvClient("http://demo.invalid", client=http, max_retries=0)


async def test_every_record_is_labelled_synthetic() -> None:
    for osv_id, record in RECORDS.items():
        assert DEMO_LABEL in record["summary"], osv_id
        assert osv_id.startswith(("CVE-2099-", "GHSA-demo-")), osv_id
        assert record["database_specific"]["vexledger_demo"] == "synthetic"


async def test_querybatch_matches_by_package_not_version() -> None:
    http = httpx.AsyncClient(transport=DemoOsvTransport())
    queries = [
        {"package": {"purl": "pkg:pypi/idna@3.20"}},
        {"package": {"purl": "pkg:pypi/idna@3.21"}},
        {"package": {"purl": "pkg:pypi/PyYAML@6.0.3"}},
        {"package": {"purl": "pkg:npm/left-pad@1.0.0"}},
        {"package": {"purl": "not a purl"}},
    ]
    resp = await http.post("http://x/v1/querybatch", json={"queries": queries})
    ids = [[v["id"] for v in r["vulns"]] for r in resp.json()["results"]]
    assert ids == [["CVE-2099-1001"], ["CVE-2099-1001"], ["CVE-2099-1004"], [], []]


async def test_detail_and_unknown_paths(client: OsvClient) -> None:
    http = httpx.AsyncClient(transport=DemoOsvTransport())
    ok = await http.get("http://x/v1/vulns/CVE-2099-1001")
    assert ok.status_code == 200
    assert ok.json()["aliases"] == ["GHSA-demo-0001-aaaa"]
    assert (await http.get("http://x/v1/vulns/CVE-1999-0001")).status_code == 404
    assert (await http.get("http://x/other")).status_code == 404
    await client.aclose()
