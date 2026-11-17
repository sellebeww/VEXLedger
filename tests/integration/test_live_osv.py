# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Talks to the REAL api.osv.dev. Skipped by default. Run it yourself:

    uv run pytest -m live_osv tests/integration/test_live_osv.py

It asserts only on the shape of real responses, never on which vulnerabilities exist.
"""

import pytest

from vexledger.osv.client import OsvClient

pytestmark = pytest.mark.live_osv

KNOWN_ID = (
    "GHSA-jfh8-c2jp-5v3q"  # a long-published GitHub advisory; used only to prove the detail path
)


async def test_real_querybatch_and_detail_have_the_expected_shape() -> None:
    async with OsvClient("https://api.osv.dev") as client:
        found = await client.query_purls(
            ["pkg:pypi/jinja2@2.4.1", "pkg:pypi/this-package-does-not-exist-vexledger@0.0.1"]
        )
        assert set(found) == {
            "pkg:pypi/jinja2@2.4.1",
            "pkg:pypi/this-package-does-not-exist-vexledger@0.0.1",
        }
        assert found["pkg:pypi/this-package-does-not-exist-vexledger@0.0.1"] == ()
        assert all(r.id for refs in found.values() for r in refs)
        record = await client.get_vulnerability(KNOWN_ID)
        assert (
            record is not None and record["id"] == KNOWN_ID and isinstance(record["modified"], str)
        )
        assert await client.get_vulnerability("GHSA-0000-0000-0000-vexledger-missing") is None
