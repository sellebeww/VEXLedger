# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""A fake OSV.dev served through respx. Records are SYNTHETIC (see tests/fixtures/README.md)."""

import json
from pathlib import Path
from typing import Any

import httpx
import respx

FIXTURES = Path(__file__).parents[1] / "fixtures" / "osv_synthetic"
BASE = "https://osv.test"


def fixture(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text())
    return data


class FakeOsv:
    """purl -> record ids; id -> record. Counts calls so tests can prove cache behaviour."""

    def __init__(self, router: respx.MockRouter) -> None:
        self.by_purl: dict[str, list[str]] = {}
        self.records: dict[str, dict[str, Any]] = {}
        self.missing: set[str] = set()  # ids whose detail answers 404
        self.failing: set[str] = set()  # ids whose detail answers 503
        self.down = False
        self.batch_calls = 0
        self.detail_calls: list[str] = []
        router.post(BASE + "/v1/querybatch").mock(side_effect=self._batch)
        router.get(url__regex=rf"{BASE}/v1/vulns/.*").mock(side_effect=self._detail)

    def serve(self, purl: str, *names: str) -> None:
        self.by_purl[purl] = list(names)
        for name in names:
            self.records.setdefault(name, fixture(name))

    def _batch(self, request: httpx.Request) -> httpx.Response:
        self.batch_calls += 1
        if self.down:
            return httpx.Response(503)
        queries = json.loads(request.content)["queries"]
        results = []
        for q in queries:
            ids = self.by_purl.get(q["package"]["purl"], [])
            results.append(
                {"vulns": [{"id": i, "modified": self.records[i]["modified"]} for i in ids]}
                if ids
                else {}
            )
        return httpx.Response(200, json={"results": results})

    def _detail(self, request: httpx.Request) -> httpx.Response:
        osv_id = request.url.path.rsplit("/", 1)[-1]
        self.detail_calls.append(osv_id)
        if self.down or osv_id in self.failing:
            return httpx.Response(503)
        if osv_id in self.missing or osv_id not in self.records:
            return httpx.Response(404)
        return httpx.Response(200, json=self.records[osv_id])
