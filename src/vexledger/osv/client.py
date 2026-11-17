# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""OSV.dev client. The base URL comes from configuration, never from input.

Behaviour: querybatch in chunks of at most 1000 queries; `next_page_token` is followed PER
query until it is exhausted (a page that holds only a token is followed too); record details
are fetched with bounded concurrency; every request has explicit timeouts; 429, 5xx and
transport errors are retried with exponential backoff and full jitter, honouring Retry-After.
"""

import asyncio
import random
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from vexledger.osv.errors import OsvPermanentError, OsvProtocolError, OsvUnavailableError
from vexledger.services.metrics import Metrics

BATCH_SIZE = 1000
MAX_PAGES_PER_QUERY = 100
RETRY_AFTER_CAP_S = 60.0
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class OsvRef:
    id: str
    modified: str | None


def default_timeout(connect: float = 5.0, read: float = 30.0) -> httpx.Timeout:
    return httpx.Timeout(connect=connect, read=read, write=10.0, pool=5.0)


class OsvClient:
    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        http2: bool = True,
        max_retries: int = 5,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 20.0,
        concurrency: int = 8,
        metrics: Metrics | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url, http2=http2, timeout=default_timeout()
        )
        self._max_retries = max_retries
        self._base = backoff_base_s
        self._cap = backoff_cap_s
        self._sem = asyncio.Semaphore(concurrency)
        self.metrics = metrics or Metrics()
        self._sleep = sleep
        self._rng = rng or random.Random()  # noqa: S311 - jitter only, not security
        self._base_url = base_url.rstrip("/")

    async def __aenter__(self) -> OsvClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # transport

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        jitter = self._rng.uniform(0, min(self._cap, self._base * 2**attempt))
        if retry_after is not None:
            try:
                return max(jitter, min(float(retry_after), RETRY_AFTER_CAP_S))
            except ValueError:
                pass  # an HTTP-date Retry-After is ignored; the jittered backoff applies
        return jitter

    async def _request(self, method: str, path: str, json: Any = None) -> httpx.Response:
        """Return a response with status < 400 or 404. Raises typed errors otherwise."""
        last = "no attempt"
        for attempt in range(self._max_retries + 1):
            retry_after: str | None = None
            try:
                resp = await self._client.request(method, self._base_url + path, json=json)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = f"{type(exc).__name__}"
            else:
                if resp.status_code < 400 or resp.status_code == 404:
                    return resp
                if resp.status_code not in _RETRYABLE_STATUS:
                    raise OsvPermanentError(
                        f"OSV rejected {method} {path}: HTTP {resp.status_code}"
                    )
                last = f"HTTP {resp.status_code}"
                retry_after = resp.headers.get("retry-after")
            if attempt == self._max_retries:
                break
            self.metrics.inc("osv_retries")
            await self._sleep(self._delay(attempt, retry_after))
        raise OsvUnavailableError(
            f"OSV unreachable for {method} {path} after {self._max_retries + 1} attempts ({last})"
        )

    @staticmethod
    def _json(resp: httpx.Response, what: str) -> Any:
        try:
            return resp.json()
        except ValueError as exc:
            raise OsvProtocolError(f"{what}: response is not JSON") from exc

    # querybatch

    @staticmethod
    def _parse_batch(data: Any, expected: int) -> list[tuple[list[OsvRef], str | None]]:
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != expected:
            raise OsvProtocolError("querybatch: results missing or not aligned with the queries")
        parsed: list[tuple[list[OsvRef], str | None]] = []
        for item in results:
            if not isinstance(item, dict):
                raise OsvProtocolError("querybatch: result entry is not an object")
            vulns = item.get("vulns") or []
            token = item.get("next_page_token")
            if not isinstance(vulns, list) or not (token is None or isinstance(token, str)):
                raise OsvProtocolError("querybatch: malformed vulns or next_page_token")
            refs = []
            for v in vulns:
                if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"]:
                    raise OsvProtocolError("querybatch: vuln without a string id")
                modified = v.get("modified")
                refs.append(OsvRef(v["id"], modified if isinstance(modified, str) else None))
            parsed.append((refs, token or None))
        return parsed

    async def query_purls(self, purls: Iterable[str]) -> dict[str, tuple[OsvRef, ...]]:
        """OSV ids per purl (deduplicated input, every page followed). All or nothing."""
        unique = list(dict.fromkeys(purls))
        found: dict[str, dict[str, OsvRef]] = {p: {} for p in unique}
        pages: dict[str, int] = dict.fromkeys(unique, 0)
        pending: list[tuple[str, str | None]] = [(p, None) for p in unique]
        while pending:
            following: list[tuple[str, str | None]] = []
            for start in range(0, len(pending), BATCH_SIZE):
                chunk = pending[start : start + BATCH_SIZE]
                queries = [
                    {"package": {"purl": p}, **({"page_token": t} if t else {})} for p, t in chunk
                ]
                self.metrics.inc("osv_queries", len(queries))
                self.metrics.inc("osv_batch_requests")
                resp = await self._request("POST", "/v1/querybatch", {"queries": queries})
                if resp.status_code == 404:
                    raise OsvProtocolError("querybatch endpoint returned 404")
                parsed = self._parse_batch(self._json(resp, "querybatch"), len(chunk))
                for (purl, sent_token), (refs, token) in zip(chunk, parsed, strict=True):
                    for ref in refs:
                        found[purl][ref.id] = ref
                    if token is not None:
                        pages[purl] += 1
                        if token == sent_token or pages[purl] >= MAX_PAGES_PER_QUERY:
                            raise OsvProtocolError(f"pagination for {purl} does not terminate")
                        following.append((purl, token))
            pending = following
        return {p: tuple(found[p].values()) for p in unique}

    # record details

    async def get_vulnerability(self, osv_id: str) -> dict[str, Any] | None:
        """The OSV record, or None if OSV no longer has it (404)."""
        async with self._sem:
            self.metrics.inc("osv_detail_fetches")
            resp = await self._request("GET", f"/v1/vulns/{quote(osv_id, safe='')}")
        if resp.status_code == 404:
            self.metrics.inc("osv_detail_missing")
            return None
        data = self._json(resp, f"vulns/{osv_id}")
        if not isinstance(data, dict) or data.get("id") != osv_id:
            raise OsvProtocolError(f"vulns/{osv_id}: record id does not match the request")
        if not isinstance(data.get("modified"), str):
            raise OsvProtocolError(f"vulns/{osv_id}: record has no modified timestamp")
        return data

    async def fetch_vulnerabilities(
        self, osv_ids: Sequence[str]
    ) -> dict[str, dict[str, Any] | None]:
        """Details for many ids concurrently (bounded). One failure fails the whole call."""
        unique = list(dict.fromkeys(osv_ids))
        try:
            # TaskGroup cancels the siblings on the first failure: no orphaned requests.
            async with asyncio.TaskGroup() as group:
                tasks = [group.create_task(self.get_vulnerability(i)) for i in unique]
        except ExceptionGroup as group_error:
            raise group_error.exceptions[0] from None
        return {i: t.result() for i, t in zip(unique, tasks, strict=True)}
