# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""OSV client behaviour against a mocked API (respx). The payloads here are synthetic."""

import asyncio
import json
import random
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

from vexledger.osv.client import BATCH_SIZE, OsvClient, OsvRef
from vexledger.osv.errors import OsvPermanentError, OsvProtocolError, OsvUnavailableError

BASE = "https://osv.test"


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as r:
        yield r


class Sleeps:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


def make_client(sleeps: Sleeps | None = None, **kw: Any) -> OsvClient:
    return OsvClient(
        BASE, client=httpx.AsyncClient(), sleep=sleeps or Sleeps(), rng=random.Random(1), **kw
    )


def batch_response(results: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"results": results})


def queries_of(request: httpx.Request) -> list[dict[str, Any]]:
    return json.loads(request.content)["queries"]


async def test_batches_are_cut_at_1000_and_results_stay_aligned(router: respx.MockRouter) -> None:
    sizes: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        qs = queries_of(request)
        sizes.append(len(qs))
        return batch_response(
            [
                {
                    "vulns": [
                        {"id": "V-" + q["package"]["purl"][-4:], "modified": "2099-01-01T00:00:00Z"}
                    ]
                }
                for q in qs
            ]
        )

    router.post(BASE + "/v1/querybatch").mock(side_effect=handler)
    purls = [f"pkg:pypi/p@{i:04d}" for i in range(2500)]
    client = make_client()
    out = await client.query_purls(purls + purls[:10])  # duplicates are sent once
    assert sizes == [BATCH_SIZE, BATCH_SIZE, 500]
    assert len(out) == 2500
    assert all(out[p][0].id == "V-" + p[-4:] for p in purls)
    assert client.metrics.counters["osv_queries"] == 2500
    assert client.metrics.counters["osv_batch_requests"] == 3


async def test_the_request_shape_matches_the_osv_api(router: respx.MockRouter) -> None:
    route = router.post(BASE + "/v1/querybatch").mock(return_value=batch_response([{}]))
    await make_client().query_purls(["pkg:pypi/a@1"])
    assert queries_of(route.calls.last.request) == [{"package": {"purl": "pkg:pypi/a@1"}}]


async def test_pagination_is_followed_per_query_including_token_only_pages(
    router: respx.MockRouter,
) -> None:
    seen: list[list[tuple[str, str | None]]] = []
    pages = {
        ("pkg:pypi/one@1", None): {
            "vulns": [{"id": "A-1", "modified": "m1"}],
            "next_page_token": "t1",
        },
        ("pkg:pypi/one@1", "t1"): {"next_page_token": "t2"},  # a page holding only a token
        ("pkg:pypi/one@1", "t2"): {
            "vulns": [{"id": "A-2", "modified": "m2"}, {"id": "A-1", "modified": "m9"}]
        },
        ("pkg:pypi/two@1", None): {"vulns": [{"id": "B-1", "modified": "m1"}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        qs = [(q["package"]["purl"], q.get("page_token")) for q in queries_of(request)]
        seen.append(qs)
        return batch_response([pages[q] for q in qs])

    router.post(BASE + "/v1/querybatch").mock(side_effect=handler)
    out = await make_client().query_purls(["pkg:pypi/one@1", "pkg:pypi/two@1"])
    assert seen == [
        [("pkg:pypi/one@1", None), ("pkg:pypi/two@1", None)],
        [("pkg:pypi/one@1", "t1")],  # only the unfinished query continues
        [("pkg:pypi/one@1", "t2")],
    ]
    assert {r.id for r in out["pkg:pypi/one@1"]} == {"A-1", "A-2"}
    assert next(r for r in out["pkg:pypi/one@1"] if r.id == "A-1") == OsvRef(
        "A-1", "m9"
    )  # newest modified kept
    assert [r.id for r in out["pkg:pypi/two@1"]] == ["B-1"]


async def test_a_token_that_never_changes_is_a_protocol_error(router: respx.MockRouter) -> None:
    router.post(BASE + "/v1/querybatch").mock(
        return_value=batch_response([{"next_page_token": "same"}])
    )
    with pytest.raises(OsvProtocolError, match="terminate"):
        await make_client().query_purls(["pkg:pypi/a@1"])


async def test_endless_distinct_tokens_are_cut_off(router: respx.MockRouter) -> None:
    counter = iter(range(10_000))
    router.post(BASE + "/v1/querybatch").mock(
        side_effect=lambda r: batch_response([{"next_page_token": f"t{next(counter)}"}])
    )
    with pytest.raises(OsvProtocolError, match="terminate"):
        await make_client().query_purls(["pkg:pypi/a@1"])


async def test_429_is_retried_with_backoff_then_succeeds(router: respx.MockRouter) -> None:
    responses = iter(
        [
            httpx.Response(429, headers={"Retry-After": "3"}),
            httpx.Response(503),
            batch_response([{"vulns": [{"id": "X-1"}]}]),
        ]
    )
    router.post(BASE + "/v1/querybatch").mock(side_effect=lambda r: next(responses))
    sleeps = Sleeps()
    client = make_client(sleeps)
    out = await client.query_purls(["pkg:pypi/a@1"])
    assert out["pkg:pypi/a@1"][0].id == "X-1"
    assert len(sleeps.delays) == 2
    assert sleeps.delays[0] >= 3.0  # honours Retry-After
    assert sleeps.delays[1] <= 1.0  # attempt 1: jitter within base * 2
    assert client.metrics.counters["osv_retries"] == 2


async def test_retry_after_is_capped_and_garbage_is_ignored() -> None:
    client = make_client()
    assert client._delay(0, "100000") <= 60.0
    assert client._delay(0, "Wed, 21 Oct 2030 07:28:00 GMT") <= 0.5
    assert all(0 <= client._delay(a, None) <= 20.0 for a in range(12))


async def test_persistent_500_becomes_a_typed_unavailable_error(router: respx.MockRouter) -> None:
    route = router.post(BASE + "/v1/querybatch").mock(return_value=httpx.Response(500))
    sleeps = Sleeps()
    with pytest.raises(OsvUnavailableError, match="after 4 attempts"):
        await make_client(sleeps, max_retries=3).query_purls(["pkg:pypi/a@1"])
    assert route.call_count == 4
    assert len(sleeps.delays) == 3  # no sleep after the final attempt


@pytest.mark.parametrize(
    "exc",
    [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("reset")],
)
async def test_transport_errors_and_timeouts_are_retried(
    router: respx.MockRouter, exc: Exception
) -> None:
    outcomes: list[Any] = [exc, batch_response([{}])]

    def side_effect(request: httpx.Request) -> httpx.Response:
        result = outcomes.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    router.post(BASE + "/v1/querybatch").mock(side_effect=side_effect)
    assert await make_client().query_purls(["pkg:pypi/a@1"]) == {"pkg:pypi/a@1": ()}


async def test_unreachable_server_is_unavailable_not_an_empty_result(
    router: respx.MockRouter,
) -> None:
    router.post(BASE + "/v1/querybatch").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(OsvUnavailableError, match="ConnectError"):
        await make_client(max_retries=2).query_purls(["pkg:pypi/a@1"])


async def test_other_4xx_is_permanent_and_not_retried(router: respx.MockRouter) -> None:
    route = router.post(BASE + "/v1/querybatch").mock(
        return_value=httpx.Response(400, json={"error": "bad"})
    )
    with pytest.raises(OsvPermanentError, match="400"):
        await make_client().query_purls(["pkg:pypi/a@1"])
    assert route.call_count == 1


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"results": "no"},
        {"results": []},  # not aligned with one query
        {"results": [1]},
        {"results": [{"vulns": "no"}]},
        {"results": [{"vulns": [{"modified": "x"}]}]},
        {"results": [{"vulns": [{"id": ""}]}]},
        {"results": [{"vulns": [1]}]},
        {"results": [{"next_page_token": 5}]},
        [],
    ],
)
async def test_malformed_batch_responses_are_rejected(
    router: respx.MockRouter, payload: Any
) -> None:
    router.post(BASE + "/v1/querybatch").mock(return_value=httpx.Response(200, json=payload))
    with pytest.raises(OsvProtocolError):
        await make_client().query_purls(["pkg:pypi/a@1"])


async def test_non_json_response_is_a_protocol_error(router: respx.MockRouter) -> None:
    router.post(BASE + "/v1/querybatch").mock(
        return_value=httpx.Response(200, text="<html>oops</html>")
    )
    with pytest.raises(OsvProtocolError, match="not JSON"):
        await make_client().query_purls(["pkg:pypi/a@1"])


async def test_a_bad_page_does_not_leak_partial_results(router: respx.MockRouter) -> None:
    responses = iter(
        [
            batch_response([{"vulns": [{"id": "A-1"}], "next_page_token": "t"}]),
            httpx.Response(200, json={"oops": 1}),
        ]
    )
    router.post(BASE + "/v1/querybatch").mock(side_effect=lambda r: next(responses))
    with pytest.raises(OsvProtocolError):
        await make_client().query_purls(
            ["pkg:pypi/a@1"]
        )  # nothing is returned, so nothing can be cached


# details


async def test_detail_fetch_quotes_the_id_and_validates(router: respx.MockRouter) -> None:
    record = {"id": "GHSA-a/b", "modified": "2099-01-01T00:00:00Z"}
    route = router.get(BASE + "/v1/vulns/GHSA-a%2Fb").mock(
        return_value=httpx.Response(200, json=record)
    )
    assert await make_client().get_vulnerability("GHSA-a/b") == record
    assert route.called


async def test_missing_detail_returns_none(router: respx.MockRouter) -> None:
    router.get(BASE + "/v1/vulns/X-1").mock(return_value=httpx.Response(404))
    client = make_client()
    assert await client.get_vulnerability("X-1") is None
    assert client.metrics.counters["osv_detail_missing"] == 1


@pytest.mark.parametrize(
    "body", [{"id": "OTHER", "modified": "m"}, {"id": "X-1"}, [], {"id": "X-1", "modified": 5}]
)
async def test_detail_with_wrong_shape_is_rejected(router: respx.MockRouter, body: Any) -> None:
    router.get(BASE + "/v1/vulns/X-1").mock(return_value=httpx.Response(200, json=body))
    with pytest.raises(OsvProtocolError):
        await make_client().get_vulnerability("X-1")


async def test_detail_fetching_is_concurrent_but_bounded(router: respx.MockRouter) -> None:
    active = 0
    peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        osv_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"id": osv_id, "modified": "m"})

    router.get(url__regex=rf"{BASE}/v1/vulns/.*").mock(side_effect=handler)
    out = await make_client(concurrency=3).fetch_vulnerabilities(
        [f"V-{i}" for i in range(12)] + ["V-0"]
    )
    assert len(out) == 12
    assert 1 < peak <= 3


async def test_one_failing_detail_fails_the_call_with_the_typed_error(
    router: respx.MockRouter,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("BAD"):
            return httpx.Response(400)
        return httpx.Response(
            200, json={"id": request.url.path.rsplit("/", 1)[-1], "modified": "m"}
        )

    router.get(url__regex=rf"{BASE}/v1/vulns/.*").mock(side_effect=handler)
    with pytest.raises(OsvPermanentError):
        await make_client().fetch_vulnerabilities(["A", "BAD", "C"])


async def test_owned_client_is_closed_and_a_given_client_is_not() -> None:
    given = httpx.AsyncClient()
    await OsvClient(BASE, client=given).aclose()
    assert not given.is_closed
    await given.aclose()
    owned = OsvClient(BASE, http2=False)
    async with owned:
        pass
    assert owned._client.is_closed


async def test_http2_client_can_be_constructed() -> None:
    async with OsvClient(BASE, http2=True) as client:  # needs the h2 package
        assert client._client is not None
