# Copyright (c) 2026 Vassel Goleyu. MIT License.
import pytest

from vexledger.db.repos.components import DEFAULT_MAX_DEPTH, ComponentRepository

from .seed import seed_release

pytestmark = pytest.mark.integration


async def paths(factory, seeded, max_depth=DEFAULT_MAX_DEPTH):  # type: ignore[no-untyped-def]
    async with factory() as s:
        return await ComponentRepository(s).shortest_paths(seeded.release.id, max_depth)


def names(seeded, path):  # type: ignore[no-untyped-def]
    by_id = {c.id: n for n, c in seeded.components.items()}
    return [by_id[i] for i in path]


async def test_chain_direct_and_transitive(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["a", "b", "c"], [("app", "a"), ("a", "b"), ("b", "c")])
    p = await paths(factory, seeded)
    c = seeded.components
    assert names(seeded, p.path_to(c["c"].id)) == ["app", "a", "b", "c"]  # type: ignore[arg-type]
    assert p.depth(c["c"].id) == 3
    assert p.is_direct(c["a"].id) is True
    assert p.is_direct(c["b"].id) is False
    assert p.is_direct(c["app"].id) is None  # the root is neither
    assert names(seeded, p.path_to(c["app"].id)) == ["app"]  # type: ignore[arg-type]


async def test_diamond_picks_the_shortest_path(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(
        factory,
        ["a", "b", "c", "d"],
        [("app", "a"), ("a", "b"), ("b", "c"), ("c", "d"), ("app", "c")],
    )
    p = await paths(factory, seeded)
    assert names(seeded, p.path_to(seeded.components["d"].id)) == ["app", "c", "d"]  # type: ignore[arg-type]
    assert p.depth(seeded.components["c"].id) == 1


async def test_cycles_terminate(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(
        factory, ["a", "b", "c"], [("app", "a"), ("a", "b"), ("b", "c"), ("c", "a"), ("b", "app")]
    )
    p = await paths(factory, seeded)
    assert names(seeded, p.path_to(seeded.components["c"].id)) == ["app", "a", "b", "c"]  # type: ignore[arg-type]
    assert p.depth(seeded.components["app"].id) == 0


async def test_depth_limit_cuts_off_deeper_components(factory) -> None:  # type: ignore[no-untyped-def]
    chain = [f"n{i}" for i in range(1, 16)]
    edges = [("app", "n1"), *[(a, b) for a, b in zip(chain, chain[1:], strict=False)]]
    seeded = await seed_release(factory, chain, edges)
    default = await paths(factory, seeded)
    assert default.depth(seeded.components["n12"].id) == 12  # at the limit: reachable
    assert default.path_to(seeded.components["n13"].id) is None  # beyond the limit
    shallow = await paths(factory, seeded, max_depth=3)
    assert shallow.depth(seeded.components["n3"].id) == 3
    assert shallow.path_to(seeded.components["n4"].id) is None
    deep = await paths(factory, seeded, max_depth=20)
    assert deep.depth(seeded.components["n15"].id) == 15


async def test_unreachable_component_and_missing_root(factory) -> None:  # type: ignore[no-untyped-def]
    seeded = await seed_release(factory, ["a", "orphan"], [("app", "a")])
    p = await paths(factory, seeded)
    assert p.path_to(seeded.components["orphan"].id) is None
    assert p.is_direct(seeded.components["orphan"].id) is None


async def test_dense_graph_stays_fast(factory) -> None:  # type: ignore[no-untyped-def]
    layers = [[f"l{d}_{i}" for i in range(6)] for d in range(8)]
    flat = [n for layer in layers for n in layer]
    edges = [("app", n) for n in layers[0]]
    for upper, lower in zip(layers, layers[1:], strict=False):
        edges += [(u, low) for u in upper for low in lower]  # 6^8 distinct paths, 300 edges
    seeded = await seed_release(factory, flat, edges)
    p = await paths(factory, seeded)
    assert p.depth(seeded.components["l7_5"].id) == 8
