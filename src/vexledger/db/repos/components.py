# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Component aggregate and the dependency graph queries."""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vexledger.db.models import Component, ComponentEdge

DEFAULT_MAX_DEPTH = 12

# Set semantics (UNION, not UNION ALL) keep the walk finite on cycles and cap the work at
# edges x depth, because identical (node, depth, parent) rows are stored once. No path arrays,
# so dense DAGs cannot explode combinatorially.
_WALK = text(
    """
    WITH RECURSIVE walk (component_id, depth, parent_id) AS (
        SELECT c.id, 0, NULL::uuid
        FROM components c
        WHERE c.release_id = :release_id AND c.is_root
      UNION
        SELECT e.child_id, w.depth + 1, e.parent_id
        FROM walk w
        JOIN component_edges e ON e.parent_id = w.component_id AND e.release_id = :release_id
        WHERE w.depth < :max_depth
    )
    SELECT DISTINCT ON (component_id) component_id, depth, parent_id
    FROM walk
    ORDER BY component_id, depth, parent_id
    """
)


@dataclass(frozen=True)
class DependencyPaths:
    """Shortest paths from the root (metadata.component) for every reachable component."""

    _parent: dict[uuid.UUID, uuid.UUID | None]
    _depth: dict[uuid.UUID, int]

    def depth(self, component_id: uuid.UUID) -> int | None:
        return self._depth.get(component_id)

    def is_direct(self, component_id: uuid.UUID) -> bool | None:
        """True for a direct dependency, False for a transitive one, None when unreachable."""
        d = self._depth.get(component_id)
        return None if d is None or d == 0 else d == 1

    def path_to(self, component_id: uuid.UUID) -> tuple[uuid.UUID, ...] | None:
        if component_id not in self._depth:
            return None
        path = [component_id]
        while (parent := self._parent[path[-1]]) is not None:
            path.append(parent)
        return tuple(reversed(path))


class ComponentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add_all(
        self, components: Sequence[Component], edges: Sequence[ComponentEdge] = ()
    ) -> None:
        self.session.add_all(components)
        await self.session.flush()  # components first: edges reference them
        self.session.add_all(edges)
        await self.session.flush()

    async def shortest_paths(
        self, release_id: uuid.UUID, max_depth: int = DEFAULT_MAX_DEPTH
    ) -> DependencyPaths:
        rows = (
            await self.session.execute(_WALK, {"release_id": release_id, "max_depth": max_depth})
        ).all()
        return DependencyPaths(
            {r.component_id: r.parent_id for r in rows}, {r.component_id: r.depth for r in rows}
        )
