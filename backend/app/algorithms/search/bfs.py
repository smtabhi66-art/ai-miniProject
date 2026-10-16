"""Breadth-First Search (BFS).

Problem in SentinelAI
    "If device X is compromised, which devices can it reach, and how many hops
    away is each one?" (the *blast radius*). Also: "is there any usable path
    from A to B?", which the simulator uses to decide whether an event can happen.

Why BFS
    BFS explores level by level (all 1-hop devices, then all 2-hop devices, ...),
    so the first time it reaches a device is along a path with the fewest hops.
    Grouping devices by hop distance is exactly the blast radius.

Data structures
    FIFO queue (collections.deque), a ``depth`` dict that doubles as the visited
    set, and a ``parent`` dict for rebuilding paths.

Complexity
    Time O(V + E): each node is enqueued once and each edge examined twice.
    Space O(V) for the queue, depth and parent maps.
"""
from collections import deque
from dataclasses import dataclass, field

from app.algorithms.search.graph import Graph, TraceStep


@dataclass
class BFSResult:
    start: str
    depth: dict[str, int]           # hop distance from start; keys = discovered nodes
    parent: dict[str, str | None]
    order: list[str]                # dequeue order
    trace: list[TraceStep] = field(default_factory=list)

    def layers(self) -> list[list[str]]:
        """``layers()[k]`` = devices exactly k hops from the start."""
        layers: list[list[str]] = []
        for node in self.order:
            d = self.depth[node]
            while len(layers) <= d:
                layers.append([])
            layers[d].append(node)
        return layers

    def reachable(self) -> list[str]:
        return [n for n in self.order if n != self.start]

    def path_to(self, node: str) -> list[str] | None:
        if node not in self.parent:
            return None
        path = []
        current: str | None = node
        while current is not None:
            path.append(current)
            current = self.parent[current]
        return path[::-1]


def bfs(graph: Graph, start: str, max_depth: int | None = None, goal: str | None = None) -> BFSResult:
    """Breadth-first search from ``start``.

    ``max_depth`` stops expanding nodes at that hop count; ``goal`` stops as soon
    as that node is dequeued.
    """
    if start not in graph:
        raise KeyError(f"unknown start node: {start}")
    if max_depth is not None and max_depth < 0:
        raise ValueError("max_depth must be >= 0")

    depth: dict[str, int] = {start: 0}
    parent: dict[str, str | None] = {start: None}
    queue = deque([start])
    order: list[str] = []
    trace: list[TraceStep] = []

    while queue:
        node = queue.popleft()
        order.append(node)
        if node == goal:
            trace.append(TraceStep(len(trace) + 1, node, "goal", list(queue), list(order),
                                   f"goal reached at depth {depth[node]}"))
            break
        if max_depth is not None and depth[node] >= max_depth:
            trace.append(TraceStep(len(trace) + 1, node, "limit", list(queue), list(order),
                                   f"depth limit {max_depth}: not expanded"))
            continue
        added, seen = [], []
        for nxt in graph.neighbors(node):
            if nxt in depth:
                seen.append(nxt)
                continue
            depth[nxt] = depth[node] + 1
            parent[nxt] = node
            queue.append(nxt)
            added.append(nxt)
        note = f"enqueue [{', '.join(added)}]" if added else "no new neighbours"
        if seen:
            note += f"; already seen [{', '.join(seen)}]"
        trace.append(TraceStep(len(trace) + 1, node, "expand", list(queue), list(order), note))

    return BFSResult(start, depth, parent, order, trace)


def bfs_reachable(graph: Graph, start: str, max_depth: int | None = None) -> BFSResult:
    """Blast radius: every device reachable from ``start`` (within ``max_depth`` hops)."""
    return bfs(graph, start, max_depth=max_depth)


def bfs_shortest_path(graph: Graph, start: str, goal: str) -> list[str] | None:
    """Fewest-hop path from ``start`` to ``goal``, or None if unreachable."""
    if goal not in graph:
        raise KeyError(f"unknown goal node: {goal}")
    return bfs(graph, start, goal=goal).path_to(goal)
