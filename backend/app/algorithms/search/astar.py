"""A* search: the cheapest path, guided by a heuristic.

Problem in SentinelAI
    "What is the cheapest, lowest-risk route from the admin workstation to a
    server?" The route must avoid blocked links, isolated devices and devices
    believed to be compromised. In scenario 6 the direct R1-R2 link is down,
    so A* has to find the alternative through R3.

How it works
    Keep a priority queue ordered by f(n) = g(n) + h(n):
        g(n) = actual cost of the best path found so far from start to n
        h(n) = heuristic estimate of the remaining cost from n to the goal
    Always expand the node with the lowest f. With an admissible h (never
    overestimates), the first time the goal is popped its path is optimal.

Data structures
    Binary heap (heapq) as the priority queue, ``g`` dict, ``parent`` dict and
    a closed set. Heap entries are (f, h, counter, node): ties prefer lower h
    (closer to the goal), and the counter keeps the order deterministic.

Complexity
    Worst case O(E log V) time and O(V) space, the same as Dijkstra. A good
    heuristic expands fewer nodes in practice.
"""
import heapq
import math
from dataclasses import dataclass, field
from typing import Callable, Iterable

from app.algorithms.search.graph import Graph, TraceStep

INF = math.inf


@dataclass
class PathResult:
    algorithm: str
    start: str
    goal: str
    path: list[str] | None
    cost: float | None
    nodes_expanded: int
    trace: list[TraceStep] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.path is not None

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "start": self.start,
            "goal": self.goal,
            "path": self.path,
            "cost": self.cost,
            "nodes_expanded": self.nodes_expanded,
            "trace": [t.to_dict() for t in self.trace],
        }


def path_cost(graph: Graph, path: list[str]) -> float:
    return sum(graph.cost(a, b) for a, b in zip(path, path[1:]))


def rebuild_path(parent: dict[str, str | None], goal: str) -> list[str]:
    path, node = [], goal
    while node is not None:
        path.append(node)
        node = parent[node]
    return path[::-1]


def _check_nodes(graph: Graph, *nodes: str) -> None:
    for node in nodes:
        if node not in graph:
            raise KeyError(f"unknown node: {node}")


def astar(graph: Graph, start: str, goal: str, heuristic: Callable[[str], float],
          forbidden: Iterable[str] = (), name: str = "A*") -> PathResult:
    """Cheapest path from ``start`` to ``goal`` that never passes through ``forbidden``."""
    _check_nodes(graph, start, goal)
    banned = set(forbidden) - {start, goal}
    counter = 0
    h0 = heuristic(start)
    open_heap = [(h0, h0, counter, start)]
    g: dict[str, float] = {start: 0.0}
    parent: dict[str, str | None] = {start: None}
    closed: set[str] = set()
    expanded = 0
    trace: list[TraceStep] = []

    def frontier() -> list[str]:
        best: dict[str, float] = {}
        for f, h_n, _, n in open_heap:
            stale = f > g[n] + h_n + 1e-9
            if n not in closed and not stale and f < best.get(n, INF):
                best[n] = f
        return [f"{n}(f={f:g})" for n, f in sorted(best.items(), key=lambda kv: (kv[1], kv[0]))]

    while open_heap:
        f, h, _, node = heapq.heappop(open_heap)
        if node in closed or f > g[node] + h + 1e-9:
            continue  # stale entry: a cheaper route to this node was already found
        if node == goal:
            trace.append(TraceStep(len(trace) + 1, node, "goal", frontier(), sorted(closed),
                                   f"goal popped with g={g[node]:g} (optimal)"))
            path = rebuild_path(parent, goal)
            return PathResult(name, start, goal, path, g[goal], expanded, trace)
        closed.add(node)
        expanded += 1
        notes = [f"g={g[node]:g} h={h:g} f={f:g}"]
        for nxt in graph.neighbors(node):
            if nxt in banned:
                notes.append(f"skip {nxt} (forbidden)")
                continue
            h_next = heuristic(nxt)
            if h_next == INF:
                continue  # cannot reach the goal from there
            tentative = g[node] + graph.cost(node, nxt)
            if tentative < g.get(nxt, INF):
                if nxt in closed:
                    closed.discard(nxt)  # reopen; only happens if h is inconsistent
                g[nxt] = tentative
                parent[nxt] = node
                counter += 1
                heapq.heappush(open_heap, (tentative + h_next, h_next, counter, nxt))
                notes.append(f"{nxt}: g={tentative:g} f={tentative + h_next:g}")
        trace.append(TraceStep(len(trace) + 1, node, "expand", frontier(), sorted(closed), "; ".join(notes)))

    return PathResult(name, start, goal, None, None, expanded, trace)


def uniform_cost_search(graph: Graph, start: str, goal: str, forbidden: Iterable[str] = ()) -> PathResult:
    """A* with h = 0 (Dijkstra). Used as the uninformed baseline for comparison."""
    return astar(graph, start, goal, lambda _: 0.0, forbidden, name="Uniform-cost")
