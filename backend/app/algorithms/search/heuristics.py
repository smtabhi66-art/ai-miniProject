"""Heuristic functions for informed search (A*, Greedy Best-First).

The problem
    A network graph has no coordinates, so the usual straight-line distance
    heuristic does not exist. We need another cheap estimate of the cost
    remaining from node n to the goal.

Our heuristic: hop lower bound
    h(n) = hops(n, goal) x c_min

    hops(n, goal)  fewest hops from n to the goal (one BFS from the goal, done once)
    c_min          the cheapest edge cost anywhere in the graph

    Admissible: any path from n to the goal uses at least hops(n, goal) edges,
    and each edge costs at least c_min, so h(n) <= true cost. It never overestimates.

    Consistent: for every edge (n, n'), hops(n) <= hops(n') + 1, so
    h(n) <= c_min + h(n') <= cost(n, n') + h(n'). That means A* never needs to
    reopen a closed node.

g(n) vs h(n)
    g(n) is the *actual* cost of the path A* has found from the start to n.
    h(n) is only an *estimate* of the cost still to go from n to the goal.
"""
import heapq
import math
from dataclasses import dataclass, field
from typing import Callable

from app.algorithms.search.bfs import bfs
from app.algorithms.search.graph import Graph

INF = math.inf


@dataclass
class Heuristic:
    name: str
    goal: str
    values: dict[str, float] = field(default_factory=dict)
    default: float = 0.0

    def __call__(self, node: str) -> float:
        return self.values.get(node, self.default)


def min_edge_cost(graph: Graph) -> float:
    costs = [c for nbrs in graph.adjacency.values() for c in nbrs.values()]
    if not costs:
        raise ValueError("graph has no edges")
    return min(costs)


def hop_lower_bound(graph: Graph, goal: str) -> Heuristic:
    """h(n) = hops(n, goal) x c_min; INF for nodes that cannot reach the goal."""
    if goal not in graph:
        raise KeyError(f"unknown goal node: {goal}")
    try:
        c_min = min_edge_cost(graph)
    except ValueError:
        c_min = 0.0
    hops = bfs(graph, goal).depth  # undirected graph, so hops from goal = hops to goal
    values = {node: (hops[node] * c_min if node in hops else INF) for node in graph.nodes}
    return Heuristic(f"hops x c_min (c_min={c_min:g})", goal, values, default=INF)


def zero_heuristic(goal: str) -> Heuristic:
    """h(n) = 0. A* with this heuristic is Uniform-Cost Search (Dijkstra)."""
    return Heuristic("zero (uniform-cost search)", goal, {}, default=0.0)


# ---- verification helpers (used by tests and the report) ------------------------
def exact_costs(graph: Graph, source: str) -> dict[str, float]:
    """True cheapest cost from ``source`` to every reachable node (Dijkstra)."""
    dist = {source: 0.0}
    heap = [(0.0, source)]
    while heap:
        d, node = heapq.heappop(heap)
        if d > dist[node]:
            continue
        for nxt in graph.neighbors(node):
            nd = d + graph.cost(node, nxt)
            if nd < dist.get(nxt, INF):
                dist[nxt] = nd
                heapq.heappush(heap, (nd, nxt))
    return dist


def admissibility_violations(graph: Graph, h: Callable[[str], float], goal: str) -> list[str]:
    """Nodes where h(n) > true cost to the goal (should be empty)."""
    true = exact_costs(graph, goal)
    return [n for n in graph.nodes if n in true and h(n) > true[n] + 1e-9]


def consistency_violations(graph: Graph, h: Callable[[str], float]) -> list[tuple[str, str]]:
    """Edges where h(n) > cost(n, n') + h(n') (should be empty)."""
    bad = []
    for n in graph.nodes:
        for m in graph.neighbors(n):
            if h(n) != INF and h(n) > graph.cost(n, m) + h(m) + 1e-9:
                bad.append((n, m))
    return bad
