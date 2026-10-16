"""Greedy Best-First Search.

Problem in SentinelAI
    Quick investigation lead: "Which way is the attacker most likely heading
    towards the crown-jewel asset?" Greedy always moves to the neighbour that
    *looks* closest to the target, so it gives an answer after expanding very
    few nodes.

How it differs from A*
    Priority is f(n) = h(n) only; the cost already paid, g(n), is ignored.
    That makes it fast but neither optimal nor guaranteed to find the cheapest
    route. The demo and tests show a case where it returns a more expensive
    path than A*. That is why the agent uses Greedy only to prioritise
    investigation, and A* for routes it actually acts on.

Data structures
    Binary heap keyed on (h, counter), a closed set and a parent dict.

Complexity
    Worst case O(E log V) time and O(V) space. With a good heuristic it
    expands about d nodes, where d is the depth of the solution.
"""
import heapq
import math
from typing import Callable, Iterable

from app.algorithms.search.astar import PathResult, _check_nodes, path_cost, rebuild_path
from app.algorithms.search.graph import Graph, TraceStep

INF = math.inf


def greedy_best_first(graph: Graph, start: str, goal: str, heuristic: Callable[[str], float],
                      forbidden: Iterable[str] = ()) -> PathResult:
    _check_nodes(graph, start, goal)
    banned = set(forbidden) - {start, goal}
    counter = 0
    open_heap = [(heuristic(start), counter, start)]
    parent: dict[str, str | None] = {start: None}
    closed: set[str] = set()
    trace: list[TraceStep] = []

    def frontier() -> list[str]:
        return [f"{n}(h={h:g})" for h, _, n in sorted(open_heap)]

    while open_heap:
        h, _, node = heapq.heappop(open_heap)
        if node == goal:
            path = rebuild_path(parent, goal)
            trace.append(TraceStep(len(trace) + 1, node, "goal", frontier(), sorted(closed),
                                   "goal reached (not necessarily the cheapest path)"))
            return PathResult("Greedy best-first", start, goal, path, path_cost(graph, path), len(closed), trace)
        closed.add(node)
        added = []
        for nxt in graph.neighbors(node):
            if nxt in banned or nxt in parent:  # parent doubles as "already discovered"
                continue
            h_next = heuristic(nxt)
            if h_next == INF:
                continue
            parent[nxt] = node
            counter += 1
            heapq.heappush(open_heap, (h_next, counter, nxt))
            added.append(f"{nxt}(h={h_next:g})")
        note = f"h={h:g}; add [{', '.join(added)}]" if added else f"h={h:g}; nothing new"
        trace.append(TraceStep(len(trace) + 1, node, "expand", frontier(), sorted(closed), note))

    return PathResult("Greedy best-first", start, goal, None, None, len(closed), trace)
