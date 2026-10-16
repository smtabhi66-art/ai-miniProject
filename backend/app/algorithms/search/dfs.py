"""Depth-First Search (DFS).

Problem in SentinelAI
    "What are *all* the routes an attacker on device X could use to reach a
    critical asset?" BFS gives only the shortest route. DFS with backtracking
    lists every *simple* path (no device visited twice on the same path), which
    shows which routers and links the attack depends on.

Why DFS
    DFS follows one route as deep as it can, records it if it ends at a target,
    then backtracks to try the next branch. Memory grows with path length, not
    with the number of paths, so enumerating paths this way is cheap on memory.

Data structures
    An explicit LIFO stack of ``(node, path)`` pairs (a Python list used with
    append/pop), so the stack is visible in the trace instead of hidden in recursion.

Complexity
    ``dfs_traversal``: time O(V + E), space O(V).
    ``dfs_all_paths``: the number of simple paths can grow exponentially,
    O(b^d) for branching factor b and depth d, so ``max_depth`` and
    ``max_paths`` bound the work. Space O(d) per stacked path.
"""
from dataclasses import dataclass, field
from typing import Iterable

from app.algorithms.search.graph import Graph, TraceStep


@dataclass
class DFSPathsResult:
    start: str
    goals: list[str]
    paths: list[list[str]]
    nodes_expanded: int
    truncated: bool                # True if max_paths stopped the search early
    trace: list[TraceStep] = field(default_factory=list)


@dataclass
class DFSTraversalResult:
    start: str
    order: list[str]
    parent: dict[str, str | None]
    trace: list[TraceStep] = field(default_factory=list)


def dfs_all_paths(graph: Graph, start: str, goals: Iterable[str],
                  max_depth: int | None = None, max_paths: int = 1000) -> DFSPathsResult:
    """Every simple path from ``start`` to any node in ``goals``.

    A path stops when it reaches a goal (the attacker has arrived). ``max_depth``
    is the maximum number of hops.
    """
    goal_list = list(dict.fromkeys(goals))
    for node in [start, *goal_list]:
        if node not in graph:
            raise KeyError(f"unknown node: {node}")
    if max_paths < 1:
        raise ValueError("max_paths must be >= 1")
    goal_set = set(goal_list)

    stack: list[tuple[str, list[str]]] = [(start, [start])]
    paths: list[list[str]] = []
    trace: list[TraceStep] = []
    expanded = 0
    truncated = False

    def record(node: str, action: str, path: list[str], note: str) -> None:
        frontier = [n for n, _ in reversed(stack)]  # top of stack first
        trace.append(TraceStep(len(trace) + 1, node, action, frontier, list(path), note))

    while stack:
        node, path = stack.pop()
        if node in goal_set:
            paths.append(path)
            record(node, "goal", path, f"path found: {' -> '.join(path)}")
            if len(paths) >= max_paths:
                truncated = bool(stack)
                break
            continue
        if max_depth is not None and len(path) - 1 >= max_depth:
            record(node, "limit", path, f"depth limit {max_depth}: backtrack")
            continue
        expanded += 1
        children = [n for n in graph.neighbors(node) if n not in path]  # keep paths simple
        for nxt in reversed(children):  # reversed so the first neighbour is popped first
            stack.append((nxt, path + [nxt]))
        note = f"push [{', '.join(children)}]" if children else "dead end: backtrack"
        record(node, "expand", path, note)

    return DFSPathsResult(start, goal_list, paths, expanded, truncated, trace)


def dfs_traversal(graph: Graph, start: str) -> DFSTraversalResult:
    """Classic DFS visiting order (each node once). Educational counterpart to BFS."""
    if start not in graph:
        raise KeyError(f"unknown start node: {start}")
    stack: list[tuple[str, str | None]] = [(start, None)]
    parent: dict[str, str | None] = {}
    order: list[str] = []
    trace: list[TraceStep] = []
    while stack:
        node, via = stack.pop()
        if node in parent:
            continue
        parent[node] = via
        order.append(node)
        children = [n for n in graph.neighbors(node) if n not in parent]
        for nxt in reversed(children):
            stack.append((nxt, node))
        trace.append(TraceStep(len(trace) + 1, node, "expand", [n for n, _ in reversed(stack)],
                               list(order), f"push [{', '.join(children)}]" if children else "backtrack"))
    return DFSTraversalResult(start, order, parent, trace)
