"""Weighted, undirected graph used by every search algorithm.

Algorithms only see this structure, an adjacency list of ``neighbour -> edge cost``::

    {"R1": {"FW1": 1.0, "WS1": 1.0, "R2": 2.0, ...}, "WS1": {"R1": 1.0}, ...}

They never touch the simulator, so they can be tested on small hand-made graphs.
``graph_from_network`` converts the agent's NetworkState into this form.
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from app.models.network import Link, NetworkState


@dataclass
class TraceStep:
    """One step of a search, recorded for the dashboard and the report."""

    step: int
    node: str
    action: str           # "expand", "goal", "limit", ...
    frontier: list[str]   # queue / stack / priority queue contents after this step
    visited: list[str]    # explored set (or, for path-DFS, the current path)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "node": self.node,
            "action": self.action,
            "frontier": list(self.frontier),
            "visited": list(self.visited),
            "note": self.note,
        }


@dataclass
class Graph:
    adjacency: dict[str, dict[str, float]] = field(default_factory=dict)

    @classmethod
    def from_edges(cls, edges: Iterable[tuple[str, str, float]], nodes: Iterable[str] = ()) -> "Graph":
        graph = cls()
        for node in nodes:
            graph.add_node(node)
        for a, b, cost in edges:
            graph.add_edge(a, b, cost)
        return graph

    def add_node(self, node: str) -> None:
        self.adjacency.setdefault(node, {})

    def add_edge(self, a: str, b: str, cost: float = 1.0) -> None:
        if a == b:
            raise ValueError(f"self-loop on {a}")
        if cost <= 0:
            raise ValueError(f"edge {a}-{b}: cost must be > 0")
        if b in self.adjacency.get(a, {}):
            raise ValueError(f"duplicate edge {a}-{b}")
        self.add_node(a)
        self.add_node(b)
        self.adjacency[a][b] = cost
        self.adjacency[b][a] = cost

    def __contains__(self, node: str) -> bool:
        return node in self.adjacency

    @property
    def nodes(self) -> list[str]:
        return list(self.adjacency)

    def neighbors(self, node: str) -> list[str]:
        if node not in self.adjacency:
            raise KeyError(f"unknown node: {node}")
        return list(self.adjacency[node])

    def cost(self, a: str, b: str) -> float:
        return self.adjacency[a][b]

    def edge_count(self) -> int:
        return sum(len(n) for n in self.adjacency.values()) // 2


EdgeCost = Callable[[Link, NetworkState], float]


def graph_from_network(state: NetworkState, edge_cost: EdgeCost | None = None) -> Graph:
    """Graph of the *usable* network: active links between traversable devices.

    Every device is a node, but an isolated/offline device has no edges, and
    blocked links are left out. ``edge_cost`` defaults to the link's latency cost.
    """
    graph = Graph()
    for device_id in state.devices:
        graph.add_node(device_id)
    for link in state.links():
        if not link.is_active:
            continue
        if not (state.devices[link.source].is_traversable and state.devices[link.target].is_traversable):
            continue
        cost = edge_cost(link, state) if edge_cost else link.latency_cost
        graph.add_edge(link.source, link.target, cost)
    return graph
