"""Investigation: the search algorithms applied to one suspicious device.

    BFS     blast radius: what can the device reach, by hop distance?
    DFS     attack paths: every route from the device to a critical asset
    Greedy  quick lead: the most direct route towards the most valuable asset
    A*      safe management route from the admin workstation to the device,
            using risk-aware costs and avoiding devices believed compromised

Chokepoints are the devices that lie on *every* attack path. Blocking or
watching them cuts the attacker off.
"""
from dataclasses import dataclass, field
from typing import Any

from app.algorithms.search.astar import astar
from app.algorithms.search.bfs import bfs_reachable
from app.algorithms.search.costs import compromised_devices, risk_aware_cost
from app.algorithms.search.dfs import dfs_all_paths
from app.algorithms.search.graph import graph_from_network
from app.algorithms.search.greedy_best_first import greedy_best_first
from app.algorithms.search.heuristics import hop_lower_bound
from app.models.network import NetworkState


@dataclass
class Investigation:
    device: str
    blast_radius: list[list[str]]
    attack_paths: list[list[str]]
    chokepoints: list[str]
    greedy_target: str | None
    greedy: dict[str, Any] | None
    admin_route: dict[str, Any] | None
    traces: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        reach = sum(len(layer) for layer in self.blast_radius[1:])
        parts = [f"reaches {reach} device(s) within {len(self.blast_radius) - 1} hop(s)",
                 f"{len(self.attack_paths)} attack path(s) to critical assets"]
        if self.chokepoints:
            parts.append(f"chokepoint(s): {', '.join(self.chokepoints)}")
        if self.greedy and self.greedy["path"]:
            parts.append(f"likely direction (Greedy): {' -> '.join(self.greedy['path'])}")
        if self.admin_route:
            route = self.admin_route["path"]
            parts.append("safe admin route (A*): " + (" -> ".join(route) if route else "none"))
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "blast_radius": self.blast_radius,
            "attack_paths": self.attack_paths,
            "chokepoints": self.chokepoints,
            "greedy_target": self.greedy_target,
            "greedy": self.greedy,
            "admin_route": self.admin_route,
            "summary": self.summary(),
            "traces": self.traces,
        }


def _round(cost: float | None) -> float | None:
    return None if cost is None else round(cost, 2)


def investigate(state: NetworkState, device: str, max_depth: int = 3) -> Investigation:
    graph = graph_from_network(state)
    bfs = bfs_reachable(graph, device, max_depth=max_depth)

    critical_hosts = sorted({h for s in state.services.values() if s.critical for h in s.hosts} - {device})
    dfs = dfs_all_paths(graph, device, critical_hosts, max_depth=6, max_paths=50)
    inner_sets = [set(p[1:-1]) for p in dfs.paths]
    chokepoints = sorted(set.intersection(*inner_sets)) if inner_sets else []

    # Greedy lead: most critical reachable asset, nearest first.
    full_reach = bfs_reachable(graph, device).depth
    candidates = [h for h in critical_hosts if h in full_reach]
    target = min(candidates, key=lambda h: (-state.devices[h].criticality, full_reach[h], h)) if candidates else None
    greedy = None
    if target:
        g = greedy_best_first(graph, device, target, hop_lower_bound(graph, target))
        greedy = {"target": target, "path": g.path, "cost": _round(g.cost), "nodes_expanded": g.nodes_expanded}

    admin = state.metadata.get("admin_device")
    route = None
    traces: dict[str, Any] = {
        "bfs": [t.to_dict() for t in bfs.trace],
        "dfs": [t.to_dict() for t in dfs.trace[:60]],
    }
    if admin and admin != device and admin in graph:
        risky = graph_from_network(state, edge_cost=risk_aware_cost())
        a = astar(risky, admin, device, hop_lower_bound(risky, device),
                  forbidden=compromised_devices(state) - {device})
        route = {"start": admin, "goal": device, "path": a.path, "cost": _round(a.cost), "nodes_expanded": a.nodes_expanded}
        traces["astar"] = [t.to_dict() for t in a.trace]
    if greedy:
        traces["greedy"] = [t.to_dict() for t in g.trace]

    return Investigation(device, bfs.layers(), dfs.paths, chokepoints, target, greedy, route, traces)
