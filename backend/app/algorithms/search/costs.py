"""Risk-aware edge costs for routing over the simulated network.

    cost(a, b) = latency_cost
               + LINK_W x link.risk                         (inherently risky link, e.g. crosses the DMZ)
               + NODE_W x max(risk_score(a), risk_score(b)) (touches a device the agent distrusts)

The cost is symmetric, so the graph stays undirected. All terms are >= 0, and
latency_cost > 0, so every edge cost is positive, which A* needs.
"""
from app.algorithms.search.graph import EdgeCost
from app.models.enums import ThreatLevel
from app.models.network import Link, NetworkState


def risk_aware_cost(link_weight: float = 2.0, node_weight: float = 5.0) -> EdgeCost:
    if link_weight < 0 or node_weight < 0:
        raise ValueError("weights must be >= 0")

    def cost(link: Link, state: NetworkState) -> float:
        a, b = state.devices[link.source], state.devices[link.target]
        return link.latency_cost + link_weight * link.risk + node_weight * max(a.risk_score, b.risk_score)

    return cost


def compromised_devices(state: NetworkState) -> set[str]:
    """Devices the agent believes are compromised; safe routes must not pass through them."""
    return {d.id for d in state.devices.values() if d.threat_level is ThreatLevel.CRITICAL}
