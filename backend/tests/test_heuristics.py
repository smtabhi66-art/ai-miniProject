"""Milestone 5: the A* heuristic is admissible and consistent."""
import math

import pytest

from app.algorithms.search.costs import compromised_devices, risk_aware_cost
from app.algorithms.search.graph import Graph, graph_from_network
from app.algorithms.search.heuristics import (
    admissibility_violations,
    consistency_violations,
    exact_costs,
    hop_lower_bound,
    min_edge_cost,
    zero_heuristic,
)
from app.models.enums import LinkStatus, ThreatLevel
from app.simulation.network_builder import load_topology

# S --1-- A --10-- G
# |                |
# 2                2
# |                |
# B ------2------- C
TRAP = Graph.from_edges([("S", "A", 1), ("A", "G", 10), ("S", "B", 2), ("B", "C", 2), ("C", "G", 2)])


def test_hop_heuristic_values():
    h = hop_lower_bound(TRAP, "G")
    assert {n: h(n) for n in "SABCG"} == {"S": 2, "A": 1, "B": 2, "C": 1, "G": 0}


def test_goal_has_zero_heuristic():
    assert hop_lower_bound(graph_from_network(load_topology()), "DB1")("DB1") == 0


def test_unreachable_node_gets_infinity():
    g = Graph.from_edges([("A", "B", 1)], nodes=["X"])
    assert hop_lower_bound(g, "B")("X") == math.inf


def test_zero_heuristic():
    assert zero_heuristic("G")("anything") == 0.0


def all_network_variants():
    plain = load_topology()
    blocked = load_topology()
    blocked.get_link("R1", "R2").status = LinkStatus.BLOCKED
    risky = load_topology()
    risky.devices["R3"].risk_score = 0.8
    return [
        graph_from_network(plain),
        graph_from_network(blocked),
        graph_from_network(risky, edge_cost=risk_aware_cost()),
    ]


@pytest.mark.parametrize("graph", all_network_variants())
def test_admissible_for_every_goal(graph):
    for goal in graph.nodes:
        assert admissibility_violations(graph, hop_lower_bound(graph, goal), goal) == []


@pytest.mark.parametrize("graph", all_network_variants())
def test_consistent_for_every_goal(graph):
    for goal in graph.nodes:
        assert consistency_violations(graph, hop_lower_bound(graph, goal)) == []


def test_violation_checkers_detect_bad_heuristics():
    overestimate = lambda n: 100.0
    assert admissibility_violations(TRAP, overestimate, "G")
    # True cost A->G is 7 (A-S-B-C-G), so h(A)=7 is admissible, but
    # h(A)=7 > cost(A,S) + h(S) = 1 breaks consistency.
    jumpy = {"S": 0, "A": 7, "B": 0, "C": 0, "G": 0}.get
    assert admissibility_violations(TRAP, jumpy, "G") == []
    assert consistency_violations(TRAP, jumpy)


def test_exact_costs():
    assert exact_costs(TRAP, "S")["G"] == 6


def test_min_edge_cost():
    assert min_edge_cost(TRAP) == 1
    with pytest.raises(ValueError):
        min_edge_cost(Graph.from_edges([], nodes=["A"]))


def test_risk_aware_cost_penalises_risky_devices():
    state = load_topology()
    cost = risk_aware_cost(link_weight=2.0, node_weight=5.0)
    link = state.get_link("R1", "R3")
    assert cost(link, state) == pytest.approx(2 + 2 * 0.1)
    state.devices["R3"].risk_score = 0.8
    assert cost(link, state) == pytest.approx(2 + 2 * 0.1 + 5 * 0.8)
    with pytest.raises(ValueError):
        risk_aware_cost(node_weight=-1)


def test_compromised_devices():
    state = load_topology()
    state.devices["R3"].threat_level = ThreatLevel.CRITICAL
    state.devices["WS1"].threat_level = ThreatLevel.SUSPICIOUS
    assert compromised_devices(state) == {"R3"}
