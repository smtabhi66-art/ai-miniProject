"""Milestone 5: A* search (and uniform-cost search as its baseline)."""
import itertools

import pytest

from app.algorithms.search.astar import astar, path_cost, uniform_cost_search
from app.algorithms.search.costs import risk_aware_cost
from app.algorithms.search.graph import Graph, graph_from_network
from app.algorithms.search.heuristics import exact_costs, hop_lower_bound
from app.models.enums import LinkStatus
from app.simulation.network_builder import load_topology

TRAP = Graph.from_edges([("S", "A", 1), ("A", "G", 10), ("S", "B", 2), ("B", "C", 2), ("C", "G", 2)])


def run_astar(graph, start, goal, **kw):
    return astar(graph, start, goal, hop_lower_bound(graph, goal), **kw)


def test_finds_cheapest_path_not_fewest_hops():
    r = run_astar(TRAP, "S", "G")
    assert r.path == ["S", "B", "C", "G"] and r.cost == 6


def test_trace_shows_f_equals_g_plus_h():
    first = run_astar(TRAP, "S", "G").trace[0]
    assert first.node == "S"
    assert first.note == "g=0 h=2 f=2; A: g=1 f=2; B: g=2 f=4"
    assert first.frontier == ["A(f=2)", "B(f=4)"]


def test_start_equals_goal():
    r = run_astar(TRAP, "S", "S")
    assert r.path == ["S"] and r.cost == 0


def test_unreachable_goal():
    g = Graph.from_edges([("A", "B", 1)], nodes=["X"])
    r = run_astar(g, "A", "X")
    assert not r.found and r.cost is None


def test_unknown_node_raises():
    with pytest.raises(KeyError):
        run_astar(TRAP, "S", "Z")


def test_forbidden_node_is_avoided():
    r = run_astar(TRAP, "S", "G", forbidden={"B"})
    assert r.path == ["S", "A", "G"] and r.cost == 11


def test_everything_forbidden_means_no_path():
    assert not run_astar(TRAP, "S", "G", forbidden={"A", "B"}).found


def test_reopens_nodes_with_inconsistent_heuristic():
    #  S -1- A -1- C -3- G      and a direct edge S -3- C
    g = Graph.from_edges([("S", "A", 1), ("A", "C", 1), ("S", "C", 3), ("C", "G", 3)])
    h = {"S": 0, "A": 4, "C": 0, "G": 0}.get  # admissible but not consistent
    r = astar(g, "S", "G", h)
    assert r.cost == 5 and r.path == ["S", "A", "C", "G"]


@pytest.mark.parametrize("variant", ["plain", "blocked", "risky"])
def test_optimal_for_every_pair_on_network(variant):
    state = load_topology()
    cost_fn = None
    if variant == "blocked":
        state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    if variant == "risky":
        state.devices["R2"].risk_score = 0.9
        cost_fn = risk_aware_cost()
    graph = graph_from_network(state, edge_cost=cost_fn)
    for start, goal in itertools.permutations(graph.nodes, 2):
        r = run_astar(graph, start, goal)
        assert r.cost == pytest.approx(exact_costs(graph, start)[goal])
        assert r.cost == pytest.approx(path_cost(graph, r.path))


def test_heuristic_expands_no_more_than_uniform_cost():
    graph = graph_from_network(load_topology())
    total_astar = total_ucs = 0
    for start, goal in itertools.permutations(graph.nodes, 2):
        a = run_astar(graph, start, goal)
        u = uniform_cost_search(graph, start, goal)
        assert a.cost == u.cost
        assert a.nodes_expanded <= u.nodes_expanded
        total_astar += a.nodes_expanded
        total_ucs += u.nodes_expanded
    assert total_astar < total_ucs


def test_admin_route_uses_backup_router_when_link_down():
    state = load_topology()
    state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    r = run_astar(graph_from_network(state), "ADMIN1", "DB1")
    assert r.path == ["ADMIN1", "R1", "R3", "R2", "DB1"] and r.cost == 6


def test_admin_route_avoids_compromised_router():
    graph = graph_from_network(load_topology())
    assert run_astar(graph, "ADMIN1", "DB1").path == ["ADMIN1", "R1", "R2", "DB1"]
    # With R2 forbidden there is no route at all: every server hangs off R2.
    assert not run_astar(graph, "ADMIN1", "DB1", forbidden={"R2"}).found


def test_risky_device_changes_the_route():
    state = load_topology()
    state.devices["R2"].risk_score = 0.0
    state.get_link("R1", "R2").latency_cost = 10  # congested by exfiltration traffic
    r = run_astar(graph_from_network(state), "ADMIN1", "DB1")
    assert r.path == ["ADMIN1", "R1", "R3", "R2", "DB1"]
