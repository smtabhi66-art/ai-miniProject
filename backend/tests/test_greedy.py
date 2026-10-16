"""Milestone 5: Greedy Best-First Search, and how it differs from A*."""
import pytest

from app.algorithms.search.astar import astar
from app.algorithms.search.graph import Graph, graph_from_network
from app.algorithms.search.greedy_best_first import greedy_best_first
from app.algorithms.search.heuristics import hop_lower_bound
from app.simulation.network_builder import load_topology

TRAP = Graph.from_edges([("S", "A", 1), ("A", "G", 10), ("S", "B", 2), ("B", "C", 2), ("C", "G", 2)])


def run_greedy(graph, start, goal, **kw):
    return greedy_best_first(graph, start, goal, hop_lower_bound(graph, goal), **kw)


def test_greedy_is_not_optimal():
    greedy = run_greedy(TRAP, "S", "G")
    best = astar(TRAP, "S", "G", hop_lower_bound(TRAP, "G"))
    assert greedy.path == ["S", "A", "G"] and greedy.cost == 11
    assert best.path == ["S", "B", "C", "G"] and best.cost == 6


def test_greedy_expands_fewer_nodes_on_trap():
    greedy = run_greedy(TRAP, "S", "G")
    best = astar(TRAP, "S", "G", hop_lower_bound(TRAP, "G"))
    assert greedy.nodes_expanded < best.nodes_expanded


def test_trace_orders_by_h_only():
    first = run_greedy(TRAP, "S", "G").trace[0]
    assert first.frontier == ["A(h=1)", "B(h=2)"]


def test_start_equals_goal():
    r = run_greedy(TRAP, "S", "S")
    assert r.path == ["S"] and r.cost == 0


def test_unreachable_goal():
    g = Graph.from_edges([("A", "B", 1)], nodes=["X"])
    assert not run_greedy(g, "A", "X").found


def test_forbidden_respected():
    assert run_greedy(TRAP, "S", "G", forbidden={"A"}).path == ["S", "B", "C", "G"]


def test_unknown_node_raises():
    with pytest.raises(KeyError):
        run_greedy(TRAP, "Z", "G")


def test_congested_link_fools_greedy_but_not_astar():
    state = load_topology()
    state.get_link("R1", "R2").latency_cost = 10
    graph = graph_from_network(state)
    greedy = run_greedy(graph, "ADMIN1", "DB1")
    best = astar(graph, "ADMIN1", "DB1", hop_lower_bound(graph, "DB1"))
    assert greedy.path == ["ADMIN1", "R1", "R2", "DB1"] and greedy.cost == 12
    assert best.path == ["ADMIN1", "R1", "R3", "R2", "DB1"] and best.cost == 6


def test_greedy_finds_attacker_lead_quickly():
    graph = graph_from_network(load_topology())
    r = run_greedy(graph, "WS2", "DB1")
    assert r.path == ["WS2", "R1", "R2", "DB1"]
    assert r.nodes_expanded == 3
