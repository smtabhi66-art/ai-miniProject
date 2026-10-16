"""Milestone 4: Depth-First Search (traversal and attack-path enumeration)."""
import itertools

import pytest

from app.algorithms.search.dfs import dfs_all_paths, dfs_traversal
from app.algorithms.search.graph import Graph, graph_from_network
from app.models.enums import LinkStatus
from app.simulation.network_builder import load_topology

DIAMOND = Graph.from_edges(
    [("A", "B", 1), ("A", "C", 1), ("B", "D", 1), ("C", "D", 1), ("D", "E", 1)], nodes=["F"])


def test_traversal_goes_deep_first():
    r = dfs_traversal(DIAMOND, "A")
    assert r.order == ["A", "B", "D", "C", "E"]  # BFS would be A, B, C, D, E
    assert r.parent["C"] == "D"


def test_all_paths_in_diamond():
    r = dfs_all_paths(DIAMOND, "A", ["E"])
    assert r.paths == [["A", "B", "D", "E"], ["A", "C", "D", "E"]]
    assert not r.truncated


def test_paths_are_simple():
    for path in dfs_all_paths(DIAMOND, "A", ["E", "C"]).paths:
        assert len(path) == len(set(path))


def test_paths_stop_at_first_goal_reached():
    # C is a goal, so no path continues *through* C to E.
    paths = dfs_all_paths(DIAMOND, "A", ["C", "E"]).paths
    assert ["A", "C"] in paths
    assert all(p.index("C") == len(p) - 1 for p in paths if "C" in p)


def test_max_depth_prunes_long_paths():
    assert dfs_all_paths(DIAMOND, "A", ["E"], max_depth=2).paths == []
    assert len(dfs_all_paths(DIAMOND, "A", ["D"], max_depth=2).paths) == 2


def test_start_is_goal():
    assert dfs_all_paths(DIAMOND, "A", ["A"]).paths == [["A"]]


def test_unreachable_goal_gives_no_paths():
    assert dfs_all_paths(DIAMOND, "A", ["F"]).paths == []


def test_max_paths_truncates_exponential_search():
    nodes = [str(i) for i in range(7)]
    complete = Graph.from_edges((a, b, 1) for a, b in itertools.combinations(nodes, 2))
    full = dfs_all_paths(complete, "0", ["6"])
    assert len(full.paths) == 326  # sum over k=0..5 of 5!/(5-k)!
    capped = dfs_all_paths(complete, "0", ["6"], max_paths=10)
    assert len(capped.paths) == 10 and capped.truncated


@pytest.mark.parametrize("call", [
    lambda: dfs_all_paths(DIAMOND, "Z", ["A"]),
    lambda: dfs_all_paths(DIAMOND, "A", ["Z"]),
    lambda: dfs_traversal(DIAMOND, "Z"),
])
def test_unknown_nodes_raise(call):
    with pytest.raises(KeyError):
        call()


def test_trace_shows_stack_and_backtracking():
    trace = dfs_all_paths(DIAMOND, "A", ["E"]).trace
    assert trace[0].note == "push [B, C]" and trace[0].frontier == ["B", "C"]
    assert [t.action for t in trace].count("goal") == 2


# ---- on the enterprise network -----------------------------------------------
def test_attack_paths_to_database():
    r = dfs_all_paths(graph_from_network(load_topology()), "WS2", ["DB1"])
    assert r.paths == [["WS2", "R1", "R2", "DB1"], ["WS2", "R1", "R3", "R2", "DB1"]]


def test_attack_paths_to_all_critical_hosts():
    state = load_topology()
    hosts = sorted({h for s in state.services.values() if s.critical for h in s.hosts})
    r = dfs_all_paths(graph_from_network(state), "WS2", hosts)
    # 2 routes to each server-zone host (APP1, DB1, DB2, AUTH1) + 1 route to each web server.
    assert len(r.paths) == 2 * 4 + 2


def test_blocking_link_removes_attack_paths():
    state = load_topology()
    state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    r = dfs_all_paths(graph_from_network(state), "WS2", ["DB1"])
    assert r.paths == [["WS2", "R1", "R3", "R2", "DB1"]]
