"""Milestone 4: Breadth-First Search."""
import pytest

from app.algorithms.search.bfs import bfs, bfs_reachable, bfs_shortest_path
from app.algorithms.search.graph import Graph, graph_from_network
from app.models.enums import DeviceStatus, LinkStatus
from app.simulation.network_builder import load_topology

#   A --- B
#   |     |
#   C --- D --- E        F (disconnected)
DIAMOND = Graph.from_edges(
    [("A", "B", 1), ("A", "C", 1), ("B", "D", 1), ("C", "D", 1), ("D", "E", 1)], nodes=["F"])


def test_levels_and_order():
    r = bfs_reachable(DIAMOND, "A")
    assert r.order == ["A", "B", "C", "D", "E"]
    assert r.layers() == [["A"], ["B", "C"], ["D"], ["E"]]
    assert r.depth["E"] == 3


def test_path_is_fewest_hops():
    assert bfs_shortest_path(DIAMOND, "A", "E") == ["A", "B", "D", "E"]


def test_max_depth_limits_blast_radius():
    r = bfs_reachable(DIAMOND, "A", max_depth=1)
    assert r.reachable() == ["B", "C"]
    assert r.trace[-1].action == "limit"


def test_depth_zero_returns_only_start():
    assert bfs_reachable(DIAMOND, "A", max_depth=0).order == ["A"]


def test_disconnected_node_unreachable():
    assert "F" not in bfs_reachable(DIAMOND, "A").depth
    assert bfs_shortest_path(DIAMOND, "A", "F") is None
    assert bfs_reachable(DIAMOND, "F").order == ["F"]


def test_start_equals_goal():
    assert bfs_shortest_path(DIAMOND, "C", "C") == ["C"]


def test_goal_stops_early():
    r = bfs(DIAMOND, "A", goal="C")
    assert r.order == ["A", "B", "C"]
    assert r.trace[-1].action == "goal"


@pytest.mark.parametrize("call", [
    lambda: bfs_reachable(DIAMOND, "Z"),
    lambda: bfs_shortest_path(DIAMOND, "A", "Z"),
])
def test_unknown_nodes_raise(call):
    with pytest.raises(KeyError):
        call()


def test_negative_depth_rejected():
    with pytest.raises(ValueError):
        bfs_reachable(DIAMOND, "A", max_depth=-1)


def test_trace_records_queue_contents():
    first = bfs_reachable(DIAMOND, "A").trace[0]
    assert first.node == "A" and first.frontier == ["B", "C"]
    assert first.note == "enqueue [B, C]"


# ---- on the enterprise network -----------------------------------------------
def test_blast_radius_of_compromised_workstation():
    r = bfs_reachable(graph_from_network(load_topology()), "WS2", max_depth=2)
    layers = r.layers()
    assert layers[1] == ["R1"]
    assert set(layers[2]) == {"FW1", "WS1", "WS3", "WS4", "ADMIN1", "R2", "R3"}


def test_whole_network_reachable_from_internet():
    r = bfs_reachable(graph_from_network(load_topology()), "INET")
    assert len(r.order) == 16


def test_isolating_router_contains_blast_radius():
    state = load_topology()
    state.devices["R1"].status = DeviceStatus.ISOLATED
    r = bfs_reachable(graph_from_network(state), "WS2")
    assert r.reachable() == []


def test_blocked_link_forces_backup_route():
    state = load_topology()
    assert bfs_shortest_path(graph_from_network(state), "WS4", "AUTH1") == ["WS4", "R1", "R2", "AUTH1"]
    state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    assert bfs_shortest_path(graph_from_network(state), "WS4", "AUTH1") == ["WS4", "R1", "R3", "R2", "AUTH1"]
