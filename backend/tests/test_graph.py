"""Milestone 4: Graph structure and conversion from the network model."""
import pytest

from app.algorithms.search.graph import Graph, graph_from_network
from app.models.enums import DeviceStatus, LinkStatus
from app.simulation.network_builder import load_topology


def test_from_edges_is_undirected():
    g = Graph.from_edges([("A", "B", 2.0)], nodes=["C"])
    assert g.neighbors("A") == ["B"] and g.neighbors("B") == ["A"]
    assert g.cost("B", "A") == 2.0
    assert g.neighbors("C") == [] and g.edge_count() == 1


@pytest.mark.parametrize("edges, message", [
    ([("A", "A", 1)], "self-loop"),
    ([("A", "B", 0)], "cost must be > 0"),
    ([("A", "B", 1), ("B", "A", 1)], "duplicate"),
])
def test_invalid_edges_rejected(edges, message):
    with pytest.raises(ValueError, match=message):
        Graph.from_edges(edges)


def test_unknown_node_raises():
    with pytest.raises(KeyError):
        Graph().neighbors("X")


def test_network_conversion_full():
    g = graph_from_network(load_topology())
    assert len(g.nodes) == 16 and g.edge_count() == 16
    assert g.cost("R1", "R2") == 2.0


def test_network_conversion_skips_blocked_links_and_isolated_devices():
    state = load_topology()
    state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    state.devices["WS2"].status = DeviceStatus.ISOLATED
    g = graph_from_network(state)
    assert "R2" not in g.neighbors("R1")
    assert "WS2" in g and g.neighbors("WS2") == []
    assert "WS2" not in g.neighbors("R1")
    assert g.edge_count() == 14


def test_custom_edge_cost():
    g = graph_from_network(load_topology(), edge_cost=lambda link, s: 1 + 10 * link.risk)
    assert g.cost("INET", "FW1") == pytest.approx(10.0)
