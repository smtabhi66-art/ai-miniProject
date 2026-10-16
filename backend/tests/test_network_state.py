"""Milestone 2: graph queries on NetworkState."""
import copy
import json

from app.models.enums import DeviceStatus, LinkStatus
from app.simulation.network_builder import load_topology


def test_neighbors_of_core_router():
    state = load_topology()
    assert state.neighbors("R1") == ["FW1", "WS1", "WS2", "WS3", "WS4", "ADMIN1", "R2", "R3"]


def test_get_link_works_in_both_directions():
    state = load_topology()
    assert state.get_link("R1", "R2") is state.get_link("R2", "R1")
    assert state.get_link("WS1", "DB1") is None


def test_blocked_link_hidden_from_usable_neighbors_both_ways():
    state = load_topology()
    state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    assert "R2" not in state.neighbors("R1")
    assert "R1" not in state.neighbors("R2")
    assert "R2" in state.neighbors("R1", usable_only=False)


def test_isolated_device_hidden_from_usable_neighbors():
    state = load_topology()
    state.devices["WS2"].status = DeviceStatus.ISOLATED
    assert "WS2" not in state.neighbors("R1")


def test_restricted_device_is_still_traversable():
    state = load_topology()
    state.devices["APP1"].status = DeviceStatus.RESTRICTED
    assert "APP1" in state.neighbors("R2")


def test_deepcopy_keeps_links_shared_between_endpoints():
    copied = copy.deepcopy(load_topology())
    copied.get_link("R1", "R2").status = LinkStatus.BLOCKED
    assert copied.get_link("R2", "R1").status is LinkStatus.BLOCKED


def test_to_dict_is_json_serializable():
    state = load_topology()
    state.facts.add(("Connected", "WS1", "R1"))
    data = json.loads(json.dumps(state.to_dict()))
    assert len(data["devices"]) == 16 and len(data["links"]) == 16
    assert data["facts"] == [["Connected", "WS1", "R1"]]
