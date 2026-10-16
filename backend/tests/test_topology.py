"""Milestone 2: loading and validating the default topology."""
import copy
import json

import pytest

from app.core.config import TOPOLOGY_DIR
from app.models.enums import DeviceStatus, DeviceType, LinkStatus
from app.simulation.network_builder import TopologyError, build_network, load_topology


@pytest.fixture
def raw():
    return json.loads((TOPOLOGY_DIR / "enterprise_default.json").read_text(encoding="utf-8"))


def test_default_topology_size():
    state = load_topology()
    assert len(state.devices) == 16
    assert sum(1 for _ in state.links()) == 16
    assert set(state.services) == {"web", "app", "db", "auth"}


def test_initial_state_is_clean():
    state = load_topology()
    assert state.tick == 0
    assert all(d.status is DeviceStatus.ONLINE for d in state.devices.values())
    assert all(link.status is LinkStatus.ACTIVE for link in state.links())
    assert state.devices["INET"].type is DeviceType.EXTERNAL


def test_adjacency_is_symmetric():
    state = load_topology()
    for a, links in state.adjacency.items():
        for link in links:
            b = link.other(a)
            assert a in state.neighbors(b, usable_only=False)


def test_design_properties_needed_by_later_scenarios():
    state = load_topology()
    # Scenario 6: two routes from R1 to R2 (direct, and via backup router R3).
    assert state.get_link("R1", "R2") is not None
    assert state.get_link("R1", "R3") is not None and state.get_link("R3", "R2") is not None
    # Scenario 7: auth has a single host, so AUTH1 must never be isolated.
    assert state.services["auth"].hosts == ["AUTH1"]
    # Replicas: web and db survive losing one host.
    assert len(state.services["web"].hosts) == 2 and len(state.services["db"].hosts) == 2
    assert state.metadata["admin_device"] == "ADMIN1"


def test_unknown_link_endpoint_rejected(raw):
    raw["links"].append({"source": "WS1", "target": "GHOST", "latency_cost": 1, "risk": 0.1})
    with pytest.raises(TopologyError, match="unknown device GHOST"):
        build_network(raw)


def test_duplicate_device_rejected(raw):
    raw["devices"].append(copy.deepcopy(raw["devices"][0]))
    with pytest.raises(TopologyError, match="duplicate device"):
        build_network(raw)


def test_duplicate_link_in_reverse_direction_rejected(raw):
    raw["links"].append({"source": "WS1", "target": "R1", "latency_cost": 1, "risk": 0.1})
    with pytest.raises(TopologyError, match="duplicate link"):
        build_network(raw)


def test_self_loop_rejected(raw):
    raw["links"].append({"source": "WS1", "target": "WS1", "latency_cost": 1, "risk": 0.1})
    with pytest.raises(TopologyError, match="self-loop"):
        build_network(raw)


@pytest.mark.parametrize("field, value, message", [
    ("risk", 1.5, "risk must be 0..1"),
    ("latency_cost", 0, "latency_cost must be > 0"),
])
def test_invalid_link_values_rejected(raw, field, value, message):
    raw["links"][0][field] = value
    with pytest.raises(TopologyError, match=message):
        build_network(raw)


def test_invalid_device_type_rejected(raw):
    raw["devices"][0]["type"] = "toaster"
    with pytest.raises(TopologyError):
        build_network(raw)


def test_service_host_mismatch_rejected(raw):
    auth1 = next(d for d in raw["devices"] if d["id"] == "AUTH1")
    auth1["services"] = []
    with pytest.raises(TopologyError, match="does not list it"):
        build_network(raw)


def test_missing_field_rejected(raw):
    del raw["devices"][0]["zone"]
    with pytest.raises(TopologyError, match="missing required field"):
        build_network(raw)


def test_missing_file_rejected():
    with pytest.raises(TopologyError, match="not found"):
        load_topology("does_not_exist")
