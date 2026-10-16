"""Milestone 3: simulated actions, their preconditions and effects."""
import pytest

from app.models.enums import DeviceStatus, LinkStatus
from app.simulation.actions import ACTIONS, ActionError, apply_action, execute_action
from app.simulation.network_builder import load_topology
from app.state.state_manager import StateManager


@pytest.fixture
def state():
    return load_topology()


def test_isolate_removes_device_from_usable_graph(state):
    apply_action(state, "isolate_device", {"device": "WS2"})
    assert state.devices["WS2"].status is DeviceStatus.ISOLATED
    assert "WS2" not in state.neighbors("R1")


def test_isolate_then_restore_round_trip(state):
    apply_action(state, "isolate_device", {"device": "WS2"})
    apply_action(state, "restore_device", {"device": "WS2"})
    assert state.devices["WS2"].status is DeviceStatus.ONLINE
    assert "WS2" in state.neighbors("R1")


def test_restricted_device_can_still_be_isolated(state):
    apply_action(state, "restrict_device", {"device": "APP1"})
    apply_action(state, "isolate_device", {"device": "APP1"})
    assert state.devices["APP1"].status is DeviceStatus.ISOLATED


@pytest.mark.parametrize("name, params, message", [
    ("isolate_device", {"device": "INET"}, "outside the organisation"),
    ("isolate_device", {"device": "GHOST"}, "unknown device"),
    ("restore_device", {"device": "WS1"}, "must be isolated/restricted"),
    ("remediate_device", {"device": "WS1"}, "must be isolated"),
    ("unblock_link", {"a": "R1", "b": "R2"}, "not blocked"),
    ("block_link", {"a": "WS1", "b": "DB1"}, "no link"),
    ("launch_missiles", {}, "unknown action"),
    ("block_link", {"a": "R1"}, "missing parameter"),
])
def test_invalid_actions_rejected(state, name, params, message):
    with pytest.raises(ActionError, match=message):
        apply_action(state, name, params)


def test_isolating_twice_rejected(state):
    apply_action(state, "isolate_device", {"device": "WS2"})
    with pytest.raises(ActionError, match="is isolated"):
        apply_action(state, "isolate_device", {"device": "WS2"})


def test_block_and_unblock_link(state):
    apply_action(state, "block_link", {"a": "R2", "b": "R1"})
    assert state.get_link("R1", "R2").status is LinkStatus.BLOCKED
    with pytest.raises(ActionError, match="already blocked"):
        apply_action(state, "block_link", {"a": "R1", "b": "R2"})
    apply_action(state, "unblock_link", {"a": "R1", "b": "R2"})
    assert state.get_link("R1", "R2").is_active


def test_execute_action_records_transition():
    manager = StateManager(load_topology())
    t = execute_action(manager, "increase_monitoring", {"device": "DB1"})
    assert t.action == "increase_monitoring"
    assert t.changes == ["DB1.monitored: False -> True"]


def test_execute_action_with_failed_precondition_changes_nothing():
    manager = StateManager(load_topology())
    digest = manager.digest()
    with pytest.raises(ActionError):
        execute_action(manager, "restore_device", {"device": "WS1"})
    assert manager.digest() == digest and manager.transitions == []


def test_every_action_has_description():
    assert all(spec.description for spec in ACTIONS.values())
