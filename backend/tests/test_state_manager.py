"""Milestone 2: state transitions, percepts and evidence."""
import pytest

from app.core.config import EVIDENCE_RETENTION_TICKS
from app.models.enums import DeviceStatus, EventType, LinkStatus, ThreatLevel
from app.models.events import SOURCE, TARGET, SecurityEvent
from app.simulation.network_builder import load_topology
from app.state.state_manager import StateManager


@pytest.fixture
def manager():
    return StateManager(load_topology())


def isolate_ws2(state):
    state.devices["WS2"].status = DeviceStatus.ISOLATED
    state.get_link("R1", "WS2").status = LinkStatus.BLOCKED


def test_apply_produces_new_state_and_transition(manager):
    old_state, old_digest = manager.state, manager.digest()
    transition = manager.apply("isolate_device", {"device": "WS2"}, isolate_ws2)

    assert manager.state is not old_state
    assert old_state.devices["WS2"].status is DeviceStatus.ONLINE  # s is untouched
    assert manager.state.devices["WS2"].status is DeviceStatus.ISOLATED  # s' changed
    assert transition.before == old_digest != transition.after == manager.digest()
    assert transition.changes == [
        "WS2.status: online -> isolated",
        "link R1-WS2: active -> blocked",
    ]
    assert manager.transitions == [transition]


def test_failed_action_leaves_state_unchanged(manager):
    digest = manager.digest()

    def broken(state):
        state.devices["WS2"].status = DeviceStatus.ISOLATED
        raise RuntimeError("precondition failed")

    with pytest.raises(RuntimeError):
        manager.apply("isolate_device", {"device": "WS2"}, broken)
    assert manager.digest() == digest
    assert manager.state.devices["WS2"].status is DeviceStatus.ONLINE
    assert manager.transitions == []


def test_fact_changes_appear_in_diff(manager):
    t = manager.apply("assert_fact", {}, lambda s: s.facts.add(("Compromised", "WS2")))
    assert t.changes == ["+ Compromised(WS2)"]


def test_record_event_updates_source_and_target_evidence(manager):
    manager.record_event(SecurityEvent("e1", 0, EventType.FAILED_LOGIN, "WS2", "AUTH1"))
    ev = manager.state.evidence
    assert ev["WS2"].count(EventType.FAILED_LOGIN, SOURCE, 0, window=3) == 1
    assert ev["AUTH1"].count(EventType.FAILED_LOGIN, TARGET, 0, window=3) == 1
    assert ev["AUTH1"].count(EventType.FAILED_LOGIN, SOURCE, 0, window=3) == 0


def test_evidence_window_counts_only_recent_ticks(manager):
    for tick in range(5):  # one failed login per tick, ticks 0..4
        manager.record_event(SecurityEvent(f"e{tick}", tick, EventType.FAILED_LOGIN, "INET", "WS1"))
        manager.advance_tick()
    ws1 = manager.state.evidence["WS1"]
    assert ws1.count(EventType.FAILED_LOGIN, TARGET, current_tick=4, window=3) == 3  # ticks 2,3,4
    assert ws1.count(EventType.FAILED_LOGIN, TARGET, current_tick=4, window=10) == 5


def test_old_evidence_is_pruned(manager):
    manager.record_event(SecurityEvent("e0", 0, EventType.PORT_SCAN, "WS3", "R1"))
    for _ in range(EVIDENCE_RETENTION_TICKS):
        manager.advance_tick()
    assert manager.state.evidence["WS3"].observations == {}


@pytest.mark.parametrize("event", [
    SecurityEvent("bad1", 0, EventType.PORT_SCAN, "GHOST", "R1"),
    SecurityEvent("bad2", 0, EventType.PORT_SCAN, "WS1", "GHOST"),
    SecurityEvent("bad3", 99, EventType.PORT_SCAN, "WS1", "R1"),
])
def test_invalid_events_rejected(manager, event):
    with pytest.raises(ValueError):
        manager.record_event(event)
    assert manager.event_log == []


def test_events_since(manager):
    manager.record_event(SecurityEvent("a", 0, EventType.NORMAL_TRAFFIC, "WS1", "WEB1"))
    manager.advance_tick()
    manager.record_event(SecurityEvent("b", 1, EventType.NORMAL_TRAFFIC, "WS1", "WEB1"))
    assert [e.id for e in manager.events_since(1)] == ["b"]


def test_set_assessment_changes_belief_not_status(manager):
    manager.set_assessment("WS2", ThreatLevel.SUSPICIOUS, 0.6)
    ws2 = manager.state.devices["WS2"]
    assert ws2.threat_level is ThreatLevel.SUSPICIOUS and ws2.risk_score == 0.6
    assert ws2.status is DeviceStatus.ONLINE
    with pytest.raises(ValueError):
        manager.set_assessment("WS2", ThreatLevel.CRITICAL, 1.7)


def test_snapshot_is_independent(manager):
    snap = manager.snapshot()
    snap.devices["WS1"].status = DeviceStatus.OFFLINE
    assert manager.state.devices["WS1"].status is DeviceStatus.ONLINE
