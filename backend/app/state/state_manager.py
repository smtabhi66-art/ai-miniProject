"""State Manager: the single owner of the agent's internal NetworkState.

Every change to the network goes through ``apply()``, which implements the
state-transition model ``s' = T(s, a)``:

1. deep-copy the current state ``s``
2. run the action's effect function on the copy
3. if the effect raises, ``s`` is untouched (the action is atomic)
4. otherwise record ``(s, a, s')`` as a Transition with a human-readable diff
"""
import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

from app.core.config import EVIDENCE_RETENTION_TICKS
from app.models.enums import ThreatLevel
from app.models.events import SOURCE, TARGET, Evidence, SecurityEvent
from app.models.network import NetworkState


@dataclass(frozen=True)
class Transition:
    tick: int
    action: str
    params: dict[str, Any]
    before: str  # state digest
    after: str
    changes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tick": self.tick,
            "action": self.action,
            "params": dict(self.params),
            "before": self.before,
            "after": self.after,
            "changes": list(self.changes),
        }


def state_digest(state: NetworkState) -> str:
    """Short fingerprint of the parts of the state that actions can change."""
    canonical = {
        "devices": {d.id: [d.status.value, d.threat_level.value, d.monitored] for d in state.devices.values()},
        "links": sorted(f"{l.source}-{l.target}:{l.status.value}" for l in state.links()),
        "facts": sorted("|".join(f) for f in state.facts),
    }
    raw = json.dumps(canonical, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()[:12]


def diff_states(before: NetworkState, after: NetworkState) -> list[str]:
    changes = []
    for device_id, old in before.devices.items():
        new = after.devices[device_id]
        if old.status != new.status:
            changes.append(f"{device_id}.status: {old.status.value} -> {new.status.value}")
        if old.threat_level != new.threat_level:
            changes.append(f"{device_id}.threat_level: {old.threat_level.value} -> {new.threat_level.value}")
        if old.monitored != new.monitored:
            changes.append(f"{device_id}.monitored: {old.monitored} -> {new.monitored}")
    for old in before.links():
        new = after.get_link(old.source, old.target)
        if new is not None and old.status != new.status:
            changes.append(f"link {old.source}-{old.target}: {old.status.value} -> {new.status.value}")
    for fact in sorted(after.facts - before.facts):
        changes.append(f"+ {fact[0]}({', '.join(fact[1:])})")
    for fact in sorted(before.facts - after.facts):
        changes.append(f"- {fact[0]}({', '.join(fact[1:])})")
    return changes


class StateManager:
    def __init__(self, initial_state: NetworkState):
        self._state = initial_state
        self.event_log: list[SecurityEvent] = []
        self.transitions: list[Transition] = []

    @property
    def state(self) -> NetworkState:
        return self._state

    @property
    def tick(self) -> int:
        return self._state.tick

    def snapshot(self) -> NetworkState:
        """Independent copy, safe for algorithms to explore without side effects."""
        return copy.deepcopy(self._state)

    def digest(self) -> str:
        return state_digest(self._state)

    # ---- time & percepts ----------------------------------------------
    def advance_tick(self) -> int:
        self._state.tick += 1
        for evidence in self._state.evidence.values():
            evidence.prune(self._state.tick, EVIDENCE_RETENTION_TICKS)
        return self._state.tick

    def record_event(self, event: SecurityEvent) -> None:
        """Store a percept and update evidence for its source and target."""
        devices = self._state.devices
        if event.source not in devices:
            raise ValueError(f"event {event.id}: unknown source {event.source}")
        if event.target is not None and event.target not in devices:
            raise ValueError(f"event {event.id}: unknown target {event.target}")
        if event.tick > self._state.tick:
            raise ValueError(f"event {event.id} is from future tick {event.tick} (now {self._state.tick})")
        self.event_log.append(event)
        self._evidence_for(event.source).add(event.type, SOURCE, event.tick)
        if event.target is not None:
            self._evidence_for(event.target).add(event.type, TARGET, event.tick)

    def events_since(self, tick: int) -> list[SecurityEvent]:
        return [e for e in self.event_log if e.tick >= tick]

    def _evidence_for(self, device_id: str) -> Evidence:
        return self._state.evidence.setdefault(device_id, Evidence(device_id))

    # ---- beliefs --------------------------------------------------------
    def set_assessment(self, device_id: str, level: ThreatLevel, risk_score: float) -> None:
        """Record the detector's belief about a device. Not an action, so no transition."""
        if not 0.0 <= risk_score <= 1.0:
            raise ValueError("risk_score must be 0..1")
        device = self._state.devices[device_id]
        device.threat_level = level
        device.risk_score = risk_score

    def add_belief(self, fact: tuple[str, ...]) -> None:
        self._state.facts.add(fact)

    def remove_belief(self, fact: tuple[str, ...]) -> None:
        self._state.facts.discard(fact)

    # ---- actions ----------------------------------------------------------
    def apply(self, action: str, params: dict[str, Any],
              effect: Callable[[NetworkState], None]) -> Transition:
        before = self._state
        candidate = copy.deepcopy(before)
        effect(candidate)  # may raise; then the current state is left unchanged
        transition = Transition(
            tick=before.tick,
            action=action,
            params=dict(params),
            before=state_digest(before),
            after=state_digest(candidate),
            changes=diff_states(before, candidate),
        )
        self._state = candidate
        self.transitions.append(transition)
        return transition
