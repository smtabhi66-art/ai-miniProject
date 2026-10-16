"""Security events (the agent's percepts) and per-device evidence."""
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import EventType

SOURCE = "source"
TARGET = "target"


@dataclass
class SecurityEvent:
    """One simulated observation, e.g. a failed login from WS2 to AUTH1."""

    id: str
    tick: int
    type: EventType
    source: str
    target: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tick": self.tick,
            "type": self.type.value,
            "source": self.source,
            "target": self.target,
            "details": dict(self.details),
        }


@dataclass
class Evidence:
    """Ticks at which a device was seen in each (event type, role).

    ``role`` is SOURCE when the device caused the event (e.g. it ran a port scan)
    and TARGET when the event was aimed at it (e.g. failed logins against it).
    Detection rules count these inside a sliding time window.
    """

    device_id: str
    observations: dict[str, list[int]] = field(default_factory=dict)

    @staticmethod
    def key(event_type: EventType, role: str) -> str:
        return f"{event_type.value}:{role}"

    def add(self, event_type: EventType, role: str, tick: int) -> None:
        self.observations.setdefault(self.key(event_type, role), []).append(tick)

    def count(self, event_type: EventType, role: str, current_tick: int, window: int) -> int:
        """Number of observations with ``current_tick - window < tick <= current_tick``."""
        ticks = self.observations.get(self.key(event_type, role), [])
        return sum(1 for t in ticks if current_tick - window < t <= current_tick)

    def prune(self, current_tick: int, retention: int) -> None:
        cutoff = current_tick - retention
        for key in list(self.observations):
            kept = [t for t in self.observations[key] if t > cutoff]
            if kept:
                self.observations[key] = kept
            else:
                del self.observations[key]

    def to_dict(self) -> dict[str, Any]:
        return {"device_id": self.device_id, "observations": {k: list(v) for k, v in self.observations.items()}}
