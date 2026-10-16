"""Incidents and the record of simulated actions taken for them."""
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import IncidentStatus, ThreatLevel


@dataclass
class ActionRecord:
    tick: int
    action: str
    params: dict[str, Any]
    success: bool
    message: str
    simulated: bool = True  # always True: no real-world action is ever taken

    def to_dict(self) -> dict[str, Any]:
        return {
            "tick": self.tick,
            "action": self.action,
            "params": dict(self.params),
            "success": self.success,
            "message": self.message,
            "simulated": self.simulated,
        }


@dataclass
class Incident:
    id: str
    opened_tick: int
    devices: list[str]
    level: ThreatLevel
    status: IncidentStatus = IncidentStatus.OPEN
    explanation: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)
    actions_taken: list[ActionRecord] = field(default_factory=list)
    verified: bool = False
    closed_tick: int | None = None
    decision: str | None = None                            # ISOLATE / RESTRICT / MONITOR / ESCALATE
    phase: str = "Detect"                                  # current HTN phase
    timeline: list[str] = field(default_factory=list)      # human-readable history
    verification: list[str] = field(default_factory=list)  # Modus Tollens proof lines
    htn_tree: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "opened_tick": self.opened_tick,
            "closed_tick": self.closed_tick,
            "devices": list(self.devices),
            "level": self.level.value,
            "status": self.status.value,
            "explanation": list(self.explanation),
            "plan": list(self.plan),
            "actions_taken": [a.to_dict() for a in self.actions_taken],
            "verified": self.verified,
            "decision": self.decision,
            "phase": self.phase,
            "timeline": list(self.timeline),
            "verification": list(self.verification),
            "htn_tree": list(self.htn_tree),
        }
