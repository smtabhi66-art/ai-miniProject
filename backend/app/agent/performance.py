"""Performance measure (rationality) and detection metrics.

The performance measure is computed by the *environment*, using ground truth
the agent never sees, as in the PEAS model:

    score =  +10 × threats contained         (compromised devices no longer free to act)
             -20 × critical-service outage ticks
              -3 × healthy devices isolated  (over-reaction)
              -1 × ticks a compromised device stayed online and unrestricted
              -5 × false-positive incidents  (incident on a device whose correct label is Normal)

Detection metrics compare the *peak* threat level the agent gave each device
with the scenario's ground-truth label: confusion matrix, accuracy and
per-class precision/recall.
"""
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import DeviceStatus, ThreatLevel
from app.models.network import NetworkState
from app.simulation.environment import NetworkSimulator
from app.simulation.scenarios import Scenario

WEIGHTS = {"contained": 10, "outage_ticks": -20, "healthy_isolated": -3,
           "active_compromise_ticks": -1, "false_positives": -5}
LEVELS = [ThreatLevel.NORMAL, ThreatLevel.SUSPICIOUS, ThreatLevel.CRITICAL]


def service_available(world: NetworkState, name: str, _seen: frozenset = frozenset()) -> bool:
    if name in _seen:
        return True  # dependency cycle: don't recurse forever
    service = world.services[name]
    if not any(world.devices[h].is_traversable for h in service.hosts):
        return False
    return all(service_available(world, dep, _seen | {name}) for dep in service.depends_on)


@dataclass
class PerformanceMeter:
    sim: NetworkSimulator
    counts: dict[str, int] = field(default_factory=lambda: {k: 0 for k in WEIGHTS})
    timeline: list[dict[str, Any]] = field(default_factory=list)
    outages: list[str] = field(default_factory=list)
    _ever_compromised: set[str] = field(default_factory=set)
    _contained: set[str] = field(default_factory=set)
    _actions_seen: int = 0

    def update(self, tick: int) -> None:
        world, hidden = self.sim.world, self.sim.hidden
        for record in self.sim.actions[self._actions_seen:]:
            if record.success and record.action == "isolate_device" and not hidden[record.params["device"]].compromised:
                self.counts["healthy_isolated"] += 1
        self._actions_seen = len(self.sim.actions)

        for name, service in world.services.items():
            if service.critical and not service_available(world, name):
                self.counts["outage_ticks"] += 1
                self.outages.append(f"tick {tick}: critical service '{name}' unavailable")

        self._ever_compromised |= {d for d, h in hidden.items() if h.compromised}
        for d in self._ever_compromised:
            status = world.devices[d].status
            free = hidden[d].compromised and status is DeviceStatus.ONLINE
            if free:
                self.counts["active_compromise_ticks"] += 1
            elif d not in self._contained:
                self._contained.add(d)
                self.counts["contained"] += 1
        self.timeline.append({"tick": tick, "score": self.score()})

    def set_false_positives(self, n: int) -> None:
        self.counts["false_positives"] = n

    def score(self) -> int:
        return sum(WEIGHTS[k] * v for k, v in self.counts.items())

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score(),
            "counts": dict(self.counts),
            "weights": dict(WEIGHTS),
            "timeline": list(self.timeline),
            "outages": list(self.outages),
            "contained_devices": sorted(self._contained),
        }


def detection_metrics(peak: dict[str, ThreatLevel], scenario: Scenario, devices: list[str]) -> dict[str, Any]:
    matrix = {e.value: {p.value: 0 for p in LEVELS} for e in LEVELS}
    mistakes = []
    for d in devices:
        expected = scenario.expected_level(d)
        predicted = peak.get(d, ThreatLevel.NORMAL)
        matrix[expected.value][predicted.value] += 1
        if expected is not predicted:
            mistakes.append({"device": d, "expected": expected.value, "predicted": predicted.value})
    total = len(devices)
    correct = sum(matrix[l.value][l.value] for l in LEVELS)
    per_class = {}
    for level in LEVELS:
        tp = matrix[level.value][level.value]
        predicted_n = sum(matrix[e.value][level.value] for e in LEVELS)
        actual_n = sum(matrix[level.value].values())
        per_class[level.value] = {
            "precision": round(tp / predicted_n, 3) if predicted_n else None,
            "recall": round(tp / actual_n, 3) if actual_n else None,
            "support": actual_n,
        }
    return {"accuracy": round(correct / total, 3) if total else None, "confusion_matrix": matrix,
            "per_class": per_class, "mistakes": mistakes}
