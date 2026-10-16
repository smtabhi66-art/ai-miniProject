"""Scenario files: scripted attacks + background noise + ground-truth labels.

A scenario step describes events to emit, for example::

    {"ticks": [2, 4], "type": "failed_login", "source": "INET", "target": "WS1",
     "repeat": 4, "malicious": true}

Step fields:
    tick / ticks         single tick, or inclusive [start, end] range
    target / targets     one target, a list (one event each), or omitted
    repeat               events per target per tick (default 1)
    malicious            ground-truth label, used for evaluation only
    requires_compromise  emit only while the source is really compromised
    compromise           device that becomes compromised when this event lands
    details              extra event fields, e.g. {"bytes": 250000}

``expected`` gives the correct threat level per device (others are Normal).
Labelling policy: really compromised -> critical; targeted by brute force or
unauthorized access, or behaving anomalously without proof of compromise ->
suspicious; everything else -> normal.
"""
import json
import random
from dataclasses import dataclass, field
from typing import Any

from app.core.config import DEFAULT_TOPOLOGY, SCENARIO_DIR
from app.models.enums import DeviceType, EventType, ThreatLevel
from app.models.network import NetworkState
from app.simulation.network_builder import load_topology

LEVEL_ORDER = [ThreatLevel.NORMAL, ThreatLevel.SUSPICIOUS, ThreatLevel.CRITICAL]


class ScenarioError(ValueError):
    """Raised when a scenario file is malformed or references unknown devices."""


@dataclass
class ScenarioStep:
    start: int
    end: int
    type: EventType
    source: str
    targets: list[str | None]
    repeat: int = 1
    malicious: bool = False
    requires_compromise: bool = False
    compromise: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def active_at(self, tick: int) -> bool:
        return self.start <= tick <= self.end


@dataclass
class Background:
    normal_traffic_per_tick: int = 2
    benign_failed_login_prob: float = 0.05


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    topology: str
    ticks: int
    steps: list[ScenarioStep]
    background: Background
    initial_compromised: list[str] = field(default_factory=list)
    initial_blocked_links: list[tuple[str, str]] = field(default_factory=list)
    expected: dict[str, ThreatLevel] = field(default_factory=dict)

    def expected_level(self, device_id: str) -> ThreatLevel:
        return self.expected.get(device_id, ThreatLevel.NORMAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "topology": self.topology,
            "ticks": self.ticks,
            "expected": {k: v.value for k, v in self.expected.items()},
        }


# ---- loading ---------------------------------------------------------------
def list_scenarios() -> list[Scenario]:
    return [load_scenario(p.stem) for p in sorted(SCENARIO_DIR.glob("*.json"))]


def load_scenario(scenario_id: str) -> Scenario:
    path = SCENARIO_DIR / f"{scenario_id}.json"
    if not path.is_file():
        raise ScenarioError(f"scenario not found: {scenario_id}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"invalid JSON in {path.name}: {exc}") from exc
    scenario = parse_scenario(data)
    if scenario.id != scenario_id:
        raise ScenarioError(f"{path.name}: id {scenario.id!r} does not match file name")
    return scenario


def parse_scenario(data: dict[str, Any], network: NetworkState | None = None) -> Scenario:
    """Build and validate a Scenario. ``network`` defaults to the scenario's topology."""
    try:
        topology = data.get("topology", DEFAULT_TOPOLOGY)
        network = network or load_topology(topology)
        ticks = int(data["ticks"])
        if ticks < 1:
            raise ScenarioError("ticks must be >= 1")
        bg = data.get("background", {})
        scenario = Scenario(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            topology=topology,
            ticks=ticks,
            steps=[_parse_step(raw, ticks) for raw in data.get("steps", [])],
            background=Background(
                normal_traffic_per_tick=int(bg.get("normal_traffic_per_tick", 2)),
                benign_failed_login_prob=float(bg.get("benign_failed_login_prob", 0.05)),
            ),
            initial_compromised=list(data.get("initial_compromised", [])),
            initial_blocked_links=[(a, b) for a, b in data.get("initial_blocked_links", [])],
            expected={d: ThreatLevel(level) for d, level in data.get("expected", {}).items()},
        )
    except KeyError as exc:
        raise ScenarioError(f"missing required field {exc}") from exc
    except ScenarioError:
        raise
    except ValueError as exc:
        raise ScenarioError(str(exc)) from exc
    _check_references(scenario, network)
    return scenario


def _parse_step(raw: dict[str, Any], ticks: int) -> ScenarioStep:
    if "tick" in raw:
        start = end = int(raw["tick"])
    else:
        start, end = (int(t) for t in raw["ticks"])
    if not 0 <= start <= end < ticks:
        raise ScenarioError(f"step ticks {start}..{end} outside 0..{ticks - 1}")
    if "targets" in raw:
        targets = list(raw["targets"])
    else:
        targets = [raw.get("target")]
    step = ScenarioStep(
        start=start,
        end=end,
        type=EventType(raw["type"]),
        source=raw["source"],
        targets=targets,
        repeat=int(raw.get("repeat", 1)),
        malicious=bool(raw.get("malicious", False)),
        requires_compromise=bool(raw.get("requires_compromise", False)),
        compromise=raw.get("compromise"),
        details=dict(raw.get("details", {})),
    )
    if step.repeat < 1:
        raise ScenarioError("repeat must be >= 1")
    return step


def _check_references(scenario: Scenario, network: NetworkState) -> None:
    known = network.devices
    if not 0.0 <= scenario.background.benign_failed_login_prob <= 1.0:
        raise ScenarioError("benign_failed_login_prob must be 0..1")
    for step in scenario.steps:
        for device_id in [step.source, step.compromise, *step.targets]:
            if device_id is not None and device_id not in known:
                raise ScenarioError(f"step references unknown device {device_id}")
    for device_id in [*scenario.initial_compromised, *scenario.expected]:
        if device_id not in known:
            raise ScenarioError(f"unknown device {device_id}")
    for a, b in scenario.initial_blocked_links:
        if network.get_link(a, b) is None:
            raise ScenarioError(f"initial_blocked_links: no link {a}-{b}")


# ---- random scenario generation ----------------------------------------------
def generate_scenario(seed: int, ticks: int = 15, topology: str = DEFAULT_TOPOLOGY) -> Scenario:
    """Compose 1-2 attack patterns on randomly chosen devices (deterministic per seed)."""
    if ticks < 8:
        raise ScenarioError("generated scenarios need at least 8 ticks")
    rng = random.Random(seed)
    network = load_topology(topology)
    workstations = sorted(d.id for d in network.devices.values() if d.type is DeviceType.WORKSTATION)
    critical_hosts = sorted({h for s in network.services.values() if s.critical for h in s.hosts})
    db_hosts = sorted(network.services["db"].hosts) if "db" in network.services else critical_hosts

    data: dict[str, Any] = {
        "id": f"random_{seed}",
        "name": f"Random scenario (seed {seed})",
        "description": "",
        "topology": topology,
        "ticks": ticks,
        "background": {"normal_traffic_per_tick": 3, "benign_failed_login_prob": 0.1},
        "steps": [],
        "initial_compromised": [],
        "expected": {},
    }
    patterns = rng.sample(["external_brute_force", "insider_scan", "compromised_exfiltration"],
                          k=rng.choice([1, 2]))
    actors = rng.sample(workstations, k=len(patterns))
    summaries = []
    for pattern, actor in zip(patterns, actors):
        start = rng.randint(1, ticks - 6)
        if pattern == "external_brute_force":
            success = rng.random() < 0.5
            _add_brute_force(data, actor, start, success, rng.choice(critical_hosts))
            summaries.append(f"external brute force on {actor} ({'succeeds' if success else 'fails'})")
        elif pattern == "insider_scan":
            others = rng.sample([w for w in workstations if w != actor], k=min(3, len(workstations) - 1))
            _add_insider_scan(data, actor, others, start)
            summaries.append(f"{actor} scans {', '.join(others)}")
        else:
            _add_exfiltration(data, actor, rng.choice(db_hosts), start)
            summaries.append(f"compromised {actor} exfiltrates data")
    data["description"] = "; ".join(summaries) + "."
    return parse_scenario(data, network)


def _raise_expected(data: dict[str, Any], device_id: str, level: ThreatLevel) -> None:
    current = ThreatLevel(data["expected"].get(device_id, ThreatLevel.NORMAL.value))
    if LEVEL_ORDER.index(level) > LEVEL_ORDER.index(current):
        data["expected"][device_id] = level.value


def _add_brute_force(data, victim, start, success, exfil_target) -> None:
    last = data["ticks"] - 1
    data["steps"].append({"ticks": [start, start + 1], "type": "failed_login", "source": "INET",
                          "target": victim, "repeat": 4, "malicious": True})
    _raise_expected(data, "INET", ThreatLevel.SUSPICIOUS)
    if success:
        data["steps"].append({"tick": start + 2, "type": "successful_login", "source": "INET",
                              "target": victim, "malicious": True, "compromise": victim})
        data["steps"].append({"ticks": [start + 3, last], "type": "unusual_traffic", "source": victim,
                              "target": exfil_target, "malicious": True, "requires_compromise": True})
        _raise_expected(data, victim, ThreatLevel.CRITICAL)
    else:
        _raise_expected(data, victim, ThreatLevel.SUSPICIOUS)


def _add_insider_scan(data, actor, targets, start) -> None:
    data["steps"].append({"tick": start, "type": "port_scan", "source": actor,
                          "targets": targets, "malicious": True})
    data["steps"].append({"ticks": [start + 1, start + 3], "type": "unusual_traffic", "source": actor,
                          "targets": targets, "malicious": True})
    _raise_expected(data, actor, ThreatLevel.SUSPICIOUS)


def _add_exfiltration(data, actor, db_host, start) -> None:
    last = data["ticks"] - 1
    data["initial_compromised"].append(actor)
    data["steps"].append({"tick": start, "type": "unauthorized_access", "source": actor,
                          "target": db_host, "malicious": True, "requires_compromise": True})
    data["steps"].append({"ticks": [start + 1, last], "type": "unusual_traffic", "source": actor,
                          "target": db_host, "malicious": True, "requires_compromise": True,
                          "details": {"bytes": 250000}})
    _raise_expected(data, actor, ThreatLevel.CRITICAL)
    _raise_expected(data, db_host, ThreatLevel.SUSPICIOUS)
