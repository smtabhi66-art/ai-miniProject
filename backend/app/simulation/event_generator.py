"""Event generator: proposes the events for each tick.

It produces seeded background noise plus the scenario's scripted steps. It does
*not* decide whether an event actually happens. The environment does that, so
a contained attacker's events can be suppressed.

Determinism: the generator makes the same number of random draws every tick,
whatever the network state is. So the same seed always gives the same noise,
even when the agent takes different actions.
"""
import random
from dataclasses import dataclass

from app.models.enums import DeviceType, EventType
from app.models.events import SecurityEvent
from app.models.network import NetworkState
from app.simulation.scenarios import Scenario

CLIENT_TYPES = (DeviceType.WORKSTATION, DeviceType.ADMIN_WORKSTATION)


@dataclass
class PlannedEvent:
    event: SecurityEvent
    malicious: bool = False
    requires_compromise: bool = False
    compromise: str | None = None


class EventGenerator:
    def __init__(self, scenario: Scenario, network: NetworkState, seed: int):
        self.scenario = scenario
        self.rng = random.Random(seed)
        # Noise endpoints are fixed at start so random draws never depend on later state.
        self.clients = sorted(d.id for d in network.devices.values() if d.type in CLIENT_TYPES)
        self.servers = sorted(d.id for d in network.devices.values() if d.services)
        auth = network.services.get("auth")
        self.auth_hosts = sorted(auth.hosts) if auth else []

    def events_for_tick(self, tick: int) -> list[PlannedEvent]:
        counter = iter(range(1, 10_000))

        def new_id() -> str:
            return f"T{tick:03d}-{next(counter):03d}"

        planned = self._background(tick, new_id)
        for step in self.scenario.steps:
            if not step.active_at(tick):
                continue
            for target in step.targets:
                for _ in range(step.repeat):
                    event = SecurityEvent(new_id(), tick, step.type, step.source, target, dict(step.details))
                    planned.append(PlannedEvent(event, step.malicious, step.requires_compromise, step.compromise))
        return planned

    def _background(self, tick: int, new_id) -> list[PlannedEvent]:
        bg = self.scenario.background
        planned = []
        if self.clients and self.servers:
            for _ in range(bg.normal_traffic_per_tick):
                src = self.rng.choice(self.clients)
                dst = self.rng.choice(self.servers)
                size = self.rng.randint(200, 5000)
                planned.append(PlannedEvent(SecurityEvent(
                    new_id(), tick, EventType.NORMAL_TRAFFIC, src, dst, {"bytes": size})))
        # Always draw, even when no event results, to keep the random sequence stable.
        roll = self.rng.random()
        src = self.rng.choice(self.clients) if self.clients else None
        if self.auth_hosts and src is not None and roll < bg.benign_failed_login_prob:
            planned.append(PlannedEvent(SecurityEvent(
                new_id(), tick, EventType.FAILED_LOGIN, src, self.auth_hosts[0])))
        return planned
