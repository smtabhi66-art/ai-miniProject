"""The environment: the true simulated world the agent acts in.

It owns two things the agent does not:

* ``world``  the true network state (statuses, links)
* ``hidden`` ground truth per device: is it *really* compromised?

The agent only ever receives events from ``step()`` and the result of its own
actions from ``execute()``. This separation is what makes the environment
partially observable.

Run a scenario from the command line::

    python -m app.simulation.environment --list
    python -m app.simulation.environment s8_multi_step --seed 42
    python -m app.simulation.environment s8_multi_step --seed 42 --isolate WS2 --at 7
"""
import argparse
import copy
import random
from dataclasses import dataclass
from typing import Any

from app.algorithms.search.bfs import bfs_shortest_path
from app.algorithms.search.graph import graph_from_network
from app.models.enums import DeviceStatus, EventType, LinkStatus
from app.models.events import SecurityEvent
from app.models.incident import ActionRecord
from app.models.network import NetworkState
from app.simulation.actions import ActionError, apply_action
from app.simulation.event_generator import EventGenerator, PlannedEvent
from app.simulation.network_builder import load_topology
from app.simulation.scenarios import Scenario, generate_scenario, list_scenarios, load_scenario
from app.core.console import utf8_output


@dataclass
class HiddenState:
    compromised: bool = False
    credentials_stolen: bool = False


class NetworkSimulator:
    def __init__(self, scenario: Scenario, seed: int | None = None):
        self.scenario = scenario
        self.seed = seed if seed is not None else random.SystemRandom().randrange(2**31)
        self.world = load_topology(scenario.topology)
        for a, b in scenario.initial_blocked_links:
            self.world.get_link(a, b).status = LinkStatus.BLOCKED
        self.hidden = {device_id: HiddenState() for device_id in self.world.devices}
        for device_id in scenario.initial_compromised:
            self.hidden[device_id].compromised = True
        self.generator = EventGenerator(scenario, self.world, self.seed)
        self.tick = 0
        self.delivered: list[SecurityEvent] = []
        self.suppressed: list[tuple[SecurityEvent, str]] = []
        self.labels: dict[str, bool] = {}  # event id -> malicious; evaluation only
        self.actions: list[ActionRecord] = []

    @property
    def finished(self) -> bool:
        return self.tick >= self.scenario.ticks

    def initial_model(self) -> NetworkState:
        """What the agent may know at start: topology and statuses, never ``hidden``."""
        return copy.deepcopy(self.world)

    # ---- percepts ---------------------------------------------------------
    def step(self) -> list[SecurityEvent]:
        """Emit this tick's events, then advance the clock."""
        if self.finished:
            return []
        delivered = []
        for planned in self.generator.events_for_tick(self.tick):
            reason = self._suppression_reason(planned)
            if reason is not None:
                self.suppressed.append((planned.event, reason))
                continue
            if planned.compromise is not None:
                victim = self.hidden[planned.compromise]
                victim.compromised = True
                if planned.event.type is EventType.SUCCESSFUL_LOGIN:
                    victim.credentials_stolen = True
            self.labels[planned.event.id] = planned.malicious
            delivered.append(planned.event)
        self.delivered.extend(delivered)
        self.tick += 1
        return delivered

    def _suppression_reason(self, planned: PlannedEvent) -> str | None:
        """Why an event cannot happen in the current world, or None if it can."""
        event = planned.event
        if planned.requires_compromise and not self.hidden[event.source].compromised:
            return f"{event.source} is not compromised"
        source = self.world.devices[event.source]
        if not source.is_traversable:
            return f"{event.source} is {source.status.value}"
        if planned.malicious and source.status is DeviceStatus.RESTRICTED:
            return f"{event.source} is restricted"
        if event.target is not None:
            target = self.world.devices[event.target]
            if not target.is_traversable:
                return f"{event.target} is {target.status.value}"
            if not _path_exists(self.world, event.source, event.target):
                return f"no usable path {event.source} -> {event.target}"
        return None

    # ---- actuators --------------------------------------------------------
    def execute(self, name: str, params: dict[str, Any]) -> ActionRecord:
        """Apply a simulated action to the true world. Never raises on bad preconditions."""
        try:
            apply_action(self.world, name, params)
        except ActionError as exc:
            record = ActionRecord(self.tick, name, dict(params), False, str(exc))
        else:
            if name == "remediate_device":
                self.hidden[params["device"]].compromised = False
            elif name == "reset_credentials":
                self.hidden[params["device"]].credentials_stolen = False
            record = ActionRecord(self.tick, name, dict(params), True, f"{name} applied (simulated)")
        self.actions.append(record)
        return record

    # ---- evaluation only ----------------------------------------------------
    def ground_truth(self) -> dict[str, Any]:
        return {
            "compromised": sorted(d for d, h in self.hidden.items() if h.compromised),
            "credentials_stolen": sorted(d for d, h in self.hidden.items() if h.credentials_stolen),
            "expected": {d: lvl.value for d, lvl in self.scenario.expected.items()},
        }


def _path_exists(world: NetworkState, source: str, target: str) -> bool:
    """Is there a usable path in the true world? (BFS over active links)"""
    return bfs_shortest_path(graph_from_network(world), source, target) is not None


def _main() -> None:
    parser = argparse.ArgumentParser(description="Run a simulated scenario (no agent yet).")
    parser.add_argument("scenario", nargs="?", default="s8_multi_step",
                        help="scenario id, or 'random' for a generated one")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--isolate", help="device to isolate during the run (demo of containment)")
    parser.add_argument("--at", type=int, default=6, help="tick at which to isolate")
    parser.add_argument("--show-noise", action="store_true", help="also print normal traffic")
    args = parser.parse_args()
    utf8_output()

    if args.list:
        for s in list_scenarios():
            print(f"{s.id:<34} {s.name}")
        return

    scenario = generate_scenario(args.seed) if args.scenario == "random" else load_scenario(args.scenario)
    sim = NetworkSimulator(scenario, args.seed)
    print(f"{scenario.name}  (seed {sim.seed})\n{scenario.description}\n")
    while not sim.finished:
        if args.isolate and sim.tick == args.at:
            print(f"  >> {sim.execute('isolate_device', {'device': args.isolate}).message}")
        tick = sim.tick
        suppressed_before = len(sim.suppressed)
        for e in sim.step():
            if args.show_noise or sim.labels[e.id] or e.type is not EventType.NORMAL_TRAFFIC:
                tag = "ATTACK" if sim.labels[e.id] else "noise "
                print(f"t={tick:<3} {tag} {e.type.value:<20} {e.source:>6} -> {e.target}")
        for e, reason in sim.suppressed[suppressed_before:]:
            print(f"t={tick:<3} BLOCKED {e.type.value:<19} {e.source:>6} -> {e.target}   ({reason})")
    print(f"\nGround truth: {sim.ground_truth()}")


if __name__ == "__main__":
    _main()
