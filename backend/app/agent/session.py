"""A simulation session: one environment (NetworkSimulator) plus one DefenseAgent.

    session = Session.create("s8_multi_step", seed=42)
    session.run()
    print(session.report()["score"])

``act=False`` runs the agent in *passive* (detection-only) mode. It still
perceives, reasons and opens incidents, but takes no actions. Detection
accuracy is measured in passive mode so that containment doesn't cut an
attack short before every stage of it has been observed.
"""
from typing import Any

from app.agent.agent import DefenseAgent
from app.agent.isolation_csp import DEFAULT_BUDGET
from app.agent.performance import PerformanceMeter, detection_metrics
from app.core.config import DEFAULT_SEED
from app.models.enums import ThreatLevel
from app.simulation.environment import NetworkSimulator
from app.simulation.scenarios import Scenario, generate_scenario, load_scenario
from app.state.state_manager import StateManager


class Session:
    def __init__(self, scenario: Scenario, seed: int | None = DEFAULT_SEED, act: bool = True,
                 budget: int = DEFAULT_BUDGET):
        self.scenario = scenario
        self.act = act
        self.sim = NetworkSimulator(scenario, seed)
        self.manager = StateManager(self.sim.initial_model())
        self.agent = DefenseAgent(self.manager, self.sim.execute if act else None, act=act, budget=budget)
        self.meter = PerformanceMeter(self.sim)
        self.tick_events: dict[int, list] = {}

    @classmethod
    def create(cls, scenario_id: str, seed: int | None = DEFAULT_SEED, act: bool = True,
               budget: int = DEFAULT_BUDGET) -> "Session":
        if scenario_id == "random":
            scenario = generate_scenario(seed if seed is not None else DEFAULT_SEED)
        else:
            scenario = load_scenario(scenario_id)
        return cls(scenario, seed, act, budget)

    @property
    def tick(self) -> int:
        return self.sim.tick

    @property
    def finished(self) -> bool:
        return self.sim.finished

    def step(self) -> bool:
        """Advance one tick. Returns False if the scenario had already finished."""
        if self.finished:
            return False
        tick = self.sim.tick
        events = self.sim.step()
        self.tick_events[tick] = events
        self.agent.step(events)
        self.meter.update(tick)
        self.meter.set_false_positives(self._false_positives())
        return True

    def run(self) -> "Session":
        while self.step():
            pass
        return self

    def _false_positives(self) -> int:
        return sum(1 for inc in self.agent.incidents
                   if all(self.scenario.expected_level(d) is ThreatLevel.NORMAL for d in inc.devices))

    # ---- views -------------------------------------------------------------------------
    def report(self) -> dict[str, Any]:
        devices = list(self.manager.state.devices)
        return {
            "scenario": self.scenario.to_dict(),
            "seed": self.sim.seed,
            "mode": "active" if self.act else "passive",
            "ticks_run": self.sim.tick,
            "finished": self.finished,
            "performance": self.meter.to_dict(),
            "detection": detection_metrics(self.agent.peak_levels, self.scenario, devices),
            "peak_levels": {d: l.value for d, l in self.agent.peak_levels.items()},
            "incidents": [i.to_dict() for i in self.agent.incidents],
            "ground_truth": self.sim.ground_truth(),
            "attack_events": {"delivered": sum(1 for v in self.sim.labels.values() if v),
                              "prevented": sum(1 for e, _ in self.sim.suppressed if e.type.value != "normal_traffic")},
        }

    def snapshot(self, since_tick: int = 0, decision_limit: int = 200) -> dict[str, Any]:
        """Everything the dashboard needs, from the agent's point of view (no hidden truth)."""
        state = self.manager.state
        events = [e.to_dict() for e in self.manager.event_log if e.tick >= since_tick]
        assessment = self.agent.last_assessment
        return {
            "scenario": self.scenario.to_dict(),
            "seed": self.sim.seed,
            "mode": "active" if self.act else "passive",
            "tick": self.sim.tick,
            "total_ticks": self.scenario.ticks,
            "finished": self.finished,
            "network": state.to_dict(),
            "events": events,
            "suppressed": [{**e.to_dict(), "reason": r} for e, r in self.sim.suppressed if e.tick >= since_tick
                           and e.type.value != "normal_traffic"],
            "incidents": self.agent.incident_views(),
            "decisions": [d.to_dict() for d in self.agent.decisions[-decision_limit:]],
            "assessment": assessment.to_dict() if assessment else None,
            "transitions": [t.to_dict() for t in self.manager.transitions],
            "performance": self.meter.to_dict(),
        }
