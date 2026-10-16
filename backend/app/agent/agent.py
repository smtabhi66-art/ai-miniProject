"""The defensive agent: a model-based, goal-based agent.

Every tick:

    1. PERCEIVE   record the new events in the internal model (StateManager)
    2. REASON     build facts and forward-chain the security rules (detection.py)
                  -> Normal / Suspicious / Critical per device, with proof trees
    3. UPDATE     store beliefs (e.g. Compromised(WS2)) and threat levels in the model
    4. DECIDE     open or escalate incidents; run the isolation CSP for any incident
                  that needs a containment decision
    5. PLAN       HTN planning: Detect -> Investigate -> Contain -> Verify -> Recover,
                  with the goal-stack planner expanding Contain
    6. ACT        execute plan steps: internal steps (evidence, BFS/DFS/Greedy/A*
                  investigation) and simulated actions through the actuator
    7. VERIFY     after containment, wait and apply Modus Tollens; only then recover
                  and resolve the incident (the goal test)

The agent never sees the simulator's hidden ground truth. It only gets events
and the results of its own actions. Every algorithm call is logged as a
DecisionLog for the dashboard.
"""
from dataclasses import dataclass, field
from typing import Any, Callable

from app.agent.detection import LEVEL_RANK, RISK, Assessment, SecurityRules, ThreatDetector, load_security_rules
from app.agent.investigation import investigate
from app.agent.isolation_csp import DEFAULT_BUDGET, ISOLATE, MONITOR, RESTRICT, solve_isolation
from app.agent.response_planning import (
    ESCALATE,
    WAIT_ACTIONS,
    WORLD_ACTIONS,
    actions_for,
    initial_state,
    plan_incident,
)
from app.agent.verification import check_containment
from app.algorithms.planning.goal_stack import goal_stack_plan
from app.algorithms.planning.strips import Action, lit
from app.models.enums import DeviceStatus, DeviceType, IncidentStatus, ThreatLevel
from app.models.events import SecurityEvent
from app.models.incident import ActionRecord, Incident
from app.simulation.actions import ActionError, execute_action
from app.state.state_manager import StateManager

Actuator = Callable[[str, dict[str, Any]], ActionRecord]

PHASE = {
    "collect_evidence": "Detect", "analyze_blast_radius": "Investigate",
    "approve_isolation": "Contain", "isolate_device": "Contain", "approve_restriction": "Contain",
    "restrict_device": "Contain", "increase_monitoring": "Contain", "escalate": "Escalate",
    "verify_containment": "Verify", "verify_quiet": "Verify",
    "remediate_device": "Recover", "reset_credentials": "Recover", "restore_device": "Recover",
}
FINAL_STATUS = {ISOLATE: IncidentStatus.RESOLVED, MONITOR: IncidentStatus.RESOLVED,
                RESTRICT: IncidentStatus.CONTAINED, ESCALATE: IncidentStatus.ESCALATED}


@dataclass
class DecisionLog:
    id: int
    tick: int
    algorithm: str
    summary: str
    incident: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "tick": self.tick, "algorithm": self.algorithm, "summary": self.summary,
                "incident": self.incident, "data": self.data}


@dataclass
class _Runtime:
    incident: Incident
    device: str
    pstate: frozenset[str]
    plan: list[Action] = field(default_factory=list)
    index: int = 0
    needs_decision: bool = True
    under_attack: bool = False
    contained_tick: int | None = None
    wait_started: int | None = None

    @property
    def open(self) -> bool:
        return self.incident.closed_tick is None


class DefenseAgent:
    def __init__(self, manager: StateManager, actuator: Actuator | None = None, *,
                 rules: SecurityRules | None = None, act: bool = True, budget: int = DEFAULT_BUDGET):
        self.manager = manager
        self.actuator = actuator
        self.act = act and actuator is not None
        self.budget = budget
        self.rules = rules or load_security_rules()
        self.detector = ThreatDetector(self.rules)
        self.decisions: list[DecisionLog] = []
        self.peak_levels: dict[str, ThreatLevel] = {}
        self.last_flagged: dict[str, int] = {}
        self.cleared_at: dict[str, int] = {}
        self.runtimes: dict[str, _Runtime] = {}
        self.last_assessment: Assessment | None = None
        self._incident_seq = 0

    # ---- public ---------------------------------------------------------------
    @property
    def incidents(self) -> list[Incident]:
        return [rt.incident for rt in self.runtimes.values()]

    def incident_views(self) -> list[dict[str, Any]]:
        """Incidents plus plan progress, for the dashboard."""
        return [{**rt.incident.to_dict(), "plan_index": rt.index} for rt in self.runtimes.values()]

    def step(self, events: list[SecurityEvent]) -> list[DecisionLog]:
        tick = self.manager.tick
        first_log = len(self.decisions)
        for event in events:                                    # 1. perceive
            self.manager.record_event(event)
        assessment = self.detector.assess(self.manager.state, self.manager.event_log, tick, self.cleared_at)
        self.last_assessment = assessment                       # 2. reason
        if assessment.steps or any(l is not ThreatLevel.NORMAL for l in assessment.levels.values()):
            flagged = sum(1 for l in assessment.levels.values() if l is not ThreatLevel.NORMAL)
            self._log(tick, "Logic: forward chaining (Modus Ponens)",
                      f"{len(assessment.steps)} inference(s); {flagged} device(s) flagged", None, assessment.to_dict())
        self._update_beliefs(assessment, tick)                  # 3. update model
        self._track_incidents(assessment, tick)                 # 4. decide
        if self.act:
            pending = [rt for rt in self.runtimes.values() if rt.open and rt.needs_decision]
            if pending:
                self._decide(pending, tick)                     # 4-5. CSP + planning
            for rt in list(self.runtimes.values()):
                if rt.open and rt.plan:
                    self._execute(rt, tick)                     # 6-7. act + verify
        self.manager.advance_tick()
        return self.decisions[first_log:]

    # ---- beliefs & incidents ---------------------------------------------------------
    def _update_beliefs(self, a: Assessment, tick: int) -> None:
        for d, level in a.levels.items():
            if level is ThreatLevel.CRITICAL:
                self.manager.add_belief(("Compromised", d))
            self.manager.set_assessment(d, level, RISK[level])
            if level is not ThreatLevel.NORMAL:
                self.last_flagged[d] = tick
                if LEVEL_RANK[level] > LEVEL_RANK[self.peak_levels.get(d, ThreatLevel.NORMAL)]:
                    self.peak_levels[d] = level

    def _latest(self, device: str) -> _Runtime | None:
        found = [rt for rt in self.runtimes.values() if rt.device == device]
        return found[-1] if found else None

    def _track_incidents(self, a: Assessment, tick: int) -> None:
        state = self.manager.state
        for d, level in a.levels.items():
            device = state.devices[d]
            if level is ThreatLevel.NORMAL or device.type is DeviceType.EXTERNAL:
                continue
            rt = self._latest(d)
            under_attack = ("UnderAttack", d) in a.kb.facts
            if rt is None or rt.incident.status is IncidentStatus.RESOLVED:
                # A resolved incident stays closed; only new evidence after it opens a new one.
                if rt is not None and tick <= rt.incident.closed_tick:
                    continue
                if device.is_traversable:
                    self._open_incident(d, level, a, tick, under_attack)
            elif LEVEL_RANK[level] > LEVEL_RANK[rt.incident.level]:
                # Threat got worse: re-open (if it was settled) and decide again.
                rt.incident.level = level
                rt.incident.explanation = a.explanation(d)
                rt.incident.timeline.append(f"t={tick}: threat level raised to {level.value}")
                rt.incident.closed_tick = None
                rt.incident.status = IncidentStatus.OPEN
                rt.needs_decision = True
                rt.under_attack |= under_attack
            else:
                rt.under_attack |= under_attack

    def _open_incident(self, d: str, level: ThreatLevel, a: Assessment, tick: int, under_attack: bool) -> None:
        self._incident_seq += 1
        inc_id = f"INC-{self._incident_seq:03d}"
        incident = Incident(inc_id, tick, [d], level, explanation=a.explanation(d))
        incident.timeline.append(f"t={tick}: opened, {d} rated {level.value}")
        online = self.manager.state.devices[d].status is DeviceStatus.ONLINE
        self.runtimes[inc_id] = _Runtime(incident, d, initial_state(d, "", online, under_attack),
                                         under_attack=under_attack)
        self._log(tick, "Incident", f"{inc_id} opened for {d} ({level.value})", inc_id,
                  {"explanation": incident.explanation})

    # ---- CSP + planning -------------------------------------------------------------------
    def _decide(self, pending: list[_Runtime], tick: int) -> None:
        state = self.manager.state
        isolated = sum(1 for d in state.devices.values() if d.status is DeviceStatus.ISOLATED)
        budget_left = max(0, self.budget - isolated)
        csp = solve_isolation(state, budget=budget_left)
        verdict = (", ".join(f"{d}={v}" for d, v in csp.decisions.items()) if csp.solvable
                   else f"no safe assignment: {csp.result.failure}")
        self._log(tick, "CSP: isolation decision", verdict, None, csp.to_dict())

        for rt in pending:
            d = rt.device
            decision = (csp.decisions or {}).get(d, MONITOR) if csp.solvable else ESCALATE
            rt.incident.decision = decision
            rt.incident.timeline.append(f"t={tick}: CSP decision {decision}")
            facts = {f for f in rt.pstate if not f.startswith(("CSPAllows(", "Verified(", "Online(", "UnderAttack("))}
            if state.devices[d].status is DeviceStatus.ONLINE:
                facts.add(lit("Online", d))
            if decision != ESCALATE:
                facts.add(lit("CSPAllows", d, decision))
            if rt.under_attack:
                facts.add(lit("UnderAttack", d))
            rt.pstate = frozenset(facts)
            result = plan_incident(rt.pstate, d)
            rt.plan = result.plan or []
            rt.index = 0
            rt.needs_decision = False
            rt.incident.plan = [a.label for a in rt.plan]
            rt.incident.htn_tree = result.tree[0].lines() if result.tree else []
            data: dict[str, Any] = {"plan": [a.to_dict() for a in rt.plan], "tree": rt.incident.htn_tree,
                                    "trace": result.trace, "initial_state": sorted(rt.pstate)}
            if decision in (ISOLATE, RESTRICT):
                gs = goal_stack_plan(rt.pstate, {lit("Contained", d)}, actions_for(d))
                data["goal_stack"] = {"goal": f"Contained({d})", "plan": gs.labels, "trace": gs.trace}
            self._log(tick, "Planning: HTN + goal-stack",
                      f"{rt.incident.id}: {' -> '.join(a.name for a in rt.plan) or 'no plan'}", rt.incident.id, data)

    # ---- execution --------------------------------------------------------------------------
    def _execute(self, rt: _Runtime, tick: int) -> None:
        while rt.index < len(rt.plan):
            action = rt.plan[rt.index]
            rt.incident.phase = PHASE.get(action.name, rt.incident.phase)
            if action.name in WAIT_ACTIONS:
                if not self._verify(rt, action, tick):
                    return
            elif action.name in WORLD_ACTIONS:
                if not self._act(rt, action, tick):
                    self._close(rt, tick, IncidentStatus.ESCALATED, f"{action.label} failed; escalated")
                    return
            else:
                self._internal(rt, action, tick)
            rt.pstate = action.apply(rt.pstate)
            rt.index += 1
            if action.name in ("isolate_device", "restrict_device"):
                rt.contained_tick = tick
                rt.incident.status = IncidentStatus.CONTAINED
        self._close(rt, tick, FINAL_STATUS.get(rt.incident.decision or ESCALATE, IncidentStatus.ESCALATED),
                    "plan complete, goal reached")

    def _internal(self, rt: _Runtime, action: Action, tick: int) -> None:
        d, inc = rt.device, rt.incident
        if action.name == "collect_evidence":
            related = [e for e in self.manager.event_log if d in (e.source, e.target) and e.tick > tick - 10]
            inc.timeline.append(f"t={tick}: collected {len(related)} recent event(s) involving {d}")
        elif action.name == "analyze_blast_radius":
            result = investigate(self.manager.state, d)
            inc.timeline.append(f"t={tick}: investigation: {result.summary()}")
            self._log(tick, "Search: BFS, DFS, Greedy, A*", f"{d}: {result.summary()}", inc.id, result.to_dict())
        elif action.name in ("approve_isolation", "approve_restriction"):
            inc.timeline.append(f"t={tick}: {action.label}: CSP found it safe")
        elif action.name == "escalate":
            inc.timeline.append(f"t={tick}: escalated to a human analyst")

    def _act(self, rt: _Runtime, action: Action, tick: int) -> bool:
        d = rt.device
        params = {"device": d}
        if action.name == "increase_monitoring" and self.manager.state.devices[d].monitored:
            rt.incident.timeline.append(f"t={tick}: {d} already monitored")
            return True
        record = self.actuator(action.name, params)
        record.tick = tick
        rt.incident.actions_taken.append(record)
        if not record.success:
            rt.incident.timeline.append(f"t={tick}: {action.label} FAILED: {record.message}")
            return False
        try:
            execute_action(self.manager, action.name, params)  # mirror the known effect in the model
        except ActionError as exc:
            rt.incident.timeline.append(f"t={tick}: model out of sync: {exc}")
            return False
        rt.incident.timeline.append(f"t={tick}: {action.label} (simulated)")
        self._log(tick, "Action (simulated)", f"{rt.incident.id}: {action.label}", rt.incident.id, record.to_dict())
        if action.name == "restore_device":
            self.manager.remove_belief(("Compromised", d))
            self.manager.set_assessment(d, ThreatLevel.NORMAL, 0.0)
            self.cleared_at[d] = tick
        return True

    def _verify(self, rt: _Runtime, action: Action, tick: int) -> bool:
        d, inc = rt.device, rt.incident
        if rt.wait_started is None:
            rt.wait_started = tick
        if action.name == "verify_containment":
            result = check_containment(d, rt.contained_tick, tick, self.manager.event_log, self.rules)
            if result.status == "pending":
                return False
            inc.verification = result.lines
            self._log(tick, "Verification: Modus Tollens", f"{inc.id}: containment {result.status}", inc.id,
                      {"lines": result.lines})
            if result.status == "failed":
                self._close(rt, tick, IncidentStatus.ESCALATED, "verification failed")
                return False
        else:  # verify_quiet
            quiet_for = tick - self.last_flagged.get(d, -1)
            if quiet_for < self.rules.quiet_ticks or tick <= rt.wait_started:
                return False
            inc.verification = [f"No new evidence about {d} for {quiet_for} tick(s) "
                                f"(last flagged at t={self.last_flagged.get(d)})"]
            self._log(tick, "Verification: quiet period", f"{inc.id}: {d} quiet", inc.id,
                      {"lines": inc.verification})
        inc.verified = True
        inc.timeline.append(f"t={tick}: verified")
        rt.wait_started = None
        return True

    def _close(self, rt: _Runtime, tick: int, status: IncidentStatus, note: str) -> None:
        rt.incident.status = status
        rt.incident.closed_tick = tick
        rt.incident.phase = "Done"
        rt.incident.timeline.append(f"t={tick}: {status.value}: {note}")
        self._log(tick, "Incident", f"{rt.incident.id} {status.value}", rt.incident.id, {"note": note})

    def _log(self, tick: int, algorithm: str, summary: str, incident: str | None, data: dict[str, Any]) -> None:
        self.decisions.append(DecisionLog(len(self.decisions) + 1, tick, algorithm, summary, incident, data))
