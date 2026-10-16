"""Incident-response planning domain: STRIPS actions plus HTN methods.

Primitive actions for a device d (pre -> add / delete):

    collect_evidence(d)      Detected(d)                                -> EvidenceCollected(d)
    analyze_blast_radius(d)  EvidenceCollected(d)                       -> Investigated(d)
    approve_isolation(d)     Investigated(d), CSPAllows(d, ISOLATE)     -> IsolationApproved(d)
    isolate_device(d)        IsolationApproved(d), Online(d)            -> Isolated(d), Contained(d) / Online(d)
    approve_restriction(d)   Investigated(d), CSPAllows(d, RESTRICT)    -> RestrictionApproved(d)
    restrict_device(d)       RestrictionApproved(d), Online(d)          -> Restricted(d), Contained(d) / Online(d)
    increase_monitoring(d)   EvidenceCollected(d)                       -> Monitored(d)
    verify_containment(d)    Contained(d)                               -> Verified(d)
    verify_quiet(d)          Monitored(d)                               -> Verified(d)
    remediate_device(d)      Isolated(d), Verified(d)                   -> Clean(d)
    reset_credentials(d)     Verified(d)                                -> CredentialsReset(d)
    restore_device(d)        Isolated(d), Clean(d), CredentialsReset(d) -> Online(d), Recovered(d) / Isolated(d)
    escalate(d)              Detected(d)                                -> Escalated(d)

HTN methods:

    HandleIncident  full:    Detect, Investigate, Contain, Verify, Recover
                    resume:  Contain, Verify, Recover   (already investigated, e.g. after escalation)
    Contain         by_goal_stack:  goal-stack planner achieves Contained(d)  (CSP allowed isolate/restrict)
                    monitor:        increase_monitoring                        (CSP said MONITOR)
                    escalate:       escalate, increase_monitoring              (no safe option)
    Verify          containment / quiet / nothing (escalated)
    Recover         isolated:   remediate_device, reset_credentials, restore_device
                    restricted: reset_credentials, escalate (needs a maintenance window)
                    attacked:   reset_credentials (monitored device that was under attack)
                    none
"""
from app.agent.isolation_csp import ISOLATE, MONITOR, RESTRICT
from app.algorithms.planning.goal_stack import goal_stack_plan
from app.algorithms.planning.hierarchical import HTNDomain, HTNResult, Method, htn_plan
from app.algorithms.planning.strips import Action, State, lit

ESCALATE = "ESCALATE"

# Actions that change the simulated world; the rest are the agent's own internal steps.
WORLD_ACTIONS = {"isolate_device", "restrict_device", "increase_monitoring",
                 "remediate_device", "reset_credentials", "restore_device"}
# Steps that need observations over the following ticks before they can complete.
WAIT_ACTIONS = {"verify_containment", "verify_quiet"}


def L(pred: str, d: str, *more: str) -> str:
    return lit(pred, d, *more)


def make_action(name: str, d: str) -> Action:
    spec = {
        "collect_evidence": ([L("Detected", d)], [L("EvidenceCollected", d)], [],
                             "Gather the events and facts about the device"),
        "analyze_blast_radius": ([L("EvidenceCollected", d)], [L("Investigated", d)], [],
                                 "BFS blast radius, DFS attack paths, Greedy lead, A* safe route"),
        "approve_isolation": ([L("Investigated", d), L("CSPAllows", d, ISOLATE)], [L("IsolationApproved", d)], [],
                              "The CSP found isolation safe"),
        "isolate_device": ([L("IsolationApproved", d), L("Online", d)], [L("Isolated", d), L("Contained", d)],
                           [L("Online", d)], "Cut the device off (simulated)"),
        "approve_restriction": ([L("Investigated", d), L("CSPAllows", d, RESTRICT)], [L("RestrictionApproved", d)],
                                [], "The CSP chose restriction"),
        "restrict_device": ([L("RestrictionApproved", d), L("Online", d)], [L("Restricted", d), L("Contained", d)],
                            [L("Online", d)], "Allow only service traffic (simulated)"),
        "increase_monitoring": ([L("EvidenceCollected", d)], [L("Monitored", d)], [], "Enable detailed logging"),
        "verify_containment": ([L("Contained", d)], [L("Verified", d)], [],
                               "Observe: malicious activity must stop (Modus Tollens check)"),
        "verify_quiet": ([L("Monitored", d)], [L("Verified", d)], [], "Observe: no new evidence for a while"),
        "remediate_device": ([L("Isolated", d), L("Verified", d)], [L("Clean", d)], [], "Clean the device (simulated)"),
        "reset_credentials": ([L("Verified", d)], [L("CredentialsReset", d)], [], "Reset passwords/keys (simulated)"),
        "restore_device": ([L("Isolated", d), L("Clean", d), L("CredentialsReset", d)],
                           [L("Online", d), L("Recovered", d)], [L("Isolated", d)], "Reconnect the cleaned device"),
        "escalate": ([L("Detected", d)], [L("Escalated", d)], [], "Hand over to a human analyst"),
    }
    if name not in spec:
        raise KeyError(f"unknown planning action: {name}")
    pre, add, delete, description = spec[name]
    return Action.make(name, [d], pre, add, delete, description)


ACTION_NAMES = ["collect_evidence", "analyze_blast_radius", "approve_isolation", "isolate_device",
                "approve_restriction", "restrict_device", "increase_monitoring", "verify_containment",
                "verify_quiet", "remediate_device", "reset_credentials", "restore_device", "escalate"]


def actions_for(d: str) -> list[Action]:
    return [make_action(n, d) for n in ACTION_NAMES]


def initial_state(d: str, decision: str, online: bool = True, under_attack: bool = False) -> State:
    facts = {L("Detected", d)}
    if online:
        facts.add(L("Online", d))
    if decision in (ISOLATE, RESTRICT, MONITOR):
        facts.add(L("CSPAllows", d, decision))
    if under_attack:
        facts.add(L("UnderAttack", d))
    return frozenset(facts)


def goal_for(d: str, decision: str) -> frozenset[str]:
    """What 'incident handled' means for each containment decision."""
    return frozenset({
        ISOLATE: [L("Verified", d), L("Recovered", d)],
        RESTRICT: [L("Verified", d), L("CredentialsReset", d), L("Escalated", d)],
        MONITOR: [L("Verified", d), L("Monitored", d)],
        ESCALATE: [L("Escalated", d), L("Monitored", d)],
    }[decision])


# ---- HTN methods -------------------------------------------------------------------
def _has(state: State, pred: str, d: str, *more: str) -> bool:
    return L(pred, d, *more) in state


def _contain_by_goal_stack(state: State, args: tuple[str, ...]):
    (d,) = args
    result = goal_stack_plan(state, {L("Contained", d)}, actions_for(d))
    return [(a.name, d) for a in result.plan] if result.found else None


def build_domain() -> HTNDomain:
    primitives = {name: (lambda d, name=name: make_action(name, d)) for name in ACTION_NAMES}
    always = lambda s, a: True
    methods = {
        "HandleIncident": [
            Method("full", "HandleIncident", lambda s, a: not _has(s, "Investigated", *a),
                   lambda s, a: [("Detect", *a), ("Investigate", *a), ("Contain", *a), ("Verify", *a), ("Recover", *a)],
                   "Detect -> Investigate -> Contain -> Verify -> Recover"),
            Method("resume", "HandleIncident", lambda s, a: _has(s, "Investigated", *a),
                   lambda s, a: [("Contain", *a), ("Verify", *a), ("Recover", *a)],
                   "Already investigated (e.g. threat level rose): contain, verify, recover"),
        ],
        "Detect": [Method("collect", "Detect", always, lambda s, a: [("collect_evidence", *a)])],
        "Investigate": [Method("analyze", "Investigate", always, lambda s, a: [("analyze_blast_radius", *a)])],
        "Contain": [
            Method("already_contained", "Contain", lambda s, a: _has(s, "Contained", *a), lambda s, a: [],
                   "Nothing to do"),
            Method("by_goal_stack", "Contain",
                   lambda s, a: _has(s, "CSPAllows", *a, ISOLATE) or _has(s, "CSPAllows", *a, RESTRICT),
                   _contain_by_goal_stack, "Goal-stack planner achieves Contained(d)"),
            Method("monitor", "Contain", lambda s, a: _has(s, "CSPAllows", *a, MONITOR),
                   lambda s, a: [] if _has(s, "Monitored", *a) else [("increase_monitoring", *a)],
                   "CSP chose MONITOR"),
            Method("escalate", "Contain", always,
                   lambda s, a: [("escalate", *a)] + ([] if _has(s, "Monitored", *a) else [("increase_monitoring", *a)]),
                   "No safe containment exists: hand over to a human"),
        ],
        "Verify": [
            Method("containment", "Verify", lambda s, a: _has(s, "Contained", *a),
                   lambda s, a: [("verify_containment", *a)]),
            Method("quiet", "Verify", lambda s, a: _has(s, "Monitored", *a) and not _has(s, "Escalated", *a),
                   lambda s, a: [("verify_quiet", *a)]),
            Method("nothing", "Verify", always, lambda s, a: []),
        ],
        "Recover": [
            Method("isolated", "Recover", lambda s, a: _has(s, "Isolated", *a),
                   lambda s, a: [("remediate_device", *a), ("reset_credentials", *a), ("restore_device", *a)]),
            Method("restricted", "Recover", lambda s, a: _has(s, "Restricted", *a),
                   lambda s, a: [("reset_credentials", *a), ("escalate", *a)],
                   "Sole critical host: keep restricted, reset credentials, schedule maintenance"),
            Method("attacked", "Recover", lambda s, a: _has(s, "UnderAttack", *a) and _has(s, "Verified", *a),
                   lambda s, a: [("reset_credentials", *a)]),
            Method("none", "Recover", always, lambda s, a: []),
        ],
    }
    return HTNDomain(primitives, methods)


DOMAIN = build_domain()


def plan_incident(state: State, d: str) -> HTNResult:
    return htn_plan(DOMAIN, state, [("HandleIncident", d)])
