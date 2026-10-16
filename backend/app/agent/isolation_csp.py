"""Safe isolation as a constraint satisfaction problem.

Question: for each device the agent distrusts, should it be ISOLATED,
RESTRICTED or only MONITORED, without breaking the business?

Variables
    One per internal device rated Suspicious or Critical that is still connected.

Domain (ordered by preference: the solver tries values in this order)
    Critical device:   ISOLATE, RESTRICT, MONITOR    (contain first)
    Suspicious device: MONITOR, RESTRICT, ISOLATE    (disrupt least first)

    ISOLATE   cut off completely
    RESTRICT  keep only its service traffic; block anything else outbound
    MONITOR   stay connected with detailed logging

Constraints
    C1 restrict_needs_service    (unary)   no hosted service    =>  X != RESTRICT
    C2 contain_compromised       (unary)   rated Critical       =>  X != MONITOR
    C3 keep_sole_critical_host   (unary)   last available host of a critical service  =>  X != ISOLATE
    C4 keep_one_replica          (binary)  the two remaining hosts of a critical service
                                           may not both be ISOLATED (n-ary if more than two)
    C5 admin_can_reach_services  (global)  the admin workstation can still reach every
                                           critical-service host it reaches now (recovery path)
    C6 isolation_budget          (global)  at most ``budget`` devices ISOLATED

If no assignment satisfies every constraint, the agent must not act on its own:
it escalates the incident.
"""
from dataclasses import dataclass
from typing import Any

from app.algorithms.csp.backtracking import CSPResult, backtracking_search
from app.algorithms.csp.csp import CSP, Assignment, Constraint, binary, global_constraint, unary
from app.algorithms.search.bfs import bfs_reachable
from app.algorithms.search.graph import Graph, graph_from_network
from app.models.enums import DeviceType, ThreatLevel
from app.models.network import NetworkState

ISOLATE = "ISOLATE"
RESTRICT = "RESTRICT"
MONITOR = "MONITOR"
PREFERENCE = {
    ThreatLevel.CRITICAL: [ISOLATE, RESTRICT, MONITOR],
    ThreatLevel.SUSPICIOUS: [MONITOR, RESTRICT, ISOLATE],
}
DEFAULT_BUDGET = 2


@dataclass
class IsolationResult:
    suspects: dict[str, ThreatLevel]
    csp: CSP
    result: CSPResult

    @property
    def solvable(self) -> bool:
        return self.result.solved

    @property
    def decisions(self) -> dict[str, str] | None:
        return self.result.solution

    def to_dict(self) -> dict[str, Any]:
        return {
            "suspects": {d: lvl.value for d, lvl in self.suspects.items()},
            "variables": self.csp.variables,
            "initial_domains": self.csp.domains,
            "constraints": [{"name": c.name, "scope": list(c.scope), "description": c.description}
                            for c in self.csp.constraints],
            "preprocessing": [str(p) for p in self.result.preprocessing],
            "domains_after_preprocessing": self.result.domains_after_preprocessing,
            "solvable": self.solvable,
            "decisions": self.decisions,
            "failure": self.result.failure,
            "conflicts": self.result.conflicts,
            "stats": vars(self.result.stats),
            "trace": [s.to_dict() for s in self.result.trace],
        }


def current_suspects(state: NetworkState) -> dict[str, ThreatLevel]:
    """Internal, still-connected devices the agent rates Suspicious or Critical."""
    return {
        d.id: d.threat_level
        for d in state.devices.values()
        if d.threat_level is not ThreatLevel.NORMAL
        and d.type is not DeviceType.EXTERNAL
        and d.is_traversable
    }


def build_isolation_csp(state: NetworkState, suspects: dict[str, ThreatLevel] | None = None,
                        budget: int = DEFAULT_BUDGET) -> CSP:
    suspects = current_suspects(state) if suspects is None else dict(suspects)
    for device_id in suspects:
        if device_id not in state.devices:
            raise KeyError(f"unknown device: {device_id}")
    if budget < 0:
        raise ValueError("budget must be >= 0")

    variables = sorted(suspects)
    domains = {v: list(PREFERENCE[suspects[v]]) for v in variables}
    constraints: list[Constraint] = []

    for v in variables:
        device = state.devices[v]
        if not device.services:
            constraints.append(unary(
                "restrict_needs_service", v, lambda x: x != RESTRICT,
                f"{v} hosts no service, so there is no service traffic to keep: RESTRICT is meaningless"))
        if suspects[v] is ThreatLevel.CRITICAL:
            constraints.append(unary(
                "contain_compromised", v, lambda x: x != MONITOR,
                f"{v} is rated Critical: only watching it is not enough"))

    for service in state.services.values():
        if not service.critical:
            continue
        available = [h for h in service.hosts if state.devices[h].is_traversable]
        if any(h not in suspects for h in available):
            continue  # an untouched host keeps the service alive
        if len(available) == 1:
            host = available[0]
            constraints.append(unary(
                "keep_sole_critical_host", host, lambda x: x != ISOLATE,
                f"{host} is the only available host of critical service '{service.name}'"))
        elif len(available) == 2:
            a, b = available
            constraints.append(binary(
                "keep_one_replica", a, b, lambda x, y: not (x == ISOLATE and y == ISOLATE),
                f"'{service.name}' needs {a} or {b}: they cannot both be isolated"))
        elif len(available) > 2:
            hosts = tuple(available)
            constraints.append(global_constraint(
                "keep_one_replica", hosts,
                lambda a, hosts=hosts: not (len(a) == len(hosts) and all(x == ISOLATE for x in a.values())),
                f"'{service.name}' needs at least one of {', '.join(hosts)}"))

    admin = state.metadata.get("admin_device")
    if variables and admin in state.devices and state.devices[admin].is_traversable:
        constraints.append(_connectivity_constraint(state, admin, variables))

    if variables:
        constraints.append(global_constraint(
            "isolation_budget", variables,
            lambda a: sum(1 for x in a.values() if x == ISOLATE) <= budget,
            f"at most {budget} device(s) may be isolated at once"))

    return CSP(variables, domains, constraints)


def _connectivity_constraint(state: NetworkState, admin: str, variables: list[str]) -> Constraint:
    base = graph_from_network(state)
    critical_hosts = {h for s in state.services.values() if s.critical for h in s.hosts}
    required = critical_hosts & set(bfs_reachable(base, admin).depth)  # don't demand what's already lost

    def check(a: Assignment) -> bool:
        isolated = {v for v, x in a.items() if x == ISOLATE}
        if admin in isolated:
            return False
        reach = set(bfs_reachable(_without(base, isolated), admin).depth)
        return all(h in reach for h in required - isolated)

    return global_constraint(
        "admin_can_reach_services", variables, check,
        f"{admin} must keep a path to every critical-service host it can reach now (recovery path)")


def _without(graph: Graph, removed: set[str]) -> Graph:
    edges = ((a, b, c) for a in graph.nodes for b, c in graph.adjacency[a].items()
             if a < b and a not in removed and b not in removed)
    return Graph.from_edges(edges, nodes=graph.nodes)


def solve_isolation(state: NetworkState, suspects: dict[str, ThreatLevel] | None = None,
                    budget: int = DEFAULT_BUDGET) -> IsolationResult:
    """Backtracking with MRV, forward checking and AC-3.

    LCV is turned off on purpose: the domain order *is* the security preference
    (contain Critical devices first, disturb Suspicious ones least), and LCV
    would reorder it to "least constraining" instead.
    """
    suspects = current_suspects(state) if suspects is None else dict(suspects)
    csp = build_isolation_csp(state, suspects, budget)
    result = backtracking_search(csp, mrv=True, lcv=False, forward_checking=True, ac3_preprocess=True)
    return IsolationResult(suspects, csp, result)
