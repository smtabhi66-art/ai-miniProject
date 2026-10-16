"""Backtracking search for CSPs, with heuristics and propagation.

Algorithm
    1. Preprocess: node consistency, then AC-3 (optional).
    2. backtrack(assignment, domains):
         if every variable is assigned: return assignment
         var := select_unassigned_variable()      (MRV + degree tie-break)
         for value in order_domain_values(var):   (LCV, or the domain's own order)
             if var = value breaks no constraint:
                 forward-check (optional); skip if a neighbour's domain empties
                 result := backtrack(assignment + {var: value}, pruned domains)
                 if result: return result
             undo and try the next value             <- backtracking
         return failure

Heuristics
    MRV (minimum remaining values): pick the variable with the fewest values
        left, so it fails fast. Ties: the variable in the most constraints
        with unassigned variables (degree heuristic).
    LCV (least constraining value): try first the value that removes the
        fewest options from neighbours, to leave room for a solution.

Complexity
    Worst case O(d^n) for n variables with domain size d (the search tree).
    Propagation and heuristics do not change the worst case but prune
    dramatically in practice (see the N-Queens comparison in the tests).
"""
from dataclasses import dataclass, field
from typing import Any

from app.algorithms.csp.csp import CSP, Value
from app.algorithms.csp.propagation import (
    Domains,
    Pruning,
    ac3,
    copy_domains,
    forward_check,
    node_consistency,
)


@dataclass
class SolverStats:
    assignments: int = 0
    backtracks: int = 0
    pruned: int = 0  # values removed by forward checking during search


@dataclass
class CSPStep:
    step: int
    action: str  # "assign", "reject", "fc-fail", "backtrack", "solution"
    var: str | None
    value: Value | None
    detail: str
    domains: dict[str, list[Value]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "action": self.action,
            "var": self.var,
            "value": self.value,
            "detail": self.detail,
            "domains": self.domains,
        }


@dataclass
class CSPResult:
    solution: dict[str, Value] | None
    stats: SolverStats
    preprocessing: list[Pruning]
    domains_after_preprocessing: Domains
    trace: list[CSPStep] = field(default_factory=list)
    failure: str | None = None
    conflicts: dict[str, int] = field(default_factory=dict)  # constraint -> times it blocked a value
    trace_truncated: bool = False

    @property
    def solved(self) -> bool:
        return self.solution is not None


def select_unassigned_variable(csp: CSP, assignment: dict, domains: Domains, mrv: bool) -> str:
    unassigned = [v for v in csp.variables if v not in assignment]
    if not mrv:
        return unassigned[0]

    def degree(v: str) -> int:
        return sum(1 for u in csp.neighbors(v) if u not in assignment)

    return min(unassigned, key=lambda v: (len(domains[v]), -degree(v), csp.variables.index(v)))


def order_domain_values(csp: CSP, var: str, assignment: dict, domains: Domains, lcv: bool) -> list[Value]:
    if not lcv:
        return list(domains[var])

    def ruled_out(value: Value) -> int:
        count = 0
        trial = {**assignment, var: value}
        for u in csp.neighbors(var):
            if u in assignment:
                continue
            shared = [c for c in csp.constraints_on(var) if u in c.scope]
            count += sum(1 for w in domains[u]
                         if not all(c.consistent({**trial, u: w}) for c in shared))
        return count

    return sorted(domains[var], key=ruled_out)  # stable: ties keep the domain's order


def backtracking_search(csp: CSP, *, mrv: bool = True, lcv: bool = True, forward_checking: bool = True,
                        ac3_preprocess: bool = True, max_trace: int = 2000) -> CSPResult:
    domains = copy_domains(csp.domains)
    pre = node_consistency(csp, domains)
    if ac3_preprocess:
        _, ac3_log = ac3(csp, domains)
        pre += ac3_log
    after = copy_domains(domains)
    result = CSPResult(None, SolverStats(), pre, after)

    def log(action: str, var: str | None, value: Value | None, detail: str, doms: Domains | None = None) -> None:
        if len(result.trace) >= max_trace:
            result.trace_truncated = True
            return
        result.trace.append(CSPStep(len(result.trace) + 1, action, var, value, detail,
                                    copy_domains(doms) if doms is not None else None))

    def blame(name: str) -> None:
        result.conflicts[name] = result.conflicts.get(name, 0) + 1

    empty = [v for v in csp.variables if not domains[v]]
    if empty:
        var = empty[0]
        causes = sorted({p.constraint for p in pre if p.var == var})
        for name in causes:
            blame(name)
        result.failure = f"{var} has no allowed value left after preprocessing (removed by: {', '.join(causes)})"
        return result

    def backtrack(assignment: dict, doms: Domains) -> dict | None:
        if len(assignment) == len(csp.variables):
            return dict(assignment)
        var = select_unassigned_variable(csp, assignment, doms, mrv)
        for value in order_domain_values(csp, var, assignment, doms, lcv):
            violated = csp.first_violation(var, value, assignment)
            if violated is not None:
                blame(violated.name)
                log("reject", var, value, f"violates {violated.name}")
                continue
            if forward_checking:
                ok, new_doms, pruned = forward_check(csp, var, value, assignment, doms)
                result.stats.pruned += len(pruned)
                if not ok:
                    blame(pruned[-1].constraint)
                    log("fc-fail", var, value,
                        f"forward checking emptied {pruned[-1].var}'s domain ({pruned[-1].constraint})", new_doms)
                    continue
            else:
                new_doms = copy_domains(doms)
                new_doms[var] = [value]
            assignment[var] = value
            result.stats.assignments += 1
            detail = "assign"
            if forward_checking and pruned:
                detail += "; pruned " + ", ".join(f"{p.var}!={p.value}" for p in pruned)
            log("assign", var, value, detail, new_doms)
            found = backtrack(assignment, new_doms)
            if found is not None:
                return found
            del assignment[var]
            result.stats.backtracks += 1
            log("backtrack", var, value, f"undo {var}={value}")
        return None

    solution = backtrack({}, domains)
    if solution is None:
        result.failure = "no assignment satisfies every constraint"
    else:
        result.solution = solution
        log("solution", None, None, ", ".join(f"{k}={v}" for k, v in solution.items()))
    return result
