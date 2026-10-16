"""Constraint propagation: shrink domains *before* or *during* search.

node_consistency   Remove values that break a unary constraint.
                   O(n·d).
ac3                Arc consistency for binary constraints: for every arc (Xi, Xj),
                   every value of Xi must have at least one supporting value in Xj.
                   O(e·d³) for e binary constraints and domain size d.
forward_check      After assigning X = v, remove from each unassigned neighbour
                   the values that conflict with X = v (and the assignment so far).
                   An empty domain means a dead end, detected *before* going deeper.
                   O(e·d) per assignment.

All three log every removed value (variable, value, constraint), so the dashboard
can show *why* an option disappeared.
"""
from collections import deque
from dataclasses import dataclass

from app.algorithms.csp.csp import CSP, Assignment, Constraint, Value

Domains = dict[str, list[Value]]


@dataclass(frozen=True)
class Pruning:
    var: str
    value: Value
    constraint: str
    stage: str  # "node", "ac3" or "forward-check"

    def __str__(self) -> str:
        return f"{self.var} != {self.value}  ({self.constraint}, {self.stage})"


def copy_domains(domains: Domains) -> Domains:
    return {v: list(d) for v, d in domains.items()}


def node_consistency(csp: CSP, domains: Domains) -> list[Pruning]:
    """Apply unary constraints in place."""
    log = []
    for c in csp.constraints:
        if c.arity != 1:
            continue
        var = c.scope[0]
        kept = []
        for value in domains[var]:
            if c.consistent({var: value}):
                kept.append(value)
            else:
                log.append(Pruning(var, value, c.name, "node"))
        domains[var] = kept
    return log


def _revise(c: Constraint, xi: str, xj: str, domains: Domains) -> list[Value]:
    """Remove values of xi with no support in xj under binary constraint c."""
    forward = c.scope == (xi, xj)

    def ok(x: Value, y: Value) -> bool:
        return c.relation(x, y) if forward else c.relation(y, x)

    removed = [x for x in domains[xi] if not any(ok(x, y) for y in domains[xj])]
    if removed:
        domains[xi] = [x for x in domains[xi] if x not in removed]
    return removed


def ac3(csp: CSP, domains: Domains) -> tuple[bool, list[Pruning]]:
    """Make all binary constraints arc-consistent in place. False if a domain empties."""
    binary = [c for c in csp.constraints if c.relation is not None]
    queue = deque()
    for c in binary:
        x, y = c.scope
        queue.append((x, y, c))
        queue.append((y, x, c))
    log = []
    while queue:
        xi, xj, c = queue.popleft()
        removed = _revise(c, xi, xj, domains)
        if not removed:
            continue
        log.extend(Pruning(xi, value, c.name, "ac3") for value in removed)
        if not domains[xi]:
            return False, log
        # xi lost values, so arcs pointing at xi must be rechecked.
        for c2 in binary:
            if xi in c2.scope and c2 is not c:
                other = c2.scope[0] if c2.scope[1] == xi else c2.scope[1]
                queue.append((other, xi, c2))
    return True, log


def forward_check(csp: CSP, var: str, value: Value, assignment: Assignment,
                  domains: Domains) -> tuple[bool, Domains, list[Pruning]]:
    """Return (ok, new_domains, pruned) after tentatively assigning ``var = value``."""
    new = copy_domains(domains)
    new[var] = [value]
    trial = {**assignment, var: value}
    log = []
    for c in csp.constraints_on(var):
        for u in c.scope:
            if u == var or u in assignment:
                continue
            kept = []
            for w in new[u]:
                if c.consistent({**trial, u: w}):
                    kept.append(w)
                else:
                    log.append(Pruning(u, w, c.name, "forward-check"))
            new[u] = kept
            if not kept:
                return False, new, log
    return True, new, log
