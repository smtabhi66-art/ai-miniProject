"""Generic constraint satisfaction problem (CSP) representation.

A CSP is a triple (X, D, C):

    X  variables             e.g. one per suspicious device
    D  an ordered domain     e.g. [ISOLATE, RESTRICT, MONITOR]
       per variable
    C  constraints           each with a *scope*: the variables it mentions

Every constraint can be checked on a *partial* assignment. ``consistent()``
returns False only when the constraint is already certainly violated:

* unary and binary constraints wait until all their variables are assigned;
* the global constraints used in this project are *monotone* (assigning more
  ISOLATE values can only make them worse), so checking them early is sound
  and lets forward checking prune sooner.

Binary constraints also keep their ``relation`` so AC-3 can reason about arcs.
"""
from dataclasses import dataclass
from typing import Callable, Hashable, Iterable, Mapping

Value = Hashable
Assignment = Mapping[str, Value]


@dataclass(frozen=True)
class Constraint:
    name: str
    scope: tuple[str, ...]
    check: Callable[[Assignment], bool]  # receives only the assigned variables of the scope
    description: str = ""
    relation: Callable[[Value, Value], bool] | None = None  # binary only: relation(x_value, y_value)

    @property
    def arity(self) -> int:
        return len(self.scope)

    def consistent(self, assignment: Assignment) -> bool:
        return self.check({v: assignment[v] for v in self.scope if v in assignment})


def unary(name: str, var: str, allowed: Callable[[Value], bool], description: str = "") -> Constraint:
    return Constraint(name, (var,), lambda a: var not in a or allowed(a[var]), description)


def binary(name: str, x: str, y: str, relation: Callable[[Value, Value], bool],
           description: str = "") -> Constraint:
    return Constraint(name, (x, y), lambda a: x not in a or y not in a or relation(a[x], a[y]),
                      description, relation)


def global_constraint(name: str, scope: Iterable[str], check: Callable[[Assignment], bool],
                      description: str = "") -> Constraint:
    return Constraint(name, tuple(scope), check, description)


class CSP:
    def __init__(self, variables: Iterable[str], domains: Mapping[str, Iterable[Value]],
                 constraints: Iterable[Constraint]):
        self.variables = list(variables)
        if len(set(self.variables)) != len(self.variables):
            raise ValueError("duplicate variables")
        missing = [v for v in self.variables if v not in domains]
        if missing:
            raise ValueError(f"no domain for: {', '.join(missing)}")
        self.domains = {v: list(domains[v]) for v in self.variables}
        self.constraints = list(constraints)
        self._by_var: dict[str, list[Constraint]] = {v: [] for v in self.variables}
        for c in self.constraints:
            for v in c.scope:
                if v not in self._by_var:
                    raise ValueError(f"constraint {c.name} uses unknown variable {v}")
                self._by_var[v].append(c)

    def constraints_on(self, var: str) -> list[Constraint]:
        return self._by_var[var]

    def neighbors(self, var: str) -> set[str]:
        """Variables that share at least one constraint with ``var``."""
        return {u for c in self._by_var[var] for u in c.scope if u != var}

    def first_violation(self, var: str, value: Value, assignment: Assignment) -> Constraint | None:
        """The first constraint broken by adding ``var = value``, or None if consistent."""
        trial = {**assignment, var: value}
        for c in self._by_var[var]:
            if not c.consistent(trial):
                return c
        return None

    def is_solution(self, assignment: Assignment) -> bool:
        return (all(v in assignment for v in self.variables)
                and all(c.consistent(assignment) for c in self.constraints))
