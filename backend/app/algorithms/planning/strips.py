"""STRIPS representation: states, actions, preconditions and effects.

A planning *state* is a set of ground literals, written as strings such as
``"Compromised(WS2)"``. Anything not in the set is false (closed world).

An action has
    pre     literals that must all be true before it runs
    add     literals it makes true
    delete  literals it makes false

    applicable(s)  <=>  pre ⊆ s
    apply(s)        =   (s - delete) ∪ add

A *plan* is a sequence of actions. It is valid if each action is applicable
in the state produced by the ones before it, and the final state contains
every goal literal.
"""
from dataclasses import dataclass, field
from typing import Iterable

State = frozenset[str]


def lit(predicate: str, *args: str) -> str:
    return f"{predicate}({', '.join(args)})"


@dataclass(frozen=True)
class Action:
    name: str
    args: tuple[str, ...]
    pre: frozenset[str]
    add: frozenset[str]
    delete: frozenset[str] = frozenset()
    description: str = ""

    @classmethod
    def make(cls, name: str, args: Iterable[str], pre: Iterable[str], add: Iterable[str],
             delete: Iterable[str] = (), description: str = "") -> "Action":
        return cls(name, tuple(args), frozenset(pre), frozenset(add), frozenset(delete), description)

    @property
    def label(self) -> str:
        return f"{self.name}({', '.join(self.args)})"

    def applicable(self, state: Iterable[str]) -> bool:
        return self.pre <= frozenset(state)

    def apply(self, state: Iterable[str]) -> State:
        s = frozenset(state)
        if not self.pre <= s:
            missing = ", ".join(sorted(self.pre - s))
            raise ValueError(f"{self.label} not applicable: missing {missing}")
        return (s - self.delete) | self.add

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "pre": sorted(self.pre),
            "add": sorted(self.add),
            "delete": sorted(self.delete),
            "description": self.description,
        }


@dataclass
class PlanResult:
    algorithm: str
    plan: list[Action] | None
    trace: list[str] = field(default_factory=list)
    explored: int = 0
    failure: str | None = None

    @property
    def found(self) -> bool:
        return self.plan is not None

    @property
    def labels(self) -> list[str]:
        return [a.label for a in self.plan or []]


def validate_plan(initial: Iterable[str], plan: list[Action], goal: Iterable[str]) -> tuple[bool, str, State]:
    """Simulate the plan step by step. Returns (ok, message, final_state)."""
    state = frozenset(initial)
    for i, action in enumerate(plan, 1):
        if not action.applicable(state):
            missing = ", ".join(sorted(action.pre - state))
            return False, f"step {i} {action.label}: missing {missing}", state
        state = action.apply(state)
    unmet = frozenset(goal) - state
    if unmet:
        return False, f"goal not reached: {', '.join(sorted(unmet))}", state
    return True, "valid", state


def relaxed_reachable(state: Iterable[str], actions: Iterable[Action]) -> frozenset[str]:
    """Every literal reachable if delete lists are ignored (a cheap over-approximation).

    If a literal is NOT in this set, no plan can ever achieve it.
    """
    reached = set(state)
    acts = list(actions)
    changed = True
    while changed:
        changed = False
        for a in acts:
            if a.pre <= reached and not a.add <= reached:
                reached |= a.add
                changed = True
    return frozenset(reached)
