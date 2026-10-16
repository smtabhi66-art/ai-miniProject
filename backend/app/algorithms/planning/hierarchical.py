"""Hierarchical task network (HTN) planning, with ordered task decomposition.

Instead of searching over every primitive action, the planner refines
high-level *tasks* using *methods*:

    HandleIncident(WS2)
      ├─ Detect(WS2)      -> collect_evidence(WS2)
      ├─ Investigate(WS2) -> analyze_blast_radius(WS2)
      ├─ Contain(WS2)     -> (method chosen by state: isolate / restrict / monitor / escalate)
      ├─ Verify(WS2)      -> verify_containment(WS2)
      └─ Recover(WS2)     -> remediate_device, reset_credentials, restore_device

A primitive task maps to one STRIPS action. A compound task has one or more
methods, each with an applicability test and a function returning its
subtasks. The planner tries the methods in order, decomposes left to right
while simulating the state, and backtracks to the next method if a subtask
cannot be done. A method's subtasks may be computed by another planner (the
agent uses goal-stack planning inside Contain).

Complexity: exponential in the worst case (method choice is a search), but in
practice nearly linear in plan length, because methods encode expert knowledge
about how incidents are handled.
"""
from dataclasses import dataclass, field
from typing import Callable

from app.algorithms.planning.strips import Action, PlanResult, State

Task = tuple[str, ...]  # ("Contain", "WS2")


@dataclass
class Method:
    name: str
    task: str
    applicable: Callable[[State, tuple[str, ...]], bool]
    subtasks: Callable[[State, tuple[str, ...]], list[Task] | None]
    description: str = ""


@dataclass
class HTNDomain:
    primitives: dict[str, Callable[..., Action]]
    methods: dict[str, list[Method]]


@dataclass
class TaskNode:
    task: Task
    method: str | None = None
    action: Action | None = None
    children: list["TaskNode"] = field(default_factory=list)

    def lines(self, indent: int = 0) -> list[str]:
        name = f"{self.task[0]}({', '.join(self.task[1:])})"
        if self.action is not None:
            head = f"{'  ' * indent}• {self.action.label}"
        else:
            head = f"{'  ' * indent}{name}  [method: {self.method}]"
        out = [head]
        for child in self.children:
            out.extend(child.lines(indent + 1))
        return out

    def to_dict(self) -> dict:
        return {
            "task": list(self.task),
            "method": self.method,
            "action": self.action.label if self.action else None,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class HTNResult(PlanResult):
    tree: list[TaskNode] = field(default_factory=list)
    final_state: State = frozenset()


def htn_plan(domain: HTNDomain, initial: State, tasks: list[Task], max_depth: int = 50) -> HTNResult:
    trace: list[str] = []

    def seek(state: State, todo: list[Task], depth: int) -> tuple[list[Action], list[TaskNode], State] | None:
        if not todo:
            return [], [], state
        if depth > max_depth:
            trace.append("depth limit reached")
            return None
        task, rest = todo[0], todo[1:]
        name, args = task[0], task[1:]

        if name in domain.primitives:
            action = domain.primitives[name](*args)
            if not action.applicable(state):
                trace.append(f"{action.label} not applicable (missing {', '.join(sorted(action.pre - state))})")
                return None
            found = seek(action.apply(state), rest, depth)
            if found is None:
                return None
            plan, nodes, final = found
            return [action, *plan], [TaskNode(task, action=action), *nodes], final

        if name not in domain.methods:
            raise KeyError(f"unknown task: {name}")
        for method in domain.methods[name]:
            if not method.applicable(state, args):
                continue
            subtasks = method.subtasks(state, args)
            if subtasks is None:
                trace.append(f"{name}{args}: method {method.name} produced no subtasks")
                continue
            trace.append(f"{name}({', '.join(args)}) -> {method.name}: "
                         f"[{', '.join(t[0] + '(' + ', '.join(t[1:]) + ')' for t in subtasks)}]")
            inner = seek(state, subtasks, depth + 1)
            if inner is None:
                trace.append(f"{name}: method {method.name} failed, trying next")
                continue
            sub_plan, sub_nodes, mid = inner
            outer = seek(mid, rest, depth)
            if outer is None:
                trace.append(f"{name}: later tasks failed after {method.name}, trying next")
                continue
            plan, nodes, final = outer
            return [*sub_plan, *plan], [TaskNode(task, method=method.name, children=sub_nodes), *nodes], final
        trace.append(f"{name}({', '.join(args)}): no applicable method")
        return None

    found = seek(frozenset(initial), list(tasks), 0)
    if found is None:
        return HTNResult("HTN", None, trace, 0, "no decomposition works")
    plan, nodes, final = found
    return HTNResult("HTN", plan, trace, len(plan), None, nodes, final)
