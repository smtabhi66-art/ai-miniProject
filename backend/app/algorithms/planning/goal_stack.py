"""Goal-stack planning (STRIPS-style linear planner).

The planner keeps a stack of goals and actions and works backwards from the goal:

    push the conjunctive goal, then each of its literals
    loop: pop the top item
      literal already true      -> discard it
      literal false             -> choose an action whose add list contains it;
                                   push the action, then its preconditions
                                   (as a conjunction, then one by one)
      conjunction               -> if some literal became false again
                                   (goal interaction), push the false ones again
      action                    -> its preconditions now hold: apply it to the
                                   current state and append it to the plan

Choosing the achieving action is the key decision. We only consider actions
whose preconditions are reachable in the *relaxed* problem (deletes ignored),
so the planner never commits to an action that can't possibly work, such as
approving isolation when the CSP did not allow it. Among those, it prefers
actions with the fewest currently-false preconditions.

Goal-stack planning is not complete: interacting goals (the Sussman anomaly)
can defeat it. ``max_steps`` guards against loops, and the tests include such a case.
"""
from typing import Iterable

from app.algorithms.planning.strips import Action, PlanResult, relaxed_reachable


def goal_stack_plan(initial: Iterable[str], goal: Iterable[str], actions: Iterable[Action],
                    max_steps: int = 500) -> PlanResult:
    state = set(initial)
    goal_set = frozenset(goal)
    acts = list(actions)
    reachable = relaxed_reachable(state, acts)
    stack: list[tuple[str, object]] = [("goals", goal_set)]
    stack += [("goal", g) for g in sorted(goal_set, reverse=True)]
    plan: list[Action] = []
    trace: list[str] = []
    steps = 0

    def fail(reason: str) -> PlanResult:
        trace.append(f"FAIL: {reason}")
        return PlanResult("Goal-stack", None, trace, steps, reason)

    while stack:
        steps += 1
        if steps > max_steps:
            return fail(f"no plan within {max_steps} steps (goals keep undoing each other)")
        kind, item = stack.pop()

        if kind == "goal":
            literal = item
            if literal in state:
                trace.append(f"{literal}: already true")
                continue
            candidates = [a for a in acts if literal in a.add and a.pre <= reachable]
            if not candidates:
                return fail(f"no usable action achieves {literal}")
            action = min(candidates, key=lambda a: (len(a.pre - state), acts.index(a)))
            trace.append(f"{literal}: false -> choose {action.label}, push its preconditions")
            stack.append(("action", action))
            stack.append(("goals", action.pre))
            stack += [("goal", p) for p in sorted(action.pre, reverse=True)]

        elif kind == "goals":
            unmet = sorted(item - state)
            if unmet:
                trace.append(f"conjunction {{{', '.join(sorted(item))}}} broken; re-push {', '.join(unmet)}")
                stack.append(("goals", item))
                stack += [("goal", g) for g in reversed(unmet)]

        else:  # action
            action = item
            if not action.applicable(state):
                return fail(f"{action.label} preconditions were undone")
            state = set(action.apply(state))
            plan.append(action)
            trace.append(f"apply {action.label}")

    return PlanResult("Goal-stack", plan, trace, steps)
