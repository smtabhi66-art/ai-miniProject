"""Goal-based planning by forward state-space search (BFS).

Start from the initial state, apply every applicable action, and search
breadth-first until a state containing all goal literals is found. BFS
explores plans in order of length, so the first plan found is a *shortest* plan.

Data structures: FIFO queue of (state, plan), visited set of frozenset states.
Complexity: O(b^d) states for branching factor b and plan length d, bounded
by ``max_states``. Fine for one incident (a dozen ground actions), which is
why the agent uses the HTN planner to keep each sub-problem small.
"""
from collections import deque
from typing import Iterable

from app.algorithms.planning.strips import Action, PlanResult, State


def forward_plan(initial: Iterable[str], goal: Iterable[str], actions: Iterable[Action],
                 max_states: int = 20000) -> PlanResult:
    start: State = frozenset(initial)
    goal_set = frozenset(goal)
    acts = list(actions)
    if goal_set <= start:
        return PlanResult("Goal-based (forward BFS)", [], ["goal already satisfied"], 1)
    queue = deque([(start, [])])
    visited = {start}
    trace = []
    while queue:
        state, plan = queue.popleft()
        for action in acts:
            if not action.applicable(state):
                continue
            nxt = action.apply(state)
            if nxt in visited:
                continue
            new_plan = plan + [action]
            if goal_set <= nxt:
                trace.append(f"goal reached after exploring {len(visited)} states: "
                             + " -> ".join(a.label for a in new_plan))
                return PlanResult("Goal-based (forward BFS)", new_plan, trace, len(visited))
            visited.add(nxt)
            if len(visited) >= max_states:
                return PlanResult("Goal-based (forward BFS)", None, trace, len(visited),
                                  f"gave up after {max_states} states")
            queue.append((nxt, new_plan))
        if len(trace) < 50:
            trace.append(f"expanded state with plan [{', '.join(a.label for a in plan)}]")
    return PlanResult("Goal-based (forward BFS)", None, trace, len(visited), "goal unreachable")
