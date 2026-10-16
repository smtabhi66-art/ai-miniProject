"""Planning demo: goal-based (forward BFS) vs goal-stack vs HTN on an incident, plus the Sussman anomaly.

    python -m app.demos.planning_demo
    python -m app.demos.planning_demo --decision RESTRICT --device AUTH1
"""
import argparse

from app.agent.response_planning import actions_for, goal_for, initial_state, plan_incident
from app.algorithms.planning.goal_based import forward_plan
from app.algorithms.planning.goal_stack import goal_stack_plan
from app.algorithms.planning.strips import Action, validate_plan
from app.core.console import utf8_output


def incident(device: str, decision: str) -> None:
    init, goal = initial_state(device, decision), goal_for(device, decision)
    print(f"=== Incident on {device}, CSP decision {decision} ===")
    print(f"Initial state: {sorted(init)}")
    print(f"Goal:          {sorted(goal)}\n")

    bfs = forward_plan(init, goal, actions_for(device))
    print(f"Goal-based (forward BFS): {len(bfs.plan or [])} steps, {bfs.explored} states explored")
    for a in bfs.plan or []:
        print(f"   {a.label}")

    gs = goal_stack_plan(init, {f"Contained({device})"}, actions_for(device))
    print(f"\nGoal-stack for Contained({device}):")
    for line in gs.trace:
        print(f"   {line}")

    htn = plan_incident(init, device)
    print("\nHTN decomposition:")
    for line in htn.tree[0].lines():
        print(f"   {line}")
    ok, msg, _ = validate_plan(init, htn.plan, goal)
    print(f"HTN plan valid against the goal? {ok} ({msg})")


def sussman() -> None:
    acts = []
    for x in "ABC":
        for y in "ABC":
            if x != y:
                acts.append(Action.make("stack", [x, y], [f"Holding({x})", f"Clear({y})"],
                                        [f"On({x},{y})", f"Clear({x})", "HandEmpty()"], [f"Holding({x})", f"Clear({y})"]))
                acts.append(Action.make("unstack", [x, y], [f"On({x},{y})", f"Clear({x})", "HandEmpty()"],
                                        [f"Holding({x})", f"Clear({y})"], [f"On({x},{y})", f"Clear({x})", "HandEmpty()"]))
        acts.append(Action.make("pickup", [x], [f"OnTable({x})", f"Clear({x})", "HandEmpty()"], [f"Holding({x})"],
                                [f"OnTable({x})", f"Clear({x})", "HandEmpty()"]))
        acts.append(Action.make("putdown", [x], [f"Holding({x})"], [f"OnTable({x})", f"Clear({x})", "HandEmpty()"],
                                [f"Holding({x})"]))
    init = {"On(C,A)", "OnTable(A)", "OnTable(B)", "Clear(C)", "Clear(B)", "HandEmpty()"}
    goal = {"On(A,B)", "On(B,C)"}
    print("\n=== Sussman anomaly (why goal-stack planning is not complete/optimal) ===")
    bfs = forward_plan(init, goal, acts)
    gs = goal_stack_plan(init, goal, acts)
    print(f"Forward BFS: {len(bfs.plan)} steps: {', '.join(bfs.labels)}")
    if gs.found:
        print(f"Goal-stack:  {len(gs.plan)} steps: {', '.join(gs.labels)}")
        print("  (achieving one goal undid the other, so it had to be redone)")
    else:
        print(f"Goal-stack failed: {gs.failure}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--device", default="WS2")
    parser.add_argument("--decision", default="ISOLATE", choices=["ISOLATE", "RESTRICT", "MONITOR", "ESCALATE"])
    args = parser.parse_args()
    utf8_output()
    incident(args.device, args.decision)
    sussman()


if __name__ == "__main__":
    main()
