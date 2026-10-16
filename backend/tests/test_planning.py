"""Milestone 8: STRIPS, goal-based, goal-stack and hierarchical planning."""
import pytest

from app.agent.isolation_csp import ISOLATE, MONITOR, RESTRICT
from app.agent.response_planning import (
    ESCALATE,
    actions_for,
    goal_for,
    initial_state,
    make_action,
    plan_incident,
)
from app.algorithms.planning.goal_based import forward_plan
from app.algorithms.planning.goal_stack import goal_stack_plan
from app.algorithms.planning.strips import Action, relaxed_reachable, validate_plan


# ---- STRIPS -----------------------------------------------------------------------
def test_action_applicability_and_effects():
    iso = make_action("isolate_device", "WS2")
    s = {"IsolationApproved(WS2)", "Online(WS2)"}
    assert iso.applicable(s)
    assert iso.apply(s) == {"IsolationApproved(WS2)", "Isolated(WS2)", "Contained(WS2)"}
    with pytest.raises(ValueError, match="missing Online"):
        iso.apply({"IsolationApproved(WS2)"})


def test_validate_plan_reports_first_problem():
    plan = [make_action("isolate_device", "WS2")]
    ok, msg, _ = validate_plan({"Online(WS2)"}, plan, {"Contained(WS2)"})
    assert not ok and "IsolationApproved(WS2)" in msg
    ok, msg, _ = validate_plan(set(), [], {"Contained(WS2)"})
    assert not ok and msg.startswith("goal not reached")


def test_relaxed_reachability_respects_csp_decision():
    reach = relaxed_reachable(initial_state("APP1", RESTRICT), actions_for("APP1"))
    assert "Restricted(APP1)" in reach and "Isolated(APP1)" not in reach


# ---- goal-based (forward BFS) ---------------------------------------------------------
@pytest.mark.parametrize("decision", [ISOLATE, RESTRICT, MONITOR, ESCALATE])
def test_forward_planner_finds_valid_shortest_plan(decision):
    init, goal = initial_state("WS2", decision), goal_for("WS2", decision)
    result = forward_plan(init, goal, actions_for("WS2"))
    assert result.found
    assert validate_plan(init, result.plan, goal)[0]


def test_forward_plan_is_shortest_for_isolation():
    r = forward_plan(initial_state("WS2", ISOLATE), goal_for("WS2", ISOLATE), actions_for("WS2"))
    assert r.labels == ["collect_evidence(WS2)", "analyze_blast_radius(WS2)", "approve_isolation(WS2)",
                        "isolate_device(WS2)", "verify_containment(WS2)", "remediate_device(WS2)",
                        "reset_credentials(WS2)", "restore_device(WS2)"]


def test_forward_planner_detects_unreachable_goal():
    r = forward_plan(initial_state("AUTH1", RESTRICT), {"Isolated(AUTH1)"}, actions_for("AUTH1"))
    assert not r.found and r.failure == "goal unreachable"


def test_goal_already_satisfied():
    assert forward_plan({"A()"}, {"A()"}, []).plan == []


# ---- goal-stack -------------------------------------------------------------------------
def test_goal_stack_contains_with_isolation():
    init = initial_state("WS2", ISOLATE)
    r = goal_stack_plan(init, {"Contained(WS2)"}, actions_for("WS2"))
    assert r.labels == ["collect_evidence(WS2)", "analyze_blast_radius(WS2)",
                        "approve_isolation(WS2)", "isolate_device(WS2)"]
    assert any("choose isolate_device(WS2)" in t for t in r.trace)


def test_goal_stack_uses_restriction_when_isolation_not_allowed():
    init = initial_state("AUTH1", RESTRICT)
    r = goal_stack_plan(init, {"Contained(AUTH1)"}, actions_for("AUTH1"))
    assert r.labels[-1] == "restrict_device(AUTH1)"
    assert "isolate_device(AUTH1)" not in r.labels


def test_goal_stack_fails_when_no_action_can_help():
    r = goal_stack_plan(initial_state("WS2", MONITOR), {"Contained(WS2)"}, actions_for("WS2"))
    assert not r.found and "no usable action" in r.failure


def blocks_world():
    """Classic blocks world, used to show goal interaction (the Sussman anomaly)."""
    blocks = "ABC"
    acts = []
    for x in blocks:
        for y in blocks:
            if x == y:
                continue
            acts.append(Action.make("stack", [x, y], [f"Holding({x})", f"Clear({y})"],
                                    [f"On({x},{y})", f"Clear({x})", "HandEmpty()"],
                                    [f"Holding({x})", f"Clear({y})"]))
            acts.append(Action.make("unstack", [x, y], [f"On({x},{y})", f"Clear({x})", "HandEmpty()"],
                                    [f"Holding({x})", f"Clear({y})"],
                                    [f"On({x},{y})", f"Clear({x})", "HandEmpty()"]))
        acts.append(Action.make("pickup", [x], [f"OnTable({x})", f"Clear({x})", "HandEmpty()"],
                                [f"Holding({x})"], [f"OnTable({x})", f"Clear({x})", "HandEmpty()"]))
        acts.append(Action.make("putdown", [x], [f"Holding({x})"],
                                [f"OnTable({x})", f"Clear({x})", "HandEmpty()"], [f"Holding({x})"]))
    return acts


SUSSMAN_INIT = {"On(C,A)", "OnTable(A)", "OnTable(B)", "Clear(C)", "Clear(B)", "HandEmpty()"}
SUSSMAN_GOAL = {"On(A,B)", "On(B,C)"}


def test_sussman_anomaly_goal_stack_vs_forward_search():
    gs = goal_stack_plan(SUSSMAN_INIT, SUSSMAN_GOAL, blocks_world())
    bfs = forward_plan(SUSSMAN_INIT, SUSSMAN_GOAL, blocks_world())
    assert bfs.found and len(bfs.plan) == 6  # optimal
    assert validate_plan(SUSSMAN_INIT, bfs.plan, SUSSMAN_GOAL)[0]
    # Goal-stack either fails or needs extra steps to redo an undone goal; it is never shorter.
    if gs.found:
        assert validate_plan(SUSSMAN_INIT, gs.plan, SUSSMAN_GOAL)[0]
        assert len(gs.plan) > len(bfs.plan)
        assert any("broken; re-push" in t for t in gs.trace)


# ---- HTN -------------------------------------------------------------------------------
@pytest.mark.parametrize("decision, expected_tail", [
    (ISOLATE, ["isolate_device", "verify_containment", "remediate_device", "reset_credentials", "restore_device"]),
    (RESTRICT, ["restrict_device", "verify_containment", "reset_credentials", "escalate"]),
    (MONITOR, ["increase_monitoring", "verify_quiet"]),
    (ESCALATE, ["escalate", "increase_monitoring"]),
])
def test_htn_plans_for_each_decision(decision, expected_tail):
    init = initial_state("D", decision)
    r = plan_incident(init, "D")
    assert r.found
    names = [a.name for a in r.plan]
    assert names[:2] == ["collect_evidence", "analyze_blast_radius"]
    assert names[-len(expected_tail):] == expected_tail
    assert validate_plan(init, r.plan, goal_for("D", decision))[0]


def test_htn_tree_shows_phases_and_methods():
    r = plan_incident(initial_state("WS2", ISOLATE), "WS2")
    lines = r.tree[0].lines()
    assert lines[0] == "HandleIncident(WS2)  [method: full]"
    assert "  Contain(WS2)  [method: by_goal_stack]" in lines
    assert "  Recover(WS2)  [method: isolated]" in lines


def test_htn_under_attack_monitored_device_resets_credentials():
    r = plan_incident(initial_state("WS1", MONITOR, under_attack=True), "WS1")
    assert r.labels[-1] == "reset_credentials(WS1)"


def test_htn_resume_after_escalation_skips_detection():
    state = initial_state("WS3", ISOLATE) | {"EvidenceCollected(WS3)", "Investigated(WS3)", "Monitored(WS3)"}
    r = plan_incident(state, "WS3")
    assert r.tree[0].method == "resume"
    assert "collect_evidence(WS3)" not in r.labels
    assert "isolate_device(WS3)" in r.labels


def test_htn_matches_goal_based_plan_length_for_isolation():
    init = initial_state("WS2", ISOLATE)
    htn = plan_incident(init, "WS2")
    bfs = forward_plan(init, goal_for("WS2", ISOLATE), actions_for("WS2"))
    assert len(htn.plan) == len(bfs.plan)
