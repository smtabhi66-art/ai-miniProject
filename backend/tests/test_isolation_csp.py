"""Milestone 6: the isolation decision CSP on the enterprise network."""
import pytest

from app.agent.isolation_csp import (
    ISOLATE,
    MONITOR,
    RESTRICT,
    build_isolation_csp,
    current_suspects,
    solve_isolation,
)
from app.models.enums import DeviceStatus, LinkStatus, ThreatLevel
from app.simulation.network_builder import load_topology

C, S = ThreatLevel.CRITICAL, ThreatLevel.SUSPICIOUS


def solve(suspects, budget=2, setup=None):
    state = load_topology()
    if setup:
        setup(state)
    return solve_isolation(state, suspects, budget)


def names(result):
    return {c.name for c in result.csp.constraints}


# ---- formulation -------------------------------------------------------------
def test_variables_and_preference_ordered_domains():
    csp = build_isolation_csp(load_topology(), {"WS3": C, "DB1": S})
    assert csp.variables == ["DB1", "WS3"]
    assert csp.domains == {"WS3": [ISOLATE, RESTRICT, MONITOR], "DB1": [MONITOR, RESTRICT, ISOLATE]}


def test_current_suspects_reads_threat_levels():
    state = load_topology()
    state.devices["WS2"].threat_level = C
    state.devices["INET"].threat_level = S          # external: never a CSP variable
    state.devices["WS4"].threat_level = S
    state.devices["WS4"].status = DeviceStatus.ISOLATED  # already contained
    assert current_suspects(state) == {"WS2": C}


def test_no_suspects_gives_empty_solution():
    r = solve({})
    assert r.solvable and r.decisions == {}


def test_bad_inputs():
    with pytest.raises(KeyError):
        build_isolation_csp(load_topology(), {"GHOST": C})
    with pytest.raises(ValueError):
        build_isolation_csp(load_topology(), {"WS1": C}, budget=-1)


# ---- scenario-based decisions ----------------------------------------------------
def test_scenario4_isolate_attacker_monitor_target():
    r = solve({"WS3": C, "DB1": S})
    assert r.decisions == {"WS3": ISOLATE, "DB1": MONITOR}


def test_scenario5_app_server_restricted_not_isolated():
    r = solve({"WS2": C, "APP1": C})
    assert r.decisions == {"WS2": ISOLATE, "APP1": RESTRICT}
    after = r.result.domains_after_preprocessing
    assert after == {"WS2": [ISOLATE], "APP1": [RESTRICT]}
    removed = {(p.var, p.value, p.constraint) for p in r.result.preprocessing}
    assert ("APP1", ISOLATE, "keep_sole_critical_host") in removed
    assert ("WS2", RESTRICT, "restrict_needs_service") in removed
    assert ("WS2", MONITOR, "contain_compromised") in removed


def test_scenario7_auth_server_cannot_be_isolated():
    r = solve({"WS1": C, "AUTH1": C})
    assert r.decisions == {"WS1": ISOLATE, "AUTH1": RESTRICT}
    assert "keep_sole_critical_host" in names(r)


def test_replicas_cannot_both_be_isolated():
    r = solve({"DB1": C, "DB2": C})
    assert "keep_one_replica" in names(r)
    assert sorted(r.decisions.values()) == [ISOLATE, RESTRICT]


def test_replica_constraint_skipped_when_other_host_is_healthy():
    r = solve({"DB1": C})
    assert "keep_one_replica" not in names(r) and "keep_sole_critical_host" not in names(r)
    assert r.decisions == {"DB1": ISOLATE}


def test_replica_becomes_sole_host_when_other_is_down():
    r = solve({"DB1": C}, setup=lambda s: setattr(s.devices["DB2"], "status", DeviceStatus.ISOLATED))
    assert r.decisions == {"DB1": RESTRICT}


def test_suspicious_workstation_is_only_monitored():
    assert solve({"WS2": S}).decisions == {"WS2": MONITOR}


# ---- impossible cases: the agent must escalate --------------------------------------
def test_compromised_admin_workstation_is_impossible():
    # Each constraint removes one value, so the domain is empty before search starts:
    #   RESTRICT (no service), MONITOR (it is Critical), ISOLATE (cuts the recovery path).
    # With one variable, the global connectivity constraint has a one-variable scope,
    # so node consistency applies it too.
    r = solve({"ADMIN1": C})
    assert not r.solvable and r.result.stats.assignments == 0
    assert r.result.conflicts == {"admin_can_reach_services": 1, "contain_compromised": 1,
                                  "restrict_needs_service": 1}


def test_compromised_admin_detected_during_search_with_other_suspects():
    r = solve({"ADMIN1": C, "WS1": C})
    assert not r.solvable
    assert r.result.domains_after_preprocessing["ADMIN1"] == [ISOLATE]  # global constraint not applied yet
    assert r.result.conflicts["admin_can_reach_services"] >= 1


def test_compromised_core_router_is_impossible():
    r = solve({"R2": C})
    assert not r.solvable and "admin_can_reach_services" in r.result.conflicts


def test_backup_router_isolatable_unless_direct_link_down():
    assert solve({"R3": C}).decisions == {"R3": ISOLATE}
    blocked = lambda s: setattr(s.get_link("R1", "R2"), "status", LinkStatus.BLOCKED)
    assert not solve({"R3": C}, setup=blocked).solvable


def test_budget_exceeded_is_impossible():
    r = solve({"WS1": C, "WS2": C, "WS3": C}, budget=2)
    assert not r.solvable and "isolation_budget" in r.result.conflicts
    assert solve({"WS1": C, "WS2": C, "WS3": C}, budget=3).solvable


def test_impossible_when_preprocessing_empties_a_domain():
    # Sole auth host, Critical, with RESTRICT removed is impossible before search starts.
    state = load_topology()
    state.devices["AUTH1"].services = []          # pretend it hosts nothing (for the test)
    state.services["auth"].hosts = ["AUTH1"]
    r = solve_isolation(state, {"AUTH1": C})
    assert not r.solvable and r.result.stats.assignments == 0
    assert "AUTH1 has no allowed value left" in r.result.failure


def test_every_found_solution_satisfies_all_constraints():
    for suspects in [{"WS2": C, "APP1": C}, {"WS1": C, "AUTH1": C}, {"DB1": C, "DB2": C, "WS4": S}]:
        r = solve(suspects)
        assert r.solvable and r.csp.is_solution(r.decisions)


def test_to_dict_is_complete():
    data = solve({"WS2": C, "APP1": C}).to_dict()
    assert data["decisions"] == {"APP1": RESTRICT, "WS2": ISOLATE}
    assert {c["name"] for c in data["constraints"]} >= {"contain_compromised", "admin_can_reach_services"}
