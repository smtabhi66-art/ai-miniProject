"""Milestone 9: the full agent loop on every scenario (active and passive)."""
import pytest

from app.agent.investigation import investigate
from app.agent.session import Session
from app.agent.verification import check_containment
from app.agent.detection import load_security_rules
from app.models.enums import DeviceStatus, EventType, IncidentStatus, LinkStatus, ThreatLevel
from app.models.events import SecurityEvent
from app.simulation.network_builder import load_topology
from app.simulation.scenarios import list_scenarios

SCENARIOS = [s.id for s in list_scenarios()]


def run(scenario_id, act=True, seed=42):
    return Session.create(scenario_id, seed, act=act).run()


def incidents_by_device(session):
    return {inc.devices[0]: inc for inc in session.agent.incidents}


@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_passive_detection_matches_ground_truth(scenario_id):
    report = run(scenario_id, act=False).report()
    assert report["detection"]["accuracy"] == 1.0, report["detection"]["mistakes"]


@pytest.mark.parametrize("seed", range(0, 30, 3))
def test_passive_detection_on_generated_scenarios(seed):
    report = Session.create("random", seed, act=False).run().report()
    assert report["detection"]["accuracy"] == 1.0, (report["scenario"]["description"], report["detection"]["mistakes"])


@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_active_runs_are_safe(scenario_id):
    s = run(scenario_id)
    counts = s.meter.counts
    assert counts["outage_ticks"] == 0          # never broke a critical service
    assert counts["healthy_isolated"] == 0      # never isolated an innocent device
    assert counts["false_positives"] == 0
    assert all(inc.closed_tick is not None for inc in s.agent.incidents)  # every incident finished
    assert s.report()["ground_truth"]["compromised"] == sorted(
        d for d in s.report()["ground_truth"]["compromised"]
        if s.sim.world.devices[d].status is not DeviceStatus.ONLINE)  # nothing compromised left free


def test_normal_scenario_raises_no_incidents():
    s = run("s1_normal")
    assert s.agent.incidents == [] and s.meter.score() == 0


def test_brute_force_scenario_monitors_and_resets_credentials():
    inc = incidents_by_device(run("s2_failed_logins"))["WS1"]
    assert inc.decision == "MONITOR" and inc.status is IncidentStatus.RESOLVED
    assert inc.plan[-1] == "reset_credentials(WS1)"


def test_multi_step_incident_full_lifecycle():
    s = run("s8_multi_step")
    inc = incidents_by_device(s)["WS2"]
    assert inc.decision == "ISOLATE" and inc.status is IncidentStatus.RESOLVED and inc.verified
    # t=2 under attack -> monitor; t=3 login succeeds -> escalate to isolation; then recover.
    assert [a.action for a in inc.actions_taken] == ["increase_monitoring", "isolate_device", "remediate_device",
                                                     "reset_credentials", "restore_device"]
    assert any("raised to critical" in t for t in inc.timeline)
    assert any("modus tollens" in line for line in inc.verification)
    assert s.sim.ground_truth()["compromised"] == [] and s.sim.ground_truth()["credentials_stolen"] == []
    assert s.manager.state.devices["WS2"].status is DeviceStatus.ONLINE
    assert s.report()["attack_events"]["prevented"] > 0
    assert s.meter.score() == 10


def test_sole_critical_hosts_are_restricted_not_isolated():
    for scenario_id, server, workstation in [("s5_multi_compromise", "APP1", "WS2"),
                                             ("s7_isolation_constraint", "AUTH1", "WS1")]:
        by = incidents_by_device(run(scenario_id))
        assert by[server].decision == "RESTRICT" and by[server].status is IncidentStatus.CONTAINED
        assert by[workstation].decision == "ISOLATE" and by[workstation].status is IncidentStatus.RESOLVED


def test_entry_point_explanation_uses_r11():
    inc = incidents_by_device(run("s7_isolation_constraint"))["WS1"]
    assert inc.explanation[0] == "Compromised(WS1)  [derived by R11_entry_point]"


def test_threat_escalation_replans_with_resume():
    inc = incidents_by_device(run("s4_compromised_to_server"))["WS3"]
    assert any("raised to critical" in t for t in inc.timeline)
    assert inc.htn_tree[0] == "HandleIncident(WS3)  [method: resume]"
    assert inc.decision == "ISOLATE"


def test_every_algorithm_is_logged():
    algorithms = {d.algorithm for d in run("s7_isolation_constraint").agent.decisions}
    assert {"Logic: forward chaining (Modus Ponens)", "CSP: isolation decision", "Planning: HTN + goal-stack",
            "Search: BFS, DFS, Greedy, A*", "Action (simulated)", "Verification: Modus Tollens"} <= algorithms


def test_passive_mode_takes_no_actions():
    s = run("s8_multi_step", act=False)
    assert s.sim.actions == [] and s.manager.transitions == []
    assert all(inc.status is IncidentStatus.OPEN for inc in s.agent.incidents)
    assert s.meter.counts["active_compromise_ticks"] > 0


def test_runs_are_deterministic():
    a, b = run("s5_multi_compromise").report(), run("s5_multi_compromise").report()
    assert a == b


def test_impossible_isolation_escalates():
    # Make the admin workstation the victim: no safe containment exists.
    from app.simulation.scenarios import parse_scenario
    sc = parse_scenario({"id": "admin_attack", "name": "admin", "ticks": 10, "steps": [
        {"ticks": [1, 2], "type": "failed_login", "source": "INET", "target": "ADMIN1", "repeat": 4, "malicious": True},
        {"tick": 3, "type": "successful_login", "source": "INET", "target": "ADMIN1", "malicious": True,
         "compromise": "ADMIN1"}]})
    s = Session(sc, 1).run()
    inc = incidents_by_device(s)["ADMIN1"]
    assert inc.decision == "ESCALATE" and inc.status is IncidentStatus.ESCALATED
    assert s.manager.state.devices["ADMIN1"].status is DeviceStatus.ONLINE  # not isolated
    assert s.manager.state.devices["ADMIN1"].monitored


# ---- building blocks -------------------------------------------------------------------
def test_investigation_finds_chokepoint_and_safe_route():
    state = load_topology()
    state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    inv = investigate(state, "AUTH1")
    assert inv.admin_route["path"] == ["ADMIN1", "R1", "R3", "R2", "AUTH1"]
    assert inv.chokepoints == ["R2"]
    assert inv.greedy_target in {"DB1", "DB2"}


def test_investigation_avoids_compromised_router():
    state = load_topology()
    state.devices["R3"].threat_level = ThreatLevel.CRITICAL
    state.get_link("R1", "R2").status = LinkStatus.BLOCKED
    assert investigate(state, "DB1").admin_route["path"] is None


def test_verification_pending_failed_passed():
    rules = load_security_rules()
    scan = lambda t: SecurityEvent(f"s{t}", t, EventType.PORT_SCAN, "WS2", "R1")
    assert check_containment("WS2", 5, 6, [], rules).status == "pending"
    assert check_containment("WS2", 5, 7, [scan(4)], rules).status == "passed"  # before containment: ignored
    failed = check_containment("WS2", 5, 7, [scan(6)], rules)
    assert failed.status == "failed" and "MaliciousActivity(WS2)" in failed.lines[1]
