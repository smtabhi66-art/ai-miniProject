"""Milestone 3: the environment, event generation, hidden state and containment."""
from app.models.enums import EventType, LinkStatus
from app.simulation.environment import NetworkSimulator
from app.simulation.scenarios import generate_scenario, load_scenario


def run(sim, actions=None):
    """Run to the end. ``actions`` maps tick -> list of (name, params) applied before that tick."""
    actions = actions or {}
    events = []
    while not sim.finished:
        for name, params in actions.get(sim.tick, []):
            assert sim.execute(name, params).success
        events.extend(sim.step())
    return events


def sim_for(scenario_id, seed=42):
    return NetworkSimulator(load_scenario(scenario_id), seed)


def attack_events(sim, events):
    return [e for e in events if sim.labels[e.id]]


def test_same_seed_gives_identical_runs():
    a = [e.to_dict() for e in run(sim_for("s8_multi_step", seed=1))]
    b = [e.to_dict() for e in run(sim_for("s8_multi_step", seed=1))]
    assert a == b


def test_different_seed_changes_background_only():
    a, b = sim_for("s8_multi_step", 1), sim_for("s8_multi_step", 2)
    ea, eb = run(a), run(b)
    assert [e.to_dict() for e in ea] != [e.to_dict() for e in eb]
    strip = lambda sim, evs: [(e.tick, e.type, e.source, e.target) for e in attack_events(sim, evs)]
    assert strip(a, ea) == strip(b, eb)


def test_normal_scenario_has_no_attacks():
    sim = sim_for("s1_normal")
    events = run(sim)
    assert events and not any(sim.labels.values())
    assert {e.type for e in events} <= {EventType.NORMAL_TRAFFIC, EventType.FAILED_LOGIN}
    assert sim.ground_truth()["compromised"] == []


def test_failed_login_scenario_counts():
    sim = sim_for("s2_failed_logins")
    attacks = attack_events(sim, run(sim))
    assert len(attacks) == 3 * 4
    assert all(e.type is EventType.FAILED_LOGIN and e.target == "WS1" for e in attacks)
    assert sim.ground_truth()["compromised"] == []


def test_brute_force_success_compromises_victim():
    sim = sim_for("s8_multi_step")
    for _ in range(3):
        sim.step()
    assert not sim.hidden["WS2"].compromised
    sim.step()  # tick 3: successful login lands
    assert sim.hidden["WS2"].compromised and sim.hidden["WS2"].credentials_stolen


def test_agent_model_has_no_hidden_information():
    sim = sim_for("s4_compromised_to_server")
    model = sim.initial_model()
    assert model is not sim.world
    assert not hasattr(model, "hidden")
    assert sim.hidden["WS3"].compromised  # true, but only the environment knows


def test_isolation_stops_attack_traffic():
    sim = sim_for("s8_multi_step")
    events = run(sim, {7: [("isolate_device", {"device": "WS2"})]})
    assert not [e for e in attack_events(sim, events) if e.source == "WS2" and e.tick >= 7]
    reasons = {reason for _, reason in sim.suppressed}
    assert "WS2 is isolated" in reasons


def test_remediation_stops_traffic_even_after_restore():
    sim = sim_for("s8_multi_step")
    run(sim, {7: [("isolate_device", {"device": "WS2"}),
                  ("remediate_device", {"device": "WS2"}),
                  ("reset_credentials", {"device": "WS2"})],
              9: [("restore_device", {"device": "WS2"})]})
    assert sim.ground_truth()["compromised"] == []
    assert sim.ground_truth()["credentials_stolen"] == []
    late = [e for e in sim.delivered if e.source == "WS2" and sim.labels[e.id] and e.tick >= 9]
    assert late == []
    assert any(reason == "WS2 is not compromised" for _, reason in sim.suppressed)


def test_restriction_blocks_malicious_outbound_only():
    sim = sim_for("s4_compromised_to_server")
    events = run(sim, {5: [("restrict_device", {"device": "WS3"})]})
    assert not [e for e in attack_events(sim, events) if e.source == "WS3" and e.tick >= 5]
    assert sim.hidden["WS3"].compromised  # restricted, not cleaned


def test_blocking_internet_link_stops_external_brute_force():
    sim = sim_for("s2_failed_logins")
    events = run(sim, {3: [("block_link", {"a": "INET", "b": "FW1"})]})
    assert [e.tick for e in attack_events(sim, events)] == [2] * 4
    assert any(reason.startswith("no usable path INET") for _, reason in sim.suppressed)


def test_blocked_path_scenario_uses_backup_router():
    sim = sim_for("s6_blocked_path")
    assert sim.world.get_link("R1", "R2").status is LinkStatus.BLOCKED
    assert sim.initial_model().get_link("R1", "R2").status is LinkStatus.BLOCKED
    events = run(sim)
    assert any(e.type is EventType.UNAUTHORIZED_ACCESS and e.target == "AUTH1" for e in events)


def test_lateral_compromise_in_multi_compromise_scenario():
    sim = sim_for("s5_multi_compromise")
    run(sim)
    assert sim.ground_truth()["compromised"] == ["APP1", "WS2"]


def test_failed_action_is_reported_not_raised():
    sim = sim_for("s1_normal")
    record = sim.execute("restore_device", {"device": "WS1"})
    assert not record.success and "must be" in record.message
    assert record.simulated


def test_step_after_finish_returns_nothing():
    sim = sim_for("s1_normal")
    run(sim)
    assert sim.step() == []


def test_actions_do_not_change_background_noise():
    plain, acted = sim_for("s8_multi_step"), sim_for("s8_multi_step")
    run(plain)
    run(acted, {7: [("isolate_device", {"device": "WS2"})]})
    every = lambda sim: sorted([e.id for e in sim.delivered] + [e.id for e, _ in sim.suppressed])
    assert every(plain) == every(acted)


def test_generated_scenario_runs():
    sim = NetworkSimulator(generate_scenario(11), seed=11)
    assert run(sim)
