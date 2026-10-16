"""Milestone 3: scenario files and the random scenario generator."""
import copy

import pytest

from app.models.enums import ThreatLevel
from app.simulation.scenarios import (
    ScenarioError,
    generate_scenario,
    list_scenarios,
    load_scenario,
    parse_scenario,
)

BASE = {
    "id": "t", "name": "t", "ticks": 5,
    "steps": [{"tick": 1, "type": "port_scan", "source": "WS1", "target": "R1"}],
}


def test_all_eight_scenarios_load():
    ids = [s.id for s in list_scenarios()]
    assert ids == [
        "s1_normal", "s2_failed_logins", "s3_lateral_traffic", "s4_compromised_to_server",
        "s5_multi_compromise", "s6_blocked_path", "s7_isolation_constraint", "s8_multi_step",
    ]


def test_expected_level_defaults_to_normal():
    s = load_scenario("s8_multi_step")
    assert s.expected_level("WS2") is ThreatLevel.CRITICAL
    assert s.expected_level("WS4") is ThreatLevel.NORMAL


def test_tick_range_and_targets_parsed():
    s = load_scenario("s3_lateral_traffic")
    scan, traffic = s.steps
    assert (scan.start, scan.end) == (3, 3) and scan.targets == ["WS1", "WS3", "WS4", "ADMIN1"]
    assert (traffic.start, traffic.end) == (4, 7)


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d["steps"][0].update(source="GHOST"), "unknown device GHOST"),
    (lambda d: d["steps"][0].update(tick=9), "outside"),
    (lambda d: d["steps"][0].update(type="teleport"), "teleport"),
    (lambda d: d["steps"][0].update(repeat=0), "repeat"),
    (lambda d: d.update(expected={"WS1": "panic"}), "panic"),
    (lambda d: d.update(initial_blocked_links=[["WS1", "DB1"]]), "no link"),
    (lambda d: d.pop("ticks"), "missing required field"),
    (lambda d: d.update(background={"benign_failed_login_prob": 2}), "0..1"),
])
def test_invalid_scenarios_rejected(mutate, message):
    data = copy.deepcopy(BASE)
    mutate(data)
    with pytest.raises(ScenarioError, match=message):
        parse_scenario(data)


def test_unknown_scenario_file():
    with pytest.raises(ScenarioError, match="not found"):
        load_scenario("s99_missing")


def test_generated_scenario_is_deterministic():
    assert generate_scenario(7).to_dict() == generate_scenario(7).to_dict()
    assert generate_scenario(7).steps == generate_scenario(7).steps


def test_generated_scenarios_vary_with_seed():
    descriptions = {generate_scenario(seed).description for seed in range(20)}
    assert len(descriptions) > 5


def test_generated_scenarios_always_have_an_attack_and_labels():
    for seed in range(30):
        s = generate_scenario(seed)
        assert s.steps and s.expected
        assert all(step.end < s.ticks for step in s.steps)


def test_generator_rejects_too_short_runs():
    with pytest.raises(ScenarioError):
        generate_scenario(1, ticks=5)
