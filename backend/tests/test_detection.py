"""Milestone 9: threat detection (evidence facts + forward chaining + classification)."""
import json

import pytest

from app.agent.detection import ThreatDetector, evidence_facts, load_security_rules, topology_facts
from app.core.config import RULES_DIR
from app.models.enums import EventType, ThreatLevel
from app.models.events import SecurityEvent
from app.simulation.network_builder import load_topology

RULES = load_security_rules()


def ev(i, tick, etype, src, dst=None):
    return SecurityEvent(f"e{i}", tick, EventType(etype), src, dst)


def assess(events, tick, cleared=None):
    return ThreatDetector(RULES).assess(load_topology(), events, tick, cleared)


def test_rules_file_loads_and_is_consistent():
    assert {r.name for r in RULES.rules} >= {"R3_credential_compromise", "R11_entry_point", "V1_active_compromise_behaviour"}
    assert RULES.quiet_ticks == 2


def test_bad_rules_file_rejected(tmp_path):
    data = json.loads((RULES_DIR / "security_rules.json").read_text(encoding="utf-8"))
    data["evidence_rules"][0]["about"] = "sideways"
    bad = tmp_path / "rules.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError):
        load_security_rules(bad)


def test_topology_facts():
    facts = set(topology_facts(load_topology()))
    assert ("External", "INET") in facts and ("Internal", "WS1") in facts
    assert ("CriticalAsset", "AUTH1") in facts and ("Hosts", "AUTH1", "auth") in facts
    assert ("Connected", "R1", "WS1") in facts and ("Connected", "WS1", "R1") in facts


def test_evidence_threshold_and_window():
    events = [ev(i, 1 + i // 2, "failed_login", "INET", "WS1") for i in range(6)]  # ticks 1,1,2,2,3,3
    facts = dict(evidence_facts(events, 3, RULES.evidence_rules))
    assert ("FailedLoginBurst", "WS1") in facts
    assert ("BruteForcing", "INET", "WS1") in facts
    assert "6 failed_login event(s) in ticks 1-3" in facts[("FailedLoginBurst", "WS1")]
    later = dict(evidence_facts(events, 5, RULES.evidence_rules))  # window 3 -> only ticks 3..5
    assert ("FailedLoginBurst", "WS1") not in later


def test_cleared_devices_ignore_old_evidence():
    events = [ev(i, 1, "port_scan", "WS2", "R1") for i in range(3)]
    assert evidence_facts(events, 2, RULES.evidence_rules)
    assert evidence_facts(events, 2, RULES.evidence_rules, cleared_at={"WS2": 1}) == []


def test_brute_force_without_login_is_suspicious():
    events = [ev(i, 2 + i // 4, "failed_login", "INET", "WS1") for i in range(8)]
    a = assess(events, 3)
    assert a.levels["WS1"] is ThreatLevel.SUSPICIOUS and a.levels["INET"] is ThreatLevel.SUSPICIOUS
    assert all(l is ThreatLevel.NORMAL for d, l in a.levels.items() if d not in ("WS1", "INET"))


def test_brute_force_then_login_is_critical_with_explanation():
    events = [ev(i, 1 + i // 4, "failed_login", "INET", "WS2") for i in range(8)]
    events.append(ev(99, 3, "successful_login", "INET", "WS2"))
    a = assess(events, 3)
    assert a.levels["WS2"] is ThreatLevel.CRITICAL
    lines = a.explanation("WS2")
    assert lines[0] == "Compromised(WS2)  [derived by R3_credential_compromise]"
    assert any("BruteForcing(INET, WS2)  [observed" in l for l in lines)


def test_external_attacker_is_never_compromised():
    events = [ev(i, 1, "failed_login", "INET", "WS2") for i in range(6)]
    a = assess(events, 1)
    assert a.levels["INET"] is ThreatLevel.SUSPICIOUS


def test_internal_brute_forcer_is_compromised():
    events = [ev(i, 2, "failed_login", "WS1", "AUTH1") for i in range(5)]
    assert assess(events, 2).levels["WS1"] is ThreatLevel.CRITICAL


def test_single_benign_failed_login_is_normal():
    assert all(l is ThreatLevel.NORMAL for l in assess([ev(1, 1, "failed_login", "WS3", "AUTH1")], 1).levels.values())


def test_exfiltration_and_entry_point_tracing():
    events = [ev(1, 2, "successful_login", "WS1", "AUTH1"), ev(2, 4, "unauthorized_access", "AUTH1", "DB1"),
              ev(3, 5, "unusual_traffic", "AUTH1", "DB1"), ev(4, 6, "unusual_traffic", "AUTH1", "DB1")]
    a = assess(events, 6)
    assert a.levels["AUTH1"] is ThreatLevel.CRITICAL      # R5
    assert a.levels["WS1"] is ThreatLevel.CRITICAL        # R11
    assert a.levels["DB1"] is ThreatLevel.SUSPICIOUS      # R6


def test_beliefs_persist_between_ticks():
    state = load_topology()
    state.facts.add(("Compromised", "WS3"))
    a = ThreatDetector(RULES).assess(state, [], 10)
    assert a.levels["WS3"] is ThreatLevel.CRITICAL
    assert "belief" in a.explanation("WS3")[0]
