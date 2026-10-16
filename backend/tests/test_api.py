"""Milestone 10: REST API and SQLite persistence."""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path / "test.db"))


def test_health_and_scenarios(client):
    assert client.get("/api/health").json()["status"] == "ok"
    scenarios = client.get("/api/scenarios").json()
    assert len(scenarios) == 8 and scenarios[0]["id"] == "s1_normal"


def test_state_before_start_is_conflict(client):
    assert client.get("/api/state").status_code == 409


def test_unknown_scenario_is_404(client):
    assert client.post("/api/simulation/start", json={"scenario_id": "nope"}).status_code == 404


def test_invalid_mode_rejected(client):
    assert client.post("/api/simulation/start", json={"mode": "chaos"}).status_code == 422


def test_full_run_and_history(client):
    snap = client.post("/api/simulation/start", json={"scenario_id": "s8_multi_step", "seed": 42}).json()
    assert snap["tick"] == 0 and len(snap["network"]["devices"]) == 16 and snap["run_id"] == 1

    snap = client.post("/api/simulation/step?ticks=4").json()
    assert snap["tick"] == 4
    assert any(d["id"] == "WS2" and d["threat_level"] == "critical" for d in snap["network"]["devices"])
    assert any(d["algorithm"].startswith("CSP") for d in snap["decisions"])

    snap = client.post("/api/simulation/run").json()
    assert snap["finished"] and snap["performance"]["score"] == 10

    incidents = client.get("/api/incidents").json()
    assert incidents[0]["status"] == "resolved"
    detail = client.get(f"/api/incidents/{incidents[0]['id']}").json()
    assert detail["decisions"] and detail["verification"]
    assert client.get("/api/incidents/INC-999").status_code == 404

    assert client.get("/api/decisions?algorithm=verification").json()
    summary = client.get("/api/reports/summary").json()
    assert summary["detection"]["accuracy"] is not None

    runs = client.get("/api/runs").json()
    assert runs[0]["final_score"] == 10 and runs[0]["incidents"] == 1 and runs[0]["actions"] == 5
    run = client.get("/api/runs/1").json()
    assert run["report"]["performance"]["score"] == 10
    assert all(a["simulated"] == 1 for a in run["actions"])
    assert run["event_count"] > 0 and run["decision_count"] > 0
    assert client.get("/api/runs/99").status_code == 404


def test_step_after_finish_is_harmless(client):
    client.post("/api/simulation/start", json={"scenario_id": "s1_normal"})
    client.post("/api/simulation/run")
    assert client.post("/api/simulation/step").json()["finished"]


def test_reset(client):
    client.post("/api/simulation/start", json={"scenario_id": "s1_normal"})
    assert client.post("/api/simulation/reset").json() == {"status": "reset"}
    assert client.get("/api/state").status_code == 409


def test_passive_mode_and_random_scenario(client):
    snap = client.post("/api/simulation/start", json={"scenario_id": "random", "seed": 3, "mode": "passive"}).json()
    assert snap["mode"] == "passive" and snap["scenario"]["id"] == "random_3"
    snap = client.post("/api/simulation/run").json()
    assert snap["transitions"] == []


def test_evaluation_endpoint(client):
    rows = client.get("/api/reports/evaluation").json()
    assert len(rows) == 8 and all(r["detection_accuracy"] == 1.0 for r in rows)
