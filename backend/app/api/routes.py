"""REST API for the dashboard.

The simulation advances only when the client asks (``/step`` or ``/run``).
The dashboard's Play button calls ``/step`` on a timer and Pause stops calling,
so no background threads are needed.
"""
import threading
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.agent.isolation_csp import DEFAULT_BUDGET
from app.agent.session import Session
from app.core.config import DEFAULT_SEED
from app.simulation.scenarios import ScenarioError, list_scenarios
from app.storage.repository import RunRepository


class StartRequest(BaseModel):
    scenario_id: str = "s8_multi_step"
    seed: int | None = DEFAULT_SEED
    mode: str = Field("active", pattern="^(active|passive)$")
    budget: int = Field(DEFAULT_BUDGET, ge=0, le=10)


class SimulationController:
    """Holds the single active session and keeps the database in sync with it."""

    def __init__(self, repo: RunRepository):
        self.repo = repo
        self.lock = threading.Lock()
        self.session: Session | None = None
        self.run_id: int | None = None
        self._positions = (0, 0, 0)

    def start(self, req: StartRequest) -> None:
        with self.lock:
            try:
                if req.scenario_id == "random":
                    from app.simulation.scenarios import generate_scenario
                    scenario = generate_scenario(req.seed if req.seed is not None else DEFAULT_SEED)
                else:
                    from app.simulation.scenarios import load_scenario
                    scenario = load_scenario(req.scenario_id)
            except ScenarioError as exc:
                raise HTTPException(404, str(exc)) from exc
            self.session = Session(scenario, req.seed, act=req.mode == "active", budget=req.budget)
            self.run_id = self.repo.start_run(self.session)
            self._positions = (0, 0, 0)

    def require(self) -> Session:
        if self.session is None:
            raise HTTPException(409, "no simulation started; POST /api/simulation/start first")
        return self.session

    def step(self, ticks: int = 1) -> None:
        with self.lock:
            s = self.require()
            for _ in range(ticks):
                if not s.step():
                    break
            self._persist(s)

    def run_to_end(self) -> None:
        with self.lock:
            s = self.require()
            s.run()
            self._persist(s)

    def reset(self) -> None:
        with self.lock:
            self.session = None
            self.run_id = None

    def _persist(self, s: Session) -> None:
        ev, dec, act = self._positions
        self.repo.save_progress(self.run_id, s, ev, dec, act)
        self._positions = (len(s.manager.event_log), len(s.agent.decisions), len(s.sim.actions))
        if s.finished:
            self.repo.finish_run(self.run_id, s)


def build_router(controller: SimulationController) -> APIRouter:
    router = APIRouter(prefix="/api")

    def snapshot(since: int = 0) -> dict[str, Any]:
        s = controller.require()
        data = s.snapshot(since_tick=since)
        data["run_id"] = controller.run_id
        return data

    @router.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "note": "all actions are simulated"}

    @router.get("/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return [s.to_dict() for s in list_scenarios()]

    @router.post("/simulation/start")
    def start(req: StartRequest) -> dict[str, Any]:
        controller.start(req)
        return snapshot()

    @router.post("/simulation/step")
    def step(ticks: int = Query(1, ge=1, le=100)) -> dict[str, Any]:
        controller.step(ticks)
        return snapshot()

    @router.post("/simulation/run")
    def run() -> dict[str, Any]:
        controller.run_to_end()
        return snapshot()

    @router.post("/simulation/reset")
    def reset() -> dict[str, str]:
        controller.reset()
        return {"status": "reset"}

    @router.get("/state")
    def state(since: int = 0) -> dict[str, Any]:
        return snapshot(since)

    @router.get("/events")
    def events(since: int = 0) -> list[dict[str, Any]]:
        return [e.to_dict() for e in controller.require().manager.event_log if e.tick >= since]

    @router.get("/incidents")
    def incidents() -> list[dict[str, Any]]:
        return [i.to_dict() for i in controller.require().agent.incidents]

    @router.get("/incidents/{incident_id}")
    def incident(incident_id: str) -> dict[str, Any]:
        for inc in controller.require().agent.incidents:
            if inc.id == incident_id:
                logs = [d.to_dict() for d in controller.require().agent.decisions if d.incident == incident_id]
                return {**inc.to_dict(), "decisions": logs}
        raise HTTPException(404, f"no incident {incident_id}")

    @router.get("/decisions")
    def decisions(algorithm: str | None = None, limit: int = Query(200, ge=1, le=5000)) -> list[dict[str, Any]]:
        logs = controller.require().agent.decisions
        if algorithm:
            logs = [d for d in logs if algorithm.lower() in d.algorithm.lower()]
        return [d.to_dict() for d in logs[-limit:]]

    @router.get("/reports/summary")
    def summary() -> dict[str, Any]:
        return controller.require().report()

    @router.get("/reports/evaluation")
    def evaluation(seed: int = DEFAULT_SEED) -> list[dict[str, Any]]:
        """Run every scenario (active and passive) and summarise; nothing is stored."""
        rows = []
        for sc in list_scenarios():
            active = Session(sc, seed).run().report()
            passive = Session(sc, seed, act=False).run().report()
            rows.append({
                "scenario": sc.id, "name": sc.name, "score": active["performance"]["score"],
                "counts": active["performance"]["counts"],
                "detection_accuracy": passive["detection"]["accuracy"],
                "confusion_matrix": passive["detection"]["confusion_matrix"],
                "incidents": [{"device": i["devices"][0], "decision": i["decision"], "status": i["status"]}
                              for i in active["incidents"]],
            })
        return rows

    @router.get("/runs")
    def runs(limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
        return controller.repo.list_runs(limit)

    @router.get("/runs/{run_id}")
    def run_detail(run_id: int) -> dict[str, Any]:
        found = controller.repo.get_run(run_id)
        if found is None:
            raise HTTPException(404, f"no run {run_id}")
        return found

    return router
