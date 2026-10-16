"""Persist simulation runs and read back incident history."""
import json
import sqlite3
from typing import Any

from app.agent.session import Session


class RunRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def start_run(self, session: Session) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs (scenario_id, scenario_name, seed, mode) VALUES (?, ?, ?, ?)",
            (session.scenario.id, session.scenario.name, session.sim.seed, "active" if session.act else "passive"))
        self.conn.commit()
        return cur.lastrowid

    def save_progress(self, run_id: int, session: Session, events_from: int, decisions_from: int,
                      actions_from: int) -> None:
        """Insert everything new since the given positions (called after each step)."""
        for e in session.manager.event_log[events_from:]:
            self.conn.execute("INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
                              (run_id, e.id, e.tick, e.type.value, e.source, e.target, json.dumps(e.details)))
        for d in session.agent.decisions[decisions_from:]:
            self.conn.execute("INSERT OR IGNORE INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                              (run_id, d.id, d.tick, d.algorithm, d.summary, d.incident, json.dumps(d.data, default=str)))
        for a in session.sim.actions[actions_from:]:
            self.conn.execute("INSERT INTO actions (run_id, tick, action, params_json, success, message) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (run_id, a.tick, a.action, json.dumps(a.params), int(a.success), a.message))
        for inc in session.agent.incidents:
            self.conn.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, inc.id, ",".join(inc.devices), inc.level.value, inc.status.value, inc.decision,
                 inc.opened_tick, inc.closed_tick, json.dumps(inc.to_dict())))
        self.conn.execute("UPDATE runs SET ticks = ?, final_score = ? WHERE id = ?",
                          (session.tick, session.meter.score(), run_id))
        self.conn.commit()

    def finish_run(self, run_id: int, session: Session) -> None:
        report = session.report()
        self.conn.execute(
            "UPDATE runs SET finished_at = datetime('now'), ticks = ?, final_score = ?, detection_accuracy = ?, "
            "report_json = ? WHERE id = ?",
            (session.tick, report["performance"]["score"], report["detection"]["accuracy"],
             json.dumps(report, default=str), run_id))
        self.conn.commit()

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT r.id, r.scenario_id, r.scenario_name, r.seed, r.mode, r.started_at, r.finished_at, r.ticks, "
            "r.final_score, r.detection_accuracy, "
            "(SELECT COUNT(*) FROM incidents i WHERE i.run_id = r.id) AS incidents, "
            "(SELECT COUNT(*) FROM actions a WHERE a.run_id = r.id) AS actions "
            "FROM runs r ORDER BY r.id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        run = dict(row)
        run["report"] = json.loads(run.pop("report_json")) if run.get("report_json") else None
        run["incidents"] = [json.loads(r["data_json"]) for r in self.conn.execute(
            "SELECT data_json FROM incidents WHERE run_id = ? ORDER BY incident_id", (run_id,))]
        run["actions"] = [dict(r) for r in self.conn.execute(
            "SELECT tick, action, params_json, success, message, simulated FROM actions WHERE run_id = ? ORDER BY id",
            (run_id,))]
        run["event_count"] = self.conn.execute("SELECT COUNT(*) FROM events WHERE run_id = ?", (run_id,)).fetchone()[0]
        run["decision_count"] = self.conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE run_id = ?", (run_id,)).fetchone()[0]
        return run

    def delete_all(self) -> None:
        self.conn.execute("DELETE FROM runs")
        self.conn.commit()
