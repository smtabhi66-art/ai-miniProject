"""SQLite storage (Python's built-in sqlite3, no ORM).

Tables
    runs       one row per simulation run (scenario, seed, mode, final score)
    events     every event the agent perceived
    incidents  final state of every incident (explanation, plan, verification as JSON)
    actions    every simulated action taken (always simulated = 1)
    decisions  every algorithm call the agent logged (inputs/outputs/traces as JSON)
"""
import sqlite3
from pathlib import Path

from app.core.config import BACKEND_DIR

DEFAULT_DB = BACKEND_DIR / "sentinel.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    seed INTEGER NOT NULL,
    mode TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    ticks INTEGER NOT NULL DEFAULT 0,
    final_score INTEGER,
    detection_accuracy REAL,
    report_json TEXT
);
CREATE TABLE IF NOT EXISTS events (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    tick INTEGER NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    target TEXT,
    details_json TEXT,
    PRIMARY KEY (run_id, event_id)
);
CREATE TABLE IF NOT EXISTS incidents (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    incident_id TEXT NOT NULL,
    devices TEXT NOT NULL,
    level TEXT NOT NULL,
    status TEXT NOT NULL,
    decision TEXT,
    opened_tick INTEGER NOT NULL,
    closed_tick INTEGER,
    data_json TEXT NOT NULL,
    PRIMARY KEY (run_id, incident_id)
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tick INTEGER NOT NULL,
    action TEXT NOT NULL,
    params_json TEXT NOT NULL,
    success INTEGER NOT NULL,
    message TEXT,
    simulated INTEGER NOT NULL DEFAULT 1 CHECK (simulated = 1)
);
CREATE TABLE IF NOT EXISTS decisions (
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    decision_id INTEGER NOT NULL,
    tick INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    summary TEXT NOT NULL,
    incident_id TEXT,
    data_json TEXT NOT NULL,
    PRIMARY KEY (run_id, decision_id)
);
"""


def connect(path: Path | str = DEFAULT_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn
