"""FastAPI application.

    cd backend
    uvicorn app.main:app --reload --port 8000

Interactive API docs: http://localhost:8000/docs
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import SimulationController, build_router
from app.storage.database import DEFAULT_DB, connect
from app.storage.repository import RunRepository


def create_app(db_path: Path | str = DEFAULT_DB) -> FastAPI:
    app = FastAPI(
        title="SentinelAI",
        description="Cyber Defense AI Agent for a *simulated* enterprise network. No real network is touched.",
        version="1.0.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    controller = SimulationController(RunRepository(connect(db_path)))
    app.state.controller = controller
    app.include_router(build_router(controller))
    return app


app = create_app()
