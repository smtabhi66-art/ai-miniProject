# SentinelAI: Cyber Defense AI Agent for Simulated Enterprise Networks

An AI mini project: a **model-based, goal-based** defensive agent that monitors a **simulated**
enterprise network. It detects threats with logic rules (and explains every decision with a
proof tree), investigates with BFS, DFS, Greedy and A\*, decides safe containment with a CSP,
plans its response with HTN and goal-stack planning, acts, and verifies the outcome with
Modus Tollens before closing an incident.

> Everything runs inside an in-memory simulation. No real network is scanned, attacked or blocked.
> IP addresses are labels, and every "action" changes Python objects only.

## Quick start (Windows, VS Code terminal)

**1. Backend** (first time only: create the environment and install packages):
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest                                  # 315 tests should pass
```
Run the API server (leave this terminal open):
```powershell
uvicorn app.main:app --reload --port 8000
```
Interactive API docs: http://localhost:8000/docs

**2. Dashboard** (in a *second* terminal; first time only: `npm install`):
```powershell
cd frontend
npm install
npm run dev
```
Open the URL Vite prints (normally http://localhost:5173). Pick a scenario, then press **Start**, then **Step**, **Play** or **Run to end**.

> If PowerShell refuses to run `Activate.ps1`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
> On macOS/Linux use `source .venv/bin/activate`.

## Terminal demos (no browser needed)

Run these from `backend/` with the virtual environment active:

| Command | Shows |
|---|---|
| `python -m app.agent.run --all` | Summary of the agent on all 8 scenarios |
| `python -m app.agent.run s7_isolation_constraint -v` | Tick-by-tick reasoning, CSP, plans, verification |
| `python -m app.agent.run s8_multi_step --passive` | Detection only (no actions) |
| `python -m app.agent.run random --seed 7` | A randomly generated attack |
| `python -m app.demos.search_demo` | BFS and DFS traces |
| `python -m app.demos.astar_demo --congest R1 R2 10` | A\* vs Greedy vs Uniform-cost vs BFS |
| `python -m app.demos.csp_demo [s5\|s7\|replicas\|admin\|router\|budget\|queens]` | CSP propagation and backtracking |
| `python -m app.demos.logic_demo` | Truth tables, entailment, MP/MT, forward chaining |
| `python -m app.demos.planning_demo` | Goal-based vs goal-stack vs HTN, Sussman anomaly |
| `python -m app.simulation.environment s8_multi_step --isolate WS2 --at 7` | The raw simulator (no agent) |

## Project structure

```
SentinelAI/
├── backend/
│   ├── app/
│   │   ├── algorithms/      search/ (BFS, DFS, A*, Greedy, heuristics) · csp/ · logic/ · planning/
│   │   ├── agent/           agent loop, detection, investigation, isolation CSP, response planning,
│   │   │                    verification, performance, session, run (CLI)
│   │   ├── simulation/      topology loader, environment (hidden ground truth), actions, scenarios, events
│   │   ├── models/ state/   data model and the agent's internal state (StateManager)
│   │   ├── api/ storage/    FastAPI routes and SQLite persistence
│   │   ├── demos/           educational command-line demos
│   │   └── main.py          FastAPI app
│   ├── data/                topology, 8 scenarios, security rules (all JSON, editable)
│   └── tests/               315 pytest tests
├── frontend/                React + React Flow dashboard (Vite)
└── docs/                    design, algorithms, results, report outline, slides, viva prep
```

## Documentation

| Document | For |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | PEAS, architecture, data model, API, agent workflow |
| [ALGORITHMS.md](docs/ALGORITHMS.md) | Every algorithm: problem, I/O, trace, complexity, edge cases, why |
| [RESULTS.md](docs/RESULTS.md) | Evaluation: confusion matrix, response table, limitations |
| [SYLLABUS_MAPPING.md](docs/SYLLABUS_MAPPING.md) | Syllabus topic → file → function → scenario → test |
| [REPORT_OUTLINE.md](docs/REPORT_OUTLINE.md) | Chapter plan for the project report |
| [PRESENTATION.md](docs/PRESENTATION.md) | Slide outline and live-demo script |
| [VIVA_QUESTIONS.md](docs/VIVA_QUESTIONS.md) | 35 likely viva questions with answers |
| [CHECKLIST.md](docs/CHECKLIST.md) | Milestones and features |
| [PROJECT_BRIEF.md](docs/PROJECT_BRIEF.md) | Refined requirements |
| [sample_runs/](docs/sample_runs/) | Real output logs for the report |

## Tech stack
Python 3.10+ · FastAPI · SQLite (stdlib `sqlite3`) · pytest · React 18 · React Flow (`@xyflow/react`) · Vite.
All AI algorithms are implemented from scratch (no networkx, no constraint or logic libraries).
