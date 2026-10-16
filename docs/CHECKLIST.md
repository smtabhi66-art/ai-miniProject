# Project Checklist

Legend: ✅ done & tested · ⬜ not done

## Milestones

| # | Milestone | Status | Tests |
|---|---|---|---|
| 1 | Requirements & architecture, folder skeleton, environment | ✅ | smoke test |
| 2 | Network model, state representation, default topology | ✅ | 33 |
| 3 | Network simulator, simulated actions, event generator, 8 scenarios | ✅ | 48 |
| 4 | BFS & DFS (blast radius, attack paths) | ✅ | 38 |
| 5 | A* + heuristic, Greedy Best-First | ✅ | 39 |
| 6 | CSP: backtracking, MRV/LCV, node consistency, AC-3, forward checking | ✅ | 43 |
| 7 | Propositional logic, predicate facts, forward chaining, MP/MT | ✅ | 31 |
| 8 | STRIPS, goal-based, goal-stack, hierarchical (HTN) planning | ✅ | 22 |
| 9 | Agent loop: detection, investigation, CSP, planning, response, verification, performance | ✅ | 51 |
| 10 | FastAPI endpoints + SQLite history | ✅ | 9 |
| 11 | React dashboard (React Flow topology + 8 panels) | ✅ | build + screenshots of every tab |
| 12 | E2E tests, docs, results, report outline, presentation, viva questions | ✅ | full suite: **315 passed** |

## Feature tracker

- [x] Deterministic runs with a seed (`test_same_seed_gives_identical_runs`, `test_runs_are_deterministic`)
- [x] All 8 scenarios run end-to-end, active and passive (`test_agent.py`)
- [x] Every classification has a proof tree (Incidents and Reasoning tabs)
- [x] Every action validated against preconditions (simulator + STRIPS)
- [x] Incident resolved only after verification (Modus Tollens)
- [x] Decision logs, events, actions and incidents persisted to SQLite (`/api/runs`)
- [x] Dashboard shows only backend data (no hardcoded results)
- [x] Syllabus mapping complete with file/function/test references
- [x] Random scenario generation from a seed
- [x] Impossible isolation detected and escalated

## Possible extensions (not required)

- WebSocket live updates instead of request-driven steps
- Scenario editor in the UI
- Learned anomaly detector compared against the rule-based one
- Adaptive attacker (adversarial search) instead of scripted steps
