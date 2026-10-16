# Project Brief (refined)

**Title:** Cyber Defense AI Agent for Simulated Enterprise Networks (SentinelAI)
**Type:** 3rd-year B.E./B.Tech Artificial Intelligence mini project

This is the original project prompt with refinements. The original requirements still apply.
The changes below close gaps that examiners commonly probe in a viva.

## Refinements to the original prompt

| # | Gap in original | Refinement |
|---|---|---|
| 1 | "Rational agent" had no measurable definition | Added a **PEAS** description and a numeric **performance measure** shown live on the dashboard |
| 2 | A* heuristic not specified (network graphs have no coordinates) | `h(n) = hops_to_goal(n) × c_min`, which is provably **admissible and consistent** |
| 3 | Greedy Best-First and A* risked looking identical | Greedy uses `h(n)` only. The demo shows a case where it returns a non-optimal path and A* does not |
| 4 | Modus Tollens had no real role | Used in **verification**: `ActiveCompromise ⇒ MaliciousTraffic`, `¬MaliciousTraffic ⊢ ¬ActiveCompromise` |
| 5 | CSP domain/constraints unspecified | Domain `{ISOLATE, RESTRICT, MONITOR}`, with unary + binary + global constraints, so AC-3 *and* forward checking both matter |
| 6 | "Goal-based", "goal-stack" and "hierarchical" planning could overlap | HTN gives the phase structure, goal-stack expands *Contain*, and the forward BFS planner is the goal-based baseline |
| 7 | No evaluation metrics | Scenarios carry **ground-truth labels**, giving a confusion matrix and precision/recall for the report |
| 8 | Logic scope could be over-claimed | Explicitly **Horn-clause forward chaining with unification**, not full FOL theorem proving |
| 9 | Dependency creep risk | No ORM (stdlib `sqlite3`), JSON configs (no YAML lib), HTTP polling (no websockets). Backend deps: FastAPI, Uvicorn, pytest, httpx |
| 10 | No time plan | 12 milestones over ~10 weeks (see `CHECKLIST.md`) |
| 11 | Event "realism" | Seeded background noise (normal traffic, occasional benign failed logins) so false-positive handling is actually tested |

## Non-negotiables (from the original prompt)

- Simulation only. No real scanning, attacks or blocking. All IPs are simulated labels.
- Algorithms are hand-implemented, with no libraries hiding the logic (no networkx, python-constraint, etc.).
- The dashboard displays real backend output only.
- Development goes one milestone at a time, and each is confirmed before the next starts.
- Every algorithm gets: problem, I/O, implementation, traced example, complexity, edge-case test, justification.

## Stretch goals (only if time remains)

- WebSocket live updates instead of polling
- Exportable PDF incident report
- Scenario editor in the UI
- Side-by-side BFS / Greedy / A* comparison chart (nodes expanded, path cost)
