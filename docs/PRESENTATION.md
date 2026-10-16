# Presentation Outline & Live-Demo Script

About 12–15 minutes of slides followed by about 5 minutes of live demo.

## Slides

| # | Slide | Key points |
|---|---|---|
| 1 | Title | SentinelAI: Cyber Defense AI Agent for Simulated Enterprise Networks; names, guide, college |
| 2 | Problem | Too many security alerts; responses must be fast **and** safe **and** explainable |
| 3 | Objective & scope | An agent that detects, explains, contains and verifies, entirely in a simulation |
| 4 | PEAS & environment | PEAS table; partially observable, stochastic-but-seeded, sequential, dynamic |
| 5 | Architecture | Simulator ↔ agent ↔ algorithms; FastAPI; React dashboard; SQLite |
| 6 | The network | 16 devices; services and dependencies; the single auth server; replicas; backup router |
| 7 | Agent loop | Perceive → Reason → Decide (CSP) → Plan (HTN) → Act → Verify (MT) |
| 8 | Search | BFS blast radius, DFS attack paths, Greedy vs A\* (12 vs 6), the heuristic proof |
| 9 | CSP | Variables, domains, 6 constraints; AUTH1 restricted, not isolated; impossible → escalate |
| 10 | Logic | Rules R3/R5/R11, proof tree, Modus Tollens verification |
| 11 | Planning | STRIPS table, HTN tree, goal-stack trace, Sussman anomaly |
| 12 | Results | Confusion matrix (128/128); 0 outages, 0 over-reactions; response table |
| 13 | Limitations & future work | Scripted attacker, hand-written rules, Horn logic only; adaptive attacker, ML detector |
| 14 | Conclusion | Every syllabus topic implemented, used and tested (315 tests) |

## Live demo script (dashboard)

1. **Start** scenario 8 (Multi-step incident), seed 42, Active mode.
2. Press **Step** 3 times (header shows *tick 3*: ticks 0–2 processed). **WS2** turns *Suspicious* from the
   failed-login burst. Show the Incidents tab: the plan is to monitor.
3. **Step** once more (*tick 4*): the successful login at t=3 makes WS2 *Critical*. Open **Reasoning** and read
   the proof tree (R3). Then **CSP**: WS2 = ISOLATE. **Planning**: the HTN tree with the goal-stack trace.
   **Search**: click "show on map" for the A\* admin route.
4. **Step** 2–3 more times: verification passes. Show the Modus Tollens lines in the incident, then the recovery
   actions. Point out the **State** tab transitions s → s′.
5. **Restart** with scenario 7: **Run to end**. Show AUTH1 = RESTRICT (striped node) and the CSP "Values removed"
   list: `AUTH1 ≠ ISOLATE (keep_sole_critical_host)`.
6. **Report** tab: score chart, confusion matrix, then **Run evaluation** for all 8 scenarios.
7. **History** tab: runs are stored in SQLite.

## Backup demo (terminal, if the browser fails)

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m app.agent.run s7_isolation_constraint -v
python -m app.agent.run --all
python -m app.demos.astar_demo --congest R1 R2 10
python -m app.demos.csp_demo admin
python -m app.demos.logic_demo
```
