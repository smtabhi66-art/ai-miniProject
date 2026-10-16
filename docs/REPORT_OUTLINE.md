# Project Report Outline

Suggested structure for the mini-project report (about 35–50 pages). For each section, the
**Source** column says which file in this repository to draw from.

| # | Chapter | Contents | Source |
|---|---|---|---|
| – | Front matter | Title page, certificate, declaration, acknowledgement, abstract (150–250 words), table of contents, list of figures/tables | — |
| 1 | Introduction | Motivation (security teams flooded with alerts; need explainable automated response), problem statement, objectives, scope (simulation only), report organisation | `PROJECT_BRIEF.md` |
| 2 | Literature / background | Intelligent agents (PEAS, agent types); uninformed vs informed search; CSPs; propositional and first-order logic; classical planning (STRIPS, goal-stack, HTN); brief survey of SOAR/IDS tools and why explainability matters | AI textbook (Russell & Norvig), course notes |
| 3 | Requirements & design | Functional and non-functional requirements; PEAS table; environment properties; architecture diagram; module responsibilities; data model; API | `ARCHITECTURE.md` §1–8 |
| 4 | Simulation environment | Topology (16 devices), services and dependencies, events, hidden ground truth, simulated actions with preconditions, the 8 scenarios, random generator, determinism | `ARCHITECTURE.md` §5, `data/scenarios/*.json` |
| 5 | Search | BFS, DFS, A\*, heuristic (with admissibility and consistency proofs), Greedy; traces, complexity, comparison table | `ALGORITHMS.md` §1–5 |
| 6 | Constraint satisfaction | Isolation CSP formulation, propagation, backtracking with heuristics, traces, impossible cases | `ALGORITHMS.md` §6 |
| 7 | Knowledge & reasoning | KB, evidence rules, Horn rules, forward chaining (MP), proof trees, Modus Tollens verification, propositional demo | `ALGORITHMS.md` §7 |
| 8 | Planning | STRIPS domain, goal-based, goal-stack, HTN, Sussman anomaly, CSP→planning link | `ALGORITHMS.md` §8 |
| 9 | Agent integration | The 7-step loop, incident lifecycle, escalation, verification-before-resolution | `ALGORITHMS.md` §9, `agent/agent.py` |
| 10 | Implementation | Tech stack, folder structure, important data structures, API endpoints, dashboard screenshots (one per tab) | `README.md`, dashboard |
| 11 | Testing | Test strategy (unit → algorithm → agent → API), 315 tests by module, notable edge cases | `CHECKLIST.md`, `backend/tests/` |
| 12 | Results & discussion | Confusion matrix, response table, algorithm comparisons, limitations | `RESULTS.md`, `sample_runs/` |
| 13 | Conclusion & future work | What was achieved per objective; extensions (adaptive attacker, ML detector, real IDS dataset) | `RESULTS.md` §5 |
| – | Appendices | Syllabus mapping table, security rules JSON, sample logs, installation guide | `SYLLABUS_MAPPING.md`, `security_rules.json`, `sample_runs/`, `README.md` |

## Figures to include
1. Architecture diagram (`ARCHITECTURE.md` §2, Mermaid)
2. Agent loop sequence diagram (`ARCHITECTURE.md` §11)
3. Network topology (dashboard screenshot)
4. BFS layers / DFS paths on the topology (Search tab, "show on map")
5. A\* vs Greedy route comparison (`astar_demo --congest R1 R2 10`)
6. CSP domains before and after propagation (CSP tab)
7. Proof tree for a Critical classification (Incidents tab)
8. HTN decomposition tree (Planning tab)
9. Score over time and confusion matrix (Report tab)

## Tables to include
PEAS · environment properties · algorithm complexity summary · CSP constraints · security rules ·
STRIPS actions · scenario list · results per scenario · syllabus mapping.
