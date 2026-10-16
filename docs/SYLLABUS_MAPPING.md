# Syllabus → Implementation Mapping

Each topic is listed only if it is **implemented and covered by passing tests**.
**Use:** *Main* = part of the cybersecurity workflow the agent runs; *Demo* = educational
demonstration only. Scenario numbers refer to `backend/data/scenarios/`. Paths are relative to `backend/`.

| Syllabus topic | File | Function / class | Where it runs | Tests | Use |
|---|---|---|---|---|---|
| Intelligent agent, agent–environment loop | `app/agent/agent.py`, `app/simulation/environment.py` | `DefenseAgent.step()`, `NetworkSimulator.step()/execute()` | every scenario | `test_agent.py`, `test_environment.py` | Main |
| Rationality / performance measure | `app/agent/performance.py` | `PerformanceMeter`, `WEIGHTS` | every scenario; Report tab | `test_agent.py::test_active_runs_are_safe` | Main |
| PEAS, partially observable environment | `app/simulation/environment.py` | `HiddenState`, `initial_model()` | S4, S5, S7 | `test_environment.py::test_agent_model_has_no_hidden_information` | Main |
| Model-based agent (internal state) | `app/state/state_manager.py`, `app/agent/agent.py` | `StateManager`, beliefs (`add_belief`) | every scenario | `test_state_manager.py` | Main |
| State space & state transitions | `app/state/state_manager.py`, `app/simulation/actions.py` | `StateManager.apply()`, `diff_states()`, `ACTIONS` | every action; State tab | `test_state_manager.py`, `test_actions.py` | Main |
| BFS | `app/algorithms/search/bfs.py` | `bfs_reachable()`, `bfs_shortest_path()` | investigation (blast radius); simulator reachability; CSP connectivity | `test_bfs.py` | Main |
| DFS | `app/algorithms/search/dfs.py` | `dfs_all_paths()` (main), `dfs_traversal()` (demo) | investigation (attack paths, chokepoints) | `test_dfs.py` | Main |
| A* search | `app/algorithms/search/astar.py`, `costs.py` | `astar()`, `risk_aware_cost()` | investigation (safe admin route); S6 | `test_astar.py` | Main |
| Heuristic function (admissible, consistent) | `app/algorithms/search/heuristics.py` | `hop_lower_bound()`, `admissibility_violations()`, `consistency_violations()` | A\* and Greedy | `test_heuristics.py` | Main |
| Greedy best-first search | `app/algorithms/search/greedy_best_first.py` | `greedy_best_first()` | investigation (likely attacker direction) | `test_greedy.py` | Main |
| Uniform-cost search (baseline) | `app/algorithms/search/astar.py` | `uniform_cost_search()` | `astar_demo` comparison | `test_astar.py` | Demo |
| CSP formulation | `app/agent/isolation_csp.py`, `app/algorithms/csp/csp.py` | `build_isolation_csp()`, `CSP`, `unary/binary/global_constraint` | containment decision; S4, S5, S7 | `test_isolation_csp.py` | Main |
| Backtracking search, MRV, degree, LCV | `app/algorithms/csp/backtracking.py` | `backtracking_search()`, `select_unassigned_variable()`, `order_domain_values()` | containment decision; N-Queens and map colouring | `test_backtracking.py` | Main (LCV: Demo) |
| Constraint propagation (node consistency, AC-3, forward checking) | `app/algorithms/csp/propagation.py` | `node_consistency()`, `ac3()`, `forward_check()` | containment decision | `test_propagation.py` | Main |
| Propositional logic, connectives, truth tables, entailment | `app/algorithms/logic/propositional.py` | `Expr`, `truth_table()`, `tt_entails()` | `logic_demo` | `test_propositional.py` | Demo |
| Knowledge base & security rules | `app/algorithms/logic/knowledge_base.py`, `data/rules/security_rules.json` | `KnowledgeBase`, `load_security_rules()` | detection every tick | `test_inference.py`, `test_detection.py` | Main |
| First-order predicate logic (Horn clauses, unification) | `app/algorithms/logic/predicate.py` | `parse_atom()`, `unify()`, `Rule` | detection every tick | `test_predicate.py` | Main |
| Modus Ponens | `app/algorithms/logic/inference.py` | `forward_chain()`; `propositional.modus_ponens()` | detection every tick | `test_inference.py`, `test_propositional.py` | Main |
| Modus Tollens | `app/algorithms/logic/inference.py`, `app/agent/verification.py` | `modus_tollens()`, `check_containment()` | verification of every contained incident | `test_inference.py`, `test_agent.py::test_verification_pending_failed_passed` | Main |
| STRIPS: states, actions, preconditions, effects | `app/algorithms/planning/strips.py`, `app/agent/response_planning.py` | `Action`, `validate_plan()`, `make_action()` | every incident plan | `test_planning.py` | Main |
| Goal-based planning (forward state-space search) | `app/algorithms/planning/goal_based.py` | `forward_plan()` | `planning_demo`; plan-optimality tests | `test_planning.py` | Demo (validates main plans) |
| Goal-stack planning | `app/algorithms/planning/goal_stack.py` | `goal_stack_plan()` | Contain phase of every isolate/restrict plan | `test_planning.py` | Main |
| Hierarchical planning (HTN) | `app/algorithms/planning/hierarchical.py`, `app/agent/response_planning.py` | `htn_plan()`, `plan_incident()` | every incident | `test_planning.py` | Main |
| Goal test / verification before resolution | `app/agent/agent.py` | `_verify()`, `_close()` | every contained incident | `test_agent.py::test_multi_step_incident_full_lifecycle` | Main |

**Totals:** 315 automated tests, all passing (`cd backend && pytest`).
