# Results & Evaluation

All numbers below come from real runs (`python -m app.agent.run --all`, the
`/api/reports/evaluation` endpoint, and the test suite). Raw logs are in [sample_runs/](sample_runs/).

## 1. Method

* **8 scenarios** (normal activity plus 7 attack patterns), each with ground-truth labels per device.
* **Detection accuracy** is measured in **passive mode**: the agent detects but does not act, so every
  stage of each attack is observable. Its *peak* threat level per device is compared with the
  label, across all 16 devices × 8 scenarios = **128 classifications**.
* **Response quality** is measured in **active mode** with the performance measure, computed by the
  environment from hidden ground truth:
  `+10 contained · −20 critical-service outage tick · −3 healthy device isolated · −1 tick a compromised device ran free · −5 false-positive incident`.
* Seeds 1, 7, 42 and 123 were run. Results were identical (only background noise changes with the seed).

## 2. Detection (passive mode, all 8 scenarios, 128 device classifications)

| Expected ↓ / Predicted → | Normal | Suspicious | Critical |
|---|---|---|---|
| **Normal** | **112** | 0 | 0 |
| **Suspicious** | 0 | **10** | 0 |
| **Critical** | 0 | 0 | **6** |

Accuracy **100%**. Precision and recall are 1.0 for every class. The same holds for 40 randomly generated
scenarios (`test_passive_detection_on_generated_scenarios` checks 10 of them on every test run).

> Honest caveat: the rules and the scenarios were designed together, so 100% shows the rules are
> *consistent with the labelling policy*, not that they generalise to real attacks. See §5.

## 3. Response (active mode, seed 42)

| Scenario | Score | Contained | Outage ticks | Healthy isolated | Incidents (device: decision → status) |
|---|---|---|---|---|---|
| 1. Normal activity | 0 | 0 | 0 | 0 | none |
| 2. Failed logins | 0 | 0 | 0 | 0 | WS1: MONITOR → resolved (credentials reset) |
| 3. Lateral traffic | 0 | 0 | 0 | 0 | WS2: MONITOR → resolved |
| 4. Compromised WS → server | 4 | 1 | 0 | 0 | WS3: ISOLATE → resolved · DB1: MONITOR → resolved |
| 5. Multiple compromised | 12 | 2 | 0 | 0 | WS2: ISOLATE → resolved · **APP1: RESTRICT → contained** · DB1: MONITOR → resolved |
| 6. Blocked path | 0 | 0 | 0 | 0 | WS4, AUTH1: MONITOR → resolved (A\* route via R3) |
| 7. Isolation constraint | 10 | 2 | 0 | 0 | WS1: ISOLATE → resolved · **AUTH1: RESTRICT → contained** · DB1: MONITOR → resolved |
| 8. Multi-step incident | 10 | 1 | 0 | 0 | WS2: MONITOR → ISOLATE → verified → recovered |

Across all scenarios: **zero critical-service outages, zero healthy devices isolated, zero false-positive
incidents**, and every incident reached a final state. In scenario 7 containment blocked 12 attack events.
In scenario 8 the attacker was isolated in the same tick the compromise was detected (tick 3), so the
later attack stages (unauthorized DB access, exfiltration) never happened.

Score interpretation: the negative part comes from "ticks a compromised device ran free" *before*
detection was possible. In scenarios 4, 5 and 7 the device was compromised before the scenario started
or quietly (stolen credentials), so evidence had to accumulate first. That is a property of the
attack, not a missed response.

## 4. Algorithm-level results

| Algorithm | Result | Evidence |
|---|---|---|
| A\* | Optimal on all 240 ordered device pairs × 3 network variants, checked against Dijkstra | `test_optimal_for_every_pair_on_network` |
| A\* vs uniform-cost | 3 vs 12 nodes expanded (normal), 4 vs 12 (scenario 6) | `astar_demo` |
| Greedy vs A\* | Congested R1–R2: Greedy cost 12, A\* cost 6 | [astar_vs_greedy.txt](sample_runs/astar_vs_greedy.txt) |
| Heuristic | Admissible and consistent for all 16 goals × 3 variants | `test_heuristics.py` |
| CSP heuristics | 8-Queens: 113 → 29 assignments with FC + MRV + LCV + AC-3 | [csp_heuristics_nqueens.txt](sample_runs/csp_heuristics_nqueens.txt) |
| CSP impossibility | Compromised admin PC: proven unsolvable → escalate | [csp_impossible_admin.txt](sample_runs/csp_impossible_admin.txt) |
| Logic | MP and MT proven sound by truth tables; fallacies rejected | [logic_demo.txt](sample_runs/logic_demo.txt) |
| Planning | HTN plan length = BFS-optimal; goal-stack fails on Sussman anomaly | [planning_demo.txt](sample_runs/planning_demo.txt) |

## 5. Limitations

1. **Simulated, scripted attacker.** There's no adaptive adversary, so the agent is never tested against evasion.
2. **Hand-written rules.** They're transparent, but thresholds such as "5 failed logins in 3 ticks" are fixed. A
   slow brute force below the threshold is missed by design (the stealthy scenarios 5 and 7 are caught
   later, through exfiltration and entry-point rules).
3. **Labels and rules come from the same designer**, so the accuracy figures measure consistency, not real-world validity.
4. **One joint CSP per decision.** If it is unsolvable, every pending incident in that batch is escalated, even
   ones that could have been handled alone.
5. **Horn-clause logic only** (no negation in rule bodies, no existential quantifiers).
6. **Goal-stack planning is incomplete** (Sussman anomaly). It is only used where goals don't interact.
7. **Single process, one active run at a time.** It is not designed for concurrency.
