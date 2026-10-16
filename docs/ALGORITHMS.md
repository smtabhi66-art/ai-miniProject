# Algorithms

Each section covers: the problem it solves in SentinelAI, its input and output, where it is
implemented, a small worked example with an execution trace, its complexity, the edge-case
tests, and why this algorithm fits the problem.

All search algorithms run on `Graph` ([graph.py](../backend/app/algorithms/search/graph.py)):
an undirected adjacency list `node -> {neighbour: edge cost}`. `graph_from_network()`
builds it from the agent's `NetworkState`, keeping only **usable** parts: blocked links
are dropped, and isolated or offline devices keep no edges.

The worked examples use this small graph (`DIAMOND` in the tests):

```
A --- B
|     |
C --- D --- E
```

---

## 1. Breadth-First Search (BFS)

| | |
|---|---|
| **Problem** | *Blast radius*: which devices can a compromised device reach, and how many hops away is each? Also used by the simulator to check whether any usable path exists between two devices. |
| **Input** | `Graph`, `start` node, optional `max_depth`, optional `goal` |
| **Output** | `BFSResult`: `depth` (hops per node), `parent` (for paths), `order`, `layers()`, `path_to()`, `trace` |
| **Code** | [bfs.py](../backend/app/algorithms/search/bfs.py): `bfs()`, `bfs_reachable()`, `bfs_shortest_path()` |
| **Data structures** | FIFO queue (`collections.deque`), `depth` dict (also serves as the visited set), `parent` dict |
| **Time** | O(V + E): each node is enqueued once and each edge checked from both ends |
| **Space** | O(V) |
| **Used in** | Investigation step of the agent (M9); simulator reachability check (`environment._path_exists`); A\* heuristic (M5) |

### Trace on DIAMOND from A

| Step | Dequeue | Queue after (front first) | Visited | Note |
|---|---|---|---|---|
| 1 | A | [B, C] | A | enqueue B, C |
| 2 | B | [C, D] | A, B | enqueue D; A already seen |
| 3 | C | [D] | A, B, C | D already seen, so not added twice |
| 4 | D | [E] | A, B, C, D | enqueue E |
| 5 | E | [] | A, B, C, D, E | done |

Layers: `0: A · 1: B, C · 2: D · 3: E`. Shortest path to E: `A → B → D → E`.

### On the enterprise network (blast radius of WS2)

```
0 hop(s): WS2
1 hop(s): R1
2 hop(s): FW1, WS1, WS3, WS4, ADMIN1, R2, R3
3 hop(s): INET, WEB1, WEB2, APP1, DB1, DB2, AUTH1
```

If R1 is isolated, the blast radius of WS2 becomes empty (`test_isolating_router_contains_blast_radius`).

### Edge-case tests ([test_bfs.py](../backend/tests/test_bfs.py))
`max_depth=0` returns only the start · a disconnected node is unreachable (`None` path) ·
start == goal · unknown nodes raise `KeyError` · negative depth is rejected · a blocked link
forces the backup route through R3.

### Why BFS here
The blast radius is defined by hop count ("devices within 2 hops"), and BFS discovers nodes in
increasing hop order, so its first path to every node has the fewest hops. DFS would find
*some* path, not necessarily the shortest one.

---

## 2. Depth-First Search (DFS)

| | |
|---|---|
| **Problem** | *Attack paths*: every route an attacker on a compromised device could take to reach a critical asset. This shows which routers and links the attack depends on. |
| **Input** | `Graph`, `start`, set of `goals`, optional `max_depth`, `max_paths` (default 1000) |
| **Output** | `DFSPathsResult`: `paths`, `nodes_expanded`, `truncated`, `trace` |
| **Code** | [dfs.py](../backend/app/algorithms/search/dfs.py): `dfs_all_paths()` (main workflow), `dfs_traversal()` (educational) |
| **Data structures** | Explicit LIFO stack of `(node, path)` pairs, so the stack appears in the trace instead of being hidden in recursion |
| **Time** | Traversal O(V + E). All simple paths: O(b^d) worst case (exponential), bounded by `max_depth` and `max_paths` |
| **Space** | O(d) per stacked path, where d is the path length |
| **Used in** | Investigation step of the agent (M9) |

### Trace: all paths A → E on DIAMOND

| Step | Pop | Action | Stack after (top first) | Current path | Note |
|---|---|---|---|---|---|
| 1 | A | expand | [B, C] | A | push B, C |
| 2 | B | expand | [D, C] | A, B | push D |
| 3 | D | expand | [C, E, C] | A, B, D | push C, E |
| 4 | C | expand | [E, C] | A, B, D, C | dead end, backtrack |
| 5 | E | **goal** | [C] | A, B, D, E | **path 1: A → B → D → E** |
| 6 | C | expand | [D] | A, C | push D |
| 7 | D | expand | [B, E] | A, C, D | push B, E |
| 8 | B | expand | [E] | A, C, D, B | dead end, backtrack |
| 9 | E | **goal** | [] | A, C, D, E | **path 2: A → C → D → E** |

C appears twice on the stack (steps 3–6). That is intentional: path-DFS tracks visited nodes
**per path** (simple paths), not globally, because the same device can lie on different attack
routes. Plain `dfs_traversal()` uses a global visited set and visits each node once:
`A, B, D, C, E` (compare BFS: `A, B, C, D, E`).

### On the enterprise network
Attack paths from WS2 to DB1:
```
WS2 -> R1 -> R2 -> DB1
WS2 -> R1 -> R3 -> R2 -> DB1
```
After blocking R1–R2, only the route through R3 remains. To WS2 *all* critical hosts there are
10 paths. Every server-zone path passes through R1 and R2, which makes them the key chokepoints.

### Edge-case tests ([test_dfs.py](../backend/tests/test_dfs.py))
Paths are simple (no repeated node) · a path stops at the first goal it reaches · `max_depth`
prunes long paths · start is a goal → `[[start]]` · unreachable goal → `[]` · on a complete
graph K7 there are 326 paths from one node to another, and `max_paths=10` truncates and sets
`truncated=True` · unknown nodes raise `KeyError`.

### Why DFS here
We need **all** routes, not just the shortest. DFS with backtracking enumerates them while
holding only one path at a time, whereas BFS would hold every partial path in its queue. The
exponential worst case is real, so it is bounded explicitly.

---

## BFS vs DFS (viva summary)

| | BFS | DFS |
|---|---|---|
| Frontier | Queue (FIFO) | Stack (LIFO) |
| Explores | Level by level | One branch as deep as possible, then backtracks |
| Finds | Fewest-hop path | Some path first; with backtracking, *all* simple paths |
| Memory | O(V), the whole frontier level | O(depth) for one path |
| Complete? | Yes (finite graph) | Yes on finite graphs with cycle checking |
| Optimal? | Yes for hop count (unit costs) | No |
| SentinelAI use | Blast radius, reachability | Attack-path enumeration |

---

## 3. Heuristic function (for A* and Greedy)

| | |
|---|---|
| **Problem** | A network has no coordinates, so "straight-line distance" doesn't exist. Informed search still needs a cheap estimate of the remaining cost. |
| **Definition** | `h(n) = hops(n, goal) × c_min`. `hops` comes from one BFS from the goal; `c_min` is the cheapest edge cost in the graph |
| **Code** | [heuristics.py](../backend/app/algorithms/search/heuristics.py): `hop_lower_bound()`, plus `admissibility_violations()` and `consistency_violations()` to verify it |
| **Cost to compute** | One BFS: O(V + E), then O(1) per lookup |

**g(n) vs h(n).** `g(n)` is the *actual* cost of the path found so far from the start to `n`.
`h(n)` is an *estimate* of the cost still to go from `n` to the goal. A\* orders its open list by
`f(n) = g(n) + h(n)`, the estimated total cost of the cheapest solution through `n`.

**Proof of admissibility** (h never overestimates): any path from `n` to the goal has at least
`hops(n, goal)` edges, and every edge costs at least `c_min`, so true cost ≥ `hops × c_min = h(n)`.

**Proof of consistency** (`h(n) ≤ cost(n, n') + h(n')` for every edge): neighbours differ by at most
one hop, so `hops(n) ≤ hops(n') + 1`, which gives `h(n) ≤ h(n') + c_min ≤ h(n') + cost(n, n')`.
So A\* never has to reopen a closed node.

**Tested, not just claimed:** `test_admissible_for_every_goal` and `test_consistent_for_every_goal`
check every one of the 16 goals on the normal network, the blocked-link network and the risk-weighted
network, comparing against exact Dijkstra costs.

Heuristic vs true cost for goal DB1 (normal network, c_min = 1):

| node | ADMIN1 | R1 | R2 | R3 | APP1 | DB1 | INET |
|---|---|---|---|---|---|---|---|
| h(n) | 3 | 2 | 1 | 2 | 2 | 0 | 4 |
| true cost | 4 | 3 | 1 | 3 | 2 | 0 | 9 |

### Risk-aware edge costs ([costs.py](../backend/app/algorithms/search/costs.py))
```
cost(a, b) = latency_cost + 2 × link.risk + 5 × max(risk_score(a), risk_score(b))
```
Symmetric (so the graph stays undirected) and always > 0. Devices the agent believes are compromised
(`ThreatLevel.CRITICAL`) are passed to A\* as `forbidden`, so safe routes never cross them.

---

## 4. A* search

| | |
|---|---|
| **Problem** | Cheapest, lowest-risk route, e.g. a management route from ADMIN1 to a server, avoiding blocked links, isolated devices and compromised devices |
| **Input** | `Graph`, `start`, `goal`, heuristic `h`, optional `forbidden` nodes |
| **Output** | `PathResult`: `path`, `cost`, `nodes_expanded`, `trace` (open list with f-values at each step) |
| **Code** | [astar.py](../backend/app/algorithms/search/astar.py): `astar()`, `uniform_cost_search()` (A\* with h = 0) |
| **Data structures** | Binary heap (`heapq`) of `(f, h, counter, node)`, `g` dict, `parent` dict, closed set |
| **Time / space** | O(E log V) / O(V) worst case; a good heuristic expands fewer nodes |
| **Optimal?** | Yes, with an admissible heuristic |
| **Used in** | Scenario 6 (alternative route), response planning (M9) |

### Trace on the TRAP graph, S → G

```
S --1-- A --10-- G
|                |
2                2
|                |
B ------2------- C
```

| Step | Expand | g | h | f | Open list after | Note |
|---|---|---|---|---|---|---|
| 1 | S | 0 | 2 | 2 | A(f=2), B(f=4) | |
| 2 | A | 1 | 1 | 2 | B(f=4), G(f=11) | G first reached via the expensive edge, g = 11 |
| 3 | B | 2 | 2 | 4 | C(f=5), G(f=11) | |
| 4 | C | 4 | 1 | 5 | G(f=6) | **cheaper route to G found: g = 6** |
| 5 | G | 6 | 0 | 6 | – | goal popped, optimal |

Result: `S → B → C → G`, cost 6. A\* did *not* stop when it first saw G at cost 11, because G was
not yet the lowest-f node.

### On the enterprise network (ADMIN1 → DB1)

| Situation | A\* route | Cost | A\* expanded | Uniform-cost expanded |
|---|---|---|---|---|
| Normal | ADMIN1 → R1 → R2 → DB1 | 4 | 3 | 12 |
| R1–R2 blocked (scenario 6) | ADMIN1 → R1 → R3 → R2 → DB1 | 6 | 4 | 12 |
| R1–R2 congested (cost 10) | ADMIN1 → R1 → R3 → R2 → DB1 | 6 | 9 | 12 |
| R1–R2 blocked **and** R3 forbidden | no route, so the agent escalates | – | 10 | 10 |

### Edge-case tests ([test_astar.py](../backend/tests/test_astar.py))
start == goal (cost 0) · unreachable goal · unknown node · forbidden nodes · everything forbidden ·
**an inconsistent but admissible heuristic still returns the optimal cost (node reopening)** · optimal
for **all 240 ordered pairs** on three network variants, checked against Dijkstra · never expands
more nodes than uniform-cost search.

### Why A* here
The agent needs the *cheapest* route, not merely the one with the fewest hops. That rules out BFS
and DFS. Uniform-cost search would also be optimal, but it explores blindly in every direction.
The heuristic focuses A\* on the goal, and it remains optimal because the heuristic is admissible.

---

## 5. Greedy Best-First Search

| | |
|---|---|
| **Problem** | Fast investigation lead: which way is the attacker most directly heading towards a crown-jewel asset? |
| **Input / output** | Same as A\* (`PathResult`) |
| **Code** | [greedy_best_first.py](../backend/app/algorithms/search/greedy_best_first.py): `greedy_best_first()` |
| **Priority** | `h(n)` only; the cost already paid, `g(n)`, is ignored |
| **Time / space** | O(E log V) / O(V) worst case; often about d expansions |
| **Optimal?** | **No.** Complete on finite graphs (with a closed set) |

### Trace on TRAP, S → G

| Step | Expand | h | Open list after | Note |
|---|---|---|---|---|
| 1 | S | 2 | A(h=1), B(h=2) | A *looks* closer |
| 2 | A | 1 | G(h=0), B(h=2) | |
| 3 | G | 0 | B(h=2) | goal: **S → A → G, cost 11** (A\* found cost 6) |

### On the network: congested R1–R2 link (`astar_demo --congest R1 R2 10`)

| Algorithm | Route | Cost | Expanded |
|---|---|---|---|
| BFS (fewest hops) | ADMIN1 → R1 → R2 → DB1 | 12 | – |
| Uniform-cost | ADMIN1 → R1 → R3 → R2 → DB1 | 6 | 12 |
| **Greedy** | ADMIN1 → R1 → R2 → DB1 | **12** | **3** |
| **A\*** | ADMIN1 → R1 → R3 → R2 → DB1 | **6** | 9 |

Greedy is the fastest but pays double, because R2 *looks* one hop from DB1 and the slow link is
invisible to `h`.

### Why Greedy here (and only here)
The agent uses Greedy where speed matters more than exactness: getting a first investigation lead
on where the attacker is heading. Routes the agent actually **acts on** always come from A\*.

---

## Informed vs uninformed search (viva summary)

| Algorithm | Priority / frontier | Optimal for cost? | Uses heuristic? | SentinelAI use |
|---|---|---|---|---|
| BFS | FIFO queue | Only for hop count | No | Blast radius, reachability |
| DFS | LIFO stack | No | No | All attack paths |
| Uniform-cost | g(n) | Yes | No | Baseline for comparison |
| Greedy best-first | h(n) | **No** | Yes | Fast investigation lead |
| **A\*** | g(n) + h(n) | **Yes** (admissible h) | Yes | Safe routes the agent acts on |

---

## 6. Constraint Satisfaction (CSP): safe isolation

| | |
|---|---|
| **Problem** | For each device the agent distrusts: ISOLATE, RESTRICT or MONITOR? The choice must not break critical services, must keep a recovery path and must stay within a disruption budget. If that's impossible, the agent should escalate. |
| **Input** | `NetworkState`, suspects `{device: Suspicious/Critical}`, isolation budget K |
| **Output** | `IsolationResult`: decision per device, or a failure with the constraints that blocked every option; plus domains before/after propagation, search trace and stats |
| **Code** | Generic solver: [csp.py](../backend/app/algorithms/csp/csp.py), [propagation.py](../backend/app/algorithms/csp/propagation.py), [backtracking.py](../backend/app/algorithms/csp/backtracking.py). Formulation: [isolation_csp.py](../backend/app/agent/isolation_csp.py) |
| **Data structures** | Domains `dict[var, list]`, constraint index `dict[var, list[Constraint]]`, arc queue (`deque`) for AC-3, recursion stack for backtracking |

### Formulation

**Variables:** one per internal, still-connected device rated Suspicious or Critical.

**Domains** (in preference order, which the solver tries first):

| Rating | Domain |
|---|---|
| Critical | ISOLATE, RESTRICT, MONITOR (contain first) |
| Suspicious | MONITOR, RESTRICT, ISOLATE (disrupt least first) |

**Constraints:**

| # | Name | Type | Rule |
|---|---|---|---|
| C1 | `restrict_needs_service` | unary | device hosts no service ⇒ X ≠ RESTRICT |
| C2 | `contain_compromised` | unary | rated Critical ⇒ X ≠ MONITOR |
| C3 | `keep_sole_critical_host` | unary | last available host of a critical service ⇒ X ≠ ISOLATE |
| C4 | `keep_one_replica` | binary (n-ary if >2) | ¬(X_DB1 = ISOLATE ∧ X_DB2 = ISOLATE) |
| C5 | `admin_can_reach_services` | global | ADMIN1 still reaches every critical host it reaches now (BFS) |
| C6 | `isolation_budget` | global | count(ISOLATE) ≤ K |

Global constraints are checked on partial assignments. That is sound because they are
**monotone**: isolating more devices can never repair a violation.

### Solving pipeline

1. **Node consistency** applies the unary constraints C1–C3.
2. **AC-3** makes the binary constraints arc-consistent (C4).
3. **Backtracking** with **MRV** (fewest values left; ties broken by degree) and **forward checking**
   (after each assignment, remove conflicting values from neighbours; an empty domain means backtrack now).
4. **LCV** is implemented and tested, but switched off here, because the domain order encodes the
   security preference and LCV would replace it with "least constraining".

### Trace: scenario 7 (WS1 and AUTH1 compromised)

| Stage | Result |
|---|---|
| Initial | AUTH1: [ISOLATE, RESTRICT, MONITOR] · WS1: [ISOLATE, RESTRICT, MONITOR] |
| Node consistency | AUTH1 ≠ MONITOR (C2) · AUTH1 ≠ ISOLATE (C3, only auth host) · WS1 ≠ RESTRICT (C1) · WS1 ≠ MONITOR (C2) |
| After preprocessing | AUTH1: [RESTRICT] · WS1: [ISOLATE] |
| Search | assign AUTH1 = RESTRICT → assign WS1 = ISOLATE → solution (0 backtracks) |
| **Decision** | **WS1 → ISOLATE, AUTH1 → RESTRICT** (AUTH1 cannot be isolated: app and web depend on auth) |

### Trace: both database replicas compromised (forward checking at work)

| Step | Action | Effect |
|---|---|---|
| 1 | assign DB1 = ISOLATE | forward checking prunes DB2 ≠ ISOLATE (C4) |
| 2 | assign DB2 = RESTRICT | solution |

### Impossible cases (the agent escalates)

| Case | Why there is no solution |
|---|---|
| ADMIN1 compromised | It can't be MONITORED (C2) or RESTRICTED (C1), and ISOLATING it cuts the recovery path (C5) |
| R2 compromised | Every server hangs off R2, so isolating it disconnects them all (C5) |
| R3 compromised **and** R1–R2 down | R3 is then the only route to the servers (C5) |
| 3 workstations compromised, K = 2 | Each must be ISOLATED (C1 + C2), but the budget allows 2 (C6) |

### Heuristics comparison: 8-Queens (`csp_demo queens`)

| Configuration | Assignments | Backtracks |
|---|---|---|
| Plain backtracking | 113 | 105 |
| + forward checking | 53 | 45 |
| + forward checking + MRV | 52 | 44 |
| + forward checking + MRV + LCV + AC-3 | 29 | 21 |

### Complexity

| Part | Time |
|---|---|
| Backtracking | O(dⁿ) worst case (n variables, domain size d) |
| Node consistency | O(n·d) |
| AC-3 | O(e·d³) for e binary constraints |
| Forward checking | O(e·d) per assignment (global constraints add a BFS each check: O(V+E)) |

The isolation CSP is small (n ≤ number of suspects, d = 3), so this is fast in practice.

### Edge-case tests
[test_propagation.py](../backend/tests/test_propagation.py), [test_backtracking.py](../backend/tests/test_backtracking.py),
[test_isolation_csp.py](../backend/tests/test_isolation_csp.py): AC-3 propagates along a chain
(A<B<C → 1,2,3) · AC-3 detects an empty domain · AC-3 alone cannot see global constraints · forward
checking detects dead ends early · 2-colouring Australia and 3-Queens are proven impossible · empty
domain after preprocessing reports the responsible constraints · no suspects → empty decision ·
replica constraint is skipped when a healthy replica exists · a replica becomes the "sole host" when
its twin is already down · every solution found is checked against all constraints.

### Why a CSP here
The decision is a combination of choices tied together by hard rules ("not both replicas", "keep
the admin path"). Trying all 3ⁿ combinations wastes effort, and greedy per-device decisions can
break a rule. A CSP states the rules declaratively, propagation removes impossible options early,
and backtracking either finds a valid combination or **proves none exists**. That proof is what
lets the agent escalate instead of taking an unsafe action.

---

## 7. Knowledge representation & logic

| | |
|---|---|
| **Problem** | Turn raw events into a classification (Normal / Suspicious / Critical) **with a reason**, and later prove that containment worked |
| **Code** | [propositional.py](../backend/app/algorithms/logic/propositional.py), [predicate.py](../backend/app/algorithms/logic/predicate.py), [knowledge_base.py](../backend/app/algorithms/logic/knowledge_base.py), [inference.py](../backend/app/algorithms/logic/inference.py); domain: [detection.py](../backend/app/agent/detection.py), [verification.py](../backend/app/agent/verification.py), [security_rules.json](../backend/data/rules/security_rules.json) |
| **Representation** | Atoms `(predicate, args...)`, e.g. `Connected(WS1, R1)`, `Compromised(WS2)`; variables start with `?`; Horn rules `P1 ∧ … ∧ Pn ⇒ Q` |
| **Inference** | Forward chaining = repeated (generalised) **Modus Ponens** with unification; **Modus Tollens** for verification |
| **Data structures** | Fact set plus an index `predicate → facts` (dict of sets); proof record per fact (dict); rule list |

### 7.1 Propositional logic (educational, `logic_demo`)
Symbols, connectives (¬ ∧ ∨ → ↔), truth tables, and entailment by model checking (`tt_entails`).
The tests prove both inference rules sound with truth tables:

* Modus Ponens: `((BruteForce ∧ LoginSuccess) → Compromised) ∧ BruteForce ∧ LoginSuccess ⊨ Compromised` ✓
* Modus Tollens: `(Compromised → MaliciousTraffic) ∧ ¬MaliciousTraffic ⊨ ¬Compromised` ✓
* Fallacies are rejected: affirming the consequent and denying the antecedent are **not** entailed.

### 7.2 Where facts come from (each tick)

| Source | Examples | How |
|---|---|---|
| Topology | `Internal(WS1)`, `External(INET)`, `CriticalAsset(DB1)`, `Hosts(AUTH1, auth)`, `Connected(R1, R2)` | From the network model |
| Evidence | `BruteForcing(INET, WS2)`, `LoggedIn(INET, WS2)`, `Scanning(WS4)`, `SustainedUnusualTraffic(AUTH1, DB1)` | **Evidence rules**: count events of a type in a sliding window and compare with a threshold (configurable JSON) |
| Beliefs | `Compromised(WS2)` | Conclusions the agent keeps between ticks until the device is recovered |

### 7.3 Security rules (first-order Horn clauses)

| Rule | Premises ⇒ conclusion |
|---|---|
| R1 | `FailedLoginBurst(?t) ⇒ UnderAttack(?t)` |
| R2 | `BruteForcing(?s, ?t) ⇒ Attacker(?s)` |
| R3 | `BruteForcing(?s, ?t) ∧ LoggedIn(?s, ?t) ⇒ Compromised(?t)` |
| R4 | `Attacker(?s) ∧ Internal(?s) ⇒ Compromised(?s)` |
| R5 | `UnauthorizedAccess(?s, ?t) ∧ SustainedUnusualTraffic(?s, ?t) ∧ CriticalAsset(?t) ⇒ Compromised(?s)` |
| R6 | `UnauthorizedAccess(?s, ?t) ⇒ Targeted(?t)` |
| R7–R9 | Scanning / unusual traffic / unauthorized access ⇒ `Anomalous(?s)` |
| R10 | `Compromised(?d) ∧ UnusualTraffic(?d, ?a) ∧ CriticalAsset(?a) ⇒ ThreatensCriticalAsset(?d, ?a)` |
| R11 | `Compromised(?t) ∧ LoggedIn(?s, ?t) ∧ Internal(?s) ⇒ Compromised(?s)` (entry-point tracing) |
| M1–M4 | each kind of attack behaviour ⇒ `MaliciousActivity(?d)` |
| V1 | `ActiveCompromise(?d) ⇒ MaliciousActivity(?d)` (attacker model, used by Modus Tollens) |

**Classification:** `Compromised` ⇒ Critical; `UnderAttack`, `Attacker`, `Targeted`, `Anomalous` ⇒ Suspicious; otherwise Normal.

### 7.4 Trace: scenario 7, tick 6 (forward chaining)
```
[modus ponens] R5: UnauthorizedAccess(AUTH1, DB1) ∧ SustainedUnusualTraffic(AUTH1, DB1) ∧ CriticalAsset(DB1) ⊢ Compromised(AUTH1)
[modus ponens] R11: Compromised(AUTH1) ∧ LoggedIn(WS1, AUTH1) ∧ Internal(WS1) ⊢ Compromised(WS1)
```
Proof tree shown on the dashboard for WS1:
```
Compromised(WS1)  [derived by R11_entry_point]
  Compromised(AUTH1)  [derived by R5_exfiltration]
    UnauthorizedAccess(AUTH1, DB1)  [observed: 1 unauthorized_access event(s) in ticks 4-6]
    SustainedUnusualTraffic(AUTH1, DB1)  [observed: 2 unusual_traffic event(s) in ticks 5-6]
    CriticalAsset(DB1)  [topology]
  LoggedIn(WS1, AUTH1)  [observed: 1 successful_login event(s) in ticks 2-6]
  Internal(WS1)  [topology]
```

### 7.5 Modus Tollens in verification
After containment the agent re-derives `MaliciousActivity(d)` using **only events after the
containment tick**. If it stays false for 2 ticks:
```
Rule V1: ActiveCompromise(?d) ⇒ MaliciousActivity(?d)
[modus tollens] V1: ¬MaliciousActivity(WS1) ⊢ ¬ActiveCompromise(WS1)
```
Only after this proof does the agent recover the device and resolve the incident.

### 7.6 Complexity
Unification: O(k) for arity k. Forward chaining: each round costs at most O(r · f^p) (r rules, f facts,
p premises per rule; premises are joined left to right with backtracking), and there are at most as many
rounds as ground facts that can be derived. Here r = 16, p ≤ 3 and f ≈ 70, so a tick takes milliseconds.
Propositional model checking: O(2ⁿ).

### 7.7 Edge-case tests
[test_propositional.py](../backend/tests/test_propositional.py), [test_predicate.py](../backend/tests/test_predicate.py),
[test_inference.py](../backend/tests/test_inference.py), [test_detection.py](../backend/tests/test_detection.py):
inconsistent bindings in a join don't fire (brute force on WS1 + login on WS2) · chaining through derived facts ·
fixpoint is idempotent · unsafe rules rejected · contradictions rejected · Modus Tollens refuses multi-premise rules ·
events older than a device's recovery are ignored · a single mistyped password stays Normal.

### 7.8 Honest scope
This is the **Horn-clause (Datalog-style) subset of first-order logic** with forward chaining.
It has no function symbols, no existential quantifiers and no resolution theorem prover. That
subset is decidable, fast and fully explainable, which is what a security agent needs.

---

## 8. Planning

| | |
|---|---|
| **Problem** | Turn a containment decision into a correct, ordered sequence of actions: Detect → Investigate → Contain → Verify → Recover |
| **Code** | [strips.py](../backend/app/algorithms/planning/strips.py), [goal_based.py](../backend/app/algorithms/planning/goal_based.py), [goal_stack.py](../backend/app/algorithms/planning/goal_stack.py), [hierarchical.py](../backend/app/algorithms/planning/hierarchical.py); domain: [response_planning.py](../backend/app/agent/response_planning.py) |
| **Representation** | State = set of ground literals (closed world). Action = (pre, add, delete). `apply(s) = (s − delete) ∪ add` |

### 8.1 STRIPS actions (device d)

| Action | Preconditions | Add | Delete |
|---|---|---|---|
| collect_evidence | Detected | EvidenceCollected | |
| analyze_blast_radius | EvidenceCollected | Investigated | |
| approve_isolation | Investigated, CSPAllows(d, ISOLATE) | IsolationApproved | |
| isolate_device | IsolationApproved, Online | Isolated, Contained | Online |
| approve_restriction | Investigated, CSPAllows(d, RESTRICT) | RestrictionApproved | |
| restrict_device | RestrictionApproved, Online | Restricted, Contained | Online |
| increase_monitoring | EvidenceCollected | Monitored | |
| verify_containment | Contained | Verified | |
| verify_quiet | Monitored | Verified | |
| remediate_device | Isolated, Verified | Clean | |
| reset_credentials | Verified | CredentialsReset | |
| restore_device | Isolated, Clean, CredentialsReset | Online, Recovered | Isolated |
| escalate | Detected | Escalated | |

The **CSP's decision enters planning as a fact** (`CSPAllows(d, X)`), so the planner can only pick
containment actions the constraint solver proved safe.

### 8.2 The three planners

| Planner | How | Role in SentinelAI |
|---|---|---|
| **Goal-based** (forward BFS) | Breadth-first search over states until goal ⊆ state; the first plan found is shortest | Baseline; checks HTN plans are optimal in length (tests) |
| **Goal-stack** | Push goal and sub-goals; pop: satisfied → drop, false → push an achieving action + its preconditions; apply actions when their preconditions hold; re-push broken conjunctions | Expands the **Contain** phase. Uses relaxed reachability (deletes ignored) so it never chooses an action whose preconditions can't be achieved |
| **Hierarchical (HTN)** | Compound tasks are refined by methods chosen by the current state; primitive tasks are STRIPS actions; backtracks over methods | Overall incident plan: `HandleIncident → Detect, Investigate, Contain, Verify, Recover` |

### 8.3 Goal-stack trace: goal `Contained(WS1)` with `CSPAllows(WS1, ISOLATE)`
```
Contained(WS1): false -> choose isolate_device(WS1), push its preconditions
IsolationApproved(WS1): false -> choose approve_isolation(WS1), push its preconditions
CSPAllows(WS1, ISOLATE): already true
Investigated(WS1): false -> choose analyze_blast_radius(WS1), push its preconditions
EvidenceCollected(WS1): false -> choose collect_evidence(WS1), push its preconditions
Detected(WS1): already true
apply collect_evidence(WS1) -> apply analyze_blast_radius(WS1) -> apply approve_isolation(WS1)
Online(WS1): already true -> apply isolate_device(WS1)
```

### 8.4 HTN tree (WS1, decision ISOLATE)
```
HandleIncident(WS1)  [method: full]
  Detect(WS1)  [method: collect]           • collect_evidence(WS1)
  Investigate(WS1)  [method: analyze]      • analyze_blast_radius(WS1)
  Contain(WS1)  [method: by_goal_stack]    • approve_isolation(WS1)  • isolate_device(WS1)
  Verify(WS1)  [method: containment]       • verify_containment(WS1)
  Recover(WS1)  [method: isolated]         • remediate_device  • reset_credentials  • restore_device
```
Other methods: `Contain → monitor` (CSP said MONITOR), `Contain → escalate` (no safe option),
`Recover → restricted` (sole critical host: reset credentials, hand over for maintenance),
`HandleIncident → resume` (threat level rose after investigation: skip Detect and Investigate).

### 8.5 Goal-stack limitation: the Sussman anomaly
On the blocks-world Sussman anomaly, forward BFS finds the optimal 6-step plan. Goal-stack planning
keeps undoing one goal while achieving the other and gives up (`planning_demo`). That's why the agent
uses goal-stack only inside the small *Contain* sub-problem, where goals don't interact, and HTN for
the overall structure.

### 8.6 Complexity
Forward BFS: O(bᵈ) states. Goal-stack: linear in plan length when goals don't interact, with no
completeness guarantee. HTN: exponential in the worst case (method choice), but near-linear here
because methods encode expert procedure.

### 8.7 Tests ([test_planning.py](../backend/tests/test_planning.py))
Every HTN plan is validated step by step against its goal for all four decisions · the HTN plan length
equals the BFS-optimal length · goal-stack picks RESTRICT when ISOLATE isn't allowed and fails cleanly when
nothing can contain · unreachable goals are reported · the Sussman anomaly.

---

## 9. The agent loop

[agent.py](../backend/app/agent/agent.py) runs once per tick:

| Step | What happens | Technique |
|---|---|---|
| 1. Perceive | Record events in the internal model | Model-based agent |
| 2. Reason | Evidence facts → forward chaining → levels + proof trees | Logic (MP) |
| 3. Update | Keep beliefs (`Compromised(d)`), threat levels, risk scores | State representation |
| 4. Decide | Open or escalate incidents; joint isolation decision | CSP |
| 5. Plan | HTN incident plan; goal-stack for Contain | Planning |
| 6. Act | Internal steps (investigation: **BFS, DFS, Greedy, A\***) and simulated actions | Search + actuators |
| 7. Verify | Wait 2 ticks, then **Modus Tollens**; only then recover and resolve | Logic (MT), goal test |

The **performance measure** is computed by the environment from ground truth the agent never sees
([performance.py](../backend/app/agent/performance.py)). Results are in [RESULTS.md](RESULTS.md).
