# Viva Questions & Model Answers

Short answers you can say out loud, with where to point in the code or dashboard.

## A. Agents

**1. What kind of agent is this?**
A **model-based, goal-based** agent. It keeps an internal model of the network (`StateManager`), because the
environment is partially observable, and it chooses actions by planning toward an explicit goal (e.g.
`Verified(d) ∧ Recovered(d)`).

**2. Give the PEAS description.**
Performance: score (+10 contained, −20 per service-outage tick, −3 per healthy device isolated, −1 per tick a
compromised device runs free, −5 per false positive). Environment: simulated enterprise network + scripted
attacker. Actuators: isolate, restrict, restore, remediate, reset credentials, monitor, block or unblock a link
(all simulated). Sensors: the security event feed.

**3. Why is the environment partially observable?**
Whether a device is *really* compromised is stored in the simulator's `HiddenState`, which the agent never
receives. It only sees events, so it must infer compromise. That's why it needs a model.

**4. Is the environment deterministic?**
Stochastic (random background noise), but reproducible: a seed fixes the random sequence, and the generator
makes the same number of random draws every tick, so the agent's actions don't change the noise.

**5. What makes your agent "rational"?**
It chooses actions that maximise the performance measure given its percepts. For example, it does not isolate
AUTH1 (that would cost −20 per tick of outage) and restricts it instead. The score is computed by the
environment from ground truth, not by the agent.

## B. Search

**6. Why BFS for the blast radius?**
BFS explores level by level, so it discovers devices in order of hop distance, which is exactly "what can
it reach within k hops". Time O(V + E).

**7. Why DFS for attack paths?**
We need *all* simple paths, not only the shortest. DFS with backtracking keeps one path in memory at a time.
It's exponential in the worst case, so I bound it with `max_depth` and `max_paths`.

**8. Why does R3 appear twice on the DFS stack?**
Path-DFS tracks visited nodes *per path*, not globally, because the same router can lie on two different attack routes.

**9. What is your A* heuristic, and why is it admissible?**
`h(n) = hops(n, goal) × c_min`. Any path needs at least that many hops, and each hop costs at least `c_min`,
so it never overestimates. It's also consistent because neighbours differ by at most one hop. My tests check
both properties for every goal on three network variants.

**10. Difference between g(n) and h(n)?**
`g(n)` is the actual cost already paid from the start. `h(n)` is an estimate of the remaining cost. A* orders by `f = g + h`.

**11. When does Greedy give a worse answer than A*?**
When the link that *looks* closer is expensive. With R1–R2 congested (cost 10), Greedy goes ADMIN1→R1→R2→DB1
(cost 12) and A* goes via R3 (cost 6). Greedy ignores `g(n)`.

**12. Then why use Greedy at all?**
Speed: it expands about 3 nodes to give a first investigation lead. Routes the agent *acts on* always come from A*.

**13. How does A* avoid compromised devices?**
They're passed as `forbidden` nodes, and edge costs add penalties for risky links and devices (`risk_aware_cost`).

## C. CSP

**14. Formulate the isolation problem as a CSP.**
Variables: each suspicious or critical device. Domain: {ISOLATE, RESTRICT, MONITOR}. Constraints: restrict
needs a service; critical can't just be monitored; the sole host of a critical service can't be isolated;
replicas can't all be isolated; the admin PC must keep a path to critical hosts; at most K isolations.

**15. Node consistency vs AC-3 vs forward checking?**
Node consistency removes values that violate unary constraints. AC-3 makes every binary arc consistent before
search. Forward checking, during search, removes conflicting values from unassigned neighbours right after
each assignment.

**16. What do MRV and LCV do?**
MRV picks the variable with the fewest values left (fail first). LCV tries the value that rules out the fewest
neighbour values. In 8-Queens, assignments drop from 113 to 29.

**17. Why is LCV off in the isolation CSP?**
The domain order *is* the security preference (contain critical devices first, disturb suspicious ones least).
LCV would reorder it.

**18. What happens if there is no solution?**
Backtracking proves no valid assignment exists, and the agent **escalates** to a human instead of taking an
unsafe action. Example: the admin PC itself is compromised.

**19. Why check global constraints on partial assignments?**
They're monotone: isolating more devices can never fix a violation. So an early violation is final.

## D. Logic

**20. What is in your knowledge base?**
Topology facts (`Connected`, `CriticalAsset`, `Internal`), evidence facts counted from events in sliding windows
(`BruteForcing(INET, WS2)`), persistent beliefs (`Compromised(WS2)`), and 16 Horn rules from a JSON file.

**21. Show Modus Ponens in your project.**
R3: `BruteForcing(INET, WS2) ∧ LoggedIn(INET, WS2) ⇒ Compromised(WS2)`. Every forward-chaining step is MP.

**22. Show Modus Tollens.**
V1: `ActiveCompromise(d) ⇒ MaliciousActivity(d)`. After isolation no malicious activity is observed, so
`¬MaliciousActivity(WS1) ⊢ ¬ActiveCompromise(WS1)`. It's used to verify containment.

**23. Is it full first-order logic?**
No. It's the Horn-clause subset with unification and forward chaining: no function symbols, no existential
quantifiers, no resolution prover. It's decidable, fast and explainable.

**24. How do you explain a decision?**
Every fact stores its proof (rule + premises, or the observed evidence). `explain()` prints the proof tree,
which is shown on the dashboard.

**25. Why are MP and MT sound but "affirming the consequent" isn't?**
Truth tables: `(P→Q) ∧ Q` has a model where P is false. My tests check this with `tt_entails`.

## E. Planning

**26. What is a STRIPS action?**
Preconditions, add list, delete list. Example: `isolate_device(d)`: pre {IsolationApproved, Online},
add {Isolated, Contained}, delete {Online}.

**27. Goal-based vs goal-stack vs hierarchical planning?**
Goal-based: forward BFS over states, which gives the shortest plan. Goal-stack: works backwards from goals using a
stack and pushes an achiever's preconditions. HTN: refines high-level tasks (Contain) with methods into primitive actions.

**28. Where does each run in the agent?**
HTN builds every incident plan. Goal-stack expands the Contain step. Forward BFS is the baseline that proves
the HTN plans have optimal length (tests).

**29. What is the Sussman anomaly?**
Two interacting goals where achieving one undoes the other. My goal-stack planner fails on it while BFS
finds the 6-step plan, which is why goal-stack is only used where goals don't interact.

**30. How does the CSP talk to the planner?**
The decision becomes a fact `CSPAllows(d, ISOLATE)`, which is a precondition of `approve_isolation(d)`. So the
planner can't choose a containment the CSP didn't approve.

## F. System & evaluation

**31. How do you know the response worked?**
Verification (Modus Tollens) plus the environment's ground truth: zero outages, zero healthy devices isolated,
zero false positives, and all compromised devices contained in every scenario.

**32. Why measure detection in passive mode?**
In active mode the agent stops attacks early, so later stages never happen and can't be detected. Passive mode
observes the whole attack: 128/128 classifications are correct.

**33. Is 100% accuracy realistic?**
No. The rules and labels were designed together, so 100% shows consistency, not real-world validity. Real
evaluation would need labelled real data (e.g. an IDS dataset).

**34. What would you add next?**
An adaptive attacker (adversarial search), a learned anomaly detector to compare with the rules, and WebSocket live updates.

**35. Does it touch a real network?**
Never. All IPs are labels, and every action changes Python objects only. The database even has
`CHECK (simulated = 1)` on actions.
