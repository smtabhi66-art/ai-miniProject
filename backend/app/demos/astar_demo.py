"""Informed search demo: A* vs Greedy vs Uniform-cost vs BFS on the enterprise network.

    python -m app.demos.astar_demo                                # ADMIN1 -> DB1, normal network
    python -m app.demos.astar_demo --block R1 R2                  # scenario 6: direct link down
    python -m app.demos.astar_demo --congest R1 R2 10             # link slowed: Greedy picks a worse route
    python -m app.demos.astar_demo --risk R2 0.9 --risk-aware     # every server route crosses R2: cost rises, route can't change
    python -m app.demos.astar_demo --avoid R3 --block R1 R2       # no safe route exists
"""
import argparse

from app.algorithms.search.astar import astar, path_cost, uniform_cost_search
from app.algorithms.search.bfs import bfs_shortest_path
from app.algorithms.search.costs import risk_aware_cost
from app.algorithms.search.graph import Graph, TraceStep, graph_from_network
from app.algorithms.search.greedy_best_first import greedy_best_first
from app.algorithms.search.heuristics import exact_costs, hop_lower_bound
from app.models.enums import LinkStatus
from app.simulation.network_builder import load_topology
from app.core.console import utf8_output


def print_trace(title: str, trace: list[TraceStep]) -> None:
    print(f"\n=== {title} ===")
    print(f"  {'step':>4}  {'expand':<7} {'open list after (priority order)':<52} note")
    for t in trace:
        print(f"  {t.step:>4}  {t.node:<7} {', '.join(t.frontier):<52} {t.note}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--start", default="ADMIN1")
    parser.add_argument("--goal", default="DB1")
    parser.add_argument("--block", nargs=2, action="append", default=[], metavar=("A", "B"))
    parser.add_argument("--congest", nargs=3, action="append", default=[], metavar=("A", "B", "COST"),
                        help="set a link's latency cost")
    parser.add_argument("--risk", nargs=2, action="append", default=[], metavar=("DEVICE", "SCORE"),
                        help="set a device's risk score (0..1)")
    parser.add_argument("--risk-aware", action="store_true", help="use risk-aware edge costs")
    parser.add_argument("--avoid", action="append", default=[], help="device that routes must not pass through")
    args = parser.parse_args()
    utf8_output()

    state = load_topology()
    for a, b in args.block:
        state.get_link(a, b).status = LinkStatus.BLOCKED
        print(f"(simulated) link {a}-{b} blocked")
    for a, b, cost in args.congest:
        state.get_link(a, b).latency_cost = float(cost)
        print(f"(simulated) link {a}-{b} latency cost set to {cost}")
    for device, score in args.risk:
        state.devices[device].risk_score = float(score)
        print(f"risk score of {device} set to {score}")
    if args.avoid:
        print(f"routes must avoid: {', '.join(args.avoid)}")

    graph = graph_from_network(state, edge_cost=risk_aware_cost() if args.risk_aware else None)
    h = hop_lower_bound(graph, args.goal)
    true = exact_costs(graph, args.goal)

    print(f"\nHeuristic for goal {args.goal}: h(n) = {h.name}")
    print(f"  {'node':<7} {'h(n)':>6} {'true cost':>10}  admissible?")
    for node in graph.nodes:
        t = true.get(node, float("inf"))
        print(f"  {node:<7} {h(node):>6g} {t:>10g}  {'yes' if h(node) <= t + 1e-9 else 'NO'}")

    best = astar(graph, args.start, args.goal, h, forbidden=args.avoid)
    greedy = greedy_best_first(graph, args.start, args.goal, h, forbidden=args.avoid)
    ucs = uniform_cost_search(graph, args.start, args.goal, forbidden=args.avoid)
    print_trace(f"A*  {args.start} -> {args.goal}   (priority f = g + h)", best.trace)
    print_trace(f"Greedy best-first  {args.start} -> {args.goal}   (priority h only)", greedy.trace)

    allowed = Graph.from_edges(  # BFS ignores costs but must respect --avoid too
        ((a, b, c) for a in graph.nodes for b, c in graph.adjacency[a].items()
         if a < b and a not in args.avoid and b not in args.avoid), nodes=graph.nodes)
    bfs_path = bfs_shortest_path(allowed, args.start, args.goal)
    print("\n=== Comparison ===")
    print(f"  {'algorithm':<20} {'path':<38} {'cost':>6} {'expanded':>9}")
    rows = [
        ("BFS (fewest hops)", bfs_path, path_cost(graph, bfs_path) if bfs_path else None, None),
        (ucs.algorithm, ucs.path, ucs.cost, ucs.nodes_expanded),
        (greedy.algorithm, greedy.path, greedy.cost, greedy.nodes_expanded),
        (best.algorithm, best.path, best.cost, best.nodes_expanded),
    ]
    for name, path, cost, expanded in rows:
        p = " -> ".join(path) if path else "no route"
        c = f"{cost:g}" if cost is not None else "-"
        e = str(expanded) if expanded is not None else "-"
        print(f"  {name:<20} {p:<38} {c:>6} {e:>9}")
    if best.found and greedy.found and greedy.cost > best.cost:
        print(f"\n  Greedy's route costs {greedy.cost:g} vs A*'s {best.cost:g}: "
              "ignoring g(n) made it take the link that only *looked* closer.")
    if not best.found:
        print("\n  No safe route exists. The agent must escalate instead of acting.")


if __name__ == "__main__":
    main()
