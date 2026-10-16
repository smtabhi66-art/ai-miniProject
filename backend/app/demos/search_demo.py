"""Search demo: BFS blast radius and DFS attack paths on the enterprise network.

    python -m app.demos.search_demo
    python -m app.demos.search_demo --source WS3 --depth 2
    python -m app.demos.search_demo --block R1 R2
"""
import argparse

from app.algorithms.search.bfs import bfs_reachable
from app.algorithms.search.dfs import dfs_all_paths
from app.algorithms.search.graph import TraceStep, graph_from_network
from app.models.enums import LinkStatus
from app.simulation.network_builder import load_topology
from app.core.console import utf8_output


def print_trace(trace: list[TraceStep], frontier_name: str, visited_name: str) -> None:
    print(f"  {'step':>4}  {'node':<7} {'action':<7} {frontier_name:<34} {visited_name}")
    for t in trace:
        print(f"  {t.step:>4}  {t.node:<7} {t.action:<7} {str(t.frontier):<34} {t.visited}")
        print(f"  {'':>4}  {'':<7} {'':<7} -> {t.note}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", default="WS2", help="compromised device (default WS2)")
    parser.add_argument("--depth", type=int, default=None, help="BFS hop limit")
    parser.add_argument("--block", nargs=2, metavar=("A", "B"), help="block a link before searching")
    args = parser.parse_args()
    utf8_output()

    state = load_topology()
    if args.block:
        state.get_link(*args.block).status = LinkStatus.BLOCKED
        print(f"(simulated) link {args.block[0]}-{args.block[1]} blocked\n")
    graph = graph_from_network(state)

    print(f"=== BFS: blast radius of {args.source} ===")
    r = bfs_reachable(graph, args.source, max_depth=args.depth)
    print_trace(r.trace, "queue (front first)", "visited")
    print("\n  Result by hop distance:")
    for hops, layer in enumerate(r.layers()):
        print(f"    {hops} hop(s): {', '.join(layer)}")

    critical_hosts = sorted({h for s in state.services.values() if s.critical for h in s.hosts})
    target = "DB1" if args.source != "DB1" else "AUTH1"
    print(f"\n=== DFS: attack paths from {args.source} to {target} (trace) ===")
    d = dfs_all_paths(graph, args.source, [target])
    print_trace(d.trace, "stack (top first)", "current path")

    print(f"\n=== DFS: all attack paths from {args.source} to critical hosts {critical_hosts} ===")
    d = dfs_all_paths(graph, args.source, critical_hosts)
    for path in d.paths:
        print(f"    {' -> '.join(path)}")
    print(f"  {len(d.paths)} paths, {d.nodes_expanded} nodes expanded, truncated={d.truncated}")


if __name__ == "__main__":
    main()
