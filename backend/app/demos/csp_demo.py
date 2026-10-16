"""CSP demo: safe isolation decisions, plus the N-Queens heuristic comparison.

    python -m app.demos.csp_demo                # scenario 7: AUTH1 cannot be isolated
    python -m app.demos.csp_demo s5             # scenario 5: APP1 restricted, WS2 isolated
    python -m app.demos.csp_demo replicas       # DB1 and DB2 both compromised
    python -m app.demos.csp_demo admin          # admin PC compromised: impossible, escalate
    python -m app.demos.csp_demo router         # R3 compromised while R1-R2 is down: impossible
    python -m app.demos.csp_demo budget         # 3 compromised PCs, budget 2: impossible
    python -m app.demos.csp_demo queens         # why MRV + forward checking matter
"""
import argparse

from app.agent.isolation_csp import solve_isolation
from app.algorithms.csp.backtracking import backtracking_search
from app.algorithms.csp.examples import n_queens
from app.models.enums import LinkStatus, ThreatLevel
from app.simulation.network_builder import load_topology
from app.core.console import utf8_output

C, S = ThreatLevel.CRITICAL, ThreatLevel.SUSPICIOUS
CASES = {
    "s4": ("Scenario 4: compromised WS3 attacking DB1", {"WS3": C, "DB1": S}, []),
    "s5": ("Scenario 5: WS2 and the only app server APP1 compromised", {"WS2": C, "APP1": C}, []),
    "s7": ("Scenario 7: WS1 and the only auth server AUTH1 compromised", {"WS1": C, "AUTH1": C}, []),
    "replicas": ("Both database replicas compromised", {"DB1": C, "DB2": C}, []),
    "admin": ("The admin workstation itself is compromised", {"ADMIN1": C, "WS1": C}, []),
    "router": ("Backup router R3 compromised while R1-R2 is down", {"R3": C}, [("R1", "R2")]),
    "budget": ("Three workstations compromised at once", {"WS1": C, "WS2": C, "WS3": C}, []),
}


def run_case(key: str, budget: int) -> None:
    title, suspects, blocked = CASES[key]
    state = load_topology()
    for a, b in blocked:
        state.get_link(a, b).status = LinkStatus.BLOCKED
    r = solve_isolation(state, suspects, budget)
    res = r.result

    print(f"=== {title} ===")
    if blocked:
        print(f"(simulated) blocked links: {blocked}")
    print("\nVariables and initial domains (preference order):")
    for v in r.csp.variables:
        print(f"  {v:<7} [{r.suspects[v].value}]  {r.csp.domains[v]}")
    print("\nConstraints:")
    for c in r.csp.constraints:
        print(f"  {c.name:<26} scope={','.join(c.scope)}\n  {'':<26} {c.description}")
    print("\nPreprocessing (node consistency + AC-3) removed:")
    for p in res.preprocessing or ["(nothing)"]:
        print(f"  {p}")
    print(f"Domains after preprocessing: {res.domains_after_preprocessing}")
    if res.trace:
        print("\nBacktracking search (MRV + forward checking):")
        for s in res.trace:
            what = f"{s.var}={s.value}" if s.var else ""
            print(f"  {s.step:>3}. {s.action:<9} {what:<16} {s.detail}")
    print()
    if r.solvable:
        print("DECISION (simulated actions to take):")
        for device, decision in r.decisions.items():
            print(f"  {device:<7} -> {decision}")
    else:
        print(f"NO SAFE ISOLATION EXISTS: {res.failure}")
        print(f"  constraints that blocked options: {res.conflicts}")
        print("  -> the agent escalates to a human instead of acting.")
    print(f"\nStats: {vars(res.stats)}")


def run_queens(n: int = 8) -> None:
    print(f"=== {n}-Queens: same solver, different heuristics ===")
    print(f"  {'configuration':<40} {'assignments':>11} {'backtracks':>10} {'pruned':>7}")
    configs = [
        ("plain backtracking", dict(mrv=False, lcv=False, forward_checking=False, ac3_preprocess=False)),
        ("+ forward checking", dict(mrv=False, lcv=False, forward_checking=True, ac3_preprocess=False)),
        ("+ forward checking + MRV", dict(mrv=True, lcv=False, forward_checking=True, ac3_preprocess=False)),
        ("+ forward checking + MRV + LCV + AC-3", dict(mrv=True, lcv=True, forward_checking=True, ac3_preprocess=True)),
    ]
    for name, options in configs:
        st = backtracking_search(n_queens(n), **options).stats
        print(f"  {name:<40} {st.assignments:>11} {st.backtracks:>10} {st.pruned:>7}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("case", nargs="?", default="s7", choices=[*CASES, "queens"])
    parser.add_argument("--budget", type=int, default=2, help="max devices isolated at once")
    args = parser.parse_args()
    utf8_output()
    if args.case == "queens":
        run_queens()
    else:
        run_case(args.case, args.budget)


if __name__ == "__main__":
    main()
