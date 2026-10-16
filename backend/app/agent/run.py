"""Run the defense agent in the terminal.

    python -m app.agent.run s8_multi_step              # one scenario, tick by tick
    python -m app.agent.run s7_isolation_constraint -v # with proofs, CSP and plan details
    python -m app.agent.run s8_multi_step --passive    # detection only, no actions
    python -m app.agent.run random --seed 7            # a generated scenario
    python -m app.agent.run --all                      # summary table for all 8 scenarios
"""
import argparse

from app.agent.session import Session
from app.core.config import DEFAULT_SEED
from app.models.enums import EventType
from app.simulation.scenarios import list_scenarios
from app.core.console import utf8_output


def run_one(scenario_id: str, seed: int, passive: bool, verbose: bool) -> None:
    session = Session.create(scenario_id, seed, act=not passive)
    sc = session.scenario
    print(f"{sc.name}  (seed {session.sim.seed}, {'passive' if passive else 'active'} mode)")
    print(f"{sc.description}\n")
    shown = 0
    while not session.finished:
        tick = session.tick
        session.step()
        events = [e for e in session.tick_events[tick] if e.type is not EventType.NORMAL_TRAFFIC]
        logs = session.agent.decisions[shown:]
        shown = len(session.agent.decisions)
        if not events and not logs:
            continue
        print(f"--- tick {tick} " + "-" * 60)
        for e in events:
            print(f"  event   {e.type.value:<20} {e.source} -> {e.target}")
        for log in logs:
            print(f"  {log.algorithm:<38} {log.summary}")
            if verbose:
                for line in _details(log):
                    print(f"      {line}")
    report = session.report()
    perf = report["performance"]
    print("\n=== Result ===")
    for inc in report["incidents"]:
        print(f"  {inc['id']} {','.join(inc['devices']):<6} {inc['level']:<10} decision={str(inc['decision']):<8} "
              f"status={inc['status']:<9} verified={inc['verified']}")
    print(f"  Performance score: {perf['score']}   {perf['counts']}")
    det = report["detection"]
    print(f"  Detection accuracy (peak level vs ground truth): {det['accuracy']}   mistakes: {det['mistakes'] or 'none'}")
    print(f"  Attack events delivered: {report['attack_events']['delivered']}, "
          f"prevented by containment: {report['attack_events']['prevented']}")


def _details(log) -> list[str]:
    data = log.data
    if log.algorithm.startswith("Logic"):
        return [*data.get("inferences", [])] + [f"{d}: " + " | ".join(lines[:1]) for d, lines in
                                                data.get("explanations", {}).items()]
    if log.algorithm.startswith("Incident") and data.get("explanation"):
        return data["explanation"]
    if log.algorithm.startswith("CSP"):
        return [str(p) for p in data.get("preprocessing", [])] + [f"decisions: {data.get('decisions')}"]
    if log.algorithm.startswith("Planning"):
        return data.get("tree", [])
    if log.algorithm.startswith("Verification"):
        return data.get("lines", [])
    if log.algorithm.startswith("Search"):
        return [f"blast radius: {data['blast_radius']}", f"chokepoints: {data['chokepoints']}"]
    return []


def run_all(seed: int) -> None:
    print(f"{'scenario':<28} {'score':>5} {'contained':>9} {'outage':>6} {'over-react':>10} "
          f"{'detect acc':>10}  incidents (device:decision:status)")
    for sc in list_scenarios():
        active = Session(sc, seed).run().report()
        passive = Session(sc, seed, act=False).run().report()
        c = active["performance"]["counts"]
        incidents = " ".join(f"{i['devices'][0]}:{i['decision']}:{i['status']}" for i in active["incidents"])
        print(f"{sc.id:<28} {active['performance']['score']:>5} {c['contained']:>9} {c['outage_ticks']:>6} "
              f"{c['healthy_isolated']:>10} {passive['detection']['accuracy']:>10}  {incidents or '-'}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", nargs="?", default="s8_multi_step")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--passive", action="store_true", help="detect only, take no actions")
    parser.add_argument("-v", "--verbose", action="store_true", help="show proofs, CSP and plans")
    parser.add_argument("--all", action="store_true", help="summary of all scenarios")
    args = parser.parse_args()
    utf8_output()
    if args.all:
        run_all(args.seed)
    else:
        run_one(args.scenario, args.seed, args.passive, args.verbose)


if __name__ == "__main__":
    main()
