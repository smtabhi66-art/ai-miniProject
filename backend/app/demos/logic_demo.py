"""Logic demo: propositional entailment, Modus Ponens / Tollens, and predicate forward chaining.

    python -m app.demos.logic_demo
"""
from app.agent.detection import ThreatDetector, load_security_rules
from app.algorithms.logic.propositional import Symbol, conjunction, modus_ponens, modus_tollens, truth_table, tt_entails
from app.models.enums import EventType
from app.models.events import SecurityEvent
from app.simulation.network_builder import load_topology
from app.core.console import utf8_output


def propositional() -> None:
    BF, LI, C, M = Symbol("BruteForce"), Symbol("LoginSuccess"), Symbol("Compromised"), Symbol("MaliciousTraffic")
    rule = (BF & LI) >> C
    print("=== Propositional logic ===")
    print(f"Rule: {rule}")
    print("Truth table of the rule:")
    for model, value in truth_table(rule):
        row = "  ".join(f"{k[:5]}={'T' if v else 'F'}" for k, v in model.items())
        print(f"  {row}   rule={'T' if value else 'F'}")
    kb = conjunction(rule, BF, LI)
    print(f"\nKB = {kb}")
    print(f"KB ⊨ Compromised ?  {tt_entails(kb, C)}   (model checking over all {2 ** 3} models)")
    print(f"Modus Ponens:  {rule},  {BF & LI}  ⊢  {modus_ponens(rule, BF & LI)}")
    behaviour = C >> M
    print(f"Modus Tollens: {behaviour},  {~M}  ⊢  {modus_tollens(behaviour, ~M)}")
    print(f"Sound? KB={conjunction(behaviour, ~M)} ⊨ ¬Compromised: {tt_entails(conjunction(behaviour, ~M), ~C)}")
    print(f"Fallacy check (affirming the consequent): {behaviour}, {M} ⊨ {C}? {tt_entails(conjunction(behaviour, M), C)}")


def predicate() -> None:
    print("\n=== First-order (Horn clause) forward chaining on the real security rules ===")
    events = [SecurityEvent(f"e{i}", 1 + i // 4, EventType.FAILED_LOGIN, "INET", "WS2") for i in range(8)]
    events.append(SecurityEvent("e9", 3, EventType.SUCCESSFUL_LOGIN, "INET", "WS2"))
    print("Events: 8 failed logins INET->WS2 at ticks 1-2, then a successful login at tick 3")
    a = ThreatDetector(load_security_rules()).assess(load_topology(), events, 3)
    print("\nInference steps (each one is Modus Ponens):")
    for step in a.steps:
        print(f"  {step}")
    print("\nProof tree for WS2:")
    for line in a.explanation("WS2"):
        print(f"  {line}")
    print(f"\nClassification: {{{', '.join(f'{d}: {l.value}' for d, l in a.levels.items() if l.value != 'normal')}}}")


if __name__ == "__main__":
    utf8_output()
    propositional()
    predicate()
