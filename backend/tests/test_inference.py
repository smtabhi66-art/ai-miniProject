"""Milestone 7: knowledge base, forward chaining (MP), Modus Tollens and proofs."""
import pytest

from app.algorithms.logic.inference import forward_chain, modus_tollens
from app.algorithms.logic.knowledge_base import KnowledgeBase, Proof
from app.algorithms.logic.predicate import Rule

RULES = [
    Rule.parse("R2", ["BruteForcing(?s, ?t)"], "Attacker(?s)"),
    Rule.parse("R3", ["BruteForcing(?s, ?t)", "LoggedIn(?s, ?t)"], "Compromised(?t)"),
    Rule.parse("R4", ["Attacker(?s)", "Internal(?s)"], "Compromised(?s)"),
    Rule.parse("V1", ["ActiveCompromise(?d)"], "MaliciousActivity(?d)"),
]


def kb_with(*facts):
    kb = KnowledgeBase(rules=list(RULES))
    for f in facts:
        kb.tell(f)
    return kb


def test_modus_ponens_derives_compromise():
    kb = kb_with(("BruteForcing", "INET", "WS2"), ("LoggedIn", "INET", "WS2"))
    steps = forward_chain(kb)
    assert kb.holds(("Compromised", "WS2"))
    assert kb.holds(("Attacker", "INET"))
    assert all(s.kind == "modus ponens" for s in steps)


def test_chaining_through_derived_facts():
    # R2 derives Attacker(WS1); R4 then needs that *derived* fact.
    kb = kb_with(("BruteForcing", "WS1", "AUTH1"), ("Internal", "WS1"))
    steps = forward_chain(kb)
    assert kb.holds(("Compromised", "WS1"))
    assert [s.rule for s in steps] == ["R2", "R4"]


def test_no_conclusion_without_all_premises():
    kb = kb_with(("BruteForcing", "INET", "WS1"))  # no successful login, INET not internal
    forward_chain(kb)
    assert not kb.holds(("Compromised", "WS1"))
    assert not kb.holds(("Compromised", "INET"))


def test_join_requires_consistent_bindings():
    # Brute force against WS1 but login to WS2: R3 must not fire.
    kb = kb_with(("BruteForcing", "INET", "WS1"), ("LoggedIn", "INET", "WS2"))
    forward_chain(kb)
    assert not kb.holds(("Compromised", "WS1")) and not kb.holds(("Compromised", "WS2"))


def test_forward_chaining_reaches_fixpoint_and_is_idempotent():
    kb = kb_with(("BruteForcing", "INET", "WS2"), ("LoggedIn", "INET", "WS2"))
    forward_chain(kb)
    assert forward_chain(kb) == []


def test_explanation_shows_proof_tree():
    kb = KnowledgeBase(rules=list(RULES))
    kb.tell(("BruteForcing", "WS1", "AUTH1"), note="6 failed logins in ticks 2-3")
    kb.tell(("Internal", "WS1"), source="topology")
    forward_chain(kb)
    assert kb.explain(("Compromised", "WS1")) == [
        "Compromised(WS1)  [derived by R4]",
        "  Attacker(WS1)  [derived by R2]",
        "    BruteForcing(WS1, AUTH1)  [observed: 6 failed logins in ticks 2-3]",
        "  Internal(WS1)  [topology]",
    ]


def test_modus_tollens_in_verification():
    kb = kb_with()
    kb.tell_not(("MaliciousActivity", "WS2"), Proof("observed", note="no malicious events for 2 ticks"))
    step = modus_tollens(kb, RULES[3], ("MaliciousActivity", "WS2"))
    assert step is not None and step.negated
    assert kb.holds_not(("ActiveCompromise", "WS2"))
    assert str(step) == "[modus tollens] V1: ¬MaliciousActivity(WS2) ⊢ ¬ActiveCompromise(WS2)"
    assert kb.explain(("ActiveCompromise", "WS2"), negated=True) == [
        "¬ActiveCompromise(WS2)  [modus tollens by V1]",
        "  ¬MaliciousActivity(WS2)  [observed: no malicious events for 2 ticks]",
    ]


def test_modus_tollens_requires_known_negation_and_single_premise():
    kb = kb_with()
    assert modus_tollens(kb, RULES[3], ("MaliciousActivity", "WS2")) is None  # ¬Q not known
    kb.tell_not(("Compromised", "WS2"), Proof("observed"))
    assert modus_tollens(kb, RULES[1], ("Compromised", "WS2")) is None       # two premises


def test_ask_returns_bindings():
    kb = kb_with(("Connected", "WS1", "R1"), ("Connected", "WS2", "R1"), ("Connected", "R1", "R2"))
    assert kb.ask(("Connected", "?d", "R1")) == [{"?d": "WS1"}, {"?d": "WS2"}]


def test_contradictions_and_bad_facts_rejected():
    kb = kb_with(("Compromised", "WS2"))
    with pytest.raises(ValueError, match="contradiction"):
        kb.tell_not(("Compromised", "WS2"), Proof("observed"))
    with pytest.raises(ValueError, match="ground"):
        kb.tell(("Compromised", "?d"))
    with pytest.raises(ValueError, match="duplicate rule"):
        kb.add_rule(RULES[0])
