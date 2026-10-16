"""Milestone 7: propositional logic, entailment and the soundness of MP / MT."""
import pytest

from app.algorithms.logic.propositional import (
    Implies,
    Not,
    Symbol,
    conjunction,
    is_satisfiable,
    is_valid,
    modus_ponens,
    modus_tollens,
    truth_table,
    tt_entails,
)

BF, LI, C, M = Symbol("BruteForce"), Symbol("LoginSuccess"), Symbol("Compromised"), Symbol("MaliciousTraffic")


def test_connectives_truth_values():
    m = {"P": True, "Q": False}
    P, Q = Symbol("P"), Symbol("Q")
    assert (P & ~Q).evaluate(m)
    assert (P | Q).evaluate(m)
    assert not (P >> Q).evaluate(m)
    assert (Q >> P).evaluate(m)
    assert not P.iff(Q).evaluate(m)


def test_implication_truth_table():
    rows = truth_table(Symbol("P") >> Symbol("Q"))
    assert [v for _, v in rows] == [True, True, False, True]  # FF, FT, TF, TT


def test_str_uses_logic_symbols():
    assert str((BF & LI) >> C) == "((BruteForce ∧ LoginSuccess) → Compromised)"
    assert str(~M) == "¬MaliciousTraffic"


def test_missing_symbol_raises():
    with pytest.raises(KeyError):
        Symbol("P").evaluate({})


def test_security_rule_entailment():
    kb = conjunction((BF & LI) >> C, BF, LI)
    assert tt_entails(kb, C)
    assert not tt_entails(conjunction((BF & LI) >> C, BF), C)  # login missing


def test_modus_ponens_is_sound():
    rule = (BF & LI) >> C
    conclusion = modus_ponens(rule, BF & LI)
    assert conclusion == C
    assert tt_entails(conjunction(rule, BF & LI), conclusion)


def test_modus_tollens_is_sound():
    rule = C >> M
    conclusion = modus_tollens(rule, ~M)
    assert conclusion == Not(C)
    assert tt_entails(conjunction(rule, ~M), conclusion)


def test_inference_rules_refuse_wrong_inputs():
    assert modus_ponens(C >> M, M) is None          # affirming the consequent is invalid
    assert modus_tollens(C >> M, Not(C)) is None    # denying the antecedent is invalid
    assert modus_ponens(C & M, C) is None           # not an implication
    assert not tt_entails(conjunction(C >> M, M), C)


def test_validity_and_satisfiability():
    P = Symbol("P")
    assert is_valid(P | ~P)
    assert not is_satisfiable(P & ~P)
    assert is_satisfiable(P >> ~P)
    assert isinstance(P >> P, Implies)
