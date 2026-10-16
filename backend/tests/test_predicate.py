"""Milestone 7: predicate atoms, parsing, unification and rule safety."""
import pytest

from app.algorithms.logic.predicate import Rule, format_atom, parse_atom, substitute, unify


def test_parse_and_format_round_trip():
    atom = parse_atom("Connected(WS1, ?x)")
    assert atom == ("Connected", "WS1", "?x")
    assert format_atom(atom) == "Connected(WS1, ?x)"
    assert parse_atom("Alarm()") == ("Alarm",)


@pytest.mark.parametrize("bad", ["Connected", "Connected(WS1,)", "(WS1)", "1Bad(x)"])
def test_parse_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_atom(bad)


def test_unify_binds_variables():
    assert unify(("Connected", "?a", "?b"), ("Connected", "WS1", "R1")) == {"?a": "WS1", "?b": "R1"}


def test_unify_respects_existing_bindings():
    assert unify(("Connected", "?a", "R1"), ("Connected", "WS1", "R1"), {"?a": "WS1"}) == {"?a": "WS1"}
    assert unify(("Connected", "?a", "R1"), ("Connected", "WS1", "R1"), {"?a": "WS2"}) is None


def test_unify_repeated_variable_must_match():
    assert unify(("Same", "?x", "?x"), ("Same", "A", "A")) == {"?x": "A"}
    assert unify(("Same", "?x", "?x"), ("Same", "A", "B")) is None


def test_unify_fails_on_predicate_or_arity_mismatch():
    assert unify(("P", "?x"), ("Q", "a")) is None
    assert unify(("P", "?x"), ("P", "a", "b")) is None
    assert unify(("P", "a"), ("P", "b")) is None


def test_substitute():
    assert substitute(("Compromised", "?d"), {"?d": "WS2"}) == ("Compromised", "WS2")


def test_rule_parse_and_str():
    rule = Rule.parse("R3", ["BruteForcing(?s, ?t)", "LoggedIn(?s, ?t)"], "Compromised(?t)")
    assert str(rule) == "BruteForcing(?s, ?t) ∧ LoggedIn(?s, ?t) ⇒ Compromised(?t)"


def test_unsafe_rule_rejected():
    with pytest.raises(ValueError, match="not in any premise"):
        Rule.parse("bad", ["Scanning(?s)"], "Compromised(?other)")
    with pytest.raises(ValueError, match="no premises"):
        Rule("empty", (), ("Alarm",))
