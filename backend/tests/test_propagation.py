"""Milestone 6: CSP model, node consistency, AC-3 and forward checking."""
import pytest

from app.algorithms.csp.csp import CSP, binary, global_constraint, unary
from app.algorithms.csp.examples import map_coloring
from app.algorithms.csp.propagation import ac3, copy_domains, forward_check, node_consistency


def less_than_csp():
    # A < B, both in {1, 2, 3}
    return CSP(["A", "B"], {"A": [1, 2, 3], "B": [1, 2, 3]},
               [binary("A<B", "A", "B", lambda a, b: a < b)])


def test_csp_rejects_bad_definitions():
    with pytest.raises(ValueError, match="duplicate"):
        CSP(["A", "A"], {"A": [1]}, [])
    with pytest.raises(ValueError, match="no domain"):
        CSP(["A"], {}, [])
    with pytest.raises(ValueError, match="unknown variable"):
        CSP(["A"], {"A": [1]}, [unary("u", "Z", lambda v: True)])


def test_partial_assignments_are_consistent_until_decided():
    c = binary("A<B", "A", "B", lambda a, b: a < b)
    assert c.consistent({}) and c.consistent({"A": 3})
    assert not c.consistent({"A": 3, "B": 1})


def test_neighbors_and_first_violation():
    csp = map_coloring(["r", "g", "b"])
    assert csp.neighbors("T") == set()
    assert csp.neighbors("WA") == {"NT", "SA"}
    assert csp.first_violation("NT", "r", {"WA": "r"}).name == "different_colors"
    assert csp.first_violation("NT", "g", {"WA": "r"}) is None


def test_node_consistency_removes_unary_violations():
    csp = CSP(["X"], {"X": [1, 2, 3, 4]}, [unary("even", "X", lambda v: v % 2 == 0)])
    domains = copy_domains(csp.domains)
    log = node_consistency(csp, domains)
    assert domains["X"] == [2, 4]
    assert [(p.value, p.stage) for p in log] == [(1, "node"), (3, "node")]


def test_ac3_prunes_unsupported_values():
    csp = less_than_csp()
    domains = copy_domains(csp.domains)
    ok, log = ac3(csp, domains)
    assert ok
    assert domains == {"A": [1, 2], "B": [2, 3]}
    assert {(p.var, p.value) for p in log} == {("A", 3), ("B", 1)}


def test_ac3_propagates_along_a_chain():
    # A < B < C with domains {1,2,3}: only A=1, B=2, C=3 survive.
    csp = CSP(["A", "B", "C"], {v: [1, 2, 3] for v in "ABC"},
              [binary("A<B", "A", "B", lambda a, b: a < b), binary("B<C", "B", "C", lambda b, c: b < c)])
    domains = copy_domains(csp.domains)
    assert ac3(csp, domains)[0]
    assert domains == {"A": [1], "B": [2], "C": [3]}


def test_ac3_detects_inconsistency():
    csp = CSP(["A", "B"], {"A": [1], "B": [1]}, [binary("A!=B", "A", "B", lambda a, b: a != b)])
    ok, _ = ac3(csp, copy_domains(csp.domains))
    assert not ok


def test_ac3_cannot_see_global_constraints():
    # all-different over three variables with only two values: AC-3 alone cannot tell.
    csp = CSP(["A", "B", "C"], {v: [1, 2] for v in "ABC"},
              [global_constraint("alldiff", "ABC", lambda a: len(set(a.values())) == len(a))])
    domains = copy_domains(csp.domains)
    assert ac3(csp, domains) == (True, [])


def test_forward_checking_prunes_neighbours():
    csp = map_coloring(["r", "g", "b"])
    ok, domains, log = forward_check(csp, "WA", "r", {}, csp.domains)
    assert ok
    assert domains["WA"] == ["r"]
    assert "r" not in domains["NT"] and "r" not in domains["SA"]
    assert domains["Q"] == ["r", "g", "b"]  # not a neighbour of WA
    assert all(p.stage == "forward-check" for p in log)


def test_forward_checking_detects_dead_end():
    csp = map_coloring(["r", "g"])
    _, domains, _ = forward_check(csp, "WA", "r", {}, csp.domains)
    ok, _, log = forward_check(csp, "NT", "g", {"WA": "r"}, domains)
    assert not ok and log[-1].var == "SA"


def test_forward_checking_handles_global_constraints():
    budget = global_constraint("at_most_one_1", "ABC", lambda a: sum(1 for v in a.values() if v == 1) <= 1)
    csp = CSP(["A", "B", "C"], {v: [1, 2] for v in "ABC"}, [budget])
    ok, domains, _ = forward_check(csp, "A", 1, {}, csp.domains)
    assert ok and domains["B"] == [2] and domains["C"] == [2]
