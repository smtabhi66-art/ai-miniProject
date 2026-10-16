"""Milestone 6: backtracking search, MRV, LCV and the value of propagation."""
import pytest

from app.algorithms.csp.backtracking import (
    backtracking_search,
    order_domain_values,
    select_unassigned_variable,
)
from app.algorithms.csp.csp import CSP, binary, unary
from app.algorithms.csp.examples import map_coloring, n_queens

PLAIN = dict(mrv=False, lcv=False, forward_checking=False, ac3_preprocess=False)


def test_map_coloring_three_colors():
    csp = map_coloring(["red", "green", "blue"])
    r = backtracking_search(csp)
    assert r.solved and csp.is_solution(r.solution)


def test_map_coloring_two_colors_is_impossible():
    r = backtracking_search(map_coloring(["red", "green"]))
    assert not r.solved
    assert r.failure == "no assignment satisfies every constraint"
    assert r.conflicts.get("different_colors", 0) > 0


@pytest.mark.parametrize("n", [4, 6, 8])
def test_n_queens_solved_with_every_configuration(n):
    csp = n_queens(n)
    for options in [PLAIN, dict(mrv=True, lcv=False, forward_checking=True, ac3_preprocess=False),
                    dict(mrv=True, lcv=True, forward_checking=True, ac3_preprocess=True)]:
        r = backtracking_search(csp, **options)
        assert r.solved and csp.is_solution(r.solution)


def test_three_queens_is_impossible():
    assert not backtracking_search(n_queens(3)).solved
    assert not backtracking_search(n_queens(3), **PLAIN).solved


def test_forward_checking_and_mrv_reduce_work():
    csp = n_queens(8)
    plain = backtracking_search(csp, **PLAIN)
    smart = backtracking_search(csp, mrv=True, lcv=False, forward_checking=True, ac3_preprocess=False)
    assert smart.stats.backtracks < plain.stats.backtracks
    assert smart.stats.assignments < plain.stats.assignments


def test_plain_backtracking_trace_shows_backtracks():
    r = backtracking_search(n_queens(4), **PLAIN)
    actions = [s.action for s in r.trace]
    assert "reject" in actions and "backtrack" in actions and actions[-1] == "solution"


def test_empty_domain_after_preprocessing_reports_cause():
    csp = CSP(["X"], {"X": [1]}, [unary("not_one", "X", lambda v: v != 1)])
    r = backtracking_search(csp)
    assert not r.solved
    assert "X has no allowed value left" in r.failure and "not_one" in r.failure
    assert r.stats.assignments == 0


def test_no_variables_is_trivially_solved():
    r = backtracking_search(CSP([], {}, []))
    assert r.solution == {}


def test_mrv_picks_smallest_domain_then_highest_degree():
    csp = map_coloring(["r", "g", "b"])
    domains = {v: ["r", "g", "b"] for v in csp.variables}
    assert select_unassigned_variable(csp, {}, domains, mrv=True) == "SA"  # degree 5
    domains["T"] = ["r"]
    assert select_unassigned_variable(csp, {}, domains, mrv=True) == "T"
    assert select_unassigned_variable(csp, {}, domains, mrv=False) == "WA"


def test_lcv_prefers_least_constraining_value():
    # X in {1, 2}; neighbour Y in {1, 1.5}; constraint X != Y. X=1 rules out one of Y's values, X=2 none.
    csp = CSP(["X", "Y"], {"X": [1, 2], "Y": [1, 1.5]}, [binary("ne", "X", "Y", lambda a, b: a != b)])
    assert order_domain_values(csp, "X", {}, csp.domains, lcv=True) == [2, 1]
    assert order_domain_values(csp, "X", {}, csp.domains, lcv=False) == [1, 2]


def test_trace_limit():
    r = backtracking_search(n_queens(8), **PLAIN, max_trace=10)
    assert len(r.trace) == 10 and r.trace_truncated
