"""Textbook CSPs used to test and demonstrate the generic solver (educational only)."""
from itertools import combinations

from app.algorithms.csp.csp import CSP, binary

AUSTRALIA_BORDERS = [
    ("WA", "NT"), ("WA", "SA"), ("NT", "SA"), ("NT", "Q"), ("SA", "Q"),
    ("SA", "NSW"), ("SA", "V"), ("Q", "NSW"), ("NSW", "V"),
]
AUSTRALIA_REGIONS = ["WA", "NT", "SA", "Q", "NSW", "V", "T"]


def map_coloring(colors: list[str]) -> CSP:
    """Colour the map of Australia so that no two neighbouring regions share a colour."""
    constraints = [binary("different_colors", a, b, lambda x, y: x != y, f"{a} and {b} share a border")
                   for a, b in AUSTRALIA_BORDERS]
    return CSP(AUSTRALIA_REGIONS, {r: colors for r in AUSTRALIA_REGIONS}, constraints)


def n_queens(n: int) -> CSP:
    """Q<i> = row of the queen in column i; no two queens on the same row or diagonal."""
    cols = [f"Q{i}" for i in range(n)]
    constraints = []
    for i, j in combinations(range(n), 2):
        gap = j - i
        constraints.append(binary(
            "no_attack", cols[i], cols[j],
            lambda a, b, gap=gap: a != b and abs(a - b) != gap,
            f"queens in columns {i} and {j} must not attack"))
    return CSP(cols, {c: list(range(n)) for c in cols}, constraints)
