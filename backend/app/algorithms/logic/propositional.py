"""Propositional logic: symbols, connectives, truth tables and entailment.

Expressions are trees built from Symbol, Not, And, Or, Implies and Iff. Python
operators give a compact syntax:

    ~P        Not(P)
    P & Q     And(P, Q)
    P | Q     Or(P, Q)
    P >> Q    Implies(P, Q)
    P.iff(Q)  Iff(P, Q)

``tt_entails(kb, alpha)`` decides KB |= alpha by model checking: alpha must be
true in every model (truth assignment) where KB is true. That's O(2^n) for n
symbols, which is fine for the small security rule sets used here.

``modus_ponens`` and ``modus_tollens`` are the two inference rules as functions.
The tests prove them *sound* by checking each conclusion with ``tt_entails``.
In SentinelAI the same reasoning runs on predicate facts (see inference.py).
This module is the educational, propositional version.
"""
from dataclasses import dataclass
from itertools import product
from typing import Iterator

Model = dict[str, bool]


class Expr:
    def evaluate(self, model: Model) -> bool:
        raise NotImplementedError

    def symbols(self) -> set[str]:
        raise NotImplementedError

    def __invert__(self) -> "Expr":
        return Not(self)

    def __and__(self, other: "Expr") -> "Expr":
        return And(self, other)

    def __or__(self, other: "Expr") -> "Expr":
        return Or(self, other)

    def __rshift__(self, other: "Expr") -> "Expr":
        return Implies(self, other)

    def iff(self, other: "Expr") -> "Expr":
        return Iff(self, other)


@dataclass(frozen=True)
class Symbol(Expr):
    name: str

    def evaluate(self, model: Model) -> bool:
        if self.name not in model:
            raise KeyError(f"no truth value for {self.name}")
        return model[self.name]

    def symbols(self) -> set[str]:
        return {self.name}

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Not(Expr):
    operand: Expr

    def evaluate(self, model: Model) -> bool:
        return not self.operand.evaluate(model)

    def symbols(self) -> set[str]:
        return self.operand.symbols()

    def __str__(self) -> str:
        return f"¬{self.operand}"


@dataclass(frozen=True)
class _Binary(Expr):
    left: Expr
    right: Expr
    symbol = "?"

    def symbols(self) -> set[str]:
        return self.left.symbols() | self.right.symbols()

    def __str__(self) -> str:
        return f"({self.left} {self.symbol} {self.right})"


class And(_Binary):
    symbol = "∧"

    def evaluate(self, model: Model) -> bool:
        return self.left.evaluate(model) and self.right.evaluate(model)


class Or(_Binary):
    symbol = "∨"

    def evaluate(self, model: Model) -> bool:
        return self.left.evaluate(model) or self.right.evaluate(model)


class Implies(_Binary):
    symbol = "→"

    def evaluate(self, model: Model) -> bool:
        return (not self.left.evaluate(model)) or self.right.evaluate(model)


class Iff(_Binary):
    symbol = "↔"

    def evaluate(self, model: Model) -> bool:
        return self.left.evaluate(model) == self.right.evaluate(model)


def conjunction(*exprs: Expr) -> Expr:
    if not exprs:
        raise ValueError("empty conjunction")
    result = exprs[0]
    for e in exprs[1:]:
        result = And(result, e)
    return result


def all_models(symbols: set[str]) -> Iterator[Model]:
    names = sorted(symbols)
    for values in product([False, True], repeat=len(names)):
        yield dict(zip(names, values))


def truth_table(expr: Expr) -> list[tuple[Model, bool]]:
    return [(m, expr.evaluate(m)) for m in all_models(expr.symbols())]


def tt_entails(kb: Expr, alpha: Expr) -> bool:
    """KB |= alpha: in every model where KB is true, alpha is true too."""
    symbols = kb.symbols() | alpha.symbols()
    return all(alpha.evaluate(m) for m in all_models(symbols) if kb.evaluate(m))


def is_satisfiable(expr: Expr) -> bool:
    return any(value for _, value in truth_table(expr))


def is_valid(expr: Expr) -> bool:
    return all(value for _, value in truth_table(expr))


def modus_ponens(rule: Expr, fact: Expr) -> Expr | None:
    """From P → Q and P, conclude Q."""
    if isinstance(rule, Implies) and rule.left == fact:
        return rule.right
    return None


def modus_tollens(rule: Expr, negated_consequent: Expr) -> Expr | None:
    """From P → Q and ¬Q, conclude ¬P."""
    if isinstance(rule, Implies) and negated_consequent == Not(rule.right):
        return Not(rule.left)
    return None
