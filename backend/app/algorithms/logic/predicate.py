"""First-order predicate atoms, variables, rules and unification.

An atom is a tuple ``(predicate, arg1, arg2, ...)``, e.g.
``("Connected", "WS1", "R1")`` for ``Connected(WS1, R1)``. Arguments that start
with ``?`` are variables, e.g. ``("Compromised", "?d")``.

Rules are definite (Horn) clauses, with all premises positive::

    BruteForcing(?s, ?t) ∧ LoggedIn(?s, ?t)  ⇒  Compromised(?t)

Variables are implicitly universally quantified. Rules must be *safe*: every
variable in the conclusion must appear in a premise.

Scope note: this is the Horn-clause (Datalog-style) subset of first-order logic.
It has no function symbols, no existential quantifiers and no resolution
theorem proving. That's enough for transparent security rules, and it is
documented as such.
"""
import re
from dataclasses import dataclass

Atom = tuple[str, ...]
Bindings = dict[str, str]

_ATOM_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$")


def is_var(term: str) -> bool:
    return term.startswith("?")


def parse_atom(text: str) -> Atom:
    """``"Connected(WS1, ?x)"`` -> ``("Connected", "WS1", "?x")``."""
    match = _ATOM_RE.match(text)
    if not match:
        raise ValueError(f"not an atom: {text!r}")
    name, args = match.groups()
    terms = [a.strip() for a in args.split(",")] if args.strip() else []
    if any(not t for t in terms):
        raise ValueError(f"empty argument in {text!r}")
    return (name, *terms)


def format_atom(atom: Atom) -> str:
    return f"{atom[0]}({', '.join(atom[1:])})"


def unify(pattern: Atom, fact: Atom, bindings: Bindings | None = None) -> Bindings | None:
    """Match a (possibly variable) pattern against a ground fact. None if they don't match."""
    if pattern[0] != fact[0] or len(pattern) != len(fact):
        return None
    result = dict(bindings or {})
    for p, f in zip(pattern[1:], fact[1:]):
        if is_var(p):
            if p in result and result[p] != f:
                return None
            result[p] = f
        elif p != f:
            return None
    return result


def substitute(atom: Atom, bindings: Bindings) -> Atom:
    return (atom[0], *(bindings.get(t, t) if is_var(t) else t for t in atom[1:]))


def variables(atom: Atom) -> set[str]:
    return {t for t in atom[1:] if is_var(t)}


@dataclass(frozen=True)
class Rule:
    name: str
    premises: tuple[Atom, ...]
    conclusion: Atom
    description: str = ""

    def __post_init__(self) -> None:
        if not self.premises:
            raise ValueError(f"rule {self.name} has no premises")
        unsafe = variables(self.conclusion) - set().union(*(variables(p) for p in self.premises))
        if unsafe:
            raise ValueError(f"rule {self.name}: conclusion variable(s) {sorted(unsafe)} not in any premise")

    @classmethod
    def parse(cls, name: str, premises: list[str], conclusion: str, description: str = "") -> "Rule":
        return cls(name, tuple(parse_atom(p) for p in premises), parse_atom(conclusion), description)

    def __str__(self) -> str:
        return f"{' ∧ '.join(format_atom(p) for p in self.premises)} ⇒ {format_atom(self.conclusion)}"
