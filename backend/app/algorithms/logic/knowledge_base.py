"""Knowledge base: ground facts, rules, negative facts and the proof of every fact.

Every fact remembers *how* it got into the KB:

* source "observed" / "topology" / "belief": told from outside, with a note
* source "derived": produced by a rule from specific premises (Modus Ponens)
* negative facts produced by Modus Tollens carry their proof too

``explain()`` turns those records into a readable proof tree, which is how the
dashboard shows why a device was classified Critical.
"""
from dataclasses import dataclass, field

from app.algorithms.logic.predicate import Atom, Bindings, Rule, format_atom, unify


@dataclass(frozen=True)
class Proof:
    source: str                      # "observed", "topology", "belief", "derived", "modus tollens"
    rule: str | None = None
    premises: tuple[Atom, ...] = ()
    note: str = ""


@dataclass
class KnowledgeBase:
    rules: list[Rule] = field(default_factory=list)
    facts: set[Atom] = field(default_factory=set)
    negated: set[Atom] = field(default_factory=set)
    proofs: dict[Atom, Proof] = field(default_factory=dict)
    negated_proofs: dict[Atom, Proof] = field(default_factory=dict)
    _index: dict[str, set[Atom]] = field(default_factory=dict, repr=False)

    def add_rule(self, rule: Rule) -> None:
        if any(r.name == rule.name for r in self.rules):
            raise ValueError(f"duplicate rule name: {rule.name}")
        self.rules.append(rule)

    def tell(self, fact: Atom, source: str = "observed", note: str = "", proof: Proof | None = None) -> bool:
        """Add a ground fact. Returns False if it was already known."""
        if any(t.startswith("?") for t in fact[1:]):
            raise ValueError(f"facts must be ground: {format_atom(fact)}")
        if fact in self.negated:
            raise ValueError(f"contradiction: {format_atom(fact)} is already known to be false")
        if fact in self.facts:
            return False
        self.facts.add(fact)
        self._index.setdefault(fact[0], set()).add(fact)
        self.proofs[fact] = proof or Proof(source, note=note)
        return True

    def tell_not(self, fact: Atom, proof: Proof) -> bool:
        if fact in self.facts:
            raise ValueError(f"contradiction: {format_atom(fact)} is already known to be true")
        if fact in self.negated:
            return False
        self.negated.add(fact)
        self.negated_proofs[fact] = proof
        return True

    def holds(self, fact: Atom) -> bool:
        return fact in self.facts

    def holds_not(self, fact: Atom) -> bool:
        return fact in self.negated

    def facts_for(self, predicate: str) -> set[Atom]:
        return self._index.get(predicate, set())

    def ask(self, pattern: Atom) -> list[Bindings]:
        """All variable bindings that make ``pattern`` a known fact."""
        results = []
        for fact in sorted(self.facts_for(pattern[0])):
            b = unify(pattern, fact)
            if b is not None:
                results.append(b)
        return results

    def explain(self, fact: Atom, negated: bool = False, indent: int = 0, _seen: set | None = None) -> list[str]:
        """Proof tree for ``fact`` as indented lines."""
        seen = _seen if _seen is not None else set()
        pad = "  " * indent
        text = ("¬" if negated else "") + format_atom(fact)
        proof = (self.negated_proofs if negated else self.proofs).get(fact)
        if proof is None:
            return [f"{pad}{text}  [unknown]"]
        if proof.rule is None:
            note = f": {proof.note}" if proof.note else ""
            return [f"{pad}{text}  [{proof.source}{note}]"]
        if (fact, negated) in seen:
            return [f"{pad}{text}  [see above]"]
        seen.add((fact, negated))
        lines = [f"{pad}{text}  [{proof.source} by {proof.rule}]"]
        for premise in proof.premises:
            premise_negated = proof.source == "modus tollens" and premise in self.negated
            lines.extend(self.explain(premise, premise_negated, indent + 1, seen))
        return lines
