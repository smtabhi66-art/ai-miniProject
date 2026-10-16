"""Inference over the knowledge base: forward chaining (Modus Ponens) and Modus Tollens.

Forward chaining
    Repeat until nothing new can be derived (a fixpoint):
        for every rule P1 ∧ ... ∧ Pn ⇒ Q
            for every way to bind the variables so that all Pi are known facts
                add Q (with those bindings) to the KB
    Each addition is one application of (generalised) Modus Ponens:
        from P1, ..., Pn and (P1 ∧ ... ∧ Pn ⇒ Q), infer Q.
    Premises are matched left to right with backtracking over bindings (a join).
    It is sound and, for Horn clauses, complete: everything entailed is derived.
    Cost: each round is at most O(r · f^k) for r rules, f facts and k premises
    per rule; there are at most (number of possible ground facts) rounds.

Modus Tollens
    From (P ⇒ Q) and ¬Q, infer ¬P. Used by verification: the KB models attacker
    behaviour as ``ActiveCompromise(?d) ⇒ MaliciousActivity(?d)``. If no
    malicious activity is observed after containment, then ¬MaliciousActivity(d),
    so ¬ActiveCompromise(d).
"""
from dataclasses import dataclass
from typing import Iterator

from app.algorithms.logic.knowledge_base import KnowledgeBase, Proof
from app.algorithms.logic.predicate import Atom, Bindings, Rule, format_atom, substitute, unify


@dataclass(frozen=True)
class InferenceStep:
    kind: str           # "modus ponens" or "modus tollens"
    rule: str
    premises: tuple[Atom, ...]
    conclusion: Atom
    negated: bool = False

    def __str__(self) -> str:
        neg = "¬" if self.negated else ""
        if self.kind == "modus tollens":
            prem = f"¬{format_atom(self.premises[0])}"
        else:
            prem = " ∧ ".join(format_atom(p) for p in self.premises)
        return f"[{self.kind}] {self.rule}: {prem} ⊢ {neg}{format_atom(self.conclusion)}"


def match_premises(kb: KnowledgeBase, premises: tuple[Atom, ...], bindings: Bindings | None = None,
                   ) -> Iterator[Bindings]:
    """Every binding that satisfies all premises (a backtracking join)."""
    bindings = bindings or {}
    if not premises:
        yield bindings
        return
    first, rest = premises[0], premises[1:]
    for fact in sorted(kb.facts_for(first[0])):
        b = unify(first, fact, bindings)
        if b is not None:
            yield from match_premises(kb, rest, b)


def forward_chain(kb: KnowledgeBase, max_rounds: int = 100) -> list[InferenceStep]:
    """Apply every rule until a fixpoint. Returns the inference steps in order."""
    steps: list[InferenceStep] = []
    for _ in range(max_rounds):
        new: list[tuple[Rule, Atom, tuple[Atom, ...]]] = []
        for rule in kb.rules:
            for b in match_premises(kb, rule.premises):
                conclusion = substitute(rule.conclusion, b)
                if not kb.holds(conclusion) and all(conclusion != c for _, c, _ in new):
                    new.append((rule, conclusion, tuple(substitute(p, b) for p in rule.premises)))
        if not new:
            return steps
        for rule, conclusion, premises in new:
            kb.tell(conclusion, proof=Proof("derived", rule.name, premises))
            steps.append(InferenceStep("modus ponens", rule.name, premises, conclusion))
    raise RuntimeError(f"forward chaining did not reach a fixpoint in {max_rounds} rounds")


def modus_tollens(kb: KnowledgeBase, rule: Rule, not_conclusion: Atom) -> InferenceStep | None:
    """From ``rule = P(?x) ⇒ Q(?x)`` and known ¬Q(a), infer and tell ¬P(a).

    Only single-premise rules qualify: from ¬(P1 ∧ P2) we could not tell *which*
    premise is false.
    """
    if len(rule.premises) != 1 or not kb.holds_not(not_conclusion):
        return None
    b = unify(rule.conclusion, not_conclusion)
    if b is None:
        return None
    negated_premise = substitute(rule.premises[0], b)
    if any(t.startswith("?") for t in negated_premise[1:]):
        return None
    kb.tell_not(negated_premise, Proof("modus tollens", rule.name, (not_conclusion,)))
    return InferenceStep("modus tollens", rule.name, (not_conclusion,), negated_premise, negated=True)
