"""Verification: did containment actually work? (Modus Tollens)

The knowledge base models attacker behaviour in this simulation:

    V1:  ActiveCompromise(?d)  ⇒  MaliciousActivity(?d)

After containment the agent watches the device for ``quiet_ticks`` ticks.
MaliciousActivity(d) is re-derived from *only* the events after containment,
using the same evidence rules and forward chaining as detection.

* If it holds, containment failed and the incident is escalated.
* If it does not hold for the whole window, the agent tells the KB
  ¬MaliciousActivity(d) and applies Modus Tollens with V1:
      ¬MaliciousActivity(d)  ⊢  ¬ActiveCompromise(d)
  so the device is no longer an active threat. Only then may the incident be resolved.
"""
from dataclasses import dataclass, field

from app.agent.detection import SecurityRules, evidence_facts
from app.algorithms.logic.inference import forward_chain, modus_tollens
from app.algorithms.logic.knowledge_base import KnowledgeBase, Proof
from app.models.events import SecurityEvent


@dataclass
class VerificationResult:
    status: str                    # "pending", "passed" or "failed"
    lines: list[str] = field(default_factory=list)


def check_containment(device: str, contained_tick: int, tick: int, events: list[SecurityEvent],
                      rules: SecurityRules) -> VerificationResult:
    """Decide whether containment of ``device`` (done at ``contained_tick``) is verified at ``tick``."""
    after = [e for e in events if e.tick > contained_tick]
    kb = KnowledgeBase(rules=[r for r in rules.rules if r.conclusion[0] == rules.observed_fact])
    # Every evidence window is cut at the containment tick: older events cannot count.
    for fact, note in evidence_facts(after, tick, rules.evidence_rules):
        kb.tell(fact, note=note)
    forward_chain(kb)
    observed = (rules.observed_fact, device)
    if kb.holds(observed):
        return VerificationResult("failed", ["Containment FAILED: malicious activity continues"] + kb.explain(observed))

    watched = tick - contained_tick
    if watched < rules.quiet_ticks:
        return VerificationResult("pending", [f"watching {device}: {watched}/{rules.quiet_ticks} quiet tick(s)"])

    kb.tell_not(observed, Proof("observed", note=f"no malicious events from {device} in ticks "
                                                 f"{contained_tick + 1}-{tick}"))
    step = modus_tollens(kb, rules.rule(rules.verification_rule), observed)
    lines = [f"Rule {rules.verification_rule}: {rules.rule(rules.verification_rule)}", str(step)]
    lines += kb.explain(step.conclusion, negated=True)
    return VerificationResult("passed", lines)
