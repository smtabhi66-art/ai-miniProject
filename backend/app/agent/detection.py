"""Threat detection: events -> facts -> forward chaining -> Normal / Suspicious / Critical.

Each tick the detector builds a fresh knowledge base from three sources:

* topology facts   Internal(d), External(d), CriticalAsset(d), Hosts(d, s), Connected(a, b)
* evidence facts   counted from recent events by the configurable evidence rules,
                   e.g. FailedLoginBurst(WS1) when 5+ failed logins hit WS1 within 3 ticks
* beliefs          conclusions the agent keeps between ticks, e.g. Compromised(WS2)

It then runs forward chaining (Modus Ponens) with the security rules and maps
the conclusions to threat levels. The proof tree of each conclusion becomes
the explanation shown on the dashboard. All thresholds and rules live in
``data/rules/security_rules.json``.
"""
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.algorithms.logic.inference import InferenceStep, forward_chain
from app.algorithms.logic.knowledge_base import KnowledgeBase
from app.algorithms.logic.predicate import Atom, Rule, format_atom
from app.core.config import RULES_DIR
from app.models.enums import DeviceType, EventType, ThreatLevel
from app.models.events import SecurityEvent
from app.models.network import NetworkState

LEVEL_RANK = {ThreatLevel.NORMAL: 0, ThreatLevel.SUSPICIOUS: 1, ThreatLevel.CRITICAL: 2}
RISK = {ThreatLevel.NORMAL: 0.0, ThreatLevel.SUSPICIOUS: 0.5, ThreatLevel.CRITICAL: 0.95}


@dataclass(frozen=True)
class EvidenceRule:
    fact: str
    event: EventType
    about: str          # "source", "target" or "pair"
    window: int
    threshold: int
    description: str = ""


@dataclass
class SecurityRules:
    evidence_rules: list[EvidenceRule]
    rules: list[Rule]
    critical: list[str]
    suspicious: list[str]
    verification_rule: str
    observed_fact: str
    quiet_ticks: int

    def rule(self, name: str) -> Rule:
        return next(r for r in self.rules if r.name == name)


def load_security_rules(path: Path | None = None) -> SecurityRules:
    path = path or RULES_DIR / "security_rules.json"
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    evidence = []
    for raw in data["evidence_rules"]:
        rule = EvidenceRule(raw["fact"], EventType(raw["event"]), raw["about"], int(raw["window"]),
                            int(raw["threshold"]), raw.get("description", ""))
        if rule.about not in ("source", "target", "pair") or rule.window < 1 or rule.threshold < 1:
            raise ValueError(f"bad evidence rule {rule.fact}")
        evidence.append(rule)
    rules = [Rule.parse(r["name"], r["if"], r["then"], r.get("description", "")) for r in data["rules"]]
    if len({r.name for r in rules}) != len(rules):
        raise ValueError("duplicate rule names")
    verification = data["verification"]
    result = SecurityRules(evidence, rules, list(data["classification"]["critical"]),
                           list(data["classification"]["suspicious"]), verification["rule"],
                           verification["observed_fact"], int(verification["quiet_ticks"]))
    result.rule(result.verification_rule)  # must exist
    return result


def topology_facts(state: NetworkState) -> list[Atom]:
    facts: list[Atom] = []
    for d in state.devices.values():
        facts.append(("External", d.id) if d.type is DeviceType.EXTERNAL else ("Internal", d.id))
        for s in d.services:
            facts.append(("Hosts", d.id, s))
    for s in state.services.values():
        if s.critical:
            facts.append(("CriticalService", s.name))
            facts.extend(("CriticalAsset", h) for h in s.hosts)
    for link in state.links():
        if link.is_active:
            facts.append(("Connected", link.source, link.target))
            facts.append(("Connected", link.target, link.source))
    return facts


def evidence_facts(events: list[SecurityEvent], tick: int, rules: list[EvidenceRule],
                   cleared_at: dict[str, int] | None = None) -> list[tuple[Atom, str]]:
    """Facts supported by recent events, each with a human-readable note.

    Events about a device at or before the tick it was cleared (recovered) are ignored,
    so old evidence cannot re-open a closed incident.
    """
    cleared_at = cleared_at or {}

    def stale(e: SecurityEvent) -> bool:
        return any(d is not None and e.tick <= cleared_at.get(d, -1) for d in (e.source, e.target))

    out = []
    for rule in rules:
        counts: Counter = Counter()
        first: dict[tuple, int] = {}
        for e in events:
            if e.type is not rule.event or not (tick - rule.window < e.tick <= tick) or stale(e):
                continue
            if rule.about == "source":
                key = (e.source,)
            elif rule.about == "target":
                if e.target is None:
                    continue
                key = (e.target,)
            else:
                if e.target is None:
                    continue
                key = (e.source, e.target)
            counts[key] += 1
            first[key] = min(first.get(key, e.tick), e.tick)
        for key, n in sorted(counts.items()):
            if n >= rule.threshold:
                note = (f"{n} {rule.event.value} event(s) in ticks {first[key]}-{tick} "
                        f"(threshold {rule.threshold} in {rule.window})")
                out.append(((rule.fact, *key), note))
    return out


@dataclass
class Assessment:
    tick: int
    levels: dict[str, ThreatLevel]
    kb: KnowledgeBase
    steps: list[InferenceStep]
    triggers: dict[str, list[Atom]] = field(default_factory=dict)  # device -> facts that set its level

    def explanation(self, device: str) -> list[str]:
        lines = []
        for fact in self.triggers.get(device, []):
            lines.extend(self.kb.explain(fact))
        return lines

    def to_dict(self) -> dict[str, Any]:
        return {
            "tick": self.tick,
            "levels": {d: lvl.value for d, lvl in self.levels.items() if lvl is not ThreatLevel.NORMAL},
            "inferences": [str(s) for s in self.steps],
            "facts": sorted(format_atom(f) for f in self.kb.facts
                            if self.kb.proofs[f].source != "topology"),
            "explanations": {d: self.explanation(d) for d in self.triggers},
        }


class ThreatDetector:
    def __init__(self, rules: SecurityRules | None = None):
        self.rules = rules or load_security_rules()
        self.window = max(r.window for r in self.rules.evidence_rules)

    def assess(self, state: NetworkState, events: list[SecurityEvent], tick: int,
               cleared_at: dict[str, int] | None = None) -> Assessment:
        kb = KnowledgeBase(rules=list(self.rules.rules))
        for fact in topology_facts(state):
            kb.tell(fact, source="topology")
        for fact in sorted(state.facts):
            kb.tell(fact, source="belief", note="concluded earlier and kept until recovery")
        recent = [e for e in events if e.tick > tick - self.window]
        for fact, note in evidence_facts(recent, tick, self.rules.evidence_rules, cleared_at):
            kb.tell(fact, source="observed", note=note)
        steps = forward_chain(kb)

        levels = {d: ThreatLevel.NORMAL for d in state.devices}
        triggers: dict[str, list[Atom]] = {}
        for level, predicates in ((ThreatLevel.CRITICAL, self.rules.critical),
                                  (ThreatLevel.SUSPICIOUS, self.rules.suspicious)):
            for pred in predicates:
                for fact in sorted(kb.facts_for(pred)):
                    device = fact[1]
                    if device not in levels:
                        continue
                    if LEVEL_RANK[level] > LEVEL_RANK[levels[device]]:
                        levels[device] = level
                        triggers[device] = []
                    if levels[device] is level:
                        triggers[device].append(fact)
        return Assessment(tick, levels, kb, steps, triggers)
