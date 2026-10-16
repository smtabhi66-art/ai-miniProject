// Incidents: explanation (proof tree), CSP decision, HTN plan progress, verification and timeline.
import React from "react";
import { Chip, Collapsible, Empty, LevelBadge, Pre } from "./common.jsx";

const PHASES = ["Detect", "Investigate", "Contain", "Verify", "Recover"];
const STATUS_TONE = { open: "warning", contained: "info", resolved: "good", escalated: "critical" };

function PhaseStepper({ incident }) {
  const done = incident.phase === "Done";
  const current = PHASES.indexOf(incident.phase === "Escalate" ? "Contain" : incident.phase);
  return (
    <ol className="stepper">
      {PHASES.map((p, i) => {
        const state = done || i < current ? "done" : i === current ? "current" : "todo";
        return (
          <li key={p} className={`step step-${state}`}>
            <span aria-hidden="true">{state === "done" ? "✓" : state === "current" ? "▶" : "○"}</span> {p}
          </li>
        );
      })}
    </ol>
  );
}

function PlanList({ incident }) {
  if (!incident.plan?.length) return <Empty>Waiting for a containment decision.</Empty>;
  return (
    <ol className="plan">
      {incident.plan.map((step, i) => {
        const state = i < incident.plan_index ? "done" : i === incident.plan_index && !incident.closed_tick ? "current" : "todo";
        return (
          <li key={i} className={`plan-step plan-${state}`}>
            <span aria-hidden="true">{state === "done" ? "✓" : state === "current" ? "▶" : "○"}</span> {step}
          </li>
        );
      })}
    </ol>
  );
}

export default function IncidentsPanel({ incidents, onSelectDevice }) {
  if (!incidents.length) return <Empty>No incidents. The agent has not flagged any internal device.</Empty>;
  // Open incidents first, then newest first.
  const sorted = [...incidents].sort(
    (a, b) => (b.closed_tick === null) - (a.closed_tick === null) || b.opened_tick - a.opened_tick,
  );
  return (
    <div className="incidents">
      {sorted.map((inc) => (
        <article key={inc.id} className={`incident level-${inc.level}`}>
          <header className="incident-head">
            <strong>{inc.id}</strong>
            <button className="link" onClick={() => onSelectDevice(inc.devices[0])}>
              {inc.devices.join(", ")}
            </button>
            <LevelBadge level={inc.level} />
            {inc.decision && <Chip tone="info" title="CSP decision">{inc.decision}</Chip>}
            <Chip tone={STATUS_TONE[inc.status]}>{inc.status}</Chip>
            {inc.verified && <Chip tone="good">verified</Chip>}
            <span className="muted small">
              t={inc.opened_tick}
              {inc.closed_tick !== null ? `–${inc.closed_tick}` : " → now"}
            </span>
          </header>
          <PhaseStepper incident={inc} />
          <div className="incident-grid">
            <div>
              <h3>Why (proof tree)</h3>
              <Pre lines={inc.explanation} />
            </div>
            <div>
              <h3>Plan (HTN)</h3>
              <PlanList incident={inc} />
            </div>
          </div>
          {inc.verification?.length > 0 && (
            <>
              <h3>Verification</h3>
              <Pre lines={inc.verification} />
            </>
          )}
          <Collapsible title={`Timeline (${inc.timeline.length})`}>
            <ul className="timeline">
              {inc.timeline.map((t, i) => (
                <li key={i}>{t}</li>
              ))}
            </ul>
          </Collapsible>
          {inc.actions_taken.length > 0 && (
            <Collapsible title={`Simulated actions (${inc.actions_taken.length})`}>
              <ul className="timeline">
                {inc.actions_taken.map((a, i) => (
                  <li key={i}>
                    t={a.tick} {a.action}({a.params.device}) — {a.success ? "ok" : "FAILED"} · simulated
                  </li>
                ))}
              </ul>
            </Collapsible>
          )}
        </article>
      ))}
    </div>
  );
}
