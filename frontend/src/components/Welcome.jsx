// Landing view: what the agent does, and one card per scenario.
import React from "react";
import { ArrowIcon, ShieldIcon } from "./icons.jsx";

const PIPELINE = [
  ["Perceive", "security events"],
  ["Reason", "logic rules · Modus Ponens"],
  ["Investigate", "BFS · DFS · Greedy · A*"],
  ["Decide", "constraint satisfaction"],
  ["Plan", "HTN · goal-stack"],
  ["Verify", "Modus Tollens"],
];

export default function Welcome({ scenarios, selected, onPick, onLaunch }) {
  return (
    <main className="welcome">
      <section className="hero-card">
        <div className="hero-icon"><ShieldIcon size={28} /></div>
        <div>
          <h2>Autonomous defense for a simulated enterprise network</h2>
          <p className="muted">
            Pick a scenario and launch it. The agent detects threats, explains its reasoning, contains them safely
            and verifies the outcome. Every action is simulated; no real system is touched.
          </p>
          <ol className="pipeline">
            {PIPELINE.map(([step, how], i) => (
              <li key={step}>
                <span className="pipeline-step">{step}</span>
                <span className="pipeline-how">{how}</span>
                {i < PIPELINE.length - 1 && <ArrowIcon size={14} className="pipeline-arrow" />}
              </li>
            ))}
          </ol>
        </div>
      </section>

      <h2 className="section-title">Scenarios</h2>
      <div className="scenario-grid">
        {scenarios.map((s) => {
          const [num, ...rest] = s.name.split(". ");
          return (
            <button key={s.id} className={`scenario-card ${selected === s.id ? "selected" : ""}`}
                    onClick={() => onPick(s.id)} onDoubleClick={() => onLaunch(s.id)}>
              <span className="scenario-num">{num}</span>
              <span className="scenario-title">{rest.join(". ")}</span>
              <span className="scenario-desc">{s.description}</span>
              <span className="scenario-meta">
                {s.ticks} ticks · {Object.keys(s.expected).length || "no"} threat{Object.keys(s.expected).length === 1 ? "" : "s"} to find
              </span>
            </button>
          );
        })}
        <button className={`scenario-card ${selected === "random" ? "selected" : ""}`}
                onClick={() => onPick("random")} onDoubleClick={() => onLaunch("random")}>
          <span className="scenario-num">?</span>
          <span className="scenario-title">Random scenario</span>
          <span className="scenario-desc">A new attack sequence generated from the seed: brute force, insider scanning
            or data exfiltration on randomly chosen machines.</span>
          <span className="scenario-meta">Change the seed for a different attack</span>
        </button>
      </div>
      <p className="muted small">Click a card to select it, then press <strong>Launch</strong>, or double-click to launch at once.</p>
    </main>
  );
}
