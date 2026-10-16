// Performance measure, score over time, detection metrics and run history.
import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { Chip, Empty } from "./common.jsx";

const LABELS = {
  contained: "Threats contained",
  outage_ticks: "Critical-service outage ticks",
  healthy_isolated: "Healthy devices isolated",
  active_compromise_ticks: "Ticks a compromised device ran free",
  false_positives: "False-positive incidents",
};

// Single-series line chart: score per tick. No legend (the title names the series);
// crosshair + tooltip on hover; recessive grid; zero baseline.
function ScoreChart({ timeline }) {
  const [hover, setHover] = useState(null);
  if (!timeline.length) return <Empty>The chart appears after the first tick.</Empty>;
  const W = 560, H = 180, L = 36, R = 12, T = 12, B = 26;
  const ticks = timeline.map((p) => p.tick);
  const scores = timeline.map((p) => p.score);
  const minY = Math.min(0, ...scores), maxY = Math.max(10, ...scores);
  const x = (t) => L + ((t - ticks[0]) / Math.max(1, ticks[ticks.length - 1] - ticks[0])) * (W - L - R);
  const y = (s) => T + (1 - (s - minY) / (maxY - minY || 1)) * (H - T - B);
  const path = timeline.map((p, i) => `${i ? "L" : "M"}${x(p.tick)},${y(p.score)}`).join(" ");
  const yTicks = [minY, 0, maxY].filter((v, i, a) => a.indexOf(v) === i);
  const step = (W - L - R) / Math.max(1, timeline.length - 1);
  const last = timeline[timeline.length - 1];

  return (
    <figure className="chart">
      <figcaption>Performance score over time</figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Line chart of the performance score per tick">
        {yTicks.map((v) => (
          <g key={v}>
            <line x1={L} x2={W - R} y1={y(v)} y2={y(v)} className={v === 0 ? "axis-zero" : "gridline"} />
            <text x={L - 6} y={y(v) + 4} className="axis-label" textAnchor="end">{v}</text>
          </g>
        ))}
        {[ticks[0], ticks[ticks.length - 1]].map((t) => (
          <text key={t} x={x(t)} y={H - 8} className="axis-label" textAnchor="middle">t={t}</text>
        ))}
        <path d={path} className="series-line" />
        <circle cx={x(last.tick)} cy={y(last.score)} r={4} className="series-dot" />
        <text x={x(last.tick) - 6} y={y(last.score) - 8 < T + 6 ? y(last.score) + 16 : y(last.score) - 8} className="direct-label" textAnchor="end">{last.score}</text>
        {hover && (
          <g>
            <line x1={x(hover.tick)} x2={x(hover.tick)} y1={T} y2={H - B} className="crosshair" />
            <circle cx={x(hover.tick)} cy={y(hover.score)} r={4} className="series-dot" />
          </g>
        )}
        {timeline.map((p) => (
          <rect key={p.tick} x={x(p.tick) - step / 2} y={T} width={Math.max(step, 6)} height={H - T - B}
                fill="transparent" onMouseEnter={() => setHover(p)} onMouseLeave={() => setHover(null)} />
        ))}
      </svg>
      {hover && (
        <div className="tooltip" style={{ left: `${(x(hover.tick) / W) * 100}%` }}>
          <strong>t={hover.tick}</strong> score {hover.score}
        </div>
      )}
    </figure>
  );
}

const SEQ = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95"];

function ConfusionMatrix({ matrix }) {
  const levels = ["normal", "suspicious", "critical"];
  const max = Math.max(1, ...levels.flatMap((e) => levels.map((p) => matrix[e][p])));
  return (
    <table className="table matrix" aria-label="Confusion matrix">
      <thead>
        <tr>
          <th>Expected ↓ / Predicted →</th>
          {levels.map((l) => <th key={l}>{l}</th>)}
        </tr>
      </thead>
      <tbody>
        {levels.map((e) => (
          <tr key={e}>
            <th>{e}</th>
            {levels.map((p) => {
              const n = matrix[e][p];
              const idx = n === 0 ? -1 : Math.min(SEQ.length - 1, Math.round((n / max) * (SEQ.length - 1)));
              return (
                <td key={p} title={`${n} device(s): expected ${e}, predicted ${p}`}
                    style={idx >= 0 ? { background: SEQ[idx], color: idx >= 3 ? "#fff" : "#0b0b0b" } : undefined}
                    className={e === p ? "diag" : ""}>
                  {n}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ReportPanel({ performance, finished, tick, seed }) {
  const [summary, setSummary] = useState(null);
  const [evaluation, setEvaluation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (finished) api.summary().then(setSummary).catch((e) => setError(e.message));
    else setSummary(null);
  }, [finished, tick]);

  const evaluate = async () => {
    setBusy(true);
    setError(null);
    try {
      setEvaluation(await api.evaluation(seed ?? 42));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <div className="hero">
        <span className="hero-number">{performance.score}</span>
        <span className="muted">performance score (rationality measure, computed by the environment)</span>
      </div>
      <table className="table">
        <thead>
          <tr><th>Measure</th><th>Count</th><th>Weight</th><th>Points</th></tr>
        </thead>
        <tbody>
          {Object.entries(performance.counts).map(([k, v]) => (
            <tr key={k}>
              <td>{LABELS[k] ?? k}</td><td>{v}</td><td>{performance.weights[k]}</td><td>{v * performance.weights[k]}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <ScoreChart timeline={performance.timeline} />

      <h3>Detection accuracy (this run)</h3>
      {!finished ? (
        <Empty>Available when the scenario finishes.</Empty>
      ) : summary ? (
        <>
          <p>
            Accuracy <strong>{summary.detection.accuracy}</strong> ({summary.mode} mode).{" "}
            {summary.mode === "active" && <span className="muted">Containment can stop an attack before every stage is seen; use passive mode for pure detection accuracy.</span>}
          </p>
          <ConfusionMatrix matrix={summary.detection.confusion_matrix} />
          {summary.detection.mistakes.length > 0 && (
            <ul className="mono-list">
              {summary.detection.mistakes.map((m) => (
                <li key={m.device}>{m.device}: expected {m.expected}, predicted {m.predicted}</li>
              ))}
            </ul>
          )}
          <p className="muted small">
            Attack events delivered {summary.attack_events.delivered} · prevented by containment {summary.attack_events.prevented}
          </p>
        </>
      ) : (
        <Empty>Loading…</Empty>
      )}

      <h3>Evaluate all scenarios</h3>
      <button className="btn" onClick={evaluate} disabled={busy}>{busy ? "Running…" : "Run evaluation"}</button>
      {error && <p className="result critical">{error}</p>}
      {evaluation && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>Scenario</th><th>Score</th><th>Detection acc. (passive)</th><th>Outage</th><th>Over-reaction</th><th>Incidents</th></tr>
            </thead>
            <tbody>
              {evaluation.map((r) => (
                <tr key={r.scenario}>
                  <td>{r.name}</td>
                  <td>{r.score}</td>
                  <td>{r.detection_accuracy}</td>
                  <td>{r.counts.outage_ticks}</td>
                  <td>{r.counts.healthy_isolated}</td>
                  <td>{r.incidents.map((i) => `${i.device}:${i.decision}`).join(" ") || "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function HistoryPanel({ refreshKey }) {
  const [runs, setRuns] = useState([]);
  const [detail, setDetail] = useState(null);
  useEffect(() => {
    api.runs().then(setRuns).catch(() => setRuns([]));
  }, [refreshKey]);
  if (!runs.length) return <Empty>No runs stored yet.</Empty>;
  return (
    <div className="panel">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr><th>#</th><th>Scenario</th><th>Mode</th><th>Seed</th><th>Ticks</th><th>Score</th><th>Incidents</th><th>Actions</th><th /></tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}>
                <td>{r.id}</td><td>{r.scenario_name}</td><td>{r.mode}</td><td>{r.seed}</td>
                <td>{r.ticks}{r.finished_at ? "" : " (running)"}</td><td>{r.final_score ?? "–"}</td>
                <td>{r.incidents}</td><td>{r.actions}</td>
                <td><button className="link small" onClick={() => api.runDetail(r.id).then(setDetail)}>details</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {detail && (
        <div className="history-detail">
          <h3>Run #{detail.id}: {detail.scenario_name}</h3>
          <p className="muted small">{detail.event_count} events · {detail.decision_count} logged decisions · started {detail.started_at}</p>
          {detail.incidents.map((i) => (
            <p key={i.id}>
              <strong>{i.id}</strong> {i.devices.join(", ")} · {i.level} · <Chip tone="info">{i.decision ?? "–"}</Chip> <Chip>{i.status}</Chip>
            </p>
          ))}
        </div>
      )}
    </div>
  );
}
