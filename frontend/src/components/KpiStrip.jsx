// Summary tiles across the top of the console. Every number comes from the backend snapshot.
import React from "react";

function Tile({ label, value, sub, children }) {
  return (
    <div className="kpi">
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">{value}</span>
      {sub && <span className="kpi-sub">{sub}</span>}
      {children}
    </div>
  );
}

export default function KpiStrip({ snap }) {
  const devices = snap.network.devices;
  const critical = devices.filter((d) => d.threat_level === "critical").length;
  const suspicious = devices.filter((d) => d.threat_level === "suspicious").length;
  const isolated = devices.filter((d) => d.status === "isolated").length;
  const restricted = devices.filter((d) => d.status === "restricted").length;
  const open = snap.incidents.filter((i) => i.closed_tick === null).length;
  const progress = Math.min(100, Math.round((snap.tick / snap.total_ticks) * 100));
  const counts = snap.performance.counts;

  return (
    <section className="kpis" aria-label="Summary">
      <Tile label="Performance score" value={snap.performance.score}
            sub={`${counts.contained} contained · ${counts.outage_ticks} outage ticks`} />
      <Tile label="Simulation progress" value={`${snap.tick} / ${snap.total_ticks}`}
            sub={snap.finished ? "Finished" : `${progress}% complete`}>
        <div className="progress" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
          <span style={{ width: `${progress}%` }} />
        </div>
      </Tile>
      <Tile label="Incidents" value={open} sub={`open · ${snap.incidents.length} total`} />
      <Tile label="Threat posture"
            value={
              <span className="posture">
                <span className="posture-item"><span className="dot dot-critical" aria-hidden="true" />{critical}</span>
                <span className="posture-item"><span className="dot dot-suspicious" aria-hidden="true" />{suspicious}</span>
              </span>
            }
            sub="critical · suspicious devices" />
      <Tile label="Contained" value={isolated + restricted} sub={`${isolated} isolated · ${restricted} restricted`} />
      <Tile label="Attacks blocked" value={snap.suppressed.length} sub="prevented by containment" />
    </section>
  );
}
