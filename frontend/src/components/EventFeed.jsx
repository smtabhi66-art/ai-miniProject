// Event log of what the agent perceived, plus attacks blocked by containment.
import React, { useState } from "react";
import { Empty } from "./common.jsx";
import { ArrowIcon, BlockIcon } from "./icons.jsx";

const TYPES = {
  normal_traffic: { label: "Normal traffic", sev: "info" },
  failed_login: { label: "Failed login", sev: "warning" },
  port_scan: { label: "Port scan", sev: "warning" },
  successful_login: { label: "Successful login", sev: "notice" },
  unusual_traffic: { label: "Unusual traffic", sev: "critical" },
  unauthorized_access: { label: "Unauthorized access", sev: "critical" },
};

export default function EventFeed({ events, suppressed }) {
  const [showNormal, setShowNormal] = useState(false);
  const [showBlocked, setShowBlocked] = useState(true);
  const rows = [
    ...events.filter((e) => showNormal || e.type !== "normal_traffic").map((e) => ({ ...e, blocked: false })),
    ...(showBlocked ? suppressed.map((e) => ({ ...e, blocked: true })) : []),
  ]
    .sort((a, b) => b.tick - a.tick || (a.id < b.id ? 1 : -1))
    .slice(0, 150);

  return (
    <div className="feed">
      <div className="feed-filters">
        <label className="toggle">
          <input type="checkbox" checked={showNormal} onChange={(e) => setShowNormal(e.target.checked)} />
          Normal traffic
        </label>
        <label className="toggle">
          <input type="checkbox" checked={showBlocked} onChange={(e) => setShowBlocked(e.target.checked)} />
          Blocked attempts
        </label>
      </div>
      {rows.length === 0 ? (
        <Empty>No security events yet.</Empty>
      ) : (
        <div className="feed-scroll">
          <table className="feed-table">
            <thead>
              <tr>
                <th>Tick</th>
                <th>Event</th>
                <th>Source → Target</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => {
                const t = TYPES[e.type] ?? { label: e.type, sev: "info" };
                return (
                  <tr key={`${e.id}-${e.blocked}`} className={e.blocked ? "row-blocked" : ""}>
                    <td className="num">{e.tick}</td>
                    <td>
                      <span className={`sev sev-${t.sev}`} aria-hidden="true" />
                      {t.label}
                    </td>
                    <td className="mono">
                      {e.source} <ArrowIcon size={11} /> {e.target ?? "—"}
                    </td>
                    <td>
                      {e.blocked ? (
                        <span className="outcome blocked" title={e.reason}>
                          <BlockIcon size={12} /> Blocked · {e.reason}
                        </span>
                      ) : (
                        <span className="outcome">Observed</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
