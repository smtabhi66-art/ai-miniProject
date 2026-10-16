// Small shared building blocks.
import React from "react";

const LEVEL = {
  normal: { icon: "●", label: "Normal" },
  suspicious: { icon: "▲", label: "Suspicious" },
  critical: { icon: "■", label: "Critical" },
};

// Threat level always shows icon + label, never colour alone.
export function LevelBadge({ level }) {
  const l = LEVEL[level] ?? LEVEL.normal;
  return (
    <span className={`badge level level-${level}`}>
      <span aria-hidden="true">{l.icon}</span> {l.label}
    </span>
  );
}

export function Chip({ children, tone = "neutral", title }) {
  return (
    <span className={`chip chip-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function Card({ title, extra, children, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {(title || extra) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {extra}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Empty({ children }) {
  return <p className="empty">{children}</p>;
}

export function Pre({ lines }) {
  if (!lines || lines.length === 0) return null;
  return <pre className="pre">{lines.join("\n")}</pre>;
}

export function Collapsible({ title, children, open = false }) {
  return (
    <details className="collapsible" open={open}>
      <summary>{title}</summary>
      {children}
    </details>
  );
}

export function TraceTable({ trace, columns }) {
  if (!trace || trace.length === 0) return <Empty>No trace recorded.</Empty>;
  return (
    <div className="table-wrap">
      <table className="table trace">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {trace.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c.key}>{c.render ? c.render(row) : formatCell(row[c.key])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function formatCell(v) {
  if (v === null || v === undefined) return "–";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

export function Path({ path }) {
  if (!path || path.length === 0) return <span className="muted">no route</span>;
  return <span className="path">{path.join(" → ")}</span>;
}

// Pick decision logs of one algorithm family, newest first.
export function logsOf(decisions, prefix) {
  return (decisions ?? []).filter((d) => d.algorithm.startsWith(prefix)).slice().reverse();
}

export function LogPicker({ logs, value, onChange }) {
  if (logs.length <= 1) return null;
  return (
    <select className="select small" value={value ?? logs[0].id} onChange={(e) => onChange(Number(e.target.value))}>
      {logs.map((l) => (
        <option key={l.id} value={l.id}>
          t={l.tick} · {l.summary.slice(0, 60)}
        </option>
      ))}
    </select>
  );
}
