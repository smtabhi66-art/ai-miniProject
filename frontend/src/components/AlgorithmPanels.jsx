// Panels that show the real output of each AI algorithm, read from the agent's decision logs.
import React, { useState } from "react";
import { Chip, Collapsible, Empty, LevelBadge, LogPicker, Path, Pre, TraceTable, formatCell, logsOf } from "./common.jsx";

function usePicked(logs) {
  const [id, setId] = useState(null);
  const picked = logs.find((l) => l.id === id) ?? logs[0];
  return [picked, setId];
}

// ---- Logic -------------------------------------------------------------------------
export function ReasoningPanel({ assessment, decisions }) {
  const logs = logsOf(decisions, "Logic");
  const [picked, setPicked] = usePicked(logs);
  const data = picked?.data ?? assessment;
  if (!data) return <Empty>No reasoning yet. Step the simulation.</Empty>;
  const levels = Object.entries(data.levels ?? {});
  return (
    <div className="panel">
      <div className="panel-bar">
        <span className="muted">Knowledge base at t={data.tick} · forward chaining (Modus Ponens)</span>
        <LogPicker logs={logs} value={picked?.id} onChange={setPicked} />
      </div>
      <h3>Classification</h3>
      {levels.length === 0 ? (
        <Empty>All devices Normal: no rule fired.</Empty>
      ) : (
        levels.map(([device, level]) => (
          <div key={device} className="explain">
            <div className="explain-head">
              <strong>{device}</strong> <LevelBadge level={level} />
            </div>
            <Pre lines={data.explanations?.[device]} />
          </div>
        ))
      )}
      <h3>Inference steps ({data.inferences?.length ?? 0})</h3>
      {data.inferences?.length ? (
        <ul className="mono-list">
          {data.inferences.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ul>
      ) : (
        <Empty>No rule fired at this tick.</Empty>
      )}
      <Collapsible title={`Facts in the KB, excluding topology (${data.facts?.length ?? 0})`}>
        <div className="chips">
          {(data.facts ?? []).map((f) => (
            <Chip key={f}>{f}</Chip>
          ))}
        </div>
      </Collapsible>
    </div>
  );
}

// ---- Search ------------------------------------------------------------------------
export function SearchPanel({ decisions, onHighlight, highlight }) {
  const logs = logsOf(decisions, "Search");
  const [picked, setPicked] = usePicked(logs);
  if (!picked) return <Empty>No investigation yet. The agent runs BFS, DFS, Greedy and A* when an incident is investigated.</Empty>;
  const d = picked.data;
  const show = (path, kind, label) => onHighlight(path?.length ? { path, kind, label } : null);
  const isOn = (path) => highlight && JSON.stringify(highlight.path) === JSON.stringify(path);
  const HL = ({ path, kind, label }) =>
    path?.length ? (
      <button className={`link small ${isOn(path) ? "active" : ""}`} onClick={() => show(isOn(path) ? null : path, kind, label)}>
        {isOn(path) ? "hide" : "show on map"}
      </button>
    ) : null;

  return (
    <div className="panel">
      <div className="panel-bar">
        <span className="muted">
          Investigation of <strong>{d.device}</strong> at t={picked.tick}
        </span>
        <LogPicker logs={logs} value={picked.id} onChange={setPicked} />
      </div>
      <p>{d.summary}</p>

      <h3>BFS · blast radius (queue, level by level)</h3>
      <table className="table">
        <tbody>
          {d.blast_radius.map((layer, i) => (
            <tr key={i}>
              <th>{i} hop{i === 1 ? "" : "s"}</th>
              <td>{layer.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Collapsible title="BFS trace">
        <TraceTable
          trace={d.traces.bfs}
          columns={[
            { key: "step", label: "#" },
            { key: "node", label: "Dequeue" },
            { key: "frontier", label: "Queue after" },
            { key: "note", label: "Note" },
          ]}
        />
      </Collapsible>

      <h3>DFS · attack paths to critical assets (stack, backtracking)</h3>
      {d.attack_paths.length === 0 ? (
        <Empty>No attack path.</Empty>
      ) : (
        <ul className="mono-list">
          {d.attack_paths.map((p, i) => (
            <li key={i}>
              <Path path={p} /> <HL path={p} kind="attack" label="Attack path (DFS)" />
            </li>
          ))}
        </ul>
      )}
      {d.chokepoints.length > 0 && (
        <p>
          Chokepoint(s) on every path: <strong>{d.chokepoints.join(", ")}</strong>
        </p>
      )}

      <h3>Greedy best-first · likely direction (priority h only)</h3>
      {d.greedy ? (
        <p>
          Towards <strong>{d.greedy.target}</strong>: <Path path={d.greedy.path} /> · cost {formatCell(d.greedy.cost)} ·{" "}
          {d.greedy.nodes_expanded} expanded <HL path={d.greedy.path} kind="greedy" label="Greedy lead" />
        </p>
      ) : (
        <Empty>No reachable critical asset.</Empty>
      )}

      <h3>A* · safe admin route (priority f = g + h, risk-aware, avoids compromised devices)</h3>
      {d.admin_route ? (
        <p>
          <Path path={d.admin_route.path} /> · cost {formatCell(d.admin_route.cost)} · {d.admin_route.nodes_expanded}{" "}
          expanded <HL path={d.admin_route.path} kind="route" label="Safe route (A*)" />
        </p>
      ) : (
        <Empty>The device is the admin workstation itself.</Empty>
      )}
      {d.traces.astar && (
        <Collapsible title="A* trace (open list with f-values)">
          <TraceTable
            trace={d.traces.astar}
            columns={[
              { key: "step", label: "#" },
              { key: "node", label: "Expand" },
              { key: "frontier", label: "Open list after" },
              { key: "note", label: "g / h / f" },
            ]}
          />
        </Collapsible>
      )}
    </div>
  );
}

// ---- CSP ---------------------------------------------------------------------------
export function CspPanel({ decisions }) {
  const logs = logsOf(decisions, "CSP");
  const [picked, setPicked] = usePicked(logs);
  if (!picked) return <Empty>No containment decision yet.</Empty>;
  const d = picked.data;
  return (
    <div className="panel">
      <div className="panel-bar">
        <span className="muted">Isolation CSP at t={picked.tick}</span>
        <LogPicker logs={logs} value={picked.id} onChange={setPicked} />
      </div>
      {d.solvable ? (
        <p className="result good">✓ Solution found: {picked.summary}</p>
      ) : (
        <p className="result critical">
          ✕ No safe isolation exists: {d.failure}. The agent escalates instead of acting.
        </p>
      )}
      <h3>Variables and domains</h3>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Device</th>
              <th>Rating</th>
              <th>Initial domain</th>
              <th>After node consistency + AC-3</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {d.variables.map((v) => (
              <tr key={v}>
                <td>{v}</td>
                <td>
                  <LevelBadge level={d.suspects[v]} />
                </td>
                <td>{d.initial_domains[v].join(", ")}</td>
                <td>{d.domains_after_preprocessing[v].join(", ") || "∅ (empty)"}</td>
                <td>
                  <strong>{d.decisions?.[v] ?? "–"}</strong>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h3>Constraints</h3>
      <ul className="constraints">
        {d.constraints.map((c, i) => (
          <li key={i}>
            <code>{c.name}</code> <span className="muted">({c.scope.join(", ")})</span>
            <div className="small">{c.description}</div>
          </li>
        ))}
      </ul>
      <h3>Values removed before search</h3>
      {d.preprocessing.length ? (
        <ul className="mono-list">
          {d.preprocessing.map((p, i) => (
            <li key={i}>{p}</li>
          ))}
        </ul>
      ) : (
        <Empty>Nothing removed.</Empty>
      )}
      <h3>Backtracking search (MRV + forward checking)</h3>
      <TraceTable
        trace={d.trace}
        columns={[
          { key: "step", label: "#" },
          { key: "action", label: "Action" },
          { key: "var", label: "Variable" },
          { key: "value", label: "Value" },
          { key: "detail", label: "Detail" },
        ]}
      />
      <p className="muted small">
        Assignments {d.stats.assignments} · backtracks {d.stats.backtracks} · values pruned by forward checking {d.stats.pruned}
        {Object.keys(d.conflicts).length > 0 && <> · conflicts {JSON.stringify(d.conflicts)}</>}
      </p>
    </div>
  );
}

// ---- Planning ------------------------------------------------------------------------
export function PlanningPanel({ decisions }) {
  const logs = logsOf(decisions, "Planning");
  const [picked, setPicked] = usePicked(logs);
  if (!picked) return <Empty>No plan yet.</Empty>;
  const d = picked.data;
  return (
    <div className="panel">
      <div className="panel-bar">
        <span className="muted">
          {picked.incident} at t={picked.tick}
        </span>
        <LogPicker logs={logs} value={picked.id} onChange={setPicked} />
      </div>
      <h3>Hierarchical plan (HTN decomposition)</h3>
      <Pre lines={d.tree} />
      {d.goal_stack && (
        <>
          <h3>Goal-stack planning for {d.goal_stack.goal}</h3>
          <ol className="mono-list">
            {d.goal_stack.trace.map((t, i) => (
              <li key={i}>{t}</li>
            ))}
          </ol>
        </>
      )}
      <h3>STRIPS actions (preconditions and effects)</h3>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Pre</th>
              <th>Add</th>
              <th>Delete</th>
            </tr>
          </thead>
          <tbody>
            {d.plan.map((a, i) => (
              <tr key={i}>
                <td>
                  <code>{a.label}</code>
                </td>
                <td>{a.pre.join(", ")}</td>
                <td>{a.add.join(", ")}</td>
                <td>{a.delete.join(", ") || "–"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Collapsible title="Initial planning state">
        <div className="chips">
          {d.initial_state.map((f) => (
            <Chip key={f}>{f}</Chip>
          ))}
        </div>
      </Collapsible>
      <Collapsible title="HTN method choices">
        <ul className="mono-list">
          {d.trace.map((t, i) => (
            <li key={i}>{t}</li>
          ))}
        </ul>
      </Collapsible>
    </div>
  );
}

// ---- State transitions -----------------------------------------------------------------
export function StatePanel({ transitions, network }) {
  const beliefs = network.facts ?? [];
  return (
    <div className="panel">
      <h3>Beliefs kept in the internal model</h3>
      {beliefs.length ? (
        <div className="chips">
          {beliefs.map((f) => (
            <Chip key={f.join()} tone="critical">{`${f[0]}(${f.slice(1).join(", ")})`}</Chip>
          ))}
        </div>
      ) : (
        <Empty>No persistent beliefs.</Empty>
      )}
      <h3>State transitions s → s′ ({transitions.length})</h3>
      {transitions.length === 0 ? (
        <Empty>No action has changed the network yet.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>t</th>
                <th>Action (simulated)</th>
                <th>s</th>
                <th>s′</th>
                <th>Changes</th>
              </tr>
            </thead>
            <tbody>
              {transitions
                .slice()
                .reverse()
                .map((t, i) => (
                  <tr key={i}>
                    <td>{t.tick}</td>
                    <td>
                      <code>
                        {t.action}({Object.values(t.params).join(", ")})
                      </code>
                    </td>
                    <td className="mono small">{t.before}</td>
                    <td className="mono small">{t.after}</td>
                    <td>{t.changes.join("; ") || "no visible change (hidden ground truth only)"}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
