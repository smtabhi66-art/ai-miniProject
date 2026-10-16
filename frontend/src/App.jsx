import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api.js";
import { Card, Empty, LevelBadge, Pre } from "./components/common.jsx";
import Topology from "./components/Topology.jsx";
import EventFeed from "./components/EventFeed.jsx";
import IncidentsPanel from "./components/IncidentsPanel.jsx";
import KpiStrip from "./components/KpiStrip.jsx";
import Welcome from "./components/Welcome.jsx";
import { CspPanel, PlanningPanel, ReasoningPanel, SearchPanel, StatePanel } from "./components/AlgorithmPanels.jsx";
import { HistoryPanel, ReportPanel } from "./components/ReportPanel.jsx";
import {
  FastForwardIcon, MoonIcon, PauseIcon, PlayIcon, ResetIcon, ShieldIcon, StepIcon, SunIcon,
} from "./components/icons.jsx";

const TABS = ["Incidents", "Reasoning", "Search", "CSP", "Planning", "State", "Report", "History"];
const SPEEDS = { "0.5×": 1500, "1×": 800, "2×": 400, "4×": 200 };

function readTheme() {
  try {
    return localStorage.getItem("sentinel-theme");
  } catch {
    return null;
  }
}

export default function App() {
  const [scenarios, setScenarios] = useState([]);
  const [config, setConfig] = useState({ scenario_id: "s8_multi_step", seed: 42, mode: "active" });
  const [snap, setSnap] = useState(null);
  const [error, setError] = useState(null);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState("1×");
  const [tab, setTabState] = useState(() => TABS.find((t) => window.location.hash === `#${t}`) ?? "Incidents");
  const [selected, setSelected] = useState(null);
  const [highlight, setHighlight] = useState(null);
  const [theme, setTheme] = useState(readTheme);
  const busy = useRef(false);

  useEffect(() => {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  }, [theme]);

  const toggleTheme = () => {
    const current = theme ?? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = current === "dark" ? "light" : "dark";
    setTheme(next);
    try {
      localStorage.setItem("sentinel-theme", next);
    } catch {
      /* preference just won't persist */
    }
  };
  const isDark = (theme ?? (window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";

  const setTab = (t) => {
    setTabState(t);
    window.history.replaceState(null, "", `#${t}`);
  };

  const call = useCallback(async (fn) => {
    if (busy.current) return null;
    busy.current = true;
    try {
      const result = await fn();
      setError(null);
      return result;
    } catch (e) {
      setError(e.message);
      setPlaying(false);
      return null;
    } finally {
      busy.current = false;
    }
  }, []);

  useEffect(() => {
    api.scenarios().then(setScenarios).catch((e) => setError(`Backend not reachable (${e.message}). Start it with: uvicorn app.main:app --port 8000`));
    api
      .state()
      .then((s) => {
        setSnap(s);
        setConfig((c) => ({ ...c, scenario_id: s.scenario.id, seed: s.seed, mode: s.mode }));
      })
      .catch(() => {});
  }, []);

  const start = async (scenarioId) => {
    setPlaying(false);
    setHighlight(null);
    setSelected(null);
    const body = { ...config, scenario_id: scenarioId ?? config.scenario_id, seed: Number(config.seed) };
    setConfig(body);
    const s = await call(() => api.start(body));
    if (s) setSnap(s);
  };
  const step = useCallback(async () => {
    const s = await call(() => api.step(1));
    if (s) {
      setSnap(s);
      if (s.finished) setPlaying(false);
    }
  }, [call]);
  const runToEnd = async () => {
    setPlaying(false);
    const s = await call(() => api.runToEnd());
    if (s) setSnap(s);
  };
  const reset = async () => {
    setPlaying(false);
    await call(() => api.reset());
    setSnap(null);
    setHighlight(null);
    setSelected(null);
  };

  useEffect(() => {
    if (!playing) return undefined;
    const id = setInterval(step, SPEEDS[speed]);
    return () => clearInterval(id);
  }, [playing, speed, step]);

  const finished = snap?.finished;
  const selectedDevice = snap?.network.devices.find((d) => d.id === selected);
  const runState = !snap ? "Idle" : finished ? "Finished" : playing ? "Running" : "Paused";
  const openIncidents = snap?.incidents.filter((i) => i.closed_tick === null).length ?? 0;

  return (
    <div className="app">
      <header className="appbar">
        <div className="brand">
          <span className="brand-mark"><ShieldIcon size={20} /></span>
          <span className="brand-name">SentinelAI</span>
          <span className="brand-sub">Defense Console</span>
        </div>
        <div className="appbar-center">
          {snap && (
            <span className={`run-pill run-${runState.toLowerCase()}`}>
              <span className="run-dot" aria-hidden="true" />
              {runState} · {snap.scenario.name} · {snap.mode}
            </span>
          )}
        </div>
        <div className="appbar-right">
          <span className="sim-note">Simulation only</span>
          <button className="icon-btn" onClick={toggleTheme} aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
                  title={`Switch to ${isDark ? "light" : "dark"} theme`}>
            {isDark ? <SunIcon /> : <MoonIcon />}
          </button>
        </div>
      </header>

      <div className="controlbar">
        <div className="control-group">
          <label className="field grow">
            <span>Scenario</span>
            <select className="select" value={config.scenario_id}
                    onChange={(e) => setConfig({ ...config, scenario_id: e.target.value })}>
              {scenarios.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              <option value="random">Random scenario (from seed)</option>
            </select>
          </label>
          <label className="field">
            <span>Seed</span>
            <input className="input" type="number" value={config.seed}
                   onChange={(e) => setConfig({ ...config, seed: e.target.value })} />
          </label>
          <div className="field">
            <span>Mode</span>
            <div className="segmented" role="radiogroup" aria-label="Mode">
              {[["active", "Detect + respond"], ["passive", "Detect only"]].map(([value, label]) => (
                <button key={value} role="radio" aria-checked={config.mode === value}
                        className={config.mode === value ? "on" : ""}
                        onClick={() => setConfig({ ...config, mode: value })}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <button className="btn primary" onClick={() => start()}>{snap ? "Restart" : "Launch"}</button>
        </div>
        <div className="control-group playback">
          <button className="btn" onClick={step} disabled={!snap || finished || playing} title="Advance one tick">
            <StepIcon size={14} /> Step
          </button>
          <button className={`btn ${playing ? "active" : ""}`} onClick={() => setPlaying(!playing)}
                  disabled={!snap || finished}>
            {playing ? <><PauseIcon size={14} /> Pause</> : <><PlayIcon size={14} /> Play</>}
          </button>
          <select className="select compact" value={speed} aria-label="Playback speed"
                  onChange={(e) => setSpeed(e.target.value)}>
            {Object.keys(SPEEDS).map((s) => <option key={s}>{s}</option>)}
          </select>
          <button className="btn" onClick={runToEnd} disabled={!snap || finished}>
            <FastForwardIcon size={14} /> Run to end
          </button>
          <button className="btn ghost" onClick={reset} disabled={!snap} title="Discard this run">
            <ResetIcon size={14} /> Reset
          </button>
        </div>
      </div>

      {error && <div className="banner" role="alert">{error}</div>}

      {!snap ? (
        <Welcome scenarios={scenarios} selected={config.scenario_id}
                 onPick={(id) => setConfig({ ...config, scenario_id: id })} onLaunch={(id) => start(id)} />
      ) : (
        <>
          <KpiStrip snap={snap} />
          <main className="grid">
            <div className="col-left">
              <Card title="Network topology"
                    extra={<span className="muted small">Click a device for details · use “show on map” in Search</span>}>
                <Topology network={snap.network} highlight={highlight} selected={selected} onSelect={setSelected} />
                {selectedDevice && (
                  <div className="device-detail">
                    <div className="device-head">
                      <strong>{selectedDevice.name}</strong>
                      <LevelBadge level={selectedDevice.threat_level} />
                      <button className="link small" onClick={() => setSelected(null)}>close</button>
                    </div>
                    <dl className="facts">
                      <div><dt>ID</dt><dd>{selectedDevice.id}</dd></div>
                      <div><dt>Address</dt><dd>{selectedDevice.ip} (simulated)</dd></div>
                      <div><dt>Zone</dt><dd>{selectedDevice.zone}</dd></div>
                      <div><dt>Criticality</dt><dd>{selectedDevice.criticality} / 5</dd></div>
                      <div><dt>Status</dt><dd>{selectedDevice.status}{selectedDevice.monitored ? " · monitored" : ""}</dd></div>
                      <div><dt>Services</dt><dd>{selectedDevice.services.join(", ") || "–"}</dd></div>
                    </dl>
                    {snap.assessment?.explanations?.[selectedDevice.id] ? (
                      <Pre lines={snap.assessment.explanations[selectedDevice.id]} />
                    ) : (
                      <Empty>No rule currently flags this device.</Empty>
                    )}
                  </div>
                )}
              </Card>
              <Card title="Event log" extra={<span className="muted small">{snap.events.length} events perceived</span>}>
                <EventFeed events={snap.events} suppressed={snap.suppressed} />
              </Card>
            </div>
            <div className="col-right">
              <section className="card tab-card">
                <nav className="tabs" role="tablist">
                  {TABS.map((t) => (
                    <button key={t} role="tab" aria-selected={tab === t} className={`tab ${tab === t ? "active" : ""}`}
                            onClick={() => setTab(t)}>
                      {t}
                      {t === "Incidents" && snap.incidents.length > 0 && (
                        <span className={`count ${openIncidents ? "count-open" : ""}`}>{snap.incidents.length}</span>
                      )}
                    </button>
                  ))}
                </nav>
                <div className="card-body tab-body">
                  {tab === "Incidents" && <IncidentsPanel incidents={snap.incidents} onSelectDevice={setSelected} />}
                  {tab === "Reasoning" && <ReasoningPanel assessment={snap.assessment} decisions={snap.decisions} />}
                  {tab === "Search" && <SearchPanel decisions={snap.decisions} highlight={highlight} onHighlight={setHighlight} />}
                  {tab === "CSP" && <CspPanel decisions={snap.decisions} />}
                  {tab === "Planning" && <PlanningPanel decisions={snap.decisions} />}
                  {tab === "State" && <StatePanel transitions={snap.transitions} network={snap.network} />}
                  {tab === "Report" && (
                    <ReportPanel performance={snap.performance} finished={finished} tick={snap.tick} seed={snap.seed} />
                  )}
                  {tab === "History" && <HistoryPanel refreshKey={`${snap.run_id}-${snap.tick}`} />}
                </div>
              </section>
            </div>
          </main>
        </>
      )}
      <footer className="statusbar">
        <span>SentinelAI · AI mini project</span>
        <span>All responses are simulated: no real network is scanned, attacked or blocked.</span>
      </footer>
    </div>
  );
}
