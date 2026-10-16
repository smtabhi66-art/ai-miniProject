// Network topology drawn with React Flow: labelled security zones, device cards with icons,
// and colours/flags taken from the backend's real state.
import React, { useMemo } from "react";
import { Background, Controls, Handle, Position, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { LevelBadge } from "./common.jsx";
import { DEVICE_ICON, EyeIcon } from "./icons.jsx";

const TYPE_LABEL = {
  workstation: "Workstation",
  admin_workstation: "Admin PC",
  server: "Server",
  database: "Database",
  router: "Router",
  firewall: "Firewall",
  external: "Internet",
};

// Device zones grouped into the regions drawn behind the nodes.
const ZONE_GROUP = {
  external: "Internet",
  perimeter: "Perimeter & DMZ",
  dmz: "Perimeter & DMZ",
  office: "Office LAN",
  core: "Core network",
  server: "Server zone",
};
const NODE_W = 128;
const NODE_H = 84;
const PAD = 16;
const LABEL = 22;

function DeviceNode({ data }) {
  const d = data.device;
  const Icon = DEVICE_ICON[d.type] ?? DEVICE_ICON.server;
  const classes = ["dev", `lvl-${d.threat_level}`, `st-${d.status}`, data.highlight ? "hl" : "", data.selected ? "sel" : ""];
  return (
    <div className={classes.join(" ")} title={`${d.name} · ${d.ip} (simulated)`}>
      <Handle type="target" position={Position.Top} className="center-handle" isConnectable={false} />
      <Handle type="source" position={Position.Top} className="center-handle" isConnectable={false} />
      <div className="dev-row">
        <span className="dev-icon"><Icon size={18} /></span>
        <span className="dev-text">
          <span className="dev-id">{d.id}</span>
          <span className="dev-type">{TYPE_LABEL[d.type] ?? d.type}</span>
        </span>
        {d.monitored && (
          <span className="dev-eye" title="Monitored">
            <EyeIcon size={13} />
          </span>
        )}
      </div>
      {(d.threat_level !== "normal" || d.status !== "online") && (
        <div className="dev-tags">
          {d.threat_level !== "normal" && <LevelBadge level={d.threat_level} />}
          {d.status !== "online" && <span className={`tag tag-${d.status}`}>{d.status}</span>}
        </div>
      )}
    </div>
  );
}

function ZoneNode({ data }) {
  return (
    <div className="zone" style={{ width: data.width, height: data.height }}>
      <span className="zone-label">{data.label}</span>
    </div>
  );
}

const nodeTypes = { device: DeviceNode, zone: ZoneNode };

function zoneNodes(devices, layout) {
  const boxes = {};
  for (const d of devices) {
    const pos = layout[d.id];
    const group = ZONE_GROUP[d.zone];
    if (!pos || !group) continue;
    const b = (boxes[group] ??= { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity });
    b.minX = Math.min(b.minX, pos[0]);
    b.minY = Math.min(b.minY, pos[1]);
    b.maxX = Math.max(b.maxX, pos[0] + NODE_W);
    b.maxY = Math.max(b.maxY, pos[1] + NODE_H);
  }
  return Object.entries(boxes).map(([label, b]) => ({
    id: `zone-${label}`,
    type: "zone",
    position: { x: b.minX - PAD, y: b.minY - PAD - LABEL },
    data: { label, width: b.maxX - b.minX + 2 * PAD, height: b.maxY - b.minY + 2 * PAD + LABEL },
    draggable: false,
    selectable: false,
    focusable: false,
    zIndex: -1,
  }));
}

export default function Topology({ network, highlight, selected, onSelect }) {
  const layout = network.metadata?.layout ?? {};
  const hlNodes = useMemo(() => new Set(highlight?.path ?? []), [highlight]);
  const hlEdges = useMemo(() => {
    const set = new Set();
    const p = highlight?.path ?? [];
    for (let i = 0; i + 1 < p.length; i++) {
      set.add(`${p[i]}|${p[i + 1]}`);
      set.add(`${p[i + 1]}|${p[i]}`);
    }
    return set;
  }, [highlight]);

  const nodes = [
    ...zoneNodes(network.devices, layout),
    ...network.devices.map((d, i) => {
      const [x, y] = layout[d.id] ?? [(i % 6) * 150, Math.floor(i / 6) * 120];
      return {
        id: d.id,
        type: "device",
        position: { x, y },
        data: { device: d, highlight: hlNodes.has(d.id), selected: selected === d.id },
        draggable: false,
      };
    }),
  ];

  const edges = network.links.map((l) => {
    const blocked = l.status === "blocked";
    const lit = hlEdges.has(`${l.source}|${l.target}`);
    return {
      id: `${l.source}-${l.target}`,
      source: l.source,
      target: l.target,
      type: "straight",
      animated: lit,
      className: [blocked ? "edge-blocked" : "", lit ? `edge-hl edge-${highlight?.kind ?? "route"}` : ""].join(" "),
      label: blocked ? "blocked" : undefined,
    };
  });

  return (
    <div className="topology-wrap">
      <div className="topology">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.06 }}
          minZoom={0.3}
          nodesConnectable={false}
          elementsSelectable={false}
          onNodeClick={(_, node) => node.type === "device" && onSelect(node.id === selected ? null : node.id)}
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={22} size={1} />
          <Controls showInteractive={false} position="top-right" />
        </ReactFlow>
      </div>
      <div className="legend" aria-label="Legend">
        <LevelBadge level="normal" />
        <LevelBadge level="suspicious" />
        <LevelBadge level="critical" />
        <span className="legend-item"><span className="swatch swatch-isolated" /> Isolated</span>
        <span className="legend-item"><span className="swatch swatch-restricted" /> Restricted</span>
        <span className="legend-item"><EyeIcon size={13} /> Monitored</span>
        <span className="legend-item"><span className="line line-blocked" /> Blocked link</span>
        {highlight && (
          <span className="legend-item">
            <span className={`line line-${highlight.kind}`} /> {highlight.label}
          </span>
        )}
      </div>
    </div>
  );
}
