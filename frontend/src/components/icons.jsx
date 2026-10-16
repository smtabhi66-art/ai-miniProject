// Minimal stroke icons (24×24). They inherit currentColor so text tokens control them.
import React from "react";

function Svg({ children, size = 16, fill = "none", ...rest }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill={fill} stroke="currentColor" strokeWidth="1.8"
         strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>
      {children}
    </svg>
  );
}

export const ShieldIcon = (p) => (
  <Svg {...p}><path d="M12 3l7 3v5c0 4.6-3 8.5-7 10-4-1.5-7-5.4-7-10V6l7-3z" /><path d="M9 12l2 2 4-4" /></Svg>
);
export const PlayIcon = (p) => <Svg {...p}><path d="M8 5l11 7-11 7V5z" fill="currentColor" /></Svg>;
export const PauseIcon = (p) => (
  <Svg {...p}><rect x="6" y="5" width="4" height="14" rx="1" fill="currentColor" /><rect x="14" y="5" width="4" height="14" rx="1" fill="currentColor" /></Svg>
);
export const StepIcon = (p) => <Svg {...p}><path d="M6 5l9 7-9 7V5z" fill="currentColor" /><path d="M18 5v14" /></Svg>;
export const FastForwardIcon = (p) => (
  <Svg {...p}><path d="M4 6l8 6-8 6V6z" fill="currentColor" /><path d="M12 6l8 6-8 6V6z" fill="currentColor" /></Svg>
);
export const ResetIcon = (p) => <Svg {...p}><path d="M3 12a9 9 0 1 0 3-6.7" /><path d="M3 4v5h5" /></Svg>;
export const SunIcon = (p) => (
  <Svg {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></Svg>
);
export const MoonIcon = (p) => <Svg {...p}><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></Svg>;
export const EyeIcon = (p) => (
  <Svg {...p}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></Svg>
);
export const BlockIcon = (p) => <Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></Svg>;
export const ArrowIcon = (p) => <Svg {...p}><path d="M5 12h14M13 6l6 6-6 6" /></Svg>;

// ---- device types -------------------------------------------------------------------
const GlobeIcon = (p) => (
  <Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18z" /></Svg>
);
const FirewallIcon = (p) => (
  <Svg {...p}><rect x="3" y="5" width="18" height="14" rx="1.5" /><path d="M3 9.7h18M3 14.3h18M9 5v4.7M15 9.7v4.6M9 14.3V19" /></Svg>
);
const RouterIcon = (p) => (
  <Svg {...p}><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 16.5h.01M11 16.5h.01" /><path d="M15 13V9M8.5 7a5 5 0 0 1 7 0M6 4.5a8.5 8.5 0 0 1 12 0" /></Svg>
);
const ServerIcon = (p) => (
  <Svg {...p}><rect x="4" y="3" width="16" height="8" rx="1.5" /><rect x="4" y="13" width="16" height="8" rx="1.5" /><path d="M8 7h.01M8 17h.01" /></Svg>
);
const DatabaseIcon = (p) => (
  <Svg {...p}><ellipse cx="12" cy="5.5" rx="8" ry="2.8" /><path d="M4 5.5v13c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8v-13" /><path d="M4 12c0 1.5 3.6 2.8 8 2.8s8-1.3 8-2.8" /></Svg>
);
const MonitorIcon = (p) => <Svg {...p}><rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M8 20h8M12 16v4" /></Svg>;
const AdminIcon = (p) => (
  <Svg {...p}><rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M8 20h8M12 16v4" /><path d="M12 7l2.5 1v1.8c0 1.5-1 2.8-2.5 3.3-1.5-.5-2.5-1.8-2.5-3.3V8L12 7z" /></Svg>
);

export const DEVICE_ICON = {
  external: GlobeIcon,
  firewall: FirewallIcon,
  router: RouterIcon,
  server: ServerIcon,
  database: DatabaseIcon,
  workstation: MonitorIcon,
  admin_workstation: AdminIcon,
};
