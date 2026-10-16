// Thin client for the FastAPI backend. Every call returns parsed JSON or throws an Error.
async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* keep statusText */
    }
    const err = new Error(detail || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export const api = {
  scenarios: () => request("/scenarios"),
  start: (body) => request("/simulation/start", { method: "POST", body: JSON.stringify(body) }),
  step: (ticks = 1) => request(`/simulation/step?ticks=${ticks}`, { method: "POST" }),
  runToEnd: () => request("/simulation/run", { method: "POST" }),
  reset: () => request("/simulation/reset", { method: "POST" }),
  state: () => request("/state"),
  summary: () => request("/reports/summary"),
  evaluation: (seed) => request(`/reports/evaluation?seed=${seed}`),
  runs: () => request("/runs"),
  runDetail: (id) => request(`/runs/${id}`),
};
