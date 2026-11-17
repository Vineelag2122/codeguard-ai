const BASE = import.meta.env.VITE_API_BASE || "";

async function handle(res) {
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {
      /* non-JSON error */
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.json();
}

export const api = {
  health: () => fetch(`${BASE}/api/health`).then(handle),
  scanZip: (file, useAi) => {
    const form = new FormData();
    form.append("file", file);
    form.append("use_ai", String(useAi));
    return fetch(`${BASE}/api/scan/upload`, { method: "POST", body: form }).then(handle);
  },
  scanGithub: (url, useAi) =>
    fetch(`${BASE}/api/scan/github`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, use_ai: useAi }),
    }).then(handle),
  scanSample: (useAi) => fetch(`${BASE}/api/scan/sample?use_ai=${useAi}`, { method: "POST" }).then(handle),
  htmlUrl: (id) => `${BASE}/api/reports/${id}/html?download=true`,
  jsonUrl: (id) => `${BASE}/api/reports/${id}/json`,
};

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const CATEGORIES = {
  security: { label: "Security", desc: "Vulnerabilities & leaked secrets", color: "text-rose-400", ring: "border-rose-500/40" },
  gap: { label: "Coding gaps", desc: "Missing handling, validation, tests", color: "text-amber-400", ring: "border-amber-500/40" },
  slop: { label: "AI slop", desc: "Low-quality / generated leftovers", color: "text-violet-400", ring: "border-violet-500/40" },
  loose_end: { label: "Loose ends", desc: "TODOs, placeholders, hardcoded config", color: "text-sky-400", ring: "border-sky-500/40" },
};
export const SEV_STYLE = {
  critical: "bg-red-500/15 text-red-300 border-red-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/15 text-yellow-200 border-yellow-500/40",
  low: "bg-blue-500/15 text-blue-300 border-blue-500/40",
  info: "bg-slate-500/15 text-slate-300 border-slate-500/40",
};
export const SEV_BAR = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-400",
  low: "bg-blue-500",
  info: "bg-slate-500",
};
