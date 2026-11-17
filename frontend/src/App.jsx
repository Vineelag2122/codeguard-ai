import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import Upload from "./components/Upload";
import Dashboard from "./components/Dashboard";
import Findings from "./components/Findings";

const STEPS = [
  "Discovering files",
  "Profiling languages & frameworks",
  "Running security rules",
  "Hunting slop, gaps & loose ends",
  "Running Bandit / Semgrep",
  "AI triage & deep review",
  "Writing the report",
];

export default function App() {
  const [health, setHealth] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");
  const [category, setCategory] = useState("all");
  const findingsRef = useRef(null);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
  }, []);

  useEffect(() => {
    if (!loading) return;
    setStep(0);
    const t = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 1100);
    return () => clearInterval(t);
  }, [loading]);

  async function run(fn) {
    setError("");
    setLoading(true);
    try {
      const r = await fn();
      setReport(r);
      setCategory("all");
    } catch (e) {
      setError(e.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  function focusCategory(c) {
    setCategory(c);
    findingsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const ai = health?.ai;

  return (
    <div className="mx-auto max-w-7xl px-4 pb-20 sm:px-6">
      <header className="flex flex-wrap items-center justify-between gap-3 py-6">
        <button onClick={() => setReport(null)} className="flex items-center gap-3 text-left">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-emerald-500/15 text-xl ring-1 ring-emerald-500/40">🛡️</div>
          <div>
            <div className="text-lg font-bold tracking-tight">
              CodeGuard <span className="text-emerald-400">AI</span>
            </div>
            <div className="text-xs text-slate-400">Architecture-agnostic security &amp; code-quality agent</div>
          </div>
        </button>
        <div className="flex items-center gap-2 text-xs">
          <StatusPill ok={health?.status === "ok"} label={health?.status === "ok" ? "Backend online" : health ? "Backend offline" : "Connecting..."} />
          {health?.status === "ok" && (
            <StatusPill ok={ai?.enabled} label={ai?.enabled ? `AI: ${ai.provider} · ${ai.model}` : "AI: rules only (no API key)"} />
          )}
        </div>
      </header>

      {error && (
        <div className="mb-6 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <b>Scan failed:</b> {error}
        </div>
      )}

      {loading ? (
        <Progress step={step} />
      ) : report ? (
        <div className="space-y-8">
          <Dashboard report={report} onCategory={focusCategory} onNewScan={() => setReport(null)} />
          <div ref={findingsRef} className="scroll-mt-6">
            <Findings findings={report.findings} category={category} setCategory={setCategory} />
          </div>
        </div>
      ) : (
        <Upload
          aiEnabled={!!ai?.enabled}
          sampleAvailable={health?.sample_available}
          onZip={(file, useAi) => run(() => api.scanZip(file, useAi))}
          onGithub={(url, useAi) => run(() => api.scanGithub(url, useAi))}
          onSample={(useAi) => run(() => api.scanSample(useAi))}
        />
      )}
    </div>
  );
}

function StatusPill({ ok, label }) {
  return (
    <span className={`flex items-center gap-2 rounded-full border px-3 py-1 ${ok ? "border-emerald-500/40 text-emerald-300" : "border-slate-700 text-slate-400"}`}>
      <span className={`h-2 w-2 rounded-full ${ok ? "bg-emerald-400" : "bg-slate-500"}`} />
      {label}
    </span>
  );
}

function Progress({ step }) {
  return (
    <div className="panel mx-auto mt-10 max-w-xl p-8">
      <div className="mb-6 flex items-center gap-3">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent" />
        <h2 className="text-lg font-semibold">Agent is analysing your code...</h2>
      </div>
      <ol className="space-y-3">
        {STEPS.map((s, i) => (
          <li key={s} className={`flex items-center gap-3 text-sm ${i <= step ? "text-slate-100" : "text-slate-600"}`}>
            <span className={`grid h-5 w-5 place-items-center rounded-full text-[10px] ${i < step ? "bg-emerald-500 text-slate-950" : i === step ? "bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-400" : "bg-slate-800"}`}>
              {i < step ? "✓" : i + 1}
            </span>
            {s}
          </li>
        ))}
      </ol>
    </div>
  );
}
