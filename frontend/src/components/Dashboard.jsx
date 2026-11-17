import { api, CATEGORIES, SEV_BAR, SEVERITIES } from "../api";

const GRADE_COLOR = { A: "#10b981", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" };
const PHASE_STYLE = {
  perceive: "bg-sky-500/15 text-sky-300",
  plan: "bg-violet-500/15 text-violet-300",
  act: "bg-amber-500/15 text-amber-300",
  reflect: "bg-emerald-500/15 text-emerald-300",
  report: "bg-slate-500/20 text-slate-300",
};

export default function Dashboard({ report, onCategory, onNewScan }) {
  const s = report.summary;
  const p = report.profile;
  const maxSev = Math.max(1, ...Object.values(s.by_severity));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="text-xs uppercase tracking-widest text-slate-500">Scan report</div>
          <h2 className="text-2xl font-bold">{report.project_name}</h2>
          <div className="text-sm text-slate-400">
            {s.files_scanned} files · {s.lines_scanned.toLocaleString()} lines · {(report.duration_ms / 1000).toFixed(1)}s ·{" "}
            {new Date(report.scanned_at).toLocaleString()}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <a className="btn-ghost" href={api.htmlUrl(report.id)}>⬇ HTML report</a>
          <a className="btn-ghost" href={api.jsonUrl(report.id)}>⬇ JSON</a>
          <button className="btn-primary" onClick={onNewScan}>New scan</button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[260px_1fr_1fr]">
        <div className="panel flex flex-col items-center justify-center p-6">
          <ScoreRing score={s.score} grade={s.grade} />
          <div className="mt-3 text-sm text-slate-400">Health score</div>
          <div className="mt-1 text-xs text-slate-500">{s.total} active findings in {s.files_affected} files</div>
        </div>

        <div className="panel p-6">
          <h3 className="mb-4 font-semibold">By severity</h3>
          <div className="space-y-3">
            {SEVERITIES.filter((k) => k !== "info" || s.by_severity.info).map((k) => (
              <div key={k} className="flex items-center gap-3 text-sm">
                <span className="w-16 capitalize text-slate-300">{k}</span>
                <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                  <div className={`h-full rounded-full ${SEV_BAR[k]}`} style={{ width: `${(s.by_severity[k] / maxSev) * 100}%` }} />
                </div>
                <span className="w-8 text-right font-mono">{s.by_severity[k]}</span>
              </div>
            ))}
          </div>
          {(s.duplicates_removed > 0 || s.false_positives_hidden > 0) && (
            <div className="mt-4 text-xs text-slate-500">
              {s.duplicates_removed} duplicates merged · {s.false_positives_hidden} AI-flagged false positives excluded from score
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3">
          {Object.entries(CATEGORIES).map(([k, c]) => (
            <button key={k} onClick={() => onCategory(k)} className={`panel border ${c.ring} p-4 text-left transition hover:bg-slate-800/60`}>
              <div className={`text-3xl font-bold ${c.color}`}>{s.by_category[k]}</div>
              <div className="text-sm font-medium">{c.label}</div>
              <div className="text-xs text-slate-500">{c.desc}</div>
            </button>
          ))}
        </div>
      </div>

      <div className="panel p-6">
        <div className="mb-2 flex items-center gap-2">
          <h3 className="font-semibold">Executive summary</h3>
          <span className={`chip ${report.ai.used ? "border-emerald-500/40 text-emerald-300" : "border-slate-700 text-slate-400"}`}>
            {report.ai.used ? `AI · ${report.ai.model}` : "rule-based"}
          </span>
        </div>
        <p className="leading-relaxed text-slate-300">{report.executive_summary}</p>
        {report.ai.errors?.length > 0 && (
          <p className="mt-3 text-xs text-amber-300">AI provider warnings: {report.ai.errors.join(" | ")}</p>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
        <div className="panel p-6">
          <h3 className="mb-4 font-semibold">Detected stack</h3>
          <dl className="space-y-3 text-sm">
            <Row label="Architecture" value={p.architecture} />
            <Row label="Frameworks" value={p.frameworks.join(", ") || "none detected"} />
            <Row label="Test files" value={p.test_files} />
            <Row label="Manifests" value={p.manifests.join(", ") || "-"} />
          </dl>
          <div className="mt-5 space-y-2">
            {p.languages.slice(0, 8).map((l) => (
              <div key={l.language} className="flex items-center gap-3 text-sm">
                <span className="w-24 capitalize text-slate-300">{l.language}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full rounded-full bg-emerald-500/70" style={{ width: `${(l.lines / Math.max(1, p.total_lines)) * 100}%` }} />
                </div>
                <span className="w-20 text-right font-mono text-xs text-slate-400">{l.lines.toLocaleString()} loc</span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel p-6">
          <h3 className="mb-4 font-semibold">Agent trace</h3>
          <ol className="relative space-y-3 border-l border-slate-800 pl-5">
            {report.trace.map((t, i) => (
              <li key={i} className="relative">
                <span className={`absolute -left-[27px] top-1 h-3 w-3 rounded-full ring-4 ring-slate-950 ${t.status === "ok" ? "bg-emerald-400" : t.status === "skipped" ? "bg-slate-600" : "bg-amber-400"}`} />
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${PHASE_STYLE[t.phase]}`}>{t.phase}</span>
                  <span className="font-medium">{t.action}</span>
                  <span className="text-xs text-slate-500">{t.duration_ms} ms</span>
                </div>
                <div className="text-sm text-slate-400">{t.detail}</div>
              </li>
            ))}
          </ol>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="flex gap-3">
      <dt className="w-28 shrink-0 text-slate-500">{label}</dt>
      <dd className="break-words text-slate-200">{value}</dd>
    </div>
  );
}

function ScoreRing({ score, grade }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const color = GRADE_COLOR[grade] || "#64748b";
  return (
    <div className="relative h-36 w-36">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#1e293b" strokeWidth="10" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} style={{ transition: "stroke-dashoffset 1s ease" }} />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="text-4xl font-extrabold">{score}</div>
          <div className="text-sm font-bold" style={{ color }}>Grade {grade}</div>
        </div>
      </div>
    </div>
  );
}
