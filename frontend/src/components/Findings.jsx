import { useMemo, useState } from "react";
import { CATEGORIES, SEV_STYLE, SEVERITIES } from "../api";

const SOURCE_LABEL = { rule: "rule", ast: "AST", bandit: "Bandit", semgrep: "Semgrep", ai: "AI review" };

export default function Findings({ findings, category, setCategory }) {
  const [severity, setSeverity] = useState("all");
  const [query, setQuery] = useState("");
  const [showFp, setShowFp] = useState(false);
  const [open, setOpen] = useState(null);

  const visible = useMemo(() => {
    const q = query.toLowerCase();
    return findings.filter(
      (f) =>
        (category === "all" || f.category === category) &&
        (severity === "all" || f.severity === severity) &&
        (showFp || f.ai_verdict !== "false_positive") &&
        (!q || `${f.title} ${f.file} ${f.description} ${f.rule_id}`.toLowerCase().includes(q))
    );
  }, [findings, category, severity, query, showFp]);

  const fpCount = findings.filter((f) => f.ai_verdict === "false_positive").length;

  return (
    <section className="panel p-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-lg font-semibold">
          Findings <span className="text-slate-500">({visible.length})</span>
        </h3>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search title, file, rule..."
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-emerald-500 sm:w-72"
        />
      </div>

      <div className="mb-3 flex flex-wrap gap-2">
        <Chip active={category === "all"} onClick={() => setCategory("all")}>All types</Chip>
        {Object.entries(CATEGORIES).map(([k, c]) => (
          <Chip key={k} active={category === k} onClick={() => setCategory(k)}>{c.label}</Chip>
        ))}
      </div>
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <Chip active={severity === "all"} onClick={() => setSeverity("all")}>All severities</Chip>
        {SEVERITIES.map((s) => (
          <Chip key={s} active={severity === s} onClick={() => setSeverity(s)}>
            <span className="capitalize">{s}</span>
          </Chip>
        ))}
        {fpCount > 0 && (
          <label className="ml-auto flex items-center gap-2 text-xs text-slate-400">
            <input type="checkbox" className="accent-emerald-500" checked={showFp} onChange={(e) => setShowFp(e.target.checked)} />
            Show {fpCount} AI-dismissed false positives
          </label>
        )}
      </div>

      {visible.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-800 p-10 text-center text-slate-500">No findings match these filters. 🎉</div>
      ) : (
        <ul className="space-y-2">
          {visible.map((f) => (
            <FindingRow key={f.id} f={f} open={open === f.id} toggle={() => setOpen(open === f.id ? null : f.id)} />
          ))}
        </ul>
      )}
    </section>
  );
}

function Chip({ active, onClick, children }) {
  return (
    <button onClick={onClick} className={`chip ${active ? "border-emerald-500 bg-emerald-500/15 text-emerald-200" : "border-slate-700 text-slate-400 hover:text-slate-200"}`}>
      {children}
    </button>
  );
}

function FindingRow({ f, open, toggle }) {
  const cat = CATEGORIES[f.category];
  const fp = f.ai_verdict === "false_positive";
  return (
    <li className={`overflow-hidden rounded-xl border border-slate-800 bg-slate-950/40 ${fp ? "opacity-50" : ""}`}>
      <button onClick={toggle} className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left hover:bg-slate-900/80">
        <span className={`w-20 shrink-0 rounded-md border px-2 py-0.5 text-center text-[11px] font-semibold uppercase ${SEV_STYLE[f.severity]}`}>{f.severity}</span>
        <span className="min-w-0 flex-1">
          <span className="block truncate font-medium">{f.title}</span>
          <span className="block truncate font-mono text-xs text-slate-500">
            {f.file}
            {f.line ? `:${f.line}` : ""}
          </span>
        </span>
        <span className={`hidden text-xs sm:inline ${cat?.color}`}>{cat?.label}</span>
        <span className="hidden rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-400 md:inline">{SOURCE_LABEL[f.source] || f.source}</span>
        {f.ai_verdict && (
          <span className={`rounded px-2 py-0.5 text-[11px] ${f.ai_verdict === "confirmed" ? "bg-emerald-500/15 text-emerald-300" : fp ? "bg-slate-700 text-slate-300" : "bg-amber-500/15 text-amber-300"}`}>
            AI: {f.ai_verdict.replace("_", " ")}
          </span>
        )}
        <span className="text-slate-500">{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="space-y-4 border-t border-slate-800 px-4 py-4 text-sm">
          {f.snippet && (
            <pre className="overflow-x-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-200">
              <span className="select-none text-slate-600">{f.line ? `${f.line} │ ` : ""}</span>
              {f.snippet}
            </pre>
          )}
          <Block title="Why it matters">{f.description}</Block>
          <Block title="Recommendation" accent>{f.recommendation}</Block>
          {f.ai_explanation && <Block title="AI analysis">{f.ai_explanation}</Block>}
          {f.ai_fix && (
            <div>
              <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-emerald-400">Suggested fix</div>
              <pre className="overflow-x-auto rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 font-mono text-xs text-emerald-100">{f.ai_fix}</pre>
            </div>
          )}
          <div className="flex flex-wrap gap-3 text-xs text-slate-500">
            <span>rule: <code>{f.rule_id}</code></span>
            {f.cwe && <span>{f.cwe}</span>}
            <span>confidence: {f.confidence}</span>
          </div>
        </div>
      )}
    </li>
  );
}

function Block({ title, children, accent }) {
  return (
    <div>
      <div className={`mb-1 text-xs font-semibold uppercase tracking-wide ${accent ? "text-sky-400" : "text-slate-500"}`}>{title}</div>
      <p className="leading-relaxed text-slate-300">{children}</p>
    </div>
  );
}
