import { useRef, useState } from "react";
import { CATEGORIES } from "../api";

export default function Upload({ aiEnabled, sampleAvailable, onZip, onGithub, onSample }) {
  const [tab, setTab] = useState("github");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [drag, setDrag] = useState(false);
  const [useAi, setUseAi] = useState(true);
  const input = useRef(null);
  const ai = aiEnabled && useAi;

  function onDrop(e) {
    e.preventDefault();
    setDrag(false);
    const f = e.dataTransfer.files?.[0];
    if (f) setFile(f);
  }

  return (
    <div className="mt-6 grid gap-8 lg:grid-cols-[1.1fr_1fr] lg:items-start">
      <section className="pt-4">
        <span className="chip border-emerald-500/40 text-emerald-300">Built for the Mycrobo hackathon</span>
        <h1 className="mt-5 text-4xl font-extrabold leading-tight tracking-tight sm:text-5xl">
          Find the <span className="text-rose-400">vulnerabilities</span>, <span className="text-violet-400">slop</span> and{" "}
          <span className="text-sky-400">loose ends</span> before they ship.
        </h1>
        <p className="mt-5 max-w-xl text-slate-400">
          Point the agent at any repository. It profiles the stack, picks the right checks, runs multi-language
          rules, Python AST analysis and Bandit, then uses an LLM to triage false positives and dig for logic
          flaws rules can't see.
        </p>
        <div className="mt-8 grid max-w-xl gap-3 sm:grid-cols-2">
          {Object.entries(CATEGORIES).map(([k, c]) => (
            <div key={k} className={`panel border ${c.ring} p-4`}>
              <div className={`font-semibold ${c.color}`}>{c.label}</div>
              <div className="text-sm text-slate-400">{c.desc}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel p-6">
        <div className="mb-5 flex rounded-lg bg-slate-950/60 p-1 text-sm">
          {[
            ["github", "GitHub URL"],
            ["zip", "Upload ZIP"],
          ].map(([k, label]) => (
            <button
              key={k}
              onClick={() => setTab(k)}
              className={`flex-1 rounded-md px-3 py-2 font-medium transition ${tab === k ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white"}`}
            >
              {label}
            </button>
          ))}
        </div>

        {tab === "github" ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (url.trim()) onGithub(url.trim(), ai);
            }}
            className="space-y-4"
          >
            <label className="block text-sm text-slate-300">Public repository URL</label>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 font-mono text-sm outline-none focus:border-emerald-500"
            />
            <p className="text-xs text-slate-500">Supports branches too: https://github.com/owner/repo/tree/dev</p>
            <button className="btn-primary w-full py-3" disabled={!url.trim()}>
              Scan repository
            </button>
          </form>
        ) : (
          <div className="space-y-4">
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDrag(true);
              }}
              onDragLeave={() => setDrag(false)}
              onDrop={onDrop}
              onClick={() => input.current?.click()}
              className={`cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition ${drag ? "border-emerald-400 bg-emerald-500/5" : "border-slate-700 hover:border-slate-500"}`}
            >
              <div className="text-3xl">📦</div>
              <div className="mt-2 font-medium">{file ? file.name : "Drop a .zip of your project"}</div>
              <div className="text-xs text-slate-500">{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : "or click to browse (max 50 MB)"}</div>
              <input ref={input} type="file" accept=".zip" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            </div>
            <button className="btn-primary w-full py-3" disabled={!file} onClick={() => onZip(file, ai)}>
              Scan archive
            </button>
          </div>
        )}

        <label className={`mt-5 flex items-start gap-3 rounded-lg border border-slate-800 p-3 text-sm ${aiEnabled ? "" : "opacity-60"}`}>
          <input type="checkbox" className="mt-0.5 accent-emerald-500" checked={ai} disabled={!aiEnabled} onChange={(e) => setUseAi(e.target.checked)} />
          <span>
            <span className="font-medium">AI triage &amp; deep review</span>
            <span className="block text-xs text-slate-500">
              {aiEnabled
                ? "Sends snippets of the riskiest code to the configured LLM provider."
                : "Add GROQ_API_KEY or OPENAI_API_KEY to backend/.env to enable."}
            </span>
          </span>
        </label>

        {sampleAvailable && (
          <div className="mt-5 border-t border-slate-800 pt-5 text-center">
            <button className="btn-ghost w-full" onClick={() => onSample(ai)}>
              ⚡ Try the built-in vulnerable demo project
            </button>
          </div>
        )}
      </section>
    </div>
  );
}
