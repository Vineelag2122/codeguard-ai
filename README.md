# 🛡️ CodeGuard AI

**An architecture-agnostic agent that finds security vulnerabilities, AI slop, coding gaps and loose ends in any codebase.**

Built for the Mycrobo hackathon brief: *"A simple agent for security and pulling slop as well as coding gaps and loose ends which is architecture agnostic."*

Upload a ZIP or paste a GitHub URL. The agent profiles the project, decides which checks to run, runs them, then uses an LLM to triage false positives and look for logic flaws that rules cannot see. It produces a scored report with file:line locations, an explanation of each issue and a recommended fix.

| Issue | Severity | Recommendation |
|---|---|---|
| `password = "admin123"` hardcoded password | High | Use environment variables or a secrets manager |
| `"SELECT * FROM users WHERE id = " + user_id` | Critical | Use parameterized queries |
| `def process_payment(): pass` empty function | Medium | Implement the function or remove unused code |

---

## What it detects

| Category | Examples |
|---|---|
| **Security** | hardcoded passwords/API keys, AWS keys, private keys, DB URLs with credentials, committed `.env`, SQL injection (regex + Python AST), command injection, `eval`/`exec`, insecure deserialization (pickle, `yaml.load`, ObjectInputStream), path traversal, SSRF, XSS (`innerHTML`, `dangerouslySetInnerHTML`, `|safe`), weak hashing (MD5/SHA-1), TLS verification disabled, JWT verification disabled, insecure randomness for tokens, debug mode, wildcard CORS, secrets in logs, `chmod 777` + **Bandit** and **Semgrep** when installed |
| **AI slop** | leftover LLM text ("here's the updated code", "rest of the code remains the same"), "in a real application..." shortcuts, duplicated logic (AST hash + cross-file block hashing), unused imports, debug prints, breakpoints, blanket `@ts-ignore`/`noqa`, TypeScript `any`, overly long functions, huge parameter lists |
| **Coding gaps** | empty functions (Python, JS/TS, Java, C#, Go...), `NotImplementedError` / `todo!()` / `UnsupportedOperationException`, empty `catch {}`, `except: pass`, bare `except`, Go `if err != nil {}`, mutable default args, HTTP calls without timeouts, syntax errors, **no tests in the project** |
| **Loose ends** | TODO / FIXME / HACK / XXX, simulated or mocked logic in production code, hardcoded `localhost` URLs, unpinned dependencies (`requirements.txt`, `package.json` `*`/`latest`), missing README |

## How the agent works

```
 PERCEIVE ──► PLAN ──────────► ACT ──────────────────► REFLECT ─────────────► REPORT
 discover     pick checks      security rules          LLM triage:            score + grade
 files,       from detected    quality rules           confirm / false        exec summary
 profile      languages &      Python AST              positive + fix         HTML / JSON
 the stack    frameworks       Bandit / Semgrep        LLM deep review of     agent trace
                               dedupe across engines   the riskiest files
```

**Why it is architecture-agnostic:** discovery, language-specific scanning and AI reasoning are separate layers. The file scanner classifies 30+ languages/config formats and profiles the stack (monolith, full-stack, monorepo; Django, FastAPI, React, Express, Spring Boot, Gin, Rails, Laravel...). Rules are tagged with the languages they apply to, so adding a language means adding rules, not changing the pipeline. Deep AST analysis is currently Python-only. Other languages use structural regex rules plus the language-neutral LLM review.

**Tested languages:** Python, JavaScript, TypeScript/TSX, Java, Go, Rust (snippets), YAML/.env/requirements. Other languages get the generic rules (secrets, TODOs, injection patterns) but are less thoroughly tested.

Every step is logged to the **agent trace** shown in the UI, so you can see what the agent decided and why.

## Quick start

### 1. Backend (Python 3.10+)

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env          # optional: add GROQ_API_KEY to enable the AI layer
uvicorn main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 2. Frontend (Node 18+)

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and click **"Try the built-in vulnerable demo project"**.

### 3. CLI (no UI needed)

```bash
cd backend
python cli.py ../sample_code
python cli.py https://github.com/owner/repo --html report.html --json report.json
python cli.py ./my-project --no-ai --fail-on high     # non-zero exit code -> use as a CI gate
```

### AI layer (optional)

The agent works fully offline with rules + AST + Bandit. To turn on the LLM triage, deep review and executive summary, put one key in `backend/.env`:

```
GROQ_API_KEY=...          # free tier at console.groq.com
# or OPENAI_API_KEY=...
# or any OpenAI-compatible server: CODEGUARD_LLM_BASE_URL=http://localhost:11434/v1 (Ollama)
```

Default Groq model: `openai/gpt-oss-120b`. If the configured model is retired, the agent automatically switches to one the key can use. Free-tier rate limits (HTTP 429) are handled by waiting and retrying, so an AI scan of a small repo takes about 20-60 seconds. Any AI failure degrades to rule-only results instead of failing the scan.

> Privacy: with AI enabled, code snippets around findings and the top 2 riskiest files are sent to the configured provider. Use a local model (Ollama) for private code.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | backend + AI provider status |
| `POST` | `/api/scan/upload` | multipart `file` (.zip) + `use_ai` |
| `POST` | `/api/scan/github` | `{"url": "https://github.com/owner/repo", "use_ai": true}` |
| `POST` | `/api/scan/sample` | scan the bundled `sample_code/` demo |
| `GET` | `/api/reports/{id}` | JSON report |
| `GET` | `/api/reports/{id}/html` | self-contained HTML report |
| `GET` | `/api/reports/{id}/json` | JSON report as a download |

## Safety of the scanner itself

- ZIP uploads: size limit, zip-bomb limit, **zip-slip path traversal blocked**, symlinks skipped
- GitHub: strict URL allow-list (`https://github.com/owner/repo[/tree/branch]`), shallow clone, no prompts, symlinks disabled, timeout
- Uploaded code is **never executed**, only read. Temp folders are deleted after every scan.
- Suppress a known/accepted finding with an inline `# codeguard: ignore` comment.

## Tests

```bash
backend\.venv\Scripts\python -m pytest tests -q
```

Covers every detector against `sample_code/`, false-positive guards (placeholders, env lookups, abstract methods, parameterized SQL), zip-slip, URL validation and the API endpoints.

## Project structure

```
codeguard-ai/
├── backend/
│   ├── main.py               FastAPI app
│   ├── cli.py                command-line interface / CI gate
│   ├── workspace.py          safe ZIP extraction + GitHub cloning
│   └── scanner/
│       ├── agent.py          perceive → plan → act → reflect → report orchestrator
│       ├── file_scanner.py   discovery + stack profiling (architecture-agnostic layer)
│       ├── security_scanner.py  security rules, Python AST, Bandit, Semgrep
│       ├── quality_scanner.py   slop / gaps / loose ends (AST + structural rules)
│       ├── ai_analyzer.py    LLM triage, deep review, summary (OpenAI-compatible)
│       ├── rules.py          language-aware rule engine
│       ├── models.py         Finding model, severities, dedupe
│       └── report.py         HTML report
├── frontend/                 React + Vite + Tailwind dashboard
├── sample_code/              intentionally vulnerable demo project (Python, JS, Java, TSX, YAML, .env)
└── tests/
```

## Limitations / roadmap

- Regex rules are pattern-based and can produce false positives. The AI triage step exists to mark these, and every finding shows its source and confidence.
- Deep AST/taint analysis is Python-only. Tree-sitter would extend it to other languages.
- Reports are kept in memory (last 50). Add a database for history and trend tracking.
- Next: GitHub PR comments / GitHub Action, SARIF export, auto-fix pull requests.
