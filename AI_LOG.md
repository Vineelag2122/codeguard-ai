# AI Usage Log

This file documents how AI was used to build CodeGuard AI, and how AI is used inside the product at runtime.

## 1. AI tools used during development

| Tool | Model | Used for |
|---|---|---|
| Claude Code (desktop app) | Claude Opus 5.5 | Architecture, code generation, testing, debugging, documentation |

**My role (human):** defined the problem from the Mycrobo brief, chose the scope and tech stack (FastAPI, React, Tailwind, Groq), reviewed the generated code and outputs, supplied the Groq API key, tested the app, and made the decisions about what to ship (for example keeping local tool config out of git).

**AI role:** implemented the backend, frontend, sample project and tests from my spec, ran the tests, and fixed the bugs it found.

## 2. Development log

### Session 1: initial build
- **Prompt (summary):** "Build CodeGuard AI: an architecture-agnostic agent that detects security vulnerabilities, AI slop, coding gaps and loose ends. Stack: FastAPI + React/Tailwind + Groq/OpenAI + Bandit/Semgrep. Input: ZIP upload or GitHub URL. Output: structured report with file, line, severity and recommendation."
- **AI produced:**
  - Backend agent pipeline: perceive → plan → act → reflect → report (`backend/scanner/agent.py`)
  - File discovery and stack profiling for 30+ languages/config formats (`file_scanner.py`)
  - Language-aware rule engine plus security rules (secrets, SQLi, command/code injection, deserialization, XSS, weak crypto, TLS, CORS...) (`rules.py`, `security_scanner.py`)
  - Python AST analysis plus quality rules for slop, gaps and loose ends (`quality_scanner.py`)
  - Bandit / Semgrep integration with de-duplication across engines
  - LLM triage, deep review and executive summary (`ai_analyzer.py`)
  - FastAPI API with safe ZIP extraction (zip-slip and zip-bomb protection) and validated GitHub cloning (`main.py`, `workspace.py`)
  - CLI with a `--fail-on` CI gate (`cli.py`), HTML report (`report.py`)
  - React dashboard (`frontend/`), intentionally vulnerable demo project (`sample_code/`), test suite (`tests/`)
- **Verification:** 68 pytest tests passing; frontend production build; end-to-end scan through the UI; real scan of a public GitHub repository.

### Problems found during testing and how they were fixed
| Problem | How it was found | Fix |
|---|---|---|
| `FIXME` comments rated low instead of medium | Reviewing demo output | Added per-match severity to the rule engine |
| Demo file's own docstring triggered the "in a real application" rule | Reviewing demo output | Reworded the sample docstring |
| `except ValueError: continue` reported as a swallowed exception | Running the tool on its own source code | Skip-and-continue with a specific exception is no longer flagged |
| Rule definitions matched themselves when scanning this repo | Running the tool on its own source code | Added inline `# codeguard: ignore` suppression markers |
| XSS rule flagged every `Markup()` call (noisy on real code) | Scanning `pallets/markupsafe` from GitHub | Removed that pattern; XSS rule skips test files. Score went from 56 (D) to 87 (B) |
| pip install hung in the background | Monitoring the install | Restarted in the foreground |

### Session 2: enabling the AI layer
- **Prompt (summary):** "Here is my Groq API key, put it in the code."
- **Decision:** the key was stored in the git-ignored `backend/.env`, **not** in source code, so it is never pushed. The key is not included anywhere in this repository.
- **Problems found when calling Groq, and fixes:**
  | Problem | Fix |
  |---|---|
  | Default model `llama-3.3-70b-versatile` retired (HTTP 404) | Default changed to `openai/gpt-oss-120b`; automatic fallback to an available model |
  | Free-tier rate limit of 8,000 tokens/min (HTTP 429) | Wait-and-retry using the provider's retry hint; smaller batched requests |
  | Strict JSON mode rejected a response (HTTP 400) | Retry without JSON mode and extract the JSON manually |
  | Model returned malformed entries, which crashed a scan | Malformed entries are skipped; every AI stage is wrapped so failures fall back to rule-only results |
  | Windows console crashed printing Unicode from AI text | CLI output made encoding-safe |
- **Verification:** live AI scan of the demo project: 16 findings triaged and confirmed with explanations and fixes, 6 additional issues found by deep review (e.g. missing authorization on an admin delete endpoint), executive summary generated, 0 errors. 2 new regression tests simulate a broken LLM, bringing the total to 70 passing tests.

### Session 3: submission prep
- Added `.claude/` (local, machine-specific Claude Code config) to `.gitignore`.
- Drafted submission text, `arena.json` and this log.

## 3. AI inside the product (runtime)

CodeGuard AI calls an LLM through any OpenAI-compatible API. The default is Groq `openai/gpt-oss-120b`; OpenAI and local Ollama are also supported.

| Stage | What the LLM does | Guardrails |
|---|---|---|
| Triage | Reviews medium+ findings with code context: confirmed / false positive / needs review, impact explanation, fix | Only acts on findings the rules produced; results matched by ID; false positives are hidden from the score, not deleted |
| Deep review | Reads the 2 riskiest files and reports issues rules cannot see | Line numbers validated against the file; duplicates of existing findings dropped; capped at 6 issues per file |
| Summary | Writes an executive summary for an engineering lead | Falls back to a rule-based summary |

The AI layer is optional: without an API key every rule, AST and Bandit check still runs. Any AI failure degrades to rule-only results instead of failing the scan.
