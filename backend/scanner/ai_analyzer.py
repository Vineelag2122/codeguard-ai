"""LLM reasoning layer.

Works with any OpenAI-compatible chat-completions API (Groq, OpenAI, Together,
local Ollama/LM Studio, ...). Three jobs:

1. triage     - review rule findings with code context, flag false positives,
                explain impact and propose a concrete fix
2. deep_review - read the riskiest files in full and report issues that
                regex/AST rules cannot see (auth logic, missing validation...)
3. summarize  - write an executive summary for the report

If no API key is configured every method is a no-op and the scan still works.
"""
from __future__ import annotations

import json
import os
import re
import time

import httpx

from .file_scanner import SourceFile
from .models import CATEGORIES, SEVERITY_ORDER, Finding

PROVIDERS = {
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "openai/gpt-oss-120b"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", "gpt-4o-mini"),
}
# used when the configured model has been retired by the provider
FALLBACK_MODELS = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b", "gpt-4.1-mini", "gpt-4o-mini"]
RISKY_NAMES = re.compile(r"auth|login|session|password|token|payment|checkout|admin|upload|api|route|controller|db|database|query|user", re.I)


class AIAnalyzer:
    def __init__(self):
        provider = os.getenv("CODEGUARD_LLM_PROVIDER", "").lower()
        if not provider:
            provider = next((p for p, (_, env, _) in PROVIDERS.items() if os.getenv(env)), "groq")
        base, key_env, model = PROVIDERS.get(provider, PROVIDERS["groq"])
        self.provider = provider
        self.base_url = os.getenv("CODEGUARD_LLM_BASE_URL", base).rstrip("/")
        self.api_key = os.getenv("CODEGUARD_LLM_API_KEY") or os.getenv(key_env, "")
        self.model = os.getenv("CODEGUARD_LLM_MODEL", model)
        self.timeout = float(os.getenv("CODEGUARD_LLM_TIMEOUT", "60"))
        self.calls = 0
        self.errors: list[str] = []

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def info(self) -> dict:
        return {"enabled": self.enabled, "provider": self.provider, "model": self.model}

    # ------------------------------------------------------------ transport
    def _switch_to_available_model(self) -> bool:
        """The configured model was not found: pick one the key can actually use."""
        try:
            resp = httpx.get(f"{self.base_url}/models", timeout=self.timeout,
                             headers={"Authorization": f"Bearer {self.api_key}"})
            resp.raise_for_status()
            available = {m["id"] for m in resp.json().get("data", [])}
        except (httpx.HTTPError, KeyError, ValueError):
            return False
        for candidate in FALLBACK_MODELS:
            if candidate in available and candidate != self.model:
                self.errors.append(f"model {self.model} unavailable, switched to {candidate}")
                self.model = candidate
                return True
        return False

    def _chat_json(self, system: str, user: str, max_tokens: int = 2500) -> dict | None:
        """Call the model and parse a JSON object, recovering from the common failure modes:
        retired model (404), free-tier rate limits (429) and strict-JSON-mode rejections (400)."""
        if not self.enabled:
            return None
        json_mode, switched, msg = True, False, ""
        for _attempt in range(5):
            payload = {
                "model": self.model,
                "temperature": 0.1,
                "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            }
            if json_mode:
                payload["response_format"] = {"type": "json_object"}
            if "gpt-oss" in self.model:
                payload["reasoning_effort"] = "low"  # faster; the findings are already pre-filtered
            try:
                self.calls += 1
                resp = httpx.post(f"{self.base_url}/chat/completions", json=payload, timeout=self.timeout,
                                  headers={"Authorization": f"Bearer {self.api_key}"})
            except httpx.HTTPError as exc:
                msg = f"{exc.__class__.__name__}: {exc}"
                break
            body = resp.text
            if resp.status_code == 429:
                wait = _retry_after(resp)
                if wait is None or wait > 40:
                    msg = "rate limit reached (try again in a minute or use a paid tier)"
                    break
                time.sleep(wait + 0.5)
                continue
            if resp.status_code == 404 and "model" in body and not switched and self._switch_to_available_model():
                switched = True
                continue
            if resp.status_code == 400 and "json_validate_failed" in body and json_mode:
                json_mode = False  # let the model answer freely; we extract the JSON ourselves
                continue
            if resp.status_code >= 400:
                msg = f"HTTP {resp.status_code}: {body[:200]}"
                break
            try:
                return _parse_json(resp.json()["choices"][0]["message"]["content"] or "")
            except (KeyError, IndexError, ValueError, TypeError) as exc:
                msg = f"unparseable model response ({exc.__class__.__name__})"
                if json_mode:
                    json_mode = False
                    continue
                break
        else:
            msg = msg or "gave up after repeated retries"
        self.errors.append(msg.replace(self.api_key, "***"))
        return None

    # ------------------------------------------------------------ 1. triage
    def triage(self, findings: list[Finding], files: dict[str, SourceFile], limit: int = 16, batch: int = 8) -> dict:
        candidates = [f for f in findings if f.weight >= SEVERITY_ORDER["medium"] and f.file in files][:limit]
        if not candidates or not self.enabled:
            return {"reviewed": 0, "false_positives": 0}
        reviewed = fp = 0
        for i in range(0, len(candidates), batch):
            r, p = self._triage_batch(candidates[i:i + batch], files)
            reviewed, fp = reviewed + r, fp + p
        return {"reviewed": reviewed, "false_positives": fp}

    def _triage_batch(self, candidates: list[Finding], files: dict[str, SourceFile]) -> tuple[int, int]:
        blocks = []
        for f in candidates:
            blocks.append(
                f"### id={f.id}\nrule: {f.title} [{f.category}/{f.severity}]\nfile: {f.file}:{f.line}\n"
                f"```\n{files[f.file].context(f.line, 3)}\n```"
            )
        system = (
            "You are a senior application-security and code-quality reviewer. You receive findings produced by "
            "static rules, each with surrounding code. For EACH finding decide: 'confirmed' (real issue), "
            "'false_positive' (rule misfired, e.g. placeholder value, test fixture, safe usage) or 'needs_review'. "
            "Explain the concrete impact in 1-2 sentences for a developer, and give a minimal corrected code snippet "
            "for confirmed issues. Respond ONLY with JSON: "
            '{"results":[{"id":"...","verdict":"confirmed|false_positive|needs_review",'
            '"severity":"critical|high|medium|low","explanation":"...","fix":"code or empty"}]}'
        )
        data = self._chat_json(system, "\n\n".join(blocks), max_tokens=3000) or {}
        by_id = {f.id: f for f in candidates}
        reviewed = fp = 0
        for r in data.get("results", []) if isinstance(data.get("results"), list) else []:
            if not isinstance(r, dict):
                continue
            f = by_id.get(str(r.get("id")))
            if not f:
                continue
            reviewed += 1
            verdict = r.get("verdict")
            f.ai_verdict = verdict if verdict in {"confirmed", "false_positive", "needs_review"} else "needs_review"
            f.ai_explanation = str(r.get("explanation") or "")[:1000] or None
            f.ai_fix = str(r.get("fix") or "")[:2000] or None
            if f.ai_verdict == "false_positive":
                fp += 1
            elif r.get("severity") in SEVERITY_ORDER and f.ai_verdict == "confirmed":
                f.severity = r["severity"]
        return reviewed, fp

    # ------------------------------------------------------------ 2. deep review
    def pick_files(self, files: list[SourceFile], findings: list[Finding], max_files: int = 2) -> list[SourceFile]:
        score: dict[str, int] = {}
        for f in findings:
            score[f.file] = score.get(f.file, 0) + f.weight ** 2
        candidates = [f for f in files if f.kind == "code" and not f.is_test and 10 <= len(f.lines) <= 1500]
        candidates.sort(key=lambda f: (score.get(f.path, 0) + (5 if RISKY_NAMES.search(f.path) else 0)), reverse=True)
        return candidates[:max_files]

    def deep_review(self, targets: list[SourceFile], existing: list[Finding]) -> list[Finding]:
        if not self.enabled:
            return []
        system = (
            "You are an expert security auditor and code reviewer. Review the file for problems that simple "
            "pattern-matching would MISS: broken authentication/authorization, missing input validation, "
            "business-logic flaws, race conditions, missing error handling, incomplete or placeholder "
            "implementations, AI-generated slop (code that looks plausible but does nothing useful, hallucinated "
            "APIs, contradictory logic) and unhandled edge cases. Do not repeat issues already listed. Report at "
            "most 6 high-value issues; skip style nitpicks. Respond ONLY with JSON: "
            '{"issues":[{"line":<int>,"title":"...","category":"security|slop|gap|loose_end",'
            '"severity":"critical|high|medium|low","description":"...","recommendation":"...","fix":"code or empty"}]}'
        )
        known = {(f.file, f.line) for f in existing}
        out: list[Finding] = []
        for sf in targets:
            numbered = "\n".join(f"{i:>4}| {l}" for i, l in enumerate(sf.lines, 1))[:9000]
            already = [f"- line {f.line}: {f.title}" for f in existing if f.file == sf.path][:20]
            user = (f"File: {sf.path} (language: {sf.language})\nAlready reported:\n"
                    + ("\n".join(already) or "- none") + f"\n\n```\n{numbered}\n```")
            data = self._chat_json(system, user, max_tokens=3000) or {}
            for item in data.get("issues", []) if isinstance(data.get("issues"), list) else []:
                if not isinstance(item, dict):
                    continue
                try:
                    line = int(item.get("line", 0))
                except (TypeError, ValueError):
                    continue
                if not (1 <= line <= len(sf.lines)) or (sf.path, line) in known:
                    continue
                category = item.get("category") if item.get("category") in CATEGORIES else "gap"
                severity = item.get("severity") if item.get("severity") in SEVERITY_ORDER else "medium"
                out.append(Finding(
                    "ai-review", str(item.get("title") or "Issue found by AI review")[:120], category, severity,
                    sf.path, line, str(item.get("description") or "")[:1000],
                    str(item.get("recommendation") or "")[:1000], snippet=sf.line(line).strip()[:300],
                    source="ai", confidence="medium", ai_verdict="confirmed",
                    ai_fix=str(item.get("fix") or "")[:2000] or None))
                known.add((sf.path, line))
        return out

    # ------------------------------------------------------------ 3. summary
    def summarize(self, profile: dict, summary: dict, top: list[Finding]) -> str | None:
        if not self.enabled:
            return None
        lines = [f"- [{f.severity}] {f.title} ({f.file}:{f.line})" for f in top[:15]]
        user = (
            f"Project profile: {json.dumps({k: profile[k] for k in ('languages', 'frameworks', 'architecture')})}\n"
            f"Totals: {json.dumps(summary)}\nTop findings:\n" + "\n".join(lines)
        )
        system = (
            "Write a concise executive summary (max 120 words) of this code audit for an engineering lead: overall "
            "risk, the 2-3 most important things to fix first and why. Plain text, no markdown headers. "
            'Respond ONLY with JSON: {"summary":"..."}'
        )
        data = self._chat_json(system, user, max_tokens=1200) or {}
        s = data.get("summary")
        return s.strip() if isinstance(s, str) and s.strip() else None


def _retry_after(resp: httpx.Response) -> float | None:
    """Seconds to wait before retrying a 429, from the header or Groq's 'try again in 7.5s' message."""
    header = resp.headers.get("retry-after")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    m = re.search(r"try again in (?:(\d+)m)?([\d.]+)(ms|s)", resp.text)
    if not m:
        return None
    seconds = float(m.group(2)) / (1000 if m.group(3) == "ms" else 1)
    return seconds + 60 * int(m.group(1) or 0)


def _parse_json(content: str) -> dict:
    content = content.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", content, re.S)
    if fence:
        content = fence.group(1)
    start, end = content.find("{"), content.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in model response")
    data = json.loads(content[start:end + 1])
    if not isinstance(data, dict):
        raise ValueError("model response is not a JSON object")
    return data
