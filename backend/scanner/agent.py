"""CodeGuard agent: perceive -> plan -> act -> reflect -> report.

Every step is recorded in a trace so users (and judges) can see what the
agent decided and why.
"""
from __future__ import annotations

import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .ai_analyzer import AIAnalyzer
from .file_scanner import discover_files, profile_project
from .models import CATEGORIES, SEVERITY_ORDER, Finding, dedupe, sort_findings
from .quality_scanner import scan_quality
from .security_scanner import run_bandit, run_semgrep, scan_security

PENALTY = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}


class CodeGuardAgent:
    def __init__(self, use_ai: bool = True, use_external_tools: bool = True, ai: AIAnalyzer | None = None):
        self.ai = ai or AIAnalyzer()
        self.use_ai = use_ai and self.ai.enabled
        self.use_external_tools = use_external_tools
        self.trace: list[dict] = []

    def _step(self, phase: str, action: str, detail: str, started: float, status: str = "ok"):
        self.trace.append({"phase": phase, "action": action, "detail": detail, "status": status,
                           "duration_ms": int((time.perf_counter() - started) * 1000)})

    def run(self, root: str | Path, project_name: str | None = None) -> dict:
        root = Path(root)
        t0 = time.perf_counter()

        # 1. PERCEIVE: discover files and profile the stack
        t = time.perf_counter()
        files, stats = discover_files(root)
        profile = profile_project(root, files, stats["all_paths"])
        langs = ", ".join(f"{l['language']} ({l['files']})" for l in profile["languages"][:6]) or "none"
        self._step("perceive", "Discover files",
                   f"{len(files)} scannable files ({profile['total_lines']} lines of code). Languages: {langs}", t)
        self._step("perceive", "Profile architecture",
                   f"{profile['architecture']}; frameworks: {', '.join(profile['frameworks']) or 'none detected'}; "
                   f"{profile['test_files']} test files", t)

        # 2. PLAN: choose tools based on what was found
        t = time.perf_counter()
        has_python = any(f.language == "python" for f in files)
        plan = ["multi-language security rules", "quality / slop / loose-end rules"]
        if has_python:
            plan.append("Python AST analysis")
        if self.use_external_tools and has_python:
            plan.append("Bandit")
        if self.use_external_tools:
            plan.append("Semgrep (if installed)")
        if self.use_ai:
            plan += ["AI triage of findings", "AI deep review of riskiest files", "AI executive summary"]
        self._step("plan", "Select tools", " -> ".join(plan), t)

        # 3. ACT: run the scanners
        findings: list[Finding] = []
        t = time.perf_counter()
        sec = scan_security(files)
        findings += sec
        self._step("act", "Security scan", f"{len(sec)} potential security issues", t)

        t = time.perf_counter()
        qual = scan_quality(files, profile)
        findings += qual
        by_cat = Counter(f.category for f in qual)
        self._step("act", "Quality scan",
                   f"{by_cat['slop']} slop, {by_cat['gap']} gaps, {by_cat['loose_end']} loose ends", t)

        if self.use_external_tools:
            for name, runner in (("Bandit", lambda: run_bandit(str(root), files)), ("Semgrep", lambda: run_semgrep(str(root)))):
                t = time.perf_counter()
                extra, status = runner()
                # keep tool findings only when no rule already flagged that exact line
                flagged = {(f.file, f.line) for f in findings if f.category == "security"}
                new = [f for f in extra if (f.file, f.line) not in flagged]
                findings += new
                self._step("act", name, f"{status}; {len(new)} new after de-duplication", t,
                           "ok" if status.startswith("ran") else "skipped")

        before = len(findings)
        findings = sort_findings(dedupe(findings))
        duplicates_removed = before - len(findings)

        # 4. REFLECT: AI triage + deep review
        ai_stats = {"reviewed": 0, "false_positives": 0, "added": 0}
        if self.use_ai:
            by_path = {f.path: f for f in files}
            # The AI layer is best-effort: any failure degrades to rule-only results, never a failed scan.
            t = time.perf_counter()
            try:
                tri = self.ai.triage(findings, by_path)
                ai_stats.update(tri)
                self._step("reflect", "AI triage",
                           f"reviewed {tri['reviewed']} findings, {tri['false_positives']} marked false positive", t,
                           "ok" if tri["reviewed"] else "warning")
            except Exception as exc:  # noqa: BLE001 - deliberate safety net around a third-party API
                self.ai.errors.append(f"triage failed: {exc.__class__.__name__}")
                self._step("reflect", "AI triage", "failed - continuing with rule results", t, "warning")

            t = time.perf_counter()
            try:
                targets = self.ai.pick_files(files, findings)
                added = self.ai.deep_review(targets, findings)
                ai_stats["added"] = len(added)
                findings = sort_findings(findings + added)
                self._step("reflect", "AI deep review",
                           f"read {', '.join(f.path for f in targets) or 'no files'}; found {len(added)} additional issues", t)
            except Exception as exc:  # noqa: BLE001
                self.ai.errors.append(f"deep review failed: {exc.__class__.__name__}")
                self._step("reflect", "AI deep review", "failed - continuing with rule results", t, "warning")
        else:
            self._step("reflect", "AI review",
                       "skipped - no LLM API key configured" if not self.ai.enabled else "skipped - disabled for this scan",
                       time.perf_counter(), "skipped")

        # 5. REPORT
        active = [f for f in findings if f.ai_verdict != "false_positive"]
        summary = build_summary(active, profile)
        summary["duplicates_removed"] = duplicates_removed
        summary["false_positives_hidden"] = len(findings) - len(active)
        ai_summary = None
        if self.use_ai:
            t = time.perf_counter()
            try:
                ai_summary = self.ai.summarize(profile, summary, active)
            except Exception as exc:  # noqa: BLE001
                self.ai.errors.append(f"summary failed: {exc.__class__.__name__}")
            self._step("report", "AI executive summary", "generated" if ai_summary else "unavailable", t)

        return {
            "id": uuid.uuid4().hex[:12],
            "project_name": project_name or root.name,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": int((time.perf_counter() - t0) * 1000),
            "profile": profile,
            "skipped_files": stats["skipped"],
            "summary": summary,
            "executive_summary": ai_summary or rule_based_summary(summary, active),
            "ai": {**self.ai.info(), "used": self.use_ai, "calls": self.ai.calls,
                   "errors": self.ai.errors[:5], **ai_stats},
            "trace": self.trace,
            "findings": [f.to_dict() for f in findings],
        }


def build_summary(findings: list[Finding], profile: dict) -> dict:
    sev = Counter(f.severity for f in findings)
    cat = Counter(f.category for f in findings)
    penalty = sum(PENALTY[f.severity] for f in findings)
    score = round(100 / (1 + penalty / 60))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    files_affected = len({f.file for f in findings})
    return {
        "total": len(findings),
        "by_severity": {s: sev.get(s, 0) for s in SEVERITY_ORDER},
        "by_category": {c: cat.get(c, 0) for c in CATEGORIES},
        "score": score,
        "grade": grade,
        "files_scanned": profile["total_files"],
        "lines_scanned": profile["total_lines"],
        "files_affected": files_affected,
    }


def rule_based_summary(summary: dict, findings: list[Finding]) -> str:
    s = summary["by_severity"]
    c = summary["by_category"]
    if not findings:
        return "No issues were detected by the enabled checks. Keep tests and dependency scanning in CI."
    parts = [f"Health score {summary['score']}/100 (grade {summary['grade']}). Found {summary['total']} issues "
             f"across {summary['files_affected']} files: {s['critical']} critical, {s['high']} high, {s['medium']} medium."]
    parts.append(f"Breakdown: {c['security']} security, {c['gap']} coding gaps, {c['slop']} slop, {c['loose_end']} loose ends.")
    top = [f for f in findings if f.severity in ("critical", "high")][:3]
    if top:
        parts.append("Fix first: " + "; ".join(f"{f.title} ({f.file}:{f.line})" for f in top) + ".")
    return " ".join(parts)
