"""Single-text triage for the Arena `POST /classify` contract.

Takes one piece of text - a code snippet, a diff, or a plain-language issue
report - and returns {category, urgency, confidence}. It reuses CodeGuard's
real rule engine and Python AST checks, then falls back to keyword cues when
the text is prose rather than code. Deterministic: no network, no API key.
"""
from __future__ import annotations

import re

from .file_scanner import SourceFile
from .models import SEVERITY_ORDER, Finding, dedupe
from .quality_scanner import MULTILINE_RULES, QUALITY_RULES, python_ast_quality
from .rules import run_line_rules, run_multiline_rules
from .security_scanner import SECURITY_RULES, python_ast_security

CATEGORIES = ("security", "slop", "gap", "loose_end", "general")
# Analyse the snippet as each of these so language-specific rules also fire.
PROBE_LANGUAGES = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "go": "go"}

KEYWORDS = {
    "security": r"vulnerab|inject|xss|csrf|ssrf|exploit|secret|credential|password|api[ _-]?key|token|leak|"
                r"hardcoded (?:key|password|secret)|unauthori[sz]ed|auth(?:entication|orization)? bypass|"
                r"privilege|malware|breach|cve-|rce\b|remote code|deserializ|encrypt",
    "slop": r"ai[- ]generated|chatgpt|llm (?:output|code)|copy[- ]?past|duplicat|boilerplate|placeholder|"
            r"lorem ipsum|dead code|unused|hallucinat|slop|redundant|as an ai",
    "gap": r"not implemented|unimplemented|missing|no (?:error|exception) handling|no tests?|untested|"
           r"swallow|ignored? error|empty (?:function|catch|method)|no validation|unvalidated|edge case|"
           r"crash|null pointer|timeout",
    "loose_end": r"\btodo\b|\bfixme\b|\bhack\b|\bxxx\b|temporary|hard[- ]?coded|localhost|debug print|"
                 r"left ?over|unfinished|wip\b|unpinned",
}
URGENT = re.compile(r"urgent|critical|immediately|asap|outage|breach|exploited|in production|data loss|"
                    r"actively|zero[- ]day|severe|p0\b|sev ?1", re.I)


def _rule_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines() or [text]
    for language, ext in PROBE_LANGUAGES.items():
        sf = SourceFile(f"snippet.{ext}", "", language, "code", text, lines)
        files = [sf]
        findings += run_line_rules(SECURITY_RULES + QUALITY_RULES, files)
        findings += run_multiline_rules(MULTILINE_RULES, files)
        if language == "python":
            findings += python_ast_security(files)
            findings += [f for f in python_ast_quality(files)
                         if f.rule_id not in {"syntax-error", "unused-import"}]  # prose isn't broken code
    # the same issue found under several probe languages counts once
    for f in findings:
        f.file = "snippet"
    return dedupe(findings)


def classify_text(text: str) -> dict:
    findings = _rule_findings(text)
    lowered = text.lower()

    if findings:
        # pick the category carrying the most severe evidence
        best: dict[str, int] = {}
        for f in findings:
            best[f.category] = max(best.get(f.category, 0), f.weight)
        category = max(best, key=lambda c: (best[c], c == "security"))
        top = max(f.weight for f in findings)
        high_conf = any(f.confidence == "high" and f.category == category for f in findings)
        confidence = 0.9 if high_conf else 0.75
        urgent = top >= SEVERITY_ORDER["high"] or bool(URGENT.search(text))
    else:
        hits = {c: len(re.findall(p, lowered)) for c, p in KEYWORDS.items()}
        category = max(hits, key=lambda c: (hits[c], c == "security"))
        if hits[category] == 0:
            category = "general"
            confidence = 0.3
        else:
            confidence = round(min(0.85, 0.5 + 0.1 * hits[category]), 2)
        urgent = bool(URGENT.search(text)) or (category == "security" and hits.get("security", 0) >= 2)

    return {
        "category": category,
        "urgency": "high" if urgent else "low",
        "confidence": confidence,
        "issues": [
            {"rule": f.rule_id, "title": f.title, "severity": f.severity, "line": f.line,
             "recommendation": f.recommendation}
            for f in sorted(findings, key=lambda f: -f.weight)[:10]
        ],
    }
