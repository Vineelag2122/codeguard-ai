"""Shared data models for CodeGuard AI."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}

# The four things Mycrobo asked for
CATEGORIES = {
    "security": "Security vulnerability",
    "slop": "AI slop / low-quality code",
    "gap": "Coding gap",
    "loose_end": "Loose end",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str  # one of CATEGORIES
    severity: str  # one of SEVERITY_ORDER
    file: str  # path relative to project root ("(project)" for project-level findings)
    line: int
    description: str
    recommendation: str
    snippet: str = ""
    source: str = "rule"  # rule | ast | bandit | semgrep | ai
    confidence: str = "medium"  # low | medium | high
    cwe: str | None = None
    ai_verdict: str | None = None  # confirmed | false_positive | needs_review
    ai_explanation: str | None = None
    ai_fix: str | None = None

    @property
    def id(self) -> str:
        raw = f"{self.rule_id}|{self.file}|{self.line}|{self.title}"
        return hashlib.blake2b(raw.encode(), digest_size=6).hexdigest()

    @property
    def weight(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["id"] = self.id
        return data


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.weight, f.category, f.file, f.line))


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Remove duplicates reported by more than one engine for the same line."""
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        prev = seen.get(key)
        if prev is None or f.weight > prev.weight:
            seen[key] = f
    return list(seen.values())
