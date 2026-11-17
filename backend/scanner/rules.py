"""Tiny, language-aware regex rule engine shared by the security and quality scanners."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from .file_scanner import SourceFile
from .models import SEVERITY_DOWNGRADE, Finding

SUPPRESS_MARKER = re.compile(r"codeguard[:\-\s]*ignore", re.IGNORECASE)
COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "<!--", "'''", '"""')
MAX_PER_RULE_PER_FILE = 5


@dataclass
class Rule:
    id: str
    title: str
    category: str
    severity: str
    pattern: re.Pattern
    description: str
    recommendation: str
    languages: set[str] | None = None  # None = every language
    kinds: tuple[str, ...] = ("code",)
    cwe: str | None = None
    confidence: str = "medium"
    skip_comments: bool = True
    skip_tests: bool = False
    downgrade_in_tests: bool = False
    validator: Callable[[re.Match], bool] | None = None  # extra check to cut false positives
    title_from_match: Callable[[re.Match], str] | None = None
    severity_from_match: Callable[[re.Match], str] | None = None


def is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


def applies(rule: Rule, f: SourceFile) -> bool:
    if f.kind not in rule.kinds:
        return False
    if rule.languages is not None and f.kind == "code" and f.language not in rule.languages:
        return False
    if rule.skip_tests and f.is_test:
        return False
    return True


def run_line_rules(rules: list[Rule], files: list[SourceFile], source: str = "rule") -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        active = [r for r in rules if applies(r, f)]
        if not active:
            continue
        per_rule = Counter()
        for lineno, line in enumerate(f.lines, start=1):
            if len(line) > 2000 or SUPPRESS_MARKER.search(line):
                continue
            comment = is_comment(line)
            for rule in active:
                if rule.skip_comments and comment:
                    continue
                if per_rule[rule.id] >= MAX_PER_RULE_PER_FILE:
                    continue
                m = rule.pattern.search(line)
                if not m or (rule.validator and not rule.validator(m)):
                    continue
                per_rule[rule.id] += 1
                severity = rule.severity_from_match(m) if rule.severity_from_match else rule.severity
                if rule.downgrade_in_tests and f.is_test:
                    severity = SEVERITY_DOWNGRADE[severity]
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title_from_match(m) if rule.title_from_match else rule.title,
                        category=rule.category,
                        severity=severity,
                        file=f.path,
                        line=lineno,
                        description=rule.description,
                        recommendation=rule.recommendation,
                        snippet=line.strip()[:300],
                        source=source,
                        confidence=rule.confidence,
                        cwe=rule.cwe,
                    )
                )
    return findings


def run_multiline_rules(rules: list[Rule], files: list[SourceFile]) -> list[Finding]:
    """Rules whose pattern can span lines (e.g. empty catch blocks)."""
    findings: list[Finding] = []
    for f in files:
        for rule in rules:
            if not applies(rule, f):
                continue
            count = 0
            for m in rule.pattern.finditer(f.text):
                if count >= MAX_PER_RULE_PER_FILE:
                    break
                lineno = f.text.count("\n", 0, m.start()) + 1
                if SUPPRESS_MARKER.search(f.line(lineno)):
                    continue
                if rule.validator and not rule.validator(m):
                    continue
                count += 1
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title_from_match(m) if rule.title_from_match else rule.title,
                        category=rule.category,
                        severity=rule.severity,
                        file=f.path,
                        line=lineno,
                        description=rule.description,
                        recommendation=rule.recommendation,
                        snippet=" ".join(m.group(0).split())[:300],
                        confidence=rule.confidence,
                        cwe=rule.cwe,
                    )
                )
    return findings
