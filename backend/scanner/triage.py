"""Ticket triage for the Arena AI-triage track (`POST /classify`).

Input: one incoming report - a support ticket, bug report or pasted code.
Output (the track contract):
    category    billing | technical | account | general
    urgency     high | low
    confidence  0..1

How it decides
1. Weighted keyword evidence per category (word-boundary matches, phrases count
   more than single words). Ties break in the contract's order: billing,
   technical, account.
2. Urgency is high for explicit urgency cues, outages, data loss, security
   compromise, or money taken in error.
3. CodeGuard layer: if the text contains code, the same security/quality rule
   engine used for repository scans runs on it. Findings are returned under
   `code_findings`, the ticket counts as `technical`, and a critical/high
   security finding (e.g. SQL injection, leaked key) makes it urgent.

Deterministic, offline, no API key - so results are reproducible and testable.
"""
from __future__ import annotations

import re

from .file_scanner import SourceFile
from .models import SEVERITY_ORDER, Finding, dedupe
from .quality_scanner import MULTILINE_RULES, QUALITY_RULES
from .rules import run_line_rules, run_multiline_rules
from .security_scanner import SECURITY_RULES, python_ast_security

LABELS = ("billing", "technical", "account")  # tie-break order; anything else is "general"

# (pattern, weight). Patterns are matched on lower-cased text with word boundaries.
SIGNALS: dict[str, list[tuple[str, float]]] = {
    "billing": [
        (r"refunds?|refunded|reimburse\w*|chargebacks?", 3),
        (r"invoices?|receipts?|billing|billed|bills?", 2.5),
        (r"payments?|pay|paid|paying|charges?|charged|overcharg\w*|double[- ]charged|charged twice", 2.5),
        (r"subscriptions?|renewals?|auto[- ]?renew\w*|plans? (?:upgrade|downgrade|change)|upgrade my plan|downgrade", 2),
        (r"price|pricing|cost|fees?|discount|coupon|promo code|credit card|debit card|card declined|bank|money|vat|tax", 1.5),
        (r"cancel(?:led|ing)? (?:my )?(?:subscription|plan|membership)", 2.5),
    ],
    "technical": [
        (r"errors?|exceptions?|crash\w*|bugs?|broken|glitch\w*|freez\w*|hangs?|stack ?trace|traceback", 2.5),
        (r"not working|doesn'?t work|does not work|stopped working|won'?t (?:load|open|start)|fails?|failed|failing|failure", 2.5),
        (r"slow|lag\w*|timeouts?|timed out|latency|down|outage|unavailable|500|502|503|504|404", 2),
        (r"install\w*|updat\w*|upgrade (?:the )?app|sync\w*|api|integration|webhook|server|database|deploy\w*|app|website|page|feature", 1),
        (r"vulnerab\w*|sql injection|xss|exploit\w*|security (?:issue|bug|flaw|hole)", 2.5),
    ],
    "account": [
        (r"log ?in|login|logged out|log ?out|sign ?in|signin|sign ?up|signup|register\w*", 2.5),
        (r"passwords?|reset (?:my )?password|forgot (?:my )?password|2fa|two[- ]factor|mfa|otp|verification code|authenticat\w*", 2.5),
        (r"accounts?|username|user ?name|profile|locked out|lock(?:ed)? (?:me )?out|deactivat\w*|delete my account|close my account", 2.5),
        (r"email (?:address )?change|change (?:my )?email|verify (?:my )?email|permissions?|access|hacked|compromised|unauthori[sz]ed", 1.5),
    ],
}
URGENT = re.compile(
    r"\b(?:urgent\w*|asap|immediately|right away|right now|emergency|critical|severe|outage|"
    r"(?:site|app|service|system|server|production|everything) (?:is )?down|down for (?:everyone|all)|"
    r"all (?:users|customers)|data loss|lost (?:all )?(?:my )?data|breach\w*|hacked|compromised|"
    r"unauthori[sz]ed (?:charge|access|transaction)|fraud\w*|charged twice|double[- ]charged|"
    r"can(?:no|')?t (?:access|log ?in|sign ?in|pay|use)|cannot (?:access|log ?in|sign ?in|pay|use)|"
    r"locked out|losing (?:money|customers|sales)|deadline|p0|sev ?1)\b|!{2,}",
    re.I,
)
NEGATED_URGENCY = re.compile(r"\b(?:not|no|isn'?t|nothing) (?:urgent|critical|an emergency)\b|no rush|whenever", re.I)
CODE_HINT = re.compile(r"[;{}]|\b(?:def|function|class|import|return|const|let|var|public|private|select\s.+\sfrom)\b|=\s*['\"]|\(\)", re.I)
PROBE_LANGUAGES = {"python": "py", "javascript": "js", "java": "java"}


def _score(text: str) -> dict[str, float]:
    lowered = text.lower()
    return {
        label: sum(weight * len(re.findall(rf"\b(?:{pattern})\b", lowered)) for pattern, weight in signals)
        for label, signals in SIGNALS.items()
    }


def _code_findings(text: str) -> list[Finding]:
    """Run CodeGuard's rule engine over code pasted into the ticket."""
    if not CODE_HINT.search(text):
        return []
    findings: list[Finding] = []
    lines = text.splitlines() or [text]
    for language, ext in PROBE_LANGUAGES.items():
        sf = SourceFile(f"snippet.{ext}", "", language, "code", text, lines)
        findings += run_line_rules(SECURITY_RULES + QUALITY_RULES, [sf])
        findings += run_multiline_rules(MULTILINE_RULES, [sf])
        if language == "python":
            findings += python_ast_security([sf])
    for f in findings:
        f.file = "snippet"
    # prose like "TODO" or "simulated" inside a normal ticket isn't a code finding
    return [f for f in dedupe(findings) if f.category in ("security", "gap") or f.rule_id == "ai-slop-marker"]


def classify_text(text: str) -> dict:
    scores = _score(text)
    findings = _code_findings(text)
    serious_code_issue = any(f.category == "security" and f.weight >= SEVERITY_ORDER["high"] for f in findings)
    if findings:
        scores["technical"] += 3 + 2 * len(findings)

    best = max(LABELS, key=lambda label: (scores[label], -LABELS.index(label)))
    total = sum(scores.values())
    if scores[best] <= 0:
        category, confidence = "general", 0.5
    else:
        share = scores[best] / total  # how clearly one category wins
        strength = min(1.0, scores[best] / 6)  # how much evidence there is
        confidence = round(min(0.97, 0.45 + 0.3 * share + 0.22 * strength), 2)
        category = best

    urgent = (bool(URGENT.search(text)) or serious_code_issue) and not NEGATED_URGENCY.search(text)
    result = {"category": category, "urgency": "high" if urgent else "low", "confidence": confidence}
    if findings:
        result["code_findings"] = [
            {"rule": f.rule_id, "title": f.title, "severity": f.severity, "line": f.line,
             "recommendation": f.recommendation}
            for f in sorted(findings, key=lambda f: -f.weight)[:10]
        ]
    return result
