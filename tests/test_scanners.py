"""Behavioural tests for the scanning agent (no network / LLM needed)."""
import io
import zipfile
from pathlib import Path

import pytest

from scanner.agent import CodeGuardAgent
from scanner.ai_analyzer import AIAnalyzer
from workspace import WorkspaceError, parse_github_url, safe_extract_zip

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample_code"


class NoAI(AIAnalyzer):
    def __init__(self):
        super().__init__()
        self.api_key = ""


def scan(path, tools=False):
    return CodeGuardAgent(use_ai=False, use_external_tools=tools, ai=NoAI()).run(path)


def write(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return tmp_path


def hits(report, rule_id, file=None):
    return [f for f in report["findings"] if f["rule_id"] == rule_id and (file is None or f["file"] == file)]


@pytest.fixture(scope="module")
def sample_report():
    return scan(SAMPLE)


@pytest.mark.parametrize("rule_id,file", [
    ("hardcoded-secret", "payment_service.py"),
    ("aws-access-key", "payment_service.py"),
    ("db-url-credentials", "payment_service.py"),
    ("sql-injection", "payment_service.py"),
    ("command-injection", "payment_service.py"),
    ("insecure-deserialization", "payment_service.py"),
    ("weak-hash", "payment_service.py"),
    ("tls-verification-disabled", "payment_service.py"),
    ("code-injection", "payment_service.py"),
    ("debug-enabled", "payment_service.py"),
    ("empty-function", "payment_service.py"),
    ("not-implemented", "payment_service.py"),
    ("swallowed-exception", "payment_service.py"),
    ("mutable-default", "payment_service.py"),
    ("missing-timeout", "payment_service.py"),
    ("duplicate-code", "payment_service.py"),
    ("unused-import", "payment_service.py"),
    ("todo-comment", "payment_service.py"),
    ("in-real-app", "payment_service.py"),
    ("ai-slop-marker", "payment_service.py"),
    ("sensitive-logging", "payment_service.py"),
    ("sql-injection", "server.js"),
    ("path-traversal", "server.js"),
    ("command-injection", "server.js"),
    ("hardcoded-secret", "server.js"),
    ("cors-wildcard", "server.js"),
    ("insecure-random", "server.js"),
    ("empty-catch", "server.js"),
    ("empty-function", "server.js"),
    ("not-implemented", "server.js"),
    ("debug-leftover", "server.js"),
    ("sql-injection", "UserRepository.java"),
    ("hardcoded-secret", "UserRepository.java"),
    ("weak-hash", "UserRepository.java"),
    ("empty-catch", "UserRepository.java"),
    ("empty-function", "UserRepository.java"),
    ("not-implemented", "UserRepository.java"),
    ("xss", "Dashboard.tsx"),
    ("simulated-logic", "Dashboard.tsx"),
    ("ai-slop-marker", "Dashboard.tsx"),
    ("suppressed-checks", "Dashboard.tsx"),
    ("typescript-any", "Dashboard.tsx"),
    ("hardcoded-secret-config", "config.yaml"),
    ("env-file-committed", ".env"),
    ("unpinned-dependencies", "requirements.txt"),
    ("no-tests", "(project)"),
])
def test_sample_findings(sample_report, rule_id, file):
    assert hits(sample_report, rule_id, file), f"expected {rule_id} in {file}"


def test_report_shape(sample_report):
    s = sample_report["summary"]
    assert s["total"] == len(sample_report["findings"])
    assert 0 <= s["score"] <= 100 and s["grade"] in "ABCDF"
    assert s["by_severity"]["critical"] >= 3
    assert {l["language"] for l in sample_report["profile"]["languages"]} >= {"python", "javascript", "java", "typescript"}
    assert [t["phase"] for t in sample_report["trace"]][:2] == ["perceive", "perceive"]
    # most severe first
    order = ["critical", "high", "medium", "low", "info"]
    sevs = [order.index(f["severity"]) for f in sample_report["findings"]]
    assert sevs == sorted(sevs)


def test_placeholder_secrets_not_flagged(tmp_path):
    write(tmp_path, "settings.py", "\n".join([
        'import os',
        'password = os.environ["DB_PASSWORD"]',
        'API_KEY = "<your-api-key>"',
        'secret = "${SECRET}"',
        'password_field = "password"',
        'token_label = "Enter your token"',
    ]))
    write(tmp_path, "app.yaml", "api_key: ${API_KEY}\npassword: changeme_example\n")
    report = scan(tmp_path)
    assert not [f for f in report["findings"] if f["rule_id"].startswith("hardcoded-secret")]


def test_safe_code_is_clean(tmp_path):
    write(tmp_path, "db.py", '''
import sqlite3


def get_user(conn: sqlite3.Connection, user_id: int):
    """Parameterised query - safe."""
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
''')
    report = scan(tmp_path)
    security = [f for f in report["findings"] if f["category"] == "security"]
    assert security == []


def test_abstract_methods_are_not_empty_functions(tmp_path):
    write(tmp_path, "base.py", '''
from abc import ABC, abstractmethod


class Repo(ABC):
    @abstractmethod
    def save(self, item):
        ...
''')
    assert not hits(scan(tmp_path), "empty-function")


def test_inline_suppression(tmp_path):
    write(tmp_path, "x.py", 'password = "admin123"  # codeguard: ignore\n')
    assert not hits(scan(tmp_path), "hardcoded-secret")


def test_secrets_in_tests_are_downgraded(tmp_path):
    write(tmp_path, "tests/test_login.py", 'password = "admin123"\n')
    f = hits(scan(tmp_path), "hardcoded-secret")
    assert f and f[0]["severity"] == "medium"


def test_syntax_error_reported(tmp_path):
    write(tmp_path, "broken.py", "def f(:\n    return 1\n")
    assert hits(scan(tmp_path), "syntax-error")


def test_go_and_rust_supported(tmp_path):
    write(tmp_path, "main.go", 'package main\n\nfunc handler() {}\n\nfunc load() {\n\tif err != nil {\n\t}\n}\n')
    write(tmp_path, "lib.rs", 'fn parse() -> u8 {\n    todo!()\n}\n')
    report = scan(tmp_path)
    assert hits(report, "empty-function", "main.go")
    assert hits(report, "go-ignored-error", "main.go")
    assert hits(report, "not-implemented", "lib.rs")


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_zip_slip_blocked(tmp_path):
    z = tmp_path / "evil.zip"
    z.write_bytes(_zip({"../../evil.py": "print('pwned')"}))
    (tmp_path / "out").mkdir()
    with pytest.raises(WorkspaceError):
        safe_extract_zip(z, tmp_path / "out")


def test_zip_single_folder_is_unwrapped(tmp_path):
    z = tmp_path / "proj.zip"
    z.write_bytes(_zip({"myproj/app.py": "x = 1\n", "myproj/README.md": "hi"}))
    (tmp_path / "out").mkdir()
    root = safe_extract_zip(z, tmp_path / "out")
    assert root.name == "myproj"


@pytest.mark.parametrize("url,ok", [
    ("https://github.com/pallets/flask", True),
    ("https://github.com/pallets/flask.git", True),
    ("https://github.com/pallets/flask/tree/main", True),
    ("http://github.com/pallets/flask", False),
    ("https://evil.com/pallets/flask", False),
    ("https://github.com/pallets/flask; rm -rf /", False),
    ("https://github.com/a/b/tree/--upload-pack=x", False),
])
def test_github_url_validation(url, ok):
    if ok:
        assert parse_github_url(url)
    else:
        with pytest.raises(WorkspaceError):
            parse_github_url(url)


class JunkAI(AIAnalyzer):
    """Simulates a flaky LLM that returns malformed payloads or raises."""

    def __init__(self, mode):
        super().__init__()
        self.api_key = "test"
        self.mode = mode

    def _chat_json(self, system, user, max_tokens=2500):
        if self.mode == "raise":
            raise RuntimeError("provider exploded")
        return {"results": ["oops", 1, None], "issues": ["bad", {"line": "x"}], "summary": 42}


@pytest.mark.parametrize("mode", ["junk", "raise"])
def test_bad_ai_responses_never_break_a_scan(mode):
    report = CodeGuardAgent(use_ai=True, use_external_tools=False, ai=JunkAI(mode)).run(SAMPLE)
    assert report["summary"]["total"] > 20
    assert report["executive_summary"]  # falls back to the rule-based summary
