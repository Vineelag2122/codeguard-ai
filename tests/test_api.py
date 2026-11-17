import io
import zipfile

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture(autouse=True)
def no_llm(monkeypatch):
    for k in ("GROQ_API_KEY", "OPENAI_API_KEY", "CODEGUARD_LLM_API_KEY"):
        monkeypatch.delenv(k, raising=False)


client = TestClient(main.app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_scan_sample_and_fetch_reports():
    r = client.post("/api/scan/sample?use_ai=false")
    assert r.status_code == 200
    report = r.json()
    assert report["summary"]["total"] > 20
    rid = report["id"]
    assert client.get(f"/api/reports/{rid}").json()["id"] == rid
    html = client.get(f"/api/reports/{rid}/html")
    assert html.status_code == 200 and "CodeGuard AI" in html.text


def test_upload_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/app.py", 'password = "admin123"\n\ndef todo():\n    pass\n')
    r = client.post("/api/scan/upload", files={"file": ("demo.zip", buf.getvalue(), "application/zip")},
                    data={"use_ai": "false"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["project_name"] == "demo"
    assert {f["rule_id"] for f in body["findings"]} >= {"hardcoded-secret", "empty-function"}


def test_upload_rejects_non_zip():
    r = client.post("/api/scan/upload", files={"file": ("x.txt", b"hello", "text/plain")})
    assert r.status_code == 400


def test_github_rejects_bad_url():
    r = client.post("/api/scan/github", json={"url": "https://example.com/x/y", "use_ai": False})
    assert r.status_code == 400


# ---------------------------------------------------------------- Arena AI-triage contract
def test_arena_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


@pytest.mark.parametrize("text,category,urgency", [
    # contract examples (organizer's reference fixture)
    ("Please refund this invoice", "billing", "low"),
    ("The screen is broken", "technical", "low"),
    ("I forgot my password", "account", "low"),
    ("Urgent outage", "technical", "high"),
    ("Hello team", "general", "low"),
    # broader wording
    ("I was charged twice for my subscription this month", "billing", "high"),
    ("How do I download last month's receipt?", "billing", "low"),
    ("The app crashes every time I open settings", "technical", "low"),
    ("Production is down for all users, fix immediately!", "technical", "high"),
    ("I can't log in, it says my account is locked", "account", "high"),
    ("Please change the email address on my profile", "account", "low"),
    ("Not urgent, but the export button doesn't work", "technical", "low"),
    ("Thanks for the great support last week", "general", "low"),
    # CodeGuard layer: code pasted into a ticket
    ('Login breaks: query = "SELECT * FROM users WHERE id = " + user_id', "technical", "high"),
])
def test_classify_contract(text, category, urgency):
    r = client.post("/classify", json={"text": text})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["category"] == category
    assert body["urgency"] == urgency
    assert 0 <= body["confidence"] <= 1


@pytest.mark.parametrize("payload,status,error", [
    (b"not json", 400, "invalid_json"),
    (b'{"text": "   "}', 400, "text_required"),
    (b'{"text": 5}', 400, "text_required"),
    (b"[1, 2]", 400, "text_required"),
    (b'{"text": "' + b"a" * 17000 + b'"}', 413, "body_size"),
])
def test_classify_rejects_bad_input(payload, status, error):
    r = client.post("/classify", content=payload, headers={"Content-Type": "application/json"})
    assert r.status_code == status and r.json() == {"error": error}


def test_classify_attaches_codeguard_findings():
    r = client.post("/classify", json={"text": 'Bug in checkout: password = "admin123"'})
    body = r.json()
    assert body["urgency"] == "high"
    assert any(f["rule"] == "hardcoded-secret" for f in body["code_findings"])


@pytest.mark.parametrize("method,path", [("GET", "/nope"), ("GET", "/classify"), ("POST", "/health")])
def test_unknown_routes_return_not_found(method, path):
    r = client.request(method, path)
    assert r.status_code == 404 and r.json() == {"error": "not_found"}


def test_own_error_messages_are_kept():
    r = client.get("/api/reports/does-not-exist")
    assert r.status_code == 404 and "not found" in r.json()["detail"].lower()


def test_rate_limit_returns_429():
    main.limiter.reset()
    try:
        statuses = [client.get("/health").status_code for _ in range(305)]
        assert statuses[0] == 200 and statuses[-1] == 429
    finally:
        main.limiter.reset()
