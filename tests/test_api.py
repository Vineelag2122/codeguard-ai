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
