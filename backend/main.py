"""CodeGuard AI - FastAPI backend.

Run:  uvicorn main:app --reload --port 8000   (from the backend/ folder)
"""
from __future__ import annotations

import os
from collections import OrderedDict
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

from fastapi import FastAPI, File, Form, HTTPException, UploadFile  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import HTMLResponse, Response  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from scanner.agent import CodeGuardAgent  # noqa: E402
from scanner.ai_analyzer import AIAnalyzer  # noqa: E402
from scanner.report import render_html  # noqa: E402
from workspace import WorkspaceError, clone_github, safe_extract_zip, save_upload, temp_workspace  # noqa: E402

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_code"
MAX_REPORTS = 50

app = FastAPI(title="CodeGuard AI", version="1.0.0",
              description="Architecture-agnostic agent for security issues, AI slop, coding gaps and loose ends.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("CODEGUARD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

REPORTS: "OrderedDict[str, dict]" = OrderedDict()


def _store(report: dict) -> dict:
    REPORTS[report["id"]] = report
    while len(REPORTS) > MAX_REPORTS:
        REPORTS.popitem(last=False)
    return report


def _scan(root: Path, name: str, use_ai: bool) -> dict:
    return _store(CodeGuardAgent(use_ai=use_ai).run(root, project_name=name))


class GithubRequest(BaseModel):
    url: str
    use_ai: bool = True


@app.get("/api/health")
def health():
    return {"status": "ok", "ai": AIAnalyzer().info(), "sample_available": SAMPLE_DIR.is_dir()}


# Endpoints are sync `def` on purpose: FastAPI runs them in a worker thread,
# so long scans never block the event loop.
@app.post("/api/scan/upload")
def scan_upload(file: UploadFile = File(...), use_ai: bool = Form(True)):
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Please upload a .zip archive of your project.")
    with temp_workspace() as ws:
        try:
            archive = save_upload(file.file, ws / "upload.zip")
            (ws / "src").mkdir()
            root = safe_extract_zip(archive, ws / "src")
        except WorkspaceError as exc:
            raise HTTPException(400, str(exc)) from exc
        name = Path(file.filename).stem if root.name == "src" else root.name
        return _scan(root, name, use_ai)


@app.post("/api/scan/github")
def scan_github(req: GithubRequest):
    with temp_workspace() as ws:
        try:
            root, name = clone_github(req.url, ws)
        except WorkspaceError as exc:
            raise HTTPException(400, str(exc)) from exc
        return _scan(root, name, req.use_ai)


@app.post("/api/scan/sample")
def scan_sample(use_ai: bool = True):
    if not SAMPLE_DIR.is_dir():
        raise HTTPException(404, "sample_code folder not found")
    return _scan(SAMPLE_DIR, "sample_code (demo)", use_ai)


@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    if report_id not in REPORTS:
        raise HTTPException(404, "Report not found (reports are kept in memory).")
    return REPORTS[report_id]


@app.get("/api/reports/{report_id}/html", response_class=HTMLResponse)
def get_report_html(report_id: str, download: bool = False):
    report = get_report(report_id)
    headers = {"Content-Disposition": f'attachment; filename="codeguard-{report_id}.html"'} if download else {}
    return HTMLResponse(render_html(report), headers=headers)


@app.get("/api/reports/{report_id}/json")
def download_report_json(report_id: str):
    import json
    report = get_report(report_id)
    return Response(json.dumps(report, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="codeguard-{report_id}.json"'})
