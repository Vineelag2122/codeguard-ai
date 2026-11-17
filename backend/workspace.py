"""Safely materialise a project to scan: from a ZIP upload or a public GitHub URL."""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path

MAX_UPLOAD_BYTES = int(os.getenv("CODEGUARD_MAX_UPLOAD_MB", "50")) * 1024 * 1024
MAX_UNZIPPED_BYTES = 300 * 1024 * 1024
MAX_ZIP_ENTRIES = 20_000
GITHUB_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?"
    r"(?:/tree/(?P<branch>[A-Za-z0-9_./-]+))?/?$"
)


class WorkspaceError(ValueError):
    """User-facing error (bad input)."""


def _force_remove(func, path, _exc):
    # git marks pack files read-only on Windows
    os.chmod(path, stat.S_IWRITE)
    func(path)


@contextmanager
def temp_workspace():
    path = tempfile.mkdtemp(prefix="codeguard-")
    try:
        yield Path(path)
    finally:
        shutil.rmtree(path, onerror=_force_remove)


def single_child(path: Path) -> Path:
    """If an archive wraps everything in one top-level folder, scan that folder."""
    entries = [p for p in path.iterdir() if p.name not in {"__MACOSX"}]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else path


def safe_extract_zip(zip_path: Path, dest: Path) -> Path:
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise WorkspaceError("The uploaded file is not a valid ZIP archive.") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise WorkspaceError(f"Archive has too many entries (max {MAX_ZIP_ENTRIES}).")
        if sum(i.file_size for i in infos) > MAX_UNZIPPED_BYTES:
            raise WorkspaceError("Archive is too large when extracted (zip bomb protection).")
        dest_real = os.path.realpath(dest)
        for info in infos:
            target = os.path.realpath(os.path.join(dest, info.filename))
            if target != dest_real and not target.startswith(dest_real + os.sep):
                raise WorkspaceError(f"Unsafe path in archive: {info.filename!r} (zip slip blocked).")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # skip symlinks
            zf.extract(info, dest)
    return single_child(dest)


def save_upload(fileobj, dest: Path) -> Path:
    written = 0
    with open(dest, "wb") as out:
        while chunk := fileobj.read(1024 * 1024):
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                raise WorkspaceError(f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.")
            out.write(chunk)
    return dest


def parse_github_url(url: str) -> tuple[str, str, str | None]:
    m = GITHUB_URL.match(url.strip())
    if not m:
        raise WorkspaceError("Please provide a public repository URL like https://github.com/owner/repo")
    branch = m.group("branch")
    if branch and (".." in branch or branch.startswith("-")):
        raise WorkspaceError("Invalid branch name.")
    return m.group("owner"), m.group("repo"), branch


def clone_github(url: str, dest: Path) -> tuple[Path, str]:
    owner, repo, branch = parse_github_url(url)
    target = dest / repo
    cmd = ["git", "-c", "core.symlinks=false", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", f"https://github.com/{owner}/{repo}.git", str(target)]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "echo"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)
    except FileNotFoundError as exc:
        raise WorkspaceError("git is not installed on the server.") from exc
    except subprocess.TimeoutExpired as exc:
        raise WorkspaceError("Cloning took too long (repository too large?).") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip().splitlines()[-1][:200] if proc.stderr.strip() else ""
        raise WorkspaceError(f"Could not clone repository. Is it public and does the branch exist? {detail}".strip())
    return target, f"{owner}/{repo}" + (f"@{branch}" if branch else "")
