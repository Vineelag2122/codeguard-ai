"""File discovery and project profiling.

This is the layer that makes the agent architecture-agnostic: it does not
care whether the project is a monolith, microservices, a monorepo, a CLI or a
frontend. It just walks the tree, classifies every file by language/kind and
builds a profile of the stack so later stages can pick the right checks.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

LANGUAGE_BY_EXT = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".dart": "dart",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".sql": "sql", ".html": "html", ".vue": "vue", ".svelte": "svelte",
}
CONFIG_BY_EXT = {
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
    ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".properties": "properties",
    ".xml": "xml", ".tf": "terraform", ".env": "dotenv",
}
CONFIG_BY_NAME = {"Dockerfile": "docker", "docker-compose.yml": "yaml", "Makefile": "make"}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "venv", ".venv",
    "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "dist",
    "build", "out", "target", ".next", ".nuxt", ".svelte-kit", "coverage", ".idea",
    ".vscode", ".gradle", "bin", "obj", ".terraform", "site-packages",
}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
              "composer.lock", "Gemfile.lock", "go.sum"}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".bundle.js")

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 5_000

TEST_PATTERN = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|testing)/|(^|/)test_[^/]+\.py$|_test\.(py|go)$|"
    r"\.(test|spec)\.[jt]sx?$|Tests?\.(java|kt|cs)$",
    re.IGNORECASE,
)

# manifest file -> [(substring in manifest, framework label)]
FRAMEWORK_MARKERS = {
    "requirements.txt": [("django", "Django"), ("flask", "Flask"), ("fastapi", "FastAPI"),
                         ("streamlit", "Streamlit"), ("langchain", "LangChain"), ("torch", "PyTorch")],
    "pyproject.toml": [("django", "Django"), ("flask", "Flask"), ("fastapi", "FastAPI")],
    "package.json": [('"react"', "React"), ('"next"', "Next.js"), ('"express"', "Express"),
                     ('"vue"', "Vue"), ('"@angular/core"', "Angular"), ('"svelte"', "Svelte"),
                     ('"@nestjs/core"', "NestJS"), ('"electron"', "Electron"), ('"react-native"', "React Native")],
    "pom.xml": [("spring-boot", "Spring Boot"), ("quarkus", "Quarkus")],
    "build.gradle": [("spring-boot", "Spring Boot"), ("android", "Android")],
    "build.gradle.kts": [("spring-boot", "Spring Boot"), ("android", "Android")],
    "go.mod": [("gin-gonic", "Gin"), ("labstack/echo", "Echo"), ("gofiber", "Fiber")],
    "Gemfile": [("rails", "Rails"), ("sinatra", "Sinatra")],
    "composer.json": [("laravel", "Laravel"), ("symfony", "Symfony")],
    "Cargo.toml": [("actix", "Actix"), ("axum", "Axum"), ("rocket", "Rocket")],
    "pubspec.yaml": [("flutter", "Flutter")],
}


@dataclass
class SourceFile:
    path: str  # relative, posix style
    abs_path: str
    language: str
    kind: str  # "code" | "config"
    text: str
    lines: list[str] = field(default_factory=list)

    @property
    def is_test(self) -> bool:
        return is_test_path(self.path)

    def line(self, n: int) -> str:
        return self.lines[n - 1] if 0 < n <= len(self.lines) else ""

    def context(self, n: int, radius: int = 3) -> str:
        start, end = max(1, n - radius), min(len(self.lines), n + radius)
        return "\n".join(f"{i:>5} | {self.lines[i - 1]}" for i in range(start, end + 1))


def is_test_path(path: str) -> bool:
    return bool(TEST_PATTERN.search(path))


def classify(path: Path) -> tuple[str, str] | None:
    name = path.name
    if name == ".env" or name.startswith(".env."):
        return "dotenv", "config"
    if name in CONFIG_BY_NAME:
        return CONFIG_BY_NAME[name], "config"
    ext = path.suffix.lower()
    if ext in LANGUAGE_BY_EXT:
        return LANGUAGE_BY_EXT[ext], "code"
    if ext in CONFIG_BY_EXT:
        return CONFIG_BY_EXT[ext], "config"
    if name in {"requirements.txt", "requirements-dev.txt"} or (name.startswith("requirements") and ext == ".txt"):
        return "requirements", "config"
    return None


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:2048]:  # binary
        return None
    return raw.decode("utf-8", errors="replace")


def discover_files(root: str | Path) -> tuple[list[SourceFile], dict]:
    """Walk the project and return scannable files plus discovery stats."""
    root = Path(root)
    files: list[SourceFile] = []
    skipped = Counter()
    all_names: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            all_names.append(rel)
            if p.is_symlink():
                skipped["symlink"] += 1
                continue
            if name in SKIP_FILES or name.endswith(SKIP_SUFFIXES):
                skipped["generated/lockfile"] += 1
                continue
            kind = classify(p)
            if kind is None:
                skipped["unsupported type"] += 1
                continue
            if len(files) >= MAX_FILES:
                skipped["file limit reached"] += 1
                continue
            text = _read_text(p)
            if text is None:
                skipped["binary or too large"] += 1
                continue
            language, k = kind
            files.append(SourceFile(rel, str(p), language, k, text, text.splitlines()))

    return files, {"skipped": dict(skipped), "all_paths": all_names}


def profile_project(root: str | Path, files: list[SourceFile], all_paths: list[str]) -> dict:
    """Build a technology profile - the agent uses it to plan which checks to run."""
    root = Path(root)
    code = [f for f in files if f.kind == "code"]
    lang_files = Counter(f.language for f in code)
    lang_lines = Counter()
    for f in code:
        lang_lines[f.language] += len(f.lines)

    frameworks: set[str] = set()
    manifests: list[str] = []
    for f in files:
        name = Path(f.path).name
        markers = FRAMEWORK_MARKERS.get(name)
        if markers is None:
            continue
        manifests.append(f.path)
        lower = f.text.lower()
        for needle, label in markers:
            if needle.lower() in lower:
                frameworks.add(label)
        if name == "package.json":
            try:
                pkg = json.loads(f.text)
                deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
            except (ValueError, AttributeError, TypeError):
                deps = {}  # malformed package.json: framework detection just falls back to substrings
            if "typescript" in deps:
                frameworks.add("TypeScript")

    test_files = [p for p in all_paths if is_test_path(p) and classify(Path(p)) and classify(Path(p))[1] == "code"]
    tops = {p.split("/")[0] for p in manifests if "/" in p}
    if len(manifests) > 2 and len(tops) > 1:
        shape = "multi-module / monorepo"
    elif any(l in lang_files for l in ("javascript", "typescript")) and any(
        l in lang_files for l in ("python", "java", "go", "ruby", "php", "csharp", "kotlin")
    ):
        shape = "full-stack (frontend + backend)"
    elif code:
        shape = "single-module"
    else:
        shape = "no source code detected"

    root_names = {p for p in all_paths if "/" not in p}
    return {
        "languages": [
            {"language": lang, "files": n, "lines": lang_lines[lang]} for lang, n in lang_files.most_common()
        ],
        "frameworks": sorted(frameworks),
        "manifests": manifests,
        "architecture": shape,
        "test_files": len(test_files),
        "has_readme": any(n.lower().startswith("readme") for n in root_names),
        "has_gitignore": ".gitignore" in root_names,
        "total_files": len(files),
        "code_files": len(code),
        "total_lines": sum(len(f.lines) for f in code),
    }
