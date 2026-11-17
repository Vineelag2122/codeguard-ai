"""CodeGuard AI command line - scan a folder, ZIP or GitHub URL without the UI.

Examples (from the backend/ folder):
    python cli.py ../sample_code
    python cli.py https://github.com/owner/repo --html report.html
    python cli.py ./my-project --no-ai --fail-on high      # use as a CI gate
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

from scanner.agent import CodeGuardAgent  # noqa: E402
from scanner.models import SEVERITY_ORDER  # noqa: E402
from scanner.report import render_html  # noqa: E402
from workspace import WorkspaceError, clone_github, safe_extract_zip, temp_workspace  # noqa: E402

COLORS = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles choke on some AI-generated characters
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    p = argparse.ArgumentParser(description="CodeGuard AI - security, slop, gaps & loose-ends agent")
    p.add_argument("target", help="folder, .zip file, or https://github.com/owner/repo URL")
    p.add_argument("--no-ai", action="store_true", help="skip the LLM layer")
    p.add_argument("--no-tools", action="store_true", help="skip Bandit/Semgrep")
    p.add_argument("--json", metavar="FILE", help="write the JSON report to FILE")
    p.add_argument("--html", metavar="FILE", help="write the HTML report to FILE")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any finding is at/above this severity")
    p.add_argument("--limit", type=int, default=40, help="max findings printed to the terminal")
    args = p.parse_args(argv)

    agent = CodeGuardAgent(use_ai=not args.no_ai, use_external_tools=not args.no_tools)
    with temp_workspace() as ws:
        try:
            if args.target.startswith("https://"):
                root, name = clone_github(args.target, ws)
            elif args.target.lower().endswith(".zip"):
                (ws / "src").mkdir()
                root, name = safe_extract_zip(Path(args.target), ws / "src"), Path(args.target).stem
            else:
                root, name = Path(args.target).resolve(), Path(args.target).resolve().name
                if not root.is_dir():
                    p.error(f"{args.target} is not a directory")
        except WorkspaceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        report = agent.run(root, project_name=name)

    s = report["summary"]
    print(f"\nCodeGuard AI - {report['project_name']}")
    for t in report["trace"]:
        print(f"  [{t['phase']:>8}] {t['action']}: {t['detail']}")
    print(f"\nHealth score {s['score']}/100 (grade {s['grade']}) - {s['total']} findings "
          f"| {s['by_severity']['critical']} critical, {s['by_severity']['high']} high, {s['by_severity']['medium']} medium\n")
    for f in report["findings"][: args.limit]:
        if f.get("ai_verdict") == "false_positive":
            continue
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        print(f"{COLORS[f['severity']]}{f['severity'].upper():<8}{RESET} [{f['category']}] {f['title']}\n         {loc}")
    if len(report["findings"]) > args.limit:
        print(f"... and {len(report['findings']) - args.limit} more (use --html/--json for the full report)")
    print(f"\n{report['executive_summary']}\n")

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"JSON report: {args.json}")
    if args.html:
        Path(args.html).write_text(render_html(report), encoding="utf-8")
        print(f"HTML report: {args.html}")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] >= threshold and f.get("ai_verdict") != "false_positive"
               for f in report["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
