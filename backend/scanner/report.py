"""Self-contained HTML report (no external assets, safe to email or attach)."""
from __future__ import annotations

from html import escape

SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}
CAT_LABEL = {"security": "Security", "slop": "AI slop", "gap": "Coding gap", "loose_end": "Loose end"}


def render_html(report: dict) -> str:
    s = report["summary"]
    rows = []
    for f in report["findings"]:
        fp = f.get("ai_verdict") == "false_positive"
        ai = ""
        if f.get("ai_explanation"):
            ai += f"<p class='ai'><b>AI:</b> {escape(f['ai_explanation'])}</p>"
        if f.get("ai_fix"):
            ai += f"<pre>{escape(f['ai_fix'])}</pre>"
        rows.append(f"""
<tr class="{'fp' if fp else ''}">
  <td><span class="sev" style="background:{SEV_COLOR.get(f['severity'], '#6b7280')}">{escape(f['severity'])}</span></td>
  <td>{escape(CAT_LABEL.get(f['category'], f['category']))}</td>
  <td><b>{escape(f['title'])}</b>{' <i>(AI: false positive)</i>' if fp else ''}
      <div class="loc">{escape(f['file'])}{':' + str(f['line']) if f['line'] else ''} &middot; {escape(f['source'])}{' &middot; ' + escape(f['cwe']) if f.get('cwe') else ''}</div>
      {f"<pre>{escape(f['snippet'])}</pre>" if f.get('snippet') else ''}
      <p>{escape(f['description'])}</p>{ai}</td>
  <td>{escape(f['recommendation'])}</td>
</tr>""")

    sev_cards = "".join(
        f"<div class='card'><div class='n' style='color:{SEV_COLOR[k]}'>{v}</div>{k}</div>"
        for k, v in s["by_severity"].items())
    cat_cards = "".join(
        f"<div class='card'><div class='n'>{v}</div>{CAT_LABEL[k]}</div>" for k, v in s["by_category"].items())
    langs = ", ".join(f"{l['language']} ({l['files']})" for l in report["profile"]["languages"]) or "-"
    trace = "".join(
        f"<li><b>{escape(t['phase'])}</b> &middot; {escape(t['action'])}: {escape(t['detail'])}</li>" for t in report["trace"])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeGuard AI report - {escape(report['project_name'])}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f8fafc;color:#0f172a}}
main{{max-width:1200px;margin:auto;padding:24px}}
h1{{margin:0 0 4px}} .muted{{color:#64748b}}
.grid{{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px 16px;min-width:110px;text-transform:capitalize}}
.n{{font-size:26px;font-weight:700}}
.score{{font-size:44px;font-weight:800}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0}}
th,td{{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #e2e8f0;font-size:14px}}
th{{background:#f1f5f9}} .sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;text-transform:uppercase}}
.loc{{font-family:ui-monospace,monospace;font-size:12px;color:#475569;margin:4px 0}}
pre{{background:#0f172a;color:#e2e8f0;padding:8px;border-radius:6px;white-space:pre-wrap;font-size:12px}}
.ai{{background:#ecfdf5;border-left:3px solid #10b981;padding:6px 8px}} tr.fp{{opacity:.5}}
</style></head><body><main>
<h1>CodeGuard AI &mdash; {escape(report['project_name'])}</h1>
<div class="muted">Scanned {escape(report['scanned_at'])} &middot; {s['files_scanned']} files &middot; {s['lines_scanned']} lines &middot; {langs}</div>
<div class="grid"><div class="card"><div class="score">{s['score']}</div>health score (grade {s['grade']})</div>{sev_cards}</div>
<div class="grid">{cat_cards}</div>
<h2>Summary</h2><p>{escape(report['executive_summary'])}</p>
<h2>Agent trace</h2><ol>{trace}</ol>
<h2>Findings ({len(report['findings'])})</h2>
<table><thead><tr><th>Severity</th><th>Type</th><th>Issue</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=4>No issues found.</td></tr>'}</tbody></table>
</main></body></html>"""
