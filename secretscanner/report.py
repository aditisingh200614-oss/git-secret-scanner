"""
report.py
Turns a list of Finding objects into multiple output formats:
  1. A human-readable, color-coded console summary (for live demo/terminal/CI use)
  2. A comprehensive JSON file (for CI pipelines / programmatic consumption)
  3. A self-contained HTML dashboard with filtering and distributions (for security analysts)

Guarantees:
  Secrets themselves are strictly masked in all formats - only safe,
  fingerprinted, and length-capped previews are emitted.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

COLORS = {
    "CRITICAL": "\033[1;41m\033[97m",  # white on red
    "HIGH": "\033[1;31m",              # red
    "MEDIUM": "\033[1;33m",            # yellow
    "LOW": "\033[1;36m",               # cyan
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "GREEN": "\033[1;32m",
    "MAGENTA": "\033[1;35m",
}


def print_console_report(
    findings: list[Any],
    repo_path: str,
    baseline_suppressed: int = 0,
    commits_scanned: int | None = None,
):
    sev_counts = Counter(f.severity for f in findings)
    conf_counts = Counter(getattr(f, "confidence", "HIGH") for f in findings)
    still_live = sum(1 for f in findings if f.still_in_head)

    print()
    print(f"{COLORS['BOLD']}{'=' * 76}{COLORS['RESET']}")
    print(f"{COLORS['BOLD']} [!] GIT SECRET LEAK SCANNER - SECURITY AUDIT REPORT{COLORS['RESET']}")
    print(f"{COLORS['BOLD']}{'=' * 76}{COLORS['RESET']}")
    print(f" Repository : {repo_path}")
    print(f" Scanned at : {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    print(f" Active Findings : {len(findings)} total "
          f"({COLORS['CRITICAL']}{sev_counts.get('CRITICAL', 0)} CRITICAL{COLORS['RESET']} "
          f"{COLORS['HIGH']}{sev_counts.get('HIGH', 0)} HIGH{COLORS['RESET']} "
          f"{COLORS['MEDIUM']}{sev_counts.get('MEDIUM', 0)} MEDIUM{COLORS['RESET']} "
          f"{COLORS['LOW']}{sev_counts.get('LOW', 0)} LOW{COLORS['RESET']})")
    print(f" Confidence      : {conf_counts.get('HIGH', 0)} HIGH, "
          f"{conf_counts.get('MEDIUM', 0)} MEDIUM, "
          f"{conf_counts.get('LOW', 0)} LOW")
    if baseline_suppressed > 0:
        print(f" Baseline Filter : {baseline_suppressed} known finding(s) suppressed by baseline")
    if still_live:
        print(f" {COLORS['CRITICAL']} WARNING {COLORS['RESET']} {still_live} secret(s) are "
              f"STILL PRESENT in current HEAD - immediate rotation required.")
    print(f"{COLORS['BOLD']}{'=' * 76}{COLORS['RESET']}\n")

    if not findings:
        if baseline_suppressed > 0:
            print(f"{COLORS['GREEN']}[+] No new secrets detected (all {baseline_suppressed} known finding(s) matched baseline).{COLORS['RESET']}\n")
        else:
            print(f"{COLORS['GREEN']}[+] No secrets detected across scanned history.{COLORS['RESET']}\n")
        return

    for f in findings:
        color = COLORS.get(f.severity, "")
        conf = getattr(f, "confidence", "HIGH")
        status = f"{COLORS['CRITICAL']}[STILL IN HEAD]{COLORS['RESET']}" if f.still_in_head \
            else f"{COLORS['DIM']}[purged from HEAD, in history only]{COLORS['RESET']}"
        print(f"{color}[{f.severity}]{COLORS['RESET']} {COLORS['BOLD']}{f.rule}{COLORS['RESET']} "
              f"{COLORS['DIM']}({f.detection_method} | Confidence: {conf}){COLORS['RESET']} {status}")
        print(f"   file     : {f.file_path}:{f.line_number}")
        print(f"   commit   : {f.commit_short}  ({f.date})  by {f.author}")
        print(f"   line     : {f.redacted()}")
        if getattr(f, "context_reason", ""):
            print(f"   rationale: {f.context_reason}")
        if f.branches:
            print(f"   branches : {', '.join(f.branches)}")
        print(f"   fp       : {f.secret_fingerprint}")
        print()

    print(f"{COLORS['BOLD']}{'-' * 76}{COLORS['RESET']}")
    print(" Recommendation: rotate all active/CRITICAL credentials, then purge history\n"
          " using git-filter-repo or BFG Repo-Cleaner to eliminate forensic recovery.\n")


def write_json_report(
    findings: list[Any],
    repo_path: str,
    path: str,
    baseline_suppressed: int = 0
) -> str:
    data = {
        "repository": repo_path,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_active_findings": len(findings),
        "baseline_suppressed_count": baseline_suppressed,
        "summary_by_severity": dict(Counter(f.severity for f in findings)),
        "summary_by_confidence": dict(Counter(getattr(f, "confidence", "HIGH") for f in findings)),
        "still_in_head_count": sum(1 for f in findings if f.still_in_head),
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity,
                "confidence": getattr(f, "confidence", "HIGH"),
                "detection_method": f.detection_method,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "commit_hash": f.commit_hash,
                "commit_short": f.commit_short,
                "author": f.author,
                "date": f.date,
                "still_in_head": f.still_in_head,
                "line_preview": f.redacted(),
                "fingerprint": f.secret_fingerprint,
                "branches": f.branches,
                "key_block_lines": getattr(f, "key_block_lines", 0),
                "context_reason": getattr(f, "context_reason", ""),
            }
            for f in findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


SEVERITY_HEX = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#06b6d4",
}

CONFIDENCE_HEX = {
    "HIGH": "#10b981",
    "MEDIUM": "#3b82f6",
    "LOW": "#8b5cf6",
}


def write_html_report(
    findings: list[Any],
    repo_path: str,
    path: str,
    baseline_suppressed: int = 0
) -> str:
    sev_counts = Counter(f.severity for f in findings)
    conf_counts = Counter(getattr(f, "confidence", "HIGH") for f in findings)
    detector_counts = Counter(f.rule for f in findings)

    # Calculate branch distribution
    branch_counts = Counter()
    for f in findings:
        for b in (f.branches or ["(unspecified)"]):
            branch_counts[b] += 1

    still_live = sum(1 for f in findings if f.still_in_head)
    purged_count = len(findings) - still_live
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def esc(s):
        return html.escape(str(s), quote=True)

    # Top summary cards
    cards = f"""
    <div class="card" style="border-left-color:#38bdf8;">
      <div class="card-num">{len(findings)}</div><div class="card-label">TOTAL FINDINGS</div>
    </div>
    <div class="card" style="border-left-color:{SEVERITY_HEX['CRITICAL']};">
      <div class="card-num">{sev_counts.get('CRITICAL', 0)}</div><div class="card-label">CRITICAL</div>
    </div>
    <div class="card" style="border-left-color:{SEVERITY_HEX['HIGH']};">
      <div class="card-num">{sev_counts.get('HIGH', 0)}</div><div class="card-label">HIGH</div>
    </div>
    <div class="card" style="border-left-color:{SEVERITY_HEX['MEDIUM']};">
      <div class="card-num">{sev_counts.get('MEDIUM', 0)}</div><div class="card-label">MEDIUM</div>
    </div>
    <div class="card" style="border-left-color:{SEVERITY_HEX['LOW']};">
      <div class="card-num">{sev_counts.get('LOW', 0)}</div><div class="card-label">LOW</div>
    </div>
    <div class="card" style="border-left-color:#10b981;">
      <div class="card-num">{conf_counts.get('HIGH', 0)}</div><div class="card-label">HIGH CONFIDENCE</div>
    </div>
    <div class="card" style="border-left-color:#dc2626;">
      <div class="card-num">{still_live}</div><div class="card-label">STILL IN HEAD</div>
    </div>
    <div class="card" style="border-left-color:#6b7280;">
      <div class="card-num">{purged_count}</div><div class="card-label">HISTORICAL ONLY</div>
    </div>
    """

    # Build distribution rows
    def render_dist_bars(counter_dict, color_map=None, default_color="#3b82f6"):
        total = max(1, sum(counter_dict.values()))
        html_bars = ""
        for key, count in counter_dict.most_common(6):
            pct = round((count / total) * 100, 1)
            bar_color = color_map.get(key, default_color) if color_map else default_color
            html_bars += f"""
            <div class="dist-row">
              <span class="dist-name">{esc(key)}</span>
              <div class="dist-bar-bg">
                <div class="dist-bar-fill" style="width:{pct}%; background:{bar_color};"></div>
              </div>
              <span class="dist-count">{count} ({pct}%)</span>
            </div>"""
        return html_bars or '<p class="muted">No data</p>'

    sev_dist_html = render_dist_bars(sev_counts, SEVERITY_HEX)
    conf_dist_html = render_dist_bars(conf_counts, CONFIDENCE_HEX)
    rule_dist_html = render_dist_bars(detector_counts, default_color="#6366f1")
    branch_dist_html = render_dist_bars(branch_counts, default_color="#0ea5e9")

    rows = ""
    for f in findings:
        conf = getattr(f, "confidence", "HIGH")
        live_badge = ('<span class="badge badge-live">LIVE IN HEAD</span>' if f.still_in_head
                      else '<span class="badge badge-purged">HISTORICAL ONLY</span>')
        branches_str = ", ".join(f.branches) if f.branches else "—"
        reason_str = f'<div class="muted context-reason">{esc(f.context_reason)}</div>' if getattr(f, "context_reason", "") else ""

        rows += f"""
        <tr class="finding-row"
            data-severity="{esc(f.severity)}"
            data-confidence="{esc(conf)}"
            data-method="{esc(f.detection_method)}"
            data-live="{ 'true' if f.still_in_head else 'false' }"
            data-search="{esc(f.rule.lower())} {esc(f.file_path.lower())} {esc(f.commit_short.lower())} {esc(f.author.lower())} {esc(branches_str.lower())} {esc(f.secret_fingerprint.lower())}">
          <td>
            <span class="sev sev-{f.severity.lower()}">{esc(f.severity)}</span>
          </td>
          <td>
            <span class="conf conf-{conf.lower()}">{esc(conf)}</span>
          </td>
          <td>
            <strong>{esc(f.rule)}</strong><br>
            <span class="muted">{esc(f.detection_method)}</span>
            {reason_str}
          </td>
          <td><code>{esc(f.file_path)}:{esc(f.line_number)}</code></td>
          <td>
            <code>{esc(f.commit_short)}</code><br>
            <span class="muted">{esc(f.date)}</span><br>
            <span class="muted">{esc(f.author)}</span>
          </td>
          <td>{live_badge}</td>
          <td><code class="preview">{esc(f.redacted())}</code></td>
          <td><span class="branches-tag">{esc(branches_str)}</span></td>
          <td><code>{esc(f.secret_fingerprint)}</code></td>
        </tr>"""

    empty_state = "" if findings else '<div class="empty-state">✅ No active secrets detected across scanned repository history.</div>'
    baseline_alert = f'<div class="baseline-note">ℹ️ Baseline active: {baseline_suppressed} pre-existing finding(s) filtered from this report.</div>' if baseline_suppressed > 0 else ""

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Git Secret Leak Scan Report - {esc(repo_path)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          max-width: 1280px; margin: 30px auto; padding: 0 20px; background:#0b0f17; color:#e2e8f0; line-height: 1.5; }}
  header {{ border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
  h1 {{ font-size: 24px; margin: 0 0 6px 0; display:flex; align-items:center; gap:10px; color:#f8fafc; }}
  .meta {{ color:#94a3b8; font-size:13px; }}
  .meta code {{ background:#1e293b; padding:2px 6px; border-radius:4px; }}

  .summary-grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap:12px; margin-bottom:24px; }}
  .card {{ background:#131b26; border-left:4px solid #64748b; border-radius:8px; padding:12px 16px; }}
  .card-num {{ font-size:24px; font-weight:700; color:#f8fafc; }}
  .card-label {{ font-size:11px; font-weight:600; letter-spacing:0.5px; color:#94a3b8; margin-top:2px; }}

  .dist-grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:16px; margin-bottom:28px; }}
  .dist-box {{ background:#131b26; border:1px solid #1e293b; border-radius:8px; padding:16px; }}
  .dist-title {{ font-size:13px; font-weight:700; color:#cbd5e1; margin-bottom:12px; text-transform:uppercase; letter-spacing:0.5px; }}
  .dist-row {{ display:flex; align-items:center; gap:10px; font-size:12px; margin-bottom:8px; }}
  .dist-name {{ width:110px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; color:#94a3b8; }}
  .dist-bar-bg {{ flex:1; background:#1e293b; height:8px; border-radius:4px; overflow:hidden; }}
  .dist-bar-fill {{ height:100%; border-radius:4px; }}
  .dist-count {{ width:70px; text-align:right; font-size:11px; color:#cbd5e1; }}

  .alert-live {{ background:#450a0a; border:1px solid #dc2626; color:#fecaca; padding:14px 18px; border-radius:8px; margin-bottom:20px; font-size:14px; }}
  .baseline-note {{ background:#082f49; border:1px solid #0284c7; color:#bae6fd; padding:10px 16px; border-radius:8px; margin-bottom:20px; font-size:13px; }}

  .toolbar {{ display:flex; gap:12px; margin-bottom:16px; flex-wrap:wrap; background:#131b26; padding:14px; border-radius:8px; border:1px solid #1e293b; align-items:center; }}
  .toolbar input[type="text"] {{ flex:1; min-width:200px; background:#0b0f17; border:1px solid #334155; color:#f8fafc; padding:8px 12px; border-radius:6px; font-size:13px; }}
  .toolbar select {{ background:#0b0f17; border:1px solid #334155; color:#f8fafc; padding:8px 12px; border-radius:6px; font-size:13px; }}

  table {{ width:100%; border-collapse:collapse; font-size:13px; background:#131b26; border-radius:8px; overflow:hidden; border:1px solid #1e293b; }}
  th {{ text-align:left; padding:12px 10px; background:#0f172a; border-bottom:2px solid #1e293b; color:#94a3b8; text-transform:uppercase; font-size:11px; letter-spacing:0.5px; }}
  td {{ padding:12px 10px; border-bottom:1px solid #1e293b; vertical-align:top; }}
  tr:hover td {{ background:#172231; }}

  code {{ background:#1e293b; color:#38bdf8; padding:2px 6px; border-radius:4px; font-size:12px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
  code.preview {{ display:block; white-space:pre-wrap; word-break:break-all; max-width:320px; color:#f1f5f9; background:#0b0f17; border:1px solid #334155; }}

  .sev {{ padding:3px 8px; border-radius:4px; font-weight:700; font-size:11px; color:white; display:inline-block; }}
  .sev-critical {{ background:#dc2626; }}
  .sev-high {{ background:#ea580c; }}
  .sev-medium {{ background:#ca8a04; }}
  .sev-low {{ background:#0891b2; }}

  .conf {{ padding:2px 7px; border-radius:4px; font-weight:600; font-size:10px; color:white; display:inline-block; }}
  .conf-high {{ background:#059669; }}
  .conf-medium {{ background:#2563eb; }}
  .conf-low {{ background:#7c3aed; }}

  .badge {{ font-size:10px; padding:3px 8px; border-radius:4px; font-weight:700; }}
  .badge-live {{ background:#dc2626; color:white; }}
  .badge-purged {{ background:#334155; color:#94a3b8; }}
  .branches-tag {{ font-size:12px; color:#94a3b8; }}
  .context-reason {{ color:#94a3b8; font-size:11px; margin-top:4px; }}
  .muted {{ color:#64748b; font-size:11px; }}
  .empty-state {{ text-align:center; padding:40px; color:#4ade80; font-size:16px; background:#131b26; border-radius:8px; border:1px solid #1e293b; }}
  footer {{ margin-top:30px; color:#64748b; font-size:12px; text-align:center; padding:16px; }}
</style>
</head>
<body>
  <header>
    <h1>🛡️ Git Secret Leak Security Report</h1>
    <div class="meta">Repository: <code>{esc(repo_path)}</code> &nbsp;|&nbsp; Scanned: {esc(scanned_at)} (UTC)</div>
  </header>

  <div class="summary-grid">{cards}</div>

  {"<div class='alert-live'><strong>🚨 ACTION REQUIRED: " + str(still_live) + " secret(s) are STILL LIVE in the current HEAD.</strong> These credentials are currently exposed to anyone with clone access. Rotate them immediately before rewriting history.</div>" if still_live else ""}
  {baseline_alert}

  <div class="dist-grid">
    <div class="dist-box"><div class="dist-title">Severity Distribution</div>{sev_dist_html}</div>
    <div class="dist-box"><div class="dist-title">Confidence Distribution</div>{conf_dist_html}</div>
    <div class="dist-box"><div class="dist-title">Top Detectors</div>{rule_dist_html}</div>
    <div class="dist-box"><div class="dist-title">Branch Reachability</div>{branch_dist_html}</div>
  </div>

  <div class="toolbar">
    <input type="text" id="searchInput" placeholder="Search by rule, file, commit, author, branch, or fingerprint..." oninput="filterTable()">
    <select id="sevFilter" onchange="filterTable()">
      <option value="ALL">All Severities</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
    <select id="confFilter" onchange="filterTable()">
      <option value="ALL">All Confidence Levels</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
    <select id="liveFilter" onchange="filterTable()">
      <option value="ALL">All HEAD Statuses</option>
      <option value="true">Live in HEAD</option>
      <option value="false">Historical Only</option>
    </select>
  </div>

  {empty_state}

  <table id="findingsTable" style="{'display:none;' if not findings else ''}">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Confidence</th>
        <th>Detector & Reason</th>
        <th>File & Line</th>
        <th>Commit & Author</th>
        <th>HEAD Status</th>
        <th>Redacted Preview</th>
        <th>Branches</th>
        <th>Fingerprint</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <footer>
    Generated by <strong>git-secret-scanner</strong> &middot; Credentials are strictly masked in all reports.<br>
    Remediation workflow: 1. Rotate active credentials &rarr; 2. Rewrite Git history (<code>git filter-repo</code>) &rarr; 3. Establish baseline if necessary.
  </footer>

  <script>
    function filterTable() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const sev = document.getElementById('sevFilter').value;
      const conf = document.getElementById('confFilter').value;
      const live = document.getElementById('liveFilter').value;
      const rows = document.querySelectorAll('.finding-row');

      rows.forEach(row => {{
        const matchesSearch = !query || row.getAttribute('data-search').includes(query);
        const matchesSev = (sev === 'ALL') || (row.getAttribute('data-severity') === sev);
        const matchesConf = (conf === 'ALL') || (row.getAttribute('data-confidence') === conf);
        const matchesLive = (live === 'ALL') || (row.getAttribute('data-live') === live);

        if (matchesSearch && matchesSev && matchesConf && matchesLive) {{
          row.style.display = '';
        }} else {{
          row.style.display = 'none';
        }}
      }});
    }}
  </script>
</body>
</html>"""

    clean_html = "\n".join(line.rstrip() for line in html_doc.splitlines()) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(clean_html)
    return path
