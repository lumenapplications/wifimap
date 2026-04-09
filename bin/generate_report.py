#!/usr/bin/env python3
"""
generate_report.py  —  WiFi/MAP Security Report Generator  v5.3
================================================================
Generates a branded PDF security report from a WiFi/MAP JSON export.

Usage:
    python3 generate_report.py export.json
    python3 generate_report.py export.json --output report.pdf
    python3 generate_report.py export.json --site "Acme Corp HQ" --period "April 2026"

The JSON export comes from the dashboard's "Export JSON" button.

Dependencies:
    pip3 install weasyprint --break-system-packages
    apt-get install weasyprint   (on Raspberry Pi)

Output:
    A multi-page PDF containing:
      - Cover page with site name, period, and risk rating
      - Executive summary with key metrics
      - Device inventory table
      - Security event log
      - Zone violation summary
      - Anomaly score leaderboard
      - Recommendations based on findings
"""

import json
import sys
import argparse
import re
from pathlib import Path
from datetime import datetime


# ── Input sanitisation ────────────────────────────────────────
def esc(s) -> str:
    """HTML-escape a string for safe inclusion in report."""
    if s is None: return ''
    return (str(s)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;'))

def safe_int(v, default=0) -> int:
    try: return int(v)
    except: return default

def time_str(ts_ms) -> str:
    """Convert millisecond timestamp to readable string."""
    try: return datetime.fromtimestamp(ts_ms / 1000).strftime('%Y-%m-%d %H:%M')
    except: return '—'


# ── Risk rating ───────────────────────────────────────────────
def compute_risk(events: list, devices: dict) -> tuple:
    """
    Compute overall risk rating from event log and device anomaly scores.
    Returns (rating_str, color, score_0_to_100).
    """
    critical = sum(1 for e in events if e.get('severity') == 'critical')
    warning  = sum(1 for e in events if e.get('severity') == 'warning')
    flagged  = sum(1 for d in devices.values() if d.get('flagged'))
    max_score = max((d.get('riskScore', 0) for d in devices.values()), default=0)

    score = min(100, critical * 15 + warning * 5 + flagged * 10 + max_score * 0.3)

    if score >= 70:   return 'HIGH RISK',    '#c0392b', score
    if score >= 35:   return 'MEDIUM RISK',  '#e67e22', score
    if score >= 10:   return 'LOW RISK',     '#2980b9', score
    return 'MINIMAL RISK', '#27ae60', score


# ── Report HTML template ──────────────────────────────────────
def build_html(data: dict, site_name: str, period: str) -> str:
    floors   = data.get('floors', [])
    devices  = data.get('devices', {})
    events   = data.get('eventLog', [])
    pi_nodes = data.get('piNodes', {})

    # Aggregate readings and zones across all floors
    all_readings = [r for f in floors for r in f.get('readings', [])]
    all_zones    = [z for f in floors for z in f.get('zones', [])]
    all_aps      = [a for f in floors for a in f.get('accessPoints', [])]

    # Metrics
    total_devices = len(devices)
    online_devices = sum(1 for d in devices.values() if d.get('online'))
    flagged_devices = sum(1 for d in devices.values() if d.get('flagged'))
    critical_events = [e for e in events if e.get('severity') == 'critical']
    warning_events  = [e for e in events if e.get('severity') == 'warning']
    generated_at    = datetime.now().strftime('%Y-%m-%d %H:%M')

    risk_label, risk_color, risk_score = compute_risk(events, devices)

    # Severity badge helper
    def sev_badge(sev):
        colors = {'critical': '#e74c3c', 'warning': '#e67e22', 'info': '#3498db'}
        c = colors.get(str(sev).lower(), '#95a5a6')
        return f'<span style="background:{c};color:#fff;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600;text-transform:uppercase">{esc(sev)}</span>'

    # Device rows
    device_rows = ''
    for mac, d in sorted(devices.items(), key=lambda x: (not x[1].get('flagged'), not x[1].get('online'), x[1].get('name',''))):
        status_color = '#e74c3c' if d.get('flagged') else ('#27ae60' if d.get('online') else '#7f8c8d')
        status_text  = 'FLAGGED' if d.get('flagged') else ('Online' if d.get('online') else 'Offline')
        score        = round(d.get('riskScore', 0))
        score_color  = '#e74c3c' if score >= 60 else ('#e67e22' if score >= 30 else '#27ae60')
        device_rows += f'''
        <tr>
          <td style="font-weight:500">{esc(d.get('name', mac))}</td>
          <td style="font-family:monospace;font-size:11px;color:#555">{esc(mac)}</td>
          <td style="font-family:monospace;font-size:11px">{esc(d.get('ip','?'))}</td>
          <td style="color:{status_color};font-weight:600;font-size:11px">{esc(status_text)}</td>
          <td style="color:{score_color};font-weight:600;text-align:center">{score}</td>
          <td style="font-size:11px;color:#555">{esc(d.get('vendor','Unknown'))}</td>
        </tr>'''

    # Event rows (last 50)
    event_rows = ''
    for e in events[:50]:
        event_rows += f'''
        <tr>
          <td style="font-size:10px;color:#777;white-space:nowrap">{esc(time_str(e.get('timestamp',0)))}</td>
          <td>{sev_badge(e.get('severity','info'))}</td>
          <td style="font-weight:500">{esc(e.get('title',''))}</td>
          <td style="font-size:11px;color:#555">{esc(e.get('location','—'))}</td>
          <td style="font-size:11px;color:#555">{esc((e.get('device') or {}).get('name') or (e.get('device') or {}).get('mac') or '—')}</td>
        </tr>'''
    if not event_rows:
        event_rows = '<tr><td colspan="5" style="text-align:center;color:#aaa;padding:20px">No events recorded</td></tr>'

    # Zone rows
    zone_rows = ''
    for z in all_zones:
        zone_type  = esc(z.get('type', 'monitored'))
        zone_color = {'restricted':'#e74c3c','monitored':'#e67e22','safe':'#27ae60','perimeter':'#8e44ad'}.get(z.get('type',''), '#7f8c8d')
        schedule   = 'Always active' if z.get('schedule', {}).get('always') else f"{z.get('schedule',{}).get('hours',{}).get('start','?')}–{z.get('schedule',{}).get('hours',{}).get('end','?')}"
        zone_rows += f'''
        <tr>
          <td style="font-weight:500">{esc(z.get('name',''))}</td>
          <td style="color:{zone_color};font-weight:600;text-transform:uppercase;font-size:11px">{zone_type}</td>
          <td style="font-size:11px">{esc(z.get('alertTier','warning').upper())}</td>
          <td style="font-size:11px;color:#555">{esc(schedule)}</td>
        </tr>'''
    if not zone_rows:
        zone_rows = '<tr><td colspan="4" style="text-align:center;color:#aaa;padding:20px">No zones configured</td></tr>'

    # Anomaly leaderboard (top 10)
    anomaly_devices = sorted(
        [(mac, d) for mac, d in devices.items() if d.get('riskScore', 0) > 5],
        key=lambda x: x[1].get('riskScore', 0), reverse=True
    )[:10]
    anomaly_rows = ''
    for mac, d in anomaly_devices:
        score = round(d.get('riskScore', 0))
        bar_w = min(score, 100)
        bar_c = '#e74c3c' if score >= 60 else ('#e67e22' if score >= 30 else '#f1c40f')
        anomaly_rows += f'''
        <tr>
          <td style="font-weight:500">{esc(d.get('name', mac))}</td>
          <td style="font-family:monospace;font-size:10px;color:#888">{esc(mac)}</td>
          <td>
            <div style="background:#eee;border-radius:3px;height:8px;width:100%;min-width:80px">
              <div style="background:{bar_c};width:{bar_w}%;height:8px;border-radius:3px"></div>
            </div>
          </td>
          <td style="color:{bar_c};font-weight:700;text-align:right;width:40px">{score}</td>
        </tr>'''
    if not anomaly_rows:
        anomaly_rows = '<tr><td colspan="4" style="text-align:center;color:#aaa;padding:20px">No anomalies detected — all devices within normal parameters</td></tr>'

    # Recommendations
    recs = []
    if flagged_devices > 0:
        recs.append(('critical', f'{flagged_devices} device{"s" if flagged_devices>1 else ""} flagged with elevated anomaly scores. Review and approve known devices or investigate unknown ones.'))
    if len(critical_events) > 0:
        recs.append(('critical', f'{len(critical_events)} critical security event{"s" if len(critical_events)>1 else ""} recorded. Review each event and confirm the source is legitimate.'))
    if not all_zones:
        recs.append(('warning', 'No security zones configured. Define restricted and monitored zones to enable automatic entry/exit alerting.'))
    if len(pi_nodes) < 3:
        recs.append(('warning', f'Only {len(pi_nodes)} Pi node{"s" if len(pi_nodes)!=1 else ""} detected. Three or more nodes enable accurate trilateration for device positioning.'))
    if online_devices == 0:
        recs.append(('info', 'No devices currently online. Ensure the scanner is running and connected to the correct network segment.'))
    if not recs:
        recs.append(('info', 'No immediate recommendations. Continue monitoring and review the event log periodically.'))

    rec_html = ''
    rec_colors = {'critical': '#fdecea', 'warning': '#fff4e6', 'info': '#e8f4fd'}
    rec_border = {'critical': '#e74c3c', 'warning': '#e67e22', 'info': '#3498db'}
    for sev, text in recs:
        rec_html += f'<div style="background:{rec_colors[sev]};border-left:4px solid {rec_border[sev]};padding:10px 14px;margin-bottom:8px;border-radius:0 5px 5px 0;font-size:12px">{esc(text)}</div>'

    # Pi node summary
    node_rows = ''
    for label, n in pi_nodes.items():
        placed = '✓ Placed' if n.get('placed') else '⚠ Unplaced'
        placed_color = '#27ae60' if n.get('placed') else '#e67e22'
        node_rows += f'<tr><td style="font-family:monospace">{esc(label)}</td><td style="color:{placed_color};font-weight:500;font-size:11px">{placed}</td></tr>'
    if not node_rows:
        node_rows = '<tr><td colspan="2" style="color:#aaa;text-align:center;padding:12px">No Pi nodes recorded</td></tr>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;700&family=Space+Mono:wght@400;700&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'DM Sans', sans-serif; font-size: 13px; color: #1a1a2e; background: white; }}
  .page {{ page-break-after: always; padding: 40px 48px; min-height: 100vh; display: flex; flex-direction: column; }}
  .page:last-child {{ page-break-after: avoid; }}
  h1 {{ font-size: 28px; font-weight: 700; color: #0d3875; margin-bottom: 6px; }}
  h2 {{ font-size: 16px; font-weight: 600; color: #0d3875; margin: 28px 0 12px;
       border-bottom: 2px solid #e8f0fb; padding-bottom: 6px; }}
  h3 {{ font-size: 13px; font-weight: 600; color: #333; margin: 16px 0 8px; }}
  p  {{ line-height: 1.6; color: #444; margin-bottom: 10px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 12px; }}
  th {{ background: #0d3875; color: white; padding: 8px 10px; text-align: left; font-weight: 600; font-size: 11px; letter-spacing: .04em; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #eee; vertical-align: middle; }}
  tr:nth-child(even) td {{ background: #f8f9fb; }}
  .mono {{ font-family: 'Space Mono', monospace; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 32px; }}
  .header-brand {{ font-family: 'Space Mono', monospace; font-size: 22px; color: #0d3875; letter-spacing: .08em; }}
  .header-brand span {{ color: #aaa; }}
  .header-meta {{ text-align: right; font-size: 11px; color: #888; line-height: 1.8; }}
  .cover-center {{ flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; }}
  .cover-title {{ font-family: 'Space Mono', monospace; font-size: 42px; color: #0d3875; letter-spacing: .06em; margin-bottom: 4px; }}
  .cover-title span {{ color: #bbb; }}
  .cover-sub {{ font-size: 15px; color: #666; margin-bottom: 48px; letter-spacing: .04em; }}
  .risk-box {{ display: inline-flex; align-items: center; gap: 20px; background: #f4f7ff; border: 1px solid #dce5f7; border-radius: 10px; padding: 24px 36px; margin-bottom: 36px; }}
  .risk-score {{ font-family: 'Space Mono', monospace; font-size: 52px; font-weight: 700; line-height: 1; }}
  .risk-right {{ text-align: left; }}
  .risk-label {{ font-size: 18px; font-weight: 700; margin-bottom: 4px; }}
  .risk-subtitle {{ font-size: 12px; color: #888; }}
  .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 20px 0 32px; }}
  .metric {{ background: #f4f7ff; border-radius: 8px; padding: 16px; text-align: center; }}
  .metric-val {{ font-family: 'Space Mono', monospace; font-size: 28px; font-weight: 700; color: #0d3875; }}
  .metric-val.red {{ color: #e74c3c; }}
  .metric-val.green {{ color: #27ae60; }}
  .metric-val.orange {{ color: #e67e22; }}
  .metric-label {{ font-size: 11px; color: #888; margin-top: 4px; text-transform: uppercase; letter-spacing: .06em; }}
  .footer {{ margin-top: auto; padding-top: 20px; border-top: 1px solid #eee; display: flex; justify-content: space-between; font-size: 10px; color: #bbb; font-family: 'Space Mono', monospace; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 600; }}
  .confidential {{ background: #e8f0fb; color: #0d3875; font-family: 'Space Mono', monospace; font-size: 11px; padding: 6px 14px; border-radius: 4px; }}
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="page">
  <div class="header">
    <div class="header-brand">WIFI<span>/</span>MAP</div>
    <div class="confidential">CONFIDENTIAL</div>
  </div>
  <div class="cover-center">
    <div class="cover-title">WIFI<span>/</span>MAP</div>
    <div class="cover-sub">Network Security Report</div>
    <div class="risk-box">
      <div class="risk-score" style="color:{risk_color}">{round(risk_score)}</div>
      <div class="risk-right">
        <div class="risk-label" style="color:{risk_color}">{esc(risk_label)}</div>
        <div class="risk-subtitle">Risk score out of 100</div>
        <div class="risk-subtitle" style="margin-top:4px">{esc(period)}</div>
      </div>
    </div>
    <table style="width:420px;margin-bottom:0">
      <tr><td style="color:#888;font-size:12px;border:none;padding:5px 8px">Site</td><td style="font-weight:600;font-size:12px;border:none;padding:5px 8px">{esc(site_name)}</td></tr>
      <tr><td style="color:#888;font-size:12px;border:none;padding:5px 8px">Period</td><td style="font-weight:600;font-size:12px;border:none;padding:5px 8px">{esc(period)}</td></tr>
      <tr><td style="color:#888;font-size:12px;border:none;padding:5px 8px">Generated</td><td style="font-weight:600;font-size:12px;border:none;padding:5px 8px">{esc(generated_at)}</td></tr>
      <tr><td style="color:#888;font-size:12px;border:none;padding:5px 8px">Pi Nodes</td><td style="font-weight:600;font-size:12px;border:none;padding:5px 8px">{len(pi_nodes)}</td></tr>
      <tr><td style="color:#888;font-size:12px;border:none;padding:5px 8px">Floors Monitored</td><td style="font-weight:600;font-size:12px;border:none;padding:5px 8px">{len(floors)}</td></tr>
    </table>
  </div>
  <div class="footer">
    <span>WiFi/MAP Security Report v5.3</span>
    <span>{esc(site_name)} · {esc(period)}</span>
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="page">
  <div class="header">
    <div class="header-brand">WIFI<span>/</span>MAP</div>
    <div class="header-meta">{esc(site_name)}<br>{esc(period)}<br>Page 2</div>
  </div>
  <h1>Executive Summary</h1>
  <div class="metrics-grid">
    <div class="metric"><div class="metric-val {'red' if flagged_devices else 'green'}">{total_devices}</div><div class="metric-label">Total Devices</div></div>
    <div class="metric"><div class="metric-val green">{online_devices}</div><div class="metric-label">Online Now</div></div>
    <div class="metric"><div class="metric-val {'red' if len(critical_events) else 'green'}">{len(critical_events)}</div><div class="metric-label">Critical Events</div></div>
    <div class="metric"><div class="metric-val {'orange' if flagged_devices else 'green'}">{flagged_devices}</div><div class="metric-label">Flagged Devices</div></div>
  </div>
  <h2>Summary</h2>
  <p>This report covers network security monitoring for <strong>{esc(site_name)}</strong> during <strong>{esc(period)}</strong>.
  WiFi/MAP detected {total_devices} unique device{"s" if total_devices != 1 else ""} across {len(floors)} floor{"s" if len(floors) != 1 else ""}, 
  with {len(events)} security events recorded during the monitoring period.</p>
  {"<p>The network presents a <strong style='color:" + risk_color + "'>" + esc(risk_label) + "</strong> security posture with a score of " + str(round(risk_score)) + "/100. Immediate attention is recommended for the items highlighted in the Recommendations section.</p>" if risk_score >= 35 else "<p>The network presents a <strong style='color:" + risk_color + "'>" + esc(risk_label) + "</strong> security posture. No critical issues were detected during this period.</p>"}
  <h2>Recommendations</h2>
  {rec_html}
  <div class="footer">
    <span>WiFi/MAP Security Report v5.3 — Confidential</span>
    <span>{esc(site_name)} · {esc(period)}</span>
  </div>
</div>

<!-- DEVICE INVENTORY -->
<div class="page">
  <div class="header">
    <div class="header-brand">WIFI<span>/</span>MAP</div>
    <div class="header-meta">{esc(site_name)}<br>{esc(period)}<br>Page 3</div>
  </div>
  <h1>Device Inventory</h1>
  <p>{total_devices} devices detected · {online_devices} online · {flagged_devices} flagged</p>
  <table>
    <thead><tr><th>Name / Hostname</th><th>MAC Address</th><th>IP Address</th><th>Status</th><th>Risk</th><th>Vendor</th></tr></thead>
    <tbody>{device_rows if device_rows else '<tr><td colspan="6" style="text-align:center;color:#aaa;padding:20px">No devices recorded</td></tr>'}</tbody>
  </table>
  <h2>Pi Node Deployment</h2>
  <table style="width:300px">
    <thead><tr><th>Label</th><th>Position</th></tr></thead>
    <tbody>{node_rows}</tbody>
  </table>
  <div class="footer">
    <span>WiFi/MAP Security Report v5.3 — Confidential</span>
    <span>{esc(site_name)} · {esc(period)}</span>
  </div>
</div>

<!-- SECURITY EVENTS -->
<div class="page">
  <div class="header">
    <div class="header-brand">WIFI<span>/</span>MAP</div>
    <div class="header-meta">{esc(site_name)}<br>{esc(period)}<br>Page 4</div>
  </div>
  <h1>Security Event Log</h1>
  <p>{len(events)} events recorded · {len(critical_events)} critical · {len(warning_events)} warnings{" · showing most recent 50" if len(events) > 50 else ""}</p>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Location</th><th>Device</th></tr></thead>
    <tbody>{event_rows}</tbody>
  </table>
  <div class="footer">
    <span>WiFi/MAP Security Report v5.3 — Confidential</span>
    <span>{esc(site_name)} · {esc(period)}</span>
  </div>
</div>

<!-- ZONES + ANOMALIES -->
<div class="page">
  <div class="header">
    <div class="header-brand">WIFI<span>/</span>MAP</div>
    <div class="header-meta">{esc(site_name)}<br>{esc(period)}<br>Page 5</div>
  </div>
  <h1>Zones &amp; Anomaly Scores</h1>
  <h2>Security Zones</h2>
  <p>{len(all_zones)} zone{"s" if len(all_zones) != 1 else ""} configured across {len(floors)} floor{"s" if len(floors) != 1 else ""}.</p>
  <table>
    <thead><tr><th>Zone Name</th><th>Type</th><th>Alert Tier</th><th>Schedule</th></tr></thead>
    <tbody>{zone_rows}</tbody>
  </table>
  <h2>Device Anomaly Scores</h2>
  <p>Scores reflect cumulative anomaly signals. Devices above 60 are flagged. Scores decay over time as normal behaviour is observed.</p>
  <table>
    <thead><tr><th>Device</th><th>MAC Address</th><th>Score (0–100)</th><th></th></tr></thead>
    <tbody>{anomaly_rows}</tbody>
  </table>
  <div class="footer">
    <span>WiFi/MAP Security Report v5.3 — Confidential</span>
    <span>{esc(site_name)} · {esc(period)}</span>
  </div>
</div>

</body>
</html>'''


# ── Main ──────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description='WiFi/MAP PDF Security Report Generator v5.3')
    p.add_argument('input',          help='Path to WiFi/MAP JSON export')
    p.add_argument('--output', '-o', default=None, help='Output PDF path (default: <input>.pdf)')
    p.add_argument('--site',         default='',   help='Site name for report header')
    p.add_argument('--period',       default='',   help='Reporting period (e.g. "April 2026")')
    args = p.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f'ERROR: File not found: {input_path}', file=sys.stderr)
        sys.exit(1)

    try:
        with open(input_path) as f:
            data = json.load(f)
    except Exception as e:
        print(f'ERROR: Could not parse JSON: {e}', file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output) if args.output else input_path.with_suffix('.pdf')
    site_name   = args.site   or data.get('siteName', 'Unknown Site')
    period      = args.period or datetime.now().strftime('%B %Y')

    print(f'Generating report for: {site_name}')
    print(f'Period:    {period}')
    print(f'Devices:   {len(data.get("devices", {}))}')
    print(f'Events:    {len(data.get("eventLog", []))}')
    print(f'Floors:    {len(data.get("floors", []))}')

    html = build_html(data, site_name, period)

    try:
        from weasyprint import HTML
        HTML(string=html, base_url='.').write_pdf(str(output_path))
        print(f'Report written to: {output_path}')
    except ImportError:
        print('ERROR: weasyprint not installed.', file=sys.stderr)
        print('Install with: pip3 install weasyprint --break-system-packages', file=sys.stderr)
        print('         or: apt-get install weasyprint', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'ERROR: PDF generation failed: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
