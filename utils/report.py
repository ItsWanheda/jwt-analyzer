# utils/report.py
import json
import html
from datetime import datetime
from pathlib import Path
from typing import Dict


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>JWT Security Analysis Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         margin: 40px; background: #f5f5f5; }}
  .container {{ max-width: 1200px; margin: 0 auto; background: white;
               padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
  h2 {{ color: #34495e; margin-top: 30px; }}
  .critical {{ background: #e74c3c; color: white; padding: 4px 12px; border-radius: 4px; }}
  .high {{ background: #e67e22; color: white; padding: 4px 12px; border-radius: 4px; }}
  .medium {{ background: #f39c12; color: white; padding: 4px 12px; border-radius: 4px; }}
  .low {{ background: #3498db; color: white; padding: 4px 12px; border-radius: 4px; }}
  .ok {{ background: #27ae60; color: white; padding: 4px 12px; border-radius: 4px; }}
  pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px;
        overflow-x: auto; font-size: 13px; }}
  .metadata {{ background: #ecf0f1; padding: 15px; border-radius: 4px;
              margin-bottom: 20px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
  th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
  th {{ background: #34495e; color: white; }}
  .summary-card {{ display: inline-block; padding: 20px; margin: 10px;
                  background: #ecf0f1; border-radius: 8px; min-width: 150px;
                  text-align: center; }}
  .summary-card .number {{ font-size: 36px; font-weight: bold; color: #2c3e50; }}
</style>
</head>
<body>
<div class="container">
<h1>🔐 JWT Security Analysis Report</h1>
<div class="metadata">
  <strong>Generated:</strong> {timestamp}<br>
  <strong>Tool:</strong> JWT Analyzer v1.1<br>
  <strong>Analyst:</strong> {analyst}
</div>

<div>
  <div class="summary-card">
    <div class="number">{critical_count}</div>
    <div>Critical</div>
  </div>
  <div class="summary-card">
    <div class="number">{high_count}</div>
    <div>High</div>
  </div>
  <div class="summary-card">
    <div class="number">{medium_count}</div>
    <div>Medium</div>
  </div>
  <div class="summary-card">
    <div class="number">{low_count}</div>
    <div>Low</div>
  </div>
</div>

<h2>📋 Token Information</h2>
<pre>{token_info}</pre>

<h2>🔍 Security Findings</h2>
{findings_html}

<h2>💡 Recommendations</h2>
{recommendations_html}

<h2>📊 Payload Analysis</h2>
<pre>{payload_json}</pre>

</div>
</body>
</html>
"""


def generate_html_report(analysis_data: Dict, output_path: str,
                         analyst: str = "Security Team") -> str:
    """Generate a professional HTML security report."""
    
    findings = analysis_data.get('findings', [])
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    low = sum(1 for f in findings if f.get('severity') == 'LOW')
    
    findings_html = _render_findings(findings)
    recommendations = _generate_recommendations(findings)
    
    html_content = HTML_TEMPLATE.format(
        timestamp=datetime.utcnow().isoformat() + 'Z',
        analyst=html.escape(analyst),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        token_info=html.escape(json.dumps(analysis_data.get('token_info', {}), indent=2)),
        findings_html=findings_html,
        recommendations_html=recommendations,
        payload_json=html.escape(json.dumps(analysis_data.get('payload', {}), indent=2))
    )
    
    Path(output_path).write_text(html_content)
    return output_path


def _render_findings(findings: list) -> str:
    if not findings:
        return '<p class="ok">✅ No security issues found</p>'
    
    rows = []
    for finding in findings:
        severity = finding.get('severity', 'INFO').lower()
        rows.append(f"""
        <tr>
          <td><span class="{severity}">{finding.get('severity', 'INFO')}</span></td>
          <td>{html.escape(finding.get('title', ''))}</td>
          <td>{html.escape(finding.get('description', ''))}</td>
          <td>{html.escape(finding.get('remediation', ''))}</td>
        </tr>
        """)
    
    return f"""
    <table>
      <tr><th>Severity</th><th>Finding</th><th>Description</th><th>Remediation</th></tr>
      {''.join(rows)}
    </table>
    """


def _generate_recommendations(findings: list) -> str:
    """Generate remediation recommendations based on findings."""
    recs = []
    
    if any(f.get('type') == 'none_algorithm' for f in findings):
        recs.append("🔴 Reject tokens with 'none' algorithm. Enforce explicit algorithm allowlist.")
    
    if any(f.get('type') == 'weak_secret' for f in findings):
        recs.append("🔴 Use cryptographically random secrets ≥256 bits. Rotate immediately.")
    
    if any(f.get('type') == 'no_expiry' for f in findings):
        recs.append("🟠 Always set 'exp' claim. Use short-lived tokens (15-60 min) with refresh tokens.")
    
    if any(f.get('type') == 'sensitive_data' for f in findings):
        recs.append("🟠 JWTs are SIGNED, not ENCRYPTED. Remove PII. Use opaque tokens for sensitive data.")
    
    if not recs:
        recs.append("✅ No critical issues. Continue monitoring and regular audits.")
    
    return '<ul>' + ''.join(f'<li>{r}</li>' for r in recs) + '</ul>'