"""HTML report generator — dark-themed, self-contained, production-grade.

Generates a single HTML file with embedded CSS/JS. No external dependencies.
Uses Jinja2 for templating. The report is designed to impress clients and
look like something from a professional pentesting firm.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import BaseLoader, Environment

from scoutx.reporting.aggregator import ScanSummary

logger = logging.getLogger("scoutx.reporting.html")

# The entire template is embedded — no external file dependencies
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ScoutX Report &mdash; {{ summary.target }}</title>
<style>
:root {
  --bg-primary: #0a0a1a;
  --bg-secondary: rgba(22, 27, 34, 0.7);
  --bg-card: rgba(28, 33, 40, 0.6);
  --bg-hover: rgba(33, 38, 45, 0.8);
  --border: rgba(48, 54, 61, 0.5);
  --text-primary: #e6edf3;
  --text-secondary: #8b949e;
  --text-muted: #6e7681;
  --accent-blue: #58a6ff;
  --accent-green: #3fb950;
  --accent-orange: #d29922;
  --accent-red: #f85149;
  --accent-purple: #bc8cff;
  --accent-cyan: #39d2c0;
  --severity-critical: #f85149;
  --severity-high: #f0883e;
  --severity-medium: #d29922;
  --severity-low: #58a6ff;
  --severity-info: #8b949e;
  --radius: 12px;
  --shadow: 0 4px 15px rgba(0,0,0,0.5);
  --glass-blur: blur(10px);
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg-primary);
  background-image: radial-gradient(circle at 10% 20%, rgba(57, 210, 192, 0.05) 0%, transparent 20%),
                    radial-gradient(circle at 90% 80%, rgba(88, 166, 255, 0.05) 0%, transparent 20%);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
}
a { color: var(--accent-blue); text-decoration: none; transition: color 0.2s; }
a:hover { color: var(--accent-cyan); }

/* Header */
.header {
  background: rgba(13, 17, 23, 0.8);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border-bottom: 1px solid var(--border);
  padding: 2rem 0;
  position: sticky;
  top: 0;
  z-index: 100;
}
.header-inner {
  max-width: 1200px; margin: 0 auto; padding: 0 2rem;
  display: flex; justify-content: space-between; align-items: center;
}
.brand { display: flex; align-items: center; gap: 1rem; }
.brand-logo {
  font-size: 2rem; font-weight: 800;
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  letter-spacing: -1px;
}
.brand-sub { color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 2px; }
.header-meta { text-align: right; color: var(--text-secondary); font-size: 0.85rem; }
.header-meta .target {
  font-size: 1.2rem; color: var(--accent-cyan); font-weight: 600; text-shadow: 0 0 10px rgba(57, 210, 192, 0.3);
}

/* Container */
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

/* Stat Cards */
.stats-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem; margin-bottom: 3rem;
}
.stat-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.5rem; text-align: center;
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  box-shadow: var(--shadow);
  transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}
.stat-card:hover {
  transform: translateY(-5px);
  border-color: rgba(88, 166, 255, 0.5);
  box-shadow: 0 8px 25px rgba(88, 166, 255, 0.1);
}
.stat-value {
  font-size: 2.5rem; font-weight: 800;
  background: linear-gradient(135deg, var(--text-primary), var(--text-secondary));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  margin-bottom: 0.5rem;
}
.stat-label { color: var(--accent-cyan); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }

/* Severity badges */
.severity-grid { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 3rem; justify-content: center; }
.sev-badge {
  display: flex; align-items: center; gap: 0.5rem;
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 30px; padding: 0.5rem 1.25rem; font-size: 0.9rem; font-weight: 600;
  backdrop-filter: var(--glass-blur);
  transition: transform 0.2s;
}
.sev-badge:hover { transform: scale(1.05); }
.sev-dot { width: 12px; height: 12px; border-radius: 50%; box-shadow: 0 0 10px currentColor; }
.sev-critical { border-color: rgba(248,81,73,0.3); color: var(--text-primary); }
.sev-critical .sev-dot { background: var(--severity-critical); color: var(--severity-critical); }
.sev-high { border-color: rgba(240,136,62,0.3); color: var(--text-primary); }
.sev-high .sev-dot { background: var(--severity-high); color: var(--severity-high); }
.sev-medium { border-color: rgba(210,153,34,0.3); color: var(--text-primary); }
.sev-medium .sev-dot { background: var(--severity-medium); color: var(--severity-medium); }
.sev-low { border-color: rgba(88,166,255,0.3); color: var(--text-primary); }
.sev-low .sev-dot { background: var(--severity-low); color: var(--severity-low); }
.sev-info { border-color: rgba(139,148,158,0.3); color: var(--text-primary); }
.sev-info .sev-dot { background: var(--severity-info); color: var(--severity-info); }

/* Sections */
.section {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius); margin-bottom: 2rem; overflow: hidden;
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  box-shadow: var(--shadow);
}
.section-header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 1.25rem 2rem; border-bottom: 1px solid var(--border);
  cursor: pointer; user-select: none;
  background: rgba(255, 255, 255, 0.02);
  transition: background 0.2s;
}
.section-header:hover { background: rgba(255, 255, 255, 0.05); }
.section-title { font-size: 1.25rem; font-weight: 700; display: flex; align-items: center; gap: 0.75rem; color: var(--text-primary); }
.section-count {
  background: rgba(88, 166, 255, 0.1); border: 1px solid rgba(88, 166, 255, 0.3);
  color: var(--accent-blue);
  border-radius: 12px; padding: 0.2rem 0.75rem; font-size: 0.8rem; font-weight: 600;
}
.section-body { padding: 2rem; }
.section-body.collapsed { display: none; }
.chevron { transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1); color: var(--accent-cyan); font-size: 0.8rem; }
.section.open .chevron { transform: rotate(90deg); }

/* Tables */
table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.9rem; }
th {
  text-align: left; padding: 1rem;
  color: var(--accent-cyan); font-weight: 600; font-size: 0.8rem;
  text-transform: uppercase; letter-spacing: 1px;
  border-bottom: 1px solid var(--border);
  background: rgba(0,0,0,0.2);
}
th:first-child { border-top-left-radius: 8px; }
th:last-child { border-top-right-radius: 8px; }
td { padding: 1rem; border-bottom: 1px solid rgba(48,54,61,0.3); transition: background 0.2s; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.03); }
.mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85rem; color: var(--accent-blue); }

/* Tags */
.tag {
  display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
  font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
}
.tag-critical { background: rgba(248,81,73,0.15); color: var(--severity-critical); border: 1px solid rgba(248,81,73,0.3); }
.tag-high { background: rgba(240,136,62,0.15); color: var(--severity-high); border: 1px solid rgba(240,136,62,0.3); }
.tag-medium { background: rgba(210,153,34,0.15); color: var(--severity-medium); border: 1px solid rgba(210,153,34,0.3); }
.tag-low { background: rgba(88,166,255,0.15); color: var(--severity-low); border: 1px solid rgba(88,166,255,0.3); }
.tag-info { background: rgba(139,148,158,0.15); color: var(--severity-info); border: 1px solid rgba(139,148,158,0.3); }
.tag-tech { background: rgba(188,140,255,0.1); color: var(--accent-purple); border: 1px solid rgba(188,140,255,0.3); }
.tag-cat { background: rgba(57,210,192,0.1); color: var(--accent-cyan); border: 1px solid rgba(57,210,192,0.3); }

/* Bar chart */
.bar-chart { display: flex; flex-direction: column; gap: 0.75rem; }
.bar-row { display: flex; align-items: center; gap: 1rem; }
.bar-label { width: 150px; font-size: 0.85rem; color: var(--text-secondary); text-align: right; font-weight: 500; }
.bar-track { flex: 1; height: 28px; background: rgba(0,0,0,0.3); border-radius: 6px; overflow: hidden; border: 1px solid var(--border); box-shadow: inset 0 2px 4px rgba(0,0,0,0.5); }
.bar-fill {
  height: 100%; border-radius: 5px; display: flex; align-items: center;
  padding-left: 0.75rem; font-size: 0.8rem; font-weight: 700; min-width: 30px;
  background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan));
  color: #000;
  box-shadow: 0 0 10px rgba(57, 210, 192, 0.3);
  transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Footer */
.footer {
  text-align: center; padding: 3rem; color: var(--text-muted);
  font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 4rem;
  background: rgba(13, 17, 23, 0.5); backdrop-filter: var(--glass-blur);
}

/* Print */
@media print {
  body { background: #fff; color: #000; }
  .section, .stat-card, .header { background: #fff !important; border: 1px solid #ddd; backdrop-filter: none; box-shadow: none; color: #000; }
  .stat-value, .brand-logo { -webkit-text-fill-color: #000; background: none; }
  .section-body.collapsed { display: block !important; }
}

/* Responsive */
@media (max-width: 768px) {
  .header-inner { flex-direction: column; gap: 1rem; text-align: center; }
  .header-meta { text-align: center; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .container { padding: 1rem; }
  .bar-label { width: 100px; }
}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="brand">
      <div>
        <div class="brand-logo">ScoutX</div>
        <div class="brand-sub">Reconnaissance Report</div>
      </div>
    </div>
    <div class="header-meta">
      <div class="target">{{ summary.target }}</div>
      <div>Profile: {{ summary.profile }} | Generated: {{ generated_at }}</div>
      {% if summary.scan_id %}<div>Scan ID: {{ summary.scan_id }}</div>{% endif %}
    </div>
  </div>
</div>

<div class="container">

  <!-- Stats Overview -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-value">{{ summary.subdomain_count }}</div>
      <div class="stat-label">Subdomains</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ summary.alive_count }}</div>
      <div class="stat-label">Alive Hosts</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ summary.open_port_count }}</div>
      <div class="stat-label">Open Ports</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ summary.js_files_downloaded }}</div>
      <div class="stat-label">JS Files</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ summary.param_count }}</div>
      <div class="stat-label">Parameters</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ summary.interesting_endpoints }}</div>
      <div class="stat-label">Endpoints</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ summary.secret_count }}</div>
      <div class="stat-label">Secrets</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ "%.1f"|format(summary.duration_seconds) }}s</div>
      <div class="stat-label">Duration</div>
    </div>
  </div>

  <!-- Severity Summary -->
  {% set sev = summary.severity_summary %}
  {% if sev.critical or sev.high or sev.medium %}
  <div class="severity-grid">
    {% if sev.critical %}<div class="sev-badge sev-critical"><div class="sev-dot"></div> {{ sev.critical }} Critical</div>{% endif %}
    {% if sev.high %}<div class="sev-badge sev-high"><div class="sev-dot"></div> {{ sev.high }} High</div>{% endif %}
    {% if sev.medium %}<div class="sev-badge sev-medium"><div class="sev-dot"></div> {{ sev.medium }} Medium</div>{% endif %}
    {% if sev.low %}<div class="sev-badge sev-low"><div class="sev-dot"></div> {{ sev.low }} Low</div>{% endif %}
    {% if sev.info %}<div class="sev-badge sev-info"><div class="sev-dot"></div> {{ sev.info }} Info</div>{% endif %}
  </div>
  {% endif %}

  <!-- Secrets -->
  {% if summary.secrets %}
  <div class="section open" id="sec-secrets">
    <div class="section-header" onclick="toggleSection('sec-secrets')">
      <div class="section-title"><span class="chevron">&#9654;</span> Secrets &amp; Credentials</div>
      <div class="section-count">{{ summary.secret_count }}</div>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Severity</th><th>Pattern</th><th>Match (redacted)</th><th>Source</th><th>Line</th></tr></thead>
        <tbody>
        {% for s in summary.secrets[:100] %}
        <tr>
          <td><span class="tag tag-{{ s.severity }}">{{ s.severity }}</span></td>
          <td>{{ s.pattern }}</td>
          <td class="mono">{{ s.match }}</td>
          <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ s.source_file or '' }}</td>
          <td>{{ s.line_number or '' }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
      {% if summary.secrets|length > 100 %}<p style="color:var(--text-muted);margin-top:1.5rem;font-size:0.9rem">Showing 100 of {{ summary.secrets|length }} findings. See secrets.jsonl for full results.</p>{% endif %}
    </div>
  </div>
  {% endif %}

  <!-- SSL Issues -->
  {% if summary.ssl_issues %}
  <div class="section open" id="sec-ssl">
    <div class="section-header" onclick="toggleSection('sec-ssl')">
      <div class="section-title"><span class="chevron">&#9654;</span> SSL/TLS Issues</div>
      <div class="section-count">{{ summary.ssl_issues|length }}</div>
    </div>
    <div class="section-body">
      <table>
        <thead><tr><th>Severity</th><th>Hostname</th><th>Issue</th><th>Details</th></tr></thead>
        <tbody>
        {% for i in summary.ssl_issues %}
        <tr>
          <td><span class="tag tag-{{ i.severity or 'info' }}">{{ i.severity or 'info' }}</span></td>
          <td class="mono">{{ i.hostname }}</td>
          <td>{{ i.issue }}</td>
          <td>{{ i.get('details', '') }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- Alive Hosts -->
  {% if summary.alive_hosts %}
  <div class="section" id="sec-alive">
    <div class="section-header" onclick="toggleSection('sec-alive')">
      <div class="section-title"><span class="chevron">&#9654;</span> Alive Hosts</div>
      <div class="section-count">{{ summary.alive_count }}</div>
    </div>
    <div class="section-body collapsed">
      <table>
        <thead><tr><th>Hostname</th><th>Status</th><th>Title</th><th>Server</th><th>Technologies</th><th>WAF</th></tr></thead>
        <tbody>
        {% for h in summary.alive_hosts[:200] %}
        <tr>
          <td class="mono">{{ h.hostname }}</td>
          <td>{{ h.status_code }}</td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{{ h.title or '' }}</td>
          <td>{{ h.server or '' }}</td>
          <td>{% for t in (h.technologies or []) %}<span class="tag tag-tech">{{ t }}</span> {% endfor %}</td>
          <td>{{ h.waf or '' }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- Technology Distribution -->
  {% if summary.technologies %}
  <div class="section" id="sec-tech">
    <div class="section-header" onclick="toggleSection('sec-tech')">
      <div class="section-title"><span class="chevron">&#9654;</span> Technology Stack</div>
      <div class="section-count">{{ summary.technologies|length }}</div>
    </div>
    <div class="section-body collapsed">
      {% set max_tech = summary.technologies.values()|max if summary.technologies else 1 %}
      <div class="bar-chart">
      {% for tech, count in summary.technologies|dictsort(false, 'value', true) %}
        <div class="bar-row">
          <div class="bar-label">{{ tech }}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{{ (count / max_tech * 100)|int }}%">{{ count }}</div></div>
        </div>
      {% endfor %}
      </div>
    </div>
  </div>
  {% endif %}

  <!-- Open Ports -->
  {% if summary.open_ports %}
  <div class="section" id="sec-ports">
    <div class="section-header" onclick="toggleSection('sec-ports')">
      <div class="section-title"><span class="chevron">&#9654;</span> Open Ports</div>
      <div class="section-count">{{ summary.open_port_count }}</div>
    </div>
    <div class="section-body collapsed">
      <table>
        <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Hostnames</th></tr></thead>
        <tbody>
        {% for p in summary.open_ports[:200] %}
        <tr>
          <td class="mono">{{ p.host }}</td>
          <td>{{ p.port }}</td>
          <td><span class="tag tag-tech">{{ p.service }}</span></td>
          <td class="mono">{{ (p.hostnames or [])|join(', ') }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- Endpoints -->
  {% if summary.endpoints %}
  <div class="section" id="sec-endpoints">
    <div class="section-header" onclick="toggleSection('sec-endpoints')">
      <div class="section-title"><span class="chevron">&#9654;</span> Endpoints</div>
      <div class="section-count">{{ summary.endpoints|length }}</div>
    </div>
    <div class="section-body collapsed">
      {% if summary.endpoint_categories %}
      <div style="margin-bottom:1.5rem;display:flex;gap:0.75rem;flex-wrap:wrap">
        {% for cat, count in summary.endpoint_categories|dictsort(false, 'value', true) %}
        <span class="tag tag-cat">{{ cat }}: {{ count }}</span>
        {% endfor %}
      </div>
      {% endif %}
      <table>
        <thead><tr><th>Path</th><th>Categories</th><th>Sources</th></tr></thead>
        <tbody>
        {% for e in summary.endpoints[:150] %}
        <tr>
          <td class="mono">{{ e.path }}</td>
          <td>{% for c in (e.categories or []) %}<span class="tag tag-cat">{{ c }}</span> {% endfor %}</td>
          <td>{{ (e.sources or [])|length }} files</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- Parameters -->
  {% if summary.parameters %}
  <div class="section" id="sec-params">
    <div class="section-header" onclick="toggleSection('sec-params')">
      <div class="section-title"><span class="chevron">&#9654;</span> URL Parameters</div>
      <div class="section-count">{{ summary.param_count }}</div>
    </div>
    <div class="section-body collapsed">
      {% if summary.interesting_params %}
      <div style="margin-bottom:1.5rem; padding: 1rem; background: rgba(210,153,34,0.1); border-radius: 8px; border: 1px solid rgba(210,153,34,0.3);">
        <strong style="color:var(--accent-orange); display: block; margin-bottom: 0.5rem;">Interesting Parameters:</strong>
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
        {% for p in summary.interesting_params[:30] %}
        <span class="tag tag-medium">{{ p }}</span>
        {% endfor %}
        </div>
      </div>
      {% endif %}
      <table>
        <thead><tr><th>Parameter</th><th>Frequency</th><th>Interesting</th><th>Examples</th></tr></thead>
        <tbody>
        {% for p in summary.parameters[:100] %}
        <tr>
          <td class="mono">{{ p.name }}</td>
          <td>{{ p.frequency or '' }}</td>
          <td>{% if p.interesting %}<span class="tag tag-medium">yes</span>{% endif %}</td>
          <td class="mono" style="max-width:300px;overflow:hidden">{{ (p.examples or [])|join(', ')|truncate(80) }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  {% endif %}

  <!-- Subdomains -->
  {% if summary.subdomains %}
  <div class="section" id="sec-subs">
    <div class="section-header" onclick="toggleSection('sec-subs')">
      <div class="section-title"><span class="chevron">&#9654;</span> Subdomains</div>
      <div class="section-count">{{ summary.subdomain_count }}</div>
    </div>
    <div class="section-body collapsed">
      {% if summary.subdomain_sources %}
      <div style="margin-bottom:2rem">
        {% set max_src = summary.subdomain_sources.values()|max if summary.subdomain_sources else 1 %}
        <div class="bar-chart">
        {% for src, count in summary.subdomain_sources|dictsort(false, 'value', true) %}
          <div class="bar-row">
            <div class="bar-label">{{ src }}</div>
            <div class="bar-track"><div class="bar-fill" style="width:{{ (count / max_src * 100)|int }}%">{{ count }}</div></div>
          </div>
        {% endfor %}
        </div>
      </div>
      {% endif %}
      <div class="mono" style="max-height:400px;overflow-y:auto;font-size:0.85rem;line-height:1.8;column-count:3;column-gap:2rem; padding: 1rem; background: rgba(0,0,0,0.2); border-radius: 8px;">
        {% for sub in summary.subdomains %}{{ sub }}<br>{% endfor %}
      </div>
    </div>
  </div>
  {% endif %}

</div>

<div class="footer">
  Generated by <strong>ScoutX v0.1.0</strong> | {{ generated_at }} | Target: <span style="color:var(--accent-cyan)">{{ summary.target }}</span>
</div>

<script>
function toggleSection(id) {
  const section = document.getElementById(id);
  const body = section.querySelector('.section-body');
  section.classList.toggle('open');
  body.classList.toggle('collapsed');
}
</script>
</body>
</html>"""


class HtmlReporter:
    """Generate a self-contained HTML report from scan data."""

    def __init__(self, summary: ScanSummary) -> None:
        self._summary = summary

    def generate(self, output_path: Path) -> Path:
        """Render and write the HTML report."""
        env = Environment(loader=BaseLoader(), autoescape=True)
        # Allow .get() method on dicts in templates
        env.globals["isinstance"] = isinstance

        template = env.from_string(HTML_TEMPLATE)
        html = template.render(
            summary=self._summary,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        logger.info("HTML report written to %s", output_path)
        return output_path
