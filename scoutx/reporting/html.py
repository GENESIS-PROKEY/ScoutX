"""HTML report generator — dark-themed, self-contained, production-grade.

Generates a single HTML file with embedded CSS/JS. No external dependencies.
Uses Jinja2 for templating. The report is designed to impress clients and
look like something from a professional pentesting firm.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, BaseLoader

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
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-card: #1c2128;
  --bg-hover: #21262d;
  --border: #30363d;
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
  --radius: 8px;
  --shadow: 0 2px 8px rgba(0,0,0,0.3);
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
}
a { color: var(--accent-blue); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Header */
.header {
  background: linear-gradient(135deg, #0d1117 0%, #1a1e2e 50%, #161b22 100%);
  border-bottom: 1px solid var(--border);
  padding: 2rem 0;
}
.header-inner {
  max-width: 1200px; margin: 0 auto; padding: 0 2rem;
  display: flex; justify-content: space-between; align-items: center;
}
.brand { display: flex; align-items: center; gap: 1rem; }
.brand-logo {
  font-size: 1.8rem; font-weight: 800;
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  letter-spacing: -0.5px;
}
.brand-sub { color: var(--text-muted); font-size: 0.85rem; }
.header-meta { text-align: right; color: var(--text-secondary); font-size: 0.85rem; }
.header-meta .target {
  font-size: 1.1rem; color: var(--accent-cyan); font-weight: 600;
}

/* Container */
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

/* Stat Cards */
.stats-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem; margin-bottom: 2rem;
}
.stat-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem; text-align: center;
  transition: transform 0.15s, border-color 0.15s;
}
.stat-card:hover { transform: translateY(-2px); border-color: var(--accent-blue); }
.stat-value {
  font-size: 2rem; font-weight: 700;
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.stat-label { color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 0.25rem; }

/* Severity badges */
.severity-grid { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 2rem; }
.sev-badge {
  display: flex; align-items: center; gap: 0.5rem;
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 20px; padding: 0.4rem 1rem; font-size: 0.85rem;
}
.sev-dot { width: 10px; height: 10px; border-radius: 50%; }
.sev-critical .sev-dot { background: var(--severity-critical); }
.sev-high .sev-dot { background: var(--severity-high); }
.sev-medium .sev-dot { background: var(--severity-medium); }
.sev-low .sev-dot { background: var(--severity-low); }
.sev-info .sev-dot { background: var(--severity-info); }

/* Sections */
.section {
  background: var(--bg-secondary); border: 1px solid var(--border);
  border-radius: var(--radius); margin-bottom: 1.5rem; overflow: hidden;
}
.section-header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 1rem 1.5rem; border-bottom: 1px solid var(--border);
  cursor: pointer; user-select: none;
}
.section-header:hover { background: var(--bg-hover); }
.section-title { font-size: 1.1rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
.section-count {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 12px; padding: 0.15rem 0.6rem; font-size: 0.75rem; color: var(--text-secondary);
}
.section-body { padding: 1.5rem; }
.section-body.collapsed { display: none; }
.chevron { transition: transform 0.2s; color: var(--text-muted); }
.section.open .chevron { transform: rotate(90deg); }

/* Tables */
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th {
  text-align: left; padding: 0.6rem 0.8rem;
  color: var(--text-secondary); font-weight: 600; font-size: 0.78rem;
  text-transform: uppercase; letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border);
}
td { padding: 0.6rem 0.8rem; border-bottom: 1px solid rgba(48,54,61,0.5); }
tr:hover td { background: var(--bg-hover); }
.mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.82rem; }

/* Tags */
.tag {
  display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
  font-size: 0.75rem; font-weight: 500;
}
.tag-critical { background: rgba(248,81,73,0.15); color: var(--severity-critical); border: 1px solid rgba(248,81,73,0.3); }
.tag-high { background: rgba(240,136,62,0.15); color: var(--severity-high); border: 1px solid rgba(240,136,62,0.3); }
.tag-medium { background: rgba(210,153,34,0.15); color: var(--severity-medium); border: 1px solid rgba(210,153,34,0.3); }
.tag-low { background: rgba(88,166,255,0.15); color: var(--severity-low); border: 1px solid rgba(88,166,255,0.3); }
.tag-info { background: rgba(139,148,158,0.15); color: var(--severity-info); border: 1px solid rgba(139,148,158,0.3); }
.tag-tech { background: rgba(188,140,255,0.15); color: var(--accent-purple); border: 1px solid rgba(188,140,255,0.3); }
.tag-cat { background: rgba(57,210,192,0.15); color: var(--accent-cyan); border: 1px solid rgba(57,210,192,0.3); }

/* Bar chart */
.bar-chart { display: flex; flex-direction: column; gap: 0.4rem; }
.bar-row { display: flex; align-items: center; gap: 0.75rem; }
.bar-label { width: 120px; font-size: 0.82rem; color: var(--text-secondary); text-align: right; }
.bar-track { flex: 1; height: 22px; background: var(--bg-primary); border-radius: 4px; overflow: hidden; }
.bar-fill {
  height: 100%; border-radius: 4px; display: flex; align-items: center;
  padding-left: 0.5rem; font-size: 0.72rem; font-weight: 600; min-width: 24px;
  background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan));
  transition: width 0.5s ease;
}

/* Footer */
.footer {
  text-align: center; padding: 2rem; color: var(--text-muted);
  font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 2rem;
}

/* Responsive */
@media (max-width: 768px) {
  .header-inner { flex-direction: column; gap: 1rem; text-align: center; }
  .header-meta { text-align: center; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .container { padding: 1rem; }
  .bar-label { width: 80px; }
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
      <div class="section-title"><span class="chevron">&#9654;</span> Secrets &amp; Credentials <span class="section-count">{{ summary.secret_count }}</span></div>
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
      {% if summary.secrets|length > 100 %}<p style="color:var(--text-muted);margin-top:1rem">Showing 100 of {{ summary.secrets|length }} findings. See secrets.jsonl for full results.</p>{% endif %}
    </div>
  </div>
  {% endif %}

  <!-- SSL Issues -->
  {% if summary.ssl_issues %}
  <div class="section open" id="sec-ssl">
    <div class="section-header" onclick="toggleSection('sec-ssl')">
      <div class="section-title"><span class="chevron">&#9654;</span> SSL/TLS Issues <span class="section-count">{{ summary.ssl_issues|length }}</span></div>
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
      <div class="section-title"><span class="chevron">&#9654;</span> Alive Hosts <span class="section-count">{{ summary.alive_count }}</span></div>
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
      <div class="section-title"><span class="chevron">&#9654;</span> Technology Stack <span class="section-count">{{ summary.technologies|length }}</span></div>
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
      <div class="section-title"><span class="chevron">&#9654;</span> Open Ports <span class="section-count">{{ summary.open_port_count }}</span></div>
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
      <div class="section-title"><span class="chevron">&#9654;</span> Endpoints <span class="section-count">{{ summary.endpoints|length }}</span></div>
    </div>
    <div class="section-body collapsed">
      {% if summary.endpoint_categories %}
      <div style="margin-bottom:1rem;display:flex;gap:0.5rem;flex-wrap:wrap">
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
      <div class="section-title"><span class="chevron">&#9654;</span> URL Parameters <span class="section-count">{{ summary.param_count }}</span></div>
    </div>
    <div class="section-body collapsed">
      {% if summary.interesting_params %}
      <div style="margin-bottom:1rem">
        <strong style="color:var(--accent-orange)">Interesting:</strong>
        {% for p in summary.interesting_params[:30] %}
        <span class="tag tag-medium">{{ p }}</span>
        {% endfor %}
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
      <div class="section-title"><span class="chevron">&#9654;</span> Subdomains <span class="section-count">{{ summary.subdomain_count }}</span></div>
    </div>
    <div class="section-body collapsed">
      {% if summary.subdomain_sources %}
      <div style="margin-bottom:1rem">
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
      <div class="mono" style="max-height:400px;overflow-y:auto;font-size:0.82rem;line-height:1.8;column-count:3;column-gap:2rem">
        {% for sub in summary.subdomains %}{{ sub }}<br>{% endfor %}
      </div>
    </div>
  </div>
  {% endif %}

</div>

<div class="footer">
  Generated by ScoutX v0.1.0 | {{ generated_at }} | {{ summary.target }}
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
