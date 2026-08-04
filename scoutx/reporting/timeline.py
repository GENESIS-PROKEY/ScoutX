from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("scoutx.reporting.timeline")

class TimelineGenerator:
    """Generate visual timeline of attack surface changes between scans."""

    def __init__(self, scan_old: dict[str, Any], scan_new: dict[str, Any]) -> None:
        self.old = scan_old
        self.new = scan_new

    def generate_markdown(self) -> str:
        """Generate markdown timeline."""
        lines = ["# Attack Surface Timeline", ""]

        # Subdomains
        old_subs = set(self.old.get("subdomains", {}).get("subdomains", []))
        new_subs = set(self.new.get("subdomains", {}).get("subdomains", []))

        for s in sorted(new_subs - old_subs):
            lines.append(f"🟢 NEW: `{s}` appeared")
        for s in sorted(old_subs - new_subs):
            lines.append(f"🔴 GONE: `{s}` removed")

        # Ports
        def _get_ports(data: dict) -> set[tuple[str, int]]:
            res = set()
            for host_ports in data.get("ports", {}).get("results", {}).values():
                for p in host_ports:
                    res.add((p.get("host"), p.get("port")))
            return res

        old_ports = _get_ports(self.old)
        new_ports = _get_ports(self.new)

        for h, p in sorted(new_ports - old_ports):
            lines.append(f"🟡 CHANGED: `{h}` — new port {p} opened")
        for h, p in sorted(old_ports - new_ports):
            lines.append(f"🟡 CHANGED: `{h}` — port {p} closed")

        if len(lines) == 2:
            lines.append("No changes detected.")

        return "\n".join(lines)

    def generate_html(self) -> str:
        """Generate HTML timeline with CSS animation."""
        md = self.generate_markdown()
        # Very basic dark-themed HTML wrapper
        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  body { background-color: #0d1117; color: #e6edf3; font-family: monospace; padding: 2rem; }
  .timeline { border-left: 2px solid #30363d; padding-left: 1rem; }
  .event { margin-bottom: 1rem; position: relative; }
  .event:before { content: ''; width: 10px; height: 10px; background: #58a6ff; border-radius: 50%; position: absolute; left: -1.4rem; top: 0.2rem; }
</style>
</head>
<body>
<div class="timeline">
"""
        for line in md.splitlines():
            if line.startswith(("#", "No changes")):
                continue
            if line.strip():
                html += f'  <div class="event">{line}</div>\n'

        html += """</div>
</body>
</html>"""
        return html
