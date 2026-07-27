"""Markdown report generator — clean, readable, Git-friendly.

Outputs a structured Markdown report perfect for pasting into Notion,
Obsidian, GitHub issues, or any markdown viewer.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from scoutx.reporting.aggregator import ScanSummary

logger = logging.getLogger("scoutx.reporting.markdown")


class MarkdownReporter:
    """Generate a clean Markdown report from scan data."""

    def __init__(self, summary: ScanSummary) -> None:
        self._s = summary

    def generate(self, output_path: Path) -> Path:
        """Render and write the Markdown report."""
        lines: list[str] = []
        s = self._s

        # Header
        lines.append(f"# ScoutX Reconnaissance Report")
        lines.append(f"")
        lines.append(f"**Target:** `{s.target}`")
        lines.append(f"**Profile:** {s.profile}")
        lines.append(f"**Scan ID:** `{s.scan_id}`")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Duration:** {s.duration_seconds:.1f}s")
        lines.append("")

        # Overview table
        lines.append("## Overview")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Subdomains | {s.subdomain_count} |")
        lines.append(f"| Alive Hosts | {s.alive_count} |")
        lines.append(f"| Open Ports | {s.open_port_count} |")
        lines.append(f"| JS Files | {s.js_files_downloaded} |")
        lines.append(f"| Parameters | {s.param_count} |")
        lines.append(f"| Endpoints | {len(s.endpoints)} ({s.interesting_endpoints} interesting) |")
        lines.append(f"| Secrets | {s.secret_count} |")
        lines.append(f"| SSL Issues | {len(s.ssl_issues)} |")
        lines.append("")

        # Severity summary
        sev = s.severity_summary
        if any(sev.values()):
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for level in ("critical", "high", "medium", "low", "info"):
                if sev.get(level, 0) > 0:
                    lines.append(f"| {level.upper()} | {sev[level]} |")
            lines.append("")

        # Secrets
        if s.secrets:
            lines.append("## Secrets & Credentials")
            lines.append("")
            lines.append("| Severity | Pattern | Match (redacted) | Source | Line |")
            lines.append("|----------|---------|------------------|--------|------|")
            for sec in s.secrets[:50]:
                lines.append(
                    f"| {sec.get('severity', 'info')} | {sec.get('pattern', '')} | "
                    f"`{sec.get('match', '')}` | {sec.get('source_file', '')} | {sec.get('line_number', '')} |"
                )
            if len(s.secrets) > 50:
                lines.append(f"\n*Showing 50 of {len(s.secrets)}. See `secrets.jsonl` for full results.*")
            lines.append("")

        # SSL Issues
        if s.ssl_issues:
            lines.append("## SSL/TLS Issues")
            lines.append("")
            lines.append("| Severity | Hostname | Issue | Details |")
            lines.append("|----------|----------|-------|---------|")
            for issue in s.ssl_issues:
                lines.append(
                    f"| {issue.get('severity', 'info')} | `{issue.get('hostname', '')}` | "
                    f"{issue.get('issue', '')} | {issue.get('details', '')} |"
                )
            lines.append("")

        # Alive Hosts
        if s.alive_hosts:
            lines.append("## Alive Hosts")
            lines.append("")
            lines.append("| Hostname | Status | Title | Server | Tech | WAF |")
            lines.append("|----------|--------|-------|--------|------|-----|")
            for h in s.alive_hosts[:100]:
                tech = ", ".join(h.get("technologies", []))
                lines.append(
                    f"| `{h.get('hostname', '')}` | {h.get('status_code', '')} | "
                    f"{(h.get('title', '') or '')[:40]} | {h.get('server', '')} | {tech} | {h.get('waf', '')} |"
                )
            if len(s.alive_hosts) > 100:
                lines.append(f"\n*Showing 100 of {len(s.alive_hosts)}. See `probe.jsonl` for full results.*")
            lines.append("")

        # Technology Distribution
        if s.technologies:
            lines.append("### Technology Stack")
            lines.append("")
            for tech, count in sorted(s.technologies.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- **{tech}**: {count} hosts")
            lines.append("")

        # Open Ports
        if s.open_ports:
            lines.append("## Open Ports")
            lines.append("")
            lines.append("| Host | Port | Service | Hostnames |")
            lines.append("|------|------|---------|-----------|")
            for p in s.open_ports[:100]:
                hostnames = ", ".join(p.get("hostnames", []))
                lines.append(f"| `{p.get('host', '')}` | {p.get('port', '')} | {p.get('service', '')} | {hostnames} |")
            lines.append("")

        # Interesting Endpoints
        if s.endpoints:
            interesting = [e for e in s.endpoints if e.get("interesting")]
            if interesting:
                lines.append("## Interesting Endpoints")
                lines.append("")
                if s.endpoint_categories:
                    cats = ", ".join(f"**{k}**: {v}" for k, v in sorted(s.endpoint_categories.items(), key=lambda x: x[1], reverse=True))
                    lines.append(f"Categories: {cats}")
                    lines.append("")
                lines.append("| Path | Categories |")
                lines.append("|------|------------|")
                for e in interesting[:75]:
                    cats = ", ".join(e.get("categories", []))
                    lines.append(f"| `{e.get('path', '')}` | {cats} |")
                lines.append("")

        # Interesting Parameters
        if s.interesting_params:
            lines.append("## Interesting Parameters")
            lines.append("")
            lines.append("Parameters flagged for potential injection/IDOR/redirect testing:")
            lines.append("")
            for p in s.interesting_params[:30]:
                lines.append(f"- `{p}`")
            lines.append("")

        # Subdomains
        if s.subdomains:
            lines.append("## Subdomains")
            lines.append("")
            if s.subdomain_sources:
                lines.append("### Sources")
                lines.append("")
                for src, count in sorted(s.subdomain_sources.items(), key=lambda x: x[1], reverse=True):
                    lines.append(f"- **{src}**: {count}")
                lines.append("")
            lines.append("<details>")
            lines.append(f"<summary>All {s.subdomain_count} subdomains</summary>")
            lines.append("")
            lines.append("```")
            for sub in s.subdomains:
                lines.append(sub)
            lines.append("```")
            lines.append("</details>")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Generated by ScoutX v0.1.0*")

        content = "\n".join(lines)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        logger.info("Markdown report written to %s", output_path)
        return output_path
