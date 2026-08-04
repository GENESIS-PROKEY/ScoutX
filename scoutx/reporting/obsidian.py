from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from scoutx.reporting.aggregator import ScanSummary

logger = logging.getLogger("scoutx.reporting.obsidian")


class ObsidianReporter:
    """Export scan results as Obsidian-compatible markdown vault."""

    def __init__(self, summary: ScanSummary) -> None:
        self.summary = summary

    def generate(self, output_dir: Path) -> Path:
        """Generate Obsidian vault structure."""
        vault_dir = output_dir / "obsidian"
        vault_dir.mkdir(parents=True, exist_ok=True)

        target = self.summary.target
        s = self.summary
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # 1. Target - {domain}.md (Main Note)
        main_note = vault_dir / f"Target - {target}.md"
        main_lines = [
            "---",
            "tags: [scoutx, recon, target]",
            f"date: {date_str}",
            f"target: {target}",
            "---",
            f"# Target: {target}",
            "",
            "## Scan Overview",
            f"- **Profile:** {s.profile}",
            f"- **Scan ID:** {s.scan_id}",
            f"- **Duration:** {s.duration_seconds:.1f}s",
            "",
            "## Map of Content",
            "- [[_index|Back to Index]]",
            "- [[Subdomains]]",
            "- [[Findings]]",
            "- [[Attack Chains]]",
            "",
            "## Statistics",
            f"- **Alive Hosts:** {s.alive_count}",
            f"- **Subdomains:** {s.subdomain_count}",
            f"- **Open Ports:** {s.open_port_count}",
            f"- **Endpoints:** {len(s.endpoints)}",
            f"- **Secrets:** {s.secret_count}",
        ]
        main_note.write_text("\n".join(main_lines), encoding="utf-8")

        # 2. Subdomains.md
        sub_note = vault_dir / "Subdomains.md"
        sub_lines = [
            "---",
            "tags: [scoutx, subdomains]",
            f"target: {target}",
            "---",
            "# Subdomains",
            "",
            f"Back to [[Target - {target}]]",
            "",
            "## Discovered",
            "| Subdomain | Source |",
            "|-----------|--------|"
        ]
        for sub in s.subdomains:
            sub_lines.append(f"| {sub} | scoutx |")
        sub_note.write_text("\n".join(sub_lines), encoding="utf-8")

        # 3. Findings.md
        findings_note = vault_dir / "Findings.md"
        findings_lines = [
            "---",
            "tags: [scoutx, findings]",
            f"target: {target}",
            "---",
            "# Findings",
            "",
            f"Back to [[Target - {target}]]",
            "",
        ]

        if s.secrets:
            findings_lines.extend(["## Secrets", ""])
            for sec in s.secrets:
                sev = sec.get("severity", "info").lower()
                tag = f"#{sev}"
                findings_lines.extend([
                    f"> [!warning] {tag} Secret Found: {sec.get('pattern')}",
                    f"> **Match:** `{sec.get('match')}`",
                    f"> **Source:** {sec.get('source_file')}",
                    ""
                ])

        if s.ssl_issues:
            findings_lines.extend(["## SSL Issues", ""])
            for issue in s.ssl_issues:
                sev = issue.get("severity", "info").lower()
                tag = f"#{sev}"
                findings_lines.extend([
                    f"> [!warning] {tag} SSL Issue: {issue.get('issue')}",
                    f"> **Host:** `{issue.get('hostname')}`",
                    f"> **Details:** {issue.get('details', '')}",
                    ""
                ])

        findings_note.write_text("\n".join(findings_lines), encoding="utf-8")

        # 4. Attack Chains.md
        chains_note = vault_dir / "Attack Chains.md"
        chains_lines = [
            "---",
            "tags: [scoutx, chains]",
            f"target: {target}",
            "---",
            "# Attack Chains",
            "",
            f"Back to [[Target - {target}]]",
            "",
            "No chains executed in this scan." # Placeholder for when chains are passed in summary
        ]
        chains_note.write_text("\n".join(chains_lines), encoding="utf-8")

        # 5. _index.md
        index_note = vault_dir / "_index.md"
        index_lines = [
            "---",
            "tags: [scoutx, index]",
            "---",
            "# ScoutX Map of Content",
            "",
            "## Targets",
            f"- [[Target - {target}]]"
        ]
        index_note.write_text("\n".join(index_lines), encoding="utf-8")

        logger.info(f"Obsidian vault generated at {vault_dir}")
        return vault_dir
