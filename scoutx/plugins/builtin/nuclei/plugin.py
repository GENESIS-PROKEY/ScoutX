"""Nuclei Wrapper Plugin — automated vulnerability scanning via ProjectDiscovery's Nuclei.

Wraps the nuclei binary to run template-based vulnerability scans against
discovered hosts. Uses intelligence data to select relevant templates
(e.g., WordPress templates if WordPress detected). Skips gracefully if
nuclei isn't installed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.nuclei")

# Map detected technologies to nuclei template tags
TECH_TAG_MAP = {
    "wordpress": ["wordpress", "wp-plugin"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis"],
    "tomcat": ["tomcat"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "confluence": ["confluence"],
    "jira": ["jira", "atlassian"],
    "grafana": ["grafana"],
    "kibana": ["kibana"],
    "elasticsearch": ["elasticsearch"],
    "php": ["php"],
    "laravel": ["laravel"],
    "spring": ["springboot"],
    "express": ["express", "nodejs"],
    "react": [],  # No specific nuclei tags
    "angular": [],
}

# Rate limits per scan profile
PROFILE_RATE_LIMITS = {
    "safe": 10,
    "balanced": 50,
    "aggressive": 150,
}


class Plugin(ScoutPlugin):
    """Nuclei vulnerability scanner — template-based with smart selection."""

    meta = PluginMeta(
        name="nuclei",
        description="Automated vulnerability scanning via Nuclei templates",
        version="0.1.0",
        author="ScoutX",
        tags=["vuln", "active", "nuclei", "scanning"],
    )
    depends_on: list[str] = ["probe"]
    concurrent_with: list[str] = []

    async def run(self, context: ScanContext) -> PluginResult:
        """Execute nuclei against discovered hosts."""
        from scoutx.cli.ui import info, success, warn

        # Check if nuclei is installed
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            warn("Nuclei binary not found on PATH")
            info("Install from: https://github.com/projectdiscovery/nuclei")
            return PluginResult.skipped(
                "Nuclei binary not found on PATH. "
                "Install from https://github.com/projectdiscovery/nuclei"
            )

        output_dir = context.output_dir / "nuclei"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Gather targets from probe data
        probe_data = context.result_data("probe")
        hosts = probe_data.get("hosts", [])
        if not hosts:
            return PluginResult.skipped("No hosts from probe to scan")

        # Build target list (alive URLs only)
        targets = []
        for host in hosts:
            if isinstance(host, dict):
                url = host.get("url", "")
                if url:
                    targets.append(url)
            elif isinstance(host, str):
                targets.append(host)

        if not targets:
            return PluginResult.skipped("No alive URLs to scan")

        info(f"Scanning {len(targets)} targets with Nuclei...")

        # Write targets to temp file
        targets_file = output_dir / "targets.txt"
        targets_file.write_text("\n".join(targets), encoding="utf-8")

        # Smart template selection based on intelligence data
        extra_tags = self._get_smart_tags(context)
        profile = context.profile or "balanced"
        rate_limit = PROFILE_RATE_LIMITS.get(profile, 50)
        timeout = int(context.config.get("timeouts.nuclei", 300))

        # Build nuclei command
        nuclei_output = output_dir / "nuclei_results.jsonl"
        cmd = [
            nuclei_path,
            "-l", str(targets_file),
            "-severity", "low,medium,high,critical",
            "-jsonl",
            "-o", str(nuclei_output),
            "-silent",
            "-rate-limit", str(rate_limit),
            "-timeout", str(min(timeout, 30)),
            "-no-color",
            "-no-update-check",
        ]

        # Add smart tags if detected technologies suggest specific templates
        if extra_tags:
            cmd.extend(["-tags", ",".join(extra_tags)])
            info(f"Smart template selection: {', '.join(extra_tags)}")

        # Run nuclei subprocess
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(output_dir),
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            if process.returncode not in (0, 1):
                # returncode 1 = findings found (normal)
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                if err_msg:
                    logger.warning("Nuclei stderr: %s", err_msg[:500])

        except asyncio.TimeoutError:
            warn(f"Nuclei timed out after {timeout}s")
            if process:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            return PluginResult(
                status="timeout",
                reason=f"Nuclei timed out after {timeout} seconds",
            )
        except Exception as exc:
            return PluginResult.failed(f"Nuclei execution error: {exc}")

        # Parse results
        findings = self._parse_results(nuclei_output)
        severity_counts = self._count_severities(findings)

        # Save structured results
        result_data = {
            "targets_scanned": len(targets),
            "findings": findings,
            "findings_count": len(findings),
            "severity_breakdown": severity_counts,
            "tags_used": extra_tags,
            "profile": profile,
            "rate_limit": rate_limit,
        }
        write_json(output_dir / "nuclei.json", result_data)

        if findings:
            success(
                f"Found {len(findings)} vulnerabilities "
                f"(C:{severity_counts.get('critical', 0)} "
                f"H:{severity_counts.get('high', 0)} "
                f"M:{severity_counts.get('medium', 0)} "
                f"L:{severity_counts.get('low', 0)})"
            )
        else:
            info("No vulnerabilities found")

        return PluginResult.completed(
            data=result_data,
            findings_count=len(findings),
            artifacts=[nuclei_output, output_dir / "nuclei.json"],
        )

    def _get_smart_tags(self, context: Any) -> list[str]:
        """Derive nuclei template tags from intelligence tech stack data."""
        tags: set[str] = set()

        intel_data = context.result_data("intelligence")
        tech_intel = intel_data.get("tech_intelligence", {})
        detected_tech = tech_intel.get("detected_technologies", [])

        if isinstance(detected_tech, list):
            for tech in detected_tech:
                tech_lower = tech.lower() if isinstance(tech, str) else ""
                for tech_key, tag_list in TECH_TAG_MAP.items():
                    if tech_key in tech_lower:
                        tags.update(tag_list)

        # Also check probe data for tech fingerprints
        probe_data = context.result_data("probe")
        for host in probe_data.get("hosts", []):
            if isinstance(host, dict):
                tech = host.get("technologies", [])
                server = host.get("server", "")
                if isinstance(server, str):
                    for tech_key, tag_list in TECH_TAG_MAP.items():
                        if tech_key in server.lower():
                            tags.update(tag_list)

        return sorted(tags) if tags else []

    def _parse_results(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse nuclei JSONL output into structured findings."""
        findings: list[dict[str, Any]] = []

        if not output_file.exists():
            return findings

        try:
            for line in output_file.read_text(encoding="utf-8").strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    finding = {
                        "template_id": record.get("template-id", "unknown"),
                        "template_name": record.get("info", {}).get("name", ""),
                        "severity": record.get("info", {}).get("severity", "unknown"),
                        "host": record.get("host", ""),
                        "matched_at": record.get("matched-at", ""),
                        "type": record.get("type", ""),
                        "description": record.get("info", {}).get("description", ""),
                        "reference": record.get("info", {}).get("reference", []),
                        "tags": record.get("info", {}).get("tags", []),
                        "curl_command": record.get("curl-command", ""),
                        "extracted_results": record.get("extracted-results", []),
                        "matcher_name": record.get("matcher-name", ""),
                    }
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
        except Exception as exc:
            logger.warning("Error parsing nuclei output: %s", exc)

        return findings

    def _count_severities(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        """Count findings by severity level."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0,
        }
        for f in findings:
            sev = f.get("severity", "unknown").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["unknown"] += 1
        return counts

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={
                "targets_scanned": int,
                "findings": list,
                "findings_count": int,
                "severity_breakdown": dict,
            },
            description="Nuclei vulnerability scan results with severity breakdown",
        )
