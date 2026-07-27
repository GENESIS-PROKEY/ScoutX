"""Scan aggregator — reads all plugin output and builds a unified scan summary.

This is the data layer for reports. Every reporter consumes the same
aggregated structure, so adding a new output format is trivial.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scoutx.utils.io import read_json, read_jsonl, read_lines

logger = logging.getLogger("scoutx.reporting.aggregator")


@dataclass
class ScanSummary:
    """Unified scan summary consumed by all reporters."""

    target: str
    scan_dir: Path
    scan_id: str = ""
    profile: str = "balanced"

    # Subdomains
    subdomains: list[str] = field(default_factory=list)
    subdomain_count: int = 0
    subdomain_sources: dict[str, int] = field(default_factory=dict)
    resolved_count: int = 0

    # Probe / Alive hosts
    alive_hosts: list[dict[str, Any]] = field(default_factory=list)
    alive_count: int = 0
    dead_count: int = 0
    technologies: dict[str, int] = field(default_factory=dict)  # tech -> count
    waf_detected: dict[str, int] = field(default_factory=dict)
    status_codes: dict[int, int] = field(default_factory=dict)

    # Ports
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    open_port_count: int = 0
    port_services: dict[str, int] = field(default_factory=dict)

    # SSL
    certificates: list[dict[str, Any]] = field(default_factory=list)
    ssl_issues: list[dict[str, Any]] = field(default_factory=list)

    # JS
    js_urls: list[str] = field(default_factory=list)
    js_files_downloaded: int = 0
    js_total_size_kb: float = 0

    # Parameters
    parameters: list[dict[str, Any]] = field(default_factory=list)
    interesting_params: list[str] = field(default_factory=list)
    param_count: int = 0

    # Endpoints
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    endpoint_categories: dict[str, int] = field(default_factory=dict)
    interesting_endpoints: int = 0

    # Secrets
    secrets: list[dict[str, Any]] = field(default_factory=list)
    secrets_by_severity: dict[str, int] = field(default_factory=dict)
    secret_count: int = 0

    # Meta
    scan_state: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0

    @property
    def total_findings(self) -> int:
        return self.secret_count + self.open_port_count + len(self.ssl_issues) + self.interesting_endpoints

    @property
    def severity_summary(self) -> dict[str, int]:
        """Overall severity breakdown across all finding types."""
        s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        # Secrets
        for k, v in self.secrets_by_severity.items():
            s[k] = s.get(k, 0) + v
        # SSL issues
        for issue in self.ssl_issues:
            sev = issue.get("severity", "info")
            s[sev] = s.get(sev, 0) + 1
        # Ports are info-level
        s["info"] += self.open_port_count
        return s


class ScanAggregator:
    """Reads all plugin output files and builds a ScanSummary."""

    def __init__(self, scan_dir: Path, target: str) -> None:
        self._scan_dir = scan_dir
        self._target = target

    def aggregate(self) -> ScanSummary:
        """Read all output directories and build the summary."""
        summary = ScanSummary(target=self._target, scan_dir=self._scan_dir)

        # Scan state
        state_data = read_json(self._scan_dir / "scan_state.json", {})
        summary.scan_state = state_data
        summary.scan_id = state_data.get("scan_id", "")
        summary.profile = state_data.get("profile", "balanced")

        durations = state_data.get("module_durations", {})
        summary.duration_seconds = sum(durations.values()) if durations else 0

        # Subdomains
        sub_dir = self._scan_dir / "subdomains"
        sub_json = read_json(sub_dir / "subdomains.json", {})
        summary.subdomains = sub_json.get("subdomains", [])
        summary.subdomain_count = sub_json.get("total", len(summary.subdomains))
        summary.subdomain_sources = sub_json.get("sources", {})
        summary.resolved_count = sub_json.get("resolved", 0)

        # Probe
        probe_dir = self._scan_dir / "probe"
        probe_json = read_json(probe_dir / "probe.json", {})
        summary.alive_hosts = probe_json.get("hosts", [])
        summary.alive_count = probe_json.get("alive", 0)
        summary.dead_count = probe_json.get("dead", 0)

        # Aggregate tech + WAF + status codes
        for host in summary.alive_hosts:
            for tech in host.get("technologies", []):
                summary.technologies[tech] = summary.technologies.get(tech, 0) + 1
            waf = host.get("waf", "")
            if waf:
                summary.waf_detected[waf] = summary.waf_detected.get(waf, 0) + 1
            sc = host.get("status_code", 0)
            if sc:
                summary.status_codes[sc] = summary.status_codes.get(sc, 0) + 1

        # Ports
        port_dir = self._scan_dir / "ports"
        port_json = read_json(port_dir / "ports.json", {})
        port_results = port_json.get("results", {})
        for host_ports in port_results.values():
            for entry in host_ports:
                summary.open_ports.append(entry)
                svc = entry.get("service", "unknown")
                summary.port_services[svc] = summary.port_services.get(svc, 0) + 1
        summary.open_port_count = port_json.get("total_open", len(summary.open_ports))

        # SSL
        ssl_dir = self._scan_dir / "ssl"
        ssl_json = read_json(ssl_dir / "ssl.json", {})
        summary.certificates = ssl_json.get("certificates", [])
        summary.ssl_issues = ssl_json.get("issues", [])

        # JS
        js_dir = self._scan_dir / "js"
        js_json = read_json(js_dir / "js_files.json", {})
        summary.js_urls = read_lines(js_dir / "js_urls.txt") if (js_dir / "js_urls.txt").exists() else []
        summary.js_files_downloaded = js_json.get("downloaded", 0)
        files = js_json.get("files", [])
        summary.js_total_size_kb = sum(f.get("size", 0) for f in files) / 1024

        # Parameters
        param_dir = self._scan_dir / "parameters"
        param_json = read_json(param_dir / "parameters.json", {})
        summary.parameters = read_jsonl(param_dir / "parameters.jsonl")
        summary.interesting_params = param_json.get("interesting_params", [])
        summary.param_count = param_json.get("total_params", len(summary.parameters))

        # Endpoints
        ep_dir = self._scan_dir / "endpoints"
        ep_json = read_json(ep_dir / "endpoints.json", {})
        summary.endpoints = ep_json.get("endpoints", [])
        summary.endpoint_categories = ep_json.get("by_category", {})
        summary.interesting_endpoints = ep_json.get("interesting", 0)

        # Secrets
        sec_dir = self._scan_dir / "secrets"
        sec_json = read_json(sec_dir / "secrets.json", {})
        summary.secrets = sec_json.get("findings", [])
        summary.secrets_by_severity = sec_json.get("by_severity", {})
        summary.secret_count = sec_json.get("total", len(summary.secrets))

        logger.info(
            "Aggregated scan for %s: %d subdomains, %d alive, %d ports, %d secrets",
            self._target, summary.subdomain_count, summary.alive_count,
            summary.open_port_count, summary.secret_count,
        )

        return summary
