"""Scan Diff Engine — compare two scans and find what changed.

This is ScoutX's killer feature. No other recon tool does this well.
Feed it two scan directories and it tells you exactly what's new,
what disappeared, and what changed. Essential for continuous monitoring.

Usage:
    scoutx diff scan-001 scan-002
    scoutx diff latest previous
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scoutx.utils.io import read_json

logger = logging.getLogger("scoutx.reporting.diff")


@dataclass
class DiffResult:
    """The output of comparing two scans."""

    target: str
    scan_a_id: str
    scan_b_id: str

    # Subdomains
    new_subdomains: list[str] = field(default_factory=list)
    removed_subdomains: list[str] = field(default_factory=list)

    # Hosts
    new_alive: list[str] = field(default_factory=list)
    went_dead: list[str] = field(default_factory=list)
    status_changed: list[dict[str, Any]] = field(default_factory=list)
    tech_changed: list[dict[str, Any]] = field(default_factory=list)

    # Ports
    new_ports: list[dict[str, Any]] = field(default_factory=list)
    closed_ports: list[dict[str, Any]] = field(default_factory=list)

    # Endpoints
    new_endpoints: list[dict[str, Any]] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)

    # Secrets
    new_secrets: list[dict[str, Any]] = field(default_factory=list)
    resolved_secrets: list[dict[str, Any]] = field(default_factory=list)

    # SSL
    new_ssl_issues: list[dict[str, Any]] = field(default_factory=list)
    resolved_ssl_issues: list[dict[str, Any]] = field(default_factory=list)

    # JS
    new_js_files: list[str] = field(default_factory=list)
    removed_js_files: list[str] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return (
            len(self.new_subdomains) + len(self.removed_subdomains)
            + len(self.new_alive) + len(self.went_dead)
            + len(self.new_ports) + len(self.closed_ports)
            + len(self.new_endpoints) + len(self.removed_endpoints)
            + len(self.new_secrets) + len(self.resolved_secrets)
            + len(self.new_ssl_issues) + len(self.resolved_ssl_issues)
            + len(self.new_js_files) + len(self.removed_js_files)
        )

    @property
    def has_critical_changes(self) -> bool:
        """True if any new secrets or new open ports were found."""
        return bool(self.new_secrets or self.new_ports or self.new_ssl_issues)

    @property
    def change_velocity(self) -> str:
        """Qualitative assessment of how much changed."""
        t = self.total_changes
        if t == 0:
            return "static"
        elif t < 5:
            return "low"
        elif t < 20:
            return "moderate"
        elif t < 50:
            return "high"
        else:
            return "volatile"

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "target": self.target,
            "scan_a": self.scan_a_id,
            "scan_b": self.scan_b_id,
            "total_changes": self.total_changes,
            "change_velocity": self.change_velocity,
            "has_critical_changes": self.has_critical_changes,
            "new_subdomains": self.new_subdomains,
            "removed_subdomains": self.removed_subdomains,
            "new_alive": self.new_alive,
            "went_dead": self.went_dead,
            "status_changed": self.status_changed,
            "tech_changed": self.tech_changed,
            "new_ports": self.new_ports,
            "closed_ports": self.closed_ports,
            "new_endpoints": self.new_endpoints,
            "removed_endpoints": self.removed_endpoints,
            "new_secrets": self.new_secrets,
            "resolved_secrets": self.resolved_secrets,
            "new_ssl_issues": self.new_ssl_issues,
            "resolved_ssl_issues": self.resolved_ssl_issues,
            "new_js_files": self.new_js_files,
            "removed_js_files": self.removed_js_files,
        }


class ScanDiffer:
    """Compare two scan directories and produce a DiffResult."""

    def __init__(self, scan_a: Path, scan_b: Path) -> None:
        self._a = scan_a  # older scan
        self._b = scan_b  # newer scan

    def diff(self) -> DiffResult:
        """Run the full comparison."""
        state_a = read_json(self._a / "scan_state.json", {})
        state_b = read_json(self._b / "scan_state.json", {})

        result = DiffResult(
            target=state_b.get("target", state_a.get("target", "unknown")),
            scan_a_id=state_a.get("scan_id", "unknown"),
            scan_b_id=state_b.get("scan_id", "unknown"),
        )

        self._diff_subdomains(result)
        self._diff_hosts(result)
        self._diff_ports(result)
        self._diff_endpoints(result)
        self._diff_secrets(result)
        self._diff_ssl(result)
        self._diff_js(result)

        logger.info(
            "Diff complete: %d total changes (%s velocity)",
            result.total_changes, result.change_velocity,
        )
        return result

    def _diff_subdomains(self, result: DiffResult) -> None:
        """Compare subdomain lists."""
        a_data = read_json(self._a / "subdomains" / "subdomains.json", {})
        b_data = read_json(self._b / "subdomains" / "subdomains.json", {})

        subs_a = set(a_data.get("subdomains", []))
        subs_b = set(b_data.get("subdomains", []))

        result.new_subdomains = sorted(subs_b - subs_a)
        result.removed_subdomains = sorted(subs_a - subs_b)

    def _diff_hosts(self, result: DiffResult) -> None:
        """Compare alive hosts, tech stacks, and status codes."""
        a_data = read_json(self._a / "probe" / "probe.json", {})
        b_data = read_json(self._b / "probe" / "probe.json", {})

        hosts_a = {h["hostname"]: h for h in a_data.get("hosts", [])}
        hosts_b = {h["hostname"]: h for h in b_data.get("hosts", [])}

        a_alive = {h for h, d in hosts_a.items() if d.get("status_code", 0) > 0}
        b_alive = {h for h, d in hosts_b.items() if d.get("status_code", 0) > 0}

        result.new_alive = sorted(b_alive - a_alive)
        result.went_dead = sorted(a_alive - b_alive)

        # Check for status code and tech changes on hosts that exist in both
        for hostname in a_alive & b_alive:
            ha, hb = hosts_a[hostname], hosts_b[hostname]
            if ha.get("status_code") != hb.get("status_code"):
                result.status_changed.append({
                    "hostname": hostname,
                    "old_status": ha.get("status_code"),
                    "new_status": hb.get("status_code"),
                })
            old_tech = set(ha.get("technologies", []))
            new_tech = set(hb.get("technologies", []))
            if old_tech != new_tech:
                result.tech_changed.append({
                    "hostname": hostname,
                    "added": sorted(new_tech - old_tech),
                    "removed": sorted(old_tech - new_tech),
                })

    def _diff_ports(self, result: DiffResult) -> None:
        """Compare open ports."""
        a_data = read_json(self._a / "ports" / "ports.json", {})
        b_data = read_json(self._b / "ports" / "ports.json", {})

        def _port_set(data: dict) -> set[tuple[str, int]]:
            ports = set()
            for host_ports in data.get("results", {}).values():
                for entry in host_ports:
                    ports.add((entry.get("host", ""), entry.get("port", 0)))
            return ports

        def _port_entry(data: dict, host: str, port: int) -> dict:
            for host_ports in data.get("results", {}).values():
                for entry in host_ports:
                    if entry.get("host") == host and entry.get("port") == port:
                        return entry
            return {"host": host, "port": port}

        ports_a = _port_set(a_data)
        ports_b = _port_set(b_data)

        result.new_ports = [_port_entry(b_data, h, p) for h, p in sorted(ports_b - ports_a)]
        result.closed_ports = [_port_entry(a_data, h, p) for h, p in sorted(ports_a - ports_b)]

    def _diff_endpoints(self, result: DiffResult) -> None:
        """Compare discovered endpoints."""
        a_data = read_json(self._a / "endpoints" / "endpoints.json", {})
        b_data = read_json(self._b / "endpoints" / "endpoints.json", {})

        eps_a = {e.get("path", ""): e for e in a_data.get("endpoints", [])}
        eps_b = {e.get("path", ""): e for e in b_data.get("endpoints", [])}

        paths_a = set(eps_a.keys())
        paths_b = set(eps_b.keys())

        result.new_endpoints = [eps_b[p] for p in sorted(paths_b - paths_a)]
        result.removed_endpoints = sorted(paths_a - paths_b)

    def _diff_secrets(self, result: DiffResult) -> None:
        """Compare secret findings using (pattern, match_raw) as identity."""
        a_data = read_json(self._a / "secrets" / "secrets.json", {})
        b_data = read_json(self._b / "secrets" / "secrets.json", {})

        def _secret_key(s: dict) -> str:
            return f"{s.get('pattern', '')}:{s.get('match_raw', '')}"

        secs_a = {_secret_key(s): s for s in a_data.get("findings", [])}
        secs_b = {_secret_key(s): s for s in b_data.get("findings", [])}

        keys_a = set(secs_a.keys())
        keys_b = set(secs_b.keys())

        result.new_secrets = [secs_b[k] for k in sorted(keys_b - keys_a)]
        result.resolved_secrets = [secs_a[k] for k in sorted(keys_a - keys_b)]

    def _diff_ssl(self, result: DiffResult) -> None:
        """Compare SSL issues."""
        a_data = read_json(self._a / "ssl" / "ssl.json", {})
        b_data = read_json(self._b / "ssl" / "ssl.json", {})

        def _issue_key(i: dict) -> str:
            return f"{i.get('hostname', '')}:{i.get('issue', '')}"

        issues_a = {_issue_key(i): i for i in a_data.get("issues", [])}
        issues_b = {_issue_key(i): i for i in b_data.get("issues", [])}

        keys_a = set(issues_a.keys())
        keys_b = set(issues_b.keys())

        result.new_ssl_issues = [issues_b[k] for k in sorted(keys_b - keys_a)]
        result.resolved_ssl_issues = [issues_a[k] for k in sorted(keys_a - keys_b)]

    def _diff_js(self, result: DiffResult) -> None:
        """Compare JS URL lists."""
        from scoutx.utils.io import read_lines

        js_a = set(read_lines(self._a / "js" / "js_urls.txt"))
        js_b = set(read_lines(self._b / "js" / "js_urls.txt"))

        result.new_js_files = sorted(js_b - js_a)
        result.removed_js_files = sorted(js_a - js_b)


def format_diff_text(diff: DiffResult) -> str:
    """Format diff results as human-readable text for CLI output."""
    lines: list[str] = []
    lines.append(f"Scan Diff: {diff.scan_a_id} -> {diff.scan_b_id}")
    lines.append(f"Target: {diff.target}")
    lines.append(f"Total changes: {diff.total_changes} ({diff.change_velocity} velocity)")
    lines.append("")

    if diff.new_subdomains:
        lines.append(f"[+] {len(diff.new_subdomains)} NEW subdomains:")
        for s in diff.new_subdomains:
            lines.append(f"    + {s}")
        lines.append("")

    if diff.removed_subdomains:
        lines.append(f"[-] {len(diff.removed_subdomains)} REMOVED subdomains:")
        for s in diff.removed_subdomains:
            lines.append(f"    - {s}")
        lines.append("")

    if diff.new_alive:
        lines.append(f"[+] {len(diff.new_alive)} NEW alive hosts:")
        for h in diff.new_alive:
            lines.append(f"    + {h}")
        lines.append("")

    if diff.went_dead:
        lines.append(f"[-] {len(diff.went_dead)} hosts WENT DEAD:")
        for h in diff.went_dead:
            lines.append(f"    - {h}")
        lines.append("")

    if diff.status_changed:
        lines.append(f"[~] {len(diff.status_changed)} status code changes:")
        for c in diff.status_changed:
            lines.append(f"    ~ {c['hostname']}: {c['old_status']} -> {c['new_status']}")
        lines.append("")

    if diff.tech_changed:
        lines.append(f"[~] {len(diff.tech_changed)} technology changes:")
        for c in diff.tech_changed:
            if c["added"]:
                lines.append(f"    + {c['hostname']}: added {', '.join(c['added'])}")
            if c["removed"]:
                lines.append(f"    - {c['hostname']}: removed {', '.join(c['removed'])}")
        lines.append("")

    if diff.new_ports:
        lines.append(f"[+] {len(diff.new_ports)} NEW open ports:")
        for p in diff.new_ports:
            lines.append(f"    + {p.get('host', '')}:{p.get('port', '')} ({p.get('service', '')})")
        lines.append("")

    if diff.closed_ports:
        lines.append(f"[-] {len(diff.closed_ports)} CLOSED ports:")
        for p in diff.closed_ports:
            lines.append(f"    - {p.get('host', '')}:{p.get('port', '')} ({p.get('service', '')})")
        lines.append("")

    if diff.new_secrets:
        lines.append(f"[!] {len(diff.new_secrets)} NEW secrets found:")
        for s in diff.new_secrets:
            lines.append(f"    ! [{s.get('severity', 'info')}] {s.get('pattern', '')}: {s.get('match', '')}")
        lines.append("")

    if diff.resolved_secrets:
        lines.append(f"[x] {len(diff.resolved_secrets)} secrets RESOLVED:")
        for s in diff.resolved_secrets:
            lines.append(f"    x [{s.get('severity', 'info')}] {s.get('pattern', '')}")
        lines.append("")

    if diff.new_endpoints:
        lines.append(f"[+] {len(diff.new_endpoints)} NEW endpoints:")
        for e in diff.new_endpoints[:20]:
            cats = ", ".join(e.get("categories", []))
            lines.append(f"    + {e.get('path', '')} ({cats})")
        if len(diff.new_endpoints) > 20:
            lines.append(f"    ... and {len(diff.new_endpoints) - 20} more")
        lines.append("")

    if diff.new_js_files:
        lines.append(f"[+] {len(diff.new_js_files)} NEW JS files:")
        for j in diff.new_js_files[:10]:
            lines.append(f"    + {j}")
        lines.append("")

    if diff.total_changes == 0:
        lines.append("No changes detected between scans.")

    return "\n".join(lines)
