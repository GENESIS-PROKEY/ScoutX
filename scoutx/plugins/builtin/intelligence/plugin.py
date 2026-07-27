"""Intelligence Engine Plugin — attack surface analysis and risk scoring.

Consumes ALL prior scan results to produce actionable intelligence:
risk scores per host, technology attack vectors, prioritized target queue,
and campaign suggestions. This is the final analysis layer.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.intelligence")

# Port risk scores — sensitive services
PORT_RISK: dict[int, tuple[int, str]] = {
    21: (15, "FTP - plaintext auth"),
    22: (5, "SSH - remote access"),
    23: (20, "Telnet - plaintext remote access"),
    25: (10, "SMTP - mail relay"),
    53: (5, "DNS"),
    110: (10, "POP3 - plaintext mail"),
    135: (15, "MSRPC - Windows RPC"),
    139: (15, "NetBIOS"),
    143: (10, "IMAP - plaintext mail"),
    389: (15, "LDAP"),
    445: (20, "SMB - file sharing"),
    1433: (20, "MSSQL"),
    1521: (20, "Oracle DB"),
    2049: (15, "NFS"),
    3306: (20, "MySQL"),
    3389: (15, "RDP - remote desktop"),
    5432: (20, "PostgreSQL"),
    5900: (15, "VNC"),
    5984: (15, "CouchDB"),
    6379: (20, "Redis"),
    8080: (5, "HTTP alt"),
    8443: (5, "HTTPS alt"),
    9200: (15, "Elasticsearch"),
    11211: (15, "Memcached"),
    27017: (20, "MongoDB"),
}

# Technology >> known attack vectors
TECH_ATTACK_MAP: dict[str, dict[str, Any]] = {
    "django": {
        "attack_vectors": [
            "Debug page exposure (/debug/)",
            "Admin panel (/admin/)",
            "ALLOWED_HOSTS bypass",
            "Secret key extraction",
        ],
        "cve_categories": ["RCE", "Auth Bypass", "SSRF"],
        "nuclei_tags": ["django", "python"],
    },
    "wordpress": {
        "attack_vectors": [
            "XML-RPC amplification (/xmlrpc.php)",
            "Login brute-force (/wp-login.php)",
            "Plugin vulnerability scan",
            "User enumeration (/wp-json/wp/v2/users)",
            "Config backup (/wp-config.php.bak)",
        ],
        "cve_categories": ["Plugin RCE", "SQLi", "XSS", "Auth Bypass"],
        "nuclei_tags": ["wordpress", "wp-plugin"],
    },
    "next.js": {
        "attack_vectors": [
            "_next/data exposure",
            "API route enumeration (/api/)",
            "Source map disclosure (/_next/static/)",
            "Server-side prop leaks",
        ],
        "cve_categories": ["SSRF", "Info Disclosure"],
        "nuclei_tags": ["nextjs", "javascript"],
    },
    "react": {
        "attack_vectors": [
            "Source map disclosure (*.js.map)",
            "Client-side routing bypass",
            "Exposed environment variables",
        ],
        "cve_categories": ["Info Disclosure", "XSS"],
        "nuclei_tags": ["react", "javascript"],
    },
    "nginx": {
        "attack_vectors": [
            "Path traversal via alias misconfiguration",
            "Off-by-slash redirect",
            "Status page exposure (/nginx_status)",
        ],
        "cve_categories": ["Path Traversal", "Info Disclosure"],
        "nuclei_tags": ["nginx"],
    },
    "apache": {
        "attack_vectors": [
            "Server-status exposure (/server-status)",
            "Server-info exposure (/server-info)",
            ".htaccess misconfiguration",
            "mod_proxy SSRF",
        ],
        "cve_categories": ["Path Traversal", "SSRF", "Info Disclosure"],
        "nuclei_tags": ["apache"],
    },
    "php": {
        "attack_vectors": [
            "PHPInfo exposure (/phpinfo.php)",
            "Debug/test files",
            "Type juggling",
            "Deserialization",
        ],
        "cve_categories": ["RCE", "SQLi", "File Inclusion"],
        "nuclei_tags": ["php"],
    },
    "iis": {
        "attack_vectors": [
            "Short filename disclosure",
            "Trace.axd exposure",
            "Web.config disclosure",
        ],
        "cve_categories": ["Info Disclosure", "Auth Bypass"],
        "nuclei_tags": ["iis", "microsoft"],
    },
    "vercel": {
        "attack_vectors": [
            "Function source exposure",
            "Environment variable leaks",
            "_vercel/insights data",
        ],
        "cve_categories": ["Info Disclosure"],
        "nuclei_tags": ["vercel"],
    },
    "flask": {
        "attack_vectors": [
            "Debug console (/console)",
            "Werkzeug debugger PIN bypass",
            "SSTI in Jinja2 templates",
        ],
        "cve_categories": ["RCE", "SSTI"],
        "nuclei_tags": ["flask", "python"],
    },
    "express": {
        "attack_vectors": [
            "Stack trace disclosure",
            "Default error handler info leak",
            "Prototype pollution",
        ],
        "cve_categories": ["Info Disclosure", "Prototype Pollution"],
        "nuclei_tags": ["express", "nodejs"],
    },
    "laravel": {
        "attack_vectors": [
            "Debug mode (/telescope)",
            "Environment file (/.env)",
            "Log viewer (/log-viewer)",
        ],
        "cve_categories": ["RCE", "Info Disclosure"],
        "nuclei_tags": ["laravel", "php"],
    },
}

# Endpoint category risk weights
ENDPOINT_RISK: dict[str, int] = {
    "api": 3,
    "admin": 8,
    "auth": 5,
    "config": 7,
    "upload": 6,
    "debug": 10,
    "data": 4,
    "internal": 8,
    "backup": 7,
}


class Plugin(ScoutPlugin):
    """Aggregate scan results into actionable intelligence."""

    meta = PluginMeta(
        name="intelligence",
        description="Attack surface analysis, risk scoring, and prioritized target queue",
        version="0.1.0",
        author="ScoutX",
        tags=["intelligence", "analysis", "risk", "strategy"],
    )
    depends_on: list[str] = ["probe", "ports", "endpoints", "secrets", "ssl_analysis"]
    concurrent_with: list[str] = []  # Runs alone after everything

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success, warn

        output_dir = context.output_dir / "intelligence"
        output_dir.mkdir(parents=True, exist_ok=True)

        info("Building intelligence report...")

        # Gather all prior results
        probe_data = context.result_data("probe")
        ports_data = context.result_data("ports")
        endpoints_data = context.result_data("endpoints")
        secrets_data = context.result_data("secrets")
        ssl_data = context.result_data("ssl_analysis")
        takeover_data = context.result_data("takeover")
        cors_data = context.result_data("cors")

        # Build host list
        hosts = _get_hosts(probe_data)
        if not hosts:
            return PluginResult.skipped("No hosts to analyze")

        # 1. Risk scoring per host
        host_scores = _score_hosts(hosts, ports_data, endpoints_data, secrets_data, ssl_data)

        # 2. Technology intelligence
        tech_intel = _build_tech_intelligence(hosts)

        # 3. Attack surface summary
        attack_surface = _build_attack_surface(
            hosts, ports_data, endpoints_data, secrets_data, ssl_data,
            takeover_data, cors_data,
        )

        # 4. Priority queue
        priority_queue = _build_priority_queue(host_scores, endpoints_data, secrets_data)

        # 5. Campaign suggestions
        campaigns = _suggest_campaigns(
            endpoints_data, secrets_data, tech_intel,
            takeover_data, cors_data, hosts,
        )

        # Overall risk
        if host_scores:
            overall_score = round(sum(h["score"] for h in host_scores) / len(host_scores))
        else:
            overall_score = 0

        risk_level = (
            "critical" if overall_score >= 70
            else "high" if overall_score >= 50
            else "medium" if overall_score >= 25
            else "low"
        )

        data = {
            "target": context.target,
            "scan_id": context.scan_id,
            "overall_risk_score": overall_score,
            "risk_level": risk_level,
            "host_scores": host_scores,
            "tech_intelligence": tech_intel,
            "attack_surface": attack_surface,
            "priority_queue": priority_queue,
            "campaigns": campaigns,
        }

        write_json(output_dir / "intelligence.json", data)

        # Summary output
        risk_icon = {"critical": "!!", "high": "!", "medium": ">", "low": "+"}
        icon = risk_icon.get(risk_level, ">")
        if risk_level in ("critical", "high"):
            warn(f"Intelligence: Risk level {risk_level.upper()} (score: {overall_score}/100)")
        else:
            info(f"Intelligence: Risk level {risk_level.upper()} (score: {overall_score}/100)")

        info(f"  {icon} {len(host_scores)} hosts scored, {len(campaigns)} campaigns suggested")
        info(f"  {icon} Top target: {priority_queue[0]['hostname']} (score: {priority_queue[0]['score']})" if priority_queue else "  > No priority targets")

        success("Intelligence report generated")

        return PluginResult.completed(
            data=data,
            findings_count=len(campaigns),
            artifacts=[output_dir / "intelligence.json"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={
                "overall_risk_score": int,
                "risk_level": str,
                "host_scores": list,
                "priority_queue": list,
                "campaigns": list,
            },
            description="Attack surface intelligence and risk assessment",
        )


def _get_hosts(probe_data: dict) -> list[dict]:
    """Extract host list from probe data (handles both shapes)."""
    hosts = probe_data.get("hosts", [])
    if not hosts:
        alive = probe_data.get("alive_hosts", [])
        urls = probe_data.get("alive_urls", [])
        for i, h in enumerate(alive):
            url = urls[i] if i < len(urls) else f"https://{h}"
            hosts.append({"hostname": h, "final_url": url, "status_code": 200, "technologies": []})

    # Normalize: ensure hostname is always a string
    for h in hosts:
        hn = h.get("hostname", "")
        if isinstance(hn, dict):
            h["hostname"] = hn.get("hostname", str(hn)[:60])
        if "technologies" not in h:
            h["technologies"] = []

    return hosts


def _score_hosts(
    hosts: list[dict],
    ports_data: dict,
    endpoints_data: dict,
    secrets_data: dict,
    ssl_data: dict,
) -> list[dict]:
    """Score each host 0-100 based on findings."""
    # Build global open ports set (ports data uses IPs not hostnames)
    all_open_ports: set[int] = set()
    results = ports_data.get("results", {})
    if isinstance(results, dict):
        # Format: {ip_address: [{port, service, ...}, ...]}
        for ip, port_list in results.items():
            if isinstance(port_list, list):
                for port_info in port_list:
                    if isinstance(port_info, dict):
                        all_open_ports.add(port_info.get("port", 0))
                    elif isinstance(port_info, int):
                        all_open_ports.add(port_info)
    elif isinstance(results, list):
        for entry in results:
            if isinstance(entry, dict):
                for port_info in entry.get("open_ports", []):
                    all_open_ports.add(port_info.get("port", 0))

    # Build per-host endpoint categories
    endpoint_categories: dict[str, int] = {}
    for ep in endpoints_data.get("endpoints", []):
        for cat in ep.get("categories", []):
            endpoint_categories[cat] = endpoint_categories.get(cat, 0) + 1

    # Secret severity counts
    secret_severities: dict[str, int] = {}
    for finding in secrets_data.get("findings", []):
        sev = finding.get("severity", "medium")
        secret_severities[sev] = secret_severities.get(sev, 0) + 1

    # SSL issues
    ssl_issues: list[dict] = ssl_data.get("issues", [])

    scored: list[dict] = []
    for host in hosts:
        hostname = host.get("hostname", "")
        # Defensive: if hostname is a dict (nested probe data), extract the string
        if isinstance(hostname, dict):
            hostname = hostname.get("hostname", str(hostname)[:60])
        score = 0
        breakdown: list[str] = []

        # Port risk (global since ports data uses IPs)
        for port in all_open_ports:
            if port in PORT_RISK:
                risk, desc = PORT_RISK[port]
                score += risk
                breakdown.append(f"Port {port} ({desc}): +{risk}")

        # Endpoint risk (shared across all hosts for now)
        for cat, count in endpoint_categories.items():
            risk = ENDPOINT_RISK.get(cat, 1) * min(count, 5)
            if risk > 0:
                score += min(risk, 15)
                breakdown.append(f"Endpoints [{cat}]: +{min(risk, 15)}")

        # Secret risk (shared)
        for sev, count in secret_severities.items():
            risk_map = {"critical": 30, "high": 20, "medium": 10, "low": 5}
            risk = risk_map.get(sev, 5) * min(count, 3)
            score += min(risk, 40)
            breakdown.append(f"Secrets [{sev}] x{count}: +{min(risk, 40)}")

        # SSL issues
        for issue in ssl_issues:
            if issue.get("hostname") == hostname:
                issue_type = issue.get("type", "unknown")
                risk_map = {"expired": 25, "self_signed": 15, "weak_protocol": 20}
                risk = risk_map.get(issue_type, 10)
                score += risk
                breakdown.append(f"SSL {issue_type}: +{risk}")

        # Tech risk
        technologies = host.get("technologies", [])
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in TECH_ATTACK_MAP:
                score += 5
                breakdown.append(f"Tech [{tech}]: +5")

        score = min(score, 100)

        scored.append({
            "hostname": hostname,
            "score": score,
            "risk_level": (
                "critical" if score >= 70
                else "high" if score >= 50
                else "medium" if score >= 25
                else "low"
            ),
            "breakdown": breakdown[:10],  # Top 10 factors
        })

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def _build_tech_intelligence(hosts: list[dict]) -> list[dict]:
    """Map discovered technologies to attack vectors."""
    seen_tech: set[str] = set()
    intel: list[dict] = []

    for host in hosts:
        for tech in host.get("technologies", []):
            tech_lower = tech.lower()
            if tech_lower not in seen_tech and tech_lower in TECH_ATTACK_MAP:
                seen_tech.add(tech_lower)
                mapping = TECH_ATTACK_MAP[tech_lower]
                intel.append({
                    "technology": tech,
                    "attack_vectors": mapping["attack_vectors"],
                    "cve_categories": mapping["cve_categories"],
                    "nuclei_tags": mapping["nuclei_tags"],
                    "hosts": [
                        h["hostname"] for h in hosts
                        if tech_lower in [t.lower() for t in h.get("technologies", [])]
                    ],
                })

    return intel


def _build_attack_surface(
    hosts: list[dict],
    ports_data: dict,
    endpoints_data: dict,
    secrets_data: dict,
    ssl_data: dict,
    takeover_data: dict,
    cors_data: dict,
) -> dict:
    """Aggregate attack surface metrics."""
    total_ports = ports_data.get("total_open", 0)
    total_endpoints = len(endpoints_data.get("endpoints", []))
    interesting_endpoints = sum(
        1 for ep in endpoints_data.get("endpoints", [])
        if ep.get("categories")
    )
    total_secrets = secrets_data.get("total", 0)
    critical_secrets = sum(
        1 for f in secrets_data.get("findings", [])
        if f.get("severity") == "critical"
    )
    ssl_issues = len(ssl_data.get("issues", []))
    takeover_findings = takeover_data.get("total_findings", 0)
    cors_vulns = cors_data.get("vulnerable", 0)

    # Tech distribution
    tech_dist: dict[str, int] = {}
    for host in hosts:
        for tech in host.get("technologies", []):
            tech_dist[tech] = tech_dist.get(tech, 0) + 1

    return {
        "total_hosts": len(hosts),
        "total_open_ports": total_ports,
        "total_endpoints": total_endpoints,
        "interesting_endpoints": interesting_endpoints,
        "total_secrets": total_secrets,
        "critical_secrets": critical_secrets,
        "ssl_issues": ssl_issues,
        "takeover_findings": takeover_findings,
        "cors_vulnerabilities": cors_vulns,
        "technology_distribution": tech_dist,
        "surface_area_score": len(hosts) * (1 + total_ports) * (1 + total_endpoints // 10),
    }


def _build_priority_queue(
    host_scores: list[dict],
    endpoints_data: dict,
    secrets_data: dict,
) -> list[dict]:
    """Build a prioritized list of targets to investigate."""
    queue: list[dict] = []

    for hs in host_scores:
        if hs["score"] < 10:
            continue

        reasons: list[str] = []
        actions: list[str] = []

        if hs["score"] >= 70:
            reasons.append("Critical risk score")
            actions.append("Immediate manual investigation")
        elif hs["score"] >= 50:
            reasons.append("High risk score")
            actions.append("Prioritize for testing")

        # Add specific reasons from breakdown
        for item in hs.get("breakdown", [])[:3]:
            reasons.append(item.split(":")[0])

        if not actions:
            actions.append("Review scan findings")
            actions.append("Run targeted Nuclei scan")

        queue.append({
            "hostname": hs["hostname"],
            "score": hs["score"],
            "risk_level": hs["risk_level"],
            "reasons": reasons,
            "suggested_actions": actions,
        })

    return queue[:20]  # Top 20 targets


def _suggest_campaigns(
    endpoints_data: dict,
    secrets_data: dict,
    tech_intel: list[dict],
    takeover_data: dict,
    cors_data: dict,
    hosts: list[dict],
) -> list[dict]:
    """Suggest investigation campaigns based on findings."""
    campaigns: list[dict] = []

    # Endpoint categories
    ep_categories: dict[str, int] = {}
    for ep in endpoints_data.get("endpoints", []):
        for cat in ep.get("categories", []):
            ep_categories[cat] = ep_categories.get(cat, 0) + 1

    if ep_categories.get("admin", 0) > 0:
        campaigns.append({
            "name": "Admin Panel Hunting",
            "description": f"Found {ep_categories['admin']} admin-related endpoints. Investigate for default credentials, auth bypass, and exposed admin functionality.",
            "targets": [h["hostname"] for h in hosts],
            "confidence": "high",
            "priority": 1,
        })

    if ep_categories.get("api", 0) > 0:
        campaigns.append({
            "name": "API Security Testing",
            "description": f"Found {ep_categories['api']} API endpoints. Test for IDOR, auth issues, rate limiting, mass assignment, and excessive data exposure.",
            "targets": [h["hostname"] for h in hosts],
            "confidence": "high",
            "priority": 2,
        })

    if ep_categories.get("auth", 0) > 0:
        campaigns.append({
            "name": "Authentication Analysis",
            "description": f"Found {ep_categories['auth']} auth endpoints. Test login flows, password reset, session handling, token security.",
            "targets": [h["hostname"] for h in hosts],
            "confidence": "high",
            "priority": 2,
        })

    if secrets_data.get("total", 0) > 0:
        campaigns.append({
            "name": "Credential Harvesting",
            "description": f"Found {secrets_data['total']} exposed secrets in JS files. Verify, test for access, check for key rotation.",
            "targets": [h["hostname"] for h in hosts],
            "confidence": "critical" if secrets_data.get("findings", []) and any(
                f.get("severity") == "critical" for f in secrets_data.get("findings", [])
            ) else "high",
            "priority": 0,
        })

    if ep_categories.get("upload", 0) > 0:
        campaigns.append({
            "name": "File Upload Exploitation",
            "description": f"Found {ep_categories['upload']} upload endpoints. Test for unrestricted file upload, path traversal, RCE via file types.",
            "targets": [h["hostname"] for h in hosts],
            "confidence": "medium",
            "priority": 3,
        })

    if ep_categories.get("debug", 0) > 0:
        campaigns.append({
            "name": "Debug Endpoint Exploitation",
            "description": f"Found {ep_categories['debug']} debug endpoints. High chance of info disclosure, RCE, or internal data exposure.",
            "targets": [h["hostname"] for h in hosts],
            "confidence": "critical",
            "priority": 0,
        })

    if takeover_data.get("total_findings", 0) > 0:
        campaigns.append({
            "name": "Subdomain Takeover Claims",
            "description": f"Found {takeover_data['total_findings']} potential subdomain takeovers. Verify and claim dangling services.",
            "targets": [f.get("hostname", "") for f in takeover_data.get("findings", [])],
            "confidence": "high",
            "priority": 1,
        })

    if cors_data.get("vulnerable", 0) > 0:
        campaigns.append({
            "name": "CORS Exploitation",
            "description": f"Found {cors_data['vulnerable']} CORS misconfigurations. Test for cross-origin data theft and session hijacking.",
            "targets": [f.get("hostname", "") for f in cors_data.get("findings", []) if f.get("vulnerable")],
            "confidence": "high",
            "priority": 1,
        })

    for ti in tech_intel:
        if len(ti["attack_vectors"]) >= 3:
            campaigns.append({
                "name": f"{ti['technology']} Deep Dive",
                "description": f"Target runs {ti['technology']} with {len(ti['attack_vectors'])} known attack vectors. Run targeted tests.",
                "targets": ti.get("hosts", []),
                "confidence": "medium",
                "priority": 3,
            })

    # Sort by priority
    campaigns.sort(key=lambda c: c["priority"])

    return campaigns
