"""Port Scanner Plugin — async TCP connect scan.

Pure Python, no nmap dependency. Scans top ports using asyncio sockets
with configurable concurrency and timeout. Fast enough for recon,
quiet enough for bug bounty.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, TYPE_CHECKING

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json, write_jsonl

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.ports")

# Top 100 most common TCP ports — covering the essentials
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111,
    135, 139, 143, 161, 389, 443, 445, 465, 514, 587,
    636, 993, 995, 1080, 1433, 1434, 1521, 1723, 2049, 2082,
    2083, 2086, 2087, 2096, 3000, 3001, 3128, 3306, 3389, 4443,
    4848, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 6379, 6443,
    7001, 7002, 7443, 8000, 8001, 8008, 8009, 8010, 8042, 8060,
    8069, 8080, 8081, 8082, 8083, 8085, 8088, 8090, 8091, 8123,
    8161, 8172, 8181, 8222, 8280, 8333, 8443, 8500, 8834, 8880,
    8888, 8983, 9000, 9001, 9042, 9090, 9091, 9200, 9201, 9300,
    9443, 9999, 10000, 10250, 11211, 15672, 27017, 27018, 28017, 50000,
]

# Service guesses based on port number
PORT_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3000: "Node/Grafana", 3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "K8s-API", 7001: "WebLogic", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "SonarQube", 9090: "Prometheus", 9200: "Elasticsearch",
    11211: "Memcached", 15672: "RabbitMQ", 27017: "MongoDB", 50000: "Jenkins",
}


class Plugin(ScoutPlugin):
    """Async TCP port scanner — connect scan on top ports."""

    meta = PluginMeta(
        name="ports",
        description="Async TCP port scanning on top 100 ports",
        version="0.1.0",
        author="ScoutX",
        tags=["enumeration", "ports", "network"],
    )
    depends_on: list[str] = ["subdomains"]
    concurrent_with: list[str] = ["probe", "ssl_analysis"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        sub_data = context.result_data("subdomains")
        subdomains = sub_data.get("subdomains", [])
        dns_results = sub_data.get("dns_results", {})

        if not subdomains:
            return PluginResult.skipped("No subdomains to scan")

        output_dir = context.output_dir / "ports"
        output_dir.mkdir(parents=True, exist_ok=True)

        config = context.config
        concurrency = int(config.get_profiled("concurrency.ports", context.profile) or 100)
        port_timeout = float(config.get("timeouts.port", 1.5))

        # Get unique IPs from DNS results — scan IPs not hostnames for speed
        ip_to_hosts: dict[str, list[str]] = {}
        for hostname in subdomains:
            ips = dns_results.get(hostname, [])
            if ips:
                for ip in ips:
                    ip_to_hosts.setdefault(ip, []).append(hostname)
            else:
                # No DNS result — try hostname directly
                ip_to_hosts.setdefault(hostname, []).append(hostname)

        targets = list(ip_to_hosts.keys())[:50]  # Limit targets for safety
        ports = TOP_PORTS

        info(f"Scanning {len(ports)} ports on {len(targets)} hosts (concurrency: {concurrency})")

        semaphore = asyncio.Semaphore(concurrency)
        open_ports: list[dict[str, Any]] = []

        async def check_port(host: str, port: int) -> dict[str, Any] | None:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=port_timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return {
                        "host": host,
                        "port": port,
                        "state": "open",
                        "service": PORT_SERVICES.get(port, "unknown"),
                        "hostnames": ip_to_hosts.get(host, [host]),
                    }
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        # Create all tasks
        tasks = [check_port(host, port) for host in targets for port in ports]
        total_checks = len(tasks)
        info(f"Running {total_checks} port checks...")

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                open_ports.append(result)

        # Sort by host then port
        open_ports.sort(key=lambda p: (p["host"], p["port"]))

        info(f"Found {len(open_ports)} open ports across {len(targets)} hosts")

        # Write outputs
        write_jsonl(output_dir / "ports.jsonl", open_ports)

        # Group by host for JSON summary
        by_host: dict[str, list[dict[str, Any]]] = {}
        for entry in open_ports:
            by_host.setdefault(entry["host"], []).append(entry)

        write_json(output_dir / "ports.json", {
            "target": context.target,
            "hosts_scanned": len(targets),
            "ports_scanned": len(ports),
            "total_open": len(open_ports),
            "results": by_host,
        })

        # Store findings in DB
        try:
            if context.db:
                for entry in open_ports:
                    await context.db.add_finding(
                        context.scan_id,
                        plugin_name="ports",
                        finding_type="open_port",
                        severity="info",
                        title=f"Port {entry['port']}/{entry['service']} open on {entry['host']}",
                        hostname=entry["hostnames"][0] if entry["hostnames"] else entry["host"],
                        raw_data=entry,
                    )
        except Exception as exc:
            logger.warning("Failed to store port results: %s", exc)

        success(f"Port scan complete: {len(open_ports)} open ports found")

        return PluginResult.completed(
            data={"open_ports": open_ports, "by_host": by_host},
            findings_count=len(open_ports),
            artifacts=[output_dir / "ports.jsonl"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"open_ports": list, "by_host": dict},
            description="Open TCP ports with service guesses",
        )
