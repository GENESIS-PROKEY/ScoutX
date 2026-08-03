"""Subdomain Takeover Detection Plugin — find dangling CNAMEs and claimable services.

Resolves CNAME chains for every discovered subdomain and matches them against
a database of cloud service fingerprints. Also checks HTTP response bodies
from the probe plugin for error page signatures.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING, Any

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.plugins.builtin.takeover.fingerprints import (
    FINGERPRINTS,
    match_cname,
)
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.takeover")


class Plugin(ScoutPlugin):
    """Detect subdomains vulnerable to takeover via dangling CNAMEs."""

    meta = PluginMeta(
        name="takeover",
        description="Subdomain takeover detection via CNAME analysis and error fingerprints",
        version="0.1.0",
        author="ScoutX",
        tags=["takeover", "cname", "security", "subdomain"],
    )
    depends_on: list[str] = ["subdomains", "probe"]
    concurrent_with: list[str] = ["ssl_analysis"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success, warn

        output_dir = context.output_dir / "takeover"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get subdomains
        sub_data = context.result_data("subdomains")
        subdomains_list = sub_data.get("subdomains", [])
        if not subdomains_list:
            return PluginResult.skipped("No subdomains to check")

        # Get hostnames from subdomain entries
        hostnames: list[str] = []
        for entry in subdomains_list:
            if isinstance(entry, dict):
                hostnames.append(entry.get("hostname", ""))
            elif isinstance(entry, str):
                hostnames.append(entry)
        hostnames = [h for h in hostnames if h]

        # Also include the main target
        hostnames.append(context.target)
        hostnames = list(set(hostnames))

        info(f"Checking {len(hostnames)} hosts for takeover vulnerabilities...")

        # Get probe data for body matching
        probe_data = context.result_data("probe")
        probe_hosts = probe_data.get("hosts", [])

        # Build hostname >> probe body map
        host_bodies: dict[str, str] = {}
        for ph in probe_hosts:
            hostname = ph.get("hostname", "")
            # We'll fetch bodies ourselves since probe only stores headers
            if hostname:
                url = ph.get("final_url") or ph.get("url") or f"https://{hostname}"
                host_bodies[hostname] = url

        semaphore = asyncio.Semaphore(20)
        findings: list[dict[str, Any]] = []

        async def check_host(hostname: str) -> list[dict[str, Any]]:
            """Check a single hostname for takeover potential."""
            async with semaphore:
                host_findings: list[dict[str, Any]] = []

                # Step 1: Resolve CNAME chain
                cnames = await _resolve_cname_chain(hostname)

                # Step 2: Match CNAMEs against fingerprints
                for cname in cnames:
                    matches = match_cname(cname)
                    for fp in matches:
                        finding = {
                            "hostname": hostname,
                            "cname": cname,
                            "service": fp.service,
                            "severity": fp.severity,
                            "type": "cname_match",
                            "vulnerable": fp.vulnerable,
                            "confirmed": False,
                        }

                        # Step 3: Try to confirm via HTTP body check
                        if fp.vulnerable and fp.body_patterns:
                            body_match = await _check_http_body(
                                hostname, fp.body_patterns
                            )
                            if body_match:
                                finding["confirmed"] = True
                                finding["severity"] = "critical"
                                finding["evidence"] = body_match

                        host_findings.append(finding)

                # Step 4: Check for NXDOMAIN CNAMEs (dangling)
                if cnames:
                    for cname in cnames:
                        is_dangling = await _is_nxdomain(cname)
                        if is_dangling:
                            host_findings.append({
                                "hostname": hostname,
                                "cname": cname,
                                "service": "Unknown (dangling CNAME)",
                                "severity": "medium",
                                "type": "dangling_cname",
                                "vulnerable": True,
                                "confirmed": False,
                            })

                return host_findings

        # Run all checks concurrently
        tasks = [check_host(h) for h in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug("Takeover check error: %s", result)

        # Deduplicate findings
        seen = set()
        unique_findings: list[dict[str, Any]] = []
        for f in findings:
            key = (f["hostname"], f.get("cname", ""), f["service"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        unique_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

        # Count by severity
        critical = sum(1 for f in unique_findings if f["severity"] == "critical")
        high = sum(1 for f in unique_findings if f["severity"] == "high")
        confirmed = sum(1 for f in unique_findings if f.get("confirmed"))

        data = {
            "target": context.target,
            "total_checked": len(hostnames),
            "total_findings": len(unique_findings),
            "confirmed": confirmed,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": sum(1 for f in unique_findings if f["severity"] == "medium"),
                "info": sum(1 for f in unique_findings if f["severity"] == "info"),
            },
            "findings": unique_findings,
            "fingerprints_loaded": len(FINGERPRINTS),
        }

        write_json(output_dir / "takeover.json", data)

        if critical > 0 or confirmed > 0:
            warn(f"TAKEOVER: {critical} critical, {confirmed} confirmed across {len(unique_findings)} findings")
        elif unique_findings:
            info(f"Takeover: {len(unique_findings)} potential findings (0 confirmed)")
        else:
            success("No takeover vulnerabilities detected")

        return PluginResult.completed(
            data=data,
            findings_count=len(unique_findings),
            artifacts=[output_dir / "takeover.json"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={
                "findings": list,
                "total_findings": int,
                "confirmed": int,
            },
            description="Subdomain takeover detection results",
        )


async def _resolve_cname_chain(hostname: str, max_depth: int = 5) -> list[str]:
    """Resolve the CNAME chain for a hostname."""
    cnames: list[str] = []
    current = hostname
    loop = asyncio.get_event_loop()

    for _ in range(max_depth):
        try:
            # Use dns.resolver if available, fallback to socket
            answers = await loop.run_in_executor(
                None, lambda h=current: _dns_cname_lookup(h)
            )
            if answers:
                cname = answers[0].rstrip(".")
                if cname != current and cname not in cnames:
                    cnames.append(cname)
                    current = cname
                else:
                    break
            else:
                break
        except Exception:
            break

    return cnames


def _dns_cname_lookup(hostname: str) -> list[str]:
    """Perform a CNAME lookup using socket (fallback, no dnspython needed)."""
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(hostname, "CNAME")
            return [str(r.target) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []
    except ImportError:
        # No dnspython — try getaddrinfo + hope for CNAME in response
        try:
            socket.getaddrinfo(hostname, None)
            # getaddrinfo doesn't return CNAMEs, but if it resolves we at least know it exists
            return []
        except socket.gaierror:
            return []


async def _is_nxdomain(hostname: str) -> bool:
    """Check if a hostname doesn't resolve (potential dangling CNAME target)."""
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, None)
        )
        return False  # Resolves = not dangling
    except socket.gaierror as e:
        if e.errno in (socket.EAI_NONAME, 11001):  # NXDOMAIN
            return True
        return False


async def _check_http_body(
    hostname: str,
    patterns: tuple[str, ...],
    timeout: float = 8.0,
) -> str | None:
    """Fetch HTTP body and check for takeover fingerprint patterns."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            async with httpx.AsyncClient(
                trust_env=False,
                verify=False,
                follow_redirects=True,
                timeout=httpx.Timeout(timeout, connect=5.0),
            ) as client:
                resp = await client.get(url)
                body = resp.text[:10000]  # Only check first 10KB

                for pattern in patterns:
                    if pattern.lower() in body.lower():
                        return pattern
        except Exception:
            continue

    return None
